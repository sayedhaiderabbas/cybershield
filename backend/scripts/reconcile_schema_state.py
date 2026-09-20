"""Reconcile the known active-database schema drift on an isolated SQLite copy.

This utility is intentionally separate from Alembic. It must be given an
explicit database path and refuses the repository's active database unless the
caller opts in with a separate, reviewed process. It never changes the
Alembic version marker.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path
from typing import Iterable

EXPECTED_REVISION = "20260916_day11_alerts"
ACTIVE_DATABASE = Path("backend/cybershield.db").resolve()
REPORT_COLUMNS = (
    ("requested_by", "VARCHAR(36)"),
    ("website_id", "VARCHAR(36)"),
    ("report_type", "VARCHAR(60)"),
    ("generated_at", "DATETIME"),
    ("risk_score_snapshot", "INTEGER"),
    ("risk_model_version", "VARCHAR(25)"),
    ("report_metadata", "TEXT"),
)
AUDIT_COLUMNS = (
    ("actor_user_id", "VARCHAR(36)"),
    ("action", "VARCHAR(120)"),
    ("resource_type", "VARCHAR(80)"),
    ("resource_id", "VARCHAR(255)"),
    ("outcome", "VARCHAR(20)"),
    ("request_id", "VARCHAR(120)"),
)
REPORT_INDEXES = (
    ("ix_reports_requested_by", "requested_by"),
    ("ix_reports_website_id", "website_id"),
)
AUDIT_INDEXES = (
    ("ix_security_events_actor_user_id", "actor_user_id"),
    ("ix_security_events_action", "action"),
    ("ix_security_events_resource_type", "resource_type"),
    ("ix_security_events_resource_id", "resource_id"),
    ("ix_security_events_outcome", "outcome"),
    ("ix_security_events_request_id", "request_id"),
)


def _columns(connection: sqlite3.Connection, table: str) -> set[str]:
    return {row[1] for row in connection.execute(f'PRAGMA table_info("{table}")')}


def _index_names(connection: sqlite3.Connection, table: str) -> set[str]:
    return {row[1] for row in connection.execute(f'PRAGMA index_list("{table}")')}


def _add_missing_columns(
    connection: sqlite3.Connection,
    table: str,
    definitions: Iterable[tuple[str, str]],
) -> None:
    existing = _columns(connection, table)
    for name, column_type in definitions:
        if name not in existing:
            connection.execute(f'ALTER TABLE "{table}" ADD COLUMN "{name}" {column_type}')


def _add_indexes(
    connection: sqlite3.Connection,
    table: str,
    indexes: Iterable[tuple[str, str]],
) -> None:
    existing = _index_names(connection, table)
    for name, column in indexes:
        if name not in existing:
            connection.execute(f'CREATE INDEX "{name}" ON "{table}" ("{column}")')


def _rebuild_security_events(connection: sqlite3.Connection) -> None:
    columns = [row[1] for row in connection.execute('PRAGMA table_info("security_events")')]
    connection.execute("ALTER TABLE security_events RENAME TO security_events__reconcile_old")
    connection.execute(
        """
        CREATE TABLE security_events (
            id VARCHAR(36) NOT NULL,
            actor_user_id VARCHAR(36),
            business_id VARCHAR(36),
            event_type VARCHAR(100) NOT NULL,
            action VARCHAR(120) NOT NULL DEFAULT 'ACCESS',
            resource_type VARCHAR(80),
            resource_id VARCHAR(255),
            outcome VARCHAR(20) NOT NULL DEFAULT 'SUCCESS',
            severity VARCHAR(25) NOT NULL DEFAULT 'info',
            message TEXT NOT NULL,
            request_id VARCHAR(120),
            metadata TEXT,
            created_at DATETIME NOT NULL,
            PRIMARY KEY (id),
            FOREIGN KEY (actor_user_id) REFERENCES users (id) ON DELETE SET NULL,
            FOREIGN KEY (business_id) REFERENCES businesses (id) ON DELETE CASCADE
        )
        """
    )
    source = set(columns)
    select = {
        "actor_user_id": '"actor_user_id"' if "actor_user_id" in source else "NULL",
        "action": '"action"' if "action" in source else "'ACCESS'",
        "resource_type": '"resource_type"' if "resource_type" in source else "NULL",
        "resource_id": '"resource_id"' if "resource_id" in source else "NULL",
        "outcome": '"outcome"' if "outcome" in source else "'SUCCESS'",
        "request_id": '"request_id"' if "request_id" in source else "NULL",
    }
    for name in ("id", "business_id", "event_type", "severity", "message", "metadata", "created_at"):
        if name in source:
            select[name] = f'"{name}"'
    connection.execute(
        f"""
        INSERT INTO security_events
        (id, actor_user_id, business_id, event_type, action, resource_type,
         resource_id, outcome, severity, message, request_id, metadata, created_at)
        SELECT {select['id']}, {select['actor_user_id']}, {select['business_id']},
               UPPER({select['event_type']}), {select['action']},
               {select['resource_type']}, {select['resource_id']},
               {select['outcome']}, {select['severity']}, {select['message']},
               {select['request_id']}, {select['metadata']}, {select['created_at']}
        FROM security_events__reconcile_old
        """
    )
    connection.execute("DROP TABLE security_events__reconcile_old")
    _add_indexes(
        connection,
        "security_events",
        (
            ("ix_security_events_id", "id"),
            ("ix_security_events_business_id", "business_id"),
            ("ix_security_events_event_type", "event_type"),
            ("ix_security_events_created_at", "created_at"),
            *AUDIT_INDEXES,
        ),
    )


def _rebuild_reports(connection: sqlite3.Connection) -> None:
    columns = [row[1] for row in connection.execute('PRAGMA table_info("reports")')]
    connection.execute("ALTER TABLE reports RENAME TO reports__reconcile_old")
    connection.execute(
        """
        CREATE TABLE reports (
            id VARCHAR(36) NOT NULL,
            business_id VARCHAR(36) NOT NULL,
            requested_by VARCHAR(36) NOT NULL,
            website_id VARCHAR(36),
            scan_id VARCHAR(36),
            report_type VARCHAR(60) NOT NULL DEFAULT 'security_assessment',
            title VARCHAR(255) NOT NULL,
            status VARCHAR(25) NOT NULL DEFAULT 'pending',
            generated_at DATETIME,
            risk_score_snapshot INTEGER,
            risk_model_version VARCHAR(25),
            report_metadata TEXT,
            created_at DATETIME NOT NULL,
            updated_at DATETIME NOT NULL,
            artifact_path VARCHAR(1024),
            PRIMARY KEY (id),
            FOREIGN KEY (business_id) REFERENCES businesses (id) ON DELETE CASCADE,
            FOREIGN KEY (requested_by) REFERENCES users (id) ON DELETE SET NULL,
            FOREIGN KEY (website_id) REFERENCES websites (id) ON DELETE SET NULL,
            FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE SET NULL
        )
        """
    )
    source = set(columns)
    select = {
        "requested_by": (
            '"requested_by"'
            if "requested_by" in source
            else "(SELECT owner_id FROM businesses WHERE businesses.id = reports__reconcile_old.business_id)"
        ),
        "website_id": '"website_id"' if "website_id" in source else "NULL",
        "report_type": '"report_type"' if "report_type" in source else "'security_assessment'",
        "generated_at": '"generated_at"' if "generated_at" in source else "NULL",
        "risk_score_snapshot": '"risk_score_snapshot"' if "risk_score_snapshot" in source else "NULL",
        "risk_model_version": '"risk_model_version"' if "risk_model_version" in source else "NULL",
        "report_metadata": '"report_metadata"' if "report_metadata" in source else "NULL",
    }
    for name in (
        "id",
        "business_id",
        "scan_id",
        "title",
        "status",
        "created_at",
        "updated_at",
        "artifact_path",
    ):
        if name in source:
            select[name] = f'"{name}"'
    connection.execute(
        f"""
        INSERT INTO reports
        (id, business_id, requested_by, website_id, scan_id, report_type, title,
         status, generated_at, risk_score_snapshot, risk_model_version,
         report_metadata, created_at, updated_at, artifact_path)
        SELECT {select['id']}, {select['business_id']}, {select['requested_by']},
               {select['website_id']}, {select['scan_id']}, {select['report_type']},
               {select['title']}, COALESCE({select['status']}, 'pending'), {select['generated_at']},
               {select['risk_score_snapshot']}, {select['risk_model_version']},
               {select['report_metadata']}, {select['created_at']},
               {select['updated_at']}, {select['artifact_path']}
        FROM reports__reconcile_old
        """
    )
    connection.execute("DROP TABLE reports__reconcile_old")
    missing = connection.execute(
        "SELECT COUNT(*) FROM reports WHERE requested_by IS NULL"
    ).fetchone()[0]
    if missing:
        raise RuntimeError(
            f"Cannot reconcile reports: {missing} rows have no business owner."
        )
    _add_indexes(connection, "reports", (("ix_reports_id", "id"), ("ix_reports_business_id", "business_id"), *REPORT_INDEXES))


def reconcile(database: Path) -> dict[str, object]:
    resolved = database.resolve()
    if resolved == ACTIVE_DATABASE:
        raise RuntimeError(
            "Refusing to reconcile backend/cybershield.db. Use an isolated copy."
        )
    connection = sqlite3.connect(f"file:{resolved.as_posix()}?mode=rw", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        revision = connection.execute(
            "SELECT version_num FROM alembic_version"
        ).fetchone()[0]
        if revision != EXPECTED_REVISION:
            raise RuntimeError(f"Expected revision {EXPECTED_REVISION}, found {revision}.")
        before = {
            row[0]: connection.execute(f'SELECT COUNT(*) FROM "{row[0]}"').fetchone()[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        }
        connection.execute("BEGIN IMMEDIATE")
        _rebuild_security_events(connection)
        _rebuild_reports(connection)
        _add_indexes(connection, "findings", (("ix_findings_category", "category"),))
        _add_indexes(connection, "monitoring_targets", (("ix_monitoring_targets_website_id", "website_id"),))
        integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
        foreign_key_violations = connection.execute("PRAGMA foreign_key_check").fetchall()
        if integrity != "ok":
            raise RuntimeError(f"SQLite integrity check failed: {integrity}")
        if foreign_key_violations:
            raise RuntimeError(
                f"Foreign-key validation failed: {foreign_key_violations}"
            )
        connection.commit()
        after = {
            table: connection.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
            for table in before
        }
        if before != after:
            raise RuntimeError(f"Row counts changed: before={before}, after={after}")
        return {"database": str(resolved), "revision": revision, "before": before, "after": after}
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("database", type=Path)
    args = parser.parse_args()
    print(json.dumps(reconcile(args.database), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
