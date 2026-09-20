from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.models.entities import Finding, Scan, Website
from app.scanner.checks.cookies import run_cookie_security_check
from app.scanner.checks.dns import run_dns_check
from app.scanner.checks.headers import run_security_header_check
from app.scanner.checks.https import run_https_check
from app.scanner.checks.technology import run_technology_check
from app.scanner.checks.tls import run_tls_check
from app.scanner.http_client import SafeHTTPClient, SafeScanError
from app.scanner.models import CheckResult, calculate_risk_score
from app.scanner.safety import validate_target_url
from app.services.finding_service import fingerprint_for_finding, priority_for_severity


class ScannerEngine:
    def __init__(self, session: Session) -> None:
        self.session = session
        self.http_client = SafeHTTPClient()

    def run(self, scan: Scan) -> Scan:
        website = self.session.query(Website).filter_by(id=scan.website_id).one_or_none()
        if website is None:
            scan.status = 'failed'
            scan.error_code = 'WEBSITE_NOT_FOUND'
            self.session.commit()
            return scan

        scan.status = 'running'
        scan.started_at = datetime.now(timezone.utc)
        scan.updated_at = datetime.now(timezone.utc)
        self.session.commit()

        try:
            safe_url = validate_target_url(website.url)
            response = self.http_client.fetch(safe_url)
            results: list[CheckResult] = []

            https_result = run_https_check(safe_url, response)
            if https_result is not None:
                results.append(https_result)

            tls_result = run_tls_check(safe_url, response)
            if tls_result is not None:
                results.append(tls_result)

            security_header_results = run_security_header_check(safe_url, response)
            results.extend(security_header_results)

            cookie_results = run_cookie_security_check(safe_url, response)
            results.extend(cookie_results)

            dns_result = run_dns_check(safe_url, response)
            if dns_result is not None:
                results.append(dns_result)

            technology_results = run_technology_check(safe_url, response)
            results.extend(technology_results)

            for finding_result in results:
                self._persist_finding(scan, website, finding_result)

            risk_score = calculate_risk_score([
                {'severity': result.severity} for result in results
            ])
            scan.risk_score = risk_score
            scan.completed_at = datetime.now(timezone.utc)
            scan.status = 'completed'
            scan.error_code = None
            self.session.commit()
            website.status = 'active'
            website.last_scan_at = datetime.now(timezone.utc)
            self.session.commit()
            return scan
        except (SafeScanError, ValueError) as exc:
            scan.status = 'failed'
            scan.error_code = 'SCAN_FAILED'
            scan.completed_at = datetime.now(timezone.utc)
            scan.updated_at = datetime.now(timezone.utc)
            self.session.commit()
            return scan

    def _persist_finding(self, scan: Scan, website: Website, result: CheckResult) -> None:
        slug = re.sub(r'[^a-z0-9]+', '-', result.check_id.lower()).strip('-') or 'scan-finding'
        fingerprint = fingerprint_for_finding(website.id, result.check_id, result.category)
        now = datetime.now(timezone.utc)
        self.session.flush()
        existing = (
            self.session.query(Finding)
            .filter(Finding.website_id == website.id, Finding.fingerprint == fingerprint)
            .order_by(Finding.last_seen_at.desc())
            .first()
        )
        if existing is not None:
            existing.scan_id = scan.id
            existing.last_seen_at = now
            existing.occurrence_count = int(existing.occurrence_count) + 1
            existing.updated_at = now
            existing.priority = priority_for_severity(existing.severity)
            return

        finding = Finding(
            scan_id=scan.id,
            website_id=website.id,
            title=result.title,
            slug=slug,
            fingerprint=fingerprint,
            severity=result.severity,
            priority=priority_for_severity(result.severity),
            category=result.category,
            status='open',
            description=result.description,
            evidence=json.dumps(result.evidence, sort_keys=True),
            recommendation=result.recommendation,
            references=result.check_id,
            first_seen_at=now,
            last_seen_at=now,
            occurrence_count=1,
            created_at=now,
            updated_at=now,
        )
        self.session.add(finding)
