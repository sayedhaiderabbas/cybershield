# Scalability readiness

## Scope

Day 23 improves scalability readiness within CyberShield's existing FastAPI,
SQLAlchemy, SQLite-compatible architecture. The changes are intentionally
incremental; no distributed infrastructure or new service architecture was
introduced.

## Implemented

- Owner-scoped list services for businesses, websites, scans, findings,
  monitoring targets, and reports now use database `COUNT`, `OFFSET`, and
  `LIMIT` rather than loading the entire collection and slicing in Python.
- List ordering is deterministic. Timestamp ordering includes the record ID as
  a stable tie-breaker.
- Finding queries apply business-owner scoping in the database query itself,
  in addition to the existing website/scan access checks.
- Monitoring target history comparisons only retrieve the two scans required
  to compare the current and previous completed states.
- Alert listing received the same stable timestamp/ID ordering convention.

Existing history, changes, audit, report-generation, scanner, risk, and AI
authorization semantics remain unchanged. Audit events remain append-only and
owner-scoped.

## Query and index review

No new indexes were added. Existing indexes cover the primary foreign keys and
frequently filtered fields. The Day 23 changes reduce transferred rows without
introducing speculative or duplicate indexes. A production database review
should use query plans and representative data before adding composite indexes.

## Performance methodology and limitations

Validation uses focused regression tests and the full backend suite. No
benchmark number is claimed: the local SQLite development environment is not a
reliable production-performance proxy, and no representative large dataset was
available. The bounded queries are intended to keep response and Python
memory growth proportional to the requested page.

## Deferred work

Distributed workers, external caches, database sharding, deployment
architecture, and broad performance benchmarking remain deferred. Monitoring
overview still performs per-target summary work because changing that
calculation would risk altering monitoring semantics; it should be revisited
with query-plan measurements and representative production data.
