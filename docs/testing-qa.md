# Day 25 Testing & QA

## Scope

Day 25 validated the existing CyberShield backend and frontend without
changing application architecture. Coverage included authentication,
authorization and ownership isolation, input validation, pagination, findings,
scan/business/website workflows, reports, monitoring, alerts, audit access,
AI safety behavior, security hardening regressions, database fixture
isolation, failure paths, and frontend build integrity.

The existing suite was inspected before changes. It contained 71 tests across
authentication, businesses, findings, scanner, reports, monitoring, alerts,
audit, AI, scalability, and Day 24 security. Six focused QA regression tests
were added for gaps found during that review.

## Environment

- Windows local environment
- Python 3.12.10 64-bit
- Backend virtual environment: `backend\.venv`
- Pytest 8.3.3 with AnyIO
- FastAPI, SQLAlchemy, SQLite in-memory test database
- Node/npm frontend environment
- React, TypeScript, Vite, and oxlint
- No external scanner or AI provider was contacted
- Tests use isolated in-memory database fixtures

## Backend tests

Baseline before Day 25 test additions:

```text
python -m pytest
71 passed, 52 warnings
```

Final command:

```text
backend\.venv\Scripts\python.exe -m pytest
77 passed, 58 warnings in 24.97s
```

Focused Day 25 command:

```text
backend\.venv\Scripts\python.exe -m pytest tests/test_day25_qa.py -q
6 passed, 10 warnings
```

No tests were skipped or weakened. Warnings are existing deprecations,
including `datetime.utcnow()`, FastAPI `on_event`, AnyIO compatibility, and
ReportLab compatibility.

## Security regression tests

The Day 24 security suite passed with 4 tests. It covers the disabled legacy
identity header, security headers, and production JWT-secret validation.
Day 25 additionally exercised malformed and missing bearer authentication,
sanitized validation responses, wildcard CORS rejection, and report artifact
path traversal.

Authorization tests continued to cover legitimate owner access and cross-user
business, report, monitoring, findings, and audit isolation. No confirmed
authorization regression was found.

## Functional tests

Existing tests cover registration, login, inactive accounts, business and
website lifecycle, scans, findings and deduplication, remediation and
verification, reports, monitoring, alerts, audit events, AI responses, and
scanner behavior. The final suite passed all 77 tests.

## Failure-path tests

The Day 25 additions verify:

- missing, malformed, and unsupported authentication headers
- malformed JSON
- invalid pagination values
- forbidden extra request fields
- empty pagination pages
- report artifact traversal attempts
- absence of an audit-event mutation endpoint
- production wildcard CORS rejection

Responses were checked for sanitized error structures and absence of
traceback/secret disclosure.

## Pagination tests

Existing Day 20/21/23 tests cover report, monitoring, and bounded list
queries. Day 25 adds business pagination checks for page one, page two,
an empty page beyond the final page, total counts, total pages, duplicate
prevention, and invalid page/page-size boundaries.

The reviewed suite does not claim exhaustive boundary coverage for every
resource at every page size. Existing resource-specific tests remain the
source of truth for reports, monitoring, findings, alerts, and audit lists.

## Reports tests

Existing report tests cover generation, snapshots, listing, detail access,
cross-user access, secure download, PDF output, and generation failure.
Day 25 adds an artifact path traversal regression test and confirms the
download endpoint returns a safe not-found response.

## Monitoring tests

Existing monitoring tests cover owner scoping, overview state, current and
previous scan comparison, risk deltas, findings counts, history pagination,
deterministic ordering, and sensitive-value exclusion.

## Alerting tests

Existing alert tests cover alert creation, listing, unread counts, summary,
ownership, filtering, and state updates. External notification delivery is
not claimed or tested because no external delivery provider is configured.

## Audit trail tests

Existing audit tests cover authenticated access, business scoping, event
creation, filtering, request identifiers, and sensitive metadata redaction.
Day 25 verifies there is no exposed ordinary-user mutation endpoint for
existing audit events. The append-only service behavior remains unchanged.

## AI security tests

Existing Day 8 and Day 18 tests cover authenticated finding context,
ownership, redaction of credentials/tokens/cookies/JWT-like values,
prompt-injection resistance, unsupported-claim rejection, ungrounded
evidence rejection, malformed-provider fallback, request limits, and safe
deterministic responses. No external provider was contacted.

## Frontend validation

```text
npm exec tsc -- -b
PASS

npm run lint
PASS, with existing non-blocking react(set-state-in-effect) warnings

npm run build
PASS
1880 modules transformed
```

No new TypeScript or lint errors were introduced.

## Defects found

No application defect was confirmed during Day 25 execution. The primary
finding was test-quality coverage gaps around negative authentication,
validation, pagination boundaries, report path traversal, and audit mutation
surface. These were addressed with focused regression tests.

## Known limitations

- No production-scale benchmark or query-plan analysis was performed.
- No external scanner, notification provider, or AI provider was contacted.
- Frontend browser interaction was not replaced with a full end-to-end test
  framework; validation focused on TypeScript, lint, build, existing API
  integration assumptions, and backend tests.
- Existing deprecation warnings remain.
- API rate limiting and frontend HttpOnly cookie migration remain deferred
  from Day 24.

## Final validation

| Area | Result |
|---|---|
| Focused Day 25 QA tests | 6 passed |
| Full backend regression | 77 passed |
| Security regression | 4 focused Day 24 tests passed |
| TypeScript | PASS |
| Lint | PASS with existing warnings |
| Production build | PASS |
| Confirmed Day 25 defects | None |

