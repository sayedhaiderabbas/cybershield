# Day 3 Frontend / Backend Mapping

## Purpose

This document maps the Day 2 frontend concepts to the backend architecture that will support them without forcing the frontend to change prematurely. The frontend is intentionally designed as a mock UI, while the backend contract is being prepared to fit it cleanly.

## Mapping table

| Frontend concept | Backend contract |
| --- | --- |
| Dashboard | `/api/v1/dashboard` or aggregated reporting endpoints |
| Websites | `/api/v1/websites` |
| Scans | `/api/v1/scans`, `/api/v1/scans/{id}` |
| Findings | `/api/v1/findings`, `/api/v1/findings/{id}` |
| Reports | `/api/v1/reports` |
| Monitoring | `/api/v1/monitoring` |
| AI Assistant | `/api/v1/ai/explain`, `/api/v1/ai/remediation` |

## Field alignment needs

The backend schema should align with the frontend definitions from Day 2 to avoid drift:
- naming mismatches should be standardized
- severity values should map consistently
- status values should use a shared lifecycle vocabulary
- timestamps should use UTC and consistent ISO formatting
- IDs should be UUID-based when exposed externally

## Example alignment checks

### Severity
Frontend values:
- Critical
- High
- Medium
- Low
- Informational

Backend values should use the same final semantics with lowercase or case-consistent serialization agreed by both sides.

### Status
Frontend controls can represent `Queued`, `Running`, `Completed`, and `Failed`. The backend should maintain stable state machine semantics and not allow free-form status names.

### Timestamps
All timestamps should be stored in UTC and serialized consistently through the API. The frontend can localize them for display without changing the storage contract.

## Boundary

No connection between the mock UI and live backend is performed in this stage. The contract is prepared so future integration is clean, testable, and low-risk.
