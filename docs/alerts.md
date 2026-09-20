# CyberShield Alerts

## Overview

CyberShield alerts are deterministic, ownership-scoped notifications generated from verified monitoring results. They are designed for business owners who need a concise explanation of what changed, how severe it is, and whether an issue is still open or has been acknowledged.

## Alert types

The platform currently generates these alert types:

- `NEW_HIGH_FINDING`: a new high-severity finding appears in a monitoring run and was not present in the prior baseline.
- `NEW_CRITICAL_FINDING`: a new critical-severity finding appears in a monitoring run and was not present in the prior baseline.
- `RISK_SCORE_INCREASE`: the current monitored risk score increased materially over the prior score.
- `SIGNIFICANT_SECURITY_CHANGE`: a meaningful verified security configuration change was detected using the same deterministic comparison rules as the monitoring system.
- `MONITORING_FAILURE`: a scheduled monitoring run failed or reported a failure code; the alert is safe and does not expose stack traces or raw underlying exceptions.

## Severity mapping

Alert severities follow the application values:

- `info`
- `low`
- `medium`
- `high`
- `critical`

The alert service normalizes severity values from the underlying findings and monitoring state and rejects unsupported alert types or severities.

## Trigger conditions

Alerts are generated from the real monitoring flow after a scan has been completed or failed. The system does not invent findings or AI-generate alert decisions.

- New critical findings create `NEW_CRITICAL_FINDING`.
- New high findings create `NEW_HIGH_FINDING`.
- Meaningful risk increases create `RISK_SCORE_INCREASE` when `current_score > previous_score` and the delta is greater than or equal to the configured threshold.
- Meaningful monitoring changes create `SIGNIFICANT_SECURITY_CHANGE` when the prior and current findings differ in a way deemed material by the deterministic comparison logic.
- Failed monitoring executions create `MONITORING_FAILURE` with a sanitized message that omits internal errors, stack traces, and secrets.

## Deduplication

Alerts prevent alert fatigue through deterministic deduplication keys built from the business, website, alert type, monitoring target, scan, and event identifiers.

Rules:

- the same event should create a single alert only
- the same persistent finding should not re-alert on every monitoring run
- a finding that disappears and then reappears later can generate a new alert only when it is genuinely new again
- duplicates are checked in the service layer and protected with a database uniqueness constraint where practical

## Lifecycle

Supported alert states:

- `open`
- `acknowledged`
- `resolved`

Valid transitions:

- `open -> acknowledged`
- `open -> resolved`
- `acknowledged -> resolved`

Invalid transitions are rejected with a 409 response. The backend allows users to update only the lifecycle status and never modifies alert type, severity, website, finding, scanning origin, business ownership, deduplication key, or server timestamps.

Resolution semantics are intentionally narrow: resolving an alert does not claim the underlying finding is fixed. It means the alert was reviewed and closed in the application, while the scanner or monitoring system remains the authoritative source for security state.

## API

Protected routes are implemented under `/api/v1/alerts` and require authentication.

- `GET /api/v1/alerts`
- `GET /api/v1/alerts/summary`
- `GET /api/v1/alerts/{id}`
- `PATCH /api/v1/alerts/{id}`
- `GET /api/v1/alerts/unread-count`

The list endpoint supports filtering by `status`, `severity`, `alert_type`, `website_id`, and pagination. Each request enforces ownership and rejects cross-user access.

The summary endpoint returns owner-scoped total, open, acknowledged, and resolved counts plus a severity distribution. It is used by the dashboard and does not expose data from another business owner.

## Frontend

The frontend exposes an alert center that consumes the real backend API instead of mock data. The app shell also includes a compact unread alert indicator that reads the current count from the backend API.

Alert detail responses include the owned website name, finding reference, safe scanner evidence, and risk score context when those values exist in the underlying scan/finding records. The dashboard summary reports open critical/high alerts and open monitoring failures, so resolved history is not counted as active work.

## Security and safety

Alert generation uses the same protections as the rest of the platform:

- authentication is required for all alert endpoints
- ownership is enforced for every business, website, and alert lookup
- cross-user IDOR and BOLA access is rejected
- monitoring and scanner safety checks remain in force
- alert messages redact internal errors and do not expose stack traces, files, or secrets
- alert creation failure is isolated so it does not roll back successful monitoring results

## Limitations

This alert system is intentionally narrow and deterministic. It does not include broader enterprise SOC concepts, external notification channels, or AI-generated issue detection. The app remains focused on safe, explainable, evidence-backed alerting for small-business security monitoring.
