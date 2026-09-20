# Security Activity and Audit Log

## Scope

CyberShield stores a compact, append-only security activity trail for important business and platform actions. The audit log is intentionally separate from scanner truth, risk scoring, and alert generation. It explains who acted, what action was performed, what resource was affected, and the result of the action, without changing the underlying security state.

The audit trail is designed for:

- accountability over user and system actions
- safe post-incident review
- request correlation through the existing request ID flow
- business-scoped visibility with server-side authorization
- easy API listing and pagination without loading the whole audit table

## Core principles

1. Append-only: historical audit entries are not edited through normal application APIs.
2. Business-scoped: a user can only read events for businesses and resources they own.
3. Minimum data: the audit record stores the action, scope, actor, timestamp, result, and safe contextual metadata.
4. Safety first: no passwords, tokens, cookies, authorization headers, API keys, or raw sensitive request bodies are stored.
5. Deterministic: ordering is stable and based on timestamp and identifier.
6. Separate concerns: audit events do not create alerts, execute scans, or change risk calculations.

## Event taxonomy

The audit model uses a controlled taxonomy aligned to the real actions supported by the platform.

### Authentication

- `AUTHENTICATION.LOGIN_SUCCESS`
- `AUTHENTICATION.LOGIN_FAILURE`
- `AUTHENTICATION.LOGOUT`

### Business

- `BUSINESS.BUSINESS_CREATED`
- `BUSINESS.BUSINESS_UPDATED`
- `BUSINESS.BUSINESS_DELETED`

### Website

- `WEBSITE.WEBSITE_CREATED`
- `WEBSITE.WEBSITE_UPDATED`
- `WEBSITE.WEBSITE_DELETED`

### Scanning

- `SCANNING.SCAN_CREATED`
- `SCANNING.SCAN_COMPLETED`
- `SCANNING.SCAN_FAILED`

### Findings

- `FINDINGS.FINDING_STATUS_CHANGED`

### Alerts

- `ALERTS.ALERT_ACKNOWLEDGED`
- `ALERTS.ALERT_RESOLVED`

### Monitoring

- `MONITORING.MONITORING_CREATED`
- `MONITORING.MONITORING_UPDATED`
- `MONITORING.MONITORING_DISABLED`
- `MONITORING.MONITORING_SCAN_COMPLETED`
- `MONITORING.MONITORING_SCAN_FAILED`

### Reports

- `REPORTS.REPORT_CREATED`
- `REPORTS.REPORT_DOWNLOADED`

### Remediation and verification

- `REMEDIATION.REMEDIATION_STARTED`
- `REMEDIATION.REMEDIATION_UPDATED`
- `REMEDIATION.VERIFICATION_REQUESTED`
- `REMEDIATION.VERIFICATION_COMPLETED`

These are the only event categories recorded by the application. The system does not create meaningless filler events.

## Event semantics

Each audit item contains:

- `actor_user_id`: the authenticated user who initiated the action when available
- `business_id`: the owning business, when the action is within a business boundary
- `event_type`: normalized event taxonomy category
- `action`: normalized action label such as `WEBSITE_CREATED`
- `resource_type`: the object class affected, such as `website` or `scan`
- `resource_id`: the specific database record affected
- `outcome`: `SUCCESS` or `FAILURE`
- `request_id`: request correlation ID when present
- `details`: sanitized, bounded metadata only
- `created_at`: UTC timestamp

The event record is written only after the underlying action succeeds or a safe failure outcome is known. It is never used to infer a security status.

## Sanitization and privacy

Audit metadata is sanitized before Insert.

Never persisted:

- passwords
- password hashes
- access tokens
- refresh tokens
- session cookies
- API keys
- raw authorization headers
- environment secrets
- authentication payloads
- raw sensitive request bodies

On login failure, the system records only safe outcome information and a request correlation ID. It does not reveal whether an account exists.

## Service model

The centralized `AuditEventService` owns validation, normalization, sanitization, ownership association, and persistence. Route handlers do not directly insert into the audit table. This keeps the audit trail consistent and avoids scattering write logic across the API layer.

The service validates the event type, removes unsafe metadata keys, associates the current actor and business when applicable, and stores the UTC timestamp. The same service is used by auth, website, scan, finding, monitoring, report, alert, and remediation flows.

## API behavior

The authenticated audit endpoint is:

- `GET /api/v1/audit-events`
- `GET /api/v1/audit/events` (compatibility alias)

Supported filters:

- `event_type`
- `resource_type`
- `resource_id`
- `outcome`
- `start_date`
- `end_date`
- `page`
- `page_size`

The endpoint returns results ordered by:

- `created_at DESC`
- `id DESC`

This ordering is deterministic and query-friendly.

## Authorization and protection

Audit events are protected with the same ownership rules as the rest of the platform. A user may only list events for businesses and resources they own or are authorized to access. The backend resolves ownership server-side and never trusts client-provided business or user identifiers.

No public update or delete endpoints are exposed for audit events. Historical records are intentionally append-only.

## Retention and operational limits

For the local MVP, retention is simple and bounded:

- keep the append-only event table in the application database
- rely on the existing business and authentication ownership model
- keep metadata minimal to reduce operational risk
- do not add external log platforms or event buses

This keeps the implementation reliable without introducing unnecessary infrastructure.

## Frontend usage

The frontend Security Activity page reads the real audit feed from the backend and displays user-friendly actions such as:

- Website added
- Scan completed
- Finding status changed
- Verification requested
- Report downloaded

The page uses the same ownership model as the backend and only displays the data the current user is authorized to see.
