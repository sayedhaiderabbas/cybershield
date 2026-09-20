# CyberShield Security Documentation

## Authentication and authorization

CyberShield uses a stateless JWT access-token model for Day 5. Registration creates a user record with a strong Argon2id password hash. The application never stores or exposes plaintext passwords.

### Password handling

- Passwords are validated on input with a minimum length of 12 characters.
- The server stores only the Argon2id hash in the `users.password_hash` column.
- Passwords are never returned in API responses or logs.
- Authentication checks compare the provided password against the stored hash using `argon2.PasswordHasher`.

### Token model

- Access tokens are short-lived JWTs signed with the configured `JWT_SECRET` and `HS256` algorithm.
- Claims include the subject user ID, issued-at timestamp, expiration timestamp, and token type.
- Tokens carry no business data, no password hash, and no secrets.
- Logout is documented as a client-side action: the application removes the token from local storage and stops sending it in future requests.
- The backend does not claim server-side revocation for stateless JWTs in this phase.

### Authorization model

Authentication answers, “Who are you?” Authorization answers, “Are you allowed to access this resource?” CyberShield enforces ownership checks at every resource boundary:

- User -> Business
- Business -> Website
- Website -> Scan
- Scan -> Finding
- Business -> Report
- Business -> MonitoringTarget

The application verifies ownership before reading, updating, or deleting protected resources. Requests must include a valid bearer token or a clear X-User-ID compatibility header for local development only.

## IDOR and BOLA protections

The service layer and repositories enforce ownership at the data-access layer. A user cannot access another user’s business or website by guessing an ID. Business and website routes require the authenticated user to own the target resource.

## Secret and environment management

- Secrets are stored in environment variables and never committed to source control.
- JWT signing keys are configured through `APP_ENV`, `JWT_SECRET`, and related settings.
- Local development uses a non-production secret placeholder and should not be committed as a real credential.

## Logging and error handling

- Structured logging excludes passwords, token values, and credentials.
- API errors return safe, documented error payloads without internal stack traces, SQL text, or database metadata.
- Validation failures and auth errors are returned with a stable application error code instead of raw exception details.

## Scanner safety model

The Day 6 scanner implements a defensive assessment pattern for owned websites only. It performs read-only HTTP checks and evaluates public security posture without altering server state.

### Scanner controls

- Only HTTP and HTTPS targets are permitted.
- Localhost, loopback, private IPv4, private IPv6, link-local addresses, and metadata endpoints are blocked.
- Redirects are verified before following them; unsafe redirects are rejected.
- A small request budget and timeout configuration are enforced.
- Response bodies are truncated and never stored in full.
- Sensitive values such as cookies, tokens, API keys, and credentials are never persisted in scan findings.

### Evidence and findings

Findings are derived from observed response data only. The scanner does not fabricate vulnerabilities, versions, CVEs, or assets. Each finding includes structured evidence, a deterministic rule ID, a recommendation, and an explainable severity.

### Risk scoring

The model uses a transparent risk score based on the severities of emitted findings. The score is bounded to 0-100 and remains deterministic for the same observed conditions.

## Finding lifecycle and access controls

Finding status is intentionally limited to the user-visible lifecycle states supported by the application:

- `open`: the issue is currently present and still requires attention
- `acknowledged`: the owner has reviewed the issue, but it has not been scanner-verified as fixed
- `resolved`: the owner has marked the issue as resolved, but this is not equivalent to scanner verification

This distinction matters. A user can mark a finding resolved without proving that the underlying condition is no longer present. A later scan can verify whether it remains observed or has disappeared.

## Authorization and ownership

Access control is enforced at the API and service layers. Users can only read or update findings, websites, scans, and businesses owned by their own account. Cross-business access is rejected with 403/404 semantics, and mass-assignment attempts on protected fields are rejected by schema validation.

## Evidence and redaction

CyberShield stores only evidence required to explain a finding without exposing credentials, session tokens, authorization headers, or user secrets. The scanner and findings model rely on verified response metadata rather than invented vulnerabilities or fabricated evidence.

CyberShield also applies a dedicated redaction layer before any AI context is sent to an external provider. Passwords, JWTs, cookies, authorization headers, and API keys are replaced with `<redacted>` placeholders before content is assembled for the AI layer.

## Report generation and report integrity

Reports are generated from authoritative backend records rather than untrusted client input. The report service loads the business, website, scan, and finding data that already exist in CyberShield, snapshots the validated risk score and model version, and saves a PDF artifact to a controlled application directory.

The report lifecycle is intentionally narrow and deterministic:

- `pending`: the report request has been accepted
- `generating`: the report snapshot is being assembled
- `completed`: the snapshot and PDF were generated successfully
- `failed`: the report could not be generated safely from the stored data

Report content is not mutated by the UI. The client cannot override the business, website ownership, scan date, finding severity, evidence, or risk score. These values are derived from the server-side snapshot.

Generated files are stored under a controlled directory and are retrieved using a safe filename derived from the report id. The download route prevents path traversal by resolving the file against the application report directory and rejecting non-file or out-of-scope paths.

## Monitoring and scheduled reassessment

CyberShield monitoring inherits the same authorization and safety rules as the rest of the platform. The scheduler only evaluates websites the authenticated user owns, schedules safe scans through the existing scan service, and compares results against the prior baseline without inventing evidence or issues.

The monitoring system enforces:

- one active monitoring target per business/website
- safe daily or weekly schedule validation
- server-side ownership checks for every monitoring action
- duplicate execution protection for the same due target
- failure isolation so one failed target does not stop the scheduler
- deterministic change classification using the stored finding fingerprint
- risk-delta tracking for each monitoring cycle

## Security posture and executive overview

The Day 12 posture layer is an aggregation view built on the same authoritative data used elsewhere in CyberShield. It is not a second scanner, a separate risk model, or an AI-generated posture score. It simply consolidates the verified business, website, scan, finding, monitoring, and alert records already stored in the platform.

### Posture data sources

The posture summary is derived from:

- business ownership and website scope
- latest and previous scan results for the business
- deterministic risk scores from the existing Day 7 risk engine
- open and acknowledged findings
- open alerts and their lifecycle status
- active monitoring targets and recent failed assessments

### Deterministic priority rules

Priorities are ordered in a fixed, deterministic way:

1. critical findings
2. high findings
3. meaningful risk increase above the established threshold
4. monitoring failures
5. significant security changes

This ordering is deterministic and uses the stored source references rather than subjective recommendations.

### Empty and limited-data behavior

If there are no monitored websites, no assessments, no findings, or no historical scan scores, the posture layer returns explicit `no-data` and empty states instead of fake values. The frontend displays those states rather than fabricated KPI numbers.

### Alert and finding handling

- resolved findings are excluded from open posture counts
- only open alerts contribute to the posture summary
- monitoring failures are counted specifically and remain tied to the underlying monitoring target and alert ID
- historical trend values come from actual risk-score snapshots, never generated placeholders

## Alert security, lifecycle, and anti-fatigue controls

The alert system reuses the same ownership and safety rules as monitoring and findings. It is intentionally deterministic and cannot be driven by AI. Alert generation is grounded in real monitoring results, comparison output, and risk deltas, and it uses business-level ownership to ensure a user only sees their own alerts.

### Alert lifecycle controls

Supported statuses are limited to `open`, `acknowledged`, and `resolved`.

Valid transitions:

- `open -> acknowledged`
- `open -> resolved`
- `acknowledged -> resolved`

The backend rejects invalid transitions and ensures only the lifecycle state is mutable by the client. Alert type, severity, business, website, finding, scan, monitoring target, deduplication key, and server timestamps remain server-controlled.

This preserves the audit trail without permitting a user to disguise a real finding or manipulate alert metadata.

### Alert deduplication and fatigue prevention

Each alert uses a fixed deduplication key built from its business, website, alert type, monitoring target, and event identifiers. This prevents repeated notifications when the same issue is reprocessed by the monitoring scheduler. The same persistent finding can generate a single alert, while a later new event can create a fresh alert with a new deduplication key.

### Safe failure handling

When alert creation fails, the monitoring result remains valid. The scheduler isolates the alert failure and preserves the underlying scan or finding result rather than rolling back a successful monitoring cycle. Failure paths do not expose stack traces, internal paths, or secret material in the alert payload.

### Ownership and authorization

All alert endpoints require authentication. Alert listing, detail retrieval, and lifecycle updates are filtered by the authenticated owner’s businesses. Requests are rejected when the user tries to read or modify another user’s alerts. This protects against IDOR and BOLA issues on alert IDs and monitoring-related references.

## Audit log and security activity

CyberShield keeps a separate, append-only security activity log for high-value business and platform events. The audit trail records what happened, when it happened, which user initiated it, what resource was affected, and the outcome of the action, without changing scanner truth or influencing risk scoring.

### Audit model and scope

The audit record is stored in the application database and includes the actor, business boundary, event type, action name, resource type and ID, outcome, request correlation ID, timestamp, and sanitized metadata. The table is intentionally append-only and is not edited through a normal user-facing PATCH or DELETE flow.

### Event taxonomy

The application records only real existing actions, mapped to the service layer and business operations already in use. Example categories include:

- `AUTHENTICATION` for login success, logout, and safe login failures
- `WEBSITE` for create, update, and delete operations
- `SCANNING` for scan creation and scan lifecycle outcomes
- `FINDINGS` for status changes
- `ALERTS` for acknowledgement and resolution
- `MONITORING` for create, update, disable, and scan execution results
- `REPORTS` for creation and download records
- `REMEDIATION` for lifecycle and verification events

These are normalized into controlled event names and not arbitrary free-form strings.

### Metadata and privacy controls

Audit metadata is sanitized before persistence:

- no passwords or hashes
- no access or refresh tokens
- no session cookies
- no authorization headers
- no API keys
- no secret environment values
- no raw sensitive request bodies
- no internal stack traces or hidden file paths

If login fails, the application records a safe failure event without revealing whether the account exists.

### Request correlation and ordering

Where available, the audit service associates the request ID from the existing request context so the API request, action, and audit trail can be correlated. Listing order is deterministic and uses `created_at DESC, id DESC`.

### Authorization and audit isolation

The audit API requires a valid bearer token. Ownership is resolved on the server side using the authenticated user’s business scope. The audit route never trusts a client-supplied `business_id` or `user_id`. A user cannot read another user’s audit events, and a cross-business IDOR or BOLA attempt is rejected server-side.

### Retention and operational simplicity

For the local MVP, the platform keeps the audit events in the primary application database with bounded metadata and no external event pipeline. This is enough for operational accountability while keeping the implementation small, secure, and easy to reason about.

## AI trust boundary and prompt defense

Day 8 introduces a constrained AI assistant layer that is separate from the scanner and risk engine. The trust boundary is:

- Trusted: CyberShield system instructions, verified findings, verified evidence, and the authenticated user identity
- Untrusted: target website content, arbitrary browser-submitted strings, and other external content

The backend builds the AI context from database-backed finding metadata only. It does not accept client-supplied evidence, severity, or risk values. Prompts are built from verified evidence and safe metadata, while untrusted target content is treated as data only and never allowed to override application instructions.

The AI assistant may explain a finding, describe its business impact, recommend remediation steps, and explain how to verify the fix. It may not invent vulnerabilities, CVEs, versions, evidence, or successful remediation. If the available evidence is insufficient, the response must say so clearly.

## AI authorization and safety rules

The AI endpoints enforce the same ownership model as findings. A user must be authenticated and must own the relevant business/website/finding before the backend will generate AI guidance. The AI cannot modify a finding record, cannot change the scanner result, cannot adjust the risk score, and cannot execute commands or automatically apply remediation.

## Provider abstraction and deterministic fallback

CyberShield uses a provider abstraction for AI logic and allows a local mock provider to be used when a real provider is unavailable or not configured. Local guidance is deterministic and clearly labeled as fallback information derived from the stored findings and recommendation metadata. This ensures the product remains usable even without an external API key while preserving strict safety limits.

## Current limitations

This phase intentionally does not implement production-grade rate limiting, MFA, OAuth, or refresh-token revocation. The Day 6 scanner is a constrained MVP for safe configuration assessment and is not a production-grade security scanning platform. It is suitable as a secure foundation for later feature work rather than a full enterprise security monitoring solution.
