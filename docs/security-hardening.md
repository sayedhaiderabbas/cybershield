# Day 24 Security Hardening

## Review scope

The review covered authentication, JWT validation, password hashing,
authorization and business ownership, IDOR/BOLA boundaries, input validation,
SQL query construction, report downloads, CORS, HTTP security headers, error
handling, configuration/secrets, audit logging, AI/monitoring/alert routes, and
frontend token handling.

## Confirmed finding and remediation

The API previously accepted `X-User-ID` as an authentication fallback. A
caller could therefore claim another user's ID without presenting a bearer
token. The compatibility path is now disabled by default through
`ENABLE_LEGACY_USER_HEADER=false`. The test suite explicitly enables the
legacy mode only where older tests exercise that compatibility behavior.
Bearer JWT authentication remains the normal authentication mechanism.

Production settings now reject the placeholder JWT secret and wildcard CORS
origins. JWT secrets must be at least 32 characters.

## Authorization and ownership controls

Owner-scoped service queries remain in place for businesses, websites, scans,
findings, reports, monitoring targets, alerts, audit events, remediation, and
AI requests. Existing regression coverage verifies cross-user access
boundaries. Report downloads resolve an authorized report first and constrain
the resolved artifact to the report storage directory.

## Authentication controls

Passwords use Argon2id hashing. Password input is bounded by the Pydantic
schemas. Access tokens require `exp`, `iat`, `sub`, and `type` claims and are
decoded with the configured algorithm. Inactive users are rejected.

## Input and query safety

Important request bodies and pagination/query parameters use Pydantic or
FastAPI validation. SQLAlchemy parameterized queries are used instead of
string-interpolated SQL. Report artifact paths are normalized and constrained
to the report storage root.

## CORS and security headers

CORS remains environment-configured. Production rejects `*` origins. Responses
now include `X-Content-Type-Options`, `X-Frame-Options`, a restrictive
Content-Security-Policy, `Permissions-Policy`, and `Referrer-Policy`.
HSTS is emitted only for production HTTPS requests; it is intentionally not
enabled for HTTP-only local development.

## Error handling and secrets

Validation and application errors use sanitized client-facing payloads.
Unhandled exceptions return a generic internal-error response while detailed
diagnostics remain server-side logs. `.env` files are ignored by Git and the
example configuration contains placeholders only. Secret values were not
printed or included in evidence.

## Testing

Day 24 adds focused security tests for legacy-header rejection, production
secret configuration, and security headers. The full backend suite and
frontend validation commands are run as part of Day 24 verification.

## Known limitations and deferred improvements

- The frontend stores the bearer token in `localStorage`; an HttpOnly,
  same-site cookie session would reduce token exposure to XSS but would require
  an authentication transport change.
- There is no general-purpose API rate limiter in the current local
  architecture.
- HSTS requires HTTPS deployment and is therefore conditional.
- The legacy identity-header compatibility switch should remain disabled in
  production and be removed entirely when all legacy clients are retired.

Day 25 security work, broader threat modeling, dependency scanning, and
deployment hardening remain deferred.
