# CyberShield Security Model

These are future requirements for implementation. They define security boundaries before application code exists.

## Authentication

- Use secure password hashing with a modern, appropriate password-hashing algorithm.
- Protect authenticated routes and reject unauthenticated access.
- Use a secure authentication and session strategy with safe expiration and rotation.
- Enforce authorization for every business, website, scan, finding, report, and monitoring resource.
- Maintain account and business isolation so one customer cannot access another customer's data.

## Application Security

- Validate all input at trust boundaries, including URL and identifier formats.
- Encode output appropriately for its rendering context.
- Prevent SQL injection through parameterized queries or a safe data-access layer.
- Use secure database access with least privilege.
- Store secrets outside source control and use secure secret management.
- Configure CORS narrowly for known application origins.
- Apply CSRF protection where cookie-based authentication makes it applicable.
- Rate-limit authentication, scans, AI requests, and other abuse-sensitive operations.
- Return secure errors that do not expose secrets, internals, or unnecessary target data.
- Record security-relevant events with privacy-aware, tamper-resistant logging.

## Scanner Security

The scanner is a defensive, authorized assessment component, never an offensive exploitation system. It must:

- Process only targets that the user is authorized to assess.
- Validate URLs and allowed protocols before making requests.
- Use safe requests, conservative methods, and request timeouts.
- Limit response sizes, concurrency, total duration, and other resource consumption.
- Prevent SSRF through target validation and redirect validation.
- Prevent access to internal, loopback, link-local, metadata, and private network destinations where appropriate.
- Prevent abuse through authentication, authorization, quotas, and rate limits.
- Avoid destructive actions and state-changing requests.
- Avoid exploitation, credential attacks, brute force, and payloads intended to compromise targets.
- Safely handle redirects by revalidating every destination.
- Safely handle malformed, oversized, unavailable, or unexpected targets.

## Data and AI Boundaries

- Treat scanner observations as evidence with provenance and timestamps.
- Permit AI explanations only when grounded in verified findings.
- Clearly distinguish stored evidence, deterministic scoring, and generated guidance.
- Never allow AI output to mark a finding fixed without a subsequent verification.
- Avoid placing secrets or unnecessary personal data in AI prompts or logs.
