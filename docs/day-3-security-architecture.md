# Day 3 Security Architecture

## Core design principles

CyberShield is intentionally safe-by-design and cannot become a destructive or exploitative security platform. The architecture is built to support trustworthy, read-only asset assessment and not real-world offensive testing.

## Authentication architecture

Future authentication uses:

```text
Register
  ↓
Password hashing
  ↓
Login
  ↓
Short-lived access token
  ↓
Authenticated API access
```

Implementation notes:
- Store only password hashes, never plaintext
- Prefer Argon2id when available
- Do not log plaintext or hashed passwords
- Do not return password hashes to clients
- Use short-lived access tokens and refresh strategy as needed later

## Authorization model

Authorization is ownership-based and layered like this:

```text
User
  ↓
Business
  ↓
Website
  ↓
Scan
  ↓
Finding
  ↓
Report
```

Every protected resource must check server-side authorization, not only UI access. A user must not access a website or finding outside the business they own or are explicitly authorized to manage.

## Target authorization and SSRF defense

The scanner must never accept arbitrary attacker-controlled targets as the primary scan mechanism. Only registered websites owned by the authenticated user or their authorized business are eligible for assessment.

Future SSRF protections must include:
- block private IP ranges and loopback addresses
- reject localhost and link-local ranges
- prevent access to cloud metadata APIs
- block internal hostnames and DNS rebinding conditions
- validate redirects and block redirect chains to forbidden destinations
- normalize alternate IP representations and reserved ranges
- perform early and mid-request validation before and during fetches

## Scanner safety boundary

The scanner subsystem is isolated and read-only:

```text
API
  ↓
Scan Service
  ↓
Target Validation and Authorization
  ↓
Scan Job
  ↓
Safe Scanner Checks
  ↓
Raw Observations
  ↓
Finding Normalizer
  ↓
Risk Engine
  ↓
Database
```

Allowed checks in the MVP concept include:
- HTTPS availability
- TLS/certificate indicators
- security headers
- cookie security attributes
- basic DNS/security indicator checks
- basic public technology information

Disallowed areas include:
- exploit framework behavior
- credential attacks
- brute force
- malware analysis
- destructive scanning
- arbitrary port scanning

## Error-handling policy

The API must never leak:
- stack traces
- internal paths
- SQL errors
- secrets
- implementation details

## CORS and request boundary

The API must only allow the frontend origin configured locally:

```text
http://localhost:3000
```

Do not use wildcard CORS for authenticated requests.

## Logging, request IDs, and auditability

Structured logs include:
- timestamp
- level
- request_id
- event name
- user_id when appropriate
- resource_id when appropriate

Protected data is never logged, including:
- passwords
- access tokens
- API keys
- session secrets

Audit events can later include:
- login
- logout
- scan_started
- scan_completed
- finding_status_changed
- report_created
- website_added
- website_removed

## Rate limiting and input validation

The API will implement safe limits in future phases for:
- login
- registration
- scan creation
- AI requests
- report creation

Validation must happen on the server, not only in the frontend. This includes normalization and strict checking of:
- email
- password
- business names
- website names
- URLs
- IDs
- pagination values
- filters

## Security header and CSRF posture

This application should configure only the headers that actually fit the application usage, such as:
- Content-Security-Policy
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy

A decision on CSRF should be made based on the chosen auth mechanism; stateless token-based patterns and same-site cookie strategies require careful evaluation rather than blind defaulting.

## Password policy

A reasonable password policy should include:
- minimum length of 12 characters
- maximum length of 128 characters
- no plaintext storage
- strong hashing in the future
- failed-login throttling

The policy should avoid unnecessary complexity rules that reduce usability without clear security benefit.
