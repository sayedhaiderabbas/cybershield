# CyberShield Scanner

## Scope

The Day 6 scanner is intentionally defensive and read-only. It is designed to assess an owned website for common configuration issues without performing exploitation or state-changing behavior.

## Scanner architecture

The scanner is organized as a modular engine with a small safety layer and a registry of assessment checks.

- Target validation: verifies scheme, hostname, URL syntax, and public destination safety.
- SSRF protection: blocks loopback, private, link-local, metadata, and internal network destinations.
- HTTP client: uses a small, controlled GET-only request path with safe timeouts, redirect controls, and response size caps.
- Check registry: HTTPS, TLS, security headers, cookies, DNS, and technology observation checks.
- Findings engine: converts verified observations into structured findings with evidence and guidance.

## Safety rules

The scanner never performs:

- exploitation
- credential attacks
- brute force
- destructive requests
- file upload or form submission
- requests to localhost, private networks, or metadata endpoints
- redirecting to an unsafe destination

## Request control

The scanner uses configured limits from environment variables:

- SCANNER_CONNECT_TIMEOUT=5
- SCANNER_READ_TIMEOUT=10
- SCANNER_TOTAL_TIMEOUT=20
- SCANNER_MAX_REDIRECTS=3
- SCANNER_MAX_RESPONSE_BYTES=200000
- SCANNER_MAX_REQUESTS_PER_SCAN=5
- SCANNER_MAX_CONCURRENT_SCANS=3

These values keep a scan small, predictable, and auditable.

## Check identifiers

The scanner emits deterministic findings with rule identifiers such as:

- CS-HTTPS-001
- CS-HSTS-001
- CS-CSP-001
- CS-CTO-001
- CS-COOKIE-001
- CS-DNS-001
- CS-TECH-001

## Evidence model

Every finding stores concise, machine-readable evidence rather than full response bodies or secrets.

Example:

```json
{
  "check": "CS-HSTS-001",
  "url": "https://example.com/",
  "observed": {
    "header_present": false
  }
}
```

## Severity and risk score

Severity is deterministic and limited to:

- info
- low
- medium
- high
- critical

The risk calculation is simple and transparent:

- info = 0
- low = 2
- medium = 4
- high = 7
- critical = 10

The overall risk score is the sum of finding severities capped at 100.

## Current limitations

This Day 6 implementation intentionally does not include:

- vulnerability exploitation
- mass scanning
- aggressive port enumeration
- advanced TLS downgrade testing
- AI-based scoring
- live third-party credential enumeration

The scanner is a safe baseline assessment engine suitable for a single-operator MVP.
