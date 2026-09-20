# Day 3 Testing Strategy

## Goals

The backend test suite should validate the architecture before real scanning, AI integration, or live database workflows are added. The aim is to prove the contract, security boundaries, and lifecycle rules remain stable.

## Test categories

### Unit tests
- validation rules for email, url, and pagination
- password policy checks
- risk calculation inputs and rounding
- normalizer behavior for URLs and findings

### Integration tests
- authenticated user can access only their resources
- business creation and website registration flows
- scan lifecycle transitions
- finding updates and resolution path

### API tests
- `/health` and `/ready` endpoints
- `/api/v1` root metadata
- validation errors return expected envelope
- not-found paths, unauthorized paths, and rate-limit responses

### Security tests
- unauthenticated resource access rejected
- cross-user resource access denied
- invalid website URL rejected
- private IP target rejected
- loopback address rejected
- redirect to private IP blocked
- malformed token rejected
- SQL injection payloads handled safely
- oversized input rejected
- invalid pagination rejected

### Database tests
- unique email constraint enforcement
- foreign key integrity
- valid status restriction
- finding lifecycle transitions
- scan concurrency safeguards

## Defensive testing principle

These tests are designed to validate safe behavior and prevent regression in security-critical paths. They are not offensive exploit tooling or destructive testing.

## Recommended test layout

```text
backend/tests/
├── unit/
├── integration/
├── security/
├── api/
└── conftest.py
```

## Example cases

- Authentication: invalid credentials return `AUTHENTICATION_FAILED`
- Authorization: user A cannot update business B
- Validation: invalid URL fails before entering business logic
- SSRF protection: internal IP resolves to `INVALID_TARGET`
- Risk calculation: resolved findings do not inflate active score
- Scan lifecycle: queued -> running -> completed -> findings persisted

## CI readiness

The test suite should be able to run locally before any database-backed production work is introduced. This keeps the project safe, maintainable, and hackathon-friendly.
