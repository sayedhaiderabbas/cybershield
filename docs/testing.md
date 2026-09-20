# CyberShield Testing Notes

## Core validation

The backend test suite is executed with:

```bash
cd backend
pytest -q
```

## Scanner-specific coverage

The current tests verify:

- valid and invalid target URLs
- SSRF blocking for loopback and private addresses
- redirect safety checks
- deterministic risk scoring
- header finding generation

These tests keep the scanner bounded and prove that the engine does not fabricate findings or allow unsafe destinations.

## Regression expectations

The Day 6 suite is designed to preserve prior functionality from Day 4 and Day 5, including:

- user registration and login
- business and website ownership enforcement
- cross-user access rejection
- auth token validation

## Safe testing practices

- Use a local development database and avoid destructive cleanup against a production-like environment.
- Use mocked HTTP responses where possible.
- Avoid live scans of third-party targets unless explicitly authorized.
- Keep findings evidence-based and reproducible.
