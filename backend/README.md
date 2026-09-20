# CyberShield Backend

This backend is the Day 3 foundation for CyberShield. It is intentionally a safe, modular monolith skeleton built to support the future API contract without implementing real scanner or authentication workflows yet.

## Purpose

- Provide a local FastAPI service at http://localhost:5000
- Expose versioned API routes under /api/v1
- Support health and readiness checks
- Define extensible modules for API, services, repositories, models, and DB access
- Preserve the safeguard model described in the product and security docs

## Local development

1. Create a virtual environment.
2. Install dependencies:
   `pip install -r requirements.txt`
3. Copy `.env.example` to `.env` and adjust local values.
4. Start the API:
   `uvicorn app.main:app --host 0.0.0.0 --port 5000 --reload`

## Current service status

The backend currently includes:

- FastAPI app bootstrap
- environment configuration
- CORS configuration
- structured logging setup
- error model scaffolding
- health and readiness endpoints
- versioned API namespace
- JWT-based authentication foundation
- registration, login, logout, and current-user endpoints
- ownership-enforced business and website access

It does not yet implement:

- real vulnerability scanning
- AI provider integration
- production deployment
- real monitoring scheduler
- refresh-token rotation or server-side JWT revocation

## Safety note

This backend is deliberately constrained to approved, read-only, non-destructive architecture work. Scanner enforcement, SSRF protections, and secure authorization boundaries will be implemented in future phases.
