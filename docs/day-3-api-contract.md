# Day 3 API Contract

## Base principles

- All routes use `/api/v1`
- Consistent success envelope: `{ "data": ..., "meta": ... }`
- Consistent error envelope: `{ "error": { "code": "...", "message": "...", "details": [] } }`
- No stack traces, SQL text, internal paths, or secrets are exposed
- All authentication and authorization are enforced server-side

## Standard error taxonomy

| HTTP status | Error code | Meaning |
| --- | --- | --- |
| 400 | VALIDATION_ERROR | Request payload or parameter is invalid |
| 401 | AUTHENTICATION_REQUIRED | No valid session or token |
| 401 | AUTHENTICATION_FAILED | Invalid credentials or malformed token |
| 403 | AUTHORIZATION_DENIED | Authenticated user lacks access |
| 404 | RESOURCE_NOT_FOUND | Resource does not exist |
| 409 | RESOURCE_CONFLICT | Duplicate or conflicting state |
| 422 | VALIDATION_ERROR | Schema validation failure in selected cases |
| 429 | RATE_LIMITED | Rate limit exceeded |
| 500 | INTERNAL_ERROR | Unexpected server error |

## Authentication contract

### POST /api/v1/auth/register
Request:

```json
{
  "email": "owner@example.com",
  "password": "StrongPass123!",
  "full_name": "Jamie Smith"
}
```

Response:

```json
{
  "data": {
    "user": {
      "id": "uuid",
      "email": "owner@example.com",
      "full_name": "Jamie Smith"
    }
  },
  "meta": {
    "request_id": "uuid"
  }
}
```

### POST /api/v1/auth/login
Request:

```json
{
  "email": "owner@example.com",
  "password": "StrongPass123!"
}
```

Response:

```json
{
  "data": {
    "access_token": "jwt-or-session-token",
    "token_type": "bearer",
    "expires_in": 3600
  },
  "meta": {
    "request_id": "uuid"
  }
}
```

### POST /api/v1/auth/logout
- Invalidates token or session in future implementation.

### GET /api/v1/auth/me
Returns current user identity and basic account metadata.

## Business endpoints

### POST /api/v1/businesses
Creates business, associated to authenticated user.

### GET /api/v1/businesses
Returns paginated list of businesses.

### GET /api/v1/businesses/{id}
Returns a single business and related metadata.

### PATCH /api/v1/businesses/{id}
Updates business metadata.

### DELETE /api/v1/businesses/{id}
Soft or hard delete depending on retention policy; default phase keeps this conceptual.

## Website endpoints

### POST /api/v1/websites
Request:

```json
{
  "business_id": "uuid",
  "name": "Marketing Site",
  "url": "https://example.com"
}
```

Validation requirements:
- URL must be absolute and well-formed
- scheme restricted to `http` or `https` in normal use
- host must not resolve to forbidden internal addresses for future scans
- normalization occurs before persistence

## Scan endpoints

### POST /api/v1/scans
Request:

```json
{
  "website_id": "uuid"
}
```

Response:

```json
{
  "data": {
    "scan_id": "uuid",
    "status": "queued"
  },
  "meta": {
    "request_id": "uuid"
  }
}
```

This endpoint accepts only a registered website ID and never arbitrary scanning targets.

### GET /api/v1/scans/{scan_id}
Returns status, progress, started_at, completed_at, finding_count.

### GET /api/v1/scans/{id}/status
Returns a lightweight state summary.

### GET /api/v1/scans/{id}/findings
Returns findings associated with a scan, with pagination.

## Findings endpoints

### GET /api/v1/findings
Supports filtering by severity, status, website, and category.

### GET /api/v1/findings/{id}
Returns full detail including evidence and recommendations.

### PATCH /api/v1/findings/{id}
Supports status change, acknowledgements, and resolution updates.

## Report endpoints

### POST /api/v1/reports
Creates a report definition based on verified findings.

### GET /api/v1/reports
Returns reports for the authenticated user and authorized businesses.

### GET /api/v1/reports/{id}
Returns a stored report metadata record and downloadable artifact metadata.

## Monitoring endpoints

### GET /api/v1/monitoring
Lists configured monitoring targets.

### POST /api/v1/monitoring
Configures website or asset monitoring.

### GET /api/v1/monitoring/{id}
Returns the target state and last observed change metadata.

### PATCH /api/v1/monitoring/{id}
Updates monitoring configuration.

### DELETE /api/v1/monitoring/{id}
Removes monitoring configuration.

## AI endpoints

### POST /api/v1/ai/explain
Request:

```json
{
  "finding_id": "uuid"
}
```

The backend constructs the verified context and passes only safe, evidence-backed information to the AI layer. It never invents findings or evidence.

### POST /api/v1/ai/remediation
Accepts a verified finding ID and returns structured remediation guidance based on the verified evidence.

## Pagination contract

```json
{
  "data": [],
  "meta": {
    "page": 1,
    "page_size": 25,
    "total": 78,
    "total_pages": 4
  }
}
```

- page is 1-based
- page_size has a safe maximum (for example, 50)
- no unbounded dataset responses

## Health endpoints

- GET /health: application process is alive
- GET /ready: dependencies and configuration are ready

## OpenAPI

FastAPI will expose OpenAPI documentation at `/docs` and `/openapi.json` during local development. The schema should remain free of secrets and internal implementation details.
