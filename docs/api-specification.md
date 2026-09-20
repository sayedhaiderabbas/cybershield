# Future API Specification

All endpoints below are documentation only. They are not implemented on Day 1. Unless noted otherwise, authenticated endpoints require the current user's secure session or token and return JSON.

## Conventions

Successful resource responses use a stable object such as `{ "data": {...} }`; collection responses use `{ "data": [...], "meta": {...} }`. Errors use `{ "error": { "code": "...", "message": "...", "details": {...} } }` without sensitive internals.

## Authentication

### `POST /api/auth/register`

- **Purpose:** Create a user account.
- **Authentication:** None.
- **Request body:** `{ "email": "string", "password": "string", "name": "string" }`.
- **Response:** `201 { "data": { "user": { "id": "string", "email": "string", "name": "string" } } }`.
- **Errors:** `400` validation error, `409` account already exists, `429` rate limit.

### `POST /api/auth/login`

- **Purpose:** Authenticate a user.
- **Authentication:** None.
- **Request body:** `{ "email": "string", "password": "string" }`.
- **Response:** `200 { "data": { "user": {...}, "session": { "expiresAt": "timestamp" } } }`.
- **Errors:** `400` validation error, `401` invalid credentials, `429` rate limit.

### `POST /api/auth/logout`

- **Purpose:** End the current session.
- **Authentication:** Required.
- **Request body:** None.
- **Response:** `204` no content.
- **Errors:** `401` unauthenticated.

### `GET /api/auth/me`

- **Purpose:** Return the current user.
- **Authentication:** Required.
- **Request body:** None.
- **Response:** `200 { "data": { "user": {...} } }`.
- **Errors:** `401` unauthenticated.

## Businesses

### `POST /api/businesses`

- **Purpose:** Create a business.
- **Authentication:** Required.
- **Request body:** `{ "name": "string", "industry": "string", "contact": {...} }`.
- **Response:** `201 { "data": { "business": {...} } }`.
- **Errors:** `400` validation error, `401` unauthenticated, `409` duplicate conflict.

### `GET /api/businesses`

- **Purpose:** List businesses visible to the current user.
- **Authentication:** Required.
- **Request body:** None.
- **Response:** `200 { "data": [business], "meta": {...} }`.
- **Errors:** `401` unauthenticated.

### `GET /api/businesses/{id}`

- **Purpose:** Get one authorized business.
- **Authentication:** Required.
- **Request body:** None.
- **Response:** `200 { "data": { "business": {...} } }`.
- **Errors:** `401` unauthenticated, `404` not found or not authorized.

### `PATCH /api/businesses/{id}`

- **Purpose:** Update an authorized business.
- **Authentication:** Required.
- **Request body:** Partial business fields.
- **Response:** `200 { "data": { "business": {...} } }`.
- **Errors:** `400` validation error, `401` unauthenticated, `404` not found.

## Websites

### `POST /api/websites`

- **Purpose:** Add an authorized website to a business.
- **Authentication:** Required.
- **Request body:** `{ "businessId": "string", "url": "string", "authorizationConfirmed": true }`.
- **Response:** `201 { "data": { "website": {...} } }`.
- **Errors:** `400` invalid or unauthorized target, `401` unauthenticated, `404` business not found, `409` duplicate.

### `GET /api/websites`

- **Purpose:** List authorized websites.
- **Authentication:** Required.
- **Request body:** None.
- **Response:** `200 { "data": [website], "meta": {...} }`.
- **Errors:** `401` unauthenticated.

### `GET /api/websites/{id}`

- **Purpose:** Get one authorized website.
- **Authentication:** Required.
- **Request body:** None.
- **Response:** `200 { "data": { "website": {...} } }`.
- **Errors:** `401` unauthenticated, `404` not found.

### `DELETE /api/websites/{id}`

- **Purpose:** Remove an authorized website.
- **Authentication:** Required.
- **Request body:** None.
- **Response:** `204` no content.
- **Errors:** `401` unauthenticated, `404` not found.

## Scans

### `POST /api/scans`

- **Purpose:** Queue a safe assessment for an authorized website.
- **Authentication:** Required.
- **Request body:** `{ "websiteId": "string", "checks": ["https", "tls", "headers", "cookies", "dns", "technology"] }`.
- **Response:** `202 { "data": { "scan": { "id": "string", "status": "queued" } } }`.
- **Errors:** `400` invalid request, `401` unauthenticated, `403` target not authorized, `409` scan unavailable, `429` rate limit.

### `GET /api/scans/{id}`

- **Purpose:** Get scan metadata and result summary.
- **Authentication:** Required.
- **Request body:** None.
- **Response:** `200 { "data": { "scan": {...} } }`.
- **Errors:** `401` unauthenticated, `404` not found.

### `GET /api/scans/{id}/status`

- **Purpose:** Get scan lifecycle status and safe progress information.
- **Authentication:** Required.
- **Request body:** None.
- **Response:** `200 { "data": { "id": "string", "status": "queued|running|completed|failed", "progress": 0 } }`.
- **Errors:** `401` unauthenticated, `404` not found.

### `GET /api/scans/{id}/findings`

- **Purpose:** List findings produced by a scan.
- **Authentication:** Required.
- **Request body:** None.
- **Response:** `200 { "data": [finding], "meta": {...} }`.
- **Errors:** `401` unauthenticated, `404` not found.

## Findings

### `GET /api/findings`

- **Purpose:** List authorized findings with filters.
- **Authentication:** Required.
- **Request body:** None; query parameters may filter severity, status, business, or website.
- **Response:** `200 { "data": [finding], "meta": {...} }`.
- **Errors:** `401` unauthenticated, `400` invalid filter.

### `GET /api/findings/{id}`

- **Purpose:** Get evidence-backed finding details.
- **Authentication:** Required.
- **Request body:** None.
- **Response:** `200 { "data": { "finding": {...} } }`.
- **Errors:** `401` unauthenticated, `404` not found.

### `PATCH /api/findings/{id}`

- **Purpose:** Update an authorized finding workflow status.
- **Authentication:** Required.
- **Request body:** `{ "status": "open|acknowledged|in_progress|resolved" }`.
- **Response:** `200 { "data": { "finding": {...} } }`.
- **Errors:** `400` invalid status, `401` unauthenticated, `404` not found.

## Reports

### `POST /api/reports`

- **Purpose:** Queue a report for an authorized business and scan.
- **Authentication:** Required.
- **Request body:** `{ "businessId": "string", "scanId": "string", "format": "pdf" }`.
- **Response:** `202 { "data": { "report": { "id": "string", "status": "queued" } } }`.
- **Errors:** `400` invalid request, `401` unauthenticated, `404` resource not found, `429` rate limit.

### `GET /api/reports`

- **Purpose:** List authorized reports.
- **Authentication:** Required.
- **Request body:** None.
- **Response:** `200 { "data": [report], "meta": {...} }`.
- **Errors:** `401` unauthenticated.

### `GET /api/reports/{id}`

- **Purpose:** Get report status and download metadata.
- **Authentication:** Required.
- **Request body:** None.
- **Response:** `200 { "data": { "report": {...} } }`.
- **Errors:** `401` unauthenticated, `404` not found.

## AI

### `POST /api/ai/explain`

- **Purpose:** Explain a verified finding and its business impact.
- **Authentication:** Required.
- **Request body:** `{ "findingId": "string", "audience": "business_owner|technical" }`.
- **Response:** `200 { "data": { "findingId": "string", "explanation": "string", "groundedIn": ["evidence-id"] } }`.
- **Errors:** `400` invalid request, `401` unauthenticated, `404` finding not found, `429` rate limit, `502` provider failure.

### `POST /api/ai/remediation`

- **Purpose:** Generate remediation guidance for a verified finding.
- **Authentication:** Required.
- **Request body:** `{ "findingId": "string", "context": "string" }`.
- **Response:** `200 { "data": { "findingId": "string", "checklist": ["string"], "verification": ["string"] } }`.
- **Errors:** `400` invalid request, `401` unauthenticated, `404` finding not found, `429` rate limit, `502` provider failure.
