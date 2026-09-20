# CyberShield API Notes

## Authentication

All protected endpoints require a bearer token.

- Authorization: `Bearer <token>`
- Auth requirement is enforced by the reusable auth dependency.

## Security overview

### GET /api/v1/security/overview

Returns the current posture for the authenticated owner�s businesses and websites.

Request:

- Requires authenticated bearer token
- Read-only

Response:

```json
{
  "data": {
    "score": 68,
    "risk_model_version": "1.0",
    "severity_counts": {
      "critical": 0,
      "high": 1,
      "medium": 2,
      "low": 3,
      "info": 4
    },
    "open_finding_count": 6,
    "affected_website_count": 2,
    "top_risk_drivers": ["TLS certificate renewal", "Cookie security"],
    "latest_scan_status": "completed",
    "latest_scan_id": "<scan-id>"
  },
  "meta": {
    "request_id": "<owner-id>"
  }
}
```

## Findings

### GET /api/v1/findings

Returns findings owned by the authenticated user. Supports safe filters and pagination.

Query parameters:

- `page` (default 1)
- `page_size` (default 20, max 100)
- `severity` (`info|low|medium|high|critical`)
- `status` (`open|acknowledged|resolved`)
- `category` (exact category value)
- `website_id` (owned website id)
- `scan_id` (owned scan id)
- `sort_by` (`last_seen|created_at|severity`)
- `order` (`asc|desc`)

Response:

```json
{
  "data": [
    {
      "id": "<finding-id>",
      "scan_id": "<scan-id>",
      "website_id": "<website-id>",
      "title": "Missing HSTS",
      "slug": "missing-hsts",
      "fingerprint": "<stable-id>",
      "severity": "medium",
      "priority": "normal",
      "category": "security_headers",
      "description": "The HTTPS response does not include HSTS.",
      "evidence": "[]",
      "recommendation": "Add a Strict-Transport-Security policy.",
      "status": "open",
      "references": "CS-HSTS-001",
      "first_seen_at": "2026-09-15T00:00:00Z",
      "last_seen_at": "2026-09-15T00:00:00Z",
      "occurrence_count": 1,
      "resolved_at": null,
      "created_at": "2026-09-15T00:00:00Z",
      "updated_at": "2026-09-15T00:00:00Z"
    }
  ],
  "meta": {
    "page": 1,
    "page_size": 20,
    "total": 1,
    "total_pages": 1
  }
}
```

### GET /api/v1/findings/{finding_id}

Returns one finding with the same owner-safe validation used by list queries.

### PATCH /api/v1/findings/{finding_id}

Allowed payload:

```json
{
  "status": "acknowledged"
}
```

Only user-editable fields are accepted. Protected fields such as severity, scan ownership, evidence, fingerprint, and timestamps are server-controlled and cannot be modified via this route.

## Reports

### POST /api/v1/reports

Creates a report snapshot from real CyberShield data for the authenticated business owner.

Request:

```json
{
  "business_id": "<business-id>",
  "website_id": "<optional-website-id>",
  "scan_id": "<optional-scan-id>",
  "title": "Quarterly security assessment",
  "report_type": "security_assessment"
}
```

Authentication:

- Requires a bearer token
- Only business owners can generate reports for their own business
- Client-supplied scores, findings, or evidence are ignored; the server reconstructs a snapshot from the database

Response:

```json
{
  "data": {
    "id": "<report-id>",
    "business_id": "<business-id>",
    "requested_by": "<user-id>",
    "website_id": "<website-id>",
    "scan_id": "<scan-id>",
    "report_type": "security_assessment",
    "title": "Quarterly security assessment",
    "status": "completed",
    "risk_score_snapshot": 68,
    "risk_model_version": "1.0",
    "generated_at": "2026-09-17T00:00:00Z",
    "artifact_path": "generated/<report-id>.pdf",
    "metadata": {
      "risk_score": 68,
      "findings": []
    }
  },
  "meta": {
    "request_id": "<report-id>"
  }
}
```

### GET /api/v1/reports

Returns reports owned by the authenticated user with pagination metadata.

### GET /api/v1/reports/{report_id}

Returns a report detail payload with report metadata, risk snapshot, and findings included in the stored snapshot.

### GET /api/v1/reports/{report_id}/download

Downloads the generated PDF for an owned report.

- Requires authentication and report ownership
- Returns `application/pdf`
- Uses a generated filename safe for the application storage directory
- Prevents arbitrary file access

## Security posture

### GET /api/v1/security/posture

Returns the authenticated business owner's posture summary built from the real scan, finding, monitoring, risk, and alert data already stored in CyberShield.

Response shape:

```json
{
  "data": {
    "summary": {
      "risk_score": 61,
      "previous_risk_score": 72,
      "risk_delta": -11,
      "assessment_status": "assessed",
      "business_name": "Example Business"
    },
    "findings": {
      "open": 8,
      "critical": 1,
      "high": 2,
      "medium": 3,
      "low": 2,
      "info": 0,
      "acknowledged": 1
    },
    "alerts": {
      "total_open": 3,
      "critical": 1,
      "high": 1,
      "monitoring_failures": 0
    },
    "monitoring": {
      "active_targets": 2,
      "last_assessment_at": "2026-09-17T00:00:00Z",
      "next_assessment_at": "2026-09-18T00:00:00Z",
      "failed_assessments": 0,
      "recent_changes": []
    },
    "trends": {
      "history": [{"date": "2026-09-16T00:00:00Z", "risk_score": 72}, {"date": "2026-09-17T00:00:00Z", "risk_score": 61}],
      "status": "available"
    },
    "priorities": [],
    "categories": [],
    "metadata": {
      "business_name": "Example Business",
      "website_count": 2,
      "assessment_count": 4,
      "latest_scan_id": "<scan-id>"
    },
    "executive_summary": "Your latest assessment identified 8 open findings. One critical finding requires attention. The risk score decreased by 11 points compared with the previous assessment."
  },
  "meta": {
    "request_id": "<owner-id>"
  }
}
```

The posture endpoint is server-side scoped to the authenticated owner and never trusts client input for ownership checks.

## Security activity and audit log

### GET /api/v1/audit-events

Returns append-only security activity events for the authenticated owner, scoped to businesses and resources they can access.

Query parameters:

- `page` (default 1)
- `page_size` (default 20, max 100)
- `event_type` (normalized value such as `AUTHENTICATION`, `WEBSITE`, `SCANNING`, `FINDINGS`, `MONITORING`, `REPORTS`, `REMEDIATION`)
- `resource_type` (e.g. `website`, `scan`, `finding`, `report`, `monitoring`)
- `resource_id` (owned resource id)
- `outcome` (`SUCCESS` or `FAILURE`)
- `start_date` (ISO-8601 UTC date)
- `end_date` (ISO-8601 UTC date)

Response:

```json
{
  "data": [
    {
      "id": "<event-id>",
      "actor_user_id": "<user-id>",
      "business_id": "<business-id>",
      "event_type": "WEBSITE",
      "action": "WEBSITE_CREATED",
      "resource_type": "website",
      "resource_id": "<website-id>",
      "outcome": "SUCCESS",
      "severity": "info",
      "message": "Website added",
      "request_id": "<request-id>",
      "details": "{\"name\":\"Example site\"}",
      "created_at": "2026-09-18T00:00:00Z"
    }
  ],
  "meta": {
    "page": 1,
    "page_size": 20,
    "total": 1,
    "total_pages": 1,
    "request_id": "<request-id>"
  }
}
```

The API enforces authentication and ownership checks at the server before returning records. Results are ordered deterministically by `created_at DESC, id DESC`.

### GET /api/v1/audit/events

Compatibility alias for the audit event listing endpoint. It supports the same filters, ordering, pagination, and authorization checks as `/api/v1/audit-events`.

No public create, update, or delete route is exposed for historical audit records. The audit log is append-only and intentionally read-only from normal application endpoints.

## Monitoring

### GET /api/v1/monitoring

Returns monitoring targets available to the authenticated owner. Each item includes the website scope, current schedule, next run, and execution metadata.

### POST /api/v1/monitoring

Creates monitoring for an owned website.

Request:

```json
{
  "business_id": "<business-id>",
  "website_id": "<website-id>",
  "enabled": true,
  "schedule": "daily"
}
```

### PATCH /api/v1/monitoring/{target_id}

Allows a user to pause or resume monitoring and update the supported schedule.

### GET /api/v1/monitoring/{target_id}/history

Returns recent monitoring execution history and risk movement.

### GET /api/v1/monitoring/{target_id}/changes

Returns comparison records for new, resolved, persistent, and changed findings derived from the latest scan and the prior monitoring baseline.

## Alerts

### GET /api/v1/alerts

Returns alerts for the authenticated business owner. Supports filtering and pagination.

Query parameters:

- `page` (default 1)
- `page_size` (default 20, max 100)
- `status` (`open|acknowledged|resolved`)
- `severity` (`info|low|medium|high|critical`)
- `alert_type` (`NEW_HIGH_FINDING`, `NEW_CRITICAL_FINDING`, `RISK_SCORE_INCREASE`, `SIGNIFICANT_SECURITY_CHANGE`, `MONITORING_FAILURE`)
- `website_id` (owned website id)

Response:

```json
{
  "data": [
    {
      "id": "<alert-id>",
      "business_id": "<business-id>",
      "website_id": "<website-id>",
      "monitoring_id": "<monitoring-id>",
      "scan_id": "<scan-id>",
      "finding_id": "<finding-id>",
      "alert_type": "NEW_HIGH_FINDING",
      "severity": "high",
      "title": "TLS certificate warning",
      "message": "New high severity finding detected: TLS certificate warning.",
      "status": "open",
      "deduplication_key": "<stable-key>",
      "alert_metadata": "{\"fingerprint\":\"...\"}",
      "created_at": "2026-09-17T00:00:00Z",
      "updated_at": "2026-09-17T00:00:00Z",
      "acknowledged_at": null,
      "resolved_at": null,
      "website_name": "Example site",
      "finding_reference": "CS-HSTS-001",
      "safe_evidence": ["{\"header\":\"Strict-Transport-Security\",\"present\":false}"],
      "previous_risk_score": null,
      "current_risk_score": 42,
      "risk_delta": null
    }
  ],
  "meta": {
    "page": 1,
    "page_size": 20,
    "total": 1,
    "total_pages": 1
  }
}
```

### GET /api/v1/alerts/{alert_id}

Returns one alert for the authenticated user, with the same ownership validation as other protected resources.
The detail response adds the owned website name, safe evidence/reference, and previous/current risk score plus delta when available.

### PATCH /api/v1/alerts/{alert_id}

Allowed payload:

```json
{
  "status": "acknowledged"
}
```

Valid lifecycle transitions are limited to:

- `open -> acknowledged`
- `open -> resolved`
- `acknowledged -> resolved`

Protected fields cannot be modified by the client. The backend rejects invalid transitions and prevents direct edits to alert type, severity, business, website, finding, scan, deduplication key, or timestamp metadata.

### GET /api/v1/alerts/unread-count

Returns the count of open alerts for the current user.

## AI assistance

### POST /api/v1/ai/explain

Returns evidence-grounded explanation data for an owned finding.

Request:

```json
{
  "finding_id": "<finding-id>"
}
```

Authentication:

- Requires a bearer token
- The backend loads the actual finding from storage and verifies ownership before responding
- Client-supplied evidence, severity, and risk values are ignored and rejected by schema validation

Response:

```json
{
  "data": {
    "summary": "The site is missing the required HSTS policy.",
    "why_it_matters": "This finding indicates a weaker HTTPS posture and increased browser exposure to downgrade attacks.",
    "verified_evidence": [
      "Strict-Transport-Security: missing"
    ],
    "remediation_steps": [
      "Add a Strict-Transport-Security header with an appropriate max-age and includeSubDomains policy."
    ],
    "verification_steps": [
      "Re-run a verification scan after the configuration update."
    ],
    "limitations": "AI provider unavailable — showing deterministic remediation guidance based on verified CyberShield evidence."
  },
  "meta": {
    "request_id": "<finding-id>"
  }
}
```

Errors:

- 401 if the caller is unauthenticated
- 403/404 if the finding is not owned by the authenticated user
- 422 if the request payload is invalid
- 429 if the user exceeds the AI request rate limit

### POST /api/v1/ai/remediation

Returns structured, evidence-grounded remediation guidance for an owned finding.

Request:

```json
{
  "finding_id": "<finding-id>"
}
```

The AI layer is not permitted to change scanner results, modify risk, or execute commands. It can only explain and recommend. If the provider is unavailable, CyberShield returns deterministic remediation guidance derived from the stored finding metadata.

## Scan endpoints

### POST /api/v1/scans

Creates a scan for an owned website.

### GET /api/v1/scans

Returns scans for the authenticated user�s owned websites.

### GET /api/v1/scans/{scan_id}

Returns the scan record and fields stored by the scanner engine.

## Error handling

The API returns the project�s centralized error contract for:

- 401 Unauthorized
- 403 Forbidden
- 404 Not Found
- 409 Conflict
- 422 Validation Error
- 500 Internal Error

## Ownership rules

A user can only inspect or modify resources that belong to their own business or website. Cross-business access is rejected.
