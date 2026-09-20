# CyberShield Monitoring

CyberShield monitoring provides a safe, scheduled re-assessment capability for websites the authenticated business owner already controls. It does not introduce a second scanner or any destructive testing workflow.

## Scope

Monitoring supports:

- enabling and disabling monitoring on an owned website
- safe daily or weekly scheduling
- scheduled re-assessment via the existing scanner engine
- tracking monitoring execution history
- comparing a new scan with the most recent prior scan
- detecting new, resolved, persisted, and changed findings
- comparing risk changes across monitoring cycles

## Scheduling and safety

- Supported schedules are limited to `daily` and `weekly`.
- Monitoring uses the existing ownership checks before creating or updating a target.
- A user cannot configure monitoring for a website they do not own.
- The scheduler prevents duplicate concurrent execution for the same monitoring target.
- Monitoring re-assessments call the same secure scanner orchestration used by standard assessments and keep the existing safety controls active.

## Execution lifecycle

1. A monitoring target is created for an owned business and website.
2. The scheduler checks due targets.
3. Before execution, the service verifies the target is still enabled and within the expected state.
4. A monitoring scan is queued through the existing scan service.
5. The target records the last scan, previous scan, next run time, and last error state.
6. The backend compares the latest scan against the previous monitoring scan to classify changes.

## Change classification

The comparison logic is deterministic and uses the existing fingerprint model:

- `new`: present in the latest scan but absent from the previous scan
- `resolved`: present in the previous scan but absent from the latest scan
- `persistent`: present in both scans without a meaningful change
- `changed`: present in both scans and differs in a meaningful field such as severity, category, description, evidence, or recommendation

## Risk comparison

Each monitoring cycle preserves the previous risk score and the latest risk score. The delta is calculated as:

`current_risk_score - previous_risk_score`

The frontend surfaces the change as increased, decreased, or unchanged without making vague or unsupported claims.

## Monitoring overview and history

Authenticated clients can use `GET /api/v1/monitoring/overview` to retrieve the current state for each owned monitoring target. The response is derived from the latest completed scan and includes website identity, monitoring status, current and previous risk scores, numeric risk delta, finding counts, scan timestamp, and failure state.

`GET /api/v1/monitoring/{target_id}/history` returns scan history in deterministic newest-completion order. It supports bounded `page` and `page_size` parameters and returns pagination metadata. The existing changes endpoint reports deterministic finding-level comparisons for the latest two scans.

The Monitoring page uses these endpoints for overview cards, monitored website rows, risk changes, history, and recent changes. Loading, empty, unavailable-history, partial-data, authentication, and safe error states are rendered without exposing internal exceptions or storage details.

## Authorization and security constraints

Monitoring stays within the same boundaries as the rest of CyberShield:

- authenticated owner only
- resource ownership enforced server-side
- no credential attacks, exploitation, or destructive actions
- scanner safety rules remain active
- rate limits and concurrency safeguards apply
