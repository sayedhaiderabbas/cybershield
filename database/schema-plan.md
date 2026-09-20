# Database Schema Plan

This is a conceptual plan only. No database or migrations are implemented on Day 1.

## Entities

### `users`

Account identity and authentication metadata. Stores a secure password hash or an external identity reference, never a plaintext password.

### `businesses`

Business profile and ownership metadata. A user can own or be authorized for one or more businesses.

### `websites`

Authorized website targets belonging to a business. Stores normalized URL information, authorization confirmation, and lifecycle metadata.

### `scans`

A requested assessment and its lifecycle, target reference, selected checks, timestamps, summary, and score reference.

### `scan_jobs`

Asynchronous execution records for queued work, including status, attempts, timing, and safe error state.

### `findings`

Evidence-backed observations linked to a scan and target, with title, category, severity, description, evidence, recommendation, workflow status, and timestamps.

### `reports`

Generated report metadata, source scan/business references, generation status, format, and secure artifact location.

### `subscriptions`

Future plan, billing status, entitlement, and usage metadata. This is not required for the first functional slice.

### `monitoring_targets`

Scheduled, authorized website checks, including schedule, latest result reference, and change-detection state.

### `security_events`

Security-relevant audit events such as authentication, authorization, scan, report, and configuration actions, with privacy-aware metadata.

## Relationships

```text
User
│
└── Business
    │
    ├── Website
    │   ├── Scan
    │   │   └── Findings
    │   ├── Reports
    │   └── Monitoring
    │
    └── Subscription
```

- A user can have many businesses through ownership or membership.
- A business has many websites.
- A website has many scans.
- A scan has many findings.
- Reports belong to a business and reference one or more scan results.
- Monitoring targets belong to a business and reference a website.
- Security events reference the relevant user, business, or resource where appropriate.
- Subscriptions belong to the account or business billing owner according to the eventual business model.

## Integrity and Isolation Rules

- Use stable unique identifiers for externally addressable resources.
- Enforce foreign keys and required ownership relationships.
- Scope every query by authorized account or business context.
- Keep evidence and timestamps immutable after a scan result is finalized; workflow status changes are auditable.
- Avoid storing secrets, raw credentials, or unnecessary sensitive target data.
