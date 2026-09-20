# Day 3 Database Schema Design

## Database choice

CyberShield uses PostgreSQL for the MVP. The schema is designed around a modular monolith but can later evolve toward organizations and memberships.

## Core entities

### users
- id: UUID primary key
- email: unique, normalized string
- password_hash: hashed secret, never plaintext
- full_name: nullable or required string
- is_active: boolean
- created_at: timestamp with time zone
- updated_at: timestamp with time zone
- last_login_at: nullable timestamp

Indexes:
- unique index on email
- index on `is_active` when filtering active users

### businesses
- id: UUID primary key
- owner_id: UUID foreign key to users
- name: string
- description: optional text
- created_at: timestamp
- updated_at: timestamp

Indexes:
- index on owner_id
- unique index on `(owner_id, lower(name))` if needed for duplicate prevention

### websites
- id: UUID primary key
- business_id: UUID foreign key
- name: string
- url: string
- normalized_url: string
- status: enum or string
- created_at: timestamp
- updated_at: timestamp
- last_scan_at: nullable timestamp

Indexes:
- index on business_id
- index on normalized_url
- unique constraint on `(business_id, normalized_url)` to prevent duplicate monitoring of the same target

### scans
- id: UUID primary key
- website_id: UUID foreign key
- status: queued/running/completed/failed/cancelled
- scan_type: string
- started_at: nullable timestamp
- completed_at: nullable timestamp
- created_at: timestamp
- error_code: nullable string

Indexes:
- index on website_id
- index on status
- index on created_at

### scan_jobs
- id: UUID primary key
- scan_id: UUID foreign key
- job_type: string
- status: string
- attempt: integer
- started_at: nullable timestamp
- completed_at: nullable timestamp
- error_code: nullable string
- created_at: timestamp

Indexes:
- index on scan_id
- index on status

### findings
- id: UUID primary key
- scan_id: UUID foreign key
- website_id: UUID foreign key
- title: string
- slug: string
- severity: critical/high/medium/low/informational
- category: string
- status: open/acknowledged/resolved/false_positive
- description: text
- evidence: JSONB
- remediation: text
- references: JSONB or related table
- first_seen_at: timestamp
- last_seen_at: timestamp
- resolved_at: nullable timestamp
- created_at: timestamp
- updated_at: timestamp

Indexes:
- index on scan_id
- index on website_id
- index on severity
- index on status
- partial index for `status = 'open'`

### reports
- id: UUID primary key
- business_id: UUID foreign key
- title: string
- status: draft/ready/generated
- generated_at: nullable timestamp
- created_at: timestamp
- updated_at: timestamp
- artifact_path: nullable string

### monitoring_targets
- id: UUID primary key
- website_id: UUID foreign key
- schedule: string
- status: active/inactive
- last_checked_at: nullable timestamp
- next_check_at: nullable timestamp
- created_at: timestamp
- updated_at: timestamp

Indexes:
- index on website_id
- index on next_check_at

### security_events
- id: UUID primary key
- user_id: nullable UUID
- website_id: nullable UUID
- event_type: string
- severity: string
- metadata: JSONB
- created_at: timestamp

Indexes:
- index on created_at
- index on event_type

## Relationship plan

```text
User 1 -> N Business
Business 1 -> N Website
Website 1 -> N Scan
Scan 1 -> N ScanJob
Scan 1 -> N Finding
Website 1 -> N MonitoringTarget
Website 1 -> N SecurityEvent
Business 1 -> N Report
```

## Constraints

- foreign keys must be enforced at the database layer
- unique email required
- explicit status enum or CHECK constraint required for valid lifecycle states
- timestamps stored in UTC
- `normalized_url` must be generated from sanitized input before storage

## Soft delete

This phase does not require a deep retention system. Security-sensitive records should eventually support retention and archival policies, but the MVP keeps the model simple and auditable.

## Future path

The schema is deliberately aligned with a future organization model where `User -> Organization -> Membership -> Business/Assets` can be introduced without breaking existing ownership semantics.
