# CyberShield Conceptual Architecture

CyberShield uses a modular architecture that is understandable for a solo developer and can evolve into a production SaaS. Day 1 documents the design only; no components are implemented yet.

## Core Flow

```text
Frontend
↓
Backend API
↓
Scan Job System
↓
Scanner
↓
Findings Engine
↓
Risk Engine
↓
Database
```

## Component Responsibilities

- **Frontend:** Provides the user experience for account, business, website, scan, finding, report, and monitoring workflows.
- **Backend API:** Authenticates requests, authorizes business access, validates input, coordinates domain services, and returns stable API responses.
- **Scan Job System:** Queues and tracks potentially long-running scans so requests remain responsive and work can be retried safely.
- **Scanner:** Performs only approved, safe, non-destructive checks against authorized public targets, with strict timeouts and resource limits.
- **Findings Engine:** Converts raw check observations into normalized, evidence-backed findings with consistent categories and statuses.
- **Risk Engine:** Applies documented scoring and prioritization rules to findings and produces a transparent security health score.
- **Database:** Stores users, businesses, websites, scan lifecycle data, findings, reports, monitoring configuration, and security events.

## AI Architecture

```text
Scanner
↓
Verified Finding
↓
AI Explanation / Remediation
↓
User
```

AI receives verified finding context, explains business impact, and suggests remediation. It is not the source of truth for detection and must not invent evidence, vulnerabilities, or remediation completion.

## Reporting

```text
Database
↓
Report Generator
↓
PDF Report
```

The report generator renders stored business and scan data, including methodology and evidence, into a professional artifact.

## Monitoring

```text
Scheduler
↓
Scan Job
↓
Scanner
↓
Compare Previous Results
↓
Change Detection
↓
Notification / Dashboard
```

Monitoring reuses the safe scan path, compares meaningful configuration results, and surfaces changes without turning into continuous offensive testing.

## Design Decisions

- Start as a modular application with clear boundaries rather than complex microservices.
- Keep detection, scoring, AI assistance, reporting, and monitoring logically separate.
- Make evidence and documented rules the source of truth.
- Isolate every business and target through authorization checks.
- Allow asynchronous jobs for scans and reports without requiring premature infrastructure.
