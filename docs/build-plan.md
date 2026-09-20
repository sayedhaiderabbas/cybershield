# 30-Day Build Plan

## DAY 1 — Foundation and scope

Create the isolated project, product scope, requirements, architecture, security model, API plan, database plan, demo structure, and repository foundation.

## DAY 2 — UX/UI design

Define user flows, information architecture, wireframes, and visual direction.

## DAY 3 — Technical specification

Finalize technology choices, contracts, data validation, job lifecycle, and implementation details.

## DAY 4 — Frontend foundation

Create the frontend application shell and shared UI foundations.

## DAY 5 — Landing page

Build the public product introduction and conversion path.

## DAY 6 — Authentication

Implement registration, login, logout, current user, protected routes, and secure session handling.

## DAY 7 — Database

Implement the planned schema, migrations, data access, and isolation tests.

## DAY 8 — Business and website onboarding

Implement business creation, website management, URL validation, and authorization confirmation.

## DAY 9 — Scanner engine

Implement safe, authorized, non-destructive initial checks with SSRF and resource protections.

## DAY 10 — Findings engine

Normalize observations into evidence-backed findings and lifecycle states.

## DAY 11 — Risk engine

Implement documented severity, prioritization, and explainable health-score rules.

## DAY 12 — Scan API

Connect scan creation, queueing, status, and findings retrieval through the API.

## DAY 13 — Live scan progress

Expose safe progress updates and clear queued, running, completed, and failed states.

## DAY 14 — Dashboard

Display score, severity distribution, recent scans, findings, priorities, and website status.

## DAY 15 — Findings interface

Add finding lists, filters, sorting, and workflow status.

Completed implementation scope for the Day 15 findings UI:
- Real backend findings list integration via the existing `/api/v1/findings` contract.
- Search against the live data for titles, categories, websites, descriptions, and finding identifiers.
- Severity and status filters using supported values returned by the backend model.
- Sort order support using the existing API fields (`last_seen`, `created_at`, `severity`) with ascending/descending direction.
- Pagination respecting the server-provided page metadata.
- Loading, empty, and error states without fake or placeholder data.
- Minimal navigation to the existing finding detail route without implementing Day 16 functionality.
- Security boundaries preserved by using the existing authenticated API client and not bypassing business or ownership checks.

## DAY 16 — Finding details

Show evidence, impact, recommendations, methodology, and verification context.

## DAY 17 — AI assistant

Add grounded explanations and remediation guidance for verified findings.

## DAY 18 — AI quality and security

Test grounding, refusal behavior, data minimization, and no-false-claim safeguards.

## DAY 19 — PDF reports

Generate professional reports from stored, verified data.

## DAY 20 — Report center

Add report requests, status, listing, and secure retrieval.

## DAY 21 — Monitoring

Add schedules, re-checks, comparison, meaningful change detection, and indicators.

## DAY 22 — Business model

Validate packaging, usage limits, pricing hypotheses, and customer value.

## DAY 23 — Scalability

Review job capacity, data growth, isolation, observability, and future service boundaries.

## DAY 24 — Security hardening

Perform focused threat modeling, abuse testing, dependency review, and security fixes.

## DAY 25 — Testing

Complete unit, integration, end-to-end, security, and controlled scanner tests.

## DAY 26 — Deployment

Prepare reproducible deployment, environment configuration, monitoring, and rollback.

## DAY 27 — Controlled demo environment

Prepare safe authorized targets and reliable seeded data for demonstration.

## DAY 28 — Product polish

Improve usability, accessibility, copy, loading states, errors, and visual consistency.

## DAY 29 — Pitch and video

Prepare the pitch, demo recording, product narrative, and submission assets.

## DAY 30 — Final QA and Devpost submission

Run final checks, verify the demo, finalize documentation, and submit to Devpost.
