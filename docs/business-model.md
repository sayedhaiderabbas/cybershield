# CyberShield Business Model

## Purpose

Day 22 adds an informational Business Model page for explaining how CyberShield could be packaged as a cybersecurity SaaS product. It is a product-value and pricing layer, not a billing system.

## Product value

CyberShield's implemented workflow connects:

1. Authorized website discovery
2. Security scanning
3. Deterministic findings and risk scoring
4. Finding explanation and bounded AI guidance
5. Remediation tracking
6. Verification
7. Monitoring comparisons
8. Reports and security activity

The page describes these capabilities using the existing product behavior. It does not claim guaranteed protection, complete vulnerability detection, autonomous remediation, certification, or real-time protection.

## Conceptual plans

The centralized frontend configuration defines three conceptual tiers:

- **Community**: evaluation and learning for individual users and developers.
- **Pro**: a practical workflow for startups and small teams.
- **Business**: broader operational visibility for security teams and consultants.

Each plan describes intended audiences, feature packaging, and conceptual usage limits such as monitored websites, scan volume, reports, AI assistance, and monitoring cadence.

These limits are product packaging concepts only. They are not enforced entitlements.

## Target customers

The intended customer segments represented in the UI are:

- developers
- startups
- security teams
- security consultants and agencies

These are potential customer profiles, not claims about current customers.

## Revenue model

The conceptual model is subscription SaaS. Potential future revenue could come from recurring plan tiers, higher usage allowances, additional monitored assets, and team/business packaging.

No revenue, customer counts, ARR, MRR, market share, or business performance metrics are represented.

## Current limitations

- Pricing is informational.
- No checkout or payment processing exists.
- No subscriptions, invoices, billing webhooks, or payment credentials are stored.
- No plan entitlement enforcement exists.
- Product limits shown on the page are separate from current technical implementation limits.

## Implementation boundary

Day 22 is frontend-only. The page uses the existing authenticated app shell and a centralized read-only TypeScript configuration. No backend route, database migration, payment integration, or authorization rule was added.
