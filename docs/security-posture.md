# Security Posture Overview

CyberShield's Day 12 posture layer aggregates real data already stored by the platform. It does not calculate a separate AI-driven score or invent vulnerabilities. The posture view draws from the authenticated business, website, scan, finding, monitoring, and alert data already verified by the scanner and monitoring system.

## Data sources

The posture summary reuses the authoritative sources already used by the application:

- website and business ownership
- latest completed scan and previous scan baseline
- deterministic risk score from the Day 7 risk engine
- open and acknowledged findings from the existing findings lifecycle
- user-owned monitoring targets and their failure counts
- open alert data produced by the Day 11 alert service

## Aggregation rules

The posture API derives counts and trend values from real records without duplicating the scanner or risk engine.

- current risk score: latest completed scan risk_score, or the deterministic risk calculation from active findings if a risk score is missing
- previous risk score: immediately earlier completed scan risk_score for the same business websites
- risk delta: current score minus previous score
- findings: status in `open` or `acknowledged` is counted as active; resolved findings are excluded
- alerts: only open alerts count toward the posture summary
- monitoring: active targets are enabled monitoring records; disabled targets remain visible but excluded from the active count
- trend data: includes only real historical scan scores from the business's owned websites

## Priority rules

Priority ordering is deterministic and based on verified data:

1. open critical findings
2. open high findings
3. material risk increase from previous assessment
4. monitoring failures
5. significant security changes

Each priority references the source object already stored in the database and remains tied to a real finding, alert, or monitoring record.

## Empty and limited data states

When no assessments, findings, or monitoring records exist, the posture response returns explicit empty states instead of fabricated numbers. The API returns `no-data` or `limited-history` states where appropriate, and the frontend displays a clear explanation rather than a fake dashboard value.

## Authorization

The posture endpoint is scoped to the authenticated owner only. It joins on the owning business and rejects access to other users' records. It never trusts client-supplied business IDs or website IDs for access control.

## Limitations

The posture view summarises verified data and makes it easier for a small business owner to understand their current posture. It does not independently determine whether a site is fully secure, and it does not replace the existing scanner, risk engine, monitoring system, or alerting logic.
