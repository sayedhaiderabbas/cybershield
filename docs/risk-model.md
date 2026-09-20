# CyberShield Risk Model

## Purpose

The CyberShield risk model converts verified scanner findings into a transparent, deterministic security posture score. The goal is to help a small business understand current exposure without implying a website is perfectly secure or compromised.

## Model version

- `risk_model_version = "1.0"`
- The version is returned by the security overview API to make report comparison explicit.

## Score range

- Range: 0 to 100
- Higher values indicate a weaker current posture based on observed, verified findings.
- The score is a posture indicator, not proof of a successful exploit or absolute security.

## Severity weights

| Severity | Weight |
|---|---:|
| info | 0 |
| low | 2 |
| medium | 4 |
| high | 7 |
| critical | 10 |

## Formula

The current implementation sums weighted severity values for every persisted finding in the authenticated owner's scope and then caps the result at 100. The security overview separately reports open and acknowledged findings. Resolved findings remain in the score until a future scanner/history policy explicitly removes or reclassifies them.

- For each finding, base weight = severity weight
- Recurrence adds a small bounded adjustment for repeated observations of the same fingerprint
- Duplicate observations do not inflate the score without limit

```text
score = min(100, sum(weight(severity) + capped recurrence adjustment))
```

The recurrence adjustment is bounded so repeated observations cannot dominate a single serious issue.

## Business aggregation

Business-level overview uses the findings currently visible for the authenticated owner’s owned websites. The score is a deterministic aggregation of that business’s findings, not a mix of unrelated or historic data sources.

The system does not combine a newer scan from one website with an older scan from another unless that is the same business-owned assessment scope and the data is explicitly part of the selected view.

## Top risk drivers

Top risk drivers are derived deterministically from the title of findings observed across the owner’s websites:

1. Count repeated findings by title
2. Rank by recurrence descending
3. Break ties alphabetically
4. Return the top five titles

This preserves explainability and avoids arbitrary ordering from database query order.

## Deduplication and history

The same issue is identified by a stable fingerprint using the website, check identifier, and category. Repeated observations of the same finding update the `occurrence_count`, `last_seen_at`, and `last_seen_at` history rather than creating a second unrelated issue record.

## Limitations

- The score reflects the checks performed by the scanner and does not prove that no other issues exist.
- Findings are evidence-based but not a complete threat model.
- The score is designed for understandable business reporting, not a multi-factor security rating system.
