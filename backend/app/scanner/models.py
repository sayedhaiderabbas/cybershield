from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


SEVERITY_POINTS = {
    'info': 0,
    'low': 2,
    'medium': 4,
    'high': 7,
    'critical': 10,
}


@dataclass
class CheckResult:
    check_id: str
    title: str
    category: str
    severity: str
    description: str
    evidence: dict[str, Any] = field(default_factory=dict)
    recommendation: str = ''

    def as_finding_payload(self, scan_id: str, website_id: str, *, slug: str | None = None) -> dict[str, Any]:
        normalized_slug = slug or self.check_id.lower().replace('_', '-')
        return {
            'scan_id': scan_id,
            'website_id': website_id,
            'title': self.title,
            'category': self.category,
            'severity': self.severity,
            'description': self.description,
            'evidence': self.evidence,
            'recommendation': self.recommendation,
            'slug': normalized_slug,
        }


def calculate_risk_score(findings: list[dict[str, Any]]) -> int:
    score = sum(SEVERITY_POINTS.get(str(item.get('severity', 'info')).lower(), 0) for item in findings)
    return min(100, score)
