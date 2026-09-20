from __future__ import annotations

from collections import Counter

from sqlalchemy.orm import Session

from app.models.entities import Business, Finding, Scan, Website

RISK_MODEL_VERSION = '1.0'
SEVERITY_WEIGHTS = {'info': 0, 'low': 2, 'medium': 4, 'high': 7, 'critical': 10}


class RiskService:
    def __init__(self, session: Session) -> None:
        self.session = session

    def overview_for_user(self, owner_id: str) -> dict:
        website_ids = [item.id for item in self.session.query(Website).join(Website.business).filter(Website.business.has(owner_id=owner_id)).all()]
        if not website_ids:
            return {
                'score': 0,
                'risk_model_version': RISK_MODEL_VERSION,
                'severity_counts': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0},
                'open_finding_count': 0,
                'affected_website_count': 0,
                'top_risk_drivers': [],
                'latest_scan_status': None,
                'latest_scan_id': None,
            }

        findings = self.session.query(Finding).join(Website).join(Business).filter(Business.owner_id == owner_id).all()
        severity_counts = {level: 0 for level in ['critical', 'high', 'medium', 'low', 'info']}
        for finding in findings:
            severity_counts.setdefault(str(finding.severity).lower(), 0)
            severity_counts[str(finding.severity).lower()] += 1

        open_finding_count = sum(1 for item in findings if str(item.status).lower() in {'open', 'acknowledged'})
        latest_scan = self.session.query(Scan).join(Website).join(Business).filter(Business.owner_id == owner_id).order_by(Scan.completed_at.desc(), Scan.created_at.desc()).first()
        score = self._compute_score(findings)
        top_risk_drivers = self._top_risk_drivers(findings)

        return {
            'score': score,
            'risk_model_version': RISK_MODEL_VERSION,
            'severity_counts': severity_counts,
            'open_finding_count': open_finding_count,
            'affected_website_count': len(set(item.website_id for item in findings)),
            'top_risk_drivers': top_risk_drivers,
            'latest_scan_status': getattr(latest_scan, 'status', None),
            'latest_scan_id': getattr(latest_scan, 'id', None),
        }

    def _compute_score(self, findings: list[Finding]) -> int:
        weighted = 0
        for item in findings:
            severity = str(item.severity).lower()
            base = SEVERITY_WEIGHTS.get(severity, 0)
            repetition = max(0, int(getattr(item, 'occurrence_count', 1)) - 1)
            if repetition > 0:
                base += min(repetition * 1, 3)
            weighted += base
        return min(100, weighted)

    def _top_risk_drivers(self, findings: list[Finding]) -> list[str]:
        by_title = Counter()
        for item in findings:
            by_title[str(item.title)] += max(1, int(getattr(item, 'occurrence_count', 1)))
        ranked = sorted(by_title.items(), key=lambda entry: (-entry[1], entry[0]))
        return [title for title, _ in ranked[:5]]
