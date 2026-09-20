from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.models.entities import Alert, Business, Finding, MonitoringTarget, Scan, Website
from app.services.risk_service import RiskService


SEVERITY_RANK = {'info': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class SecurityPostureService:
    def __init__(self, session: Session) -> None:
        self.session = session

    def get_for_user(self, owner_id: str) -> dict[str, Any]:
        businesses = self.session.query(Business).filter(Business.owner_id == owner_id).order_by(Business.created_at.asc()).all()
        websites = self.session.query(Website).join(Business).filter(Business.owner_id == owner_id).order_by(Website.created_at.asc()).all()
        if not websites:
            return self._empty_posture(businesses[0].name if businesses else None)

        findings = self.session.query(Finding).join(Website).join(Business).filter(Business.owner_id == owner_id).all()
        alerts = self.session.query(Alert).join(Business).filter(Business.owner_id == owner_id).all()
        monitoring_targets = self.session.query(MonitoringTarget).join(Business).filter(Business.owner_id == owner_id).all()
        scans = self.session.query(Scan).join(Website).join(Business).filter(Business.owner_id == owner_id).order_by(Scan.completed_at.desc().nullslast(), Scan.created_at.desc()).all()

        active_findings = [finding for finding in findings if str(finding.status).lower() in {'open', 'acknowledged'}]
        open_alerts = [alert for alert in alerts if str(alert.status).lower() == 'open']
        active_targets = [target for target in monitoring_targets if target.enabled]

        latest_scan = scans[0] if scans else None
        previous_scan = scans[1] if len(scans) > 1 else None

        score = self._latest_risk_score(latest_scan, active_findings)
        previous_score = None if previous_scan is None or previous_scan.risk_score is None else int(round(float(previous_scan.risk_score)))
        risk_delta = None if previous_score is None else score - previous_score

        summary = {
            'risk_score': score,
            'previous_risk_score': previous_score,
            'risk_delta': risk_delta,
            'assessment_status': self._assessment_status(latest_scan),
            'business_name': businesses[0].name if businesses else None,
        }
        findings_summary = {
            'open': len(active_findings),
            'critical': sum(1 for item in active_findings if str(item.severity).lower() == 'critical'),
            'high': sum(1 for item in active_findings if str(item.severity).lower() == 'high'),
            'medium': sum(1 for item in active_findings if str(item.severity).lower() == 'medium'),
            'low': sum(1 for item in active_findings if str(item.severity).lower() == 'low'),
            'info': sum(1 for item in active_findings if str(item.severity).lower() == 'info'),
            'acknowledged': sum(1 for item in active_findings if str(item.status).lower() == 'acknowledged'),
        }
        alerts_summary = {
            'total_open': len(open_alerts),
            'critical': sum(1 for item in open_alerts if str(item.severity).lower() == 'critical'),
            'high': sum(1 for item in open_alerts if str(item.severity).lower() == 'high'),
            'monitoring_failures': sum(1 for item in open_alerts if str(item.alert_type).upper() == 'MONITORING_FAILURE'),
        }
        last_assessment_at = None
        if latest_scan is not None:
            last_assessment_at = latest_scan.completed_at or latest_scan.created_at
        next_assessment_at = min((target.next_check_at for target in active_targets if target.next_check_at is not None), default=None)
        monitoring_summary = {
            'active_targets': len(active_targets),
            'disabled_targets': len(monitoring_targets) - len(active_targets),
            'last_assessment_at': last_assessment_at,
            'next_assessment_at': next_assessment_at,
            'failed_assessments': sum(1 for target in monitoring_targets if (target.failure_count or 0) > 0),
            'recent_changes': self._recent_monitoring_changes(latest_scan, previous_scan),
        }

        trend_points = []
        for scan in scans:
            if scan.risk_score is None:
                continue
            trend_points.append({'date': (scan.completed_at or scan.created_at).isoformat() if (scan.completed_at or scan.created_at) else None, 'risk_score': int(round(float(scan.risk_score)))})
        trends = {
            'history': trend_points,
            'status': 'available' if len(trend_points) > 1 else 'limited-history' if trend_points else 'no-data',
        }

        categories = self._category_breakdown(active_findings)
        priorities = self._build_priorities(active_findings, open_alerts, active_targets, latest_scan, previous_scan)
        executive_summary = self._build_executive_summary(summary, findings_summary, alerts_summary, monitoring_summary)
        metadata = {
            'business_id': businesses[0].id if businesses else None,
            'business_name': businesses[0].name if businesses else None,
            'website_count': len(websites),
            'assessment_count': len(scans),
            'generated_at': utcnow().isoformat(),
            'latest_scan_id': latest_scan.id if latest_scan else None,
        }

        return {
            'summary': summary,
            'risk': {
                'current_score': score,
                'previous_score': previous_score,
                'delta': risk_delta,
                'trend_status': trends['status'],
                'model_version': '1.0',
            },
            'findings': findings_summary,
            'alerts': alerts_summary,
            'monitoring': monitoring_summary,
            'trends': trends,
            'priorities': priorities,
            'categories': categories,
            'metadata': metadata,
            'executive_summary': executive_summary,
        }

    @staticmethod
    def _assessment_status(latest_scan: Scan | None) -> str:
        if latest_scan is None:
            return 'no_assessment'
        if str(latest_scan.status).lower() == 'failed':
            return 'failed'
        if latest_scan.completed_at is not None or latest_scan.risk_score is not None:
            return 'assessed'
        return 'pending'

    def _latest_risk_score(self, latest_scan: Scan | None, findings: list[Finding]) -> int:
        if latest_scan is not None and latest_scan.risk_score is not None:
            return int(round(float(latest_scan.risk_score)))
        if findings:
            return RiskService(self.session)._compute_score(findings)
        return 0

    @staticmethod
    def _build_executive_summary(summary: dict[str, Any], findings_summary: dict[str, Any], alerts_summary: dict[str, Any], monitoring_summary: dict[str, Any]) -> str:
        if summary['risk_score'] == 0 and findings_summary['open'] == 0 and alerts_summary['total_open'] == 0 and monitoring_summary['active_targets'] == 0:
            return 'No websites are currently monitored for this business.'

        parts: list[str] = []
        if findings_summary['open'] > 0:
            parts.append(f"Your latest assessment identified {findings_summary['open']} open findings.")
        if findings_summary['critical'] > 0:
            parts.append(f"{findings_summary['critical']} critical finding{'s' if findings_summary['critical'] != 1 else ''} require attention.")
        if summary['previous_risk_score'] is not None and summary['risk_delta'] is not None:
            direction = 'increased' if summary['risk_delta'] > 0 else 'decreased'
            parts.append(f"The risk score {direction} by {abs(summary['risk_delta'])} points compared with the previous assessment.")
        elif summary['risk_score'] > 0:
            parts.append(f"The current risk score is {summary['risk_score']} out of 100.")
        if alerts_summary['critical'] > 0:
            parts.append(f"{alerts_summary['critical']} critical alert{'s' if alerts_summary['critical'] != 1 else ''} are still open.")
        if monitoring_summary['active_targets'] == 0:
            parts.append('No websites are currently monitored.')

        return ' '.join(parts) if parts else 'No verified security posture data is available for this business yet.'

    @staticmethod
    def _category_breakdown(findings: list[Finding]) -> list[dict[str, Any]]:
        grouped: dict[str, dict[str, Any]] = {}
        for finding in findings:
            category = str(finding.category).strip() or 'uncategorized'
            entry = grouped.setdefault(category, {'category': category, 'open_findings': 0, 'highest_severity': 'info', 'status': 'open'})
            entry['open_findings'] += 1
            if SEVERITY_RANK.get(str(finding.severity).lower(), 0) > SEVERITY_RANK.get(entry['highest_severity'], 0):
                entry['highest_severity'] = str(finding.severity).lower()
        ordered = sorted(grouped.values(), key=lambda item: (-SEVERITY_RANK.get(item['highest_severity'], 0), -item['open_findings'], item['category']))
        return ordered

    def _build_priorities(self, findings: list[Finding], alerts: list[Alert], active_targets: list[MonitoringTarget], latest_scan: Scan | None, previous_scan: Scan | None) -> list[dict[str, Any]]:
        priorities: list[dict[str, Any]] = []
        for finding in sorted(findings, key=lambda item: (-SEVERITY_RANK.get(str(item.severity).lower(), 0), item.title)):
            if str(finding.severity).lower() == 'critical':
                priorities.append({
                    'title': f"Resolve critical finding affecting {finding.website_id}",
                    'source_type': 'finding',
                    'source_id': finding.id,
                    'severity': 'critical',
                    'reference': finding.id,
                })
        for finding in sorted(findings, key=lambda item: (-SEVERITY_RANK.get(str(item.severity).lower(), 0), item.title)):
            if str(finding.severity).lower() == 'high':
                priorities.append({
                    'title': f"Review high-severity finding affecting {finding.website_id}",
                    'source_type': 'finding',
                    'source_id': finding.id,
                    'severity': 'high',
                    'reference': finding.id,
                })

        latest_risk = (latest_scan.risk_score if latest_scan and latest_scan.risk_score is not None else None)
        previous_risk = (previous_scan.risk_score if previous_scan and previous_scan.risk_score is not None else None)
        if latest_risk is not None and previous_risk is not None and float(latest_risk) > float(previous_risk) and (float(latest_risk) - float(previous_risk)) >= 5:
            priorities.append({
                'title': 'Risk score increased compared with the previous assessment',
                'source_type': 'alert',
                'source_id': 'risk-score-increase',
                'severity': 'high' if (float(latest_risk) - float(previous_risk)) >= 15 else 'medium',
                'reference': f"{previous_risk}->{latest_risk}",
            })
        for alert in sorted(alerts, key=lambda item: (-SEVERITY_RANK.get(str(item.severity).lower(), 0), item.created_at), reverse=True):
            if str(alert.alert_type).upper() == 'MONITORING_FAILURE':
                priorities.append({
                    'title': 'Monitoring failure requires follow-up',
                    'source_type': 'monitoring',
                    'source_id': str(alert.monitoring_id or alert.website_id or alert.id),
                    'severity': 'medium',
                    'reference': str(alert.id),
                })
                break
        for alert in sorted(alerts, key=lambda item: (-SEVERITY_RANK.get(str(item.severity).lower(), 0), item.created_at), reverse=True):
            if str(alert.alert_type).upper() == 'SIGNIFICANT_SECURITY_CHANGE':
                priorities.append({
                    'title': 'Significant security change detected',
                    'source_type': 'alert',
                    'source_id': alert.id,
                    'severity': str(alert.severity).lower(),
                    'reference': alert.id,
                })
                break

        seen: set[tuple[str, str]] = set()
        final_priorities: list[dict[str, Any]] = []
        for entry in sorted(priorities, key=lambda item: (-SEVERITY_RANK.get(str(item['severity']).lower(), 0), str(item['title']))):
            key = (str(entry['source_type']), str(entry['source_id']))
            if key in seen:
                continue
            seen.add(key)
            final_priorities.append(entry)
        return final_priorities[:6]

    @staticmethod
    def _recent_monitoring_changes(latest_scan: Scan | None, previous_scan: Scan | None) -> list[dict[str, Any]]:
        if latest_scan is None:
            return []
        if previous_scan is None:
            return []
        changes: list[dict[str, Any]] = []
        previous_by_fingerprint = {finding.fingerprint: finding for finding in previous_scan.findings}
        current_by_fingerprint = {finding.fingerprint: finding for finding in latest_scan.findings}
        for fingerprint in sorted(set(current_by_fingerprint) - set(previous_by_fingerprint)):
            changes.append({'status': 'new', 'title': current_by_fingerprint[fingerprint].title, 'severity': current_by_fingerprint[fingerprint].severity})
        return changes[:5]

    @staticmethod
    def _empty_posture(business_name: str | None) -> dict[str, Any]:
        summary = {
            'risk_score': 0,
            'previous_risk_score': None,
            'risk_delta': None,
            'assessment_status': 'no_assessment',
            'business_name': business_name,
        }
        return {
            'summary': summary,
            'risk': {'current_score': 0, 'previous_score': None, 'delta': None, 'trend_status': 'no-data', 'model_version': '1.0'},
            'findings': {'open': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0, 'acknowledged': 0},
            'alerts': {'total_open': 0, 'critical': 0, 'high': 0, 'monitoring_failures': 0},
            'monitoring': {'active_targets': 0, 'disabled_targets': 0, 'last_assessment_at': None, 'next_assessment_at': None, 'failed_assessments': 0, 'recent_changes': []},
            'trends': {'history': [], 'status': 'no-data'},
            'priorities': [],
            'categories': [],
            'metadata': {'business_id': None, 'business_name': business_name, 'website_count': 0, 'assessment_count': 0, 'generated_at': utcnow().isoformat(), 'latest_scan_id': None},
            'executive_summary': 'No websites are currently monitored for this business.',
        }
