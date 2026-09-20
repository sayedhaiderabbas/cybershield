from __future__ import annotations

import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

from fastapi import HTTPException
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import LongTable, Paragraph, SimpleDocTemplate, Spacer, TableStyle
from sqlalchemy import asc, desc
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.entities import Business, Finding, Report, Scan, Website
from app.repositories.report_repository import ReportRepository
from app.schemas import ReportCreate
from app.services.base import ensure_entity
from app.services.risk_service import RiskService, RISK_MODEL_VERSION, SEVERITY_WEIGHTS

_PROJECT_ROOT = Path(__file__).resolve().parents[3]
_configured_storage_root = Path(get_settings().report_storage_root).expanduser()
REPORT_STORAGE_ROOT = (
    _configured_storage_root
    if _configured_storage_root.is_absolute()
    else (_PROJECT_ROOT / _configured_storage_root).resolve()
)


def _safe_report_text(value: object | None) -> str:
    text = '' if value is None else str(value)
    patterns = [
        (r'(?i)(authorization\s*:\s*)bearer\s+[A-Za-z0-9._~+/=-]+', r'\1Bearer <redacted>'),
        (r'(?i)(cookie\s*:\s*)(?:[^\n;]+)', r'\1<redacted>'),
        (r'(?i)(password\s*[:=]\s*)(?:[^\s,;]+)', r'\1<redacted>'),
        (r'(?i)(credentials?\s*[:=]\s*)(?:[^\s,;]+)', r'\1<redacted>'),
        (r'(?i)(api[_-]?key\s*[:=]\s*)(?:[^\s,;]+)', r'\1<redacted>'),
        (r'(?i)(token\s*[:=]\s*)(?:[^\s,;]+)', r'\1<redacted>'),
        (r'(?i)(secret\s*[:=]\s*)(?:[^\s,;]+)', r'\1<redacted>'),
        (r'(?i)eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}', '<redacted-jwt>'),
    ]
    for pattern, replacement in patterns:
        text = re.sub(pattern, replacement, text)
    return text


def _pdf_text(value: object | None) -> str:
    return escape(_safe_report_text(value))


class ReportService:
    def __init__(self, session: Session) -> None:
        self.session = session
        self.repo = ReportRepository(session)

    def create(self, owner_id: str, payload: ReportCreate) -> Report:
        business = self.session.query(Business).filter(Business.id == payload.business_id, Business.owner_id == owner_id).one_or_none()
        ensure_entity(business, 'Business not found or access denied.')

        website: Website | None = None
        if payload.website_id:
            website = self.session.query(Website).filter(Website.id == payload.website_id, Website.business_id == payload.business_id).one_or_none()
            ensure_entity(website, 'Website not found or access denied.')

        scan: Scan | None = None
        if payload.scan_id:
            scan = self.session.query(Scan).join(Website).filter(Scan.id == payload.scan_id, Website.business_id == payload.business_id).one_or_none()
            ensure_entity(scan, 'Scan not found or access denied.')
            if website is not None and scan.website_id != website.id:
                raise HTTPException(status_code=422, detail='Scan does not belong to the selected website.')

        report = Report(
            business_id=payload.business_id,
            requested_by=owner_id,
            website_id=payload.website_id,
            scan_id=payload.scan_id,
            report_type=payload.report_type or 'security_assessment',
            title=(payload.title or f'{business.name} Security Assessment Report').strip() or f'{business.name} Security Assessment Report',
            status='pending',
            generated_at=None,
            risk_score_snapshot=None,
            risk_model_version=None,
            report_metadata=None,
            artifact_path=None,
        )
        self.repo.add(report)
        self.repo.commit()
        self.repo.refresh(report)

        try:
            snapshot = self._build_snapshot(report, business, website, scan)
            report_path = self._write_pdf(report, snapshot)
            report.status = 'completed'
            report.generated_at = datetime.now(timezone.utc)
            report.risk_score_snapshot = int(snapshot['risk_score'])
            report.risk_model_version = snapshot['risk_model_version']
            report.report_metadata = json.dumps(snapshot, sort_keys=True)
            report.artifact_path = f'generated/{report.id}.pdf'
            self.repo.commit()
            self.repo.refresh(report)
            return report
        except Exception as exc:
            report.status = 'failed'
            report.generated_at = datetime.now(timezone.utc)
            report.report_metadata = json.dumps({'error': 'Report generation failed.', 'limitations': 'This report could not be generated from verified CyberShield data.'}, sort_keys=True)
            self.repo.commit()
            raise HTTPException(status_code=500, detail='The report could not be generated.') from exc

    def list(
        self,
        owner_id: str,
        page: int,
        page_size: int,
        *,
        search: str | None = None,
        website_id: str | None = None,
        status: str | None = None,
        sort: str = 'newest',
    ) -> tuple[list[Report], int]:
        query = self.session.query(Report).join(Business).filter(Business.owner_id == owner_id)
        if search:
            term = f'%{search.strip()}%'
            query = query.filter(Report.title.ilike(term) | Report.report_type.ilike(term))
        if website_id:
            query = query.filter(Report.website_id == website_id)
        if status:
            query = query.filter(Report.status == status)
        order_column = Report.generated_at if sort in {'generated', 'oldest-generated'} else Report.created_at
        order = asc(order_column) if sort in {'oldest', 'oldest-generated'} else desc(order_column)
        total = query.order_by(None).count()
        items = query.order_by(order, desc(Report.created_at), desc(Report.id)).offset((page - 1) * page_size).limit(page_size).all()
        return items, total

    def get(self, report_id: str, owner_id: str) -> Report:
        report = self.session.query(Report).join(Business).filter(Report.id == report_id, Business.owner_id == owner_id).one_or_none()
        ensure_entity(report, 'Report not found.')
        return report

    def _build_snapshot(self, report: Report, business: Business, website: Website | None, scan: Scan | None) -> dict[str, Any]:
        if website is not None:
            scope_websites = [website]
        else:
            scope_websites = self.session.query(Website).filter(Website.business_id == business.id).all()

        findings = self.session.query(Finding).join(Scan).join(Website).filter(Website.business_id == business.id)
        if website is not None:
            findings = findings.filter(Finding.website_id == website.id)
        if scan is not None:
            findings = findings.filter(Finding.scan_id == scan.id)
        findings = findings.order_by(Finding.last_seen_at.desc(), Finding.created_at.desc()).all()

        severity_counts = {level: 0 for level in ['critical', 'high', 'medium', 'low', 'info']}
        for item in findings:
            severity_counts[str(item.severity).lower()] = severity_counts.get(str(item.severity).lower(), 0) + 1

        weighted = 0
        for item in findings:
            severity = str(item.severity).lower()
            weighted += SEVERITY_WEIGHTS.get(severity, 0)
            repetition = max(0, int(getattr(item, 'occurrence_count', 1)) - 1)
            if repetition > 0:
                weighted += min(repetition * 1, 3)
        score = min(100, weighted)

        by_title = Counter()
        for item in findings:
            by_title[str(item.title)] += max(1, int(getattr(item, 'occurrence_count', 1)))
        top_risk_drivers = [title for title, _ in sorted(by_title.items(), key=lambda entry: (-entry[1], entry[0]))[:5]]

        selected_scan = scan or self.session.query(Scan).join(Website).filter(Website.business_id == business.id).order_by(Scan.completed_at.desc(), Scan.created_at.desc()).first()
        report_scope = []
        for item in scope_websites:
            report_scope.append({
                'id': item.id,
                'name': _safe_report_text(item.name),
                'url': _safe_report_text(item.url),
                'status': _safe_report_text(item.status),
                'last_scan_at': item.last_scan_at.isoformat() if item.last_scan_at else None,
            })

        report_findings = []
        for item in findings:
            evidence = []
            if item.evidence:
                for chunk in str(item.evidence).replace('\r', '\n').split('\n'):
                    cleaned = chunk.strip().strip('-*• ')
                    if cleaned:
                        evidence.append(cleaned)
            report_findings.append({
                'id': item.id,
                'title': _safe_report_text(item.title),
                'category': _safe_report_text(item.category),
                'severity': _safe_report_text(item.severity),
                'status': _safe_report_text(item.status),
                'website': item.website_id,
                'description': _safe_report_text(item.description),
                'evidence': [_safe_report_text(entry) for entry in evidence],
                'recommendation': _safe_report_text(item.recommendation),
                'first_seen_at': item.first_seen_at.isoformat() if item.first_seen_at else None,
                'last_seen_at': item.last_seen_at.isoformat() if item.last_seen_at else None,
                'occurrence_count': item.occurrence_count,
            })

        snapshot = {
            'report_id': report.id,
            'report_type': report.report_type,
            'title': report.title,
            'business': {'id': business.id, 'name': business.name, 'industry': business.industry},
            'scope': report_scope,
            'assessment_date': datetime.now(timezone.utc).isoformat(),
            'risk_score': score,
            'risk_model_version': RISK_MODEL_VERSION,
            'severity_counts': severity_counts,
            'open_finding_count': sum(1 for item in findings if str(item.status).lower() in {'open', 'acknowledged'}),
            'affected_website_count': len({item.website_id for item in findings}),
            'top_risk_drivers': top_risk_drivers,
            'scan': {
                'id': getattr(selected_scan, 'id', None),
                'status': getattr(selected_scan, 'status', None),
                'scan_type': getattr(selected_scan, 'scan_type', None),
                'started_at': getattr(selected_scan, 'started_at', None).isoformat() if getattr(selected_scan, 'started_at', None) else None,
                'completed_at': getattr(selected_scan, 'completed_at', None).isoformat() if getattr(selected_scan, 'completed_at', None) else None,
            },
            'findings': report_findings,
            'limitations': 'This report reflects the checks and evidence collected by CyberShield during the specified assessment.',
        }
        return snapshot

    def _write_pdf(self, report: Report, snapshot: dict[str, Any]) -> Path:
        REPORT_STORAGE_ROOT.mkdir(parents=True, exist_ok=True)
        file_path = REPORT_STORAGE_ROOT / f'{report.id}.pdf'
        doc = SimpleDocTemplate(
            str(file_path),
            pagesize=letter,
            title=_pdf_text(snapshot['title']),
            author='CyberShield',
            leftMargin=42,
            rightMargin=42,
            topMargin=42,
            bottomMargin=42,
        )
        styles = getSampleStyleSheet()
        body = styles['BodyText']
        body.leading = 13
        story = []
        story.append(Paragraph('CyberShield', styles['Title']))
        story.append(Paragraph('Security Assessment Report', styles['Heading1']))
        story.append(Spacer(1, 12))
        story.append(Paragraph(f'<b>Report:</b> {_pdf_text(snapshot["title"])}', body))
        story.append(Paragraph(f'<b>Business:</b> {_pdf_text(snapshot["business"]["name"])}', body))
        story.append(Paragraph(f'<b>Assessment date:</b> {_pdf_text(snapshot["assessment_date"])}', body))
        story.append(Paragraph(f'<b>Risk score:</b> {_pdf_text(snapshot["risk_score"])}/100', body))
        story.append(Paragraph(f'<b>Risk model version:</b> {_pdf_text(snapshot["risk_model_version"])}', body))
        story.append(Spacer(1, 12))
        story.append(Paragraph('Executive summary', styles['Heading2']))
        story.append(Paragraph(
            'This report reflects the checks and evidence collected by CyberShield during the specified assessment. '
            'The report is based on the verified findings observed for the selected business and website scope.',
            body,
        ))
        story.append(Paragraph(f'<b>Open findings:</b> {_pdf_text(snapshot["open_finding_count"])}', body))
        story.append(Paragraph(f'<b>Top risk drivers:</b> {_pdf_text(", ".join(snapshot["top_risk_drivers"]) if snapshot["top_risk_drivers"] else "No major risk drivers identified.")}', body))
        story.append(Spacer(1, 12))

        table_data = [['Finding', 'Severity', 'Status', 'Website']]
        for item in snapshot['findings'][:12]:
            table_data.append([_pdf_text(item['title']), _pdf_text(item['severity']), _pdf_text(item['status']), _pdf_text(item['website'])])
        summary_table = LongTable(table_data, colWidths=[220, 80, 80, 140], repeatRows=1)
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), '#1F2937'),
            ('TEXTCOLOR', (0, 0), (-1, 0), '#FFFFFF'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.5, '#D1D5DB'),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), ['#F8FAFC', '#FFFFFF']),
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 12))

        for item in snapshot['findings']:
            story.append(Paragraph(f'<b>{_pdf_text(item["title"])}</b>', styles['Heading3']))
            story.append(Paragraph(f'<b>Severity:</b> {_pdf_text(item["severity"])} | <b>Status:</b> {_pdf_text(item["status"])}', body))
            story.append(Paragraph(f'<b>What we found:</b> {_pdf_text(item["description"])}', body))
            evidence = ' '.join(item['evidence']) if item['evidence'] else 'No evidence details were recorded by the scanner.'
            story.append(Paragraph(f'<b>Evidence:</b> {_pdf_text(evidence)}', body))
            story.append(Paragraph(f'<b>How to fix:</b> {_pdf_text(item["recommendation"])}', body))
            story.append(Paragraph(f'<b>History:</b> first seen {_pdf_text(item["first_seen_at"] or "n/a")}; last seen {_pdf_text(item["last_seen_at"] or "n/a")}; occurrences {_pdf_text(item["occurrence_count"])}.', body))
            story.append(Spacer(1, 8))

        story.append(Spacer(1, 12))
        story.append(Paragraph('Limitations', styles['Heading2']))
        story.append(Paragraph(_pdf_text(snapshot['limitations']), body))

        doc.build(story, onFirstPage=ReportService._draw_page_number, onLaterPages=ReportService._draw_page_number)
        return file_path

    @staticmethod
    def _draw_page_number(canvas: Any, document: Any) -> None:
        canvas.saveState()
        canvas.setFont('Helvetica', 8)
        canvas.drawRightString(letter[0] - 42, 24, f'Page {document.page}')
        canvas.restoreState()

    @staticmethod
    def serialize_report(report: Report, *, include_metadata: bool = True) -> dict[str, Any]:
        metadata = {}
        if report.report_metadata:
            try:
                metadata = json.loads(report.report_metadata)
            except json.JSONDecodeError:
                metadata = {'raw_metadata': report.report_metadata}
        safe_metadata = metadata if include_metadata else {
            'finding_count': len(metadata.get('findings', [])) if isinstance(metadata.get('findings'), list) else 0,
            'severity_counts': metadata.get('severity_counts', {}),
            'open_finding_count': metadata.get('open_finding_count', 0),
            'scan': metadata.get('scan', {}),
            'scope': metadata.get('scope', []),
        }
        return {
            'id': report.id,
            'business_id': report.business_id,
            'requested_by': report.requested_by,
            'website_id': report.website_id,
            'scan_id': report.scan_id,
            'report_type': report.report_type,
            'title': report.title,
            'status': report.status,
            'generated_at': report.generated_at.isoformat() if report.generated_at else None,
            'risk_score_snapshot': report.risk_score_snapshot,
            'risk_model_version': report.risk_model_version,
            'artifact_path': report.artifact_path,
            'created_at': report.created_at.isoformat() if report.created_at else None,
            'updated_at': report.updated_at.isoformat() if report.updated_at else None,
            'metadata': safe_metadata,
        }

    @staticmethod
    def resolve_download_path(report: Report) -> Path | None:
        storage_root = REPORT_STORAGE_ROOT.resolve()
        candidate_name = Path(report.artifact_path).name if report.artifact_path else f'{report.id}.pdf'
        candidate = (storage_root / candidate_name).resolve()
        if not candidate.exists() or storage_root not in candidate.parents and candidate != storage_root:
            return None
        if not candidate.is_file():
            return None
        return candidate
