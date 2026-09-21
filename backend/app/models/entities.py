from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, Float
from sqlalchemy.orm import Mapped, relationship

from app.db.base import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = 'users'

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    email: Mapped[str] = Column(String(255), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = Column(String(255), nullable=False)
    full_name: Mapped[str] = Column(String(255), nullable=False)
    is_active: Mapped[bool] = Column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)
    last_login_at: Mapped[datetime | None] = Column(DateTime(timezone=True), nullable=True)

    businesses: Mapped[list['Business']] = relationship(back_populates='owner', cascade='all, delete-orphan')
    audit_events: Mapped[list['SecurityEvent']] = relationship(back_populates='actor', cascade='all, delete-orphan')


class TokenRevocation(Base):
    __tablename__ = 'token_revocations'

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    jti: Mapped[str] = Column(String(36), unique=True, nullable=False, index=True)
    user_id: Mapped[str] = Column(String(36), ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    expires_at: Mapped[datetime] = Column(DateTime(timezone=True), nullable=False, index=True)
    revoked_at: Mapped[datetime] = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    reason: Mapped[str] = Column(String(100), default='logout', nullable=False)


class Business(Base):
    __tablename__ = 'businesses'

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    owner_id: Mapped[str] = Column(String(36), ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    name: Mapped[str] = Column(String(255), nullable=False)
    industry: Mapped[str | None] = Column(String(255), nullable=True)
    description: Mapped[str | None] = Column(Text, nullable=True)
    created_at: Mapped[datetime] = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)

    owner: Mapped[User] = relationship(back_populates='businesses')
    websites: Mapped[list['Website']] = relationship(back_populates='business', cascade='all, delete-orphan')
    reports: Mapped[list['Report']] = relationship(back_populates='business', cascade='all, delete-orphan')
    monitoring_targets: Mapped[list['MonitoringTarget']] = relationship(back_populates='business', cascade='all, delete-orphan')
    alerts: Mapped[list['Alert']] = relationship(back_populates='business', cascade='all, delete-orphan')
    security_events: Mapped[list['SecurityEvent']] = relationship(back_populates='business', cascade='all, delete-orphan')

    __table_args__ = (
        UniqueConstraint('owner_id', 'name', name='uq_business_owner_name'),
    )


class Website(Base):
    __tablename__ = 'websites'

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    business_id: Mapped[str] = Column(String(36), ForeignKey('businesses.id', ondelete='CASCADE'), nullable=False, index=True)
    name: Mapped[str] = Column(String(255), nullable=False)
    url: Mapped[str] = Column(String(2048), nullable=False)
    normalized_url: Mapped[str] = Column(String(2048), nullable=False, index=True)
    hostname: Mapped[str] = Column(String(255), nullable=False, index=True)
    status: Mapped[str] = Column(String(50), default='pending', nullable=False)
    created_at: Mapped[datetime] = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)
    last_scan_at: Mapped[datetime | None] = Column(DateTime(timezone=True), nullable=True)

    business: Mapped[Business] = relationship(back_populates='websites')
    scans: Mapped[list['Scan']] = relationship(back_populates='website', cascade='all, delete-orphan')
    monitoring_targets: Mapped[list['MonitoringTarget']] = relationship(back_populates='website', cascade='all, delete-orphan')
    reports: Mapped[list['Report']] = relationship(back_populates='website')
    alerts: Mapped[list['Alert']] = relationship(back_populates='website', cascade='all, delete-orphan')

    __table_args__ = (
        UniqueConstraint('business_id', 'normalized_url', name='uq_business_url'),
    )


class Scan(Base):
    __tablename__ = 'scans'

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    website_id: Mapped[str] = Column(String(36), ForeignKey('websites.id', ondelete='CASCADE'), nullable=False, index=True)
    status: Mapped[str] = Column(String(20), default='queued', nullable=False, index=True)
    scan_type: Mapped[str] = Column(String(50), default='baseline', nullable=False)
    risk_score: Mapped[float | None] = Column(Float, nullable=True)
    started_at: Mapped[datetime | None] = Column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = Column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)
    error_code: Mapped[str | None] = Column(String(100), nullable=True)

    website: Mapped[Website] = relationship(back_populates='scans')
    findings: Mapped[list['Finding']] = relationship(back_populates='scan', cascade='all, delete-orphan')


class Finding(Base):
    __tablename__ = 'findings'

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    scan_id: Mapped[str] = Column(String(36), ForeignKey('scans.id', ondelete='CASCADE'), nullable=False, index=True)
    website_id: Mapped[str] = Column(String(36), ForeignKey('websites.id', ondelete='CASCADE'), nullable=False, index=True)
    title: Mapped[str] = Column(String(255), nullable=False)
    slug: Mapped[str] = Column(String(255), nullable=False)
    fingerprint: Mapped[str] = Column(String(255), nullable=False, default='manual', index=True)
    severity: Mapped[str] = Column(String(20), nullable=False, index=True)
    priority: Mapped[str] = Column(String(25), default='normal', nullable=False, index=True)
    category: Mapped[str] = Column(String(100), nullable=False, index=True)
    status: Mapped[str] = Column(String(25), default='open', nullable=False, index=True)
    description: Mapped[str] = Column(Text, nullable=False)
    evidence: Mapped[str] = Column(Text, nullable=False)
    recommendation: Mapped[str] = Column(Text, nullable=False)
    references: Mapped[str | None] = Column(Text, nullable=True)
    first_seen_at: Mapped[datetime] = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    last_seen_at: Mapped[datetime] = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)
    occurrence_count: Mapped[int] = Column(Integer, default=1, nullable=False)
    resolved_at: Mapped[datetime | None] = Column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)

    scan: Mapped[Scan] = relationship(back_populates='findings')
    remediation: Mapped['FindingRemediation | None'] = relationship(back_populates='finding', uselist=False, cascade='all, delete-orphan')

    @property
    def remediation_status(self) -> str | None:
        return self.remediation.status if self.remediation else None


class FindingRemediation(Base):
    __tablename__ = 'finding_remediation'

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    finding_id: Mapped[str] = Column(String(36), ForeignKey('findings.id', ondelete='CASCADE'), nullable=False, unique=True, index=True)
    business_id: Mapped[str] = Column(String(36), ForeignKey('businesses.id', ondelete='CASCADE'), nullable=False, index=True)
    website_id: Mapped[str] = Column(String(36), ForeignKey('websites.id', ondelete='CASCADE'), nullable=False, index=True)
    user_id: Mapped[str] = Column(String(36), ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    status: Mapped[str] = Column(String(25), default='open', nullable=False, index=True)
    remediation_notes: Mapped[str | None] = Column(Text, nullable=True)
    started_at: Mapped[datetime | None] = Column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = Column(DateTime(timezone=True), nullable=True)
    verification_requested_at: Mapped[datetime | None] = Column(DateTime(timezone=True), nullable=True)
    verified_at: Mapped[datetime | None] = Column(DateTime(timezone=True), nullable=True)
    verification_scan_id: Mapped[str | None] = Column(String(36), ForeignKey('scans.id', ondelete='SET NULL'), nullable=True, index=True)
    verification_result: Mapped[str | None] = Column(String(50), nullable=True)
    created_at: Mapped[datetime] = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)

    finding: Mapped[Finding] = relationship(back_populates='remediation')
    business: Mapped[Business] = relationship()
    website: Mapped[Website] = relationship()
    user: Mapped[User] = relationship()


class Report(Base):
    __tablename__ = 'reports'

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    business_id: Mapped[str] = Column(String(36), ForeignKey('businesses.id', ondelete='CASCADE'), nullable=False, index=True)
    requested_by: Mapped[str] = Column(String(36), ForeignKey('users.id', ondelete='SET NULL'), nullable=False, index=True)
    website_id: Mapped[str | None] = Column(String(36), ForeignKey('websites.id', ondelete='SET NULL'), nullable=True, index=True)
    scan_id: Mapped[str | None] = Column(String(36), ForeignKey('scans.id', ondelete='SET NULL'), nullable=True)
    report_type: Mapped[str] = Column(String(60), default='security_assessment', nullable=False)
    title: Mapped[str] = Column(String(255), nullable=False)
    status: Mapped[str] = Column(String(25), default='pending', nullable=False)
    generated_at: Mapped[datetime | None] = Column(DateTime(timezone=True), nullable=True)
    risk_score_snapshot: Mapped[int | None] = Column(Integer, nullable=True)
    risk_model_version: Mapped[str | None] = Column(String(25), nullable=True)
    report_metadata: Mapped[str | None] = Column(Text, nullable=True)
    created_at: Mapped[datetime] = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)
    artifact_path: Mapped[str | None] = Column(String(1024), nullable=True)

    business: Mapped[Business] = relationship(back_populates='reports')
    website: Mapped[Website | None] = relationship(back_populates='reports')


class MonitoringTarget(Base):
    __tablename__ = 'monitoring_targets'

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    business_id: Mapped[str] = Column(String(36), ForeignKey('businesses.id', ondelete='CASCADE'), nullable=False, index=True)
    website_id: Mapped[str] = Column(String(36), ForeignKey('websites.id', ondelete='CASCADE'), nullable=False, index=True)
    enabled: Mapped[bool] = Column(Boolean, default=True, nullable=False)
    schedule: Mapped[str] = Column(String(20), default='daily', nullable=False, index=True)
    interval_minutes: Mapped[int] = Column(Integer, default=1440, nullable=False)
    last_check_at: Mapped[datetime | None] = Column(DateTime(timezone=True), nullable=True)
    next_check_at: Mapped[datetime | None] = Column(DateTime(timezone=True), nullable=True)
    last_scan_id: Mapped[str | None] = Column(String(36), nullable=True, index=True)
    previous_scan_id: Mapped[str | None] = Column(String(36), nullable=True, index=True)
    paused_at: Mapped[datetime | None] = Column(DateTime(timezone=True), nullable=True)
    failure_count: Mapped[int] = Column(Integer, default=0, nullable=False)
    last_error: Mapped[str | None] = Column(String(255), nullable=True)
    created_at: Mapped[datetime] = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)

    business: Mapped[Business] = relationship(back_populates='monitoring_targets')
    website: Mapped[Website] = relationship(back_populates='monitoring_targets')

    __table_args__ = (
        UniqueConstraint('business_id', 'website_id', name='uq_monitoring_business_website'),
    )


class Alert(Base):
    __tablename__ = 'alerts'

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    business_id: Mapped[str] = Column(String(36), ForeignKey('businesses.id', ondelete='CASCADE'), nullable=False, index=True)
    website_id: Mapped[str | None] = Column(String(36), ForeignKey('websites.id', ondelete='CASCADE'), nullable=True, index=True)
    monitoring_id: Mapped[str | None] = Column(String(36), ForeignKey('monitoring_targets.id', ondelete='SET NULL'), nullable=True, index=True)
    scan_id: Mapped[str | None] = Column(String(36), ForeignKey('scans.id', ondelete='SET NULL'), nullable=True, index=True)
    finding_id: Mapped[str | None] = Column(String(36), ForeignKey('findings.id', ondelete='SET NULL'), nullable=True, index=True)
    alert_type: Mapped[str] = Column(String(80), nullable=False, index=True)
    severity: Mapped[str] = Column(String(25), default='info', nullable=False, index=True)
    title: Mapped[str] = Column(String(255), nullable=False)
    message: Mapped[str] = Column(Text, nullable=False)
    status: Mapped[str] = Column(String(25), default='open', nullable=False, index=True)
    deduplication_key: Mapped[str] = Column(String(255), nullable=False, unique=True, index=True)
    alert_metadata: Mapped[str | None] = Column(Text, nullable=True)
    created_at: Mapped[datetime] = Column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)
    acknowledged_at: Mapped[datetime | None] = Column(DateTime(timezone=True), nullable=True)
    resolved_at: Mapped[datetime | None] = Column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)

    business: Mapped[Business] = relationship(back_populates='alerts')
    website: Mapped[Website | None] = relationship(back_populates='alerts')
    scan: Mapped[Scan | None] = relationship(foreign_keys=[scan_id])
    finding: Mapped[Finding | None] = relationship(foreign_keys=[finding_id])


class SecurityEvent(Base):
    __tablename__ = 'security_events'

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    actor_user_id: Mapped[str | None] = Column(String(36), ForeignKey('users.id', ondelete='SET NULL'), nullable=True, index=True)
    business_id: Mapped[str | None] = Column(String(36), ForeignKey('businesses.id', ondelete='CASCADE'), nullable=True, index=True)
    event_type: Mapped[str] = Column(String(100), nullable=False, index=True)
    action: Mapped[str] = Column(String(120), nullable=False, default='ACCESS', index=True)
    resource_type: Mapped[str | None] = Column(String(80), nullable=True, index=True)
    resource_id: Mapped[str | None] = Column(String(255), nullable=True, index=True)
    outcome: Mapped[str] = Column(String(20), default='SUCCESS', nullable=False, index=True)
    severity: Mapped[str] = Column(String(25), default='info', nullable=False)
    message: Mapped[str] = Column(Text, nullable=False)
    request_id: Mapped[str | None] = Column(String(120), nullable=True, index=True)
    event_details: Mapped[str | None] = Column('metadata', Text, nullable=True)
    created_at: Mapped[datetime] = Column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)

    actor: Mapped[User | None] = relationship(back_populates='audit_events')
    business: Mapped[Business | None] = relationship(back_populates='security_events')


class Subscription(Base):
    __tablename__ = 'subscriptions'

    id: Mapped[str] = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    business_id: Mapped[str] = Column(String(36), ForeignKey('businesses.id', ondelete='CASCADE'), nullable=False, index=True)
    plan_name: Mapped[str] = Column(String(100), nullable=False)
    status: Mapped[str] = Column(String(25), default='active', nullable=False)
    current_period_end: Mapped[datetime | None] = Column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)
