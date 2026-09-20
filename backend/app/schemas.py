from __future__ import annotations

from datetime import datetime
from typing import Generic, TypeVar

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

T = TypeVar('T')


class BaseSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True, extra='forbid')


class PaginationQuery(BaseSchema):
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=20, ge=1, le=100)


class PaginationMeta(BaseSchema):
    page: int
    page_size: int
    total: int
    total_pages: int


class PaginatedResponse(BaseSchema, Generic[T]):
    items: list[T]
    page: int
    page_size: int
    total: int
    total_pages: int


class UserCreate(BaseSchema):
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)
    full_name: str = Field(min_length=1, max_length=255)

    @field_validator('password')
    @classmethod
    def validate_password(cls, value: str) -> str:
        if len(value) < 12:
            raise ValueError('Password must be at least 12 characters long.')
        return value


class UserLogin(BaseSchema):
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)


class UserResponse(BaseSchema):
    id: str
    email: EmailStr
    full_name: str
    is_active: bool = True
    created_at: datetime
    updated_at: datetime


class BusinessCreate(BaseSchema):
    name: str = Field(min_length=1, max_length=255)
    industry: str | None = Field(default=None, max_length=255)
    description: str | None = Field(default=None, max_length=2000)


class BusinessUpdate(BaseSchema):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    industry: str | None = Field(default=None, max_length=255)
    description: str | None = Field(default=None, max_length=2000)


class BusinessResponse(BaseSchema):
    id: str
    owner_id: str
    name: str
    industry: str | None = None
    description: str | None = None
    created_at: datetime
    updated_at: datetime


class WebsiteCreate(BaseSchema):
    business_id: str
    name: str = Field(min_length=1, max_length=255)
    url: str

    @field_validator('url')
    @classmethod
    def validate_url(cls, value: str) -> str:
        if not value:
            raise ValueError('URL is required.')
        if '://' not in value:
            raise ValueError('URL must include a scheme such as https://')
        return value


class WebsiteUpdate(BaseSchema):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    url: str | None = None
    status: str | None = Field(default=None, max_length=50)


class WebsiteResponse(BaseSchema):
    id: str
    business_id: str
    name: str
    url: str
    normalized_url: str
    hostname: str
    status: str
    created_at: datetime
    updated_at: datetime
    last_scan_at: datetime | None = None


class ScanCreate(BaseSchema):
    website_id: str
    scan_type: str = Field(default='baseline', max_length=50)


class ScanUpdate(BaseSchema):
    status: str | None = Field(default=None, max_length=20)
    risk_score: float | None = None


class ScanResponse(BaseSchema):
    id: str
    website_id: str
    status: str
    scan_type: str
    risk_score: float | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class FindingCreate(BaseSchema):
    scan_id: str
    website_id: str
    title: str = Field(min_length=1, max_length=255)
    category: str = Field(min_length=1, max_length=100)
    severity: str = Field(max_length=20)
    description: str = Field(min_length=1)
    evidence: str = Field(min_length=1)
    recommendation: str = Field(min_length=1)
    status: str = Field(default='open', max_length=25)


class FindingUpdate(BaseSchema):
    status: str | None = Field(default=None, max_length=25)


class FindingResponse(BaseSchema):
    id: str
    scan_id: str
    website_id: str
    title: str
    slug: str
    fingerprint: str
    severity: str
    priority: str
    category: str
    description: str
    evidence: str
    recommendation: str
    status: str
    remediation_status: str | None = None
    references: str | None = None
    first_seen_at: datetime
    last_seen_at: datetime
    occurrence_count: int = 1
    resolved_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class FindingDetailResponse(FindingResponse):
    website_name: str
    website_url: str
    scan_status: str
    scan_type: str
    scan_completed_at: datetime | None = None


class FindingRemediationCreate(BaseSchema):
    remediation_notes: str | None = Field(default=None, max_length=5000)


class FindingRemediationUpdate(BaseSchema):
    status: str | None = Field(default=None, max_length=25)
    remediation_notes: str | None = Field(default=None, max_length=5000)


class FindingRemediationResponse(BaseSchema):
    id: str
    finding_id: str
    business_id: str
    website_id: str
    user_id: str
    status: str
    remediation_notes: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    verification_requested_at: datetime | None = None
    verified_at: datetime | None = None
    verification_scan_id: str | None = None
    verification_result: str | None = None
    created_at: datetime
    updated_at: datetime


class ReportCreate(BaseSchema):
    business_id: str
    website_id: str | None = None
    scan_id: str | None = None
    title: str | None = Field(default=None, min_length=1, max_length=255)
    report_type: str = Field(default='security_assessment', max_length=60)


class ReportResponse(BaseSchema):
    id: str
    business_id: str
    requested_by: str
    website_id: str | None = None
    scan_id: str | None = None
    report_type: str
    title: str
    status: str
    generated_at: datetime | None = None
    risk_score_snapshot: int | None = None
    risk_model_version: str | None = None
    artifact_path: str | None = None
    created_at: datetime
    updated_at: datetime


class MonitoringTargetCreate(BaseSchema):
    business_id: str
    website_id: str
    enabled: bool = True
    schedule: str = Field(default='daily', max_length=20)
    interval_minutes: int | None = Field(default=None, ge=1, le=10080)

    @field_validator('schedule')
    @classmethod
    def validate_schedule(cls, value: str) -> str:
        allowed = {'daily', 'weekly'}
        normalized = value.lower().strip()
        if normalized not in allowed:
            raise ValueError('Schedule must be one of: daily, weekly.')
        return normalized


class MonitoringTargetUpdate(BaseSchema):
    enabled: bool | None = None
    schedule: str | None = Field(default=None, max_length=20)
    interval_minutes: int | None = Field(default=None, ge=1, le=10080)

    @field_validator('schedule')
    @classmethod
    def validate_schedule(cls, value: str | None) -> str | None:
        if value is None:
            return value
        normalized = value.lower().strip()
        if normalized not in {'daily', 'weekly'}:
            raise ValueError('Schedule must be one of: daily, weekly.')
        return normalized


class MonitoringTargetResponse(BaseSchema):
    id: str
    business_id: str
    website_id: str
    enabled: bool
    schedule: str
    interval_minutes: int
    last_check_at: datetime | None = None
    next_check_at: datetime | None = None
    last_scan_id: str | None = None
    previous_scan_id: str | None = None
    paused_at: datetime | None = None
    failure_count: int = 0
    last_error: str | None = None
    created_at: datetime
    updated_at: datetime


class MonitoringHistoryEntry(BaseSchema):
    scan_id: str
    status: str
    started_at: datetime | None = None
    completed_at: datetime | None = None
    findings_count: int = 0
    new_findings_count: int = 0
    resolved_findings_count: int = 0
    changed_findings_count: int = 0
    persistent_findings_count: int = 0
    previous_risk_score: float | None = None
    current_risk_score: float | None = None
    risk_delta: float | None = None
    failure_code: str | None = None


class MonitoringChangeEntry(BaseSchema):
    fingerprint: str
    title: str
    category: str
    severity: str
    status: str
    previous_severity: str | None = None
    current_severity: str | None = None
    previous_evidence: str | None = None
    current_evidence: str | None = None
    changed_at: datetime


class AlertUpdate(BaseSchema):
    status: str = Field(min_length=1, max_length=25)

    @field_validator('status')
    @classmethod
    def validate_status(cls, value: str) -> str:
        normalized = value.strip().lower()
        if normalized not in {'open', 'acknowledged', 'resolved'}:
            raise ValueError('Alert status must be one of: open, acknowledged, resolved.')
        return normalized


class AlertResponse(BaseSchema):
    id: str
    business_id: str
    website_id: str | None = None
    monitoring_id: str | None = None
    scan_id: str | None = None
    finding_id: str | None = None
    alert_type: str
    severity: str
    title: str
    message: str
    status: str
    deduplication_key: str
    alert_metadata: str | None = None
    created_at: datetime
    updated_at: datetime
    acknowledged_at: datetime | None = None
    resolved_at: datetime | None = None
    website_name: str | None = None
    finding_reference: str | None = None
    safe_evidence: list[str] = Field(default_factory=list)
    previous_risk_score: float | None = None
    current_risk_score: float | None = None
    risk_delta: float | None = None


class AIExplainRequest(BaseSchema):
    finding_id: str = Field(min_length=1, max_length=128)


class AIResponseSummary(BaseSchema):
    summary: str
    why_it_matters: str
    verified_evidence: list[str]
    remediation_steps: list[str]
    verification_steps: list[str]
    limitations: str


class AIResponseSchema(AIResponseSummary):
    pass


class SecurityEventResponse(BaseSchema):
    id: str
    actor_user_id: str | None = None
    business_id: str | None = None
    event_type: str
    action: str
    resource_type: str | None = None
    resource_id: str | None = None
    outcome: str = 'SUCCESS'
    severity: str
    message: str
    request_id: str | None = None
    details: str | None = None
    created_at: datetime


class SubscriptionResponse(BaseSchema):
    id: str
    business_id: str
    plan_name: str
    status: str
    current_period_end: datetime | None = None
    created_at: datetime
    updated_at: datetime
