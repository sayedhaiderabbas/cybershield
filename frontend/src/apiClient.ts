const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:5000/api/v1';
const AUTH_TOKEN_KEY = 'cybershield-token';

export type ApiErrorBody = {
  error?: {
    code?: string;
    message?: string;
    details?: unknown[];
  };
};

export type ApiListMeta = {
  page: number;
  page_size: number;
  total: number;
  total_pages: number;
};

async function request<T>(path: string, options: RequestInit = {}, token?: string, unwrapData = true): Promise<T> {
  const headers = new Headers(options.headers ?? {});
  if (!headers.has('Content-Type') && !(options.body instanceof FormData)) {
    headers.set('Content-Type', 'application/json');
  }

  if (token) {
    headers.set('Authorization', `Bearer ${token}`);
  }

  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...options,
    headers,
  });

  const payload = await response.json().catch(() => null);
  if (!response.ok) {
    const message = (payload as ApiErrorBody | null)?.error?.message ?? 'Request failed.';
    throw new Error(message);
  }

  return (unwrapData ? payload?.data ?? payload : payload) as T;
}

export function getStoredToken(): string | null {
  return localStorage.getItem(AUTH_TOKEN_KEY);
}

export function storeToken(token: string): void {
  localStorage.setItem(AUTH_TOKEN_KEY, token);
}

export function clearStoredToken(): void {
  localStorage.removeItem(AUTH_TOKEN_KEY);
}

export async function registerUser(payload: { email: string; password: string; full_name: string }) {
  return request<{ id: string; email: string; full_name: string; is_active: boolean }>(
    '/auth/register',
    { method: 'POST', body: JSON.stringify(payload) },
  );
}

export async function loginUser(payload: { email: string; password: string }) {
  return request<{ token: string; token_type: string; user: { id: string; email: string; full_name: string; is_active: boolean } }>(
    '/auth/login',
    { method: 'POST', body: JSON.stringify(payload) },
  );
}

export async function getCurrentUser(token: string) {
  return request<{ id: string; email: string; full_name: string; is_active: boolean }>('/auth/me', { method: 'GET' }, token);
}

export async function logoutUser(token: string) {
  return request<{ message: string; user_id: string }>('/auth/logout', { method: 'POST' }, token);
}

export type FindingApiResponse = {
  id: string;
  scan_id: string;
  website_id: string;
  title: string;
  slug: string;
  fingerprint: string;
  severity: string;
  priority: string;
  category: string;
  description: string;
  evidence: string | Record<string, unknown> | unknown[];
  recommendation: string;
  status: string;
  remediation_status?: string | null;
  references: string | null;
  first_seen_at: string;
  last_seen_at: string;
  occurrence_count: number;
  resolved_at: string | null;
  created_at: string;
  updated_at: string;
  website_name?: string;
  website_url?: string;
  scan_status?: string;
  scan_type?: string;
  scan_completed_at?: string | null;
};

export type FindingRemediationApiResponse = {
  id: string;
  finding_id: string;
  business_id: string;
  website_id: string;
  user_id: string;
  status: string;
  remediation_notes: string | null;
  started_at: string | null;
  completed_at: string | null;
  verification_requested_at: string | null;
  verified_at: string | null;
  verification_scan_id: string | null;
  verification_result: string | null;
  created_at: string;
  updated_at: string;
};

export type AuditEventApiResponse = {
  id: string;
  actor_user_id: string | null;
  business_id: string | null;
  event_type: string;
  action: string;
  resource_type: string | null;
  resource_id: string | null;
  outcome: string;
  severity: string;
  message: string;
  request_id: string | null;
  details: string | null;
  created_at: string;
};

export type BusinessApiResponse = {
  id: string;
  owner_id: string;
  name: string;
  industry: string | null;
  description: string | null;
  created_at: string;
  updated_at: string;
};

export type WebsiteApiResponse = {
  id: string;
  business_id: string;
  name: string;
  url: string;
  normalized_url: string;
  hostname: string;
  status: string;
  created_at: string;
  updated_at: string;
  last_scan_at: string | null;
};

export type MonitoringTargetApiResponse = {
  id: string;
  business_id: string;
  website_id: string;
  enabled: boolean;
  schedule: string;
  interval_minutes: number;
  last_check_at: string | null;
  next_check_at: string | null;
  last_scan_id: string | null;
  previous_scan_id: string | null;
  paused_at: string | null;
  failure_count: number;
  last_error: string | null;
  created_at: string;
  updated_at: string;
};

export type MonitoringHistoryApiResponse = {
  scan_id: string;
  status: string;
  started_at: string | null;
  completed_at: string | null;
  findings_count: number;
  new_findings_count: number;
  resolved_findings_count: number;
  changed_findings_count: number;
  persistent_findings_count: number;
  previous_risk_score: number | null;
  current_risk_score: number | null;
  risk_delta: number | null;
  failure_code: string | null;
};

export type MonitoringOverviewApiResponse = {
  monitoring_id: string;
  business_id: string;
  website_id: string;
  website_name: string;
  website_url: string | null;
  enabled: boolean;
  status: string;
  last_check_at: string | null;
  last_scan_id: string | null;
  last_scan_at: string | null;
  current_risk_score: number | null;
  previous_risk_score: number | null;
  risk_delta: number | null;
  findings_count: number;
  open_finding_count: number;
  failure_count: number;
  last_error: string | null;
  updated_at: string;
};

export type MonitoringChangeApiResponse = {
  fingerprint: string;
  title: string;
  category: string;
  severity: string;
  status: string;
  previous_severity: string | null;
  current_severity: string | null;
  previous_evidence: string | null;
  current_evidence: string | null;
  changed_at: string;
};

export async function listAuditEvents(token: string, params?: { page?: number; page_size?: number; event_type?: string; resource_type?: string; resource_id?: string; outcome?: string; start_date?: string; end_date?: string }) {
  const query = new URLSearchParams();
  if (params) {
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined && value !== null && value !== '') query.append(key, String(value));
    });
  }
  const suffix = query.toString() ? `?${query.toString()}` : '';
  return request<{ data: AuditEventApiResponse[]; meta: ApiListMeta & { request_id?: string } }>(`/audit-events${suffix}`, { method: 'GET' }, token, false);
}

export async function listBusinesses(token: string) {
  return request<{ data: BusinessApiResponse[]; meta: ApiListMeta }>('/businesses', { method: 'GET' }, token, false);
}

export async function listWebsites(token: string) {
  return request<{ data: WebsiteApiResponse[]; meta: ApiListMeta }>('/websites', { method: 'GET' }, token, false);
}

export async function getSecurityOverview(token: string) {
  return request<{
    score: number;
    risk_model_version: string;
    severity_counts: Record<string, number>;
    open_finding_count: number;
    affected_website_count: number;
    top_risk_drivers: string[];
    latest_scan_status: string | null;
    latest_scan_id: string | null;
  }>('/security/overview', { method: 'GET' }, token);
}

export type SecurityPostureApiResponse = {
  summary: {
    risk_score: number;
    previous_risk_score: number | null;
    risk_delta: number | null;
    assessment_status: string;
    business_name: string | null;
  };
  risk: {
    current_score: number;
    previous_score: number | null;
    delta: number | null;
    trend_status: string;
    model_version: string;
  };
  findings: {
    open: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    acknowledged: number;
  };
  alerts: {
    total_open: number;
    critical: number;
    high: number;
    monitoring_failures: number;
  };
  monitoring: {
    active_targets: number;
    disabled_targets: number;
    last_assessment_at: string | null;
    next_assessment_at: string | null;
    failed_assessments: number;
    recent_changes: Array<{ status: string; title: string; severity: string }>;
  };
  trends: {
    history: Array<{ date: string | null; risk_score: number }>;
    status: string;
  };
  priorities: Array<{ title: string; source_type: string; source_id: string; severity: string; reference: string }>;
  categories: Array<{ category: string; open_findings: number; highest_severity: string; status: string }>;
  metadata: {
    business_id: string | null;
    business_name: string | null;
    website_count: number;
    assessment_count: number;
    generated_at: string;
    latest_scan_id: string | null;
  };
  executive_summary: string;
};

export async function getSecurityPosture(token: string) {
  return request<SecurityPostureApiResponse>('/security/posture', { method: 'GET' }, token);
}

export async function listMonitoring(token: string) {
  return request<{ data: MonitoringTargetApiResponse[]; meta: ApiListMeta }>('/monitoring', { method: 'GET' }, token, false);
}

export async function getMonitoringOverview(token: string) {
  return request<{ data: MonitoringOverviewApiResponse[]; meta: { request_id: string } }>('/monitoring/overview', { method: 'GET' }, token, false);
}

export async function getMonitoring(token: string, id: string) {
  return request<{ data: MonitoringTargetApiResponse; meta: { request_id: string } }>(`/monitoring/${id}`, { method: 'GET' }, token, false);
}

export async function createMonitoring(token: string, payload: { business_id: string; website_id: string; enabled?: boolean; schedule?: string; interval_minutes?: number }) {
  return request<{ data: MonitoringTargetApiResponse; meta: { request_id: string } }>('/monitoring', {
    method: 'POST',
    body: JSON.stringify(payload),
  }, token, false);
}

export async function updateMonitoring(token: string, id: string, payload: { enabled?: boolean; schedule?: string; interval_minutes?: number }) {
  return request<{ data: MonitoringTargetApiResponse; meta: { request_id: string } }>(`/monitoring/${id}`, {
    method: 'PATCH',
    body: JSON.stringify(payload),
  }, token, false);
}

export async function deleteMonitoring(token: string, id: string) {
  return request<void>(`/monitoring/${id}`, { method: 'DELETE' }, token, false);
}

export async function getMonitoringHistory(token: string, id: string, page = 1, pageSize = 20) {
  return request<{ data: MonitoringHistoryApiResponse[]; meta: ApiListMeta & { request_id: string } }>(`/monitoring/${id}/history?page=${page}&page_size=${pageSize}`, { method: 'GET' }, token, false);
}

export async function getMonitoringChanges(token: string, id: string) {
  return request<{ data: MonitoringChangeApiResponse[]; meta: { request_id: string } }>(`/monitoring/${id}/changes`, { method: 'GET' }, token, false);
}

export type AlertApiResponse = {
  id: string;
  business_id: string;
  website_id: string | null;
  monitoring_id: string | null;
  scan_id: string | null;
  finding_id: string | null;
  alert_type: string;
  severity: string;
  title: string;
  message: string;
  status: string;
  deduplication_key: string;
  alert_metadata: string | null;
  created_at: string;
  updated_at: string;
  acknowledged_at: string | null;
  resolved_at: string | null;
  website_name: string | null;
  finding_reference: string | null;
  safe_evidence: string[];
  previous_risk_score: number | null;
  current_risk_score: number | null;
  risk_delta: number | null;
};

export async function listAlerts(token: string, params: Record<string, string | number | undefined> = {}) {
  const query = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== '') {
      query.set(key, String(value));
    }
  });
  const suffix = query.toString() ? `?${query.toString()}` : '';
  return request<{ data: AlertApiResponse[]; meta: ApiListMeta }>('/alerts' + suffix, { method: 'GET' }, token, false);
}

export async function getAlert(token: string, id: string) {
  return request<{ data: AlertApiResponse; meta: { request_id: string } }>(`/alerts/${id}`, { method: 'GET' }, token, false);
}

export async function updateAlert(token: string, id: string, payload: { status: string }) {
  return request<{ data: AlertApiResponse; meta: { request_id: string } }>(`/alerts/${id}`, {
    method: 'PATCH',
    body: JSON.stringify(payload),
  }, token, false);
}

export async function getUnreadAlertCount(token: string) {
  return request<{ data: { count: number }; meta: { request_id: string } }>('/alerts/unread-count', { method: 'GET' }, token, false);
}

export type AlertSummaryApiResponse = {
  total: number;
  open: number;
  acknowledged: number;
  resolved: number;
  by_severity: Record<string, number>;
  open_by_severity: Record<string, number>;
  open_monitoring_failures: number;
};

export async function getAlertSummary(token: string) {
  return request<{ data: AlertSummaryApiResponse; meta: { request_id: string } }>('/alerts/summary', { method: 'GET' }, token, false);
}

export type ReportApiResponse = {
  id: string;
  business_id: string;
  requested_by: string;
  website_id: string | null;
  scan_id: string | null;
  report_type: string;
  title: string;
  status: string;
  generated_at: string | null;
  risk_score_snapshot: number | null;
  risk_model_version: string | null;
  artifact_path: string | null;
  created_at: string;
  updated_at: string;
  metadata?: Record<string, unknown>;
};

export async function listReports(token: string, options: { page?: number; page_size?: number; search?: string; website_id?: string; status?: string; sort?: string } = {}) {
  const params = new URLSearchParams();
  Object.entries(options).forEach(([key, value]) => {
    if (value) params.set(key, String(value));
  });
  const query = params.toString();
  return request<{ data: ReportApiResponse[]; meta: ApiListMeta }>(`/reports${query ? `?${query}` : ''}`, { method: 'GET' }, token, false);
}

export async function getReport(token: string, id: string) {
  return request<{ data: ReportApiResponse; meta: { request_id: string } }>(`/reports/${id}`, { method: 'GET' }, token, false);
}

export async function createReport(token: string, payload: { business_id: string; website_id?: string | null; scan_id?: string | null; title?: string; report_type?: string }) {
  return request<{ data: ReportApiResponse; meta: { request_id: string } }>('/reports', {
    method: 'POST',
    body: JSON.stringify(payload),
  }, token, false);
}

export async function downloadReport(token: string, id: string) {
  const response = await fetch(`${API_BASE_URL}/reports/${id}/download`, {
    method: 'GET',
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!response.ok) {
    const body = await response.json().catch(() => null);
    throw new Error((body as ApiErrorBody | null)?.error?.message ?? 'Unable to download report.');
  }
  return response.blob();
}

export async function listFindings(token: string, params: Record<string, string | number | undefined> = {}) {
  const query = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== '') {
      query.set(key, String(value));
    }
  });
  const suffix = query.toString() ? `?${query.toString()}` : '';
  return request<{ data: FindingApiResponse[]; meta: ApiListMeta }>('/findings' + suffix, { method: 'GET' }, token, false);
}

export async function getFinding(token: string, id: string) {
  return request<{ data: FindingApiResponse; meta: { request_id: string } }>(`/findings/${id}`, { method: 'GET' }, token, false);
}

export async function updateFinding(token: string, id: string, payload: { status: string }) {
  return request<{ data: FindingApiResponse; meta: { request_id: string } }>(`/findings/${id}`, {
    method: 'PATCH',
    body: JSON.stringify(payload),
  }, token, false);
}

export async function getFindingRemediation(token: string, findingId: string) {
  return request<{ data: FindingRemediationApiResponse; meta: { request_id: string } }>(`/findings/${findingId}/remediation`, { method: 'GET' }, token, false);
}

export async function createFindingRemediation(token: string, findingId: string, payload: { remediation_notes?: string } = {}) {
  return request<{ data: FindingRemediationApiResponse; meta: { request_id: string } }>(`/findings/${findingId}/remediation`, {
    method: 'POST',
    body: JSON.stringify(payload),
  }, token, false);
}

export async function updateFindingRemediation(token: string, findingId: string, payload: { status?: string; remediation_notes?: string }) {
  return request<{ data: FindingRemediationApiResponse; meta: { request_id: string } }>(`/findings/${findingId}/remediation`, {
    method: 'PATCH',
    body: JSON.stringify(payload),
  }, token, false);
}

export async function verifyFindingRemediation(token: string, findingId: string) {
  return request<{ data: FindingRemediationApiResponse; meta: { request_id: string } }>(`/findings/${findingId}/remediation/verify`, {
    method: 'POST',
  }, token, false);
}

export type AiResponse = {
  summary: string;
  why_it_matters: string;
  verified_evidence: string[];
  remediation_steps: string[];
  verification_steps: string[];
  limitations: string;
};

export async function explainFinding(token: string, findingId: string) {
  return request<{ data: AiResponse; meta: { request_id: string } }>('/ai/explain', {
    method: 'POST',
    body: JSON.stringify({ finding_id: findingId }),
  }, token, false);
}

export async function requestFindingRemediation(token: string, findingId: string) {
  return request<{ data: AiResponse; meta: { request_id: string } }>('/ai/remediation', {
    method: 'POST',
    body: JSON.stringify({ finding_id: findingId }),
  }, token, false);
}
