import { BrowserRouter, Link, NavLink, Navigate, Route, Routes, useLocation, useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { useEffect, useState } from 'react';
import {
  AlertTriangle,
  Bell,
  BriefcaseBusiness,
  CheckCircle2,
  CircleDashed,
  Download,
  FileText,
  Gauge,
  KeyRound,
  LayoutDashboard,
  Menu,
  Moon,
  MonitorCog,
  Search,
  ShieldCheck,
  Sparkles,
  SunMedium,
  Target,
  TriangleAlert,
  UserCircle2,
  Wand2,
  X,
  Zap,
} from 'lucide-react';
import './App.css';
import {
  clearStoredToken,
  createMonitoring,
  createReport,
  deleteMonitoring,
  downloadReport,
  explainFinding,
  createFindingRemediation,
  getAlert,
  getAlertSummary,
  getFinding,
  getFindingRemediation,
  getMonitoringChanges,
  getMonitoringHistory,
  getMonitoringOverview,
  getReport,
  getSecurityOverview,
  getSecurityPosture,
  getStoredToken,
  getUnreadAlertCount,
  listAlerts,
  listAuditEvents,
  listBusinesses,
  listFindings,
  listMonitoring,
  listReports,
  listWebsites,
  loginUser,
  logoutUser,
  registerUser,
  requestFindingRemediation,
  type AlertApiResponse,
  type ApiListMeta,
  type AiResponse,
  type AuditEventApiResponse,
  type BusinessApiResponse,
  type FindingApiResponse,
  type FindingRemediationApiResponse,
  type MonitoringChangeApiResponse,
  type MonitoringOverviewApiResponse,
  type MonitoringHistoryApiResponse,
  type MonitoringTargetApiResponse,
  type ReportApiResponse,
  type SecurityPostureApiResponse,
  type WebsiteApiResponse,
  updateAlert,
  updateFinding,
  updateFindingRemediation,
  updateMonitoring,
  verifyFindingRemediation,
} from './apiClient';
import { scans, user, websites } from './data/mockData';
import { businessModelFeatures, businessModelPlans, businessModelSegments, businessModelWorkflow } from './businessModel';
import type { BusinessPlan } from './businessModel';
import type { Finding, Severity, ThemeMode } from './types';

const navItems = [
  { to: '/dashboard', label: 'Overview', icon: LayoutDashboard },
  { to: '/security-posture', label: 'Security Posture', icon: ShieldCheck },
  { to: '/websites', label: 'Websites', icon: ShieldCheck },
  { to: '/scans', label: 'Scans', icon: Target },
  { to: '/findings', label: 'Findings', icon: AlertTriangle },
  { to: '/alerts', label: 'Alerts', icon: Bell },
  { to: '/activity', label: 'Security Activity', icon: FileText },
  { to: '/reports', label: 'Reports', icon: FileText },
  { to: '/monitoring', label: 'Monitoring', icon: MonitorCog },
  { to: '/ai-assistant', label: 'AI Assistant', icon: Wand2 },
  { to: '/business-model', label: 'Plans', icon: BriefcaseBusiness },
];

const secondaryNav = [
  { to: '/settings', label: 'Settings', icon: KeyRound },
  { to: '/help', label: 'Help', icon: CircleDashed },
];

const formatSeverityLabel = (severity: Severity) => severity.toLowerCase();

const toDisplaySeverity = (value: string): string => {
  const normalized = value.toLowerCase();
  if (normalized === 'info' || normalized === 'informational') return 'Informational';
  if (normalized === 'low') return 'Low';
  if (normalized === 'medium') return 'Medium';
  if (normalized === 'high') return 'High';
  if (normalized === 'critical') return 'Critical';
  return value;
};

const toDisplayStatus = (value: string): string => {
  const normalized = value.toLowerCase();
  if (normalized === 'resolved') return 'Resolved';
  if (normalized === 'acknowledged') return 'Acknowledged';
  if (normalized === 'open') return 'Open';
  return value;
};

const formatDateLabel = (value?: string | null): string => {
  if (!value) return 'Not available';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat('en-US', { month: 'short', day: 'numeric', year: 'numeric' }).format(date);
};

const parseEvidence = (value: string | Record<string, unknown> | unknown[] | null | undefined): string[] => {
  if (Array.isArray(value)) return value.map((item) => String(item));
  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (!trimmed) return [];
    try {
      const parsed = JSON.parse(trimmed);
      if (Array.isArray(parsed)) return parsed.map((item) => String(item));
    } catch {
      return [trimmed];
    }
    return [trimmed];
  }
  if (value && typeof value === 'object') {
    return Object.entries(value).map(([key, entry]) => `${key}: ${String(entry)}`);
  }
  return [];
};

const normalizeApiFinding = (finding: FindingApiResponse): Finding => ({
  id: finding.id,
  title: finding.title,
  severity: toDisplaySeverity(finding.severity) as Severity,
  category: finding.category,
  website: finding.website_id,
  status: toDisplayStatus(finding.status) as Finding['status'],
  detectedDate: formatDateLabel(finding.last_seen_at),
  description: finding.description || 'No finding description was provided by the scan result.',
  evidence: parseEvidence(finding.evidence),
  recommendation: finding.recommendation || 'No remediation guidance is available for this finding.',
  whyItMatters: undefined,
  affectedAsset: finding.website_id,
  verification: undefined,
  websiteName: finding.website_name,
  websiteUrl: finding.website_url,
  scanStatus: finding.scan_status,
  scanType: finding.scan_type,
  scanCompletedAt: finding.scan_completed_at,
  remediationStatus: finding.remediation_status ?? undefined,
  firstSeenAt: finding.first_seen_at,
  lastSeenAt: finding.last_seen_at,
  occurrenceCount: finding.occurrence_count,
  resolvedAt: finding.resolved_at,
});

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const token = getStoredToken();
  if (!token) {
    return <Navigate to="/login" replace />;
  }
  return <>{children}</>;
}

function App() {
  const [theme] = useState<ThemeMode>(() => {
    const saved = localStorage.getItem('cybershield-theme') as ThemeMode | null;
    return saved ?? 'system';
  });

  useEffect(() => {
    const root = document.documentElement;
    const systemPrefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    const resolvedTheme = theme === 'system' ? (systemPrefersDark ? 'dark' : 'light') : theme;
    root.dataset.theme = resolvedTheme;
    localStorage.setItem('cybershield-theme', theme);
  }, [theme]);

  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<LandingPage />} />
        <Route path="/login" element={<AuthPage mode="login" />} />
        <Route path="/register" element={<AuthPage mode="register" />} />
        <Route path="/onboarding" element={<OnboardingPage />} />
        <Route path="/dashboard" element={<ProtectedRoute><AppShell><DashboardPage /></AppShell></ProtectedRoute>} />
        <Route path="/security-posture" element={<ProtectedRoute><AppShell><SecurityPosturePage /></AppShell></ProtectedRoute>} />
        <Route path="/websites" element={<ProtectedRoute><AppShell><WebsitesPage /></AppShell></ProtectedRoute>} />
        <Route path="/websites/add" element={<ProtectedRoute><AppShell><WebsiteAddPage /></AppShell></ProtectedRoute>} />
        <Route path="/scans" element={<ProtectedRoute><AppShell><ScansPage /></AppShell></ProtectedRoute>} />
        <Route path="/findings" element={<ProtectedRoute><AppShell><FindingsPage /></AppShell></ProtectedRoute>} />
        <Route path="/findings/:id" element={<ProtectedRoute><AppShell><FindingDetailPage /></AppShell></ProtectedRoute>} />
        <Route path="/alerts" element={<ProtectedRoute><AppShell><AlertsPage /></AppShell></ProtectedRoute>} />
        <Route path="/alerts/:id" element={<ProtectedRoute><AppShell><AlertDetailPage /></AppShell></ProtectedRoute>} />
        <Route path="/activity" element={<ProtectedRoute><AppShell><SecurityActivityPage /></AppShell></ProtectedRoute>} />
        <Route path="/reports" element={<ProtectedRoute><AppShell><ReportsPage /></AppShell></ProtectedRoute>} />
        <Route path="/reports/:id" element={<ProtectedRoute><AppShell><ReportDetailPage /></AppShell></ProtectedRoute>} />
        <Route path="/monitoring" element={<ProtectedRoute><AppShell><MonitoringPage /></AppShell></ProtectedRoute>} />
        <Route path="/ai-assistant" element={<ProtectedRoute><AppShell><AiAssistantPage /></AppShell></ProtectedRoute>} />
        <Route path="/business-model" element={<ProtectedRoute><AppShell><BusinessModelPage /></AppShell></ProtectedRoute>} />
        <Route path="/settings" element={<ProtectedRoute><AppShell><SettingsPage /></AppShell></ProtectedRoute>} />
        <Route path="/help" element={<ProtectedRoute><AppShell><HelpPage /></AppShell></ProtectedRoute>} />
        <Route path="/404" element={<PageNotFound />} />
        <Route path="*" element={<Navigate to="/404" replace />} />
      </Routes>
    </BrowserRouter>
  );
}

function AppShell({ children }: { children: React.ReactNode }) {
  const [isDrawerOpen, setIsDrawerOpen] = useState(false);
  const location = useLocation();
  const navigate = useNavigate();

  const breadcrumbs = location.pathname
    .split('/')
    .filter(Boolean)
    .map((segment) => segment.replace(/-/g, ' '));

  return (
    <div className="app-shell">
      <aside className={`sidebar ${isDrawerOpen ? 'open' : ''}`}>
        <div className="brand-block">
          <div className="brand-mark"><ShieldCheck size={18} /></div>
          <div>
            <div className="brand-name">CyberShield</div>
            <div className="brand-subtitle">Security overview</div>
          </div>
        </div>

        <nav className="nav-group" aria-label="Primary navigation">
          {navItems.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
              onClick={() => setIsDrawerOpen(false)}
            >
              <Icon size={17} />
              <span>{label}</span>
            </NavLink>
          ))}
        </nav>

        <div className="nav-divider" />

        <nav className="nav-group" aria-label="Secondary navigation">
          {secondaryNav.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
              onClick={() => setIsDrawerOpen(false)}
            >
              <Icon size={17} />
              <span>{label}</span>
            </NavLink>
          ))}
        </nav>

        <div className="user-card">
          <div className="user-avatar">AP</div>
          <div>
            <div className="user-name">{user.name}</div>
            <div className="user-org">{user.company}</div>
            <button
              className="ghost-button small"
              type="button"
              onClick={async () => {
                const token = getStoredToken();
                if (token) {
                  try {
                    await logoutUser(token);
                  } catch {
                    // logout is best-effort and token removal is the important action.
                  }
                }
                clearStoredToken();
                navigate('/login');
              }}
            >
              Sign out
            </button>
          </div>
        </div>
      </aside>

      <div className="page-shell">
        <header className="topbar">
          <div className="topbar-left">
            <button className="icon-button mobile-only" type="button" aria-label="Toggle menu" onClick={() => setIsDrawerOpen((value) => !value)}>
              {isDrawerOpen ? <X size={18} /> : <Menu size={18} />}
            </button>
            <div className="breadcrumbs" aria-label="Breadcrumb">
              <span className="crumb">Home</span>
              {breadcrumbs.length > 0 && breadcrumbs.map((segment) => <span key={segment} className="crumb-separator">/</span>)}
              {breadcrumbs.length > 0 && <span className="crumb current">{breadcrumbs[breadcrumbs.length - 1]}</span>}
            </div>
          </div>

          <div className="topbar-right">
            <label className="search-field" aria-label="Search">
              <Search size={15} />
              <input type="text" placeholder="Search" aria-label="Search placeholder" />
            </label>
            <AlertIndicator />
            <ThemeToggle />
            <button type="button" className="avatar-pill">
              <UserCircle2 size={18} />
              <span>{user.name}</span>
            </button>
          </div>
        </header>

        <main className="main-content">
          {children}
        </main>
      </div>
    </div>
  );
}

function ThemeToggle() {
  const [mode, setMode] = useState<ThemeMode>(() => localStorage.getItem('cybershield-theme') as ThemeMode || 'system');

  useEffect(() => {
    setMode(localStorage.getItem('cybershield-theme') as ThemeMode || 'system');
  }, []);

  const handleThemeChange = (nextMode: ThemeMode) => {
    localStorage.setItem('cybershield-theme', nextMode);
    document.documentElement.dataset.theme = nextMode === 'system' ? (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light') : nextMode;
    setMode(nextMode);
  };

  return (
    <div className="theme-toggle" aria-label="Theme selector">
      <button type="button" className={mode === 'light' ? 'selected' : ''} onClick={() => handleThemeChange('light')} aria-label="Use light theme">
        <SunMedium size={14} />
      </button>
      <button type="button" className={mode === 'dark' ? 'selected' : ''} onClick={() => handleThemeChange('dark')} aria-label="Use dark theme">
        <Moon size={14} />
      </button>
      <button type="button" className={mode === 'system' ? 'selected' : ''} onClick={() => handleThemeChange('system')} aria-label="Use system theme">
        <MonitorCog size={14} />
      </button>
    </div>
  );
}

function AlertIndicator() {
  const navigate = useNavigate();
  const [count, setCount] = useState(0);

  useEffect(() => {
    const token = getStoredToken();
    if (!token) {
      setCount(0);
      return;
    }

    getUnreadAlertCount(token)
      .then((result) => setCount(result.data?.count ?? 0))
      .catch(() => setCount(0));
  }, []);

  return (
    <button type="button" className="icon-button" aria-label="Alerts" onClick={() => navigate('/alerts')}>
      <Bell size={17} />
      {count > 0 && (
        <span aria-hidden="true" style={{ position: 'absolute', top: '6px', right: '6px', minWidth: '16px', height: '16px', borderRadius: '999px', background: '#ef4444', color: '#fff', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '10px', fontWeight: 700 }}>
          {count > 99 ? '99+' : count}
        </span>
      )}
    </button>
  );
}

function AlertSummaryPanel() {
  const [summary, setSummary] = useState<{ total: number; open: number; open_by_severity: Record<string, number>; open_monitoring_failures: number } | null>(null);
  const [latest, setLatest] = useState<AlertApiResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const token = getStoredToken();
    if (!token) {
      setSummary(null);
      setLatest(null);
      return;
    }

    Promise.all([
      getAlertSummary(token),
      listAlerts(token, { page: 1, page_size: 1, status: 'open' }),
    ])
      .then(([summaryResponse, latestResponse]) => {
        setSummary(summaryResponse.data);
        setLatest(latestResponse.data[0] ?? null);
        setError(null);
      })
      .catch((fetchError) => setError(fetchError instanceof Error ? fetchError.message : 'Unable to load alerts.'));
  }, []);

  return (
    <div className="panel-surface chart-panel">
      <div className="panel-head">
        <h3>Alert summary</h3>
        <span className="demo-label">live</span>
      </div>
      {error ? <p>{error}</p> : (
        <div className="distribution-list">
          <div className="distribution-row"><strong>Open alerts</strong><span>{summary?.open ?? 0}</span></div>
          <div className="distribution-row"><strong>Open critical alerts</strong><span>{summary?.open_by_severity.critical ?? 0}</span></div>
          <div className="distribution-row"><strong>Open high alerts</strong><span>{summary?.open_by_severity.high ?? 0}</span></div>
          <div className="distribution-row"><strong>Monitoring failures</strong><span>{summary?.open_monitoring_failures ?? 0}</span></div>
          <div className="distribution-row"><strong>Latest alert</strong><span>{latest ? latest.title : 'None'}</span></div>
        </div>
      )}
      <div className="action-row justify-end">
        <Link to="/alerts" className="secondary-button">Open alert center</Link>
      </div>
    </div>
  );
}

function AlertsPage() {
  const [items, setItems] = useState<AlertApiResponse[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [pageSize] = useState(10);
  const [status, setStatus] = useState('');
  const [severity, setSeverity] = useState('');
  const [alertType, setAlertType] = useState('');
  const [websiteId, setWebsiteId] = useState('');
  const [totalPages, setTotalPages] = useState(0);

  useEffect(() => {
    const token = getStoredToken();
    if (!token) {
      setError('You must sign in to view alerts.');
      setIsLoading(false);
      return;
    }

    setIsLoading(true);
    listAlerts(token, {
      page,
      page_size: pageSize,
      status: status || undefined,
      severity: severity || undefined,
      alert_type: alertType || undefined,
      website_id: websiteId || undefined,
    }).then((response) => {
      setItems(response.data ?? []);
      setTotalPages(response.meta.total_pages);
      setError(null);
    }).catch((fetchError) => {
      setItems([]);
      setError(fetchError instanceof Error ? fetchError.message : 'Unable to load alerts.');
    }).finally(() => setIsLoading(false));
  }, [page, pageSize, status, severity, alertType, websiteId]);

  const handleStatusUpdate = async (alertId: string, nextStatus: 'acknowledged' | 'resolved') => {
    const token = getStoredToken();
    if (!token) return;
    try {
      await updateAlert(token, alertId, { status: nextStatus });
      setItems((current) => current.map((item) => item.id === alertId ? { ...item, status: nextStatus } : item));
    } catch (fetchError) {
      setError(fetchError instanceof Error ? fetchError.message : 'Unable to update alert state.');
    }
  };

  const summary = {
    open: items.filter((item) => item.status === 'open').length,
    critical: items.filter((item) => item.severity === 'critical').length,
    high: items.filter((item) => item.severity === 'high').length,
    recent: items.slice(0, 5).length,
  };

  return (
    <div className="page-layout">
      <PageHeader eyebrow="Alerts" title="Alert center" description="Review verified, prioritized security events that require action." />
      {error && <div className="inline-status danger">{error}</div>}
      {isLoading && <div className="inline-status neutral">Loading alerts…</div>}
      {!error && (
        <>
          <div className="summary-row">
            <SummaryPill label="Open alerts" value={summary.open} tone="warning" />
            <SummaryPill label="Critical" value={summary.critical} tone="danger" />
            <SummaryPill label="High" value={summary.high} tone="warning" />
            <SummaryPill label="Recent" value={summary.recent} tone="info" />
          </div>

          <div className="filter-bar panel-surface">
            <label className="field-block compact">
              <span>Status</span>
              <select value={status} onChange={(event) => { setPage(1); setStatus(event.target.value); }}>
                <option value="">Any</option>
                <option value="open">Open</option>
                <option value="acknowledged">Acknowledged</option>
                <option value="resolved">Resolved</option>
              </select>
            </label>
            <label className="field-block compact">
              <span>Severity</span>
              <select value={severity} onChange={(event) => { setPage(1); setSeverity(event.target.value); }}>
                <option value="">Any</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </label>
            <label className="field-block compact">
              <span>Type</span>
              <select value={alertType} onChange={(event) => { setPage(1); setAlertType(event.target.value); }}>
                <option value="">Any</option>
                <option value="NEW_CRITICAL_FINDING">New critical finding</option>
                <option value="NEW_HIGH_FINDING">New high finding</option>
                <option value="RISK_SCORE_INCREASE">Risk score increase</option>
                <option value="SIGNIFICANT_SECURITY_CHANGE">Significant change</option>
                <option value="MONITORING_FAILURE">Monitoring failure</option>
              </select>
            </label>
            <label className="field-block compact">
              <span>Website ID</span>
              <input type="text" value={websiteId} onChange={(event) => { setPage(1); setWebsiteId(event.target.value); }} placeholder="Optional website id" />
            </label>
          </div>

          {items.length === 0 ? (
            <div className="panel-surface empty-state">No alerts match the current filters.</div>
          ) : (
            <div className="finding-list">
              {items.map((alert) => (
                <div key={alert.id} className="panel-surface result-card" style={{ marginBottom: '12px' }}>
                  <div className="result-header">
                    <div>
                      <div style={{ fontSize: 12, textTransform: 'uppercase', letterSpacing: 0.8, color: '#7dd3fc' }}>{alert.alert_type}</div>
                      <h3 style={{ margin: '6px 0' }}>{alert.title}</h3>
                    </div>
                    <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
                      <span className="status-pill" style={{ textTransform: 'capitalize' }}>{alert.severity}</span>
                      <span className="status-pill" style={{ textTransform: 'capitalize' }}>{alert.status}</span>
                    </div>
                  </div>
                  <p>{alert.message}</p>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 12, fontSize: 12, color: '#94a3b8' }}>
                    <span>Website: {alert.website_name ?? alert.website_id ?? 'N/A'}</span>
                    <span>Created: {new Date(alert.created_at).toLocaleString()}</span>
                  </div>
                  <div className="action-row justify-end">
                    <Link to={`/alerts/${alert.id}`} className="secondary-button">View details</Link>
                    {alert.status === 'open' && (
                      <button type="button" className="secondary-button" onClick={() => handleStatusUpdate(alert.id, 'acknowledged')}>Acknowledge</button>
                    )}
                    {alert.status !== 'resolved' && (
                      <button type="button" className="primary-button" onClick={() => handleStatusUpdate(alert.id, 'resolved')}>Resolve</button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}

          <div className="action-row justify-end">
            <button type="button" className="secondary-button" onClick={() => setPage((current) => Math.max(1, current - 1))} disabled={page <= 1}>Previous</button>
            <span>Page {page}</span>
            <button type="button" className="primary-button" onClick={() => setPage((current) => current + 1)} disabled={totalPages === 0 || page >= totalPages}>Next</button>
          </div>
        </>
      )}
    </div>
  );
}

function AlertDetailPage() {
  const { id } = useParams();
  const [alert, setAlert] = useState<AlertApiResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const token = getStoredToken();
    if (!token || !id) {
      setError('Alert detail is unavailable.');
      setIsLoading(false);
      return;
    }

    getAlert(token, id)
      .then((response) => {
        setAlert(response.data ?? null);
        setError(null);
      })
      .catch((fetchError) => setError(fetchError instanceof Error ? fetchError.message : 'Unable to load alert detail.'))
      .finally(() => setIsLoading(false));
  }, [id]);

  const performAction = async (nextStatus: 'acknowledged' | 'resolved') => {
    const token = getStoredToken();
    if (!token || !id) return;
    try {
      const response = await updateAlert(token, id, { status: nextStatus });
      setAlert(response.data ?? null);
    } catch (fetchError) {
      setError(fetchError instanceof Error ? fetchError.message : 'Unable to update alert.');
    }
  };

  if (isLoading) return <div className="page-layout"><div className="inline-status neutral">Loading alert detail…</div></div>;
  if (error) return <div className="page-layout"><div className="inline-status danger">{error}</div></div>;
  if (!alert) return <div className="page-layout"><div className="inline-status neutral">No alert was found.</div></div>;

  return (
    <div className="page-layout narrow">
      <PageHeader eyebrow="Alert detail" title={alert.title} description={alert.message} />
      <div className="panel-surface form-panel">
        <div className="summary-row">
          <SummaryPill label="Severity" value={alert.severity} tone={alert.severity === 'critical' ? 'danger' : alert.severity === 'high' ? 'warning' : 'info'} />
          <SummaryPill label="Status" value={alert.status} tone={alert.status === 'resolved' ? 'success' : alert.status === 'acknowledged' ? 'warning' : 'info'} />
          <SummaryPill label="Type" value={alert.alert_type} tone="neutral" />
        </div>
        <div style={{ display: 'grid', gap: 10 }}>
          <div><strong>Website:</strong> {alert.website_name ?? alert.website_id ?? 'Not available'}</div>
          <div><strong>Created:</strong> {new Date(alert.created_at).toLocaleString()}</div>
          <div><strong>Alert message:</strong> {alert.message}</div>
          <div><strong>Monitoring ID:</strong> {alert.monitoring_id ?? 'N/A'}</div>
          <div><strong>Scan ID:</strong> {alert.scan_id ?? 'N/A'}</div>
          <div><strong>Finding reference:</strong> {alert.finding_reference ?? alert.finding_id ?? 'N/A'}</div>
          <div><strong>Previous risk score:</strong> {alert.previous_risk_score ?? 'N/A'}</div>
          <div><strong>Current risk score:</strong> {alert.current_risk_score ?? 'N/A'}</div>
          <div><strong>Risk delta:</strong> {alert.risk_delta ?? 'N/A'}</div>
          <div><strong>Safe evidence:</strong> {alert.safe_evidence.length ? alert.safe_evidence.join(' ') : 'None recorded'}</div>
        </div>
        <div className="action-row justify-end">
          {alert.status === 'open' && <button type="button" className="secondary-button" onClick={() => performAction('acknowledged')}>Acknowledge</button>}
          {alert.status !== 'resolved' && <button type="button" className="primary-button" onClick={() => performAction('resolved')}>Resolve</button>}
          <Link to="/alerts" className="secondary-button">Back to alerts</Link>
        </div>
      </div>
    </div>
  );
}

function SecurityActivityPage() {
  const [events, setEvents] = useState<AuditEventApiResponse[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [eventType, setEventType] = useState('');
  const [resourceType, setResourceType] = useState('');
  const [outcome, setOutcome] = useState('');

  useEffect(() => {
    const token = getStoredToken();
    if (!token) {
      setError('Security activity is unavailable.');
      setIsLoading(false);
      return;
    }

    listAuditEvents(token, {
      page: 1,
      page_size: 20,
      event_type: eventType || undefined,
      resource_type: resourceType || undefined,
      outcome: outcome || undefined,
    })
      .then((response) => {
        setEvents(response.data ?? []);
        setError(null);
      })
      .catch((fetchError) => setError(fetchError instanceof Error ? fetchError.message : 'Unable to load security activity.'))
      .finally(() => setIsLoading(false));
  }, [eventType, resourceType, outcome]);

  return (
    <div className="page-layout">
      <PageHeader eyebrow="Security activity" title="Security Activity" description="Review real user and system actions across the protected estate." />
      <div className="panel-surface form-panel">
        <div className="field-row compact">
          <label className="field-block compact">
            <span>Event type</span>
            <select value={eventType} onChange={(event) => setEventType(event.target.value)}>
              <option value="">Any</option>
              <option value="AUTHENTICATION">Authentication</option>
              <option value="WEBSITE">Website</option>
              <option value="SCANNING">Scanning</option>
              <option value="FINDINGS">Finding</option>
              <option value="ALERTS">Alerts</option>
              <option value="MONITORING">Monitoring</option>
              <option value="REPORTS">Reports</option>
              <option value="REMEDIATION">Remediation</option>
            </select>
          </label>
          <label className="field-block compact">
            <span>Resource</span>
            <select value={resourceType} onChange={(event) => setResourceType(event.target.value)}>
              <option value="">Any</option>
              <option value="website">Website</option>
              <option value="scan">Scan</option>
              <option value="finding">Finding</option>
              <option value="alert">Alert</option>
              <option value="report">Report</option>
              <option value="monitoring">Monitoring</option>
              <option value="user">User</option>
            </select>
          </label>
          <label className="field-block compact">
            <span>Outcome</span>
            <select value={outcome} onChange={(event) => setOutcome(event.target.value)}>
              <option value="">Any</option>
              <option value="SUCCESS">Success</option>
              <option value="FAILURE">Failure</option>
            </select>
          </label>
        </div>
      </div>

      {isLoading ? (
        <div className="inline-status neutral">Loading activity…</div>
      ) : error ? (
        <div className="inline-status danger">{error}</div>
      ) : events.length === 0 ? (
        <div className="panel-surface empty-state">No security activity matches the current filters.</div>
      ) : (
        <div className="finding-list">
          {events.map((event) => (
            <div key={event.id} className="panel-surface result-card" style={{ marginBottom: 12 }}>
              <div className="result-header">
                <div>
                  <div style={{ fontSize: 12, textTransform: 'uppercase', letterSpacing: 0.8, color: '#7dd3fc' }}>{event.event_type}</div>
                  <h3 style={{ margin: '6px 0' }}>{event.action.replace(/_/g, ' ').toLowerCase().replace(/(^\w|\s\w)/g, (match) => match.toUpperCase())}</h3>
                </div>
                <div className="status-pill" style={{ textTransform: 'capitalize' }}>{event.outcome.toLowerCase()}</div>
              </div>
              <p>{event.message}</p>
              <div style={{ display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12, fontSize: 12, color: '#94a3b8' }}>
                <span>Resource: {event.resource_type ?? 'N/A'} #{event.resource_id ?? 'N/A'}</span>
                <span>Actor: {event.actor_user_id ?? 'System'}</span>
                <span>{new Date(event.created_at).toLocaleString()}</span>
              </div>
              {event.details && <div style={{ marginTop: 12, color: '#cbd5e1', fontSize: 12 }}>Metadata: {event.details}</div>}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function RecentActivityPanel() {
  const [items, setItems] = useState<AuditEventApiResponse[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const token = getStoredToken();
    if (!token) return;

    listAuditEvents(token, { page: 1, page_size: 5 })
      .then((response) => setItems(response.data ?? []))
      .catch((fetchError) => setError(fetchError instanceof Error ? fetchError.message : 'Unable to load recent activity.'));
  }, []);

  return (
    <div className="panel-surface chart-panel">
      <div className="panel-head">
        <h3>Recent security activity</h3>
        <Link to="/activity" className="text-link">View Security Activity</Link>
      </div>
      {error ? <p>{error}</p> : items.length === 0 ? <p>No recent activity.</p> : (
        <div className="distribution-list">
          {items.slice(0, 4).map((item) => (
            <div key={item.id} className="distribution-row">
              <strong>{item.action.replace(/_/g, ' ')}</strong>
              <span>{new Date(item.created_at).toLocaleString()}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function LandingPage() {
  return (
    <div className="landing-page">
      <header className="landing-header">
        <div className="brand-row">
          <div className="brand-mark"><ShieldCheck size={18} /></div>
          <span>CyberShield</span>
        </div>
        <nav className="landing-nav">
          <Link to="/dashboard">Platform</Link>
          <Link to="/findings">Findings</Link>
          <Link to="/monitoring">Monitoring</Link>
        </nav>
        <div className="landing-actions">
          <Link to="/login" className="secondary-button">Login</Link>
          <Link to="/register" className="primary-button">Start Security Check</Link>
        </div>
      </header>

      <main className="landing-main">
        <section className="hero-section panel-surface">
          <div className="hero-copy">
            <div className="eyebrow">Small business cybersecurity</div>
            <h1>Know what puts your business at risk.</h1>
            <p>
              CyberShield gives small businesses a clear view of website security, prioritized findings,
              and practical remediation guidance.
            </p>
            <div className="cta-row">
              <Link to="/register" className="primary-button large">Start Security Check</Link>
              <Link to="/dashboard" className="secondary-button large">Explore CyberShield</Link>
            </div>
            <ul className="mini-proof">
              <li><CheckCircle2 size={16} /> Safe-by-design checks</li>
              <li><CheckCircle2 size={16} /> Transparent findings</li>
              <li><CheckCircle2 size={16} /> Practical remediation</li>
            </ul>
          </div>

          <div className="hero-visual" aria-label="CyberShield dashboard preview">
            <div className="dashboard-preview">
              <div className="preview-topbar">
                <span className="dot red" />
                <span className="dot amber" />
                <span className="dot green" />
              </div>
              <div className="preview-score-row">
                <div>
                  <small>Security posture</small>
                  <div className="preview-score">78 / 100</div>
                </div>
                <span className="status-pill success">Good</span>
              </div>
              <div className="preview-grid">
                <div className="mini-card">
                  <span>Active findings</span>
                  <strong>7</strong>
                </div>
                <div className="mini-card">
                  <span>Website status</span>
                  <strong>4 protected</strong>
                </div>
                <div className="mini-card">
                  <span>Recent scan</span>
                  <strong>Today</strong>
                </div>
                <div className="mini-card">
                  <span>Recommended</span>
                  <strong>3 actions</strong>
                </div>
              </div>
              <div className="progress-bars">
                <div>
                  <label>Critical</label>
                  <div className="bar"><span style={{ width: '18%' }} /></div>
                </div>
                <div>
                  <label>High</label>
                  <div className="bar"><span style={{ width: '34%' }} /></div>
                </div>
                <div>
                  <label>Medium</label>
                  <div className="bar"><span style={{ width: '46%' }} /></div>
                </div>
              </div>
            </div>
          </div>
        </section>

        <section className="problem-section section-block">
          <SectionHeader eyebrow="Why it matters" title="Security tools are often too technical for small teams." />
          <div className="three-col-grid">
            <FeatureCard icon={<TriangleAlert size={18} />} title="Too technical" description="Most tools require expertise many businesses do not have in-house." />
            <FeatureCard icon={<BriefcaseBusiness size={18} />} title="Limited time" description="Owners and operators need clear action, not long reports or jargon-heavy dashboards." />
            <FeatureCard icon={<Zap size={18} />} title="Hidden priorities" description="Important findings get buried before a team understands what needs attention first." />
          </div>
        </section>

        <section className="solution-section section-block">
          <SectionHeader eyebrow="Our approach" title="A simple progression from signal to action." />
          <div className="flow-grid">
            {['Discover', 'Understand', 'Prioritize', 'Fix', 'Monitor'].map((step, index) => (
              <div key={step} className="flow-card panel-surface">
                <div className="flow-step">0{index + 1}</div>
                <h3>{step}</h3>
                <p>Turn security observations into business-ready guidance and an understandable next step.</p>
              </div>
            ))}
          </div>
        </section>

        <section className="value-section section-block">
          <SectionHeader eyebrow="Value" title="Built for practical security decisions." />
          <div className="four-col-grid">
            <FeatureCard icon={<ShieldCheck size={18} />} title="Security Visibility" description="A clear overview of your website posture for non-specialist teams." />
            <FeatureCard icon={<Gauge size={18} />} title="Prioritized Risk" description="Focus on what matters most and remove noise from the signal." />
            <FeatureCard icon={<Sparkles size={18} />} title="Practical Remediation" description="Action-oriented guidance that helps teams fix issues without deep security expertise." />
            <FeatureCard icon={<MonitorCog size={18} />} title="Continuous Awareness" description="Keep an eye on meaningful security changes before they become bigger issues." />
          </div>
        </section>

        <section className="trust-section section-block panel-surface">
          <SectionHeader eyebrow="Trust" title="Safe, transparent, and practical by design." />
          <div className="trust-grid">
            {['Safe-by-design checks', 'Transparent findings', 'No destructive testing', 'Clear evidence', 'Actionable recommendations'].map((item) => (
              <div key={item} className="trust-item">
                <CheckCircle2 size={16} />
                <span>{item}</span>
              </div>
            ))}
          </div>
        </section>
      </main>
    </div>
  );
}

function AuthPage({ mode }: { mode: 'login' | 'register' }) {
  const isRegister = mode === 'register';
  const navigate = useNavigate();
  const [form, setForm] = useState({ fullName: '', email: '', password: '', businessName: '' });
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError(null);
    setIsSubmitting(true);

    try {
      if (isRegister) {
        const user = await registerUser({
          email: form.email,
          password: form.password,
          full_name: form.fullName,
        });
        if (user) {
          navigate('/login');
        }
        return;
      }

      const response = await loginUser({ email: form.email, password: form.password });
      localStorage.setItem('cybershield-token', response.token);
      navigate('/dashboard');
    } catch (submitError) {
      setError(submitError instanceof Error ? submitError.message : 'Unable to complete authentication.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="auth-page">
      <div className="auth-panel panel-surface">
        <div className="brand-block compact">
          <div className="brand-mark"><ShieldCheck size={18} /></div>
          <div>
            <div className="brand-name">CyberShield</div>
            <div className="brand-subtitle">Secure website oversight</div>
          </div>
        </div>

        <div className="auth-header">
          <h1>{isRegister ? 'Create your account' : 'Welcome back'}</h1>
          <p>{isRegister ? 'Set up your business and start scanning with confidence.' : 'Sign in to continue protecting your websites.'}</p>
        </div>

        <form className="auth-form" onSubmit={handleSubmit}>
          {isRegister && (
            <InputField
              label="Full name"
              type="text"
              placeholder="Aisha Patel"
              value={form.fullName}
              onChange={(value) => setForm((current) => ({ ...current, fullName: value }))}
            />
          )}
          <InputField
            label="Email"
            type="email"
            placeholder="name@company.com"
            value={form.email}
            onChange={(value) => setForm((current) => ({ ...current, email: value }))}
          />
          <InputField
            label="Password"
            type="password"
            placeholder="••••••••"
            value={form.password}
            onChange={(value) => setForm((current) => ({ ...current, password: value }))}
          />
          {isRegister && (
            <InputField
              label="Business name"
              type="text"
              placeholder="Northlane Studio"
              value={form.businessName}
              onChange={(value) => setForm((current) => ({ ...current, businessName: value }))}
            />
          )}
          {error && <div className="inline-status danger">{error}</div>}
          <button type="submit" className="primary-button full-width" disabled={isSubmitting}>
            {isSubmitting ? (isRegister ? 'Creating account...' : 'Logging in...') : (isRegister ? 'Create account' : 'Log in')}
          </button>
        </form>

        <div className="auth-footer">
          <Link to={isRegister ? '/login' : '/register'} className="text-link">
            {isRegister ? 'Already have an account? Log in' : 'Need an account? Create one'}
          </Link>
          <Link to="/dashboard" className="text-link">Preview dashboard</Link>
        </div>
      </div>
    </div>
  );
}

function OnboardingPage() {
  return (
    <div className="page-layout narrow">
      <PageHeader eyebrow="Welcome to CyberShield" title="Welcome to CyberShield" description="A simple path from your business to a clearer security posture." />

      <div className="onboarding-progress panel-surface">
        <div className="progress-header">
          <strong>Step 2 of 4</strong>
          <span>Website setup</span>
        </div>
        <div className="progress-bar"><span style={{ width: '50%' }} /></div>
      </div>

      <div className="panel-surface onboarding-card">
        <h2>1. Create your business</h2>
        <h2>2. Add your website</h2>
        <h2>3. Run your first security check</h2>
        <h2>4. Review your security posture</h2>
      </div>

      <div className="action-row justify-end">
        <Link to="/websites/add" className="primary-button">Add website</Link>
      </div>
    </div>
  );
}

function DashboardPage() {
  const [overview, setOverview] = useState<{
    score: number;
    risk_model_version: string;
    severity_counts: Record<string, number>;
    open_finding_count: number;
    affected_website_count: number;
    top_risk_drivers: string[];
    latest_scan_status: string | null;
    latest_scan_id: string | null;
  } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const token = getStoredToken();
    if (!token) {
      setError('You must be signed in to view the security overview.');
      setIsLoading(false);
      return;
    }

    getSecurityOverview(token)
      .then((result) => {
        setOverview(result);
        setError(null);
      })
      .catch((fetchError) => {
        setError(fetchError instanceof Error ? fetchError.message : 'Unable to load security overview.');
      })
      .finally(() => setIsLoading(false));
  }, []);

  const severityCounts = overview?.severity_counts ?? { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const scoreValue = overview?.score ?? 0;
  const summaryText = overview?.top_risk_drivers?.length ? overview.top_risk_drivers.join(', ') : 'No top risk drivers available.';

  return (
    <div className="page-layout">
      <PageHeader eyebrow="Overview" title="Security posture" description="Current assessment based on the latest completed scan for your owned websites." />

      {error && <div className="inline-status danger">{error}</div>}
      {isLoading ? <div className="inline-status neutral">Loading security overview…</div> : null}

      {!error && overview && (
        <>
          <div className="hero-card panel-surface">
            <div>
              <p className="eyebrow">Security risk score</p>
              <h2 className="score-big">{scoreValue} <span>/ 100</span></h2>
              <div className="status-row">
                <StatusBadge status={scoreValue >= 75 ? 'Healthy' : scoreValue >= 50 ? 'Watch' : 'At Risk'} tone={scoreValue >= 75 ? 'success' : scoreValue >= 50 ? 'warning' : 'danger'} />
                <span>{overview.open_finding_count} open findings</span>
              </div>
              <div className="action-row" style={{ marginTop: '16px' }}>
                <Link to="/security-posture" className="primary-button">View Security Posture</Link>
              </div>
            </div>
            <div className="score-visual">
              <div className="ring"><span>{scoreValue}</span></div>
            </div>
          </div>

          <div className="stat-grid">
            <StatCard label="Security score" value={`${scoreValue} / 100`} context={`Model ${overview.risk_model_version}`} icon={<Gauge size={18} />} status="good" />
            <StatCard label="Critical findings" value={String(severityCounts.critical ?? 0)} context="Needs attention" icon={<AlertTriangle size={18} />} status="danger" />
            <StatCard label="Open findings" value={String(overview.open_finding_count)} context={summaryText} icon={<FileText size={18} />} status="warning" />
            <StatCard label="Affected websites" value={String(overview.affected_website_count)} context="Current scope" icon={<ShieldCheck size={18} />} status="success" />
            <StatCard label="Latest scan" value={overview.latest_scan_status ?? 'No completed scan'} context={overview.latest_scan_id ? `ID ${overview.latest_scan_id.slice(0, 8)}` : 'No latest scan'} icon={<CheckCircle2 size={18} />} status="info" />
          </div>

          <div className="dashboard-grid">
            <AlertSummaryPanel />
            <RecentActivityPanel />
          </div>

          <div className="dashboard-grid">
            <div className="panel-surface chart-panel">
              <div className="panel-head">
                <h3>Security summary</h3>
                <span className="demo-label">verified</span>
              </div>
              <p>{summaryText}</p>
            </div>
          </div>

          <div className="dashboard-grid">
            <div className="panel-surface chart-panel">
              <div className="panel-head">
                <h3>Severity distribution</h3>
                <span className="demo-label">verified data</span>
              </div>
              <div className="distribution-list" role="img" aria-label="Severity distribution chart">
                {Object.entries(severityCounts).map(([key, value]) => (
                  <div key={key} className="distribution-row">
                    <strong>{toDisplaySeverity(key)}</strong>
                    <div className="distribution-bar"><span style={{ width: `${Math.min((value / Math.max(1, Object.values(severityCounts).reduce((sum, item) => sum + item, 0))) * 100, 100)}%` }} className={`bar-${formatSeverityLabel(toDisplaySeverity(key) as Severity)}`} /></div>
                    <span>{value}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="panel-surface chart-panel">
              <div className="panel-head">
                <h3>Risk drivers</h3>
                <span className="demo-label">deterministic</span>
              </div>
              {overview.top_risk_drivers.length > 0 ? (
                <ul className="bullet-list">
                  {overview.top_risk_drivers.map((item) => <li key={item}>{item}</li>)}
                </ul>
              ) : (
                <p>No risk drivers were identified in the current assessment.</p>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}

function SecurityPosturePage() {
  const [posture, setPosture] = useState<SecurityPostureApiResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const token = getStoredToken();
    if (!token) {
      setError('You must be signed in to view the security posture.');
      setIsLoading(false);
      return;
    }

    getSecurityPosture(token)
      .then((result) => {
        setPosture(result);
        setError(null);
      })
      .catch((fetchError) => {
        setError(fetchError instanceof Error ? fetchError.message : 'Unable to load security posture.');
      })
      .finally(() => setIsLoading(false));
  }, []);

  if (isLoading) return <div className="page-layout"><div className="inline-status neutral">Loading security posture…</div></div>;
  if (error) return <div className="page-layout"><div className="inline-status danger">{error}</div></div>;
  if (!posture) return <div className="page-layout"><div className="inline-status neutral">No security posture is available yet.</div></div>;

  const summary = posture.summary;
  const findings = posture.findings;
  const alerts = posture.alerts;
  const monitoring = posture.monitoring;
  const riskDeltaText = summary.risk_delta == null ? 'No previous assessment' : `${summary.risk_delta > 0 ? '+' : ''}${summary.risk_delta} pts`;

  return (
    <div className="page-layout">
      <PageHeader eyebrow="Executive overview" title={summary.business_name ?? 'Security posture'} description={posture.executive_summary} />

      <div className="hero-card panel-surface">
        <div>
          <p className="eyebrow">Current risk score</p>
          <h2 className="score-big">{summary.risk_score} <span>/ 100</span></h2>
          <div className="status-row">
            <StatusBadge status={summary.risk_score >= 75 ? 'Healthy' : summary.risk_score >= 50 ? 'Watch' : 'At Risk'} tone={summary.risk_score >= 75 ? 'success' : summary.risk_score >= 50 ? 'warning' : 'danger'} />
            <span>{summary.previous_risk_score == null ? 'No previous score' : `Previous: ${summary.previous_risk_score}`}</span>
          </div>
        </div>
        <div className="score-visual">
          <div className="ring"><span>{summary.risk_score}</span></div>
        </div>
      </div>

      <div className="stat-grid">
        <StatCard label="Risk score" value={`${summary.risk_score} / 100`} context={riskDeltaText} icon={<Gauge size={18} />} status="good" />
        <StatCard label="Open findings" value={String(findings.open)} context={`${findings.critical} critical / ${findings.high} high`} icon={<FileText size={18} />} status="warning" />
        <StatCard label="Critical alerts" value={String(alerts.critical)} context={`${alerts.high} high alerts`} icon={<AlertTriangle size={18} />} status="danger" />
        <StatCard label="Monitoring" value={String(monitoring.active_targets)} context={monitoring.last_assessment_at ? `Last: ${formatDateLabel(monitoring.last_assessment_at)}` : 'No assessments yet'} icon={<MonitorCog size={18} />} status="info" />
        <StatCard label="Assessment" value={monitoring.last_assessment_at ? formatDateLabel(monitoring.last_assessment_at) : 'Not available'} context={monitoring.next_assessment_at ? `Next: ${formatDateLabel(monitoring.next_assessment_at)}` : 'No scheduled assessment'} icon={<CheckCircle2 size={18} />} status="success" />
      </div>

      <div className="dashboard-grid">
        <div className="panel-surface chart-panel">
          <div className="panel-head">
            <h3>Risk trend</h3>
            <span className="demo-label">verified history</span>
          </div>
          {posture.trends.history.length === 0 ? (
            <p>No historical risk score data is available yet.</p>
          ) : (
            <div className="distribution-list">
              {posture.trends.history.map((point) => (
                <div key={`${point.date ?? 'snapshot'}-${point.risk_score}`} className="distribution-row">
                  <strong>{point.date ? new Date(point.date).toLocaleDateString() : 'Assessment'}</strong>
                  <div className="distribution-bar"><span style={{ width: `${Math.min(point.risk_score, 100)}%` }} className="bar-warning" /></div>
                  <span>{point.risk_score}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="panel-surface chart-panel">
          <div className="panel-head">
            <h3>Findings overview</h3>
            <span className="demo-label">current</span>
          </div>
          <div className="summary-row">
            <SummaryPill label="Open" value={String(findings.open)} tone="info" />
            <SummaryPill label="Critical" value={String(findings.critical)} tone="danger" />
            <SummaryPill label="High" value={String(findings.high)} tone="warning" />
          </div>
          <div className="summary-row" style={{ marginTop: 8 }}>
            <SummaryPill label="Medium" value={String(findings.medium)} tone="neutral" />
            <SummaryPill label="Low" value={String(findings.low)} tone="neutral" />
            <SummaryPill label="Ack" value={String(findings.acknowledged)} tone="warning" />
          </div>
        </div>
      </div>

      <div className="dashboard-grid">
        <div className="panel-surface chart-panel">
          <div className="panel-head">
            <h3>Alert overview</h3>
            <span className="demo-label">open items</span>
          </div>
          <div className="summary-row">
            <SummaryPill label="Critical" value={String(alerts.critical)} tone="danger" />
            <SummaryPill label="High" value={String(alerts.high)} tone="warning" />
            <SummaryPill label="Monitoring failures" value={String(alerts.monitoring_failures)} tone="info" />
          </div>
        </div>

        <div className="panel-surface chart-panel">
          <div className="panel-head">
            <h3>Monitoring posture</h3>
            <span className="demo-label">active targets</span>
          </div>
          <div className="summary-row">
            <SummaryPill label="Active" value={String(monitoring.active_targets)} tone="success" />
            <SummaryPill label="Disabled" value={String(monitoring.disabled_targets)} tone="neutral" />
            <SummaryPill label="Failed" value={String(monitoring.failed_assessments)} tone="danger" />
          </div>
        </div>
      </div>

      <div className="dashboard-grid">
        <div className="panel-surface chart-panel">
          <div className="panel-head">
            <h3>Security categories</h3>
            <span className="demo-label">actual findings</span>
          </div>
          {posture.categories.length === 0 ? (
            <p>No verified finding categories are currently open.</p>
          ) : (
            <ul className="bullet-list">
              {posture.categories.map((category) => (
                <li key={category.category}>
                  <strong>{category.category}</strong>: {category.open_findings} open, highest {toDisplaySeverity(category.highest_severity)}
                </li>
              ))}
            </ul>
          )}
        </div>

        <div className="panel-surface chart-panel">
          <div className="panel-head">
            <h3>Top priorities</h3>
            <span className="demo-label">deterministic</span>
          </div>
          {posture.priorities.length === 0 ? (
            <p>No priorities are currently identified from the verified data.</p>
          ) : (
            <ul className="bullet-list">
              {posture.priorities.map((item) => (
                <li key={`${item.source_type}-${item.source_id}`}>
                  {item.title}
                  {item.source_type === 'finding' && <Link to={`/findings/${item.source_id}`}> View detail</Link>}
                  {item.source_type === 'alert' && <Link to={`/alerts`}> View alerts</Link>}
                  {item.source_type === 'monitoring' && <Link to={`/monitoring`}> View monitoring</Link>}
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </div>
  );
}

function WebsitesPage() {
  return (
    <div className="page-layout">
      <PageHeader eyebrow="Websites" title="Asset overview" description="Monitor and manage the websites you are authorized to assess." />
      <div className="action-row">
        <Link to="/websites/add" className="primary-button">Add website</Link>
      </div>
      <div className="website-grid large">
        {websites.map((website) => (
          <WebsiteCard key={website.id} website={website} compact />
        ))}
      </div>
    </div>
  );
}

function WebsiteAddPage() {
  return (
    <div className="page-layout narrow">
      <PageHeader eyebrow="Website setup" title="Add a website" description="Only assess websites and systems you own or are authorized to test." />
      <div className="panel-surface form-panel">
        <FormField label="Business" value="Northlane Studio" />
        <InputField label="Website name" type="text" placeholder="Northlane Studio" />
        <InputField label="Website URL" type="url" placeholder="https://northlane.example" />
        <p className="helper-text">Only assess websites and systems you own or are authorized to test.</p>
        <div className="inline-status success">Ready to validate</div>
        <div className="action-row justify-end">
          <Link to="/dashboard" className="secondary-button">Save draft</Link>
          <Link to="/dashboard" className="primary-button">Continue</Link>
        </div>
      </div>
    </div>
  );
}

function ScansPage() {
  return (
    <div className="page-layout">
      <PageHeader eyebrow="Scans" title="Scan history" description="Review historical assessments and in-progress checks across your monitored websites." />
      <div className="panel-surface table-surface">
        <table>
          <thead>
            <tr>
              <th>Website</th>
              <th>Scan type</th>
              <th>Started</th>
              <th>Duration</th>
              <th>Status</th>
              <th>Findings</th>
            </tr>
          </thead>
          <tbody>
            {scans.map((scan) => (
              <tr key={scan.id}>
                <td>{scan.website}</td>
                <td>{scan.type}</td>
                <td>{scan.started}</td>
                <td>{scan.duration}</td>
                <td><StatusBadge status={scan.status} tone={scan.status === 'Completed' ? 'success' : scan.status === 'Failed' ? 'danger' : scan.status === 'Running' ? 'warning' : 'neutral'} /></td>
                <td>{scan.findings}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function FindingsPage() {
  const [items, setItems] = useState<Finding[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [pageSize] = useState(10);
  const [searchQuery, setSearchQuery] = useState('');
  const [severity, setSeverity] = useState('');
  const [status, setStatus] = useState('');
  const [category, setCategory] = useState('');
  const [websiteId, setWebsiteId] = useState('');
  const [scanId, setScanId] = useState('');
  const [sortBy, setSortBy] = useState<'last_seen' | 'created_at' | 'severity'>('last_seen');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');
  const [totalPages, setTotalPages] = useState(0);

  useEffect(() => {
    const token = getStoredToken();
    if (!token) {
      setError('You must sign in to view findings.');
      setIsLoading(false);
      return;
    }

    setIsLoading(true);
    listFindings(token, {
      page,
      page_size: pageSize,
      severity: severity || undefined,
      status: status || undefined,
      category: category || undefined,
      website_id: websiteId || undefined,
      scan_id: scanId || undefined,
      sort_by: sortBy,
      order: sortOrder,
    }).then((response) => {
      setItems(response.data.map((item) => normalizeApiFinding(item)));
      setTotalPages(response.meta.total_pages);
      setError(null);
    }).catch((fetchError) => {
      setError(fetchError instanceof Error ? fetchError.message : 'Unable to load findings.');
      setItems([]);
    }).finally(() => setIsLoading(false));
  }, [page, pageSize, severity, status, category, websiteId, scanId, sortBy, sortOrder]);

  const activeFilters = Boolean(searchQuery.trim() || severity || status || category || websiteId || scanId);

  const filteredItems = items.filter((finding) => {
    if (!searchQuery.trim()) return true;
    const haystack = [
      finding.title,
      finding.category,
      finding.website,
      finding.description,
      finding.severity,
      finding.status,
      finding.id,
    ].join(' ').toLowerCase();
    return haystack.includes(searchQuery.trim().toLowerCase());
  });

  const summary = {
    critical: filteredItems.filter((item) => item.severity === 'Critical').length,
    high: filteredItems.filter((item) => item.severity === 'High').length,
    medium: filteredItems.filter((item) => item.severity === 'Medium').length,
    low: filteredItems.filter((item) => item.severity === 'Low').length,
    resolved: filteredItems.filter((item) => item.status === 'Resolved').length,
  };

  const resetFilters = () => {
    setSearchQuery('');
    setSeverity('');
    setStatus('');
    setCategory('');
    setWebsiteId('');
    setScanId('');
    setSortBy('last_seen');
    setSortOrder('desc');
    setPage(1);
  };

  return (
    <div className="page-layout">
      <PageHeader eyebrow="Findings" title="Findings" description="Review detected security findings, severity, status, and affected resources across the business." />

      {error && <div className="inline-status danger">{error}</div>}
      {isLoading ? <div className="inline-status neutral">Loading findings…</div> : null}

      {!error && (
        <>
          <div className="summary-row">
            <SummaryPill label="Critical" value={summary.critical} tone="danger" />
            <SummaryPill label="High" value={summary.high} tone="warning" />
            <SummaryPill label="Medium" value={summary.medium} tone="info" />
            <SummaryPill label="Low" value={summary.low} tone="neutral" />
            <SummaryPill label="Visible" value={filteredItems.length} tone="success" />
          </div>

          <div className="filter-bar panel-surface">
            <label className="field-block compact" style={{ flex: '1 1 260px' }}>
              <span>Search</span>
              <input type="search" value={searchQuery} onChange={(event) => { setPage(1); setSearchQuery(event.target.value); }} placeholder="Search title, category, website or ID" />
            </label>
            <label className="field-block compact">
              <span>Severity</span>
              <select value={severity} onChange={(event) => { setPage(1); setSeverity(event.target.value); }}>
                <option value="">Any</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="info">Informational</option>
              </select>
            </label>
            <label className="field-block compact">
              <span>Status</span>
              <select value={status} onChange={(event) => { setPage(1); setStatus(event.target.value); }}>
                <option value="">Any</option>
                <option value="open">Open</option>
                <option value="acknowledged">Acknowledged</option>
                <option value="resolved">Resolved</option>
              </select>
            </label>
            <label className="field-block compact">
              <span>Sort</span>
              <select value={sortBy} onChange={(event) => { setPage(1); setSortBy(event.target.value as 'last_seen' | 'created_at' | 'severity'); }}>
                <option value="last_seen">Newest</option>
                <option value="created_at">Oldest</option>
                <option value="severity">Severity</option>
              </select>
            </label>
            <label className="field-block compact">
              <span>Direction</span>
              <select value={sortOrder} onChange={(event) => { setPage(1); setSortOrder(event.target.value as 'asc' | 'desc'); }}>
                <option value="desc">Descending</option>
                <option value="asc">Ascending</option>
              </select>
            </label>
            <label className="field-block compact">
              <span>Category</span>
              <input type="text" value={category} onChange={(event) => { setPage(1); setCategory(event.target.value); }} placeholder="transport_security" />
            </label>
            <label className="field-block compact">
              <span>Website ID</span>
              <input type="text" value={websiteId} onChange={(event) => { setPage(1); setWebsiteId(event.target.value); }} placeholder="Optional website ID" />
            </label>
            <label className="field-block compact">
              <span>Scan ID</span>
              <input type="text" value={scanId} onChange={(event) => { setPage(1); setScanId(event.target.value); }} placeholder="Optional scan ID" />
            </label>
            {activeFilters && (
              <button type="button" className="secondary-button" onClick={resetFilters} style={{ alignSelf: 'flex-end' }}>
                Clear filters
              </button>
            )}
          </div>

          <div className="finding-list">
            {filteredItems.length === 0 ? (
              <div className="panel-surface empty-state">
                <h3>No security findings found.</h3>
                <p>{activeFilters ? 'The current search and filters do not match any findings in this dataset.' : 'No findings were returned for this business yet.'}</p>
                {activeFilters && <button type="button" className="primary-button" onClick={resetFilters}>Clear filters</button>}
              </div>
            ) : (
              filteredItems.map((finding) => <FindingCard key={finding.id} finding={finding} />)
            )}
          </div>

          <div className="action-row justify-end">
            <button type="button" className="secondary-button" onClick={() => setPage((current) => Math.max(1, current - 1))} disabled={page <= 1}>Previous</button>
            <span>Page {page} of {Math.max(totalPages, 1)}</span>
            <button type="button" className="primary-button" onClick={() => setPage((current) => current + 1)} disabled={totalPages === 0 || page >= totalPages}>Next</button>
          </div>
        </>
      )}
    </div>
  );
}

function FindingDetailPage() {
  const { id } = useParams();
  const [finding, setFinding] = useState<Finding | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isSaving, setIsSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [aiState, setAiState] = useState<'idle' | 'loading' | 'success' | 'fallback' | 'error'>('idle');
  const [aiResponse, setAiResponse] = useState<AiResponse | null>(null);
  const [remediation, setRemediation] = useState<FindingRemediationApiResponse | null>(null);
  const [remediationState, setRemediationState] = useState<'loading' | 'idle' | 'error'>('loading');
  const [remediationNotes, setRemediationNotes] = useState('');

  useEffect(() => {
    if (!id) {
      setError('No finding ID was provided.');
      setIsLoading(false);
      return;
    }

    const token = getStoredToken();
    if (!token) {
      setError('You must sign in to view this finding.');
      setIsLoading(false);
      return;
    }

    Promise.all([
      getFinding(token, id),
      getFindingRemediation(token, id).catch(() => null),
    ])
      .then(([findingResponse, remediationResponse]) => {
        setFinding(normalizeApiFinding(findingResponse.data));
        setRemediation(remediationResponse?.data ?? null);
        setRemediationNotes(remediationResponse?.data?.remediation_notes ?? '');
        setRemediationState('idle');
        setError(null);
      })
      .catch((fetchError) => {
        setError(fetchError instanceof Error ? fetchError.message : 'Unable to load the finding.');
      })
      .finally(() => setIsLoading(false));
  }, [id]);

  const startRemediation = async () => {
    if (!id) return;
    const token = getStoredToken();
    if (!token) {
      setError('You must sign in to start remediation.');
      return;
    }

    setRemediationState('loading');
    try {
      const response = await createFindingRemediation(token, id, { remediation_notes: remediationNotes || undefined });
      setRemediation(response.data);
      setRemediationNotes(response.data.remediation_notes ?? '');
      setNotice('Remediation started. Follow the guidance below and request verification after the change is applied.');
      setError(null);
    } catch (fetchError) {
      setError(fetchError instanceof Error ? fetchError.message : 'Unable to start remediation.');
    } finally {
      setRemediationState('idle');
    }
  };

  const updateRemediationNotes = async () => {
    if (!id || !remediation) return;
    const token = getStoredToken();
    if (!token) {
      setError('You must sign in to update remediation notes.');
      return;
    }

    setRemediationState('loading');
    try {
      const response = await updateFindingRemediation(token, id, { remediation_notes: remediationNotes });
      setRemediation(response.data);
      setNotice('Remediation notes updated.');
      setError(null);
    } catch (fetchError) {
      setError(fetchError instanceof Error ? fetchError.message : 'Unable to update remediation notes.');
    } finally {
      setRemediationState('idle');
    }
  };

  const runVerification = async () => {
    if (!id) return;
    const token = getStoredToken();
    if (!token) {
      setError('You must sign in to verify remediation.');
      return;
    }

    setRemediationState('loading');
    try {
      const response = await verifyFindingRemediation(token, id);
      setRemediation(response.data);
      const result = response.data.verification_result;
      const success = result === 'resolved';
      setNotice(success ? 'Verification successful — the finding is no longer detected by the scanner.' : 'Verification unsuccessful — the finding is still detected.');
      setError(null);
    } catch (fetchError) {
      setError(fetchError instanceof Error ? fetchError.message : 'Verification scan failed.');
    } finally {
      setRemediationState('idle');
    }
  };

  const callAssistant = async (kind: 'explain' | 'remediation') => {
    if (!id) return;
    const token = getStoredToken();
    if (!token) {
      setAiState('error');
      setError('You must sign in to use the AI assistant.');
      return;
    }

    setAiState('loading');
    setAiResponse(null);
    try {
      const response = kind === 'explain'
        ? await explainFinding(token, id)
        : await requestFindingRemediation(token, id);
      const payload = response.data;
      setAiResponse(payload);
      setAiState(payload.limitations.toLowerCase().includes('provider unavailable') || payload.limitations.toLowerCase().includes('deterministic') ? 'fallback' : 'success');
      setError(null);
    } catch (fetchError) {
      setAiState('error');
      setError(fetchError instanceof Error ? fetchError.message : 'Unable to load AI guidance for this finding.');
    }
  };

  const updateStatus = async (status: 'open' | 'acknowledged' | 'resolved') => {
    if (!id) return;
    const token = getStoredToken();
    if (!token) {
      setError('You must sign in to update the finding status.');
      return;
    }

    setIsSaving(true);
    setNotice(null);
    try {
      const response = await updateFinding(token, id, { status });
      setFinding(normalizeApiFinding(response.data));
      setNotice(`Status updated to ${toDisplayStatus(status)}. User acknowledgment is tracked separately from scanner verification.`);
      setError(null);
    } catch (updateError) {
      setError(updateError instanceof Error ? updateError.message : 'Unable to update the finding status.');
    } finally {
      setIsSaving(false);
    }
  };

  if (isLoading) return <div className="page-layout narrow"><div className="inline-status neutral">Loading finding details…</div></div>;
  if (error || !finding) return <div className="page-layout narrow"><div className="inline-status danger">{error ?? 'Finding not available.'}</div></div>;

  return (
    <div className="page-layout narrow">
      <PageHeader eyebrow="Finding detail" title={finding.title} description="Review the observed evidence and the recommended action to understand the issue clearly." />

      {notice && <div className="inline-status success">{notice}</div>}

      <div className="detail-header panel-surface">
        <div>
          <SeverityBadge severity={finding.severity} />
          <div className="detail-meta-row">
            <span>{finding.category}</span>
            <span>{finding.websiteName ?? finding.website}</span>
            {finding.websiteUrl && <span>{finding.websiteUrl}</span>}
            <span>{formatDateLabel(finding.detectedDate)}</span>
          </div>
        </div>
        <StatusBadge status={finding.status} tone={finding.status === 'Resolved' ? 'success' : finding.status === 'Acknowledged' ? 'warning' : 'neutral'} />
      </div>

      <div className="detail-grid">
        <section className="panel-surface detail-section">
          <h3>What we found</h3>
          <p>{finding.description}</p>
          <h3>Why it matters</h3>
          <p>{finding.whyItMatters || 'No separate business-impact explanation was recorded by the scanner.'}</p>
        </section>

        <section className="panel-surface detail-section">
          <h3>Observed evidence</h3>
          {finding.evidence.length > 0 ? (
            <ul className="bullet-list">
              {finding.evidence.map((item) => <li key={item}>{item}</li>)}
            </ul>
          ) : (
            <p>No evidence details were recorded in the current scan result.</p>
          )}
        </section>
      </div>

      <div className="detail-grid">
        <section className="panel-surface detail-section">
          <h3>How to fix it</h3>
          <p>{finding.recommendation}</p>
        </section>

        <section className="panel-surface detail-section">
          <h3>How to verify</h3>
          <p>{finding.verification || 'No separate verification guidance was recorded. Run a fresh assessment before treating the issue as scanner-verified.'}</p>
        </section>
      </div>

      <section className="panel-surface detail-section">
        <h3>History</h3>
        <p>First seen: {formatDateLabel(finding.firstSeenAt)}. Last seen: {formatDateLabel(finding.lastSeenAt)}. Observed {finding.occurrenceCount ?? 1} time{finding.occurrenceCount === 1 ? '' : 's'}.</p>
        {finding.resolvedAt && <p>User marked resolved: {formatDateLabel(finding.resolvedAt)}. This does not indicate scanner verification.</p>}
        <p>Observed by {finding.scanType ?? 'the security'} scan ({finding.scanStatus ?? 'completed'}){finding.scanCompletedAt ? ` completed ${formatDateLabel(finding.scanCompletedAt)}` : ''}. Finding reference: {finding.id}.</p>
      </section>

      <section className="panel-surface detail-section">
        <h3>Remediation</h3>
        <p className="muted-copy">A user starts remediation separately from scanner verification. The scanner remains the authority for whether the issue is actually resolved.</p>

        {remediation ? (
          <>
            <div className="detail-meta-row" style={{ marginBottom: '12px' }}>
              <span><strong>Status:</strong> {remediation.status}</span>
              <span><strong>Verification:</strong> {remediation.verification_result ?? 'Awaiting verification'}</span>
              <span><strong>Last scanned:</strong> {remediation.verified_at ? formatDateLabel(remediation.verified_at) : 'Not yet verified'}</span>
            </div>

            <label className="field-block compact" style={{ marginBottom: '10px' }}>
              <span>Remediation notes</span>
              <textarea value={remediationNotes} onChange={(event) => setRemediationNotes(event.target.value)} rows={4} placeholder="Document the change applied outside CyberShield." />
            </label>

            <div className="action-row justify-start">
              <button type="button" className="secondary-button" onClick={updateRemediationNotes} disabled={remediationState === 'loading'}>Save notes</button>
              <button type="button" className="primary-button" onClick={runVerification} disabled={remediationState === 'loading' || remediation.status === 'resolved'}>Verify remediation</button>
            </div>

            {remediation.status === 'pending_verification' && <div className="inline-status neutral">Verification scan running…</div>}
            {remediation.verification_result === 'resolved' && <div className="inline-status success">Verification successful — finding no longer detected.</div>}
            {remediation.verification_result === 'still_present' && <div className="inline-status warning">Verification unsuccessful — finding is still detected.</div>}
          </>
        ) : (
          <>
            <p>No remediation workflow has started for this finding yet.</p>
            <div className="action-row justify-start">
              <button type="button" className="primary-button" onClick={startRemediation} disabled={remediationState === 'loading'}>Start remediation</button>
            </div>
          </>
        )}
      </section>

      <section className="panel-surface detail-section">
        <h3>AI Security Assistant</h3>
        <p className="muted-copy">AI guidance is generated from this verified finding and its available evidence. It does not replace the scanner&apos;s findings or risk assessment.</p>
        <div className="action-row justify-start">
          <Link to={`/ai-assistant?finding_id=${encodeURIComponent(finding.id)}`} className="secondary-button">Open in assistant</Link>
          <button type="button" className="secondary-button" onClick={() => callAssistant('explain')} disabled={aiState === 'loading'}>Explain this finding</button>
          <button type="button" className="secondary-button" onClick={() => callAssistant('remediation')} disabled={aiState === 'loading'}>Generate remediation guidance</button>
        </div>

        {aiState === 'idle' && (
          <div className="inline-status neutral">Ask CyberShield AI</div>
        )}

        {aiState === 'loading' && (
          <div className="inline-status neutral">Analyzing verified finding evidence...</div>
        )}

        {aiState !== 'idle' && aiState !== 'loading' && aiResponse && (
          <div className="ai-assistant-output">
            <h4>Explanation</h4>
            <p>{aiResponse.summary}</p>
            <h4>Why it matters</h4>
            <p>{aiResponse.why_it_matters}</p>
            <h4>Verified evidence</h4>
            <ul className="bullet-list">{aiResponse.verified_evidence.map((entry) => <li key={entry}>{entry}</li>)}</ul>
            <h4>Remediation</h4>
            <ul className="bullet-list">{aiResponse.remediation_steps.map((entry) => <li key={entry}>{entry}</li>)}</ul>
            <h4>Verification</h4>
            <ul className="bullet-list">{aiResponse.verification_steps.map((entry) => <li key={entry}>{entry}</li>)}</ul>
            <h4>Limitations</h4>
            <p>{aiResponse.limitations}</p>
          </div>
        )}

        {aiState === 'error' && (
          <div className="inline-status danger">The AI assistant could not process the finding. Please try again.</div>
        )}

        {aiState === 'fallback' && aiResponse && (
          <div className="inline-status warning">{aiResponse.limitations}</div>
        )}
      </section>

      <div className="action-row justify-end">
        <button type="button" className="secondary-button" disabled={isSaving || finding.status === 'Acknowledged'} onClick={() => updateStatus('acknowledged')}>Acknowledge</button>
        <button type="button" className="secondary-button" disabled={isSaving || finding.status === 'Resolved'} onClick={() => updateStatus('resolved')}>Mark resolved</button>
        <button type="button" className="primary-button" disabled={isSaving || finding.status === 'Open'} onClick={() => updateStatus('open')}>Reopen</button>
      </div>
    </div>
  );
}

function ReportsPage() {
  const navigate = useNavigate();
  const [reports, setReports] = useState<ReportApiResponse[]>([]);
  const [businesses, setBusinesses] = useState<BusinessApiResponse[]>([]);
  const [websites, setWebsites] = useState<WebsiteApiResponse[]>([]);
  const [selectedBusiness, setSelectedBusiness] = useState('');
  const [selectedWebsite, setSelectedWebsite] = useState('');
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [sort, setSort] = useState('newest');
  const [page, setPage] = useState(1);
  const [reportMeta, setReportMeta] = useState<ApiListMeta | null>(null);
  const [reportTitle, setReportTitle] = useState('');
  const [isLoading, setIsLoading] = useState(true);
  const [isCreating, setIsCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const token = getStoredToken();
    if (!token) {
      setError('You must sign in to view reports.');
      setIsLoading(false);
      return;
    }

    Promise.all([listBusinesses(token), listWebsites(token)])
      .then(([businessResponse, websiteResponse]) => {
        setBusinesses(businessResponse.data);
        setWebsites(websiteResponse.data);
        if (businessResponse.data[0]) {
          setSelectedBusiness(businessResponse.data[0].id);
        }
      })
      .catch((fetchError) => {
        setError(fetchError instanceof Error ? fetchError.message : 'Unable to load reports.');
      })
      .finally(() => setIsLoading(false));
  }, []);

  useEffect(() => {
    const token = getStoredToken();
    if (!token) return;
    setIsLoading(true);
    listReports(token, {
      page,
      page_size: 12,
      search: search.trim() || undefined,
      website_id: selectedWebsite || undefined,
      status: statusFilter || undefined,
      sort,
    })
      .then((response) => {
        setReports(response.data);
        setReportMeta(response.meta);
        setError(null);
      })
      .catch((fetchError) => {
        setError(fetchError instanceof Error ? fetchError.message : 'Unable to load reports.');
      })
      .finally(() => setIsLoading(false));
  }, [page, search, selectedWebsite, sort, statusFilter]);

  const filteredWebsites = selectedBusiness ? websites.filter((website) => website.business_id === selectedBusiness) : websites;

  const handleCreateReport = async () => {
    const token = getStoredToken();
    if (!token || !selectedBusiness) {
      setError('Select a business before generating a report.');
      return;
    }

    setIsCreating(true);
    setError(null);
    try {
      const payload = {
        business_id: selectedBusiness,
        website_id: selectedWebsite || undefined,
        title: reportTitle || undefined,
      };
      const response = await createReport(token, payload);
      const created = response.data;
      setReports((current) => [created, ...current]);
      navigate(`/reports/${created.id}`);
    } catch (createError) {
      setError(createError instanceof Error ? createError.message : 'Unable to generate the report.');
    } finally {
      setIsCreating(false);
    }
  };

  const downloadPdf = async (id: string) => {
    const token = getStoredToken();
    if (!token) {
      setError('You must sign in to download a report.');
      return;
    }

    try {
      const blob = await downloadReport(token, id);
      const url = window.URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = `cybershield-report-${id}.pdf`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      window.URL.revokeObjectURL(url);
    } catch (downloadError) {
      setError(downloadError instanceof Error ? downloadError.message : 'Unable to download the report.');
    }
  };

  return (
    <div className="page-layout">
      <PageHeader eyebrow="Reports" title="Report center" description="Generate and review professional security summaries for each business and website." />

      {error && <div className="inline-status danger">{error}</div>}
      {isLoading ? <div className="inline-status neutral">Loading reports…</div> : null}

      {!isLoading && (
        <>
          <div className="panel-surface detail-section">
            <h3>Report history</h3>
            <div className="filter-bar">
              <label className="field-block compact">
                <span>Search</span>
                <input type="search" value={search} onChange={(event) => { setSearch(event.target.value); setPage(1); }} placeholder="Search report title or type" />
              </label>
              <label className="field-block compact">
                <span>Website</span>
                <select value={selectedWebsite} onChange={(event) => { setSelectedWebsite(event.target.value); setPage(1); }}>
                  <option value="">All websites</option>
                  {filteredWebsites.map((website) => <option key={website.id} value={website.id}>{website.name}</option>)}
                </select>
              </label>
              <label className="field-block compact">
                <span>Status</span>
                <select value={statusFilter} onChange={(event) => { setStatusFilter(event.target.value); setPage(1); }}>
                  <option value="">All statuses</option>
                  <option value="completed">Completed</option>
                  <option value="pending">Pending</option>
                  <option value="failed">Failed</option>
                </select>
              </label>
              <label className="field-block compact">
                <span>Sort</span>
                <select value={sort} onChange={(event) => { setSort(event.target.value); setPage(1); }}>
                  <option value="newest">Newest first</option>
                  <option value="oldest">Oldest first</option>
                </select>
              </label>
            </div>
          </div>

          <div className="panel-surface detail-section">
            <h3>Generate assessment report</h3>
            <div className="filter-bar">
              <label className="field-block compact">
                <span>Business</span>
                <select value={selectedBusiness} onChange={(event) => { setSelectedBusiness(event.target.value); setSelectedWebsite(''); }}>
                  <option value="">Select a business</option>
                  {businesses.map((business) => (
                    <option key={business.id} value={business.id}>{business.name}</option>
                  ))}
                </select>
              </label>
              <label className="field-block compact">
                <span>Website (optional)</span>
                <select value={selectedWebsite} onChange={(event) => setSelectedWebsite(event.target.value)}>
                  <option value="">All websites</option>
                  {filteredWebsites.map((website) => (
                    <option key={website.id} value={website.id}>{website.name}</option>
                  ))}
                </select>
              </label>
              <label className="field-block compact">
                <span>Title</span>
                <input type="text" value={reportTitle} onChange={(event) => setReportTitle(event.target.value)} placeholder="Security assessment report" />
              </label>
            </div>
            <div className="action-row justify-end">
              <button type="button" className="primary-button" onClick={handleCreateReport} disabled={isCreating || !selectedBusiness}>
                {isCreating ? 'Generating…' : 'Create report'}
              </button>
            </div>
          </div>

          <div className="report-grid">
            {reports.length === 0 ? (
              <div className="panel-surface empty-state">No reports have been generated for this account yet.</div>
            ) : (
              reports.map((report) => (
                <div key={report.id} className="panel-surface report-card">
                  <div className="report-header-row">
                    <div>
                      <h3>{report.title}</h3>
                      <small>{report.report_type}</small>
                    </div>
                    <StatusBadge status={report.status} tone={report.status === 'completed' ? 'success' : report.status === 'failed' ? 'danger' : 'neutral'} />
                  </div>
                  <div className="report-meta">
                    <span>{report.generated_at ? formatDateLabel(report.generated_at) : 'Pending'}</span>
                    <strong>{report.risk_score_snapshot !== null ? `${report.risk_score_snapshot} / 100` : 'Not available'}</strong>
                  </div>
                  <div className="report-meta">
                    <span>{String((report.metadata?.finding_count as number | undefined) ?? 0)} findings</span>
                    <span>{report.website_id
                      ? String(((report.metadata?.scope as Array<{ name?: string }> | undefined)?.[0]?.name) ?? 'Website scoped')
                      : 'All websites'}</span>
                  </div>
                  <div className="action-row">
                    <button type="button" className="secondary-button" onClick={() => navigate(`/reports/${report.id}`)}>View</button>
                    {!!report.artifact_path && (
                      <button type="button" className="primary-button narrow" onClick={() => downloadPdf(report.id)}><Download size={14} /> Download</button>
                    )}
                  </div>
                </div>
              ))
            )}
          </div>
          {reportMeta && reportMeta.total_pages > 1 && (
            <div className="action-row justify-end">
              <button type="button" className="secondary-button" disabled={page <= 1} onClick={() => setPage((current) => current - 1)}>Previous</button>
              <span className="inline-status neutral">Page {reportMeta.page} of {reportMeta.total_pages}</span>
              <button type="button" className="secondary-button" disabled={page >= reportMeta.total_pages} onClick={() => setPage((current) => current + 1)}>Next</button>
            </div>
          )}
        </>
      )}
    </div>
  );
}

function ReportDetailPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [report, setReport] = useState<ReportApiResponse | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!id) {
      setError('No report ID supplied.');
      setIsLoading(false);
      return;
    }

    const token = getStoredToken();
    if (!token) {
      setError('You must sign in to view this report.');
      setIsLoading(false);
      return;
    }

    getReport(token, id)
      .then((response) => {
        setReport(response.data);
        setError(null);
      })
      .catch((fetchError) => {
        setError(fetchError instanceof Error ? fetchError.message : 'Unable to load the report.');
      })
      .finally(() => setIsLoading(false));
  }, [id]);

  const handleDownload = async () => {
    if (!id) return;
    const token = getStoredToken();
    if (!token) {
      setError('You must sign in to download this report.');
      return;
    }

    try {
      const blob = await downloadReport(token, id);
      const url = window.URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = `cybershield-report-${id}.pdf`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      window.URL.revokeObjectURL(url);
    } catch (fetchError) {
      setError(fetchError instanceof Error ? fetchError.message : 'Unable to download the report.');
    }
  };

  if (isLoading) return <div className="page-layout narrow"><div className="inline-status neutral">Loading report…</div></div>;
  if (error || !report) return <div className="page-layout narrow"><div className="inline-status danger">{error ?? 'Report not available.'}</div></div>;

  const metadata = report.metadata ?? {};
  const quality = metadata.risk_score as number | undefined;
  const topDrivers = Array.isArray(metadata.top_risk_drivers) ? metadata.top_risk_drivers as string[] : [];
  const findings = Array.isArray(metadata.findings) ? metadata.findings as Array<Record<string, unknown>> : [];
  const severityCounts = metadata.severity_counts as Record<string, number> | undefined;

  return (
    <div className="page-layout narrow">
      <PageHeader eyebrow="Report detail" title={report.title} description="Review the verified scope, score, and findings included in this report." />
      <div className="detail-header panel-surface">
        <div>
          <div className="detail-meta-row">
            <span>{report.report_type}</span>
            <span>{report.status}</span>
            <span>{report.generated_at ? formatDateLabel(report.generated_at) : 'Pending generation'}</span>
          </div>
        </div>
        <strong>{quality !== undefined ? `${quality} / 100` : report.risk_score_snapshot !== null ? `${report.risk_score_snapshot} / 100` : 'Score unavailable'}</strong>
      </div>

      <section className="panel-surface detail-section">
        <h3>Assessment scope</h3>
        <p>Business ID: {report.business_id}</p>
        <p>Website ID: {report.website_id ?? 'All websites'}</p>
        <p>Risk model version: {report.risk_model_version ?? 'Unknown'}</p>
        <p>Report status: {report.status}</p>
        {report.artifact_path && (
          <button type="button" className="primary-button" onClick={handleDownload}>Download PDF</button>
        )}
      </section>

      {severityCounts && (
        <section className="panel-surface detail-section">
          <h3>Severity distribution</h3>
          <ul className="bullet-list">
            {Object.entries(severityCounts).map(([level, value]) => <li key={level}>{level}: {value}</li>)}
          </ul>
        </section>
      )}

      {topDrivers.length > 0 && (
        <section className="panel-surface detail-section">
          <h3>Top risk drivers</h3>
          <ul className="bullet-list">{topDrivers.map((item) => <li key={item}>{item}</li>)}</ul>
        </section>
      )}

      <section className="panel-surface detail-section">
        <h3>Finding summary</h3>
        {findings.length > 0 ? (
          <ul className="bullet-list">{findings.map((finding) => <li key={String(finding.id)}>{String(finding.title)} ({String(finding.severity)})</li>)}</ul>
        ) : (
          <p>No findings were included in the snapshot.</p>
        )}
      </section>

      <div className="action-row justify-end">
        <button type="button" className="secondary-button" onClick={() => navigate('/reports')}>Back to reports</button>
      </div>
    </div>
  );
}

function MonitoringPage() {
  const [targets, setTargets] = useState<MonitoringTargetApiResponse[]>([]);
  const [businesses, setBusinesses] = useState<BusinessApiResponse[]>([]);
  const [websites, setWebsites] = useState<WebsiteApiResponse[]>([]);
  const [historyMap, setHistoryMap] = useState<Record<string, MonitoringHistoryApiResponse[]>>({});
  const [changeMap, setChangeMap] = useState<Record<string, MonitoringChangeApiResponse[]>>({});
  const [overviewMap, setOverviewMap] = useState<Record<string, MonitoringOverviewApiResponse>>({});
  const [selectedBusiness, setSelectedBusiness] = useState('');
  const [selectedWebsite, setSelectedWebsite] = useState('');
  const [schedule, setSchedule] = useState('daily');
  const [isLoading, setIsLoading] = useState(true);
  const [isSaving, setIsSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadMonitoring = async () => {
    const token = getStoredToken();
    if (!token) {
      setError('You must sign in to view monitoring status.');
      setIsLoading(false);
      return;
    }

    try {
      setIsLoading(true);
      const [businessResponse, monitoringResponse, overviewResponse, websiteResponse] = await Promise.all([
        listBusinesses(token),
        listMonitoring(token),
        getMonitoringOverview(token),
        listWebsites(token),
      ]);
      setBusinesses(businessResponse.data);
      setTargets(monitoringResponse.data);
      setOverviewMap(Object.fromEntries(overviewResponse.data.map((item) => [item.monitoring_id, item])));
      setWebsites(websiteResponse.data);
      if (businessResponse.data[0]) {
        setSelectedBusiness((current) => current || businessResponse.data[0].id);
      }
      setError(null);

      const historyEntries = await Promise.all(monitoringResponse.data.map(async (target) => {
        const historyResponse = await getMonitoringHistory(token, target.id);
        return [target.id, historyResponse.data] as const;
      }));
      const changesEntries = await Promise.all(monitoringResponse.data.map(async (target) => {
        const changeResponse = await getMonitoringChanges(token, target.id);
        return [target.id, changeResponse.data] as const;
      }));
      setHistoryMap(Object.fromEntries(historyEntries));
      setChangeMap(Object.fromEntries(changesEntries));
    } catch (fetchError) {
      setError(fetchError instanceof Error ? fetchError.message : 'Unable to load monitoring status.');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    void loadMonitoring();
  }, []);

  const filteredWebsites = websites.filter((website) => website.business_id === selectedBusiness);

  const handleCreateMonitoring = async () => {
    const token = getStoredToken();
    if (!token || !selectedBusiness || !selectedWebsite) {
      setError('Select a business and website before enabling monitoring.');
      return;
    }

    try {
      setIsSaving(true);
      setError(null);
      await createMonitoring(token, {
        business_id: selectedBusiness,
        website_id: selectedWebsite,
        enabled: true,
        schedule,
      });
      await loadMonitoring();
    } catch (createError) {
      setError(createError instanceof Error ? createError.message : 'Unable to enable monitoring.');
    } finally {
      setIsSaving(false);
    }
  };

  const toggleTarget = async (target: MonitoringTargetApiResponse, enabled: boolean) => {
    const token = getStoredToken();
    if (!token) {
      setError('You must sign in to change monitoring state.');
      return;
    }

    try {
      setIsSaving(true);
      await updateMonitoring(token, target.id, { enabled, schedule: target.schedule });
      await loadMonitoring();
    } catch (updateError) {
      setError(updateError instanceof Error ? updateError.message : 'Unable to update monitoring state.');
    } finally {
      setIsSaving(false);
    }
  };

  const removeTarget = async (targetId: string) => {
    const token = getStoredToken();
    if (!token) {
      setError('You must sign in to remove monitoring.');
      return;
    }

    try {
      setIsSaving(true);
      await deleteMonitoring(token, targetId);
      await loadMonitoring();
    } catch (deleteError) {
      setError(deleteError instanceof Error ? deleteError.message : 'Unable to disable monitoring.');
    } finally {
      setIsSaving(false);
    }
  };

  const totalMonitored = targets.length;
  const activeTargets = targets.filter((target) => target.enabled).length;
  const recentChanges = targets.reduce((sum, target) => sum + (changeMap[target.id] ?? []).length, 0);
  const nextRunLabel = targets[0] && targets[0].next_check_at ? formatDateLabel(targets[0].next_check_at) : 'Not scheduled';

  return (
    <div className="page-layout">
      <PageHeader eyebrow="Monitoring" title="Monitoring status" description="Track safe, scheduled re-assessment and meaningful changes across your protected websites." />

      {error && <div className="inline-status danger">{error}</div>}
      {isLoading ? <div className="inline-status neutral">Loading monitoring…</div> : null}

      <div className="monitoring-grid">
        <div className="panel-surface metric-card">
          <small>Protected websites</small>
          <strong>{totalMonitored}</strong>
        </div>
        <div className="panel-surface metric-card">
          <small>Active monitoring</small>
          <strong>{activeTargets}</strong>
        </div>
        <div className="panel-surface metric-card">
          <small>Recent changes</small>
          <strong>{recentChanges}</strong>
        </div>
        <div className="panel-surface metric-card">
          <small>Next assessment</small>
          <strong>{nextRunLabel}</strong>
        </div>
      </div>

      <div className="panel-surface" style={{ marginBottom: '1.5rem', padding: '1rem' }}>
        <h3>Enable monitoring</h3>
        <div className="filter-bar" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '1rem' }}>
          <label className="field-block compact">
            <span>Business</span>
            <select value={selectedBusiness} onChange={(event) => setSelectedBusiness(event.target.value)}>
              <option value="">Select</option>
              {businesses.map((business) => <option key={business.id} value={business.id}>{business.name}</option>)}
            </select>
          </label>
          <label className="field-block compact">
            <span>Website</span>
            <select value={selectedWebsite} onChange={(event) => setSelectedWebsite(event.target.value)}>
              <option value="">Select</option>
              {filteredWebsites.map((website) => <option key={website.id} value={website.id}>{website.name}</option>)}
            </select>
          </label>
          <label className="field-block compact">
            <span>Schedule</span>
            <select value={schedule} onChange={(event) => setSchedule(event.target.value)}>
              <option value="daily">Daily</option>
              <option value="weekly">Weekly</option>
            </select>
          </label>
          <div className="action-row justify-end" style={{ alignItems: 'end' }}>
            <button type="button" className="primary-button" disabled={!selectedBusiness || !selectedWebsite || isSaving} onClick={handleCreateMonitoring}>
              {isSaving ? 'Saving…' : 'Enable monitoring'}
            </button>
          </div>
        </div>
      </div>

      {!isLoading && targets.length === 0 && (
        <div className="panel-surface empty-state">No monitoring targets yet. Enable monitoring for a website to start safe scheduled reassessment.</div>
      )}

      {targets.length > 0 && (
        <div className="monitoring-list panel-surface">
          {targets.map((target) => {
            const targetWebsites = websites.filter((website) => website.id === target.website_id);
            const websiteName = targetWebsites[0]?.name ?? 'Website';
            const targetHistory = historyMap[target.id] ?? [];
            const targetChanges = changeMap[target.id] ?? [];
            const overview = overviewMap[target.id];
            const latestHistory = targetHistory[0];
            const riskDelta = overview?.risk_delta ?? latestHistory?.risk_delta ?? null;
            const statusText = overview?.status ?? (target.enabled ? (target.last_error ? 'Failed' : 'Active') : 'Disabled');
            const statusTone = statusText === 'failed' ? 'danger' : statusText === 'active' ? 'success' : 'neutral';

            return (
              <div key={target.id} className="monitor-row" style={{ display: 'block' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', gap: '1rem', alignItems: 'center' }}>
                  <div>
                    <h3>{websiteName}</h3>
                    <small>{overview?.website_url ?? ''} · Last scan: {overview?.last_scan_at ? formatDateLabel(overview.last_scan_at) : 'Not yet scanned'} · Next: {target.next_check_at ? formatDateLabel(target.next_check_at) : 'Not scheduled'} · Schedule: {target.schedule}</small>
                  </div>
                  <StatusBadge status={statusText} tone={statusTone} />
                </div>

                <div className="monitor-meta" style={{ marginTop: '0.75rem' }}>
                  <span>Current risk: {overview?.current_risk_score ?? 'n/a'}</span>
                  <span>Risk change: {riskDelta === null ? 'n/a' : `${riskDelta > 0 ? '+' : ''}${riskDelta}`}</span>
                  <span>Findings: {overview?.findings_count ?? latestHistory?.findings_count ?? 0} ({overview?.open_finding_count ?? 0} open)</span>
                </div>

                <div className="action-row justify-end" style={{ marginTop: '0.75rem' }}>
                  <button type="button" className="secondary-button" disabled={isSaving || !target.enabled} onClick={() => toggleTarget(target, false)}>Pause</button>
                  <button type="button" className="secondary-button" disabled={isSaving || target.enabled} onClick={() => toggleTarget(target, true)}>Resume</button>
                  <button type="button" className="secondary-button" onClick={() => removeTarget(target.id)}>Remove</button>
                </div>

                <div style={{ marginTop: '1rem' }}>
                  <h4>Recent changes</h4>
                  {targetChanges.length === 0 ? (
                    <p className="muted-copy">No meaningful changes detected in the latest comparisons.</p>
                  ) : (
                    <ul className="bullet-list">
                      {targetChanges.slice(0, 4).map((change) => (
                        <li key={`${change.fingerprint}-${change.status}`}>
                          <strong>{change.status}</strong> · {change.title} ({change.severity})
                        </li>
                      ))}
                    </ul>
                  )}
                </div>

                <div style={{ marginTop: '1rem' }}>
                  <h4>History</h4>
                  {targetHistory.length === 0 ? (
                    <p className="muted-copy">No scheduled runs yet.</p>
                  ) : (
                    <ul className="bullet-list">
                      {targetHistory.slice(0, 3).map((entry) => (
                        <li key={entry.scan_id}>
                          {entry.started_at ? formatDateLabel(entry.started_at) : 'Scan'} · {entry.status} · {entry.current_risk_score ?? 'n/a'} risk · {entry.risk_delta === null ? 'n/a' : `${entry.risk_delta > 0 ? '+' : ''}${entry.risk_delta}`} change · {entry.new_findings_count} new / {entry.resolved_findings_count} resolved / {entry.changed_findings_count} changed
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}

      <div className="inline-status neutral">Monitoring uses the existing scanner and verifies ownership before scheduling a safe re-assessment.</div>
    </div>
  );
}

function AiAssistantPage() {
  const [searchParams] = useSearchParams();
  const [findingId, setFindingId] = useState(() => searchParams.get('finding_id') ?? '');
  const [finding, setFinding] = useState<Finding | null>(null);
  const [response, setResponse] = useState<AiResponse | null>(null);
  const [mode, setMode] = useState<'explain' | 'remediation'>('explain');
  const [state, setState] = useState<'idle' | 'loading' | 'success' | 'fallback' | 'error'>('idle');
  const [error, setError] = useState<string | null>(null);

  const runAssistant = async (requestedMode: 'explain' | 'remediation' = mode) => {
    const normalizedId = findingId.trim();
    if (!normalizedId) {
      setError('Enter a finding ID to load its authorized context.');
      setState('error');
      return;
    }

    const token = getStoredToken();
    if (!token) {
      setError('You must sign in to use the AI assistant.');
      setState('error');
      return;
    }

    setMode(requestedMode);
    setState('loading');
    setError(null);
    setResponse(null);
    try {
      const findingResponse = await getFinding(token, normalizedId);
      const authorizedFinding = normalizeApiFinding(findingResponse.data);
      setFinding(authorizedFinding);
      const aiResponse = requestedMode === 'explain'
        ? await explainFinding(token, normalizedId)
        : await requestFindingRemediation(token, normalizedId);
      setResponse(aiResponse.data);
      setState(aiResponse.data.limitations.toLowerCase().includes('provider unavailable') || aiResponse.data.limitations.toLowerCase().includes('deterministic') ? 'fallback' : 'success');
    } catch (assistantError) {
      setFinding(null);
      setError(assistantError instanceof Error ? assistantError.message : 'Unable to load authorized finding guidance.');
      setState('error');
    }
  };

  return (
    <div className="page-layout">
      <PageHeader eyebrow="AI assistant" title="Security assistant" description="Ask for an explanation of an authorized finding. Scanner facts remain authoritative; AI provides bounded explanation and defensive guidance." />
      <div className="panel-surface detail-section">
        <label className="field-block">
          <span>Finding ID</span>
          <input value={findingId} onChange={(event) => setFindingId(event.target.value)} placeholder="Paste a finding ID from Finding Details" />
        </label>
        <div className="action-row justify-start">
          <button type="button" className="primary-button" onClick={() => runAssistant('explain')} disabled={state === 'loading'}>Explain finding</button>
          <button type="button" className="secondary-button" onClick={() => runAssistant('remediation')} disabled={state === 'loading'}>Generate remediation guidance</button>
        </div>
        {state === 'loading' && <div className="inline-status neutral">Loading authorized finding context and preparing guidance...</div>}
        {state === 'error' && <div className="inline-status danger">{error ?? 'The assistant could not process this finding.'}</div>}
        {state === 'idle' && <div className="inline-status neutral">Start with a finding ID from an authorized Finding Details page.</div>}
      </div>

      {finding && (
        <div className="panel-surface detail-section">
          <h3>Scanner facts</h3>
          <div className="detail-meta-row">
            <span><strong>Finding:</strong> {finding.title}</span>
            <span><strong>Severity:</strong> {finding.severity}</span>
            <span><strong>Status:</strong> {finding.status}</span>
            <span><strong>Target:</strong> {finding.websiteName ?? finding.website}</span>
          </div>
          <p>{finding.description}</p>
          <p className="muted-copy">The assistant can explain these backend-provided facts but cannot change severity, risk, scanner evidence, ownership, or verification status.</p>
        </div>
      )}

      {response && (
        <div className="panel-surface detail-section">
          <h3>{mode === 'explain' ? 'AI-generated explanation' : 'AI-generated defensive guidance'}</h3>
          <p>{response.summary}</p>
          <h4>Why it matters</h4>
          <p>{response.why_it_matters}</p>
          <h4>Evidence supplied by CyberShield</h4>
          <ul className="bullet-list">{response.verified_evidence.map((entry) => <li key={entry}>{entry}</li>)}</ul>
          <h4>Remediation guidance</h4>
          <ul className="bullet-list">{response.remediation_steps.map((entry) => <li key={entry}>{entry}</li>)}</ul>
          <h4>Verification considerations</h4>
          <ul className="bullet-list">{response.verification_steps.map((entry) => <li key={entry}>{entry}</li>)}</ul>
          <p className="muted-copy"><strong>Limitations:</strong> {response.limitations}</p>
          {state === 'fallback' && <div className="inline-status warning">The configured AI provider was unavailable. This is deterministic guidance based on authorized finding data.</div>}
        </div>
      )}

      <div className="panel-surface detail-section">
        <h3>Assistant scope</h3>
        <ul className="bullet-list">
          <li>Explain a verified finding in plain language.</li>
          <li>Describe why the finding matters to the business.</li>
          <li>Summarize the evidence CyberShield observed.</li>
          <li>Outline remediation and verification steps.</li>
        </ul>
        <div className="inline-status neutral">
          AI guidance is generated from this verified finding and its available evidence. It does not replace the scanner&apos;s findings or risk assessment.
        </div>
      </div>
    </div>
  );
}

function BusinessModelPage() {
  const availabilityLabel = (availability: BusinessPlan['availability']): string => {
    if (availability === 'coming_soon') return 'Coming soon';
    if (availability === 'evaluation') return 'Evaluation';
    return 'Conceptual offering';
  };

  return (
    <div className="page-layout business-model-page">
      <PageHeader
        eyebrow="Business model"
        title="CyberShield plans"
        description="A transparent packaging model for turning website security findings into an understandable, repeatable operating workflow."
      />

      <section className="business-model-hero panel-surface">
        <div>
          <span className="eyebrow">Product value</span>
          <h2>From security signal to accountable action.</h2>
          <p>CyberShield connects authorized scanning, findings, deterministic risk visibility, bounded AI assistance, reporting, remediation, verification, monitoring, and audit context in one workflow.</p>
        </div>
        <div className="business-model-note">
          <strong>Informational only</strong>
          <span>Pricing and plan limits describe a product model. No checkout, payment collection, or subscription enforcement is enabled.</span>
        </div>
      </section>

      <section>
        <SectionHeader eyebrow="Plans" title="Choose the operating model that fits your team" />
        <div className="business-plan-grid">
          {businessModelPlans.map((plan) => (
            <article className={`business-plan-card panel-surface ${plan.id === 'pro' ? 'featured' : ''}`} key={plan.id}>
              {plan.id === 'pro' && <span className="plan-badge">Recommended starting point</span>}
              <div className="plan-card-header">
                <div>
                  <h3>{plan.name}</h3>
                  <span className="plan-audience">{plan.audience}</span>
                </div>
                <span className={`plan-status ${plan.availability}`}>{availabilityLabel(plan.availability)}</span>
              </div>
              <p>{plan.description}</p>
              <div className="plan-price">
                <strong>{plan.priceDisplay}</strong>
                <span>{plan.billingDisplay}</span>
              </div>
              <h4>Includes</h4>
              <ul className="business-list">{plan.features.map((feature) => <li key={feature}>{feature}</li>)}</ul>
              <h4>Conceptual limits</h4>
              <ul className="business-list muted-list">{plan.limits.map((limit) => <li key={limit}>{limit}</li>)}</ul>
              <button type="button" disabled className={plan.id === 'pro' ? 'primary-button full-width' : 'secondary-button full-width'}>
                {plan.cta}
              </button>
            </article>
          ))}
        </div>
      </section>

      <section>
        <SectionHeader eyebrow="Feature matrix" title="Capabilities packaged clearly" />
        <div className="business-table-wrap panel-surface">
          <table className="business-feature-table">
            <thead><tr><th>Capability</th><th>Community</th><th>Pro</th><th>Business</th></tr></thead>
            <tbody>
              {businessModelFeatures.map((feature) => (
                <tr key={feature.name}><th scope="row">{feature.name}</th><td>{feature.community}</td><td>{feature.pro}</td><td>{feature.business}</td></tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section>
        <SectionHeader eyebrow="Product workflow" title="One security journey, from discovery to audit" />
        <div className="business-workflow-grid">
          {businessModelWorkflow.map(([step, title, description]) => (
            <div className="business-workflow-card panel-surface" key={step}>
              <span className="flow-step">{step}</span>
              <h3>{title}</h3>
              <p>{description}</p>
            </div>
          ))}
        </div>
      </section>

      <section>
        <SectionHeader eyebrow="Target customers" title="Who this product is designed to serve" />
        <div className="business-segment-grid">
          {businessModelSegments.map((segment) => (
            <div className="feature-card panel-surface" key={segment.title}>
              <div className="feature-icon"><BriefcaseBusiness size={18} /></div>
              <h3>{segment.title}</h3>
              <p>{segment.description}</p>
            </div>
          ))}
        </div>
      </section>

      <section className="business-model-limitations panel-surface">
        <div>
          <span className="eyebrow">Product boundaries</span>
          <h2>Credibility through clear limitations</h2>
        </div>
        <ul className="business-list">
          <li>Pricing is currently informational and does not represent a purchased plan.</li>
          <li>Payment processing, subscriptions, invoices, billing webhooks, and entitlement enforcement are not implemented.</li>
          <li>Product limits shown here are packaging concepts, separate from current technical implementation limits.</li>
          <li>CyberShield does not guarantee complete security, prevention, or vulnerability detection.</li>
        </ul>
      </section>
    </div>
  );
}

function SettingsPage() {
  return (
    <div className="page-layout narrow">
      <PageHeader eyebrow="Settings" title="Account settings" description="Profile, business, appearance, notifications, and security controls." />
      <div className="settings-grid">
        <div className="panel-surface settings-block">
          <h3>Profile</h3>
          <InputField label="Name" type="text" value="Aisha Patel" />
          <InputField label="Email" type="email" value="aisha@northlane.io" />
        </div>
        <div className="panel-surface settings-block">
          <h3>Appearance</h3>
          <ThemeToggle />
        </div>
        <div className="panel-surface settings-block">
          <h3>Notifications</h3>
          <div className="check-row"><span>Weekly digest</span><label className="switch"><input type="checkbox" defaultChecked /><span /></label></div>
          <div className="check-row"><span>Critical alerts</span><label className="switch"><input type="checkbox" defaultChecked /><span /></label></div>
        </div>
      </div>
    </div>
  );
}

function HelpPage() {
  return (
    <div className="page-layout narrow">
      <PageHeader eyebrow="Help" title="Support" description="Documentation and guidance resources for understanding the platform." />
      <div className="panel-surface help-panel">
        <h3>Product guidance</h3>
        <ul className="bullet-list">
          <li>Review scan results in the dashboard.</li>
          <li>Open findings and compare evidence with recommendations.</li>
          <li>Use the AI assistant to explain verified findings in plain language.</li>
          <li>Monitoring surfaces changes that deserve a follow-up review.</li>
        </ul>
      </div>
    </div>
  );
}

function PageNotFound() {
  return (
    <div className="error-page">
      <div className="panel-surface error-card">
        <h1>404</h1>
        <p>This page is unavailable.</p>
        <Link to="/dashboard" className="primary-button">Return to Overview</Link>
      </div>
    </div>
  );
}

function PageHeader({ eyebrow, title, description }: { eyebrow: string; title: string; description?: string }) {
  return (
    <header className="page-header">
      <div className="eyebrow">{eyebrow}</div>
      <h1>{title}</h1>
      {description && <p>{description}</p>}
    </header>
  );
}

function SectionHeader({ eyebrow, title }: { eyebrow: string; title: string }) {
  return (
    <div className="section-header">
      <div className="eyebrow">{eyebrow}</div>
      <h2>{title}</h2>
    </div>
  );
}

function FeatureCard({ icon, title, description }: { icon: React.ReactNode; title: string; description: string }) {
  return (
    <div className="feature-card panel-surface">
      <div className="feature-icon">{icon}</div>
      <h3>{title}</h3>
      <p>{description}</p>
    </div>
  );
}

function SummaryPill({ label, value, tone }: { label: string; value: string | number; tone: 'danger' | 'warning' | 'info' | 'neutral' | 'success' }) {
  return (
    <div className={`summary-pill ${tone}`}>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function StatCard({ label, value, context, icon, status }: { label: string; value: string; context: string; icon: React.ReactNode; status: 'good' | 'danger' | 'warning' | 'success' | 'info' }) {
  return (
    <div className="stat-card panel-surface">
      <div className="stat-icon">{icon}</div>
      <div>
        <small>{label}</small>
        <h3>{value}</h3>
        <span className={`stat-context ${status}`}>{context}</span>
      </div>
    </div>
  );
}

function WebsiteCard({ website, compact = false }: { website: { id: string; name: string; url: string; status: 'Healthy' | 'Watch' | 'At Risk'; score: number; lastAssessment: string; openFindings: number; }; compact?: boolean }) {
  return (
    <div className={`website-card panel-surface ${compact ? 'compact' : ''}`}>
      <div className="website-row">
        <div>
          <h3>{website.name}</h3>
          <small>{website.url}</small>
        </div>
        <StatusBadge status={website.status} tone={website.status === 'Healthy' ? 'success' : website.status === 'Watch' ? 'warning' : 'danger'} />
      </div>
      <div className="website-stats">
        <div>
          <label>Security score</label>
          <strong>{website.score}</strong>
        </div>
        <div>
          <label>Last assessment</label>
          <strong>{website.lastAssessment}</strong>
        </div>
        <div>
          <label>Open findings</label>
          <strong>{website.openFindings}</strong>
        </div>
      </div>
    </div>
  );
}

function FindingCard({ finding }: { finding: Finding }) {
  return (
    <div className="finding-card panel-surface">
      <div className="finding-topline">
        <div>
          <h3>{finding.title}</h3>
          <div className="meta-row">
            <SeverityBadge severity={finding.severity} />
            <span>{finding.category}</span>
          </div>
        </div>
        <StatusBadge status={finding.status} tone={finding.status === 'Resolved' ? 'success' : finding.status === 'In Progress' ? 'warning' : 'neutral'} />
      </div>
      <div className="finding-meta-row">
        <span>{finding.website}</span>
        <span>{finding.detectedDate}</span>
      </div>
      <div className="action-row justify-end">
        <Link to={`/findings/${finding.id}`} className="secondary-button">View details</Link>
      </div>
    </div>
  );
}

function InputField({ label, type, placeholder, value, onChange }: { label: string; type: string; placeholder?: string; value?: string; onChange?: (value: string) => void }) {
  return (
    <label className="field-block">
      <span>{label}</span>
      <input type={type} placeholder={placeholder} value={value} onChange={(event) => onChange?.(event.target.value)} />
    </label>
  );
}

function FormField({ label, value }: { label: string; value: string }) {
  return (
    <label className="field-block">
      <span>{label}</span>
      <input type="text" defaultValue={value} />
    </label>
  );
}

function StatusBadge({ status, tone }: { status: string; tone?: 'success' | 'warning' | 'danger' | 'neutral' | 'info' }) {
  const normalizedTone = tone ?? 'neutral';
  return <span className={`badge ${normalizedTone}`}>{status}</span>;
}

function SeverityBadge({ severity }: { severity: Severity | 'Critical' | 'High' | 'Medium' | 'Low' }) {
  const tone = severity === 'Critical' ? 'danger' : severity === 'High' ? 'warning' : severity === 'Medium' ? 'info' : severity === 'Low' ? 'neutral' : 'success';
  return <span className={`badge severity ${tone}`}>{severity}</span>;
}

export default App;
