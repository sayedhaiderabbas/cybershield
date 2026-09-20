import type {
  Business,
  DashboardStats,
  Finding,
  MonitoringTarget,
  NotificationItem,
  Report,
  Scan,
  User,
  Website,
} from '../types';

export const user: User = {
  id: 'u-100',
  name: 'Aisha Patel',
  email: 'aisha@northlane.io',
  company: 'Northlane Studio',
  role: 'Business owner',
};

export const business: Business = {
  id: 'b-100',
  name: 'Northlane Studio',
  industry: 'Creative services',
  primaryContact: 'Aisha Patel',
};

export const dashboardStats: DashboardStats = {
  score: 78,
  critical: 1,
  openFindings: 7,
  protectedWebsites: 4,
  lastAssessment: 'Today, 09:40',
};

export const websites: Website[] = [
  {
    id: 'ws-1',
    name: 'Northlane Studio',
    url: 'https://northlane.example',
    status: 'At Risk',
    score: 72,
    lastAssessment: 'Today, 09:40',
    openFindings: 3,
    businessId: 'b-100',
  },
  {
    id: 'ws-2',
    name: 'Brand Campaign Portal',
    url: 'https://campaigns.northlane.example',
    status: 'Healthy',
    score: 86,
    lastAssessment: '2 days ago',
    openFindings: 1,
    businessId: 'b-100',
  },
  {
    id: 'ws-3',
    name: 'Client Intake',
    url: 'https://intake.northlane.example',
    status: 'Watch',
    score: 81,
    lastAssessment: '4 days ago',
    openFindings: 2,
    businessId: 'b-100',
  },
];

export const findings: Finding[] = [
  {
    id: 'f-101',
    title: 'Session cookies are missing secure attributes',
    severity: 'High',
    category: 'Cookie security',
    website: 'Northlane Studio',
    status: 'Open',
    detectedDate: '2026-09-13',
    description: 'Session cookies are observed without explicit secure and same-site controls, increasing the risk of exposure on unencrypted or cross-site flows.',
    evidence: [
      'Cookie attributes do not include Secure on the session cookie.',
      'SameSite is not configured for the authentication cookie.',
      'Demo check shows a live configuration mismatch for session handling.',
    ],
    recommendation: 'Set Secure and SameSite=Lax or Strict on session cookies and validate browser behavior with a staging test.',
    whyItMatters: 'Without these protections, user sessions can be more exposed to interception or cross-site abuse patterns.',
    affectedAsset: 'northlane.example / session cookie',
    verification: 'Verified in mock review: evidence reflects a simulated configuration review and should be validated before production remediation.',
  },
  {
    id: 'f-102',
    title: 'HSTS is not enforced on production domain',
    severity: 'Medium',
    category: 'Security headers',
    website: 'Northlane Studio',
    status: 'In Progress',
    detectedDate: '2026-09-11',
    description: 'The site is available over HTTPS but is not consistently returning the Strict-Transport-Security header.',
    evidence: [
      'HTTPS is enabled for the root domain.',
      'The response headers do not include Strict-Transport-Security.',
      'Demo data indicates the header is missing from a live mock response.',
    ],
    recommendation: 'Add an HSTS policy with a reasonable max-age and include preloading only when deployment is ready.',
    whyItMatters: 'Without HSTS, browsers are more likely to fall back to insecure transport during future sessions.',
    affectedAsset: 'northlane.example / root response',
    verification: 'Mock evidence from a sample HTTP response review. Production validation is still required before implementation.',
  },
  {
    id: 'f-103',
    title: 'TLS certificate is nearing expiry',
    severity: 'Critical',
    category: 'TLS configuration',
    website: 'Brand Campaign Portal',
    status: 'Open',
    detectedDate: '2026-09-10',
    description: 'The certificate validity window is approaching its renewal threshold and may disrupt secure connections if not renewed early.',
    evidence: [
      'Certification expiry is within 14 days in the mock assessment.',
      'The certificate chain is valid but renewal is approaching.',
      'Expiry warning is based on demo data only.',
    ],
    recommendation: 'Renew the certificate before the renewal threshold and monitor the certificate rotation schedule.',
    whyItMatters: 'A certificate that expires can lead to visitors seeing trust warnings and service disruption.',
    affectedAsset: 'campaigns.northlane.example / TLS certificate',
    verification: 'This is demo-only evidence and is not a real certificate status claim.',
  },
  {
    id: 'f-104',
    title: 'Security scan includes missing CSP policy',
    severity: 'Low',
    category: 'Content security',
    website: 'Client Intake',
    status: 'Resolved',
    detectedDate: '2026-09-09',
    description: 'A content security policy has not been configured for a static client intake experience.',
    evidence: [
      'Response headers are missing Content-Security-Policy.',
      'Demo data shows no CSP field in the policy set.',
      'The issue was previously tracked and fixed in a staging check.',
    ],
    recommendation: 'Introduce a least-privilege CSP tailored to the site\'s script, style, and image needs.',
    whyItMatters: 'CSP reduces the damage an attacker can do if a script injection vector is introduced.',
    affectedAsset: 'intake.northlane.example / edge response headers',
    verification: 'Mock check indicated a remediation attempt; production verification remains required before closure.',
  },
];

export const scans: Scan[] = [
  {
    id: 'scan-200',
    website: 'Northlane Studio',
    type: 'Full website review',
    started: 'Today, 09:40',
    duration: '03m 42s',
    status: 'Completed',
    findings: 4,
  },
  {
    id: 'scan-201',
    website: 'Brand Campaign Portal',
    type: 'TLS and headers',
    started: 'Yesterday, 16:10',
    duration: '02m 18s',
    status: 'Completed',
    findings: 2,
  },
  {
    id: 'scan-202',
    website: 'Client Intake',
    type: 'Scheduled monitoring',
    started: 'Mon, 11:30',
    duration: '01m 55s',
    status: 'Running',
    findings: 1,
  },
  {
    id: 'scan-203',
    website: 'Northlane Studio',
    type: 'Quick configuration check',
    started: 'Sun, 08:00',
    duration: '01m 12s',
    status: 'Failed',
    findings: 0,
  },
];

export const reports: Report[] = [
  {
    id: 'r-300',
    name: 'Northlane Studio - September report',
    website: 'Northlane Studio',
    date: '2026-09-15',
    posture: '78 / 100',
    status: 'Ready',
  },
  {
    id: 'r-301',
    name: 'Campaign portal - executive summary',
    website: 'Brand Campaign Portal',
    date: '2026-09-08',
    posture: '86 / 100',
    status: 'Review',
  },
  {
    id: 'r-302',
    name: 'Intake site - change summary',
    website: 'Client Intake',
    date: '2026-09-03',
    posture: '81 / 100',
    status: 'Generating',
  },
];

export const monitoringTargets: MonitoringTarget[] = [
  {
    id: 'm-1',
    name: 'Northlane Studio',
    status: 'Protected',
    lastCheck: '09:40 today',
    nextAssessment: 'Tomorrow, 09:00',
    changes: 0,
  },
  {
    id: 'm-2',
    name: 'Brand Campaign Portal',
    status: 'Watch',
    lastCheck: '2 days ago',
    nextAssessment: 'Tomorrow, 10:30',
    changes: 1,
  },
  {
    id: 'm-3',
    name: 'Client Intake',
    status: 'Change detected',
    lastCheck: '4 days ago',
    nextAssessment: 'Today, 20:00',
    changes: 2,
  },
];

export const notifications: NotificationItem[] = [
  {
    id: 'n-1',
    title: 'Assessment completed',
    detail: 'Northlane Studio review finished with 4 findings.',
    time: '12 minutes ago',
    type: 'assessment',
  },
  {
    id: 'n-2',
    title: 'Finding updated',
    detail: 'The TLS cert issue is now marked as critical.',
    time: '1 hour ago',
    type: 'finding',
  },
  {
    id: 'n-3',
    title: 'Monitoring notice',
    detail: 'A change was detected in the intake site configuration.',
    time: '3 hours ago',
    type: 'monitoring',
  },
  {
    id: 'n-4',
    title: 'Finding resolved',
    detail: 'Security header remediation was resolved via staging validation.',
    time: 'Yesterday',
    type: 'resolved',
  },
];
