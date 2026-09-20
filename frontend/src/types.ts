export type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational';
export type FindingStatus = 'Open' | 'In Progress' | 'Resolved' | 'Acknowledged';
export type ScanStatus = 'Queued' | 'Running' | 'Completed' | 'Failed';
export type ThemeMode = 'light' | 'dark' | 'system';

export interface User {
  id: string;
  name: string;
  email: string;
  company: string;
  role: string;
}

export interface Business {
  id: string;
  name: string;
  industry: string;
  primaryContact: string;
}

export interface Website {
  id: string;
  name: string;
  url: string;
  status: 'Healthy' | 'Watch' | 'At Risk';
  score: number;
  lastAssessment: string;
  openFindings: number;
  businessId: string;
}

export interface Scan {
  id: string;
  website: string;
  type: string;
  started: string;
  duration: string;
  status: ScanStatus;
  findings: number;
}

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  category: string;
  website: string;
  status: FindingStatus;
  remediationStatus?: string;
  detectedDate: string;
  description: string;
  evidence: string[];
  recommendation: string;
  whyItMatters?: string;
  affectedAsset?: string;
  verification?: string;
  firstSeenAt?: string;
  lastSeenAt?: string;
  occurrenceCount?: number;
  resolvedAt?: string | null;
  websiteName?: string;
  websiteUrl?: string;
  scanStatus?: string;
  scanType?: string;
  scanCompletedAt?: string | null;
}

export interface Report {
  id: string;
  name: string;
  website: string;
  date: string;
  posture: string;
  status: 'Ready' | 'Generating' | 'Review';
}

export interface MonitoringTarget {
  id: string;
  name: string;
  status: 'Protected' | 'Watch' | 'Change detected';
  lastCheck: string;
  nextAssessment: string;
  changes: number;
}

export interface NotificationItem {
  id: string;
  title: string;
  detail: string;
  time: string;
  type: 'assessment' | 'finding' | 'resolved' | 'monitoring';
}

export interface DashboardStats {
  score: number;
  critical: number;
  openFindings: number;
  protectedWebsites: number;
  lastAssessment: string;
}

export interface MockThemePreference {
  mode: ThemeMode;
}
