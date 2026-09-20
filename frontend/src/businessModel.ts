export type PlanAvailability = 'evaluation' | 'available' | 'coming_soon';

export type BusinessPlan = {
  id: string;
  name: string;
  description: string;
  audience: string;
  priceDisplay: string;
  billingDisplay: string;
  availability: PlanAvailability;
  cta: string;
  features: string[];
  limits: string[];
};

export const businessModelPlans: BusinessPlan[] = [
  {
    id: 'community',
    name: 'Community',
    description: 'A clear starting point for learning the security workflow and evaluating CyberShield.',
    audience: 'Individual users and developers',
    priceDisplay: 'Free',
    billingDisplay: 'Informational plan',
    availability: 'evaluation',
    cta: 'Start evaluation',
    features: ['Website scanning', 'Findings and risk visibility', 'Guided remediation context', 'Limited report access'],
    limits: ['Limited websites', 'Limited scan volume', 'Basic monitoring cadence'],
  },
  {
    id: 'pro',
    name: 'Pro',
    description: 'A practical security workflow for startups, developers, and small teams.',
    audience: 'Startups and small teams',
    priceDisplay: 'Pro',
    billingDisplay: 'Conceptual monthly tier',
    availability: 'available',
    cta: 'Explore Pro',
    features: ['Everything in Community', 'Continuous monitoring', 'PDF security reports', 'AI-assisted explanations', 'Remediation and verification workflow'],
    limits: ['More monitored websites', 'Higher scan allowance', 'Expanded AI assistance'],
  },
  {
    id: 'business',
    name: 'Business',
    description: 'A broader operational view for organizations and consultants managing multiple assessments.',
    audience: 'Security teams and agencies',
    priceDisplay: 'Business',
    billingDisplay: 'Contact-oriented tier',
    availability: 'coming_soon',
    cta: 'Request access',
    features: ['Everything in Pro', 'Multiple website visibility', 'Security activity and audit context', 'Operational reporting workflows', 'Team-oriented visibility'],
    limits: ['Higher asset capacity', 'Higher usage allowance', 'Advanced operational visibility'],
  },
];

export const businessModelFeatures = [
  { name: 'Website scanning', community: 'Included', pro: 'Included', business: 'Included' },
  { name: 'Findings and risk scoring', community: 'Included', pro: 'Included', business: 'Included' },
  { name: 'Monitoring', community: 'Limited', pro: 'Included', business: 'Included' },
  { name: 'AI security assistant', community: 'Limited', pro: 'Included', business: 'Included' },
  { name: 'PDF reports', community: 'Limited', pro: 'Included', business: 'Included' },
  { name: 'Remediation and verification', community: 'Limited', pro: 'Included', business: 'Included' },
  { name: 'Security activity / audit context', community: 'Limited', pro: 'Available', business: 'Included' },
];

export const businessModelSegments = [
  { title: 'Developers', description: 'Need quick, understandable security visibility while building and maintaining websites.' },
  { title: 'Startups', description: 'Need an affordable path from assessment findings to tracked remediation and verification.' },
  { title: 'Security teams', description: 'Need a shared view of findings, risk, monitoring, reports, and security activity.' },
  { title: 'Consultants and agencies', description: 'Need repeatable assessment, reporting, and follow-up workflows across client websites.' },
];

export const businessModelWorkflow = [
  ['01', 'Discover', 'Register owned websites and establish the assessment scope.'],
  ['02', 'Scan', 'Run the existing security assessment workflow against authorized assets.'],
  ['03', 'Assess risk', 'Use deterministic findings and risk scoring to prioritize attention.'],
  ['04', 'Understand', 'Use finding detail and bounded AI explanation to clarify evidence.'],
  ['05', 'Remediate', 'Track the recommended remediation workflow without changing scanner truth.'],
  ['06', 'Verify', 'Record verification outcomes from subsequent authorized checks.'],
  ['07', 'Monitor', 'Compare current and previous monitoring states over time.'],
  ['08', 'Audit', 'Review security activity and maintain an accountable history.'],
] as const;
