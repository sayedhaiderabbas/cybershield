# Product Requirements

## 1. Account Registration

**User Story**

As a prospective customer, I want to register an account, so that I can securely manage my business security information.

### Acceptance Criteria

- User can enter required registration information.
- System validates required fields and input formats.
- System rejects duplicate or invalid registrations clearly.
- Passwords are never stored or displayed in plaintext.
- Successful registration creates an isolated account.

## 2. Login

**User Story**

As a registered user, I want to log in, so that I can access my protected application area.

### Acceptance Criteria

- User can submit valid credentials.
- Invalid credentials produce a clear, non-sensitive error.
- Successful login establishes a secure authenticated session.
- Unauthenticated users cannot access protected application areas.

## 3. Business Creation

**User Story**

As a business owner, I want to create a business profile, so that security information is associated with my organization.

### Acceptance Criteria

- Authenticated user can enter business information.
- Required fields are validated.
- A unique business identifier is created.
- Only authorized account members can access the business.

## 4. Website Addition

**User Story**

As a business owner, I want to add my website, so that CyberShield can assess an authorized target.

### Acceptance Criteria

- User can enter a website URL.
- System validates the URL and allowed scheme.
- Website is associated with the selected business.
- System communicates the authorization and safe-check expectations.
- Duplicate or invalid website entries are handled clearly.

## 5. Starting a Security Scan

**User Story**

As a business owner, I want to scan my website, so that I can understand its security posture.

### Acceptance Criteria

- User can select an authorized website.
- User can start a scan.
- System validates scan eligibility and target safety.
- Scan receives a unique identifier.
- System indicates that checks are safe and non-destructive.

## 6. Viewing Scan Progress

**User Story**

As a business owner, I want to view scan progress, so that I know whether results are ready.

### Acceptance Criteria

- User can retrieve scan status by identifier.
- Status distinguishes queued, running, completed, and failed states.
- Progress does not expose another account's scan.
- Errors are displayed clearly without sensitive internals.

## 7. Viewing Findings

**User Story**

As a business owner, I want to view findings, so that I can prioritize security improvements.

### Acceptance Criteria

- Completed scans display verified findings.
- Findings show title, category, severity, status, and affected target.
- User can filter or sort findings by relevant priority fields.
- Finding data is isolated to the authorized business.

## 8. Viewing Finding Details

**User Story**

As a business owner, I want to view finding details, so that I understand the evidence and recommended action.

### Acceptance Criteria

- Detail view includes description, evidence, recommendation, timestamp, and target.
- Severity uses the documented severity levels.
- Evidence is traceable to the completed check.
- No unsupported claim is presented as verified evidence.

## 9. Getting an AI Explanation

**User Story**

As a business owner, I want an AI explanation of a verified finding, so that I can understand its business impact.

### Acceptance Criteria

- User can request an explanation for an existing verified finding.
- AI input is grounded in stored finding data.
- Explanation distinguishes evidence from interpretation.
- AI cannot introduce a new unverified vulnerability as fact.
- AI failures are surfaced clearly.

## 10. Getting Remediation Guidance

**User Story**

As a business owner, I want remediation guidance, so that I can take practical corrective action.

### Acceptance Criteria

- User can request guidance for a verified finding.
- Guidance references the finding and its evidence.
- Steps are understandable and actionable.
- AI does not claim remediation is complete without verification.
- Guidance errors are handled clearly.

## 11. Generating a Security Report

**User Story**

As a business owner, I want to generate a security report, so that I can share a professional summary and track remediation.

### Acceptance Criteria

- User can request a report for an authorized business and scan.
- Report includes business, target, date, score, summary, findings, evidence, recommendations, priorities, and methodology.
- Report receives a unique identifier and generation status.
- Report contains only data authorized for that business.
- Generation errors are communicated clearly.

## 12. Viewing Monitoring Status

**User Story**

As a business owner, I want to view monitoring status, so that I know whether meaningful website security changes are detected.

### Acceptance Criteria

- User can view configured monitoring targets.
- Each target shows schedule and latest check status.
- Changes are compared with a previous result.
- Monitoring uses safe, authorized checks.
- Notifications or dashboard indicators identify meaningful changes without overstating risk.
