# CyberShield Product Scope

## Product

CyberShield

**Tagline:** Simple cybersecurity management for small businesses.

**One-line description:** CyberShield helps small businesses discover, understand, prioritize, and remediate common cybersecurity weaknesses without requiring a dedicated cybersecurity expert.

## Target Customer

Small businesses that:

- operate websites
- depend on online services
- may not have dedicated cybersecurity staff
- need understandable security information
- need practical remediation guidance

## Problem

Small businesses can have basic security weaknesses but often lack the technical expertise, time, or budget required to continuously assess and manage their security posture.

## Solution

CyberShield provides a simple workflow:

```text
Business
→ Website
→ Security Check
→ Findings
→ Risk Prioritization
→ AI Explanation
→ Remediation Guidance
→ Security Report
→ Monitoring
```

## MVP Capabilities

### 1. Authentication

- Register
- Login
- Logout
- Current user
- Protected application area

### 2. Business Management

- Create a business
- Store business information
- Manage the business website

### 3. Website Security Assessment

Only safe and non-destructive checks against authorized targets:

- HTTPS availability
- TLS and certificate information
- HTTP security headers
- Cookie security attributes
- Basic DNS and security configuration indicators
- Basic publicly observable technology information where appropriate

### 4. Findings

Every finding should eventually contain:

- title
- category
- severity
- description
- evidence
- affected target
- recommendation
- status
- timestamp

Severity levels: Critical, High, Medium, Low, Informational.

### 5. Security Health Score

The score will be transparent, explainable, and based on documented rules. It will not be a mysterious AI-generated number.

### 6. Dashboard

Eventually show:

- security health score
- finding severity distribution
- recent scans
- recent findings
- remediation priorities
- website status

### 7. AI Security Assistant

The AI may explain a verified finding, explain business impact, provide remediation guidance, and create remediation checklists.

The AI must not invent evidence or vulnerabilities, claim a scan detected something it did not detect, or claim that an issue was fixed without verification.

### 8. Security Reports

Eventually generate professional reports containing business information, target, scan date, security score, executive summary, findings, evidence, recommendations, remediation priorities, and methodology.

### 9. Basic Monitoring

Eventually support scheduled re-checking of configured websites and detection of meaningful security configuration changes.

## Non-Goals

The following are explicitly excluded from the MVP to keep the hackathon product focused, safe, achievable, and polished:

- **Full SIEM:** broad enterprise event collection and correlation would overwhelm the focused product.
- **EDR:** endpoint telemetry and response require a different product surface and deployment model.
- **Antivirus:** malware prevention is outside website security posture management.
- **Malware analysis:** analyzing malicious artifacts is high-risk and not needed for the MVP.
- **Exploit framework:** exploitation is unsafe and unnecessary for demonstrating preventive value.
- **Automated exploitation:** the product must verify configuration weaknesses without attacking targets.
- **Credential attacks:** password testing and credential abuse are outside the authorized safe-check boundary.
- **Brute force:** aggressive authentication testing is unsafe and not part of the product.
- **Destructive penetration testing:** the MVP uses non-destructive checks only.
- **Enterprise SOC:** continuous analyst operations are beyond a solo-developer hackathon scope.
- **Mobile application:** the first product surface is web and website security.
- **Blockchain:** it does not solve the core customer problem.
- **Custom machine-learning model:** constrained explanations do not justify model development in the MVP.
- **Hundreds of vulnerability checks:** a small, reliable set of checks is preferable to shallow coverage.
- **Complex microservice infrastructure:** a modular, understandable architecture is safer and faster for a solo developer.
