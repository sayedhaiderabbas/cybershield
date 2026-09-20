from __future__ import annotations

from app.scanner.models import CheckResult


def run_security_header_check(url: str, response: dict) -> list[CheckResult]:
    headers = {str(key).lower(): str(value) for key, value in response.get('headers', {}).items()}
    results: list[CheckResult] = []

    if 'strict-transport-security' not in headers:
        results.append(
            CheckResult(
                check_id='CS-HSTS-001',
                title='HSTS missing',
                category='headers',
                severity='low',
                description='The HTTPS website did not expose a Strict-Transport-Security header during the assessment.',
                evidence={'url': url, 'header': 'Strict-Transport-Security', 'present': False},
                recommendation='Add a Strict-Transport-Security header with a reasonable max-age to enforce HTTPS.',
            )
        )

    for header_name, check_id, title, severity, description, recommendation in [
        ('content-security-policy', 'CS-CSP-001', 'Content-Security-Policy missing', 'info', 'The target did not expose a Content-Security-Policy header.', 'Add a conservative Content-Security-Policy policy that matches the application’s actual needs.'),
        ('x-content-type-options', 'CS-CTO-001', 'X-Content-Type-Options missing', 'low', 'The target did not expose X-Content-Type-Options: nosniff.', 'Set X-Content-Type-Options to nosniff to reduce MIME confusion risk.'),
        ('referrer-policy', 'CS-RP-001', 'Referrer-Policy missing', 'info', 'The target did not expose a Referrer-Policy header.', 'Add a restrictive Referrer-Policy for user safety and privacy.'),
        ('permissions-policy', 'CS-PP-001', 'Permissions-Policy missing', 'info', 'The target did not expose a Permissions-Policy header.', 'Configure Permissions-Policy for a minimal browser feature policy.'),
    ]:
        if header_name not in headers:
            results.append(
                CheckResult(
                    check_id=check_id,
                    title=title,
                    category='headers',
                    severity=severity,
                    description=description,
                    evidence={'url': url, 'header': header_name, 'present': False},
                    recommendation=recommendation,
                )
            )

    return results
