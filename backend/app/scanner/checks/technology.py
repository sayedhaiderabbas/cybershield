from __future__ import annotations

from app.scanner.models import CheckResult


def run_technology_check(url: str, response: dict) -> list[CheckResult]:
    headers = response.get('headers', {})
    results: list[CheckResult] = []
    product = headers.get('Server') or headers.get('server')
    if product:
        results.append(
            CheckResult(
                check_id='CS-TECH-001',
                title='Server header observed',
                category='technology',
                severity='info',
                description='The server identified itself in a response header, which is a passive public observation.',
                evidence={'url': url, 'header': 'Server', 'observed_value': product},
                recommendation='Keep operational headers aligned with your security baseline and avoid unnecessary disclosure.',
            )
        )

    powered_by = headers.get('X-Powered-By') or headers.get('x-powered-by')
    if powered_by:
        results.append(
            CheckResult(
                check_id='CS-TECH-002',
                title='Framework header observed',
                category='technology',
                severity='info',
                description='A framework or platform header was observed in a public response header.',
                evidence={'url': url, 'header': 'X-Powered-By', 'observed_value': powered_by},
                recommendation='Reduce unnecessary framework disclosure when it is not required for customer-facing operation.',
            )
        )

    return results
