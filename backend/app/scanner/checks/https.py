from __future__ import annotations

from urllib.parse import urlsplit

from app.scanner.models import CheckResult


def run_https_check(url: str, response: dict) -> CheckResult | None:
    final_url = response.get('final_url', url)
    scheme = urlsplit(final_url).scheme.lower()
    if scheme == 'https':
        return None

    return CheckResult(
        check_id='CS-HTTPS-001',
        title='HTTPS not enforced',
        category='transport',
        severity='low',
        description='The website was observed over HTTP or did not redirect to HTTPS during the safe assessment.',
        evidence={
            'url': final_url,
            'observed_scheme': scheme,
            'status_code': response.get('status_code'),
        },
        recommendation='Configure TLS on the website and enforce HTTPS redirects for all user traffic.',
    )
