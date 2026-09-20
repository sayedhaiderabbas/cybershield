from __future__ import annotations

from urllib.parse import urlsplit

from app.scanner.safety import resolve_hostname
from app.scanner.models import CheckResult


def run_dns_check(url: str, response: dict) -> CheckResult | None:
    hostname = urlsplit(url).hostname
    if not hostname:
        return None
    addresses = resolve_hostname(hostname)
    if not addresses:
        return CheckResult(
            check_id='CS-DNS-001',
            title='DNS resolution unavailable',
            category='dns',
            severity='info',
            description='The scanner could not resolve the target hostname safely during the check.',
            evidence={'url': url, 'hostname': hostname, 'resolved_addresses': []},
            recommendation='Review the configured hostname and ensure it resolves to a public endpoint before scanning again.',
        )

    return CheckResult(
        check_id='CS-DNS-001',
        title='DNS resolution observed',
        category='dns',
        severity='info',
        description='The hostname resolved to a public IP address within the safe rule set.',
        evidence={'url': url, 'hostname': hostname, 'resolved_addresses': addresses[:4]},
        recommendation='Keep DNS records monitored for unexpected or unauthorized changes.',
    )
