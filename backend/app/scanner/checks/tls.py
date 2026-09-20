from __future__ import annotations

import socket
import ssl
from urllib.parse import urlsplit

from app.scanner.models import CheckResult


def run_tls_check(url: str, response: dict) -> CheckResult | None:
    parsed = urlsplit(url)
    if parsed.scheme.lower() != 'https':
        return None
    host = parsed.hostname
    if not host:
        return None
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                cert = tls_sock.getpeercert()
    except Exception:
        return CheckResult(
            check_id='CS-TLS-001',
            title='TLS information unavailable',
            category='tls',
            severity='info',
            description='The scanner could not establish a safe certificate observation for the target endpoint.',
            evidence={'url': url, 'observed': 'unavailable'},
            recommendation='Validate the certificate configuration manually or retry during a normal maintenance window.',
        )

    if not cert:
        return None

    not_after = cert.get('notAfter')
    issuer = cert.get('issuer')
    subject = cert.get('subject')
    if not_after is None:
        return None

    evidence = {
        'url': url,
        'issuer': issuer,
        'subject': subject,
        'not_after': not_after,
        'observation': 'certificate_observed',
    }
    return CheckResult(
        check_id='CS-TLS-001',
        title='TLS certificate observed',
        category='tls',
        severity='info',
        description='The server presented a valid certificate chain or a certificate observation was collected without exploitation.',
        evidence=evidence,
        recommendation='Keep certificate monitoring active and renew certificates before expiry.',
    )
