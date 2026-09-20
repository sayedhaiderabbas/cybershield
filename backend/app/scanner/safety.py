from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit

ALLOWED_SCHEMES = {'http', 'https'}
BLOCKED_NETWORKS = (
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('169.254.0.0/16'),
    ipaddress.ip_network('100.64.0.0/10'),
    ipaddress.ip_network('::1/128'),
    ipaddress.ip_network('fc00::/7'),
    ipaddress.ip_network('fe80::/10'),
)


class ScannerSafetyError(ValueError):
    pass


def _is_blocked_ip(ip: ipaddress._BaseAddress) -> bool:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
        return True
    if ip.is_private or ip.is_unspecified:
        return True
    for network in BLOCKED_NETWORKS:
        if ip in network:
            return True
    return False


def resolve_hostname(hostname: str) -> list[str]:
    if not hostname:
        return []
    host = hostname.strip().lower()
    if host == 'localhost' or host.endswith('.localhost'):
        return ['127.0.0.1']
    try:
        infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return []
    addresses: list[str] = []
    for info in infos:
        sockaddr = info[4]
        if not sockaddr or len(sockaddr) < 2:
            continue
        ip_value = sockaddr[0]
        try:
            ip_obj = ipaddress.ip_address(ip_value)
        except ValueError:
            continue
        if not _is_blocked_ip(ip_obj):
            addresses.append(ip_obj.compressed)
    return addresses


def validate_target_url(raw_url: str) -> str:
    if not raw_url or not isinstance(raw_url, str):
        raise ScannerSafetyError('Target URL is required.')
    parsed = urlsplit(raw_url.strip())
    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise ScannerSafetyError('Only HTTP and HTTPS are allowed.')
    if not parsed.hostname:
        raise ScannerSafetyError('A valid hostname is required.')
    if '@' in raw_url:
        raise ScannerSafetyError('Credentials in URLs are not allowed.')
    host = parsed.hostname.strip().lower()
    if host in {'localhost', '127.0.0.1'} or host.endswith('.localhost'):
        raise ScannerSafetyError('Local and loopback targets are not allowed.')
    addresses = resolve_hostname(host)
    if not addresses:
        raise ScannerSafetyError('Host could not be resolved safely.')
    return raw_url.strip()


def is_safe_redirect_target(target: str, *, current_url: str | None = None) -> bool:
    if not target:
        return False
    try:
        parsed = urlsplit(target)
    except ValueError:
        return False
    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        return False
    hostname = parsed.hostname
    if not hostname:
        return False
    host = hostname.strip().lower()
    if host in {'localhost', '127.0.0.1'} or host.endswith('.localhost'):
        return False
    addresses = resolve_hostname(host)
    return bool(addresses)


def redact_sensitive_value(value: str | None) -> str:
    if value is None or value == '':
        return '[REDACTED]'
    if len(value) <= 6:
        return '[REDACTED]'
    return f'{value[:2]}***{value[-2:]}'
