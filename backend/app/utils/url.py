from __future__ import annotations

from urllib.parse import urlparse


def normalize_url(value: str) -> tuple[str, str]:
    if not value or not value.strip():
        raise ValueError('URL is required.')

    parsed = urlparse(value)
    if parsed.scheme not in {'http', 'https'}:
        raise ValueError('Only http and https URLs are allowed.')
    if not parsed.netloc:
        raise ValueError('URL must include a valid hostname.')

    hostname = parsed.hostname or ''
    if not hostname:
        raise ValueError('URL must include a valid hostname.')

    normalized = f"{parsed.scheme.lower()}://{hostname.lower()}"
    if parsed.port:
        normalized = f"{normalized}:{parsed.port}"
    if parsed.path and parsed.path != '/':
        normalized = f"{normalized}{parsed.path.rstrip('/')}"
    elif parsed.path == '/':
        normalized = f"{normalized}/"
    if parsed.query:
        normalized = f"{normalized}?{parsed.query}"
    if parsed.fragment:
        normalized = f"{normalized}#{parsed.fragment}"

    return normalized, hostname.lower()
