from __future__ import annotations

from typing import Any
from urllib.parse import urljoin

import httpx

from app.core.config import get_settings
from app.scanner.safety import is_safe_redirect_target, validate_target_url


class SafeScanError(RuntimeError):
    pass


class SafeHTTPClient:
    def __init__(self) -> None:
        settings = get_settings()
        self.connect_timeout = settings.scanner_connect_timeout
        self.read_timeout = settings.scanner_read_timeout
        self.total_timeout = settings.scanner_total_timeout
        self.max_redirects = settings.scanner_max_redirects
        self.max_response_bytes = settings.scanner_max_response_bytes
        self.headers = {
            'User-Agent': 'CyberShield-Security-Scanner/0.1.0',
            'Accept': 'text/html,application/json,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
        }

    def fetch(self, url: str, *, method: str = 'GET') -> dict[str, Any]:
        safe_url = validate_target_url(url)
        final_url = safe_url
        redirect_count = 0
        response_data: dict[str, Any] = {
            'url': final_url,
            'final_url': final_url,
            'status_code': 0,
            'headers': {},
            'cookies': [],
            'body_preview': '',
            'redirected': False,
        }

        while True:
            try:
                with httpx.Client(
                    headers=self.headers,
                    timeout=httpx.Timeout(self.connect_timeout, read=self.read_timeout, write=self.read_timeout, connect=self.connect_timeout),
                    follow_redirects=False,
                    verify=True,
                ) as client:
                    request = client.build_request(method, final_url)
                    response = client.send(request)
            except httpx.HTTPError as exc:  # pragma: no cover - network errors handled by scanner
                raise SafeScanError(f'HTTP request failed: {exc}') from exc

            response_data['status_code'] = response.status_code
            response_data['headers'] = dict(response.headers)
            response_data['url'] = str(response.url)
            response_data['final_url'] = str(response.url)
            response_data['cookies'] = self._extract_cookie_flags(response.headers)

            body = response.content[: self.max_response_bytes]
            if body:
                text = body.decode('utf-8', errors='ignore')
                response_data['body_preview'] = text[:800]
            else:
                response_data['body_preview'] = ''

            if response.status_code not in {301, 302, 303, 307, 308}:
                break
            if redirect_count >= self.max_redirects:
                raise SafeScanError('Redirect limit reached before a safe destination was confirmed.')
            location = response.headers.get('location')
            if not location:
                break
            redirect_target = urljoin(str(response.url), location)
            if not is_safe_redirect_target(redirect_target):
                raise SafeScanError('Unsafe redirect target blocked by SSRF policy.')
            final_url = redirect_target
            redirect_count += 1
            response_data['redirected'] = True

        return response_data

    @staticmethod
    def _extract_cookie_flags(headers: httpx.Headers) -> list[dict[str, object]]:
        results: list[dict[str, object]] = []
        for key, value in headers.multi_items():
            if key.lower() != 'set-cookie':
                continue
            cookie_name = value.split(';', 1)[0].split('=', 1)[0].strip()
            flags = {
                'name': cookie_name,
                'secure': 'secure' in value.lower(),
                'httponly': 'httponly' in value.lower(),
                'samesite': 'samesite=' in value.lower(),
            }
            results.append(flags)
        return results
