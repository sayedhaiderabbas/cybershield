from __future__ import annotations

from app.scanner.models import CheckResult


def run_cookie_security_check(url: str, response: dict) -> list[CheckResult]:
    results: list[CheckResult] = []
    cookies = response.get('cookies', [])
    if not cookies:
        return results

    for cookie in cookies:
        name = str(cookie.get('name', 'unknown-cookie'))
        secure = bool(cookie.get('secure'))
        http_only = bool(cookie.get('httponly'))
        same_site = bool(cookie.get('samesite'))

        if not secure:
            results.append(
                CheckResult(
                    check_id='CS-COOKIE-001',
                    title='Cookie missing Secure flag',
                    category='cookies',
                    severity='low',
                    description=f'The cookie {name} did not include the Secure attribute during the observed response.',
                    evidence={'url': url, 'cookie': name, 'missing_flags': ['Secure']},
                    recommendation='Set the Secure attribute on cookies that carry session or state data over HTTPS.',
                )
            )
        if not http_only:
            results.append(
                CheckResult(
                    check_id='CS-COOKIE-002',
                    title='Cookie missing HttpOnly flag',
                    category='cookies',
                    severity='low',
                    description=f'The cookie {name} did not include the HttpOnly attribute, which reduces protection against script access.',
                    evidence={'url': url, 'cookie': name, 'missing_flags': ['HttpOnly']},
                    recommendation='Set HttpOnly on sensitive cookies to reduce script-based exposure.',
                )
            )
        if not same_site:
            results.append(
                CheckResult(
                    check_id='CS-COOKIE-003',
                    title='Cookie missing SameSite attribute',
                    category='cookies',
                    severity='info',
                    description=f'The cookie {name} did not include a SameSite attribute in the observed Set-Cookie headers.',
                    evidence={'url': url, 'cookie': name, 'missing_flags': ['SameSite']},
                    recommendation='Add a conservative SameSite policy such as Lax or Strict where the application supports it.',
                )
            )

    return results
