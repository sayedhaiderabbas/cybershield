from __future__ import annotations

import pytest

from app.scanner.checks.headers import run_security_header_check
from app.scanner.models import calculate_risk_score
from app.scanner.safety import is_safe_redirect_target, validate_target_url


def test_target_validation_and_ssrf_boundary() -> None:
    assert validate_target_url('https://example.com') == 'https://example.com'
    assert validate_target_url('http://example.com') == 'http://example.com'

    with pytest.raises(ValueError):
        validate_target_url('file:///etc/passwd')
    with pytest.raises(ValueError):
        validate_target_url('ftp://example.com')
    with pytest.raises(ValueError):
        validate_target_url('http://localhost')
    with pytest.raises(ValueError):
        validate_target_url('http://127.0.0.1')
    with pytest.raises(ValueError):
        validate_target_url('http://169.254.169.254')


def test_redirects_are_restricted_to_safe_destinations() -> None:
    assert is_safe_redirect_target('https://example.com') is True
    assert is_safe_redirect_target('http://localhost') is False
    assert is_safe_redirect_target('http://127.0.0.1') is False
    assert is_safe_redirect_target('http://169.254.169.254') is False


def test_risk_score_is_deterministic_and_bounded() -> None:
    findings = [
        {'severity': 'critical'},
        {'severity': 'high'},
        {'severity': 'low'},
    ]
    assert calculate_risk_score(findings) == 19
    assert calculate_risk_score([]) == 0
    assert calculate_risk_score([{'severity': 'critical'} for _ in range(30)]) == 100


def test_header_checks_create_safe_findings() -> None:
    findings = run_security_header_check('https://example.com', {'headers': {'server': 'nginx'}})
    ids = {item.check_id for item in findings}
    assert 'CS-HSTS-001' in ids
    assert 'CS-CTO-001' in ids
