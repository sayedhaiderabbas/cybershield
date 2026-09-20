from __future__ import annotations

from app.core.config import Settings
from app.models.entities import Business, Report
from conftest import TestingSessionLocal


def _register_and_login(client, email: str) -> tuple[str, str]:
    response = client.post(
        '/api/v1/auth/register',
        json={'email': email, 'password': 'SecurePassword123', 'full_name': 'QA Owner'},
    )
    assert response.status_code == 201, response.text
    login = client.post(
        '/api/v1/auth/login',
        json={'email': email, 'password': 'SecurePassword123'},
    )
    assert login.status_code == 200, login.text
    payload = login.json()['data']
    return payload['token'], payload['user']['id']


def test_authentication_failure_paths_are_sanitized(client) -> None:
    for headers in (
        {},
        {'Authorization': 'Bearer malformed-token'},
        {'Authorization': 'Basic credentials'},
    ):
        response = client.get('/api/v1/auth/me', headers=headers)
        assert response.status_code in {401, 403}
        body = response.json()
        assert 'traceback' not in response.text.lower()
        assert 'secret' not in response.text.lower()
        assert body['error']['details'] == []


def test_validation_and_pagination_boundaries_are_rejected_safely(client) -> None:
    token, _ = _register_and_login(client, 'day25-validation@example.com')
    auth = {'Authorization': f'Bearer {token}'}

    malformed = client.post(
        '/api/v1/businesses',
        content='{"name":',
        headers={**auth, 'Content-Type': 'application/json'},
    )
    assert malformed.status_code == 422
    assert malformed.json()['error']['code'] == 'VALIDATION_ERROR'
    assert 'Traceback' not in malformed.text

    for query in ('page=0', 'page_size=0', 'page_size=101', 'page=bad'):
        response = client.get(f'/api/v1/businesses?{query}', headers=auth)
        assert response.status_code == 422
        assert response.json()['error']['code'] == 'VALIDATION_ERROR'

    extra_field = client.post(
        '/api/v1/businesses',
        json={'name': 'QA business', 'unexpected': 'rejected'},
        headers=auth,
    )
    assert extra_field.status_code == 422


def test_business_pagination_has_stable_pages_and_empty_final_page(client) -> None:
    token, _ = _register_and_login(client, 'day25-pagination@example.com')
    auth = {'Authorization': f'Bearer {token}'}
    for index in range(3):
        response = client.post(
            '/api/v1/businesses',
            json={'name': f'Business {index}'},
            headers=auth,
        )
        assert response.status_code == 201, response.text

    first = client.get('/api/v1/businesses?page=1&page_size=2', headers=auth)
    second = client.get('/api/v1/businesses?page=2&page_size=2', headers=auth)
    empty = client.get('/api/v1/businesses?page=3&page_size=2', headers=auth)
    assert first.status_code == second.status_code == empty.status_code == 200
    assert len(first.json()['data']) == 2
    assert len(second.json()['data']) == 1
    assert empty.json()['data'] == []
    assert first.json()['meta']['total'] == 3
    assert first.json()['meta']['total_pages'] == 2
    ids = [item['id'] for item in first.json()['data'] + second.json()['data']]
    assert len(ids) == len(set(ids)) == 3


def test_report_download_rejects_artifact_path_traversal(client) -> None:
    token, owner_id = _register_and_login(client, 'day25-report-path@example.com')
    db = TestingSessionLocal()
    try:
        business = Business(owner_id=owner_id, name='Report QA business')
        db.add(business)
        db.commit()
        db.refresh(business)

        report = Report(
            business_id=business.id,
            requested_by=owner_id,
            title='Path safety report',
            report_type='security_assessment',
            status='completed',
            artifact_path='generated/../../outside.pdf',
        )
        db.add(report)
        db.commit()
        db.refresh(report)
        report_id = report.id
    finally:
        db.close()

    response = client.get(
        f'/api/v1/reports/{report_id}/download',
        headers={'Authorization': f'Bearer {token}'},
    )
    assert response.status_code == 404
    assert 'outside.pdf' not in response.text


def test_audit_events_have_no_mutation_endpoint(client) -> None:
    token, _ = _register_and_login(client, 'day25-audit@example.com')
    response = client.patch(
        '/api/v1/audit-events/nonexistent',
        json={'message': 'mutated'},
        headers={'Authorization': f'Bearer {token}'},
    )
    assert response.status_code in {404, 405}


def test_day24_production_security_configuration_regressions() -> None:
    try:
        Settings(
            APP_ENV='production',
            JWT_SECRET='a-secure-production-secret-that-is-long-enough',
            CORS_ORIGINS=['*'],
        )
    except ValueError as exc:
        assert 'CORS' in str(exc)
    else:
        raise AssertionError('Production settings accepted wildcard CORS.')
