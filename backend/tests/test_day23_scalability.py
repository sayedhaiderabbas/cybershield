from __future__ import annotations

from app.models.entities import Business, MonitoringTarget, Website
from conftest import TestingSessionLocal


def _register_and_login(client, email: str) -> tuple[str, str]:
    client.post(
        '/api/v1/auth/register',
        json={'email': email, 'password': 'SecurePassword123', 'full_name': 'Scalability Owner'},
    )
    response = client.post(
        '/api/v1/auth/login',
        json={'email': email, 'password': 'SecurePassword123'},
    )
    assert response.status_code == 200, response.text
    return response.json()['data']['token'], response.json()['data']['user']['id']


def test_monitoring_list_is_bounded_and_deterministic(client) -> None:
    token, owner_id = _register_and_login(client, 'day23-monitoring@example.com')
    db = TestingSessionLocal()
    try:
        business = Business(owner_id=owner_id, name='Scalability Business')
        db.add(business)
        db.flush()
        websites = [
            Website(
                business_id=business.id,
                name=f'Site {index}',
                url=f'https://site-{index}.example',
                normalized_url=f'https://site-{index}.example',
                hostname=f'site-{index}.example',
                status='active',
            )
            for index in range(3)
        ]
        db.add_all(websites)
        db.flush()
        db.add_all([MonitoringTarget(business_id=business.id, website_id=website.id) for website in websites])
        db.commit()

        response = client.get(
            '/api/v1/monitoring?page=2&page_size=2',
            headers={'Authorization': f'Bearer {token}'},
        )
        assert response.status_code == 200
        payload = response.json()
        assert payload['meta']['total'] == 3
        assert payload['meta']['total_pages'] == 2
        assert len(payload['data']) == 1
    finally:
        db.close()
