from __future__ import annotations

from fastapi.testclient import TestClient

from app.db.session import SessionLocal
from app.models.entities import Business


def _create_business(client: TestClient, user_id: str, *, name: str = 'Acme Co') -> dict:
    response = client.post(
        '/api/v1/businesses',
        json={'name': name, 'industry': 'Retail', 'description': 'Regional retailer'},
        headers={'X-User-ID': user_id},
    )
    assert response.status_code == 201, response.text
    return response.json()['data']


def test_business_crud(client: TestClient, user_record) -> None:
    headers = {'X-User-ID': user_record.id}

    created = _create_business(client, user_record.id)
    assert created['name'] == 'Acme Co'

    list_response = client.get('/api/v1/businesses', headers=headers)
    assert list_response.status_code == 200, list_response.text
    assert list_response.json()['meta']['total'] == 1

    business_id = created['id']
    get_response = client.get(f'/api/v1/businesses/{business_id}', headers=headers)
    assert get_response.status_code == 200, get_response.text
    assert get_response.json()['data']['id'] == business_id

    patch_response = client.patch(
        f'/api/v1/businesses/{business_id}',
        json={'description': 'Updated description'},
        headers=headers,
    )
    assert patch_response.status_code == 200, patch_response.text
    assert patch_response.json()['data']['description'] == 'Updated description'

    delete_response = client.delete(f'/api/v1/businesses/{business_id}', headers=headers)
    assert delete_response.status_code == 204, delete_response.text


def test_website_url_validation(client: TestClient, user_record) -> None:
    business = _create_business(client, user_record.id, name='Example Business')
    headers = {'X-User-ID': user_record.id}

    invalid_response = client.post(
        '/api/v1/websites',
        json={'business_id': business['id'], 'name': 'Main site', 'url': 'not-a-url'},
        headers=headers,
    )
    assert invalid_response.status_code == 422, invalid_response.text

    created = client.post(
        '/api/v1/websites',
        json={'business_id': business['id'], 'name': 'Main site', 'url': 'https://example.com/'},
        headers=headers,
    )
    assert created.status_code == 201, created.text

    duplicate = client.post(
        '/api/v1/websites',
        json={'business_id': business['id'], 'name': 'Main site', 'url': 'https://example.com/'},
        headers=headers,
    )
    assert duplicate.status_code == 409, duplicate.text
