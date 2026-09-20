from __future__ import annotations

from conftest import TestingSessionLocal
from test_day9_reports import _create_report_fixture, _register_and_login


def _create_report(client, token: str, business_id: str, *, title: str, website_id: str | None = None, status: str | None = None) -> dict:
    response = client.post(
        '/api/v1/reports',
        json={'business_id': business_id, 'website_id': website_id, 'title': title},
        headers={'Authorization': f'Bearer {token}'},
    )
    assert response.status_code == 201, response.text
    report = response.json()['data']
    if status and status != report['status']:
        raise AssertionError(f'Unable to create requested report status {status}.')
    return report


def test_day20_report_center_listing_supports_search_filter_sort_and_pagination(client) -> None:
    token, owner_id = _register_and_login(client, email='day20-list@example.com')
    db = TestingSessionLocal()
    try:
        business, website, _, _ = _create_report_fixture(db, owner_id)
        _create_report(client, token, business.id, title='Alpha assessment', website_id=website.id)
        _create_report(client, token, business.id, title='Beta assessment')
        _create_report(client, token, business.id, title='Gamma assessment')

        first_page = client.get('/api/v1/reports?page=1&page_size=2', headers={'Authorization': f'Bearer {token}'})
        assert first_page.status_code == 200, first_page.text
        assert len(first_page.json()['data']) == 2
        assert first_page.json()['meta']['total'] == 3
        assert first_page.json()['meta']['total_pages'] == 2
        assert all('findings' not in (item.get('metadata') or {}) for item in first_page.json()['data'])

        search = client.get('/api/v1/reports?search=beta', headers={'Authorization': f'Bearer {token}'})
        assert search.status_code == 200
        assert [item['title'] for item in search.json()['data']] == ['Beta assessment']

        website_filter = client.get(f'/api/v1/reports?website_id={website.id}', headers={'Authorization': f'Bearer {token}'})
        assert website_filter.status_code == 200
        assert all(item['website_id'] == website.id for item in website_filter.json()['data'])

        oldest = client.get('/api/v1/reports?sort=oldest', headers={'Authorization': f'Bearer {token}'})
        assert oldest.status_code == 200
        created_times = [item['created_at'] for item in oldest.json()['data']]
        assert created_times == sorted(created_times)
    finally:
        db.close()


def test_day20_report_center_listing_is_authenticated_and_business_scoped(client) -> None:
    owner_token, owner_id = _register_and_login(client, email='day20-owner@example.com')
    other_token, other_id = _register_and_login(client, email='day20-other@example.com')
    db = TestingSessionLocal()
    try:
        owner_business, _, _, _ = _create_report_fixture(db, owner_id)
        other_business, _, _, _ = _create_report_fixture(db, other_id, business_name='Other business')
        _create_report(client, owner_token, owner_business.id, title='Owner report')
        _create_report(client, other_token, other_business.id, title='Other report')

        assert client.get('/api/v1/reports').status_code in {401, 403}
        owner_list = client.get('/api/v1/reports', headers={'Authorization': f'Bearer {owner_token}'})
        assert owner_list.status_code == 200
        assert all(item['business_id'] == owner_business.id for item in owner_list.json()['data'])

        other_list = client.get('/api/v1/reports', headers={'Authorization': f'Bearer {other_token}'})
        assert other_list.status_code == 200
        assert all(item['business_id'] == other_business.id for item in other_list.json()['data'])
    finally:
        db.close()
