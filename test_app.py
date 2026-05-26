import pytest
from app import app


@pytest.fixture
def client():
    app.config['TESTING'] = True

    with app.test_client() as client:
        yield client


def test_home_page_opens(client):
    response = client.get('/')
    assert response.status_code == 200


def test_login_page_opens(client):
    response = client.get('/login')
    assert response.status_code == 200


def test_register_page_opens(client):
    response = client.get('/register')
    assert response.status_code == 200


def test_admin_without_login_redirects(client):
    response = client.get('/admin')
    assert response.status_code in (302, 301)