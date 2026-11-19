""" TEST - Index page """

import fixtures  # pylint: disable=unused-import


def test_index(client, login, logout):
    """Index page test - logged in"""
    login(client)

    # Get the index page after being authenticated
    response = client.get('/')
    assert response.status_code == 200
    assert 'Logged in as: testuser' in response.text
    assert 'Download VPN Server Configuration' in response.text
    assert 'myserver' in response.text
    assert 'myserver2' in response.text
    assert 'myserver3' in response.text
    assert 'myserver4' not in response.text

    logout(client)


def test_index_expired(client, login, logout, expire_session):
    """Index page test - Expired session"""
    login(client)

    expire_session(client)

    response = client.get('/', allow_redirects=False)
    assert response.status_code == 302
    assert response.headers['Location'] == '/auth/login'

    logout(client)


def test_logout_when_anonymous_is_idempotent(client):
    """An anonymous logout is a no-op that redirects to the index"""

    assert 'session' not in client.cookies
    response = client.post('/auth/logout', allow_redirects=False)
    assert response.status_code == 302
    assert response.headers['Location'] == '/'
