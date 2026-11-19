""" TEST - Server Endpoint """

import fixtures  # pylint: disable=unused-import
from fixtures.client import csrf_token


def test_get_server_config(client, login, logout):
    """Server config test case - valid config response"""
    login(client)

    token = csrf_token(client.get('/'))
    response = client.post('/api/servers/myserver', data={'csrf_token': token})
    assert response.status_code == 200
    assert 'dev tun' in response.text
    assert response.headers['Content-Disposition'] == 'attachment; filename="myserver.ovpn"'

    logout(client)


def test_get_server_config_expired(client, expire_session, login, logout):
    """Server config test case - expired session return Unauthorized"""
    login(client)
    expire_session(client)

    response = client.post(
        '/api/servers/myserver',
        data={'csrf_token': getattr(client, 'csrf_token', '')})
    assert response.status_code == 401

    logout(client)


def test_get_server_config_not_logged_in(client):
    """Server config test case - not logged in return Unauthorized"""
    # A form body is required so axum's Form extractor does not answer 415
    # before the handler can apply its authentication check.
    response = client.post('/api/servers/myserver', data={'csrf_token': ''})
    assert response.status_code == 401


def test_get_server_config_invalid_server(client, login, logout):
    """Server config test case - invalid server choice is forbidden"""
    login(client)

    token = csrf_token(client.get('/'))
    response = client.post(
        '/api/servers/mybadserver', data={'csrf_token': token})
    assert response.status_code == 403
    assert response.headers['Content-Type'].startswith('text/html')
    assert 'Forbidden' in response.text

    logout(client)


def test_get_server_config_denied_server(client, login, logout):
    """Server config test case - access denied is forbidden"""
    login(client)

    token = csrf_token(client.get('/'))
    response = client.post(
        '/api/servers/myserver4', data={'csrf_token': token})
    assert response.status_code == 403
    assert response.headers['Content-Type'].startswith('text/html')
    assert 'Forbidden' in response.text

    logout(client)
