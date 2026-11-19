"""Login fixture to create a new session for the test"""

from collections.abc import Callable
from urllib.parse import urlsplit, urlunsplit

import pytest
import requests
from bs4 import BeautifulSoup

from fixtures.client import csrf_token


@pytest.fixture
def login() -> Callable:
    """Helper function to login to the application over HTTP"""

    def factory(client: requests.Session):
        # Grab the index page which redirects to the login API
        response = client.get('/', allow_redirects=False)
        assert response.status_code == 302
        assert 'Location' in response.headers
        assert response.headers['Location'] == '/auth/login'

        # Get the login API to send you to Keycloak's auth form
        response = client.get('/auth/login', allow_redirects=False)
        assert response.status_code == 302
        assert 'Location' in response.headers
        auth_url = 'http://kc.local.kronus.network/realms/devel/protocol/openid-connect/auth?'
        assert response.headers['Location'].startswith(auth_url)

        # Get the authentication form using a separate Keycloak session
        with requests.Session() as idp_client:
            response = idp_client.get(response.headers['Location'])
            soup = BeautifulSoup(response.content, features="html.parser")
            idp_authenticate_endpoint = soup.find('form')['action']

            # Send the form data; Keycloak redirects back to the configured
            # callback on the VSM hostname, not on localhost.
            response = idp_client.post(
                idp_authenticate_endpoint, data={
                    "username": "testuser"}, allow_redirects=False)
            assert response.status_code == 302
            assert 'Location' in response.headers
            callback_url = response.headers['Location']
            assert callback_url.startswith(
                'http://vsm.local.kronus.network/auth/callback?')

        # Follow the callback against the locally running binary so the
        # session cookie is scoped to localhost.
        callback = urlsplit(callback_url)
        vsm = urlsplit(client.base_url)
        local_callback = urlunsplit(
            (vsm.scheme, vsm.netloc, callback.path, callback.query, callback.fragment))
        response = client.get(local_callback, allow_redirects=False)
        assert response.status_code == 302
        assert 'Location' in response.headers
        assert response.headers['Location'] == '/'

        # Finalize authentication with the portal; remember its CSRF token so
        # logout still works once the session has been expired.
        response = client.get('/')
        assert response.status_code == 200
        client.csrf_token = csrf_token(response)

    return factory
