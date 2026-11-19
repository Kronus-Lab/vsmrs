"""Logout fixture to delete the current session for the tests"""

from collections.abc import Callable

import pytest
import requests

from fixtures.client import csrf_token


@pytest.fixture
def logout() -> Callable:
    """Helper function to log out after we are done with the application"""

    def factory(client: requests.Session):
        # The token is seeded per session and rendered into the logout form.
        response = client.get('/', allow_redirects=False)
        if response.status_code == 200:
            token = csrf_token(response)
            client.csrf_token = token
        else:
            # An expired session can no longer render the portal, but the
            # token read at login is still the one its cache record expects.
            token = getattr(client, 'csrf_token', None)
        assert token is not None, 'no CSRF token available for logout'

        response = client.post(
            '/auth/logout', data={'csrf_token': token}, allow_redirects=False)
        assert response.status_code == 302
        assert 'Location' in response.headers
        assert response.headers['Location'] == '/'

    return factory
