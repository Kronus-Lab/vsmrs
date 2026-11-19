"""Client fixture for pytest to access the application over http"""

import os

import pytest
import requests
from bs4 import BeautifulSoup


class BaseUrlSession(requests.Session):
    """A requests session that resolves relative URLs against the VSM base URL."""

    def __init__(self, base_url):
        super().__init__()
        self.base_url = base_url.rstrip('/')

    def request(self, method, url, *args, **kwargs):
        if not url.startswith(('http://', 'https://')):
            url = self.base_url + url
        return super().request(method, url, *args, **kwargs)


def csrf_token(response):
    """Read the session-scoped CSRF token from a rendered portal page."""

    field = BeautifulSoup(response.text, features="html.parser").find(
        'input', {'name': 'csrf_token'})
    assert field is not None, 'portal page has no csrf_token field'
    return field['value']


@pytest.fixture
def client() -> requests.Session:
    """HTTP client for the running VSM binary."""

    with BaseUrlSession(
            os.environ.get('VSM_BASE_URL', 'http://localhost:3000')) as session:
        yield session
