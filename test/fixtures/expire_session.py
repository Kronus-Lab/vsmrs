"""Expire Session fixture to expire active session from the cache"""

import json
import time
from collections.abc import Callable
from urllib.parse import unquote

import pytest
import redis
import requests


@pytest.fixture
def expire_session() -> Callable:
    """Helper function to expire an active session"""

    def factory(client: requests.Session):
        # The signed cookie is a 44-char base64 HMAC digest followed by the
        # opaque 32-char session UUID. That UUID is the Redis key itself; it is
        # not a base64-encoded JSON document. The cookie is transported
        # percent-encoded (its base64 '=' padding arrives as '%3D'), so decode
        # it before slicing off the digest.
        signed_value = unquote(client.cookies.get('session')).split('.')[0]
        uuid = signed_value[44:]
        assert len(uuid) == 32 and all(c in '0123456789abcdef' for c in uuid)

        # Connect to the cache server
        rcon = redis.Redis(host='localhost', port=6379, db=0)

        # Expire the current token
        token = json.loads(rcon.get(uuid))
        token['expires_at'] = int(time.time())

        # Save the expired token to the cache. Plain SET clears the outer TTL,
        # so only read-time expiry can reject the session.
        rcon.set(uuid, json.dumps(token))

    return factory
