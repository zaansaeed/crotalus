"""The HTTP client crotalus makes every request with.

`client` is created once per process and shared: it reuses connections instead of
opening a new one (and a new TLS handshake) per request, and keeps the User-Agent,
timeouts and redirect handling in one place. Use it as `http_client.client.get(...)`
(not `from crotalus.http_client import client`) so tests can replace it: see the
`no_network` and `fake_pypi` fixtures in tests/conftest.py.
"""

from __future__ import annotations

import httpx

from crotalus import __version__

# PyPI asks API clients to identify themselves.
USER_AGENT = f"crotalus/{__version__} (+https://github.com/zaansaeed/crotalus)"


def make_client(transport: httpx.BaseTransport | None = None) -> httpx.Client:
    """`transport` is for tests: an httpx.MockTransport answers without a network."""
    return httpx.Client(
        headers={"User-Agent": USER_AGENT},
        # connect: reaching the server. read: the gap between chunks of a response,
        # so a slow download is fine as long as data keeps coming.
        timeout=httpx.Timeout(10.0, connect=5.0),
        # PyPI redirects non-canonical project names to the canonical URL.
        follow_redirects=True,
        transport=transport,
    )


client = make_client()
