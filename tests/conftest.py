"""Shared test configuration.

Constitution V: the default test run makes no network calls. Every test not marked ``live`` runs
with socket connections and name resolution blocked, so an accidental network call fails loudly.
"""

from __future__ import annotations

import socket

import pytest


class NetworkBlockedError(RuntimeError):
    """Raised when a test not marked ``live`` tries to use the network."""


def _blocked(*args: object, **kwargs: object) -> None:
    raise NetworkBlockedError(
        "network access is blocked in tests; mark the test 'live' if it needs a real source"
    )


@pytest.fixture(autouse=True)
def _block_network(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    if request.node.get_closest_marker("live") is not None:
        return
    monkeypatch.setattr(socket.socket, "connect", _blocked)
    monkeypatch.setattr(socket.socket, "connect_ex", _blocked)
    monkeypatch.setattr(socket, "create_connection", _blocked)
    monkeypatch.setattr(socket, "getaddrinfo", _blocked)
