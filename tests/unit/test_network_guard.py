"""The autouse guard in conftest.py blocks network access in the default run."""

import socket
import urllib.request

import pytest

from conftest import NetworkBlockedError


def test_socket_connect_is_blocked() -> None:
    with (
        socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock,
        pytest.raises(NetworkBlockedError),
    ):
        sock.connect(("127.0.0.1", 9))


def test_urlopen_is_blocked() -> None:
    with pytest.raises(NetworkBlockedError):
        urllib.request.urlopen("http://example.invalid/", timeout=1)


def test_name_resolution_is_blocked() -> None:
    with pytest.raises(NetworkBlockedError):
        socket.getaddrinfo("example.invalid", 80)
