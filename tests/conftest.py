"""Shared fixtures."""

from __future__ import annotations

from collections.abc import Generator
from pathlib import Path
import shutil
import socket

import pytest
import pytest_socket

from .harness import PYTEST_PLUGINS

pytest_plugins = PYTEST_PLUGINS

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(
    enable_custom_integrations, mock_async_zeroconf
) -> Generator[None]:
    """Load custom_components/ in every test, with zeroconf mocked."""
    yield


@pytest.fixture
def http_fixture(tmp_path: Path):
    """Copy a configuration fixture into a temporary config directory."""

    def _copy(name: str) -> Path:
        target = tmp_path / name
        shutil.copytree(FIXTURES / "http" / name, target)
        return target

    return _copy


@pytest.fixture
def unix_sockets(monkeypatch: pytest.MonkeyPatch, socket_enabled) -> None:
    """Allow connecting to the agent's Unix socket.

    The Home Assistant test plugin only allows TCP connections to 127.0.0.1.
    """
    real_connect = pytest_socket._true_connect
    guarded = socket.socket.connect

    def connect(sock: socket.socket, address, *args):
        if sock.family == socket.AF_UNIX:
            return real_connect(sock, address, *args)
        return guarded(sock, address, *args)

    monkeypatch.setattr(socket.socket, "connect", connect)
