"""Tests for the agent socket client, binary verification and supervisor."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
from pathlib import Path
import sys
from unittest.mock import AsyncMock, patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import pytest

from custom_components.quicharc import agent as agent_module
from custom_components.quicharc.agent import AgentSupervisor
from custom_components.quicharc.agent_binary import (
    AGENT_SIGNING_KEY,
    AgentBinary,
    NoAgentPinned,
    UnsupportedArchitecture,
    VerificationFailed,
    agent_arch,
    verify,
)
from custom_components.quicharc.agent_client import (
    AgentClient,
    AgentConnectionError,
    AgentRequestError,
)
from custom_components.quicharc.otel import async_get_telemetry
from custom_components.quicharc.otel.metrics import AGENT_RESTARTS
from homeassistant.core import HomeAssistant

from .harness import AiohttpClientMocker

FAKE_AGENT = Path(__file__).parent / "fake_agent.py"


async def _auth() -> str:
    return "user-token"


def _fake_agent_wrapper(tmp_path: Path) -> Path:
    """Return an executable that runs the fake agent with this interpreter."""
    wrapper = tmp_path / "quicharc-agent"
    wrapper.write_text(f'#!/bin/sh\nexec {sys.executable} {FAKE_AGENT} "$@"\n')
    wrapper.chmod(0o700)
    return wrapper


async def _start_fake(tmp_path: Path) -> tuple[asyncio.subprocess.Process, Path]:
    sock = tmp_path / "agent.sock"
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        str(FAKE_AGENT),
        "--socket",
        str(sock),
        "--data-dir",
        str(tmp_path),
    )
    for _ in range(100):
        if sock.exists():
            break
        await asyncio.sleep(0.05)
    return process, sock


async def test_client_handshake_requests_and_events(
    tmp_path: Path, unix_sockets
) -> None:
    """Hello, a request, an event and an error all round-trip."""
    process, sock = await _start_fake(tmp_path)
    events: list[tuple[str, dict]] = []
    client = AgentClient(str(sock), lambda e, d: events.append((e, d)))
    try:
        await client.async_connect()
        assert client.protocol == 1
        assert client.agent_version == "0.0.0-fake"
        key = await client.async_request("home_key.get")
        point = base64.urlsafe_b64decode(
            key["public_key"] + "=" * (-len(key["public_key"]) % 4)
        )
        assert len(point) == 65 and point[0] == 4
        with pytest.raises(AgentRequestError) as refused:
            await client.async_request(
                "home_key.proof",
                {"purpose": "anything", "caller": "u", "key_id": "-", "ts": 1},
            )
        assert refused.value.code == "bad_request"
        await client.async_request(
            "test.emit", {"event": "log", "data": {"message": "hi"}}
        )
        await asyncio.sleep(0.05)
        assert ("log", {"message": "hi"}) in events
        assert events[0][0] == "state"
        with pytest.raises(AgentRequestError) as err:
            await client.async_request("nope")
        assert err.value.code == "unknown_method"
        await client.async_request("shutdown")
        await asyncio.wait_for(client.closed.wait(), 5)
        with pytest.raises(AgentConnectionError):
            await client.async_request("status.get")
    finally:
        await client.async_close()
        await process.wait()


async def test_client_no_socket(tmp_path: Path, unix_sockets) -> None:
    """Connecting to a missing socket is a connection error."""
    client = AgentClient(str(tmp_path / "missing.sock"), lambda e, d: None)
    with pytest.raises(AgentConnectionError):
        await client.async_connect()


def _signed(data: bytes) -> tuple[bytes, str, str]:
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return (
        key.sign(data),
        hashlib.sha256(data).hexdigest(),
        base64.b64encode(public).decode(),
    )


def test_verify() -> None:
    """A matching hash and signature pass; any mismatch fails."""
    data = b"agent binary"
    signature, digest, public = _signed(data)
    verify(data, signature, digest, public)
    with pytest.raises(VerificationFailed, match="SHA-256"):
        verify(data + b"x", signature, digest, public)
    with pytest.raises(VerificationFailed, match="signature"):
        verify(data, b"\0" * 64, digest, public)
    _, _, other_key = _signed(data)
    with pytest.raises(VerificationFailed, match="signature"):
        verify(data, signature, digest, other_key)


def test_arch() -> None:
    """Only 64-bit x86 and ARM are supported."""
    assert agent_arch("x86_64") == "amd64"
    assert agent_arch("aarch64") == "arm64"
    with pytest.raises(UnsupportedArchitecture):
        agent_arch("armv7l")


async def test_download_verify_install(
    hass: HomeAssistant, tmp_path: Path, aioclient_mock: AiohttpClientMocker
) -> None:
    """The binary is downloaded once, verified, installed and re-checked."""
    data = b"#!/bin/sh\necho agent\n"
    signature, digest, public = _signed(data)
    base = "https://releases.example.com/agent"
    arch = agent_arch()
    url = f"{base}/1.2.3/quicharc-agent-linux-{arch}"
    aioclient_mock.get(url, content=data)
    aioclient_mock.get(f"{url}.sig", content=signature)
    binary = AgentBinary(
        hass,
        tmp_path,
        version="1.2.3",
        base_url=base,
        auth=_auth,
        hashes={arch: digest},
        signing_key=public,
    )
    path = await binary.async_ensure()
    assert path.read_bytes() == data
    # The service's agent route needs the signed-in user's token.
    assert aioclient_mock.mock_calls[0][3]["Authorization"] == "Bearer user-token"
    assert path.stat().st_mode & 0o777 == 0o700
    assert aioclient_mock.call_count == 2
    await binary.async_ensure()
    assert aioclient_mock.call_count == 2

    # Tampered on disk: deleted and downloaded again.
    path.write_bytes(b"evil")
    await binary.async_ensure()
    assert aioclient_mock.call_count == 4
    assert path.read_bytes() == data


async def test_no_agent_pinned(hass: HomeAssistant, tmp_path: Path) -> None:
    """Until a release pins an agent, starting it is a clear error."""
    binary = AgentBinary(
        hass, tmp_path, base_url="https://unused", auth=_auth, version=None
    )
    with pytest.raises(NoAgentPinned):
        await binary.async_ensure()


def test_embedded_signing_key_is_quicharcs() -> None:
    """The embedded key is quicharc's release/agent-signing-key.pub."""
    assert AGENT_SIGNING_KEY == "3apvG1OHZlTWRim/+jsycoa/TdtjVvZtwo/1aBgXkBs="
    assert len(base64.b64decode(AGENT_SIGNING_KEY)) == 32


async def test_download_rejects_bad_signature(
    hass: HomeAssistant, tmp_path: Path, aioclient_mock: AiohttpClientMocker
) -> None:
    """A binary with a bad signature is never installed."""
    data = b"binary"
    _, digest, public = _signed(data)
    arch = agent_arch()
    url = f"https://r.example.com/1/quicharc-agent-linux-{arch}"
    aioclient_mock.get(url, content=data)
    aioclient_mock.get(f"{url}.sig", content=b"\0" * 64)
    binary = AgentBinary(
        hass,
        tmp_path,
        version="1",
        base_url="https://r.example.com",
        auth=_auth,
        hashes={arch: digest},
        signing_key=public,
    )
    with pytest.raises(VerificationFailed):
        await binary.async_ensure()
    assert not binary.path.exists()


async def test_supervisor_restarts_crashed_agent(
    hass: HomeAssistant, tmp_path: Path, unix_sockets
) -> None:
    """A crashed agent is restarted and reconnected; stop shuts it down."""
    binary = AgentBinary(hass, tmp_path, base_url="https://unused", auth=_auth)
    connected = asyncio.Event()
    connections = 0

    async def on_connected() -> None:
        nonlocal connections
        connections += 1
        connected.set()

    with (
        patch.object(
            binary,
            "async_ensure",
            AsyncMock(return_value=_fake_agent_wrapper(tmp_path)),
        ),
        patch.object(agent_module, "BACKOFF_INITIAL", 0.05),
    ):
        telemetry = await async_get_telemetry(hass)
        supervisor = AgentSupervisor(
            hass,
            tmp_path / "data",
            binary,
            telemetry=telemetry,
            on_event=lambda e, d: None,
            on_connected=on_connected,
            on_failure=lambda err: None,
            on_recovered=lambda: None,
            on_disconnected=lambda: None,
        )
        supervisor.start()
        await asyncio.wait_for(connected.wait(), 10)
        first_pid = supervisor.pid
        assert supervisor.connected
        assert (tmp_path / "data").stat().st_mode & 0o777 == 0o700

        connected.clear()
        with pytest.raises(AgentConnectionError):
            await supervisor.async_request("test.crash")
        await asyncio.wait_for(connected.wait(), 10)
        assert connections == 2
        assert supervisor.pid != first_pid
        assert telemetry.metrics.counter_value(AGENT_RESTARTS, reason="exited") == 1

        await supervisor.async_stop()
        assert not supervisor.connected
        assert supervisor.pid is None
    requests = [
        json.loads(line)["method"]
        for line in (tmp_path / "data" / "requests.jsonl").read_text().splitlines()
    ]
    assert requests[-1] == "shutdown"


async def test_socket_outside_the_data_dir(
    hass: HomeAssistant,
    tmp_path: Path,
    unix_sockets,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The socket is in a private temp directory, new for each start, removed on stop.

    /config can be a host share (Docker on macOS) where a Unix socket can't be
    created or chmodded, and where chmod on the data directory fails too.
    """
    import tempfile

    binary = AgentBinary(hass, tmp_path, base_url="https://unused", auth=_auth)
    connected = asyncio.Event()
    data_dir = tmp_path / "data"
    # An earlier version's socket file, left in the data directory.
    data_dir.mkdir()
    (data_dir / "agent.sock").write_text("")
    real_chmod = Path.chmod

    async def on_connected() -> None:
        connected.set()

    def refusing_chmod(path: Path, mode: int, **kwargs) -> None:
        if path == data_dir:
            raise OSError(22, "Invalid argument")
        real_chmod(path, mode, **kwargs)

    with (
        patch.object(
            binary,
            "async_ensure",
            AsyncMock(return_value=_fake_agent_wrapper(tmp_path)),
        ),
        patch.object(agent_module, "BACKOFF_INITIAL", 0.05),
        patch.object(Path, "chmod", refusing_chmod),
    ):
        supervisor = AgentSupervisor(
            hass,
            data_dir,
            binary,
            telemetry=await async_get_telemetry(hass),
            on_event=lambda e, d: None,
            on_connected=on_connected,
            on_failure=lambda err: None,
            on_recovered=lambda: None,
            on_disconnected=lambda: None,
        )
        supervisor.start()
        await asyncio.wait_for(connected.wait(), 10)
        socket_path = supervisor.socket_path
        socket_dir = socket_path.parent
        assert socket_path.is_socket()
        assert data_dir not in socket_path.parents
        assert not (data_dir / "agent.sock").exists()
        assert socket_dir.parent == Path(tempfile.gettempdir())
        assert socket_dir.stat().st_mode & 0o777 == 0o700
        assert "Can't restrict" in caplog.text

        connected.clear()
        with pytest.raises(AgentConnectionError):
            await supervisor.async_request("test.crash")
        await asyncio.wait_for(connected.wait(), 10)
        assert supervisor.socket_path != socket_path
        assert supervisor.socket_path.is_socket()
        assert not socket_dir.exists()
        socket_dir = supervisor.socket_path.parent

        await supervisor.async_stop()
    assert not socket_dir.exists()


def test_socket_dir_prefers_xdg_runtime_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """XDG_RUNTIME_DIR when set; the directory is private."""
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
    socket_dir = agent_module._make_socket_dir()
    assert socket_dir.parent == tmp_path
    assert socket_dir.name.startswith("quicharc-")
    assert socket_dir.stat().st_mode & 0o777 == 0o700


def test_socket_dir_falls_back_to_tmp_when_too_long(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A base too long for a Unix socket path falls back to /tmp."""
    deep = tmp_path / ("d" * 120)
    deep.mkdir()
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(deep))
    socket_dir = agent_module._make_socket_dir()
    try:
        assert socket_dir.parent == Path("/tmp")
        assert len(str(socket_dir / "agent.sock")) <= agent_module.MAX_SOCKET_PATH
        assert not any(deep.iterdir())
    finally:
        socket_dir.rmdir()
