"""Interop: the integration against a real quicharc agent binary.

The agent test is skipped unless QUICHARC_AGENT_BINARY points at an agent
build (for example one downloaded from {api}/agent/<version>/ and verified).
The quicharc service is mocked as in test_init; the agent's edge connections
fail harmlessly because the mocked edges don't exist, and its telemetry goes
to a local sink, never to ot.ezlo.com.
"""

from __future__ import annotations

import asyncio
import base64
from collections.abc import AsyncIterator
import hashlib
import ipaddress
import os
from pathlib import Path
import struct
import time
from unittest.mock import AsyncMock, patch

from aiohttp import web
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest
from yarl import URL

from custom_components.quicharc.agent_binary import AgentBinary
from custom_components.quicharc.const import (
    CONF_ENVIRONMENT,
    CONF_EZLO_USER_UUID,
    CONF_HA_USER_ID,
    DOMAIN,
)
from homeassistant.core import HomeAssistant
from homeassistant.setup import async_setup_component

from .harness import AiohttpClientMocker, AiohttpClientMockResponse, MockConfigEntry
from .test_init import (  # mock_service is a fixture
    API,
    HOME_ID,
    OWNER,
    _grant,
    _home,
    _verify_proof,
    _wait_for,
    mock_service,  # noqa: F401
)

AGENT = os.environ.get("QUICHARC_AGENT_BINARY")

requires_agent = pytest.mark.skipif(not AGENT, reason="QUICHARC_AGENT_BINARY not set")

# Where the agent sends its OpenTelemetry (default https://ot.ezlo.com).
TELEMETRY_ENDPOINT_ENV = "QUICHARC_OTEL_ENDPOINT"

GRANT_KEY = Ed25519PrivateKey.generate()
GRANT_KID = "test-1"


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _cbor_head(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([major << 5 | n])
    for info, fmt in ((24, ">B"), (25, ">H"), (26, ">I"), (27, ">Q")):
        if n < 1 << (8 * struct.calcsize(fmt)):
            return bytes([major << 5 | info]) + struct.pack(fmt, n)
    raise ValueError(n)


def _cbor(value) -> bytes:
    """Deterministic CBOR for the types a grant uses."""
    if isinstance(value, int):
        return _cbor_head(0, value)
    if isinstance(value, bytes):
        return _cbor_head(2, len(value)) + value
    if isinstance(value, str):
        raw = value.encode()
        return _cbor_head(3, len(raw)) + raw
    if isinstance(value, list):
        return _cbor_head(4, len(value)) + b"".join(_cbor(v) for v in value)
    if isinstance(value, dict):
        items = sorted(value.items())
        return _cbor_head(5, len(items)) + b"".join(
            _cbor(k) + _cbor(v) for k, v in items
        )
    raise TypeError(type(value))


def _home_grant(public_key_b64u: str) -> str:
    """A home grant in cloud/pkg/quicharc/grant format, bound to this key."""
    point = base64.urlsafe_b64decode(
        public_key_b64u + "=" * (-len(public_key_b64u) % 4)
    )
    spki = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), point
    ).public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    fp = hashlib.sha256(spki).digest()
    now = int(time.time())
    payload = _cbor(
        {
            1: GRANT_KID,
            2: HOME_ID,
            3: fp,
            5: HOME_ID,
            6: fp,
            7: ["app"],
            8: now,
            9: now + 12 * 3600,
        }
    )
    sig = GRANT_KEY.sign(b"quicharc-grant/1\x00" + payload)
    return _b64u(_cbor([payload, sig]))


def _local_telemetry(env: dict[str, str], endpoint: str) -> dict[str, str]:
    """The agent's environment with its telemetry sent to a local sink.

    The integration always lets the agent send telemetry; a test agent
    serving a mocked home must not send it to Ezlo.
    """
    return {**env, TELEMETRY_ENDPOINT_ENV: endpoint}


def _reaches_ezlo(env: dict[str, str]) -> bool:
    """Whether an agent started with env could send telemetry off this host."""
    url = URL(env.get(TELEMETRY_ENDPOINT_ENV) or "https://ot.ezlo.com")
    if url.scheme not in ("http", "https") or not url.host:
        return True
    if url.host == "localhost":
        return False
    try:
        return not ipaddress.ip_address(url.host).is_loopback
    except ValueError:
        return True


@pytest.mark.parametrize(
    ("env", "reaches"),
    [
        ({}, True),
        ({TELEMETRY_ENDPOINT_ENV: ""}, True),
        ({TELEMETRY_ENDPOINT_ENV: "https://ot.ezlo.com"}, True),
        ({TELEMETRY_ENDPOINT_ENV: "https://sink.example.com"}, True),
        ({TELEMETRY_ENDPOINT_ENV: "http://127.0.0.1:9"}, False),
        ({TELEMETRY_ENDPOINT_ENV: "http://localhost:4318"}, False),
        ({TELEMETRY_ENDPOINT_ENV: "http://[::1]:9"}, False),
    ],
)
def test_reaches_ezlo(env: dict[str, str], reaches: bool) -> None:
    """The guard used on the real agent's environment."""
    assert _reaches_ezlo(env) is reaches


def test_local_telemetry_overrides_an_inherited_endpoint() -> None:
    """The sink wins over an endpoint Home Assistant's environment carries."""
    env = _local_telemetry(
        {TELEMETRY_ENDPOINT_ENV: "https://ot.ezlo.com", "PATH": "/bin"},
        "http://127.0.0.1:9",
    )
    assert not _reaches_ezlo(env)
    assert env["PATH"] == "/bin"


@pytest.fixture
async def telemetry_sink() -> AsyncIterator[tuple[str, list[str]]]:
    """A local OTLP ingest: its base URL and the paths posted to it."""
    paths: list[str] = []

    async def ingest(request: web.Request) -> web.Response:
        await request.read()
        paths.append(request.path)
        return web.Response()

    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", ingest)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    host, port = runner.addresses[0][:2]
    try:
        yield f"http://{host}:{port}", paths
    finally:
        await runner.cleanup()


@requires_agent
async def test_real_agent_registers_and_configures(
    hass: HomeAssistant,
    tmp_path: Path,
    unix_sockets,
    mock_service: AiohttpClientMocker,  # noqa: F811 - fixture from test_init
    hass_admin_user,
    mock_async_zeroconf,
    telemetry_sink: tuple[str, list[str]],
) -> None:
    """Handshake, home key, proofs the service would accept, config.set, state."""
    hass.config.config_dir = str(tmp_path)
    (tmp_path / "configuration.yaml").write_text("")
    entry = MockConfigEntry(
        domain=DOMAIN,
        unique_id=OWNER,
        data={
            "auth_implementation": f"{DOMAIN}_stg",
            "token": {
                "access_token": "ezlo-access",
                "refresh_token": "ezlo-refresh",
                "expires_at": time.time() + 3600,
                "expires_in": 3600,
            },
            CONF_ENVIRONMENT: "stg",
            CONF_EZLO_USER_UUID: OWNER,
            CONF_HA_USER_ID: hass_admin_user.id,
        },
        options={"web_access": False, "auto_approve_owner": True},
        minor_version=2,
    )
    entry.add_to_hass(hass)

    async def issue_grant(method, url, data):
        register = next(
            c
            for c in mock_service.mock_calls
            if c[0] == "POST" and str(c[1]).endswith("/homes")
        )
        body = _grant()
        body["grant"] = _home_grant(register[2]["public_key"])
        body["grant_keys"] = {
            "keys": [
                {
                    "kid": GRANT_KID,
                    "alg": "Ed25519",
                    "public_key": _b64u(
                        GRANT_KEY.public_key().public_bytes(
                            serialization.Encoding.Raw, serialization.PublicFormat.Raw
                        )
                    ),
                    "status": "current",
                }
            ]
        }
        return AiohttpClientMockResponse(method, url, json=body)

    # Replace the fixture's static grant with one minted for the agent's key.
    mock_service.clear_requests()
    mock_service.post(f"{API}/homes", status=201, json={**_home(), "edges": []})
    mock_service.post(f"{API}/homes/{HOME_ID}/grant", side_effect=issue_grant)
    mock_service.get(
        f"{API}/homes/{HOME_ID}/devices?state=pending", json={"pairings": []}
    )
    mock_service.get(f"{API}/homes/{HOME_ID}/enrollments", json={"enrollments": []})
    assert await async_setup_component(hass, "web_rtc", {})
    sink, sink_paths = telemetry_sink
    start_process = asyncio.create_subprocess_exec
    launched: list[dict[str, str]] = []

    async def quiet_agent(*args, env, **kwargs):
        env = _local_telemetry(env, sink)
        launched.append(env)
        return await start_process(*args, env=env, **kwargs)

    with (
        patch.object(AgentBinary, "async_ensure", AsyncMock(return_value=Path(AGENT))),
        patch.object(asyncio, "create_subprocess_exec", quiet_agent),
    ):
        assert await hass.config_entries.async_setup(entry.entry_id)
        runtime = entry.runtime_data
        await _wait_for(lambda: runtime.home_config is not None, timeout=20)
        await hass.async_block_till_done()

        assert runtime.supervisor.connected
        assert runtime.supervisor.agent_version
        assert entry.data["home_id"] == HOME_ID

        calls = mock_service.mock_calls
        register = next(
            c for c in calls if c[0] == "POST" and str(c[1]).endswith("/homes")
        )
        public_key = register[2]["public_key"]
        assert public_key == runtime.home_public_key
        _verify_proof(register[2], "register-home", "-", public_key)
        grant = next(c for c in calls if str(c[1]).endswith("/grant"))
        _verify_proof(grant[2], "home-grant", HOME_ID, public_key)

        # The agent took the configuration and reported its LAN port.
        assert runtime.last_refresh_error is None
        await _wait_for(lambda: runtime.lan.advertised is not None)
        assert runtime.lan.advertised.port == (runtime.state.lan_port or 4433)

        # The agent knows identity.reclaim (the identity conflict repair's
        # "Use this installation"); with no conflict there's nothing to take.
        assert not runtime.state.identity_conflict
        assert await runtime.async_reclaim_identity() is False

        # The home key survives an agent restart.
        first_key = runtime.home_public_key
        await hass.config_entries.async_reload(entry.entry_id)
        await hass.async_block_till_done()
        runtime = entry.runtime_data
        await _wait_for(lambda: runtime.home_public_key is not None, timeout=20)
        assert runtime.home_public_key == first_key

        # The agents this test started sent their telemetry to the sink (log
        # records at least; this mocked home finishes few spans).
        await _wait_for(lambda: bool(sink_paths), timeout=20)
        assert set(sink_paths) <= {"/traces", "/logs", "/metrics"}
        assert len(launched) == 2
        assert not any(_reaches_ezlo(env) for env in launched)

        assert await hass.config_entries.async_unload(entry.entry_id)
        await hass.async_block_till_done()
        assert runtime.supervisor.pid is None
