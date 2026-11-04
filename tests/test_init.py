"""End-to-end: setup with the fake agent and a mocked quicharc service."""

from __future__ import annotations

import asyncio
import base64
from datetime import timedelta
import json
import logging
from pathlib import Path
import time
from unittest.mock import AsyncMock, patch

import pytest

from custom_components.quicharc.agent_binary import AgentBinary
from custom_components.quicharc.agent_client import AgentRequestError
from custom_components.quicharc.const import (
    CONF_ENVIRONMENT,
    CONF_EZLO_USER_UUID,
    CONF_HA_USER_ID,
    DOMAIN,
    ENVIRONMENTS,
    EVENT_NOTIFICATION,
    IOS_CLIENT_ID,
    ISSUE_CLOCK_SKEW,
    ISSUE_IDENTITY_CONFLICT,
    ISSUE_SUBSCRIPTION_LAPSED,
    ISSUE_SUBSCRIPTION_REQUIRED,
)
from homeassistant.components.web_rtc import async_get_ice_servers
from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import HomeAssistant
from homeassistant.helpers import issue_registry as ir
from homeassistant.setup import async_setup_component
from homeassistant.util import dt as dt_util

from .harness import (
    AiohttpClientMocker,
    MockConfigEntry,
    async_capture_events,
    async_mock_service,
)
from .test_agent import _fake_agent_wrapper

API = ENVIRONMENTS["stg"].api_base
OWNER = "7f9c1c3e-0000-4000-8000-000000000001"
HOME_ID = "abcdefghijklmnop"


def _home(web_access: bool = False) -> dict:
    return {
        "id": HOME_ID,
        "hostname": f"{HOME_ID}.remote.example.com",
        "name": "Home",
        "owner_user_uuid": OWNER,
        "location_uuid": "loc-1",
        "key_fingerprint": "fp",
        "web_access": web_access,
        "created_at": "2026-10-25T00:00:00Z",
    }


def _grant(web_access: bool = False) -> dict:
    """A HomeGrantResponse, as in the quicharc OpenAPI document."""
    now = dt_util.utcnow()
    return {
        "grant": "grant-bytes",
        "scopes": ["app"],
        "expires_at": (now + timedelta(hours=12)).isoformat(),
        "refresh_after": (now + timedelta(hours=6)).isoformat(),
        "grant_keys": {
            "keys": [
                {
                    "kid": "k1",
                    "alg": "Ed25519",
                    "public_key": "AAAA",
                    "status": "current",
                }
            ]
        },
        "home": _home(web_access),
        "edges": [
            {
                "id": "gcp-us-west1",
                "agent_endpoints": [
                    {
                        "node_id": "gcp-us-west1-a",
                        "quic": "agent-a.remote.example.com:443",
                        "tcp": "agent-a.remote.example.com:443",
                        "key_fingerprint": "edge-node-key-fingerprint",
                    }
                ],
                "signal_url": "wss://signal.remote.example.com/v1",
            }
        ],
        "ice_servers": [
            {"urls": ["stun:stun.remote.example.com:3478"]},
            {
                "urls": ["turn:turn.remote.example.com:3478"],
                "username": "u",
                "credential": "c",
            },
        ],
        "revocations": [],
    }


def proof_message(
    purpose: str, caller: str, key_id: str, public_key: str, ts: int
) -> bytes:
    """The quicharc-proof-v1 message (quicharc OpenAPI: Proof)."""
    return "\n".join(
        ["quicharc-proof-v1", purpose, caller, key_id, public_key, str(ts)]
    ).encode()


def _verify_proof(body: dict, purpose: str, key_id: str, public_key: str) -> None:
    """Check a proof the way the quicharc service does."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    def unb64(text: str) -> bytes:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))

    key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), unb64(public_key)
    )
    message = proof_message(purpose, OWNER, key_id, public_key, body["proof_ts"])
    key.verify(unb64(body["proof"]), message, ec.ECDSA(hashes.SHA256()))
    assert abs(body["proof_ts"] - time.time()) < 60


def _requests(data_dir: Path) -> list[dict]:
    log = data_dir / "requests.jsonl"
    if not log.exists():
        return []
    return [json.loads(line) for line in log.read_text().splitlines()]


async def _wait_for(predicate, timeout: float = 10) -> None:
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() > deadline:
            raise AssertionError("condition not met in time")
        await asyncio.sleep(0.05)


@pytest.fixture
def mock_service(aioclient_mock: AiohttpClientMocker) -> AiohttpClientMocker:
    """Mock the quicharc service."""
    aioclient_mock.post(f"{API}/homes", status=201, json={**_home(), "edges": []})
    aioclient_mock.post(f"{API}/homes/{HOME_ID}/grant", json=_grant())
    aioclient_mock.get(
        f"{API}/homes/{HOME_ID}/devices?state=pending", json={"pairings": []}
    )
    aioclient_mock.patch(f"{API}/homes/{HOME_ID}", json=_home(web_access=True))
    aioclient_mock.put(f"{API}/homes/{HOME_ID}/devices/dev-1", json={})
    aioclient_mock.delete(f"{API}/homes/{HOME_ID}/devices/dev-1", status=204)
    aioclient_mock.get(f"{API}/homes/{HOME_ID}/enrollments", json={"enrollments": []})
    return aioclient_mock


@pytest.fixture
def entry_options() -> dict:
    """The test entry's options; parametrize to change them."""
    return {"web_access": False, "auto_approve_owner": True}


@pytest.fixture
def entry_minor_version() -> int:
    """The test entry's config entry minor version; parametrize for old entries."""
    return 2


@pytest.fixture
async def setup_entry(
    hass: HomeAssistant,
    tmp_path: Path,
    unix_sockets,
    mock_service,
    hass_admin_user,
    entry_options,
    entry_minor_version,
):
    """Set up the integration against the fake agent."""
    hass.config.config_dir = str(tmp_path)
    (tmp_path / "configuration.yaml").write_text(
        "http:\n  use_x_forwarded_for: true\n  trusted_proxies:\n    - 127.0.0.1\n    - ::1\n"
    )
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
        options=entry_options,
        minor_version=entry_minor_version,
    )
    entry.add_to_hass(hass)
    wrapper = _fake_agent_wrapper(tmp_path)
    assert await async_setup_component(hass, "web_rtc", {})
    with patch.object(AgentBinary, "async_ensure", AsyncMock(return_value=wrapper)):
        assert await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()
        runtime = entry.runtime_data
        await _wait_for(
            lambda: (
                runtime.home_config is not None and runtime.state.edge == "connected"
            )
        )
        await hass.async_block_till_done()
        yield entry
        if hass.config_entries.async_get_entry(entry.entry_id):
            await hass.config_entries.async_unload(entry.entry_id)
        await hass.async_block_till_done()


def _data_dir(hass: HomeAssistant) -> Path:
    return Path(hass.config.path(".quicharc"))


async def test_setup_registers_and_configures_agent(
    hass: HomeAssistant, setup_entry, mock_service
) -> None:
    """The home is registered and the agent gets the grant and edges."""
    entry = setup_entry
    assert entry.state is ConfigEntryState.LOADED
    assert entry.data["home_id"] == HOME_ID
    register = next(
        c
        for c in mock_service.mock_calls
        if c[0] == "POST" and str(c[1]).endswith("/homes")
    )
    body = register[2]
    assert register[3]["Authorization"] == "Bearer ezlo-access"
    assert body["name"] == hass.config.location_name
    assert body["ha_instance_id"]
    _verify_proof(body, "register-home", "-", body["public_key"])
    grant_call = next(
        c for c in mock_service.mock_calls if str(c[1]).endswith("/grant")
    )
    _verify_proof(grant_call[2], "home-grant", HOME_ID, body["public_key"])
    assert grant_call[2]["agent_version"] == "0.0.0-fake"

    config_set = [r for r in _requests(_data_dir(hass)) if r["method"] == "config.set"][
        -1
    ]
    params = config_set["params"]
    assert params["grant"] == "grant-bytes"
    assert (
        params["edges"][0]["agent_endpoints"][0]["quic"]
        == "agent-a.remote.example.com:443"
    )
    assert params["grant_keys"]["keys"][0]["kid"] == "k1"
    assert params["ice_servers"][1]["username"] == "u"
    assert params["revocations"] == []
    assert params["web_access"] is False
    assert params["ha_url"].startswith("http://127.0.0.1:")

    assert hass.states.get("sensor.quicharc_edge_connection").state == "connected"
    assert float(hass.states.get("sensor.quicharc_edge_round_trip_time").state) == 42.5
    assert hass.states.get("binary_sensor.quicharc_agent").state == "on"
    assert hass.states.get("binary_sensor.quicharc_real_client_ips").state == "on"
    assert hass.states.get("switch.quicharc_web_access").state == "off"
    assert hass.states.get("sensor.quicharc_active_path").state == "none"


async def test_ice_servers_registered(hass: HomeAssistant, setup_entry) -> None:
    """QuicHarc's TURN server is offered to WebRTC cameras."""
    urls = [url for server in async_get_ice_servers(hass) for url in server.urls]
    assert "turn:turn.remote.example.com:3478" in urls


def _cloudflare_ice(username: str) -> list[dict]:
    """ICE servers as Cloudflare Realtime TURN issues them: STUN without
    credentials, then TURN and TURNS on several ports and transports."""
    return [
        {"urls": ["stun:stun.cloudflare.com:3478", "stun:stun.cloudflare.com:53"]},
        {
            "urls": [
                "turn:turn.cloudflare.com:3478?transport=udp",
                "turn:turn.cloudflare.com:53?transport=udp",
                "turn:turn.cloudflare.com:3478?transport=tcp",
                "turn:turn.cloudflare.com:80?transport=tcp",
                "turns:turn.cloudflare.com:5349?transport=tcp",
                "turns:turn.cloudflare.com:443?transport=tcp",
            ],
            "username": username,
            "credential": f"{username}-credential",
        },
    ]


async def test_ice_servers_follow_the_grant(
    hass: HomeAssistant, setup_entry, mock_service
) -> None:
    """Whatever the grant carries goes to cameras and the agent, and a
    refreshed grant's credentials replace the old ones at once."""
    runtime = setup_entry.runtime_data
    for username in ("cf-1", "cf-2"):
        grant = _grant()
        grant["ice_servers"] = _cloudflare_ice(username)
        mock_service.clear_requests()
        mock_service.post(f"{API}/homes/{HOME_ID}/grant", json=grant)
        mock_service.get(
            f"{API}/homes/{HOME_ID}/devices?state=pending", json={"pairings": []}
        )
        mock_service.get(f"{API}/homes/{HOME_ID}/enrollments", json={"enrollments": []})
        # The scheduled refresh, at the grant's refresh_after.
        await runtime.async_refresh_config(dt_util.utcnow())
        await hass.async_block_till_done()

        ours = [
            server
            for server in async_get_ice_servers(hass)
            if any(
                "cloudflare" in url or "remote.example" in url for url in server.urls
            )
        ]
        assert [
            {"urls": s.urls, "username": s.username, "credential": s.credential}
            for s in ours
        ] == [
            {"username": None, "credential": None, **grant["ice_servers"][0]},
            grant["ice_servers"][1],
        ]
        config_set = [
            r for r in _requests(_data_dir(hass)) if r["method"] == "config.set"
        ][-1]
        assert config_set["params"]["ice_servers"] == grant["ice_servers"]


async def test_notify_fires_event(hass: HomeAssistant, setup_entry) -> None:
    """notify.quicharc fires quicharc_notification with title and message."""
    events = async_capture_events(hass, EVENT_NOTIFICATION)
    await _wait_for(lambda: hass.services.has_service("notify", DOMAIN))
    await hass.services.async_call(
        "notify",
        DOMAIN,
        {"title": "Door", "message": "Front door opened"},
        blocking=True,
    )
    assert len(events) == 1
    assert events[0].data == {"title": "Door", "message": "Front door opened"}


async def test_web_access_switch(
    hass: HomeAssistant, setup_entry, mock_service
) -> None:
    """Turning web access on calls the service and reconfigures the agent."""
    # After the PATCH the service issues grants with web access on.
    mock_service.clear_requests()
    mock_service.patch(f"{API}/homes/{HOME_ID}", json=_home(web_access=True))
    web_grant = _grant(web_access=True)
    web_grant["scopes"] = ["app", "web"]
    mock_service.post(f"{API}/homes/{HOME_ID}/grant", json=web_grant)
    mock_service.get(
        f"{API}/homes/{HOME_ID}/devices?state=pending", json={"pairings": []}
    )
    mock_service.get(f"{API}/homes/{HOME_ID}/enrollments", json={"enrollments": []})
    await hass.services.async_call(
        "switch", "turn_on", {"entity_id": "switch.quicharc_web_access"}, blocking=True
    )
    patch_call = next(c for c in mock_service.mock_calls if c[0] == "PATCH")
    assert patch_call[2] == {"web_access": True}
    # The grant is re-issued after the PATCH so its scopes include web.
    calls = [(c[0], str(c[1])) for c in mock_service.mock_calls]
    patch_at = calls.index(("PATCH", f"{API}/homes/{HOME_ID}"))
    assert ("POST", f"{API}/homes/{HOME_ID}/grant") in calls[patch_at:]
    assert hass.states.get("switch.quicharc_web_access").state == "on"
    config_set = [r for r in _requests(_data_dir(hass)) if r["method"] == "config.set"][
        -1
    ]
    assert config_set["params"]["web_access"] is True
    assert setup_entry.options["web_access"] is True


async def _emit(entry, event: str, data: dict) -> None:
    await entry.runtime_data.supervisor.async_request(
        "test.emit", {"event": event, "data": data}
    )


async def test_pairing_approved_through_repairs(
    hass: HomeAssistant, setup_entry, mock_service, hass_client, hass_admin_user
) -> None:
    """A stranger's device needs approval; approving mints a refresh token."""
    await _emit(
        setup_entry,
        "pairing_request",
        {
            "device_id": "dev-1",
            "device_name": "Alice's iPhone",
            "platform": "ios",
            "ezlo_user_uuid": "someone-else",
            "ezlo_user_email": "alice@example.com",
        },
    )
    await _wait_for(lambda: ir.async_get(hass).async_get_issue(DOMAIN, "pairing_dev-1"))
    assert await async_setup_component(hass, "repairs", {})
    client = await hass_client()
    resp = await client.post(
        "/api/repairs/issues/fix", json={"handler": DOMAIN, "issue_id": "pairing_dev-1"}
    )
    flow = await resp.json()
    assert flow["step_id"] == "init"
    resp = await client.post(
        f"/api/repairs/issues/fix/{flow['flow_id']}",
        json={"action": "approve", "ha_user_id": hass_admin_user.id},
    )
    assert (await resp.json())["type"] == "create_entry"

    approve = [
        r for r in _requests(_data_dir(hass)) if r["method"] == "device.approve"
    ][-1]
    token = approve["params"]["token"]
    assert token["kind"] == "refresh_token"
    assert token["client_id"] == IOS_CLIENT_ID
    refresh = hass.auth.async_get_refresh_token_by_token(token["refresh_token"])
    assert refresh is not None
    assert refresh.user.id == hass_admin_user.id
    assert refresh.client_id == IOS_CLIENT_ID
    assert ir.async_get(hass).async_get_issue(DOMAIN, "pairing_dev-1") is None
    report = next(c for c in mock_service.mock_calls if c[0] == "PUT")
    assert report[2] == {
        "state": "approved",
        "ha_user_id": hass_admin_user.id,
        "ha_user_name": hass_admin_user.name,
    }

    # Deleting the token in Home Assistant revokes the device everywhere.
    hass.auth.async_remove_refresh_token(refresh)
    await _wait_for(
        lambda: any(r["method"] == "device.revoke" for r in _requests(_data_dir(hass)))
    )
    await hass.async_block_till_done()
    assert any(c[0] == "DELETE" for c in mock_service.mock_calls)
    assert "dev-1" not in setup_entry.runtime_data.pairing.devices


async def test_owner_device_auto_approved(
    hass: HomeAssistant, setup_entry, hass_admin_user
) -> None:
    """The Ezlo account that set up QuicHarc pairs without asking."""
    await _emit(
        setup_entry,
        "pairing_request",
        {
            "device_id": "dev-1",
            "device_name": "Mine",
            "ezlo_user_uuid": OWNER,
        },
    )
    await _wait_for(lambda: "dev-1" in setup_entry.runtime_data.pairing.devices)
    assert (
        setup_entry.runtime_data.pairing.devices["dev-1"]["ha_user_id"]
        == hass_admin_user.id
    )
    assert ir.async_get(hass).async_get_issue(DOMAIN, "pairing_dev-1") is None


async def test_pairing_denied_by_service(
    hass: HomeAssistant, setup_entry, mock_service
) -> None:
    """quicharc.deny_device denies a pending request."""
    await _emit(
        setup_entry,
        "pairing_request",
        {"device_id": "dev-1", "ezlo_user_uuid": "x"},
    )
    await _wait_for(lambda: "dev-1" in setup_entry.runtime_data.pairing.pending)
    await hass.services.async_call(
        DOMAIN, "deny_device", {"device_id": "dev-1"}, blocking=True
    )
    assert any(r["method"] == "device.deny" for r in _requests(_data_dir(hass)))
    assert not setup_entry.runtime_data.pairing.pending


async def test_service_peer_token(
    hass: HomeAssistant, setup_entry, hass_admin_user
) -> None:
    """The enrolled cloud integration gets a working long-lived access token."""
    await _emit(
        setup_entry,
        "token_request",
        {
            "request_id": "t-1",
            "peer_id": "svc-1",
            "service": "integrations-homeassistant",
            "ezlo_user_uuid": OWNER,
        },
    )
    await _wait_for(
        lambda: any(
            r["method"] == "peer.send_token" for r in _requests(_data_dir(hass))
        )
    )
    sent = [r for r in _requests(_data_dir(hass)) if r["method"] == "peer.send_token"][
        -1
    ]
    token = sent["params"]["token"]
    assert token["kind"] == "access_token"
    refresh = hass.auth.async_validate_access_token(token["access_token"])
    assert refresh is not None
    assert refresh.user.id == hass_admin_user.id
    assert refresh.client_name.startswith("Ezlo cloud (QuicHarc ")

    # A second request replaces the first token instead of failing.
    await _emit(
        setup_entry,
        "token_request",
        {
            "request_id": "t-2",
            "peer_id": "svc-1",
            "service": "integrations-homeassistant",
            "ezlo_user_uuid": OWNER,
        },
    )
    await _wait_for(
        lambda: (
            len(
                [
                    r
                    for r in _requests(_data_dir(hass))
                    if r["method"] == "peer.send_token"
                ]
            )
            == 2
        )
    )
    # The old token is removed only after the new one is delivered.
    await _wait_for(
        lambda: hass.auth.async_validate_access_token(token["access_token"]) is None
    )


async def test_token_request_for_other_user_ignored(
    hass: HomeAssistant, setup_entry
) -> None:
    """A service asking on behalf of a different Ezlo user gets nothing."""
    await _emit(
        setup_entry,
        "token_request",
        {
            "request_id": "t-9",
            "service": "integrations-homeassistant",
            "ezlo_user_uuid": "intruder",
        },
    )
    await asyncio.sleep(0.2)
    await hass.async_block_till_done()
    sent = [r for r in _requests(_data_dir(hass)) if r["method"] == "peer.send_token"]
    assert len(sent) == 1
    assert sent[0]["params"]["error"] == "refused"
    assert "token" not in sent[0]["params"]


async def test_subscription_and_clock_issues(
    hass: HomeAssistant, setup_entry, mock_service: AiohttpClientMocker
) -> None:
    """403 not_entitled raises the subscription issue; a skewed Date raises clock skew."""
    mock_service.clear_requests()
    mock_service.post(
        f"{API}/homes/{HOME_ID}/grant",
        status=403,
        json={"error": "not_entitled"},
        headers={"Date": "Mon, 01 Jan 2024 00:00:00 GMT"},
    )
    await setup_entry.runtime_data.async_refresh_config()
    registry = ir.async_get(hass)
    # Without "entitlement" the service doesn't say it lapsed: needed, not lapsed.
    assert registry.async_get_issue(DOMAIN, ISSUE_SUBSCRIPTION_REQUIRED)
    assert registry.async_get_issue(DOMAIN, ISSUE_SUBSCRIPTION_LAPSED) is None
    assert registry.async_get_issue(DOMAIN, ISSUE_CLOCK_SKEW)


@pytest.mark.parametrize(
    ("body", "issue", "other", "url"),
    [
        (
            {"entitlement": "none", "subscribe_url": "https://ezlo.com/buy"},
            ISSUE_SUBSCRIPTION_REQUIRED,
            ISSUE_SUBSCRIPTION_LAPSED,
            "https://ezlo.com/buy",
        ),
        (
            {
                "entitlement": "lapsed",
                "subscribe_url": "https://ezlo.com/buy",
                "manage_url": "https://ezlo.com/manage",
            },
            ISSUE_SUBSCRIPTION_LAPSED,
            ISSUE_SUBSCRIPTION_REQUIRED,
            "https://ezlo.com/manage",
        ),
        # quicharc d1057bf passes billing's manage_url for "none" too; a
        # never-subscribed account still gets the subscribe link.
        (
            {
                "entitlement": "none",
                "manage_url": "https://ezlo.com/portal",
                "subscribe_url": "https://ezlo.com/subscribe",
            },
            ISSUE_SUBSCRIPTION_REQUIRED,
            ISSUE_SUBSCRIPTION_LAPSED,
            "https://ezlo.com/subscribe",
        ),
        # Only https links are shown; an unknown value isn't "lapsed".
        (
            {"entitlement": "gone", "subscribe_url": "javascript:alert(1)"},
            ISSUE_SUBSCRIPTION_REQUIRED,
            ISSUE_SUBSCRIPTION_LAPSED,
            None,
        ),
    ],
)
async def test_subscription_none_or_lapsed(
    hass: HomeAssistant,
    setup_entry,
    mock_service: AiohttpClientMocker,
    body: dict,
    issue: str,
    other: str,
    url: str | None,
) -> None:
    """Never had it and lost it are different issues, each with its own link."""
    registry = ir.async_get(hass)
    runtime = setup_entry.runtime_data
    # The other issue is open first: raising one replaces it.
    mock_service.clear_requests()
    flipped = {
        "entitlement": "none" if issue == ISSUE_SUBSCRIPTION_LAPSED else "lapsed"
    }
    mock_service.post(
        f"{API}/homes/{HOME_ID}/grant",
        status=403,
        json={"error": "not_entitled", **flipped},
    )
    await runtime.async_refresh_config()
    assert registry.async_get_issue(DOMAIN, other)

    mock_service.clear_requests()
    mock_service.post(
        f"{API}/homes/{HOME_ID}/grant",
        status=403,
        json={"error": "not_entitled", **body},
    )
    await runtime.async_refresh_config()
    raised = registry.async_get_issue(DOMAIN, issue)
    assert raised is not None
    assert raised.learn_more_url == url
    assert registry.async_get_issue(DOMAIN, other) is None

    # Once entitled, the next grant clears it.
    mock_service.clear_requests()
    mock_service.post(f"{API}/homes/{HOME_ID}/grant", json=_grant())
    mock_service.get(
        f"{API}/homes/{HOME_ID}/devices?state=pending", json={"pairings": []}
    )
    mock_service.get(f"{API}/homes/{HOME_ID}/enrollments", json={"enrollments": []})
    await runtime.async_refresh_config()
    assert runtime.last_refresh_error is None
    assert registry.async_get_issue(DOMAIN, issue) is None
    assert registry.async_get_issue(DOMAIN, other) is None


async def test_unload_shuts_agent_down(hass: HomeAssistant, setup_entry) -> None:
    """Unloading stops the agent cleanly."""
    supervisor = setup_entry.runtime_data.supervisor
    assert await hass.config_entries.async_unload(setup_entry.entry_id)
    await hass.async_block_till_done()
    assert _requests(_data_dir(hass))[-1]["method"] == "shutdown"
    assert supervisor.pid is None


async def test_diagnostics_redacts_secrets(hass: HomeAssistant, setup_entry) -> None:
    """Diagnostics hide tokens, grants and TURN credentials."""
    from custom_components.quicharc.diagnostics import (
        async_get_config_entry_diagnostics,
    )

    diag = await async_get_config_entry_diagnostics(hass, setup_entry)
    text = json.dumps(diag, default=str)
    assert "ezlo-access" not in text
    assert "grant-bytes" not in text
    assert '"credential": "c"' not in text
    assert diag["agent"]["connected"] is True


async def test_admin_only_services(
    hass: HomeAssistant, setup_entry, hass_read_only_user
) -> None:
    """A non-admin user can't approve devices (it would mint tokens for admins)."""
    from homeassistant.core import Context
    from homeassistant.exceptions import Unauthorized

    await _emit(
        setup_entry,
        "pairing_request",
        {"device_id": "dev-1", "ezlo_user_uuid": "x"},
    )
    await _wait_for(lambda: "dev-1" in setup_entry.runtime_data.pairing.pending)
    with pytest.raises(Unauthorized):
        await hass.services.async_call(
            DOMAIN,
            "approve_device",
            {"device_id": "dev-1"},
            blocking=True,
            context=Context(user_id=hass_read_only_user.id),
        )
    assert not any(r["method"] == "device.approve" for r in _requests(_data_dir(hass)))


async def test_auto_approve_failure_falls_back_to_asking(
    hass: HomeAssistant, setup_entry
) -> None:
    """If the owner's Home Assistant user is gone, the request is shown instead."""
    hass.config_entries.async_update_entry(
        setup_entry, data={**setup_entry.data, CONF_HA_USER_ID: "deleted-user"}
    )
    await _emit(
        setup_entry,
        "pairing_request",
        {"device_id": "dev-1", "ezlo_user_uuid": OWNER},
    )
    await _wait_for(lambda: ir.async_get(hass).async_get_issue(DOMAIN, "pairing_dev-1"))
    assert "dev-1" in setup_entry.runtime_data.pairing.pending


async def test_markdown_stripped_from_device_names(
    hass: HomeAssistant, setup_entry
) -> None:
    """A stranger can't put links into the repair issue or notification."""
    await _emit(
        setup_entry,
        "pairing_request",
        {
            "device_id": "dev-1",
            "device_name": "[Approve](https://evil.example)",
            "ezlo_user_uuid": "x",
        },
    )
    await _wait_for(lambda: ir.async_get(hass).async_get_issue(DOMAIN, "pairing_dev-1"))
    name = (
        ir.async_get(hass)
        .async_get_issue(DOMAIN, "pairing_dev-1")
        .translation_placeholders["device_name"]
    )
    assert "[" not in name and "(" not in name


async def test_unknown_service_gets_no_token(hass: HomeAssistant, setup_entry) -> None:
    """Only known service peers get tokens."""
    await _emit(
        setup_entry,
        "token_request",
        {"request_id": "t-5", "service": "something/else", "ezlo_user_uuid": OWNER},
    )
    await asyncio.sleep(0.2)
    await hass.async_block_till_done()
    sent = [r for r in _requests(_data_dir(hass)) if r["method"] == "peer.send_token"]
    assert len(sent) == 1
    assert sent[0]["params"]["error"] == "refused"
    assert "token" not in sent[0]["params"]


async def test_cloud_revocation_retried(
    hass: HomeAssistant, setup_entry, mock_service: AiohttpClientMocker
) -> None:
    """A revocation the cloud didn't take is kept and retried on reconnect."""
    mock_service.clear_requests()
    mock_service.delete(f"{API}/homes/{HOME_ID}/devices/dev-9", status=503)
    runtime = setup_entry.runtime_data
    await runtime.pairing.async_revoke("dev-9")
    assert runtime.data["revocations"]["dev-9"] == {"agent": False, "cloud": True}

    mock_service.clear_requests()
    mock_service.delete(f"{API}/homes/{HOME_ID}/devices/dev-9", status=204)
    await runtime.pairing.async_replay_revocations()
    assert "dev-9" not in runtime.data["revocations"]


async def test_remove_entry_deletes_tokens(
    hass: HomeAssistant, setup_entry, mock_service: AiohttpClientMocker
) -> None:
    """Removing the integration deletes every token it minted."""
    await _emit(
        setup_entry,
        "pairing_request",
        {"device_id": "dev-1", "ezlo_user_uuid": OWNER},
    )
    await _wait_for(lambda: "dev-1" in setup_entry.runtime_data.pairing.devices)
    token_id = setup_entry.runtime_data.pairing.devices["dev-1"]["refresh_token_id"]
    await setup_entry.runtime_data.store.async_save(setup_entry.runtime_data.data)
    mock_service.delete(f"{API}/homes/{HOME_ID}", status=204)
    assert await hass.config_entries.async_remove(setup_entry.entry_id)
    await hass.async_block_till_done()
    assert hass.auth.async_get_refresh_token(token_id) is None


async def test_grant_revocation_deletes_device_token(
    hass: HomeAssistant, setup_entry, mock_service: AiohttpClientMocker
) -> None:
    """A device revocation in the grant response deletes its Home Assistant token."""
    await _emit(
        setup_entry,
        "pairing_request",
        {"device_id": "dev-1", "device_name": "Mine", "ezlo_user_uuid": OWNER},
    )
    await _wait_for(lambda: "dev-1" in setup_entry.runtime_data.pairing.devices)
    token_id = setup_entry.runtime_data.pairing.devices["dev-1"]["refresh_token_id"]

    mock_service.clear_requests()
    grant = _grant()
    grant["revocations"] = [
        {
            "id": "r1",
            "type": "device",
            "home_id": HOME_ID,
            "subject": "dev-1",
            "revoked_at": "2026-10-25T00:00:00Z",
        }
    ]
    mock_service.post(f"{API}/homes/{HOME_ID}/grant", json=grant)
    mock_service.get(f"{API}/homes/{HOME_ID}/enrollments", json={"enrollments": []})
    mock_service.get(
        f"{API}/homes/{HOME_ID}/devices?state=pending", json={"pairings": []}
    )
    await setup_entry.runtime_data.async_refresh_config()
    assert "dev-1" not in setup_entry.runtime_data.pairing.devices
    assert hass.auth.async_get_refresh_token(token_id) is None
    config_set = [r for r in _requests(_data_dir(hass)) if r["method"] == "config.set"]
    assert config_set[-1]["params"]["revocations"][0]["subject"] == "dev-1"


async def test_polled_pending_pairing_is_shown(
    hass: HomeAssistant, setup_entry, mock_service: AiohttpClientMocker
) -> None:
    """A pairing the agent didn't report is picked up from the service."""
    mock_service.clear_requests()
    mock_service.post(f"{API}/homes/{HOME_ID}/grant", json=_grant())
    mock_service.get(f"{API}/homes/{HOME_ID}/enrollments", json={"enrollments": []})
    mock_service.get(
        f"{API}/homes/{HOME_ID}/devices?state=pending",
        json={
            "pairings": [
                {
                    "home_id": HOME_ID,
                    "device_id": "dev-2",
                    "device_name": "Bob's iPad",
                    "user_uuid": "someone-else",
                    "user_email": "bob@example.com",
                    "state": "pending",
                    "requested_at": "2026-10-25T00:00:00Z",
                }
            ]
        },
    )
    await setup_entry.runtime_data.async_refresh_config()
    issue = ir.async_get(hass).async_get_issue(DOMAIN, "pairing_dev-2")
    assert issue is not None
    assert issue.translation_placeholders["ezlo_user"] == "bob@example.com"


async def test_proof_clock_skew_raises_issue(
    hass: HomeAssistant, setup_entry, mock_service: AiohttpClientMocker
) -> None:
    """400 clock_skew from the service raises the clock issue."""
    mock_service.clear_requests()
    mock_service.post(
        f"{API}/homes/{HOME_ID}/grant", status=400, json={"error": "clock_skew"}
    )
    await setup_entry.runtime_data.async_refresh_config()
    assert ir.async_get(hass).async_get_issue(DOMAIN, ISSUE_CLOCK_SKEW)


async def test_device_sync_switch(
    hass: HomeAssistant, setup_entry, mock_service: AiohttpClientMocker
) -> None:
    """The switch enrolls the home with integrations-homeassistant and withdraws it."""
    assert hass.states.get("switch.quicharc_ezlo_device_sync").state == "off"
    mock_service.post(
        f"{API}/homes/{HOME_ID}/enrollments",
        status=201,
        json={"home_id": HOME_ID, "service_peer_id": "integrations-homeassistant"},
    )
    mock_service.delete(
        f"{API}/homes/{HOME_ID}/enrollments/integrations-homeassistant", status=204
    )
    await hass.services.async_call(
        "switch",
        "turn_on",
        {"entity_id": "switch.quicharc_ezlo_device_sync"},
        blocking=True,
    )
    enroll = next(
        c
        for c in mock_service.mock_calls
        if c[0] == "POST" and str(c[1]).endswith("/enrollments")
    )
    assert enroll[2] == {"service_peer_id": "integrations-homeassistant"}
    assert hass.states.get("switch.quicharc_ezlo_device_sync").state == "on"

    # The cloud integration asks for its token under the alias the agent uses.
    await _emit(
        setup_entry,
        "token_request",
        {
            "request_id": "t-7",
            "peer_id": "svc-1",
            "service": "integrations/homeassistant",
            "ezlo_user_uuid": OWNER,
        },
    )
    await _wait_for(
        lambda: (
            "integrations-homeassistant"
            in setup_entry.runtime_data.data["service_tokens"]
        )
    )
    token_id = setup_entry.runtime_data.data["service_tokens"][
        "integrations-homeassistant"
    ]

    await hass.services.async_call(
        "switch",
        "turn_off",
        {"entity_id": "switch.quicharc_ezlo_device_sync"},
        blocking=True,
    )
    assert hass.states.get("switch.quicharc_ezlo_device_sync").state == "off"
    assert hass.auth.async_get_refresh_token(token_id) is None


async def test_lan_announcement(
    hass: HomeAssistant, setup_entry, mock_async_zeroconf
) -> None:
    """The home is announced as _quicharc._udp with its id and key fingerprint."""
    runtime = setup_entry.runtime_data
    await _wait_for(lambda: runtime.lan.advertised is not None)
    info = mock_async_zeroconf.async_register_service.call_args[0][0]
    assert info.type == "_quicharc._udp.local."
    assert info.port == 4433
    props = {k.decode(): v.decode() for k, v in info.properties.items()}
    assert props == {"v": "1", "home": HOME_ID, "fp": runtime.home_key_fingerprint}

    # A new peer port re-announces in place.
    await _emit(setup_entry, "state", {"edge": "connected", "lan_port": 5000})
    await _wait_for(lambda: runtime.lan.advertised.port == 5000)
    assert mock_async_zeroconf.async_update_service.call_args[0][0].port == 5000

    # Unloading withdraws it.
    assert await hass.config_entries.async_unload(setup_entry.entry_id)
    await hass.async_block_till_done()
    assert mock_async_zeroconf.async_unregister_service.called


async def test_stop_event_shuts_agent_down(
    hass: HomeAssistant, setup_entry, caplog: pytest.LogCaptureFixture
) -> None:
    """Home Assistant stopping shuts the agent down cleanly; unloading after is quiet."""
    from homeassistant.const import EVENT_HOMEASSISTANT_STOP

    supervisor = setup_entry.runtime_data.supervisor
    hass.bus.async_fire(EVENT_HOMEASSISTANT_STOP)
    await hass.async_block_till_done()
    assert _requests(_data_dir(hass))[-1]["method"] == "shutdown"
    assert supervisor.pid is None

    assert await hass.config_entries.async_unload(setup_entry.entry_id)
    await hass.async_block_till_done()
    assert not [r for r in caplog.records if r.levelno >= logging.ERROR]


async def test_device_name_kept_for_token(hass: HomeAssistant, setup_entry) -> None:
    """The stored name keeps parentheses; only the repair text is stripped."""
    await _emit(
        setup_entry,
        "pairing_request",
        {"device_id": "dev-1", "device_name": "Phone (work)", "ezlo_user_uuid": OWNER},
    )
    await _wait_for(lambda: "dev-1" in setup_entry.runtime_data.pairing.devices)
    device = setup_entry.runtime_data.pairing.devices["dev-1"]
    assert device["name"] == "Phone (work)"
    token = hass.auth.async_get_refresh_token(device["refresh_token_id"])
    assert token.client_name == "QuicHarc: Phone (work)"


async def test_revoked_event_pulls_other_revocations(
    hass: HomeAssistant, setup_entry, mock_service: AiohttpClientMocker
) -> None:
    """A revoked event refreshes the grant, which revokes offline devices too."""
    runtime = setup_entry.runtime_data
    mock_service.put(f"{API}/homes/{HOME_ID}/devices/dev-2", json={})
    for dev in ("dev-1", "dev-2"):
        await _emit(
            setup_entry,
            "pairing_request",
            {"device_id": dev, "device_name": dev, "ezlo_user_uuid": OWNER},
        )
        await _wait_for(lambda dev=dev: dev in runtime.pairing.devices)
    offline_token = runtime.pairing.devices["dev-2"]["refresh_token_id"]

    mock_service.clear_requests()
    grant = _grant()
    grant["revocations"] = [
        {
            "id": f"r-{d}",
            "type": "device",
            "home_id": HOME_ID,
            "subject": d,
            "revoked_at": "2026-10-25T00:00:00Z",
        }
        for d in ("dev-1", "dev-2")
    ]
    mock_service.post(f"{API}/homes/{HOME_ID}/grant", json=grant)
    mock_service.get(
        f"{API}/homes/{HOME_ID}/devices?state=pending", json={"pairings": []}
    )
    mock_service.get(f"{API}/homes/{HOME_ID}/enrollments", json={"enrollments": []})

    # The agent reports only dev-1, the connected one.
    await _emit(setup_entry, "revoked", {"device_id": "dev-1"})
    await _wait_for(lambda: not runtime.pairing.devices)
    assert hass.auth.async_get_refresh_token(offline_token) is None


async def test_enrollment_revocation_deletes_service_token(
    hass: HomeAssistant, setup_entry
) -> None:
    """A revoked enrollment deletes the service's token and turns sync off."""
    runtime = setup_entry.runtime_data
    await _emit(
        setup_entry,
        "token_request",
        {
            "request_id": "t-1",
            "service": "integrations-homeassistant",
            "ezlo_user_uuid": OWNER,
        },
    )
    await _wait_for(
        lambda: "integrations-homeassistant" in runtime.data["service_tokens"]
    )
    token_id = runtime.data["service_tokens"]["integrations-homeassistant"]
    runtime.device_sync = True
    await _emit(
        setup_entry,
        "revoked",
        {"device_id": "integrations-homeassistant", "type": "enrollment"},
    )
    await _wait_for(
        lambda: "integrations-homeassistant" not in runtime.data["service_tokens"]
    )
    assert hass.auth.async_get_refresh_token(token_id) is None
    assert runtime.device_sync is False


async def test_repairing_a_device_keeps_one_token(
    hass: HomeAssistant, setup_entry
) -> None:
    """A device that pairs again ends up with exactly one Home Assistant token."""
    runtime = setup_entry.runtime_data
    token_ids = []
    for _attempt in range(4):
        await _emit(
            setup_entry,
            "pairing_request",
            {
                "device_id": "dev-1",
                "device_name": "iPhone 16 Pro",
                "ezlo_user_uuid": OWNER,
            },
        )
        await _wait_for(
            lambda: (
                "dev-1" in runtime.pairing.devices
                and runtime.pairing.devices["dev-1"]["refresh_token_id"]
                not in token_ids
            )
        )
        token_ids.append(runtime.pairing.devices["dev-1"]["refresh_token_id"])
    assert len(set(token_ids)) == 4
    assert [hass.auth.async_get_refresh_token(t) is not None for t in token_ids] == [
        False,
        False,
        False,
        True,
    ]
    ios_tokens = [
        t
        for user in await hass.auth.async_get_users()
        for t in user.refresh_tokens.values()
        if t.client_name == "QuicHarc: iPhone 16 Pro"
    ]
    assert len(ios_tokens) == 1


CONFLICT_AT = "2026-11-02T20:00:00Z"


async def _conflict(entry, node: str = "edge-a") -> None:
    """Make the fake agent behave as if another installation took its link."""
    runtime = entry.runtime_data
    await runtime.supervisor.async_request(
        "test.conflict", {"node": node, "at": CONFLICT_AT}
    )
    await _wait_for(lambda: runtime.state.identity_conflict)


def _conflict_issue(hass: HomeAssistant) -> ir.IssueEntry | None:
    return ir.async_get(hass).async_get_issue(DOMAIN, ISSUE_IDENTITY_CONFLICT)


async def _start_conflict_fix(hass: HomeAssistant, hass_client) -> tuple:
    assert await async_setup_component(hass, "repairs", {})
    client = await hass_client()
    resp = await client.post(
        "/api/repairs/issues/fix",
        json={"handler": DOMAIN, "issue_id": ISSUE_IDENTITY_CONFLICT},
    )
    assert resp.status == 200
    return client, await resp.json()


async def test_identity_conflict_reclaimed_through_repairs(
    hass: HomeAssistant, setup_entry, hass_client
) -> None:
    """Replaced by another installation: a repair; using this one reclaims."""
    runtime = setup_entry.runtime_data
    await _conflict(setup_entry)
    await hass.async_block_till_done()

    issue = _conflict_issue(hass)
    assert issue is not None
    assert issue.is_fixable
    assert issue.severity is ir.IssueSeverity.ERROR
    assert issue.translation_placeholders == {"node": "edge-a", "at": CONFLICT_AT}
    assert runtime.state.edge == "disconnected"
    assert runtime.state.identity_conflict_node == "edge-a"
    assert runtime.state.identity_conflict_at == CONFLICT_AT

    # A grant refresh doesn't end the conflict (config.set doesn't clear it).
    await runtime.async_refresh_config()
    await hass.async_block_till_done()
    assert runtime.state.identity_conflict
    assert _conflict_issue(hass) is not None

    client, flow = await _start_conflict_fix(hass, hass_client)
    assert flow["step_id"] == "init"
    assert flow["description_placeholders"] == {"node": "edge-a", "at": CONFLICT_AT}
    resp = await client.post(
        f"/api/repairs/issues/fix/{flow['flow_id']}", json={"action": "reclaim"}
    )
    assert (await resp.json())["type"] == "create_entry"
    assert "identity.reclaim" in [r["method"] for r in _requests(_data_dir(hass))]

    await _wait_for(lambda: not runtime.state.identity_conflict)
    await hass.async_block_till_done()
    assert runtime.state.edge == "connected"
    assert runtime.state.identity_conflict_node is None
    assert _conflict_issue(hass) is None


async def test_identity_conflict_left_on_other(
    hass: HomeAssistant, setup_entry, hass_client
) -> None:
    """Leaving it on the other installation dismisses the issue until it ends."""
    runtime = setup_entry.runtime_data
    await _conflict(setup_entry)
    await hass.async_block_till_done()

    client, flow = await _start_conflict_fix(hass, hass_client)
    resp = await client.post(
        f"/api/repairs/issues/fix/{flow['flow_id']}", json={"action": "leave"}
    )
    result = await resp.json()
    assert result["type"] == "abort"
    assert result["reason"] == "left_on_other"
    assert "identity.reclaim" not in [r["method"] for r in _requests(_data_dir(hass))]
    issue = _conflict_issue(hass)
    assert issue is not None
    assert issue.dismissed_version is not None
    assert runtime.state.identity_conflict

    # Once the conflict ends the issue goes away entirely.
    await runtime.async_reclaim_identity()
    await _wait_for(lambda: not runtime.state.identity_conflict)
    await hass.async_block_till_done()
    assert _conflict_issue(hass) is None


async def test_identity_reclaim_failure_keeps_the_issue(
    hass: HomeAssistant, setup_entry, hass_client
) -> None:
    """An agent that can't reclaim (older than identity.reclaim) shows an error."""
    await _conflict(setup_entry)
    await hass.async_block_till_done()

    client, flow = await _start_conflict_fix(hass, hass_client)
    with patch.object(
        setup_entry.runtime_data.supervisor,
        "async_request",
        AsyncMock(side_effect=AgentRequestError("unknown_method", "identity.reclaim")),
    ):
        resp = await client.post(
            f"/api/repairs/issues/fix/{flow['flow_id']}", json={"action": "reclaim"}
        )
    result = await resp.json()
    assert result["type"] == "form"
    assert result["errors"] == {"base": "reclaim_failed"}
    assert _conflict_issue(hass) is not None


async def test_identity_conflict_event_raises_at_once(
    hass: HomeAssistant, setup_entry
) -> None:
    """The event alone raises the issue, before any state arrives."""
    await _emit(
        setup_entry,
        "identity_conflict",
        {"reason": "identity_in_use", "node": "edge-b"},
    )
    await _wait_for(lambda: _conflict_issue(hass) is not None)
    assert _conflict_issue(hass).translation_placeholders["node"] == "edge-b"


async def test_stg_entry_keeps_its_environment(
    hass: HomeAssistant, setup_entry, mock_service: AiohttpClientMocker
) -> None:
    """A staging entry loads and refreshes without the YAML switch; new
    sign-ins on the same Home Assistant still go straight to live."""
    from yarl import URL

    from custom_components.quicharc.const import ENVIRONMENTS
    from homeassistant import config_entries
    from homeassistant.data_entry_flow import FlowResultType

    runtime = setup_entry.runtime_data
    assert setup_entry.state is ConfigEntryState.LOADED
    assert setup_entry.data[CONF_ENVIRONMENT] == "stg"
    calls = len(mock_service.mock_calls)
    await runtime.async_refresh_config()
    assert runtime.last_refresh_error is None
    assert len(mock_service.mock_calls) > calls

    with patch(
        "custom_components.quicharc.config_flow.async_setup_component",
        return_value=True,
    ):
        result = await hass.config_entries.flow.async_init(
            DOMAIN, context={"source": config_entries.SOURCE_USER}
        )
    # Single config entry: a second sign-in aborts, but never shows a picker.
    assert result.get("step_id") != "pick_implementation"
    if result["type"] is FlowResultType.EXTERNAL_STEP:
        url = URL(result["url"]).with_query(None)
        assert str(url) == ENVIRONMENTS["live"].authorize_url


@pytest.mark.parametrize(
    ("restart_flag", "status", "restarts"),
    [
        (True, "editable", 1),
        (False, "editable", 0),
        # Nothing was changed (already trusted, or it needs a manual edit).
        (True, "already_trusted", 0),
        (True, "manual", 0),
    ],
)
async def test_restart_now_after_the_http_change(
    hass: HomeAssistant,
    tmp_path: Path,
    unix_sockets,
    mock_service,
    hass_admin_user,
    restart_flag: bool,
    status: str,
    restarts: int,
) -> None:
    """ "Change them and restart now" restarts once, only if a change was made."""
    from custom_components.quicharc import http_config
    from custom_components.quicharc.const import (
        CONF_EDIT_HTTP_CONFIG,
        CONF_RESTART_AFTER_HTTP_EDIT,
    )

    hass.config.config_dir = str(tmp_path)
    (tmp_path / "configuration.yaml").write_text("")
    restart_calls = async_mock_service(hass, "homeassistant", "restart")
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
            CONF_EDIT_HTTP_CONFIG: True,
            CONF_RESTART_AFTER_HTTP_EDIT: restart_flag,
        },
        options={"web_access": False, "auto_approve_owner": True},
        minor_version=2,
    )
    entry.add_to_hass(hass)
    with (
        patch(
            "custom_components.quicharc.async_ensure_http_config",
            return_value=http_config.Status(status),
        ),
        patch.object(
            AgentBinary,
            "async_ensure",
            AsyncMock(return_value=_fake_agent_wrapper(tmp_path)),
        ),
    ):
        assert await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()
        runtime = entry.runtime_data
        await _wait_for(
            lambda: (
                runtime.home_config is not None and runtime.state.edge == "connected"
            )
        )
    assert len(restart_calls) == restarts
    # Acted on once: a reload or the next start doesn't restart again.
    assert entry.data[CONF_EDIT_HTTP_CONFIG] is False
    assert entry.data[CONF_RESTART_AFTER_HTTP_EDIT] is False
    assert await hass.config_entries.async_unload(entry.entry_id)
    await hass.async_block_till_done()


@pytest.mark.parametrize(
    ("status", "code"),
    [(404, "unknown_service_peer"), (409, "service_peer_disabled")],
)
async def test_device_sync_unavailable(
    hass: HomeAssistant,
    setup_entry,
    mock_service: AiohttpClientMocker,
    status: int,
    code: str,
) -> None:
    """A service that isn't registered or is turned off says so, and stays off."""
    from homeassistant.exceptions import HomeAssistantError

    mock_service.post(
        f"{API}/homes/{HOME_ID}/enrollments", status=status, json={"error": code}
    )
    with pytest.raises(HomeAssistantError) as err:
        await hass.services.async_call(
            "switch",
            "turn_on",
            {"entity_id": "switch.quicharc_ezlo_device_sync"},
            blocking=True,
        )
    assert err.value.translation_key == "device_sync_unavailable"
    assert str(err.value) == "Ezlo device sync isn't available yet"
    assert hass.states.get("switch.quicharc_ezlo_device_sync").state == "off"
    assert not setup_entry.runtime_data.device_sync


WEB_URL_SENSOR = "sensor.quicharc_web_access_url"


def _mock_web_grant(mock_service: AiohttpClientMocker, web: bool, scope: bool) -> None:
    """The service after a web access change: home flag, grant and its scopes."""
    mock_service.clear_requests()
    mock_service.patch(f"{API}/homes/{HOME_ID}", json=_home(web_access=web))
    grant = _grant(web_access=web)
    grant["scopes"] = ["app", "web"] if scope else ["app"]
    mock_service.post(f"{API}/homes/{HOME_ID}/grant", json=grant)
    mock_service.get(
        f"{API}/homes/{HOME_ID}/devices?state=pending", json={"pairings": []}
    )
    mock_service.get(f"{API}/homes/{HOME_ID}/enrollments", json={"enrollments": []})


async def test_web_access_url_off(hass: HomeAssistant, setup_entry) -> None:
    """With web access off there's no URL, not a stale one."""
    from homeassistant.helpers import entity_registry as er

    state = hass.states.get(WEB_URL_SENSOR)
    assert state.state == "unknown"
    entry = er.async_get(hass).async_get(WEB_URL_SENSOR)
    assert entry.entity_category is er.EntityCategory.DIAGNOSTIC
    assert entry.translation_key == "web_access_url"
    assert hass.states.get("switch.quicharc_web_access").attributes["url"] is None


async def test_web_access_url_on_with_web_scope(
    hass: HomeAssistant, setup_entry, mock_service: AiohttpClientMocker
) -> None:
    """Switch on and a grant with the web scope: the URL shows."""
    _mock_web_grant(mock_service, web=True, scope=True)
    await hass.services.async_call(
        "switch", "turn_on", {"entity_id": "switch.quicharc_web_access"}, blocking=True
    )
    url = f"https://{_home()['hostname']}"
    assert hass.states.get(WEB_URL_SENSOR).state == url
    assert hass.states.get("switch.quicharc_web_access").attributes["url"] == url


async def test_web_access_url_on_without_web_scope(
    hass: HomeAssistant, setup_entry, mock_service: AiohttpClientMocker
) -> None:
    """Switch on but the grant lacks web (not entitled to it): no URL."""
    _mock_web_grant(mock_service, web=True, scope=False)
    await hass.services.async_call(
        "switch", "turn_on", {"entity_id": "switch.quicharc_web_access"}, blocking=True
    )
    assert hass.states.get("switch.quicharc_web_access").state == "on"
    assert hass.states.get(WEB_URL_SENSOR).state == "unknown"


async def test_web_access_url_follows_the_switch(
    hass: HomeAssistant, setup_entry, mock_service: AiohttpClientMocker
) -> None:
    """Turning web access on and off updates the sensor straight away."""
    url = f"https://{_home()['hostname']}"
    _mock_web_grant(mock_service, web=True, scope=True)
    await hass.services.async_call(
        "switch", "turn_on", {"entity_id": "switch.quicharc_web_access"}, blocking=True
    )
    assert hass.states.get(WEB_URL_SENSOR).state == url

    _mock_web_grant(mock_service, web=False, scope=False)
    await hass.services.async_call(
        "switch", "turn_off", {"entity_id": "switch.quicharc_web_access"}, blocking=True
    )
    assert hass.states.get(WEB_URL_SENSOR).state == "unknown"

    # A later grant refresh that drops the web scope also clears it.
    _mock_web_grant(mock_service, web=True, scope=True)
    await hass.services.async_call(
        "switch", "turn_on", {"entity_id": "switch.quicharc_web_access"}, blocking=True
    )
    assert hass.states.get(WEB_URL_SENSOR).state == url
    _mock_web_grant(mock_service, web=True, scope=False)
    await setup_entry.runtime_data.async_refresh_config()
    await hass.async_block_till_done()
    assert hass.states.get(WEB_URL_SENSOR).state == "unknown"


GATE_SWITCH = "switch.quicharc_require_ezlo_sign_in_for_web_access"


def _mock_gate(
    mock_service: AiohttpClientMocker, *, applied: bool | None, scopes: list[str]
) -> None:
    """The service's answer to a gate_required PATCH, and the next grant.

    applied None is a service older than the setting: it drops the field
    and answers with a home view that has no gate_required.
    """
    mock_service.clear_requests()
    home = _home(web_access=True)
    if applied is not None:
        home["gate_required"] = applied
    mock_service.patch(f"{API}/homes/{HOME_ID}", json=home)
    grant = _grant(web_access=True)
    grant["scopes"] = scopes
    if applied is not None:
        grant["home"]["gate_required"] = applied
    mock_service.post(f"{API}/homes/{HOME_ID}/grant", json=grant)
    mock_service.get(
        f"{API}/homes/{HOME_ID}/devices?state=pending", json={"pairings": []}
    )
    mock_service.get(f"{API}/homes/{HOME_ID}/enrollments", json={"enrollments": []})


async def test_gate_switch_off_by_default(hass: HomeAssistant, setup_entry) -> None:
    """Existing homes don't require the Ezlo sign-in."""
    from homeassistant.helpers import entity_registry as er

    assert hass.states.get(GATE_SWITCH).state == "off"
    entry = er.async_get(hass).async_get(GATE_SWITCH)
    assert entry.entity_category is er.EntityCategory.CONFIG
    assert entry.translation_key == "gate_required"


async def test_gate_switch_on_and_off(
    hass: HomeAssistant, setup_entry, mock_service: AiohttpClientMocker
) -> None:
    """The switch PATCHes the home and re-issues the grant each way."""
    _mock_gate(mock_service, applied=True, scopes=["app", "web"])
    await hass.services.async_call(
        "switch", "turn_on", {"entity_id": GATE_SWITCH}, blocking=True
    )
    calls = [(c[0], str(c[1]), c[2]) for c in mock_service.mock_calls]
    patch_at = next(i for i, c in enumerate(calls) if c[0] == "PATCH")
    assert calls[patch_at][2] == {"gate_required": True}
    assert ("POST", f"{API}/homes/{HOME_ID}/grant") in [c[:2] for c in calls[patch_at:]]
    assert hass.states.get(GATE_SWITCH).state == "on"
    assert setup_entry.options["gate_required"] is True

    # Off takes effect with the next grant, which carries web_open as well.
    _mock_gate(mock_service, applied=False, scopes=["app", "web", "web_open"])
    await hass.services.async_call(
        "switch", "turn_off", {"entity_id": GATE_SWITCH}, blocking=True
    )
    calls = [(c[0], str(c[1]), c[2]) for c in mock_service.mock_calls]
    assert calls[0][:2] == ("PATCH", f"{API}/homes/{HOME_ID}")
    assert calls[0][2] == {"gate_required": False}
    assert ("POST", f"{API}/homes/{HOME_ID}/grant") in [c[:2] for c in calls]
    assert hass.states.get(GATE_SWITCH).state == "off"
    # web_open next to web doesn't change what web access shows.
    runtime = setup_entry.runtime_data
    assert runtime.home_config.scopes == ["app", "web", "web_open"]
    assert hass.states.get(WEB_URL_SENSOR).state == f"https://{_home()['hostname']}"


async def test_gate_switch_on_an_old_service(
    hass: HomeAssistant, setup_entry, mock_service: AiohttpClientMocker
) -> None:
    """A service that ignores gate_required is caught, not silently accepted."""
    from homeassistant.exceptions import HomeAssistantError

    _mock_gate(mock_service, applied=None, scopes=["app", "web"])
    with pytest.raises(HomeAssistantError) as err:
        await hass.services.async_call(
            "switch", "turn_on", {"entity_id": GATE_SWITCH}, blocking=True
        )
    assert err.value.translation_key == "gate_not_supported"
    assert hass.states.get(GATE_SWITCH).state == "off"
    assert "gate_required" not in setup_entry.options
    # No grant was re-issued for a setting that didn't change.
    assert not [c for c in mock_service.mock_calls if str(c[1]).endswith("/grant")]
