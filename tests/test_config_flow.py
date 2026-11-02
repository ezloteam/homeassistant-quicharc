"""Tests for Sign in with Ezlo and the setup steps."""

from __future__ import annotations

import base64
import json
from unittest.mock import patch

import pytest
from yarl import URL

from custom_components.quicharc import http_config
from custom_components.quicharc.const import (
    CONF_EDIT_HTTP_CONFIG,
    CONF_ENVIRONMENT,
    CONF_EZLO_USER_EMAIL,
    CONF_EZLO_USER_UUID,
    CONF_HA_USER_ID,
    CONF_TELEMETRY,
    DOMAIN,
    ENVIRONMENTS,
    TELEMETRY_ENDPOINT,
    implementation_domain,
)
from custom_components.quicharc.oauth import EzloOAuth2Implementation
from custom_components.quicharc.otel import get_telemetry
from homeassistant import config_entries
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.helpers import config_entry_oauth2_flow
from homeassistant.setup import async_setup_component

from .harness import AiohttpClientMocker, MockConfigEntry

STG = ENVIRONMENTS["stg"]
USER_UUID = "7f9c1c3e-0000-4000-8000-000000000001"


@pytest.fixture(autouse=True)
def mock_my_integration(hass: HomeAssistant):
    """Stand in for loading the my integration (its frontend isn't installed here)."""

    async def setup(hass: HomeAssistant, domain: str, config: dict) -> bool:
        hass.config.components.add(domain)
        return True

    with patch(
        "custom_components.quicharc.config_flow.async_setup_component",
        side_effect=setup,
    ) as mock:
        yield mock


@pytest.fixture
async def skip_entry_setup(hass: HomeAssistant):
    """Create entries without setting them up, and unload them the same way."""
    with (
        patch("custom_components.quicharc.async_setup_entry", return_value=True),
        patch("custom_components.quicharc.async_unload_entry", return_value=True),
    ):
        yield
        for entry in hass.config_entries.async_loaded_entries(DOMAIN):
            await hass.config_entries.async_unload(entry.entry_id)


def _b64(data: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")


def _jwt(claims: dict) -> str:
    """An unsigned JWT; the integration only reads the claims."""
    return f"{_b64({'alg': 'HS256'})}.{_b64(claims)}.c2ln"


# The user envelope the access token carries once cloud/login issues normal
# user tokens, and the id_token whose sub is the numeric user id.
ACCESS_TOKEN = _jwt({"user": {"uuid": USER_UUID}, "location": {"uuid": "loc-1"}})
ID_TOKEN = _jwt({"sub": "12345", "email": "owner@example.com"})


async def _start_flow(
    hass: HomeAssistant, hass_client_no_auth, aioclient_mock, env_key="stg"
):
    """Run the flow through the Ezlo authorization and token exchange."""
    env = ENVIRONMENTS[env_key]
    if env_key == "stg":
        # A developer's configuration.yaml: quicharc: environment: staging.
        assert await async_setup_component(
            hass, DOMAIN, {DOMAIN: {"environment": "staging"}}
        )
    # The environment is never the user's choice: straight to its sign-in.
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER}
    )
    assert result["type"] is FlowResultType.EXTERNAL_STEP
    url = URL(result["url"])
    assert str(url.with_query(None)) == env.authorize_url
    query = url.query
    assert query["client_id"] == env.client_id
    assert query["code_challenge_method"] == "S256"
    assert query["scope"] == "openid email profile"
    # The flow loads the my integration, so the redirect is the one
    # registered with cloud/login.
    assert query["redirect_uri"] == "https://my.home-assistant.io/redirect/oauth"
    state = query["state"]

    client = await hass_client_no_auth()
    resp = await client.get(f"/auth/external/callback?code=abcd&state={state}")
    assert resp.status == 200

    aioclient_mock.post(
        env.token_url,
        json={
            "access_token": ACCESS_TOKEN,
            "id_token": ID_TOKEN,
            "refresh_token": "ezlo_rt_refresh",
            "token_type": "Bearer",
            "expires_in": 600,
        },
    )
    return result, query["code_challenge"]


@pytest.mark.usefixtures("skip_entry_setup")
@pytest.mark.parametrize(
    ("action", "edit", "restart"),
    [("restart_now", True, True), ("later", True, False), ("skip", False, False)],
)
async def test_full_flow(
    hass: HomeAssistant,
    hass_client_no_auth,
    aioclient_mock: AiohttpClientMocker,
    current_request_with_host,
    hass_admin_user,
    action: str,
    edit: bool,
    restart: bool,
) -> None:
    """Sign in, pick the owner, choose what happens to the HTTP settings."""
    result, challenge = await _start_flow(hass, hass_client_no_auth, aioclient_mock)

    with patch(
        "custom_components.quicharc.config_flow.QuicHarcFlowHandler._async_http_plan",
        return_value=http_config.Plan(
            http_config.Status.EDITABLE, target=http_config.Path("configuration.yaml")
        ),
    ):
        result = await hass.config_entries.flow.async_configure(result["flow_id"])
        assert result["type"] is FlowResultType.FORM
        assert result["step_id"] == "owner"
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], {CONF_HA_USER_ID: hass_admin_user.id}
        )
        assert result["step_id"] == "http"
        # Restarting now is what's offered first.
        assert result["data_schema"]({})["http_action"] == "restart_now"
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], {"http_action": action}
        )

    assert result["type"] is FlowResultType.CREATE_ENTRY
    data = result["data"]
    assert data[CONF_ENVIRONMENT] == "stg"
    assert data[CONF_EZLO_USER_UUID] == USER_UUID
    assert data[CONF_EZLO_USER_EMAIL] == "owner@example.com"
    assert data[CONF_HA_USER_ID] == hass_admin_user.id
    assert data[CONF_EDIT_HTTP_CONFIG] is edit
    assert data["restart_after_http_edit"] is restart
    assert data["token"]["refresh_token"] == "ezlo_rt_refresh"
    assert result["result"].unique_id == USER_UUID

    # The token request was a public-client PKCE exchange: no secret, a verifier
    # matching the challenge in the authorize URL.
    token_call = next(
        call for call in aioclient_mock.mock_calls if str(call[1]) == STG.token_url
    )
    body = token_call[2]
    assert "client_secret" not in body
    assert body["client_id"] == STG.client_id
    assert (
        config_entry_oauth2_flow.LocalOAuth2ImplementationWithPkce.compute_code_challenge(
            body["code_verifier"]
        )
        == challenge
    )


@pytest.mark.usefixtures("skip_entry_setup")
async def test_flow_skips_http_step_when_trusted(
    hass: HomeAssistant,
    hass_client_no_auth,
    aioclient_mock: AiohttpClientMocker,
    current_request_with_host,
    hass_admin_user,
) -> None:
    """No HTTP question when Home Assistant already trusts loopback."""
    result, _ = await _start_flow(hass, hass_client_no_auth, aioclient_mock)
    with patch(
        "custom_components.quicharc.config_flow.QuicHarcFlowHandler._async_http_plan",
        return_value=http_config.Plan(http_config.Status.ALREADY_TRUSTED),
    ):
        result = await hass.config_entries.flow.async_configure(result["flow_id"])
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], {CONF_HA_USER_ID: hass_admin_user.id}
        )
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["data"][CONF_EDIT_HTTP_CONFIG] is False


@pytest.mark.usefixtures("skip_entry_setup")
async def test_live_sign_in(
    hass: HomeAssistant,
    hass_client_no_auth,
    aioclient_mock: AiohttpClientMocker,
    current_request_with_host,
    hass_admin_user,
) -> None:
    """Ezlo (live) signs in with the live client and creates a live entry."""
    live = ENVIRONMENTS["live"]
    assert live.client_id == "c63290a1-d9ee-4b6f-99b5-3615045941a1"
    result, _ = await _start_flow(hass, hass_client_no_auth, aioclient_mock, "live")
    with patch(
        "custom_components.quicharc.config_flow.QuicHarcFlowHandler._async_http_plan",
        return_value=http_config.Plan(http_config.Status.ALREADY_TRUSTED),
    ):
        result = await hass.config_entries.flow.async_configure(result["flow_id"])
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], {CONF_HA_USER_ID: hass_admin_user.id}
        )
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["data"][CONF_ENVIRONMENT] == "live"
    assert result["data"]["auth_implementation"] == DOMAIN
    token_call = next(
        call for call in aioclient_mock.mock_calls if str(call[1]) == live.token_url
    )
    assert token_call[2]["client_id"] == live.client_id
    assert "client_secret" not in token_call[2]


async def test_verifier_is_per_flow(hass: HomeAssistant) -> None:
    """Two flows get different PKCE challenges from the same implementation."""
    impl = EzloOAuth2Implementation(hass, STG)
    with patch(
        "homeassistant.helpers.config_entry_oauth2_flow.async_get_redirect_uri",
        return_value="https://example.com/cb",
    ):
        first = URL(await impl.async_generate_authorize_url("flow-1")).query[
            "code_challenge"
        ]
        second = URL(await impl.async_generate_authorize_url("flow-2")).query[
            "code_challenge"
        ]
    assert first != second


@pytest.mark.usefixtures("skip_entry_setup")
async def test_reauth(
    hass: HomeAssistant,
    hass_client_no_auth,
    aioclient_mock: AiohttpClientMocker,
    current_request_with_host,
) -> None:
    """Reauth updates the token on the existing entry."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        unique_id=USER_UUID,
        data={
            "auth_implementation": f"{DOMAIN}_stg",
            "token": {"access_token": "old", "refresh_token": "old", "expires_at": 0},
            CONF_ENVIRONMENT: "stg",
            CONF_EZLO_USER_UUID: USER_UUID,
        },
    )
    entry.add_to_hass(hass)
    result = await entry.start_reauth_flow(hass)
    assert result["step_id"] == "reauth_confirm"
    result = await hass.config_entries.flow.async_configure(result["flow_id"], {})
    assert result["type"] is FlowResultType.EXTERNAL_STEP
    state = URL(result["url"]).query["state"]
    client = await hass_client_no_auth()
    await client.get(f"/auth/external/callback?code=abcd&state={state}")
    aioclient_mock.post(
        STG.token_url,
        json={
            "access_token": ACCESS_TOKEN,
            "refresh_token": "new-r",
            "expires_in": 600,
        },
    )
    result = await hass.config_entries.flow.async_configure(result["flow_id"])
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "reauth_successful"
    assert entry.data["token"]["refresh_token"] == "new-r"


async def test_flow_aborts_without_user_uuid(
    hass: HomeAssistant,
    hass_client_no_auth,
    aioclient_mock: AiohttpClientMocker,
    current_request_with_host,
) -> None:
    """A token without the user envelope can't be used for key proofs."""
    result, _ = await _start_flow(hass, hass_client_no_auth, aioclient_mock)
    aioclient_mock.clear_requests()
    aioclient_mock.post(
        STG.token_url,
        json={"access_token": _jwt({"sub": "record-id"}), "expires_in": 600},
    )
    result = await hass.config_entries.flow.async_configure(result["flow_id"])
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "no_user_uuid"


@pytest.mark.usefixtures("skip_entry_setup")
async def test_sign_in_is_one_trace(
    hass: HomeAssistant,
    hass_client_no_auth,
    aioclient_mock: AiohttpClientMocker,
    current_request_with_host,
    hass_admin_user,
) -> None:
    """Sign-in is one trace, with no question about sharing it."""
    for signal in ("traces", "logs", "metrics"):
        aioclient_mock.post(f"{TELEMETRY_ENDPOINT}/{signal}", json={})
    result, _ = await _start_flow(hass, hass_client_no_auth, aioclient_mock)
    telemetry = get_telemetry(hass)
    assert telemetry is not None

    def exported() -> list[dict]:
        return [
            span
            for call in aioclient_mock.mock_calls
            if str(call[1]) == f"{TELEMETRY_ENDPOINT}/traces"
            for span in json.loads(call[2])["resourceSpans"][0]["scopeSpans"][0][
                "spans"
            ]
        ]

    with patch(
        "custom_components.quicharc.config_flow.QuicHarcFlowHandler._async_http_plan",
        return_value=http_config.Plan(http_config.Status.ALREADY_TRUSTED),
    ):
        result = await hass.config_entries.flow.async_configure(result["flow_id"])
        assert result["step_id"] == "owner"
        assert set(result["data_schema"].schema) == {CONF_HA_USER_ID}
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], {CONF_HA_USER_ID: hass_admin_user.id}
        )

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert CONF_TELEMETRY not in result["options"]
    assert result["result"].minor_version == 2
    await telemetry.async_flush()
    spans = exported()
    sign_in = next(s for s in spans if s["name"] == "sign_in")
    token = next(s for s in spans if s["name"] == "POST /oauth/token")
    values = {a["key"]: a["value"] for a in sign_in["attributes"]}
    assert values["quicharc.flow.outcome"] == {"stringValue": "created"}
    assert values["quicharc.environment"] == {"stringValue": "stg"}
    assert token["traceId"] == sign_in["traceId"]
    token_call = next(
        c for c in aioclient_mock.mock_calls if str(c[1]) == STG.token_url
    )
    assert token_call[3]["traceparent"].split("-")[1] == sign_in["traceId"]


async def test_no_yaml_registers_only_live(hass: HomeAssistant) -> None:
    """Without the YAML switch only Ezlo (live) exists, so nothing asks."""
    assert await async_setup_component(hass, DOMAIN, {})
    implementations = await config_entry_oauth2_flow.async_get_implementations(
        hass, DOMAIN
    )
    assert list(implementations) == [implementation_domain("live")]


async def test_staging_yaml_registers_only_staging(hass: HomeAssistant) -> None:
    """With quicharc: environment: staging, only staging exists."""
    assert await async_setup_component(
        hass, DOMAIN, {DOMAIN: {"environment": "staging"}}
    )
    implementations = await config_entry_oauth2_flow.async_get_implementations(
        hass, DOMAIN
    )
    assert list(implementations) == [implementation_domain("stg")]


async def test_flow_without_setup_reads_the_yaml(hass: HomeAssistant) -> None:
    """A flow started before async_setup still honours configuration.yaml."""
    with patch(
        "homeassistant.helpers.reload.async_integration_yaml_config",
        return_value={DOMAIN: {"environment": "staging"}},
    ):
        result = await hass.config_entries.flow.async_init(
            DOMAIN, context={"source": config_entries.SOURCE_USER}
        )
    assert result["type"] is FlowResultType.EXTERNAL_STEP
    assert str(URL(result["url"]).with_query(None)) == STG.authorize_url
