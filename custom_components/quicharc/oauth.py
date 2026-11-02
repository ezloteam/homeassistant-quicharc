"""Sign in with Ezlo: authorization code with PKCE against cloud/login.

The integration is a public OpenID Connect client (no secret), registered by
Ezlo, so it registers its own implementation per environment instead of
asking the user for application credentials.
"""

from __future__ import annotations

import logging
from typing import Any, Final, NoReturn, cast

from aiohttp import ClientError, ClientResponseError
from yarl import URL

from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import (
    HomeAssistantError,
    OAuth2TokenRequestError,
    OAuth2TokenRequestReauthError,
    OAuth2TokenRequestTransientError,
)
from homeassistant.helpers import config_entry_oauth2_flow
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.config_entry_oauth2_flow import (
    LocalOAuth2ImplementationWithPkce as _Pkce,
)

from .const import (
    DOMAIN,
    ENVIRONMENTS,
    OAUTH_SCOPES,
    Environment,
    environment_from_config,
    implementation_domain,
)
from .otel import KIND_CLIENT, AnySpan, async_get_telemetry, child_span, trace_headers

_LOGGER = logging.getLogger(__name__)


class EzloOAuth2Implementation(config_entry_oauth2_flow.LocalOAuth2Implementation):
    """Public client with a fresh PKCE verifier for every flow."""

    def __init__(self, hass: HomeAssistant, env: Environment) -> None:
        """Initialize."""
        super().__init__(
            hass,
            implementation_domain(env.key),
            env.client_id or "",
            "",
            env.authorize_url,
            env.token_url,
        )
        self._env = env
        self._verifiers: dict[str, str] = {}

    @property
    def name(self) -> str:
        """Return the name shown when picking an environment."""
        return self._env.name

    async def async_generate_authorize_url(self, flow_id: str) -> str:
        """Return the authorize URL with a per-flow PKCE challenge."""
        verifier = _Pkce.generate_code_verifier(128)
        self._verifiers[flow_id] = verifier
        url = await super().async_generate_authorize_url(flow_id)
        return str(
            URL(url).update_query(
                {
                    "scope": " ".join(OAUTH_SCOPES),
                    "code_challenge": _Pkce.compute_code_challenge(verifier),
                    "code_challenge_method": "S256",
                }
            )
        )

    async def async_resolve_external_data(self, external_data: Any) -> dict:
        """Redeem the code with the flow's verifier."""
        verifier = self._verifiers.pop(external_data["state"]["flow_id"], None)
        if verifier is None:
            raise config_entry_oauth2_flow.ImplementationUnavailableError(
                "no PKCE verifier for this flow"
            )
        return await self._token_request(
            {
                "grant_type": "authorization_code",
                "code": external_data["code"],
                "redirect_uri": external_data["state"]["redirect_uri"],
                "code_verifier": verifier,
            }
        )

    async def _async_refresh_token(self, token: dict) -> dict:
        """Refresh the Ezlo token; its own trace unless part of another."""
        telemetry = await async_get_telemetry(self.hass)
        with telemetry.span(
            "ezlo.token_refresh", attributes={"quicharc.environment": self._env.key}
        ):
            return await super()._async_refresh_token(token)

    async def _token_request(self, data: dict) -> dict:
        """Call cloud/login's token endpoint, carrying the trace context."""
        with child_span(
            "POST /oauth/token",
            kind=KIND_CLIENT,
            attributes={
                "http.request.method": "POST",
                "url.template": "/oauth/token",
                "server.address": URL(self.token_url).host,
                "oauth.grant_type": data.get("grant_type"),
            },
        ) as span:
            headers = trace_headers()
            if not headers:
                return await super()._token_request(data)
            return await self._traced_token_request(data, headers, span)

    async def _traced_token_request(
        self, data: dict, headers: dict[str, str], span: AnySpan
    ) -> dict:
        """Home Assistant's token request, plus the traceparent header."""
        data["client_id"] = self.client_id
        session = async_get_clientsession(self.hass)
        try:
            resp = await session.post(self.token_url, data=data, headers=headers)
            span.set_attribute("http.response.status_code", resp.status)
            resp.raise_for_status()
            return cast(dict, await resp.json())
        except ClientError as err:
            _raise_token_error(err, self)


DATA_REGISTERED: Final = f"{DOMAIN}_oauth_registered"
DATA_ENVIRONMENT: Final = f"{DOMAIN}_environment"


@callback
def async_set_environment(hass: HomeAssistant, env: str) -> None:
    """Remember the environment configuration.yaml chose (from async_setup)."""
    hass.data[DATA_ENVIRONMENT] = env


async def async_get_environment(hass: HomeAssistant) -> Environment:
    """Return the environment new sign-ins use: live unless YAML says staging.

    Home Assistant starts a config flow without setting the integration up,
    so when async_setup hasn't run the YAML is read here.
    """
    if (env := hass.data.get(DATA_ENVIRONMENT)) is None:
        from homeassistant.helpers.reload import async_integration_yaml_config

        try:
            config = await async_integration_yaml_config(hass, DOMAIN) or {}
        except (HomeAssistantError, OSError) as err:
            # A configuration.yaml that can't be read leaves new sign-ins on live.
            _LOGGER.debug("Can't read the quicharc YAML, using live: %s", err)
            config = {}
        env = environment_from_config(config)
        hass.data[DATA_ENVIRONMENT] = env
    return ENVIRONMENTS[env]


@callback
def async_register_implementation(hass: HomeAssistant, env: Environment) -> None:
    """Register Sign in with Ezlo for one environment, once.

    Registering only once keeps the in-progress flows' PKCE verifiers.
    """
    registered: set[str] = hass.data.setdefault(DATA_REGISTERED, set())
    if env.key in registered or env.client_id is None:
        return
    registered.add(env.key)
    config_entry_oauth2_flow.async_register_implementation(
        hass, DOMAIN, EzloOAuth2Implementation(hass, env)
    )


async def async_register_implementations(hass: HomeAssistant) -> Environment:
    """Register only the environment new sign-ins use, and return it.

    One implementation means Home Assistant never asks which to use; the
    environment is never the user's choice.
    """
    env = await async_get_environment(hass)
    async_register_implementation(hass, env)
    return env


def _raise_token_error(err: ClientError, impl: EzloOAuth2Implementation) -> NoReturn:
    """Raise what Home Assistant's own token request would for this error."""
    mapper = getattr(config_entry_oauth2_flow, "_raise_mapped_token_error", None)
    if mapper is not None:  # Home Assistant 2026.8+
        mapper(err, getattr(impl, "service_domain", impl.domain))
    if not isinstance(err, ClientResponseError):
        raise err
    kwargs: dict[str, Any] = {
        "request_info": err.request_info,
        "history": err.history,
        "status": err.status,
        "message": err.message,
        "headers": err.headers,
        "domain": impl.domain,
    }
    if err.status == 429 or 500 <= err.status <= 599:
        raise OAuth2TokenRequestTransientError(**kwargs) from err
    if 400 <= err.status <= 499:
        raise OAuth2TokenRequestReauthError(**kwargs) from err
    raise OAuth2TokenRequestError(**kwargs) from err
