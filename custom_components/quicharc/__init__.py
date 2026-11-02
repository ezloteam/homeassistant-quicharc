"""QuicHarc: remote access to Home Assistant through the Ezlo cloud."""

from __future__ import annotations

import logging
from pathlib import Path

from aiohttp import ClientError, ClientResponseError

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_NAME, EVENT_HOMEASSISTANT_STOP, Platform
from homeassistant.core import Event, HomeAssistant, ServiceCall, callback
from homeassistant.exceptions import (
    ConfigEntryAuthFailed,
    ConfigEntryNotReady,
    HomeAssistantError,
    ServiceValidationError,
)
from homeassistant.helpers import (
    config_entry_oauth2_flow,
    config_validation as cv,
    discovery,
)
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.service import async_register_admin_service
from homeassistant.helpers.start import async_at_started
from homeassistant.helpers.storage import Store
from homeassistant.helpers.typing import ConfigType

from . import http_config
from .agent_binary import AgentBinary, AgentBinaryError
from .api import QuicHarcApi, QuicHarcApiError, QuicHarcConnectionError
from .const import (
    CONF_EDIT_HTTP_CONFIG,
    CONF_ENVIRONMENT,
    CONF_HA_USER_ID,
    CONF_HOME_ID,
    CONF_RESTART_AFTER_HTTP_EDIT,
    CONF_TELEMETRY,
    CONF_YAML_ENVIRONMENT,
    DATA_DIR_NAME,
    DEFAULT_ENVIRONMENT,
    DOMAIN,
    ENVIRONMENTS,
    YAML_ENVIRONMENTS,
    environment_from_config,
)
from .http_setup import async_after_start, async_ensure_http_config
from .oauth import (
    async_register_implementation,
    async_register_implementations,
    async_set_environment,
)
from .otel import AnySpan, Telemetry, async_get_telemetry
from .pairing import PairingError
from .runtime import STORAGE_VERSION, QuicHarcRuntime
from .schema import vol
from .tokens import remove_token

_LOGGER = logging.getLogger(__name__)

PLATFORMS: list[Platform] = [Platform.BINARY_SENSOR, Platform.SENSOR, Platform.SWITCH]
# Set up from the UI; the only YAML is a developer switch to Ezlo staging.
CONFIG_SCHEMA = vol.Schema(
    {
        vol.Optional(DOMAIN): vol.Schema(
            {
                vol.Optional(CONF_YAML_ENVIRONMENT, default="live"): vol.In(
                    list(YAML_ENVIRONMENTS)
                )
            }
        )
    },
    extra=vol.ALLOW_EXTRA,
)

type QuicHarcConfigEntry = ConfigEntry[QuicHarcRuntime]

SERVICE_APPROVE = "approve_device"
SERVICE_DENY = "deny_device"
SERVICE_REVOKE = "revoke_device"


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Register Sign in with Ezlo and the services."""
    async_set_environment(hass, environment_from_config(config))
    await async_register_implementations(hass)
    _async_register_services(hass)
    return True


async def async_migrate_entry(hass: HomeAssistant, entry: QuicHarcConfigEntry) -> bool:
    """Bring an entry from an earlier version up to date."""
    if entry.version > 1:
        return False
    if entry.minor_version < 2:
        # 1.2: the "Share diagnostics with Ezlo" option is gone.
        options = {k: v for k, v in entry.options.items() if k != CONF_TELEMETRY}
        hass.config_entries.async_update_entry(entry, options=options, minor_version=2)
        _LOGGER.info("Updated the QuicHarc entry to version 1.2")
    return True


async def async_setup_entry(hass: HomeAssistant, entry: QuicHarcConfigEntry) -> bool:
    """Set up QuicHarc from a config entry, as one trace."""
    telemetry = await async_get_telemetry(hass)
    _async_configure_telemetry(telemetry, entry)
    with telemetry.span(
        "integration.setup",
        root=True,
        attributes={"quicharc.home_id": entry.data.get(CONF_HOME_ID)},
    ) as span:
        return await _async_setup_entry(hass, entry, telemetry, span)


@callback
def _async_configure_telemetry(
    telemetry: Telemetry, entry: QuicHarcConfigEntry
) -> None:
    """Apply the entry's environment and home id."""
    telemetry.async_configure(
        environment=entry.data.get(CONF_ENVIRONMENT, DEFAULT_ENVIRONMENT),
    )
    if home_id := entry.data.get(CONF_HOME_ID):
        telemetry.attributes["quicharc.home_id"] = home_id


async def _async_setup_entry(
    hass: HomeAssistant,
    entry: QuicHarcConfigEntry,
    telemetry: Telemetry,
    span: AnySpan,
) -> bool:
    # An entry keeps the environment it signed in to, whatever new sign-ins use.
    async_register_implementation(
        hass, ENVIRONMENTS[entry.data.get(CONF_ENVIRONMENT, DEFAULT_ENVIRONMENT)]
    )
    implementation = (
        await config_entry_oauth2_flow.async_get_config_entry_implementation(
            hass, entry
        )
    )
    oauth_session = config_entry_oauth2_flow.OAuth2Session(hass, entry, implementation)
    try:
        await oauth_session.async_ensure_token_valid()
    except ClientResponseError as err:
        if 400 <= err.status < 500:
            raise ConfigEntryAuthFailed("Ezlo session expired") from err
        raise ConfigEntryNotReady(str(err)) from err
    except ClientError as err:
        raise ConfigEntryNotReady(str(err)) from err

    env = ENVIRONMENTS[entry.data.get(CONF_ENVIRONMENT, DEFAULT_ENVIRONMENT)]
    api = QuicHarcApi(async_get_clientsession(hass), oauth_session, env.api_base)
    data_dir = Path(hass.config.path(DATA_DIR_NAME))

    async def agent_download_token() -> str:
        try:
            return (await api.async_access_token())["access_token"]
        except (QuicHarcApiError, QuicHarcConnectionError) as err:
            raise AgentBinaryError(f"can't authenticate the download: {err}") from err

    binary = AgentBinary(
        hass, data_dir, base_url=f"{env.api_base}/agent", auth=agent_download_token
    )
    runtime = QuicHarcRuntime(hass, entry, api, data_dir, binary, telemetry)
    entry.runtime_data = runtime
    await runtime.async_start()
    entry.async_on_unload(runtime.async_stop)

    async def _on_stop(_event: Event) -> None:
        # Home Assistant doesn't unload entries when it stops; shut the agent
        # down cleanly so it closes its edge links instead of being cut off.
        await runtime.async_stop()

    # Not async_listen_once: its remover logs an error when called after the
    # event has fired, as an unload after the stop event would.
    entry.async_on_unload(hass.bus.async_listen(EVENT_HOMEASSISTANT_STOP, _on_stop))

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    span.set_attribute(
        "quicharc.ice_servers.registered",
        _async_register_ice_servers(hass, entry, runtime),
    )
    hass.async_create_task(
        discovery.async_load_platform(
            hass,
            Platform.NOTIFY,
            DOMAIN,
            {CONF_NAME: DOMAIN, "entry_id": entry.entry_id},
            {},
        )
    )

    if entry.data.get(CONF_EDIT_HTTP_CONFIG):
        status = await async_ensure_http_config(hass)
        restart = bool(entry.data.get(CONF_RESTART_AFTER_HTTP_EDIT))
        hass.config_entries.async_update_entry(
            entry,
            data={
                **entry.data,
                CONF_EDIT_HTTP_CONFIG: False,
                CONF_RESTART_AFTER_HTTP_EDIT: False,
            },
        )
        # "Change it and restart now": only if a change was made that needs it.
        if restart and status is http_config.Status.EDITABLE:
            _async_restart_for_http(hass, telemetry)
    entry.async_on_unload(entry.add_update_listener(_async_options_updated))

    async def _after_start(_hass: HomeAssistant) -> None:
        await async_after_start(hass)

    entry.async_on_unload(async_at_started(hass, _after_start))
    return True


@callback
def _async_restart_for_http(hass: HomeAssistant, telemetry: Telemetry) -> None:
    """Restart Home Assistant so the HTTP change applies, as the user asked."""

    async def _restart(_hass: HomeAssistant) -> None:
        with telemetry.span("http_config.restart_now", root=True):
            _LOGGER.info("Restarting Home Assistant to apply the HTTP settings")
            await hass.services.async_call("homeassistant", "restart")

    # Once Home Assistant has started (at once from the config flow), and
    # not tied to the entry, whose tasks the restart cancels.
    async_at_started(hass, _restart)


async def _async_options_updated(
    hass: HomeAssistant, entry: QuicHarcConfigEntry
) -> None:
    entry.runtime_data.async_notify()


def _async_register_ice_servers(
    hass: HomeAssistant, entry: QuicHarcConfigEntry, runtime: QuicHarcRuntime
) -> bool:
    """Offer QuicHarc's TURN relay to Home Assistant's WebRTC cameras."""
    from homeassistant.components.web_rtc import (
        async_register_ice_servers,
    )

    with runtime.telemetry.span("ice_servers.register") as span:
        try:
            entry.async_on_unload(async_register_ice_servers(hass, runtime.ice_servers))
        except KeyError:
            span.set_attribute("quicharc.ice_servers.registered", False)
            _LOGGER.debug("WebRTC isn't loaded; not registering ICE servers")
            return False
        span.set_attribute("quicharc.ice_servers.registered", True)
        return True


async def async_unload_entry(hass: HomeAssistant, entry: QuicHarcConfigEntry) -> bool:
    """Unload a config entry; telemetry sends what it holds and stops."""
    unloaded = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unloaded:
        telemetry = entry.runtime_data.telemetry
        await telemetry.async_final_flush()
        telemetry.async_shutdown()
    return unloaded


async def async_remove_entry(hass: HomeAssistant, entry: QuicHarcConfigEntry) -> None:
    """Delete the tokens this entry minted and unregister the home."""
    store: Store[dict] = Store(hass, STORAGE_VERSION, f"{DOMAIN}.{entry.entry_id}")
    if stored := await store.async_load():
        for device in (stored.get("devices") or {}).values():
            remove_token(hass, device.get("refresh_token_id"))
        for token_id in (stored.get("service_tokens") or {}).values():
            remove_token(hass, token_id)
    await store.async_remove()

    home_id = entry.data.get("home_id")
    if not home_id:
        return
    telemetry = await async_get_telemetry(hass)
    with telemetry.span(
        "integration.remove", root=True, attributes={"quicharc.home_id": home_id}
    ) as span:
        await _async_unregister_home(hass, entry, home_id, span)
    await telemetry.async_final_flush()
    telemetry.async_shutdown()


async def _async_unregister_home(
    hass: HomeAssistant, entry: QuicHarcConfigEntry, home_id: str, span: AnySpan
) -> None:
    try:
        implementation = (
            await config_entry_oauth2_flow.async_get_config_entry_implementation(
                hass, entry
            )
        )
        session = config_entry_oauth2_flow.OAuth2Session(hass, entry, implementation)
        env = ENVIRONMENTS[entry.data.get(CONF_ENVIRONMENT, DEFAULT_ENVIRONMENT)]
        await QuicHarcApi(
            async_get_clientsession(hass), session, env.api_base
        ).async_delete_home(home_id)
    except (
        QuicHarcApiError,
        QuicHarcConnectionError,
        ClientError,
        ValueError,
        HomeAssistantError,
    ) as err:
        span.record_exception(err)
        _LOGGER.warning("Couldn't unregister home %s: %s", home_id, err)
    else:
        _LOGGER.info("Unregistered home %s", home_id)


def _runtime(hass: HomeAssistant) -> QuicHarcRuntime:
    for entry in hass.config_entries.async_loaded_entries(DOMAIN):
        return entry.runtime_data
    raise ServiceValidationError(
        translation_domain=DOMAIN, translation_key="not_loaded"
    )


def _async_register_services(hass: HomeAssistant) -> None:
    async def approve(call: ServiceCall) -> None:
        runtime = _runtime(hass)
        user_id = call.data.get(CONF_HA_USER_ID) or runtime.entry.data.get(
            CONF_HA_USER_ID
        )
        try:
            await runtime.pairing.async_approve(call.data["device_id"], user_id)
        except PairingError as err:
            raise HomeAssistantError(str(err)) from err

    async def deny(call: ServiceCall) -> None:
        try:
            await _runtime(hass).pairing.async_deny(call.data["device_id"])
        except PairingError as err:
            raise HomeAssistantError(str(err)) from err

    async def revoke(call: ServiceCall) -> None:
        await _runtime(hass).pairing.async_revoke(call.data["device_id"])

    # Admin only: approving mints a Home Assistant token for any user.
    async_register_admin_service(
        hass,
        DOMAIN,
        SERVICE_APPROVE,
        approve,
        schema=vol.Schema(
            {
                vol.Required("device_id"): cv.string,
                vol.Optional(CONF_HA_USER_ID): cv.string,
            }
        ),
    )
    async_register_admin_service(
        hass,
        DOMAIN,
        SERVICE_DENY,
        deny,
        schema=vol.Schema({vol.Required("device_id"): cv.string}),
    )
    async_register_admin_service(
        hass,
        DOMAIN,
        SERVICE_REVOKE,
        revoke,
        schema=vol.Schema({vol.Required("device_id"): cv.string}),
    )
