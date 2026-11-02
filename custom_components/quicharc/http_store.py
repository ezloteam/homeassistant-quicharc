"""Trust the agent's forwarded headers through Home Assistant's HTTP config store.

From Home Assistant 2026.8 the HTTP settings live in storage, not YAML: a
`stable` config, and a `pending` one that is tried at the next start and
reverted after five minutes unless it is promoted. YAML `http:` is migrated
once and ignored afterwards. On those releases the integration stages its
change as `pending`, asks for a restart, and promotes the change once Home
Assistant is up and accepts X-Forwarded-For from loopback, but only when the
pending config is exactly the stable one plus QuicHarc's change.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import TYPE_CHECKING, Any, Final

import aiohttp

from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .http_config import LOOPBACK, Status
from .otel import child_span, current_span

if TYPE_CHECKING:
    from homeassistant.components.http.config import HTTPConfigStore

_LOGGER = logging.getLogger(__name__)

_META: Final = ("created_at", "error", "error_message")


async def async_get_store(hass: HomeAssistant) -> HTTPConfigStore | None:
    """Return Home Assistant's HTTP config store, or None before 2026.8."""
    try:
        from homeassistant.components.http.config import (
            async_get_and_load_store,
        )
    except ImportError:
        return None
    return await async_get_and_load_store(hass)


def _strip(config: dict[str, Any] | None) -> dict[str, Any]:
    return {k: v for k, v in (config or {}).items() if k not in _META}


def _covers(proxies: list[str], addr: str) -> bool:
    ip = ipaddress.ip_address(addr)
    for entry in proxies:
        try:
            if ip in ipaddress.ip_network(entry, strict=False):
                return True
        except ValueError:
            continue
    return False


def is_trusting(config: dict[str, Any] | None) -> bool:
    """Return True if the config accepts X-Forwarded-For from loopback."""
    if not config or not config.get("use_x_forwarded_for"):
        return False
    proxies = list(config.get("trusted_proxies") or [])
    return all(_covers(proxies, addr) for addr in LOOPBACK)


def with_trust(stable: dict[str, Any]) -> dict[str, Any]:
    """Return stable plus QuicHarc's change, without metadata."""
    config = _strip(stable)
    proxies = list(config.get("trusted_proxies") or [])
    for addr in LOOPBACK:
        if not _covers(proxies, addr):
            proxies.append(addr)
    config["use_x_forwarded_for"] = True
    config["trusted_proxies"] = proxies
    return config


def running_config(store: HTTPConfigStore) -> dict[str, Any]:
    """Return the config the running HTTP server was started with."""
    from homeassistant.components.http.config import (
        ActiveConfigType,
    )

    if store.active_config_type is ActiveConfigType.PENDING and store.pending:
        return store.pending
    return store.stable


def _pending_is_ours(store: HTTPConfigStore) -> bool:
    pending = store.pending
    return (
        pending is not None
        and pending.get("error") is None
        and _strip(pending) == with_trust(store.stable)
    )


async def async_stage(
    hass: HomeAssistant, store: HTTPConfigStore
) -> tuple[Status, str | None]:
    """Stage the change as pending; return the status and, if manual, why."""
    if is_trusting(running_config(store)):
        return Status.ALREADY_TRUSTED, None
    if _pending_is_ours(store):
        return Status.EDITABLE, None
    pending = store.pending
    if pending is not None and pending.get("error") is None:
        return (
            Status.MANUAL,
            "another HTTP configuration change is waiting for a restart",
        )
    try:
        await store.async_set_pending(with_trust(store.stable))
    except HomeAssistantError as err:
        return Status.MANUAL, f"the HTTP configuration couldn't be saved: {err}"
    _LOGGER.info("Staged an HTTP configuration that trusts the QuicHarc agent")
    return Status.EDITABLE, None


async def async_self_test(hass: HomeAssistant) -> bool:
    """Return True if Home Assistant accepts X-Forwarded-For from loopback.

    Home Assistant answers a forwarded request from an untrusted proxy with
    400, like the agent's own check.
    """
    port = hass.http.server_port if hass.http is not None else 8123
    scheme = "https" if hass.http is not None and hass.http.ssl_certificate else "http"
    session = async_get_clientsession(hass, verify_ssl=False)
    with child_span("http_config.self_test") as span:
        try:
            async with session.get(
                f"{scheme}://127.0.0.1:{port}/manifest.json",
                headers={"X-Forwarded-For": "203.0.113.7"},
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                span.set_attribute("http.response.status_code", resp.status)
                trusted = resp.status != 400
        except aiohttp.ClientError, TimeoutError:
            trusted = False
        span.set_attribute("quicharc.http_config.trusted", trusted)
        return trusted


async def async_promote_if_ours(hass: HomeAssistant) -> bool:
    """Promote QuicHarc's pending config once it is running and works.

    Without promotion Home Assistant reverts the trial after five minutes.
    """
    store = await async_get_store(hass)
    if store is None:
        return False
    from homeassistant.components.http.config import (
        ActiveConfigType,
    )

    if (span := current_span()) is not None:
        span.set_attributes(
            {
                "quicharc.http_config.active": str(store.active_config_type),
                "quicharc.http_config.pending": store.pending is not None,
                "quicharc.http_config.pending_error": str(
                    (store.pending or {}).get("error") or ""
                )
                or None,
            }
        )
    if store.active_config_type is not ActiveConfigType.PENDING or not _pending_is_ours(
        store
    ):
        return False
    if not await async_self_test(hass):
        if (span := current_span()) is not None:
            span.add_event("http_config.left_for_auto_revert")
        _LOGGER.warning(
            "The staged HTTP configuration is running but forwarded headers are "
            "still refused; leaving it to Home Assistant's automatic revert"
        )
        return False
    try:
        with child_span("http_config.promote"):
            await store.async_promote_pending()
    except HomeAssistantError as err:
        _LOGGER.warning("Couldn't promote the HTTP configuration: %s", err)
        return False
    _LOGGER.info("Promoted the HTTP configuration that trusts the QuicHarc agent")
    return True
