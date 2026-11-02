"""HTTP settings in Home Assistant's config store (2026.8 and later)."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from custom_components.quicharc import http_store
from custom_components.quicharc.const import (
    DOMAIN,
    ISSUE_HTTP_CONFIG_MANUAL,
    ISSUE_RESTART_REQUIRED,
)
from custom_components.quicharc.http_config import Status
from custom_components.quicharc.http_setup import (
    DATA_RESTART_NEEDED,
    async_after_start,
    async_ensure_http_config,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers import issue_registry as ir

config = pytest.importorskip("homeassistant.components.http.config")


async def _store(hass: HomeAssistant):
    store = await http_store.async_get_store(hass)
    assert store is not None
    return store


async def test_stage_pending_and_ask_restart(hass: HomeAssistant) -> None:
    """The change is staged as pending on top of stable; YAML is untouched."""
    store = await _store(hass)
    stable_before = dict(store.stable)
    assert await async_ensure_http_config(hass) is Status.EDITABLE
    assert store.pending["use_x_forwarded_for"] is True
    assert store.pending["trusted_proxies"] == ["127.0.0.1", "::1"]
    assert store.stable == stable_before
    assert ir.async_get(hass).async_get_issue(DOMAIN, ISSUE_RESTART_REQUIRED)
    # Staging again is idempotent.
    created = store.pending["created_at"]
    assert await async_ensure_http_config(hass) is Status.EDITABLE
    assert store.pending["created_at"] == created


async def test_existing_proxies_are_kept(hass: HomeAssistant) -> None:
    """Proxies already in stable stay; only missing loopback addresses are added."""
    store = await _store(hass)
    store._stable = {
        **store.stable,
        "use_x_forwarded_for": True,
        "trusted_proxies": ["127.0.0.0/8", "172.30.33.0/24"],
    }
    await async_ensure_http_config(hass)
    assert store.pending["trusted_proxies"] == ["127.0.0.0/8", "172.30.33.0/24", "::1"]


async def test_already_trusted(hass: HomeAssistant) -> None:
    """Nothing is staged when the running config already trusts loopback."""
    store = await _store(hass)
    store._stable = {
        **store.stable,
        "use_x_forwarded_for": True,
        "trusted_proxies": ["127.0.0.1", "::1"],
    }
    assert await async_ensure_http_config(hass) is Status.ALREADY_TRUSTED
    assert store.pending is None


async def test_users_own_pending_change_is_left_alone(hass: HomeAssistant) -> None:
    """Another pending change isn't overwritten; the user is told what to set."""
    store = await _store(hass)
    await store.async_set_pending(
        {**http_store._strip(store.stable), "server_port": 8124}
    )
    pending = dict(store.pending)
    assert await async_ensure_http_config(hass) is Status.MANUAL
    assert store.pending == pending
    issue = ir.async_get(hass).async_get_issue(DOMAIN, ISSUE_HTTP_CONFIG_MANUAL)
    assert "waiting for a restart" in issue.translation_placeholders["reason"]


async def test_promote_after_restart(hass: HomeAssistant) -> None:
    """Once running and working, QuicHarc's pending config is promoted."""
    store = await _store(hass)
    await store.async_set_pending(http_store.with_trust(store.stable))
    store._active_config_type = config.ActiveConfigType.PENDING
    with patch.object(http_store, "async_self_test", return_value=True):
        await async_after_start(hass)
    assert store.pending is None
    assert store.stable["use_x_forwarded_for"] is True
    assert ir.async_get(hass).async_get_issue(DOMAIN, ISSUE_RESTART_REQUIRED) is None


async def test_no_promotion_when_check_fails(hass: HomeAssistant) -> None:
    """A pending config that doesn't work is left to Home Assistant's revert."""
    store = await _store(hass)
    await store.async_set_pending(http_store.with_trust(store.stable))
    store._active_config_type = config.ActiveConfigType.PENDING
    with patch.object(http_store, "async_self_test", return_value=False):
        await async_after_start(hass)
    assert store.pending is not None


async def test_other_pending_config_not_promoted(hass: HomeAssistant) -> None:
    """A pending config with any other change is never promoted by QuicHarc."""
    store = await _store(hass)
    await store.async_set_pending(
        {**http_store.with_trust(store.stable), "server_port": 8124}
    )
    store._active_config_type = config.ActiveConfigType.PENDING
    with patch.object(http_store, "async_self_test", return_value=True):
        assert not await http_store.async_promote_if_ours(hass)
    assert store.pending is not None


async def test_restart_issue_kept_until_restart(hass: HomeAssistant) -> None:
    """A change made in this process keeps its restart issue across a reload."""
    await async_ensure_http_config(hass)
    assert hass.data[DATA_RESTART_NEEDED]
    await async_after_start(hass)
    assert ir.async_get(hass).async_get_issue(DOMAIN, ISSUE_RESTART_REQUIRED)
