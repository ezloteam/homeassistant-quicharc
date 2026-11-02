"""Apply the HTTP configuration edit and raise the matching repair issues."""

from __future__ import annotations

import logging

from ruamel.yaml.error import YAMLError

from homeassistant.core import HomeAssistant
from homeassistant.helpers import issue_registry as ir

from . import http_config, http_store
from .const import DOMAIN, ISSUE_HTTP_CONFIG_MANUAL, ISSUE_RESTART_REQUIRED
from .issues import async_clear, async_raise
from .otel import AnySpan, async_get_telemetry
from .otel.logs import NOT_EXPORTED

_LOGGER = logging.getLogger(__name__)

# Set when this process staged or wrote a change that needs a restart, so the
# restart issue survives a reload of the entry but not a real restart.
DATA_RESTART_NEEDED = f"{DOMAIN}_http_restart_needed"


async def async_ensure_http_config(hass: HomeAssistant) -> http_config.Status:
    """Make Home Assistant trust the agent's forwarded headers, if it doesn't yet.

    From Home Assistant 2026.8 the change is staged in the HTTP config store
    (http_store); before that, configuration.yaml (or its http include) is
    edited when that is safe. Either way a restart is asked for; otherwise an
    issue explains what to change by hand.
    """
    telemetry = await async_get_telemetry(hass)
    with telemetry.span("http_config.ensure") as span:
        status = await _async_ensure(hass, span)
        span.set_attribute("quicharc.http_config.status", status.value)
        return status


async def _async_ensure(hass: HomeAssistant, span: AnySpan) -> http_config.Status:
    if (store := await http_store.async_get_store(hass)) is not None:
        span.set_attribute("quicharc.http_config.model", "storage")
        status, reason = await http_store.async_stage(hass, store)
        span.set_attribute("quicharc.http_config.reason", reason)
        if status is http_config.Status.MANUAL:
            _raise_manual(hass, reason or "unknown")
        elif status is http_config.Status.EDITABLE:
            _ask_restart(hass)
        else:
            async_clear(hass, ISSUE_HTTP_CONFIG_MANUAL)
        return status

    span.set_attribute("quicharc.http_config.model", "yaml")
    plan = await http_config.async_plan(hass)
    span.set_attribute("quicharc.http_config.reason", plan.reason)
    if plan.status is http_config.Status.ALREADY_TRUSTED:
        async_clear(hass, ISSUE_HTTP_CONFIG_MANUAL)
        return plan.status

    if plan.status is http_config.Status.EDITABLE:
        try:
            await http_config.async_apply(hass, plan)
        except http_config.EditFailed as err:
            _raise_manual(hass, str(err))
            return http_config.Status.MANUAL
        except (OSError, YAMLError) as err:
            _raise_manual(hass, f"the file couldn't be edited: {err}")
            return http_config.Status.MANUAL
        _ask_restart(hass)
        return plan.status

    _raise_manual(hass, plan.reason or "unknown")
    return plan.status


def _ask_restart(hass: HomeAssistant) -> None:
    hass.data[DATA_RESTART_NEEDED] = True
    async_clear(hass, ISSUE_HTTP_CONFIG_MANUAL)
    async_raise(
        hass,
        ISSUE_RESTART_REQUIRED,
        is_fixable=True,
        severity=ir.IssueSeverity.WARNING,
        translation_key=ISSUE_RESTART_REQUIRED,
    )


async def async_after_start(hass: HomeAssistant) -> None:
    """Finish the HTTP change once Home Assistant has (re)started.

    Clears the restart issue unless the change was made in this process, and
    on 2026.8+ promotes QuicHarc's staged config so it isn't reverted.
    """
    telemetry = await async_get_telemetry(hass)
    with telemetry.span("http_config.after_start") as span:
        restart_needed = bool(hass.data.get(DATA_RESTART_NEEDED))
        span.set_attribute("quicharc.http_config.restart_needed", restart_needed)
        if not restart_needed:
            async_clear(hass, ISSUE_RESTART_REQUIRED)
        promoted = await http_store.async_promote_if_ours(hass)
        span.set_attribute("quicharc.http_config.promoted", promoted)
        if promoted:
            async_clear(hass, ISSUE_HTTP_CONFIG_MANUAL)


def _raise_manual(hass: HomeAssistant, reason: str) -> None:
    # The reason can quote configuration check output, so it stays local.
    _LOGGER.warning(
        "Can't edit the HTTP configuration automatically: %s",
        reason,
        extra=NOT_EXPORTED,
    )
    _LOGGER.warning("The HTTP configuration needs a manual change (repair raised)")
    async_raise(
        hass,
        ISSUE_HTTP_CONFIG_MANUAL,
        is_fixable=False,
        severity=ir.IssueSeverity.WARNING,
        translation_key=ISSUE_HTTP_CONFIG_MANUAL,
        translation_placeholders={"reason": reason, "snippet": http_config.SNIPPET},
    )
