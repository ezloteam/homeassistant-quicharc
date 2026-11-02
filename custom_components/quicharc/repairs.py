"""Repair flows: pairing requests, the restart after the HTTP edit, identity conflicts."""

from __future__ import annotations

from typing import Any

from homeassistant.components.repairs import ConfirmRepairFlow, RepairsFlow
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResult
from homeassistant.helpers import issue_registry as ir
from homeassistant.helpers.selector import (
    SelectOptionDict,
    SelectSelector,
    SelectSelectorConfig,
)

from .agent_client import AgentError
from .const import (
    CONF_HA_USER_ID,
    DOMAIN,
    ISSUE_IDENTITY_CONFLICT,
    ISSUE_PAIRING_PREFIX,
    ISSUE_RESTART_REQUIRED,
)
from .otel import async_get_telemetry
from .pairing import PairingError, request_placeholders
from .schema import vol
from .tokens import async_selectable_users

ACTION = "action"
APPROVE = "approve"
DENY = "deny"
RECLAIM = "reclaim"
LEAVE = "leave"


class PairingRepairFlow(RepairsFlow):
    """Let an administrator approve a device and pick its Home Assistant user."""

    def __init__(self, request_id: str) -> None:
        """Initialize."""
        self._request_id = request_id

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Show the decision form."""
        entries = self.hass.config_entries.async_loaded_entries(DOMAIN)
        if not entries:
            return self.async_abort(reason="not_loaded")
        runtime = entries[0].runtime_data
        request = runtime.pairing.pending.get(self._request_id)
        if request is None:
            return self.async_abort(reason="request_gone")

        errors: dict[str, str] = {}
        if user_input and ACTION in user_input:
            try:
                if user_input[ACTION] == APPROVE:
                    await runtime.pairing.async_approve(
                        self._request_id, user_input[CONF_HA_USER_ID]
                    )
                else:
                    await runtime.pairing.async_deny(self._request_id)
            except PairingError:
                errors["base"] = "pairing_failed"
            else:
                return self.async_create_entry(data={})

        users = [
            SelectOptionDict(value=user.id, label=user.name or user.id)
            for user in await async_selectable_users(self.hass)
        ]
        default_user = runtime.entry.data.get(CONF_HA_USER_ID)
        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Required(ACTION, default=APPROVE): SelectSelector(
                        SelectSelectorConfig(
                            options=[APPROVE, DENY], translation_key="pairing_action"
                        )
                    ),
                    vol.Required(
                        CONF_HA_USER_ID,
                        default=default_user or (users[0]["value"] if users else ""),
                    ): SelectSelector(SelectSelectorConfig(options=users)),
                }
            ),
            errors=errors,
            description_placeholders=request_placeholders(request),
        )


class RestartRepairFlow(ConfirmRepairFlow):
    """Restart Home Assistant so the HTTP configuration takes effect."""

    async def async_step_confirm(
        self, user_input: dict[str, str] | None = None
    ) -> FlowResult:
        """Restart on confirmation."""
        if user_input is not None:
            telemetry = await async_get_telemetry(self.hass)
            with telemetry.span("repair.restart_confirmed"):
                await self.hass.services.async_call("homeassistant", "restart")
            return self.async_create_entry(data={})
        return self.async_show_form(step_id="confirm")


class IdentityConflictRepairFlow(RepairsFlow):
    """Choose which installation keeps the home's remote access."""

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Show the choice."""
        entries = self.hass.config_entries.async_loaded_entries(DOMAIN)
        if not entries:
            return self.async_abort(reason="not_loaded")
        runtime = entries[0].runtime_data
        if not runtime.state.identity_conflict:
            return self.async_abort(reason="conflict_gone")

        errors: dict[str, str] = {}
        if user_input and ACTION in user_input:
            if user_input[ACTION] == LEAVE:
                # Dismissed, not deleted: it's deleted when the conflict ends.
                ir.async_ignore_issue(
                    self.hass, DOMAIN, ISSUE_IDENTITY_CONFLICT, ignore=True
                )
                return self.async_abort(reason="left_on_other")
            try:
                await runtime.async_reclaim_identity()
            except AgentError:
                errors["base"] = "reclaim_failed"
            else:
                return self.async_create_entry(data={})

        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Required(ACTION, default=RECLAIM): SelectSelector(
                        SelectSelectorConfig(
                            options=[RECLAIM, LEAVE],
                            translation_key="identity_conflict_action",
                        )
                    ),
                }
            ),
            errors=errors,
            description_placeholders={
                "node": runtime.state.identity_conflict_node or "unknown",
                "at": runtime.state.identity_conflict_at or "unknown",
            },
        )


async def async_create_fix_flow(
    hass: HomeAssistant,
    issue_id: str,
    data: dict[str, str | int | float | None] | None,
) -> RepairsFlow:
    """Return the fix flow for an issue."""
    if issue_id.startswith(ISSUE_PAIRING_PREFIX):
        return PairingRepairFlow(issue_id.removeprefix(ISSUE_PAIRING_PREFIX))
    if issue_id == ISSUE_RESTART_REQUIRED:
        return RestartRepairFlow()
    if issue_id == ISSUE_IDENTITY_CONFLICT:
        return IdentityConflictRepairFlow()
    return ConfirmRepairFlow()
