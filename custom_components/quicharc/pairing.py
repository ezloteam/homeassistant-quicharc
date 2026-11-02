"""Device pairing and service peer tokens (sections 3.4, 5.4 and 6)."""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any

from homeassistant.components import persistent_notification
from homeassistant.core import CALLBACK_TYPE, callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import issue_registry as ir
from homeassistant.util import dt as dt_util

from .agent_client import AgentError
from .api import QuicHarcApiError, QuicHarcConnectionError
from .const import (
    CONF_AUTO_APPROVE_OWNER,
    CONF_EZLO_USER_UUID,
    CONF_HA_USER_ID,
    DOMAIN,
    ISSUE_PAIRING_PREFIX,
    SERVICE_PEER_ALIASES,
    SERVICE_PEER_CLIENT_NAMES,
)
from .issues import async_clear, async_raise
from .otel import AnySpan, SpanContext, Telemetry, child_span
from .otel.metrics import PAIRING_OUTCOMES
from .otel.trace import run_span
from .tokens import (
    TokenError,
    async_mint_device_token,
    async_mint_service_token,
    remove_token,
)

if TYPE_CHECKING:
    from .runtime import QuicHarcRuntime

_LOGGER = logging.getLogger(__name__)


MAX_PENDING = 20
_MARKDOWN = str.maketrans({c: " " for c in "[]()<>*_`#|\\!\n\r"})


def _clean(value: Any, limit: int = 64) -> str:
    """Return remote-supplied text without control characters, length-capped."""
    return " ".join("".join(c if c.isprintable() else " " for c in str(value)).split())[
        :limit
    ]


def _plain(value: Any, limit: int = 64) -> str:
    """Return remote-supplied text safe to show in markdown."""
    return " ".join(str(value).translate(_MARKDOWN).split())[:limit]


class PairingError(HomeAssistantError):
    """A pairing action failed."""


def issue_id(request_id: str) -> str:
    """Return the repair issue id for a pairing request."""
    return f"{ISSUE_PAIRING_PREFIX}{request_id}"


def request_placeholders(request: dict[str, Any]) -> dict[str, str]:
    """Return the request's display fields, stripped of markdown."""
    return {
        "device_name": _plain(request.get("device_name") or request["device_id"]),
        "ezlo_user": _plain(
            request.get("ezlo_user_email") or request.get("ezlo_user_uuid") or "?"
        ),
        "platform": _plain(request.get("platform") or ""),
    }


class PairingManager:
    """Approve, deny and revoke devices; answer service token requests."""

    def __init__(self, runtime: QuicHarcRuntime) -> None:
        """Initialize."""
        self._runtime = runtime
        self._hass = runtime.hass
        self.pending: dict[str, dict[str, Any]] = {}
        # Each pending request's span, so its approval or denial joins the
        # request's trace even when it comes from a repair flow later.
        self._traces: dict[str, SpanContext] = {}
        self._revoke_unsubs: dict[str, CALLBACK_TYPE] = {}
        self._token_lock = asyncio.Lock()

    @property
    def _telemetry(self) -> Telemetry:
        return self._runtime.telemetry

    def _trace_of(self, device_id: str) -> dict[str, Any]:
        """Return span arguments that continue a pending request's trace."""
        context = self._traces.get(device_id)
        return {"parent": context} if context is not None else {}

    def _outcome(self, outcome: str) -> None:
        self._telemetry.metrics.add(PAIRING_OUTCOMES, outcome=outcome)

    @property
    def devices(self) -> dict[str, dict[str, Any]]:
        """Return paired devices keyed by device id."""
        return self._runtime.data["devices"]

    @property
    def _revocations(self) -> dict[str, dict[str, bool]]:
        """Revocations the agent or the cloud hasn't confirmed yet."""
        return self._runtime.data.setdefault("revocations", {})

    @callback
    def async_restore(self) -> None:
        """Watch stored tokens so deleting one in Home Assistant revokes the device."""
        for device_id, device in list(self.devices.items()):
            token_id = device.get("refresh_token_id")
            if token_id and self._hass.auth.async_get_refresh_token(token_id):
                self._watch(device_id, token_id)
            else:
                # The token was deleted while we weren't running.
                self._hass.async_create_task(
                    self.async_revoke(device_id, reason="token_deleted")
                )

    @callback
    def async_unload(self) -> None:
        """Stop watching tokens and clear pending requests."""
        for unsub in self._revoke_unsubs.values():
            unsub()
        self._revoke_unsubs.clear()
        for request_id in self.pending:
            ir.async_delete_issue(self._hass, DOMAIN, issue_id(request_id))
        self.pending.clear()
        self._traces.clear()

    @callback
    def _watch(self, device_id: str, token_id: str) -> None:
        @callback
        def _revoked() -> None:
            self._revoke_unsubs.pop(device_id, None)
            if device_id in self.devices:
                _LOGGER.info("Refresh token for %s deleted; revoking device", device_id)
                self._hass.async_create_task(
                    self.async_revoke(device_id, reason="token_deleted")
                )

        self._revoke_unsubs[device_id] = (
            self._hass.auth.async_register_revoke_token_callback(token_id, _revoked)
        )

    @callback
    def async_handle_request(self, data: dict[str, Any]) -> None:
        """Handle a pairing_request event from the agent.

        Starts the pairing's trace, or continues the agent's if it sent a
        traceparent.
        """
        request_id = data.get("device_id")
        span = self._telemetry.start_span(
            "pairing.request",
            parent=SpanContext.from_traceparent(data.get("traceparent")),
            attributes={
                "quicharc.device_id": request_id
                if isinstance(request_id, str)
                else None,
                "quicharc.pairing.platform": _clean(data.get("platform") or "", 32),
                "quicharc.ezlo_user_uuid": _clean(data.get("ezlo_user_uuid") or "", 64),
                "quicharc.home_id": self._runtime.home_id,
            },
        )
        with run_span(span):
            self._async_handle_request(data, span)

    @callback
    def _async_handle_request(self, data: dict[str, Any], span: AnySpan) -> None:
        request_id = data.get("device_id")
        if not isinstance(request_id, str) or not request_id:
            span.set_error("malformed pairing request")
            _LOGGER.warning(
                "Ignoring malformed pairing request (fields %s)", sorted(data)
            )
            return
        if request_id not in self.pending and len(self.pending) >= MAX_PENDING:
            span.set_error("too many pending requests")
            _LOGGER.warning(
                "Too many pending pairing requests; ignoring %s", request_id
            )
            return
        self.pending[request_id] = data
        if span.context is not None:
            self._traces[request_id] = span.context
        entry = self._runtime.entry
        owner = entry.data.get(CONF_EZLO_USER_UUID)
        auto = bool(
            entry.options.get(CONF_AUTO_APPROVE_OWNER, True)
            and owner
            and data.get("ezlo_user_uuid") == owner
            and entry.data.get(CONF_HA_USER_ID)
        )
        span.set_attribute("quicharc.pairing.auto_approve", auto)
        if auto:
            self._runtime.entry.async_create_background_task(
                self._hass,
                self._async_auto_approve(request_id, entry.data[CONF_HA_USER_ID]),
                f"quicharc auto-approve {request_id}",
            )
            return
        _LOGGER.info("Pairing request from device %s waits for approval", request_id)
        self._async_ask(request_id)

    async def _async_auto_approve(self, request_id: str, ha_user_id: str) -> None:
        try:
            await self.async_approve(request_id, ha_user_id, auto=True)
        except PairingError as err:
            _LOGGER.warning(
                "Auto-approval of %s failed, asking instead: %s", request_id, err
            )
            if request_id in self.pending:
                self._async_ask(request_id)

    @callback
    def _async_ask(self, request_id: str) -> None:
        """Raise the repair issue and notification for a pending request."""
        data = self.pending[request_id]
        placeholders = request_placeholders(data)
        async_raise(
            self._hass,
            issue_id(request_id),
            data={"device_id": request_id},
            is_fixable=True,
            severity=ir.IssueSeverity.WARNING,
            translation_key="pairing_request",
            translation_placeholders=placeholders,
        )
        persistent_notification.async_create(
            self._hass,
            (
                f"{placeholders['device_name']} ({placeholders['ezlo_user']}) wants "
                "remote access to this Home Assistant through QuicHarc. "
                "Approve or deny it under [Settings > Repairs](/config/repairs)."
            ),
            title="QuicHarc: new device",
            notification_id=f"{DOMAIN}_{issue_id(request_id)}",
        )

    @callback
    def async_handle_cancelled(self, data: dict[str, Any]) -> None:
        """Handle a pairing_cancelled event."""
        device_id = data.get("device_id")
        if not isinstance(device_id, str):
            return
        with self._telemetry.span(
            "pairing.cancelled",
            attributes={"quicharc.device_id": device_id},
            **self._trace_of(device_id),
        ):
            if device_id in self.pending:
                self._outcome("cancelled")
            self._clear_request(device_id)

    @callback
    def _clear_request(self, request_id: str) -> None:
        self.pending.pop(request_id, None)
        self._traces.pop(request_id, None)
        async_clear(self._hass, issue_id(request_id))
        persistent_notification.async_dismiss(
            self._hass, f"{DOMAIN}_{issue_id(request_id)}"
        )

    async def async_approve(
        self, request_id: str, ha_user_id: str, *, auto: bool = False
    ) -> None:
        """Approve a pending device as a Home Assistant user.

        Pairing requests are keyed by device id, like the quicharc service's
        pairing records, so request_id is the device id.
        """
        with self._telemetry.span(
            "pairing.approve",
            attributes={
                "quicharc.device_id": request_id,
                "quicharc.pairing.auto": auto,
                "quicharc.home_id": self._runtime.home_id,
            },
            **self._trace_of(request_id),
        ) as span:
            try:
                await self._async_approve(request_id, ha_user_id, span)
            except PairingError:
                self._outcome("failed")
                raise
            self._outcome("auto_approved" if auto else "approved")

    async def _async_approve(
        self, request_id: str, ha_user_id: str, span: AnySpan
    ) -> None:
        # Taken out of pending before the first await, so a second approval
        # of the same request (double click, auto-approve racing a service
        # call) can't mint a second token.
        request = self.pending.pop(request_id, None)
        if request is None:
            raise PairingError(f"No pending pairing request {request_id}")
        device_id = request["device_id"]
        # Stored and used as the token's client name as sent (control
        # characters removed); only markdown displays get _plain().
        device_name = _clean(request.get("device_name") or device_id)
        try:
            with child_span("token.mint", attributes={"quicharc.token.kind": "device"}):
                refresh_token, token = await async_mint_device_token(
                    self._hass, ha_user_id, device_name
                )
        except (TokenError, ValueError) as err:
            self.pending[request_id] = request
            raise PairingError(str(err)) from err

        try:
            await self._runtime.supervisor.async_request(
                "device.approve",
                {"device_id": device_id, "ha_user_id": ha_user_id, "token": token},
            )
        except AgentError as err:
            remove_token(self._hass, refresh_token.id)
            self.pending[request_id] = request
            raise PairingError(f"The agent couldn't deliver the token: {err}") from err
        span.add_event("token.delivered")

        old = self.devices.get(device_id)
        span.set_attribute("quicharc.pairing.replaced_previous_token", bool(old))
        if old:
            self._forget_token(device_id, old)
            span.add_event("token.previous_removed")
        self.devices[device_id] = {
            "name": device_name,
            "platform": request.get("platform"),
            "ezlo_user_uuid": request.get("ezlo_user_uuid"),
            "ha_user_id": ha_user_id,
            "refresh_token_id": refresh_token.id,
            "paired_at": dt_util.utcnow().isoformat(),
        }
        self._watch(device_id, refresh_token.id)
        self._runtime.async_save()
        self._clear_request(request_id)
        user = await self._hass.auth.async_get_user(ha_user_id)
        await self._report(
            device_id,
            approved=True,
            ha_user_id=ha_user_id,
            ha_user_name=user.name if user else None,
        )
        _LOGGER.info("Paired device %s", device_id)
        self._runtime.async_notify()

    async def async_deny(self, request_id: str) -> None:
        """Deny a pending device."""
        with self._telemetry.span(
            "pairing.deny",
            attributes={"quicharc.device_id": request_id},
            **self._trace_of(request_id),
        ):
            request = self.pending.pop(request_id, None)
            if request is None:
                raise PairingError(f"No pending pairing request {request_id}")
            try:
                await self._runtime.supervisor.async_request(
                    "device.deny", {"device_id": request_id}
                )
            except AgentError as err:
                _LOGGER.warning("Agent didn't take the denial: %s", err)
            self._clear_request(request_id)
            await self._report(request_id, approved=False)
            self._outcome("denied")
            _LOGGER.info("Denied device %s", request_id)

    async def async_revoke(self, device_id: str, *, reason: str = "admin") -> None:
        """Revoke a paired device everywhere: token, agent and service."""
        with self._telemetry.span(
            "pairing.revoke",
            attributes={
                "quicharc.device_id": device_id,
                "quicharc.revoke.reason": reason,
            },
        ) as span:
            device = self.devices.pop(device_id, None)
            span.set_attribute("quicharc.pairing.had_token", bool(device))
            if device:
                self._forget_token(device_id, device)
            self._revocations[device_id] = {"agent": True, "cloud": True}
            self._runtime.async_save()
            await self._async_send_revocation(device_id)
            self._runtime.async_notify()
            _LOGGER.info("Revoked device %s (%s)", device_id, reason)

    async def _async_send_revocation(self, device_id: str) -> None:
        """Tell the agent and the cloud; keep whatever fails for a retry."""
        pending = self._revocations.get(device_id)
        if pending is None:
            return
        if pending.get("agent"):
            try:
                await self._runtime.supervisor.async_request(
                    "device.revoke", {"device_id": device_id}
                )
            except AgentError as err:
                _LOGGER.debug(
                    "Agent didn't take the revocation of %s: %s", device_id, err
                )
            else:
                pending["agent"] = False
        if pending.get("cloud") and self._runtime.home_id:
            try:
                await self._runtime.api.async_revoke_device(
                    self._runtime.home_id, device_id
                )
            except (QuicHarcApiError, QuicHarcConnectionError) as err:
                _LOGGER.warning(
                    "Couldn't revoke %s in the cloud yet: %s", device_id, err
                )
            else:
                pending["cloud"] = False
        if not pending.get("agent") and not pending.get("cloud"):
            self._revocations.pop(device_id, None)
        self._runtime.async_save()

    async def async_replay_revocations(self) -> None:
        """Retry revocations that didn't reach the agent or the cloud."""
        for device_id in list(self._revocations):
            await self._async_send_revocation(device_id)

    @callback
    def async_remove_service_token(self, service: str) -> None:
        """Delete the Home Assistant token a service peer holds."""
        token_id = self._runtime.data["service_tokens"].pop(service, None)
        with self._telemetry.span(
            "service_token.remove",
            attributes={
                "quicharc.service_peer": service,
                "quicharc.token.removed": token_id is not None,
            },
        ):
            remove_token(self._hass, token_id)
            self._runtime.async_save()

    @callback
    def async_remove_all_tokens(self) -> None:
        """Delete every Home Assistant token this integration created."""
        for device_id, device in list(self.devices.items()):
            self._forget_token(device_id, device)
        self.devices.clear()
        for token_id in self._runtime.data["service_tokens"].values():
            remove_token(self._hass, token_id)
        self._runtime.data["service_tokens"].clear()

    @callback
    def async_handle_revoked(self, data: dict[str, Any]) -> None:
        """A revocation arrived from the cloud: drop the device's token."""
        device_id = data.get("device_id")
        device = (
            self.devices.pop(device_id, None) if isinstance(device_id, str) else None
        )
        if device:
            self._forget_token(device_id, device)  # type: ignore[arg-type]
            self._runtime.async_save()
            _LOGGER.info("Device %s was revoked in the cloud; token deleted", device_id)

    @callback
    def _forget_token(self, device_id: str, device: dict[str, Any]) -> None:
        if unsub := self._revoke_unsubs.pop(device_id, None):
            unsub()
        remove_token(self._hass, device.get("refresh_token_id"))

    @callback
    def async_handle_token_request(self, data: dict[str, Any]) -> None:
        """A service peer the user enrolled the home with needs a token."""
        self._runtime.entry.async_create_background_task(
            self._hass,
            self._async_answer_token_request(data),
            "quicharc service token request",
        )

    async def _async_answer_token_request(self, data: dict[str, Any]) -> None:
        service = data.get("service")
        with self._telemetry.span(
            "service_token.request",
            parent=SpanContext.from_traceparent(data.get("traceparent")),
            attributes={
                "quicharc.service_peer": _clean(service, 64)
                if isinstance(service, str)
                else None,
                "quicharc.peer_id": _clean(data.get("peer_id") or "", 64),
                "quicharc.home_id": self._runtime.home_id,
            },
        ) as span:
            async with self._token_lock:
                outcome = await self._async_answer_token_request_locked(data)
            span.set_attribute("quicharc.service_token.outcome", outcome)
            if outcome != "delivered":
                span.set_error(outcome)

    async def _async_answer_token_request_locked(self, data: dict[str, Any]) -> str:
        """Answer the request; return delivered, refused:<code> or failed."""
        request_id = data.get("request_id")
        service = data.get("service")
        entry = self._runtime.entry
        user_id = entry.data.get(CONF_HA_USER_ID)
        if not isinstance(request_id, str):
            _LOGGER.warning(
                "Ignoring malformed token request (fields %s)", sorted(data)
            )
            return "malformed"
        if not isinstance(service, str):
            return await self._async_refuse_token(request_id, "bad_request")
        service = SERVICE_PEER_ALIASES.get(service, service)
        if service not in SERVICE_PEER_CLIENT_NAMES:
            _LOGGER.warning("Refusing a token to unknown service %r", service)
            return await self._async_refuse_token(request_id, "refused")
        if not user_id:
            _LOGGER.warning("No Home Assistant user configured for service tokens")
            return await self._async_refuse_token(request_id, "refused")
        if data.get("ezlo_user_uuid") != entry.data.get(CONF_EZLO_USER_UUID):
            _LOGGER.warning("Refusing %s a token for a different Ezlo user", service)
            return await self._async_refuse_token(request_id, "refused")
        try:
            with child_span(
                "token.mint", attributes={"quicharc.token.kind": "service"}
            ):
                refresh_token, token = await async_mint_service_token(
                    self._hass, user_id, service
                )
        except (TokenError, ValueError) as err:
            _LOGGER.error("Can't mint a token for %s: %s", service, err)
            return await self._async_refuse_token(request_id, "unavailable")
        try:
            await self._runtime.supervisor.async_request(
                "peer.send_token", {"request_id": request_id, "token": token}
            )
        except AgentError as err:
            remove_token(self._hass, refresh_token.id)
            _LOGGER.error("Couldn't send the token to %s: %s", service, err)
            return "failed"
        # Only now drop the token the service had, so a failed delivery never
        # leaves it without a working one.
        old = self._runtime.data["service_tokens"].get(service)
        if old != refresh_token.id:
            remove_token(self._hass, old)
        self._runtime.data["service_tokens"][service] = refresh_token.id
        self._runtime.async_save()
        _LOGGER.info("Sent a Home Assistant token to %s", service)
        return "delivered"

    async def _async_refuse_token(self, request_id: str, code: str) -> str:
        """Answer a token request with an error, so the service isn't left waiting."""
        try:
            await self._runtime.supervisor.async_request(
                "peer.send_token", {"request_id": request_id, "error": code}
            )
        except AgentError as err:
            _LOGGER.debug("Couldn't refuse token request %s: %s", request_id, err)
        return f"refused:{code}"

    async def _report(
        self,
        device_id: str,
        *,
        approved: bool,
        ha_user_id: str | None = None,
        ha_user_name: str | None = None,
    ) -> None:
        if not self._runtime.home_id:
            return
        try:
            await self._runtime.api.async_set_pairing(
                self._runtime.home_id,
                device_id,
                approved=approved,
                ha_user_id=ha_user_id,
                ha_user_name=ha_user_name,
            )
        except (QuicHarcApiError, QuicHarcConnectionError) as err:
            _LOGGER.warning("Couldn't report pairing of %s: %s", device_id, err)
