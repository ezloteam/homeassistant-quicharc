"""Ties the agent, the quicharc service and Home Assistant together."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import logging
from pathlib import Path
import time
from typing import TYPE_CHECKING, Any, Final

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import __version__ as HA_VERSION
from homeassistant.core import CALLBACK_TYPE, HomeAssistant, callback
from homeassistant.helpers import instance_id, issue_registry as ir
from homeassistant.helpers.event import async_track_point_in_utc_time
from homeassistant.helpers.storage import Store
from homeassistant.util import dt as dt_util

from .agent import AgentSupervisor
from .agent_binary import (
    AgentBinary,
    AgentBinaryError,
    UnsupportedArchitecture,
    VerificationFailed,
)
from .agent_client import AgentError
from .api import (
    ClockSkewError,
    HomeGrant,
    IceServer,
    QuicHarcApi,
    QuicHarcApiError,
    QuicHarcAuthError,
    QuicHarcConnectionError,
    SubscriptionRequired,
)
from .const import (
    CLOCK_SKEW_TOLERANCE_SECONDS,
    CONF_EZLO_USER_UUID,
    CONF_GATE_REQUIRED,
    CONF_HOME_ID,
    CONF_HOSTNAME,
    CONF_WEB_ACCESS,
    DEVICE_SYNC_PEER,
    DOMAIN,
    ISSUE_AGENT_FAILED,
    ISSUE_AGENT_VERIFY_FAILED,
    ISSUE_CLOCK_SKEW,
    ISSUE_IDENTITY_CONFLICT,
    ISSUE_SUBSCRIPTION_LAPSED,
    ISSUE_SUBSCRIPTION_REQUIRED,
    ISSUE_UNSUPPORTED_ARCH,
    SERVICE_PEER_ALIASES,
)
from .issues import active_issues, async_clear, async_raise
from .lan import LanAdvertiser
from .otel import AnySpan, SpanContext, Telemetry
from .otel.metrics import AGENT_CONNECTED, REPAIRS_ACTIVE
from .otel.otlp import MetricPoint
from .pairing import PairingManager
from .tokens import ha_url

if TYPE_CHECKING:
    from webrtc_models import RTCIceServer

_LOGGER = logging.getLogger(__name__)

STORAGE_VERSION: Final = 1
RETRY_DELAY: Final = timedelta(minutes=5)
MIN_REFRESH_DELAY: Final = timedelta(minutes=1)


@dataclass(slots=True)
class AgentState:
    """What the agent last reported."""

    edge: str = "disconnected"
    edge_nodes: list[dict[str, Any]] = field(default_factory=list)
    peers: list[dict[str, Any]] = field(default_factory=list)
    forwarded_headers_trusted: bool = False
    lan_port: int | None = None
    # Another installation holds this home's edge link (the keys are absent
    # from the state when there is no conflict).
    identity_conflict: bool = False
    identity_conflict_node: str | None = None
    identity_conflict_at: str | None = None

    def update(self, data: dict[str, Any]) -> None:
        """Apply a state event."""
        self.edge = str(data.get("edge", self.edge))
        self.edge_nodes = list(data.get("edge_nodes") or [])
        self.peers = list(data.get("peers") or [])
        self.forwarded_headers_trusted = bool(
            data.get("forwarded_headers_trusted", False)
        )
        # lan_port per agent-v0.2.1; peer_port was the draft name.
        port = data.get("lan_port", data.get("peer_port"))
        self.lan_port = port if isinstance(port, int) and 0 < port < 65536 else None
        self.identity_conflict = data.get("identity_conflict") is True
        node = data.get("identity_conflict_node")
        at = data.get("identity_conflict_at")
        self.identity_conflict_node = (
            str(node) if self.identity_conflict and node else None
        )
        self.identity_conflict_at = str(at) if self.identity_conflict and at else None

    @property
    def edge_rtt_ms(self) -> float | None:
        """Return the best round-trip time among connected edge nodes."""
        rtts = [
            float(node["rtt_ms"])
            for node in self.edge_nodes
            if node.get("connected") and node.get("rtt_ms") is not None
        ]
        return min(rtts) if rtts else None

    @property
    def device_peers(self) -> list[dict[str, Any]]:
        """Return connected native devices."""
        return [peer for peer in self.peers if peer.get("kind") == "device"]

    @property
    def active_path(self) -> str:
        """Return the best path in use by any device: lan, direct, relay or none."""
        paths = {peer.get("path") for peer in self.device_peers}
        for path in ("lan", "direct", "relay"):
            if path in paths:
                return path
        return "none"


class QuicHarcRuntime:
    """Runtime state for one config entry."""

    def __init__(
        self,
        hass: HomeAssistant,
        entry: ConfigEntry,
        api: QuicHarcApi,
        data_dir: Path,
        binary: AgentBinary,
        telemetry: Telemetry,
    ) -> None:
        """Initialize."""
        self.hass = hass
        self.entry = entry
        self.api = api
        self.telemetry = telemetry
        self.data_dir = data_dir
        self.binary = binary
        self.store: Store[dict[str, Any]] = Store(
            hass, STORAGE_VERSION, f"{DOMAIN}.{entry.entry_id}"
        )
        self.data: dict[str, Any] = {"devices": {}, "service_tokens": {}}
        self.state = AgentState()
        self.home_config: HomeGrant | None = None
        self.device_sync: bool | None = None
        self.home_public_key: str | None = None
        self.home_key_fingerprint: str | None = None
        self.last_refresh: datetime | None = None
        self.last_refresh_error: str | None = None
        self.pairing = PairingManager(self)
        self.lan = LanAdvertiser(hass)
        self._lan_lock = asyncio.Lock()
        self._lan_key: tuple[str | None, str | None, int | None] | None = None
        self.supervisor = AgentSupervisor(
            hass,
            data_dir,
            self.binary,
            telemetry=telemetry,
            on_event=self._on_event,
            on_connected=self._async_on_connected,
            on_failure=self._on_agent_failure,
            on_recovered=self._on_agent_recovered,
            on_disconnected=self._on_agent_disconnected,
        )
        self._listeners: list[CALLBACK_TYPE] = []
        self._unsub_refresh: CALLBACK_TYPE | None = None
        self._unsub_gauges: list[Callable[[], None]] = []
        self._stopped = False

    @property
    def home_id(self) -> str | None:
        """Return the registered home id."""
        return self.entry.data.get(CONF_HOME_ID)

    @property
    def web_access(self) -> bool:
        """Return whether web access is on."""
        if self.home_config is not None:
            return self.home_config.web_access
        return bool(self.entry.options.get(CONF_WEB_ACCESS, False))

    @property
    def gate_required(self) -> bool:
        """Return whether browsers must pass the Ezlo sign-in gate."""
        if self.home_config is not None:
            return self.home_config.gate_required
        return bool(self.entry.options.get(CONF_GATE_REQUIRED, False))

    @property
    def web_url(self) -> str | None:
        """Return the web address while web access is usable, else None.

        Usable means the switch is on and the current grant carries the web
        scope; the edge only proxies web traffic for such a grant.
        """
        config = self.home_config
        if config is None or not self.web_access or "web" not in config.scopes:
            return None
        hostname = config.hostname or self.entry.data.get("hostname")
        return f"https://{hostname}" if hostname else None

    async def async_start(self) -> None:
        """Load state and start the agent."""
        if stored := await self.store.async_load():
            self.data.update(stored)
        self._unsub_gauges = [
            self.telemetry.metrics.register_gauge(
                AGENT_CONNECTED,
                lambda: [MetricPoint({}, int(self.supervisor.connected))],
            ),
            self.telemetry.metrics.register_gauge(
                REPAIRS_ACTIVE, lambda: active_issues(self.hass)
            ),
        ]
        self.pairing.async_restore()
        self.supervisor.start()

    async def async_stop(self) -> None:
        """Stop the agent and timers. Safe to call twice (stop event, then unload)."""
        if self._stopped:
            return
        self._stopped = True
        if self._unsub_refresh:
            self._unsub_refresh()
            self._unsub_refresh = None
        for unsub in self._unsub_gauges:
            unsub()
        self._unsub_gauges = []
        self.pairing.async_unload()
        await self.supervisor.async_stop()
        async with self._lan_lock:
            await self.lan.async_stop()

    @callback
    def async_save(self) -> None:
        """Persist device and token bookkeeping."""
        self.store.async_delay_save(lambda: self.data, 1)

    @callback
    def async_add_listener(self, update: CALLBACK_TYPE) -> Callable[[], None]:
        """Register an entity update callback."""
        self._listeners.append(update)
        return lambda: self._listeners.remove(update)

    @callback
    def async_notify(self) -> None:
        """Tell entities something changed, and keep the LAN announcement current."""
        for update in list(self._listeners):
            update()
        lan_key = (
            self.home_id if self.supervisor.connected else None,
            self.home_key_fingerprint,
            self.state.lan_port,
        )
        if not self._stopped and lan_key != self._lan_key:
            self._lan_key = lan_key
            self.entry.async_create_background_task(
                self.hass, self._async_update_lan(), "quicharc lan announcement"
            )

    async def _async_update_lan(self) -> None:
        """Announce _quicharc._udp while the agent runs and the home is registered."""
        async with self._lan_lock:
            if self._stopped:
                return
            running = self.supervisor.connected
            await self.lan.async_update(
                self.home_id if running else None,
                self.home_key_fingerprint,
                self.state.lan_port,
            )

    async def _async_on_connected(self) -> None:
        """Run after every (re)connection to the agent."""
        key = await self.supervisor.async_request("home_key.get")
        self.home_public_key = key["public_key"]
        self.home_key_fingerprint = key.get("fingerprint")
        self.async_notify()
        await self.async_refresh_config()
        await self.pairing.async_replay_revocations()

    async def _async_proof(self, purpose: str, key_id: str) -> tuple[int, str]:
        """Have the agent sign a proof of possession of the home key.

        The agent builds the quicharc-proof-v1 message itself from these
        fields and its own public key, so the home key signs nothing else.
        """
        ts = int(time.time())
        result = await self.supervisor.async_request(
            "home_key.proof",
            {
                "purpose": purpose,
                "caller": self.entry.data[CONF_EZLO_USER_UUID],
                "key_id": key_id,
                "ts": ts,
            },
        )
        return ts, result["proof"]

    async def _async_register(self) -> None:
        with self.telemetry.span("home.register") as span:
            await self._async_register_home(span)

    async def _async_register_home(self, span: AnySpan) -> None:
        assert self.home_public_key is not None
        span.set_attribute("quicharc.home_key.fingerprint", self.home_key_fingerprint)
        proof_ts, proof = await self._async_proof("register-home", "-")
        registration = await self.api.async_register_home(
            public_key=self.home_public_key,
            proof_ts=proof_ts,
            proof=proof,
            name=self.hass.config.location_name,
            agent_version=self.supervisor.agent_version or self.binary.version or "",
            ha_version=HA_VERSION,
            ha_instance_id=await instance_id.async_get(self.hass),
        )
        self.hass.config_entries.async_update_entry(
            self.entry,
            data={
                **self.entry.data,
                CONF_HOME_ID: registration.home_id,
                CONF_HOSTNAME: registration.hostname,
            },
        )
        span.set_attribute("quicharc.home_id", registration.home_id)
        self.telemetry.attributes["quicharc.home_id"] = registration.home_id
        _LOGGER.info("Registered home %s", registration.home_id)

    async def async_refresh_config(self, _now: datetime | None = None) -> None:
        """Refresh the home's grant and hand it, with edges and ICE servers, to the agent.

        A scheduled refresh starts its own trace; one caused by something
        else (agent start, web access change) is part of that trace.
        """
        with self.telemetry.span(
            "grant.refresh",
            root=_now is not None,
            attributes={"quicharc.trigger": "schedule" if _now else None},
        ) as span:
            await self._async_refresh_config(span)

    async def _async_refresh_config(self, span: AnySpan) -> None:
        if self._unsub_refresh:
            self._unsub_refresh()
            self._unsub_refresh = None
        if self._stopped:
            return
        next_refresh = dt_util.utcnow() + RETRY_DELAY
        try:
            if self.home_public_key is None:
                return
            if self.home_id is None:
                await self._async_register()
            assert self.home_id is not None
            proof_ts, proof = await self._async_proof("home-grant", self.home_id)
            grant = await self.api.async_issue_home_grant(
                self.home_id,
                proof_ts=proof_ts,
                proof=proof,
                agent_version=self.supervisor.agent_version,
                ha_version=HA_VERSION,
            )
        except QuicHarcAuthError as err:
            self.last_refresh_error = str(err)
            span.set_error(f"reauth: {err}")
            _LOGGER.warning("Ezlo session is no longer valid: %s", err)
            self.entry.async_start_reauth(self.hass)
        except SubscriptionRequired as err:
            self.last_refresh_error = str(err)
            span.set_error(f"not entitled: {err}")
            span.set_attribute("quicharc.entitlement", err.entitlement)
            self._raise_subscription_issue(err)
        except ClockSkewError as err:
            self.last_refresh_error = str(err)
            span.set_error(f"clock skew: {err}")
            self._raise_clock_skew(self.api.clock_skew)
        except (
            AgentError,
            QuicHarcApiError,
            QuicHarcConnectionError,
            ValueError,
            KeyError,
        ) as err:
            self.last_refresh_error = str(err)
            span.record_exception(err)
            _LOGGER.warning("Can't refresh the QuicHarc grant: %s", err)
        else:
            self.home_config = grant
            self.last_refresh = dt_util.utcnow()
            self.last_refresh_error = None
            async_clear(self.hass, ISSUE_SUBSCRIPTION_LAPSED)
            async_clear(self.hass, ISSUE_SUBSCRIPTION_REQUIRED)
            next_refresh = max(
                grant.refresh_after, dt_util.utcnow() + MIN_REFRESH_DELAY
            )
            span.set_attributes(
                {
                    "quicharc.home_id": grant.home_id,
                    "quicharc.web_access": grant.web_access,
                    "quicharc.grant.scopes": ",".join(grant.scopes),
                    "quicharc.grant.expires_at": grant.expires_at.isoformat(),
                    "quicharc.grant.revocations": len(grant.revocations),
                    "quicharc.grant.edges": len(grant.edges),
                }
            )
            self._apply_revocations(grant.revocations)
            await self.async_push_config()
            await self._async_poll_pairings()
            await self._async_refresh_device_sync()
        finally:
            span.set_attribute("quicharc.grant.next_refresh", next_refresh.isoformat())
            self._check_clock_skew()
            # Never re-arm after async_stop, or a cancelled refresh would leave
            # an orphaned timer refreshing for an unloaded entry.
            if not self._stopped:
                self._unsub_refresh = async_track_point_in_utc_time(
                    self.hass, self.async_refresh_config, next_refresh
                )
            self.async_notify()

    @callback
    def _apply_revocations(self, revocations: list[dict[str, Any]]) -> None:
        """Delete Home Assistant tokens of devices and service peers the cloud revoked.

        A device revocation names the device id; an enrollment revocation names
        the service peer, whose token goes and whose sync switch turns off.
        """
        for revocation in revocations:
            subject = revocation.get("subject")
            if not isinstance(subject, str) or not subject:
                continue
            if revocation.get("type") == "enrollment":
                service = SERVICE_PEER_ALIASES.get(subject, subject)
                self.pairing.async_remove_service_token(service)
                if service == DEVICE_SYNC_PEER:
                    self.device_sync = False
            elif revocation.get("type") == "device":
                self.pairing.async_handle_revoked({"device_id": subject})

    async def _async_poll_pairings(self) -> None:
        """Pick up pairing requests the agent didn't report (spec fallback)."""
        assert self.home_id is not None
        try:
            pairings = await self.api.async_pending_pairings(self.home_id)
        except (QuicHarcApiError, QuicHarcConnectionError) as err:
            _LOGGER.debug("Can't list pending pairings: %s", err)
            return
        for pairing in pairings:
            if pairing.get("device_id") in self.pairing.pending:
                continue
            self.pairing.async_handle_request(
                {
                    "device_id": pairing.get("device_id"),
                    "device_name": pairing.get("device_name"),
                    "ezlo_user_uuid": pairing.get("user_uuid"),
                    "ezlo_user_email": pairing.get("user_email"),
                    "device_key_fingerprint": pairing.get("device_key_fingerprint"),
                }
            )

    async def _async_refresh_device_sync(self) -> None:
        """Read whether the home is enrolled with Ezlo device sync."""
        assert self.home_id is not None
        try:
            enrollments = await self.api.async_enrollments(self.home_id)
        except (QuicHarcApiError, QuicHarcConnectionError) as err:
            _LOGGER.debug("Can't list enrollments: %s", err)
            return
        self.device_sync = any(
            e.get("service_peer_id") == DEVICE_SYNC_PEER and not e.get("withdrawn_at")
            for e in enrollments
        )

    async def async_set_device_sync(self, enabled: bool) -> None:
        """Enroll the home with, or withdraw it from, cloud/integrations/homeassistant.

        The cloud integration picks up a new enrollment by polling and then
        asks the agent for a Home Assistant token (token_request).
        """
        assert self.home_id is not None
        with self.telemetry.span(
            "device_sync.set",
            attributes={
                "quicharc.device_sync": enabled,
                "quicharc.service_peer": DEVICE_SYNC_PEER,
                "quicharc.home_id": self.home_id,
            },
        ):
            if enabled:
                await self.api.async_enroll(self.home_id, DEVICE_SYNC_PEER)
            else:
                await self.api.async_withdraw_enrollment(self.home_id, DEVICE_SYNC_PEER)
                self.pairing.async_remove_service_token(DEVICE_SYNC_PEER)
            self.device_sync = enabled
            self.async_notify()

    async def async_push_config(self) -> None:
        """Send the current configuration to the agent."""
        config = self.home_config
        if config is None or not self.supervisor.connected:
            return
        try:
            await self.supervisor.async_request(
                "config.set",
                {
                    "home_id": config.home_id,
                    "hostname": config.hostname,
                    "grant": config.grant,
                    "grant_expires_at": config.expires_at.isoformat(),
                    "grant_keys": config.grant_keys,
                    "edges": config.edges,
                    "ice_servers": [server.as_dict() for server in config.ice_servers],
                    "revocations": config.revocations,
                    "ha_url": ha_url(self.hass),
                    "web_access": config.web_access,
                },
            )
        except AgentError as err:
            _LOGGER.warning("Can't configure the agent: %s", err)

    def _raise_subscription_issue(self, err: SubscriptionRequired) -> None:
        """Lapsed only when the service says the account had it; else needed."""
        if err.lapsed:
            issue, other = ISSUE_SUBSCRIPTION_LAPSED, ISSUE_SUBSCRIPTION_REQUIRED
            url = err.manage_url or err.subscribe_url
        else:
            issue, other = ISSUE_SUBSCRIPTION_REQUIRED, ISSUE_SUBSCRIPTION_LAPSED
            url = err.subscribe_url or err.manage_url
        async_clear(self.hass, other)
        async_raise(
            self.hass,
            issue,
            is_fixable=False,
            severity=ir.IssueSeverity.ERROR,
            translation_key=issue,
            learn_more_url=url,
        )

    def _check_clock_skew(self) -> None:
        skew = self.api.clock_skew
        if skew is None:
            return
        if abs(skew) > CLOCK_SKEW_TOLERANCE_SECONDS:
            self._raise_clock_skew(skew)
        else:
            async_clear(self.hass, ISSUE_CLOCK_SKEW)

    def _raise_clock_skew(self, skew: float | None) -> None:
        async_raise(
            self.hass,
            ISSUE_CLOCK_SKEW,
            is_fixable=False,
            severity=ir.IssueSeverity.ERROR,
            translation_key=ISSUE_CLOCK_SKEW,
            translation_placeholders={
                "skew": f"{skew:+.0f}" if skew is not None else "more than 300"
            },
        )

    async def async_set_web_access(self, enabled: bool) -> None:
        """Turn web access on or off in the service and the agent.

        The grant's scopes carry `web`, so the grant is re-issued right away
        and handed to the agent; the edge only proxies web traffic for a
        grant that has it.
        """
        assert self.home_id is not None
        with self.telemetry.span(
            "web_access.set",
            attributes={
                "quicharc.web_access": enabled,
                "quicharc.home_id": self.home_id,
            },
        ) as span:
            await self.api.async_set_web_access(self.home_id, enabled)
            if self.home_config is not None:
                self.home_config.web_access = enabled
            self.hass.config_entries.async_update_entry(
                self.entry, options={**self.entry.options, CONF_WEB_ACCESS: enabled}
            )
            await self.async_refresh_config()
            if self.last_refresh_error:
                span.set_error(f"grant refresh failed: {self.last_refresh_error}")
            _LOGGER.info("Web access turned %s", "on" if enabled else "off")

    async def async_set_gate_required(self, enabled: bool) -> None:
        """Require the Ezlo sign-in gate for web access, or not.

        On takes effect at once (the service revokes open web access at the
        edges); off takes effect with the next grant, so the grant is
        re-issued right away, as for web access.
        """
        assert self.home_id is not None
        with self.telemetry.span(
            "gate_required.set",
            attributes={
                "quicharc.gate_required": enabled,
                "quicharc.home_id": self.home_id,
            },
        ) as span:
            await self.api.async_set_gate_required(self.home_id, enabled)
            if self.home_config is not None:
                self.home_config.gate_required = enabled
            self.hass.config_entries.async_update_entry(
                self.entry,
                options={**self.entry.options, CONF_GATE_REQUIRED: enabled},
            )
            await self.async_refresh_config()
            if self.last_refresh_error:
                span.set_error(f"grant refresh failed: {self.last_refresh_error}")
            _LOGGER.info(
                "Ezlo sign-in for web access %s",
                "required" if enabled else "not required",
            )

    @callback
    def ice_servers(self) -> list[RTCIceServer]:
        """Return QuicHarc's STUN and TURN servers for Home Assistant's WebRTC."""
        from webrtc_models import RTCIceServer

        if self.home_config is None:
            return []
        return [
            RTCIceServer(
                urls=server.urls,
                username=server.username,
                credential=server.credential,
            )
            for server in self.home_config.ice_servers
        ]

    @callback
    def _on_event(self, event: str, data: dict[str, Any]) -> None:
        if event == "state":
            self.state.update(data)
            self._sync_identity_conflict()
        elif event == "identity_conflict":
            self._async_handle_identity_conflict(data)
        elif event == "pairing_request":
            self.pairing.async_handle_request(data)
        elif event == "pairing_cancelled":
            self.pairing.async_handle_cancelled(data)
        elif event == "token_request":
            self.pairing.async_handle_token_request(data)
        elif event == "revoked":
            self._async_handle_revoked(data)
        elif event == "grant_expiring":
            self.entry.async_create_background_task(
                self.hass, self.async_refresh_config(), "quicharc grant refresh"
            )
        elif event == "log":
            level = {
                "debug": logging.DEBUG,
                "info": logging.INFO,
                "warning": logging.WARNING,
                "error": logging.ERROR,
            }.get(str(data.get("level")), logging.INFO)
            _LOGGER.log(level, "agent: %s", data.get("message"))
            return
        self.async_notify()

    @callback
    def _async_handle_identity_conflict(self, data: dict[str, Any]) -> None:
        """The edge replaced this agent's link with another installation's."""
        node = data.get("node")
        with self.telemetry.span(
            "identity.conflict",
            attributes={
                "quicharc.identity_conflict.reason": data.get("reason"),
                "quicharc.edge.node": node,
            },
        ):
            _LOGGER.warning(
                "Another installation is using this home's identity; it took "
                "the link on edge node %s",
                node,
            )
            self.state.identity_conflict = True
            self.state.identity_conflict_node = str(node) if node else None
            self._sync_identity_conflict()

    @callback
    def _sync_identity_conflict(self) -> None:
        """Raise or clear the repair issue to match the agent's state."""
        if not self.state.identity_conflict:
            async_clear(self.hass, ISSUE_IDENTITY_CONFLICT)
            return
        async_raise(
            self.hass,
            ISSUE_IDENTITY_CONFLICT,
            is_fixable=True,
            severity=ir.IssueSeverity.ERROR,
            translation_key=ISSUE_IDENTITY_CONFLICT,
            translation_placeholders={
                "node": self.state.identity_conflict_node or "unknown",
                "at": self.state.identity_conflict_at or "unknown",
            },
        )

    async def async_reclaim_identity(self) -> bool:
        """Take the edge link back from the other installation."""
        with self.telemetry.span("identity.reclaim") as span:
            result = await self.supervisor.async_request("identity.reclaim")
            reclaimed = result.get("reclaimed") is True
            span.set_attribute("quicharc.identity.reclaimed", reclaimed)
            _LOGGER.info(
                "Remote access identity %s",
                "reclaimed" if reclaimed else "not reclaimed: no conflict",
            )
            return reclaimed

    @callback
    def _async_handle_revoked(self, data: dict[str, Any]) -> None:
        kind = data.get("type", "device")
        with self.telemetry.span(
            "revocation.received",
            parent=SpanContext.from_traceparent(data.get("traceparent")),
            attributes={
                "quicharc.revocation.type": str(kind),
                "quicharc.device_id": data.get("device_id")
                if kind == "device"
                else None,
                "quicharc.service_peer": data.get("device_id")
                if kind == "enrollment"
                else None,
            },
        ):
            self._apply_revocations([{"type": kind, "subject": data.get("device_id")}])
            # The agent reports only devices it was connected to; the grant's
            # revocation list names the others, so fetch it now rather than
            # at the next scheduled refresh.
            self.entry.async_create_background_task(
                self.hass, self.async_refresh_config(), "quicharc revocation refresh"
            )

    @callback
    def _on_agent_failure(self, error: Exception | None) -> None:
        if isinstance(error, UnsupportedArchitecture):
            issue, placeholders = ISSUE_UNSUPPORTED_ARCH, {"arch": str(error)}
        elif isinstance(error, VerificationFailed):
            issue, placeholders = ISSUE_AGENT_VERIFY_FAILED, {"error": str(error)}
        elif isinstance(error, AgentBinaryError):
            issue, placeholders = ISSUE_AGENT_FAILED, {"error": str(error)}
        else:
            issue = ISSUE_AGENT_FAILED
            placeholders = {"error": self.supervisor.last_error or "unknown"}
        async_raise(
            self.hass,
            issue,
            is_fixable=False,
            severity=ir.IssueSeverity.ERROR,
            translation_key=issue,
            translation_placeholders=placeholders,
        )
        self.state = AgentState()
        self.async_notify()

    @callback
    def _on_agent_disconnected(self) -> None:
        """Forget what the agent reported; it's no longer true."""
        self.state = AgentState()
        self.async_notify()

    @callback
    def _on_agent_recovered(self) -> None:
        for issue in (ISSUE_AGENT_FAILED, ISSUE_AGENT_VERIFY_FAILED):
            async_clear(self.hass, issue)


__all__ = ["AgentState", "IceServer", "QuicHarcRuntime"]
