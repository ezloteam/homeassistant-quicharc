"""Diagnostics download for support."""

from __future__ import annotations

from typing import Any

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.core import HomeAssistant

from . import QuicHarcConfigEntry
from .const import SERVICE_NAME

# What the integration sends to Ezlo's OpenTelemetry ingest when "Share
# diagnostics with Ezlo" is on (README: Privacy).
TELEMETRY_CONTENT = (
    "Traces of sign-in, home registration, agent download and start, pairing, "
    "service tokens, web access, device sync, HTTP settings changes, ICE "
    "server registration, notify.quicharc and repairs; the integration's log "
    "records at INFO and above; counters for agent restarts, pairing outcomes "
    "and open repairs. Identified by this install's id, the Ezlo home, device "
    "and user ids, the Home Assistant and integration versions. Never tokens, "
    "keys, cookies, passwords, grants, email addresses, notification text, or "
    "Home Assistant entities and states; IP addresses are cut to the network."
)

TO_REDACT = {
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "grant",
    "credential",
    "username",
    "ezlo_user_email",
    "ezlo_user_uuid",
    "refresh_token_id",
}


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: QuicHarcConfigEntry
) -> dict[str, Any]:
    """Return diagnostics for a config entry."""
    runtime = entry.runtime_data
    supervisor = runtime.supervisor
    config = runtime.home_config
    return async_redact_data(
        {
            "entry": {"data": dict(entry.data), "options": dict(entry.options)},
            "agent": {
                "pinned_version": runtime.binary.version,
                "reported_version": supervisor.agent_version,
                "connected": supervisor.connected,
                "pid": supervisor.pid,
                "failures": supervisor.failures,
                "last_error": supervisor.last_error,
                "home_key_fingerprint": runtime.home_key_fingerprint,
            },
            "state": {
                "edge": runtime.state.edge,
                "edge_nodes": runtime.state.edge_nodes,
                "peers": runtime.state.peers,
                "forwarded_headers_trusted": runtime.state.forwarded_headers_trusted,
                "identity_conflict": runtime.state.identity_conflict,
                "identity_conflict_node": runtime.state.identity_conflict_node,
                "identity_conflict_at": runtime.state.identity_conflict_at,
            },
            "service": {
                "clock_skew_seconds": runtime.api.clock_skew,
                "last_refresh": runtime.last_refresh.isoformat()
                if runtime.last_refresh
                else None,
                "last_refresh_error": runtime.last_refresh_error,
                "config": None
                if config is None
                else {
                    "home_id": config.home_id,
                    "hostname": config.hostname,
                    "web_access": config.web_access,
                    "gate_required": config.gate_required,
                    "scopes": config.scopes,
                    "grant_expires_at": config.expires_at.isoformat(),
                    "refresh_after": config.refresh_after.isoformat(),
                    "edges": config.edges,
                    "ice_servers": [s.as_dict() for s in config.ice_servers],
                    "revocations": len(config.revocations),
                },
            },
            "lan": None
            if runtime.lan.advertised is None
            else {
                "port": runtime.lan.advertised.port,
                "addresses": list(runtime.lan.advertised.addresses),
            },
            "devices": runtime.pairing.devices,
            "pending_pairings": list(runtime.pairing.pending.values()),
            "telemetry": _telemetry(runtime.telemetry),
        },
        TO_REDACT,
    )


def _telemetry(telemetry: Any) -> dict[str, Any]:
    """Return what telemetry sends, where, and how it's doing."""
    return {
        "endpoint": telemetry.endpoint,
        "service_name": SERVICE_NAME,
        "content": TELEMETRY_CONTENT,
        "resource": telemetry.resource(),
        "exported": dict(telemetry.exported),
        "queued": telemetry.queued,
        "dropped": telemetry.dropped,
        "last_export": telemetry.last_export.isoformat()
        if telemetry.last_export
        else None,
        "last_export_error": telemetry.last_export_error,
    }
