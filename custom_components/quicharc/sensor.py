"""Diagnostic sensors: edge connection, active path, devices, round-trip time."""

from __future__ import annotations

from typing import Any

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorStateClass,
)
from homeassistant.const import EntityCategory, UnitOfTime
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from . import QuicHarcConfigEntry
from .entity import QuicHarcEntity

EDGE_STATES = ["disconnected", "connecting", "connected"]
PATHS = ["none", "lan", "direct", "relay"]


async def async_setup_entry(
    hass: HomeAssistant,
    entry: QuicHarcConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up sensors."""
    runtime = entry.runtime_data
    async_add_entities(
        [
            EdgeConnectionSensor(runtime),
            ActivePathSensor(runtime),
            ConnectedDevicesSensor(runtime),
            EdgeRoundTripSensor(runtime),
        ]
    )


class EdgeConnectionSensor(QuicHarcEntity, SensorEntity):
    """State of the home's standing connection to the edge."""

    _attr_device_class = SensorDeviceClass.ENUM
    _attr_options = EDGE_STATES
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, runtime) -> None:
        """Initialize."""
        super().__init__(runtime, "edge_connection")

    @property
    def native_value(self) -> str:
        """Return the connection state."""
        if not self.runtime.supervisor.connected:
            return "disconnected"
        state = self.runtime.state.edge
        return state if state in EDGE_STATES else "disconnected"

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return per-node details."""
        return {
            "home_id": self.runtime.home_id,
            "hostname": self.runtime.entry.data.get("hostname"),
            "nodes": self.runtime.state.edge_nodes,
        }


class ActivePathSensor(QuicHarcEntity, SensorEntity):
    """Best path any device is using: LAN, direct or relay."""

    _attr_device_class = SensorDeviceClass.ENUM
    _attr_options = PATHS
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, runtime) -> None:
        """Initialize."""
        super().__init__(runtime, "active_path")

    @property
    def native_value(self) -> str:
        """Return the path."""
        return self.runtime.state.active_path


class ConnectedDevicesSensor(QuicHarcEntity, SensorEntity):
    """Number of native devices connected right now."""

    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, runtime) -> None:
        """Initialize."""
        super().__init__(runtime, "connected_devices")

    @property
    def native_value(self) -> int:
        """Return the count."""
        return len(self.runtime.state.device_peers)

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return the connected devices with their names."""
        devices = self.runtime.pairing.devices
        return {
            "devices": [
                {
                    "device_id": peer.get("peer_id"),
                    "name": devices.get(peer.get("peer_id"), {}).get("name"),
                    "path": peer.get("path"),
                    "rtt_ms": peer.get("rtt_ms"),
                }
                for peer in self.runtime.state.device_peers
            ],
            "paired": len(devices),
        }


class EdgeRoundTripSensor(QuicHarcEntity, SensorEntity):
    """Round-trip time to the nearest connected edge node."""

    _attr_device_class = SensorDeviceClass.DURATION
    _attr_native_unit_of_measurement = UnitOfTime.MILLISECONDS
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_suggested_display_precision = 0

    def __init__(self, runtime) -> None:
        """Initialize."""
        super().__init__(runtime, "edge_rtt")

    @property
    def native_value(self) -> float | None:
        """Return the round-trip time."""
        return self.runtime.state.edge_rtt_ms
