"""Binary sensors: agent running and forwarded headers trusted."""

from __future__ import annotations

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from . import QuicHarcConfigEntry
from .entity import QuicHarcEntity


async def async_setup_entry(
    hass: HomeAssistant,
    entry: QuicHarcConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up binary sensors."""
    runtime = entry.runtime_data
    async_add_entities([AgentRunningSensor(runtime), ForwardedHeadersSensor(runtime)])


class AgentRunningSensor(QuicHarcEntity, BinarySensorEntity):
    """Whether the integration is connected to a running agent."""

    _attr_device_class = BinarySensorDeviceClass.RUNNING
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, runtime) -> None:
        """Initialize."""
        super().__init__(runtime, "agent")

    @property
    def is_on(self) -> bool:
        """Return True while the agent is connected."""
        return self.runtime.supervisor.connected

    @property
    def extra_state_attributes(self) -> dict:
        """Return agent details."""
        supervisor = self.runtime.supervisor
        return {
            "version": supervisor.agent_version or self.runtime.binary.version,
            "restarts": supervisor.failures,
            "last_error": supervisor.last_error,
        }


class ForwardedHeadersSensor(QuicHarcEntity, BinarySensorEntity):
    """Whether Home Assistant accepts the agent's X-Forwarded-For."""

    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, runtime) -> None:
        """Initialize."""
        super().__init__(runtime, "forwarded_headers")

    @property
    def is_on(self) -> bool:
        """Return True when Home Assistant trusts forwarded headers."""
        return self.runtime.state.forwarded_headers_trusted
