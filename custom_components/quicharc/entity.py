"""Base entity for QuicHarc."""

from __future__ import annotations

from homeassistant.helpers.device_registry import DeviceEntryType, DeviceInfo
from homeassistant.helpers.entity import Entity

from .const import DOMAIN, VERSION
from .runtime import QuicHarcRuntime


class QuicHarcEntity(Entity):
    """An entity backed by the runtime's state."""

    _attr_has_entity_name = True
    _attr_should_poll = False

    def __init__(self, runtime: QuicHarcRuntime, key: str) -> None:
        """Initialize."""
        self.runtime = runtime
        self._attr_unique_id = f"{runtime.entry.entry_id}_{key}"
        self._attr_translation_key = key
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, runtime.entry.entry_id)},
            name="QuicHarc",
            manufacturer="Ezlo",
            model="Remote access",
            sw_version=VERSION,
            entry_type=DeviceEntryType.SERVICE,
            configuration_url="https://github.com/ezloteam/homeassistant-quicharc",
        )

    async def async_added_to_hass(self) -> None:
        """Subscribe to runtime updates."""
        self.async_on_remove(self.runtime.async_add_listener(self.async_write_ha_state))
