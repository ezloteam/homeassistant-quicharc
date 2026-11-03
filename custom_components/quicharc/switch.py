"""Web access switch."""

from __future__ import annotations

from typing import Any

from homeassistant.components.switch import SwitchEntity
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from . import QuicHarcConfigEntry
from .api import QuicHarcApiError, QuicHarcConnectionError
from .const import DOMAIN
from .entity import QuicHarcEntity


async def async_setup_entry(
    hass: HomeAssistant,
    entry: QuicHarcConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up the switch."""
    async_add_entities(
        [WebAccessSwitch(entry.runtime_data), DeviceSyncSwitch(entry.runtime_data)]
    )


class WebAccessSwitch(QuicHarcEntity, SwitchEntity):
    """Lets browsers reach Home Assistant through the Ezlo edge. Off by default."""

    _attr_entity_category = EntityCategory.CONFIG

    def __init__(self, runtime) -> None:
        """Initialize."""
        super().__init__(runtime, "web_access")

    @property
    def available(self) -> bool:
        """Available once the home is registered."""
        return self.runtime.home_id is not None

    @property
    def is_on(self) -> bool:
        """Return whether web access is on."""
        return self.runtime.web_access

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return the web address while web access is usable."""
        return {"url": self.runtime.web_url}

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Turn web access on."""
        await self._async_set(True)

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Turn web access off."""
        await self._async_set(False)

    async def _async_set(self, enabled: bool) -> None:
        try:
            await self.runtime.async_set_web_access(enabled)
        except (QuicHarcApiError, QuicHarcConnectionError) as err:
            raise HomeAssistantError(f"Couldn't change web access: {err}") from err


# The service isn't registered in this Ezlo environment (404), or is turned
# off (409): nothing the user can fix here.
DEVICE_SYNC_UNAVAILABLE = frozenset({"unknown_service_peer", "service_peer_disabled"})


class DeviceSyncSwitch(QuicHarcEntity, SwitchEntity):
    """Ezlo device sync: enrolls the home with cloud/integrations/homeassistant.

    That service then reaches Home Assistant over QuicHarc with a token it
    asks the agent for, and turns Home Assistant devices into Ezlo devices.
    """

    _attr_entity_category = EntityCategory.CONFIG

    def __init__(self, runtime) -> None:
        """Initialize."""
        super().__init__(runtime, "device_sync")

    @property
    def available(self) -> bool:
        """Available once the enrollment state is known."""
        return self.runtime.home_id is not None and self.runtime.device_sync is not None

    @property
    def is_on(self) -> bool:
        """Return whether the home is enrolled."""
        return bool(self.runtime.device_sync)

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Enroll the home."""
        await self._async_set(True)

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Withdraw the enrollment and delete the service's token."""
        await self._async_set(False)

    async def _async_set(self, enabled: bool) -> None:
        try:
            await self.runtime.async_set_device_sync(enabled)
        except QuicHarcApiError as err:
            if err.code in DEVICE_SYNC_UNAVAILABLE:
                raise HomeAssistantError(
                    translation_domain=DOMAIN,
                    translation_key="device_sync_unavailable",
                ) from err
            raise HomeAssistantError(
                f"Couldn't change Ezlo device sync: {err}"
            ) from err
        except QuicHarcConnectionError as err:
            raise HomeAssistantError(
                f"Couldn't change Ezlo device sync: {err}"
            ) from err
