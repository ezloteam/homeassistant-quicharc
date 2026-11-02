"""Advertise the home on the LAN for native clients (architecture section 5.2).

The iOS app browses _quicharc._udp.local, connects straight to the agent's
UDP peer port, and checks the home key fingerprint it cached at pairing.
"""

from __future__ import annotations

from dataclasses import dataclass
import logging
from typing import Final

from zeroconf import BadTypeInNameException, NonUniqueNameException
from zeroconf.asyncio import AsyncServiceInfo

from homeassistant.components import network, zeroconf
from homeassistant.core import HomeAssistant

from .const import DEFAULT_LAN_PORT

_LOGGER = logging.getLogger(__name__)

SERVICE_TYPE: Final = "_quicharc._udp.local."


@dataclass(frozen=True, slots=True)
class Advertisement:
    """What is announced; a change means re-announcing."""

    home_id: str
    fingerprint: str
    port: int
    addresses: tuple[str, ...]


class LanAdvertiser:
    """Keeps one _quicharc._udp service registered on Home Assistant's zeroconf."""

    def __init__(self, hass: HomeAssistant) -> None:
        """Initialize."""
        self._hass = hass
        self._info: AsyncServiceInfo | None = None
        self._current: Advertisement | None = None

    @property
    def advertised(self) -> Advertisement | None:
        """Return what is announced right now."""
        return self._current

    async def async_update(
        self, home_id: str | None, fingerprint: str | None, port: int | None
    ) -> None:
        """Announce, re-announce or withdraw to match the current state."""
        if not home_id or not fingerprint:
            await self.async_stop()
            return
        addresses = tuple(await network.async_get_announce_addresses(self._hass))
        wanted = Advertisement(
            home_id, fingerprint, port or DEFAULT_LAN_PORT, addresses
        )
        if wanted == self._current:
            return
        info = AsyncServiceInfo(
            SERVICE_TYPE,
            name=f"{home_id}.{SERVICE_TYPE}",
            server=f"quicharc-{home_id}.local.",
            parsed_addresses=list(addresses),
            port=wanted.port,
            properties={"v": "1", "home": home_id, "fp": fingerprint},
        )
        aiozc = await zeroconf.async_get_async_instance(self._hass)
        try:
            if (
                self._info is not None
                and self._current is not None
                and (self._current.home_id == home_id)
            ):
                await aiozc.async_update_service(info)
            else:
                await self.async_stop()
                await aiozc.async_register_service(info, allow_name_change=True)
        except (BadTypeInNameException, NonUniqueNameException, OSError) as err:
            _LOGGER.warning("Can't announce QuicHarc on the LAN: %s", err)
            return
        self._info = info
        self._current = wanted
        _LOGGER.debug("Announced %s on port %s", info.name, wanted.port)

    async def async_stop(self) -> None:
        """Withdraw the announcement."""
        if self._info is None:
            return
        info, self._info, self._current = self._info, None, None
        aiozc = await zeroconf.async_get_async_instance(self._hass)
        try:
            await aiozc.async_unregister_service(info)
        except (KeyError, OSError) as err:
            _LOGGER.debug("Unregistering %s failed: %s", info.name, err)
