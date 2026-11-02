"""notify.quicharc: hand notifications to cloud/integrations/homeassistant.

The plugin doesn't deliver anything itself. It fires a quicharc_notification
event, which the Ezlo cloud integration subscribes to over its WebSocket
session and delivers through Ezlo's push path (architecture section 4.5).
"""

from __future__ import annotations

from typing import Any

from homeassistant.components.notify import (
    ATTR_DATA,
    ATTR_TITLE,
    ATTR_TITLE_DEFAULT,
    BaseNotificationService,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers.typing import ConfigType, DiscoveryInfoType

from .const import EVENT_NOTIFICATION
from .otel import async_get_telemetry


async def async_get_service(
    hass: HomeAssistant,
    config: ConfigType,
    discovery_info: DiscoveryInfoType | None = None,
) -> QuicHarcNotificationService | None:
    """Return the notify service, only when loaded by the integration."""
    if discovery_info is None:
        return None
    return QuicHarcNotificationService(hass)


class QuicHarcNotificationService(BaseNotificationService):
    """Fire notifications as events on the bus."""

    def __init__(self, hass: HomeAssistant) -> None:
        """Initialize."""
        self.hass = hass

    async def async_send_message(self, message: str = "", **kwargs: Any) -> None:
        """Fire a quicharc_notification event.

        The trace records only the event's shape, never its title, message
        or data.
        """
        telemetry = await async_get_telemetry(self.hass)
        with telemetry.span(
            "notify.send",
            attributes={
                "event.name": EVENT_NOTIFICATION,
                "quicharc.notify.has_title": bool(kwargs.get(ATTR_TITLE)),
                "quicharc.notify.has_data": bool(kwargs.get(ATTR_DATA)),
                "quicharc.notify.message_length": len(message),
                "quicharc.notify.targets": len(kwargs.get("target") or []),
            },
        ):
            event: dict[str, Any] = {
                "title": kwargs.get(ATTR_TITLE) or ATTR_TITLE_DEFAULT,
                "message": message,
            }
            if data := kwargs.get(ATTR_DATA):
                event["data"] = data
            self.hass.bus.async_fire(EVENT_NOTIFICATION, event)
