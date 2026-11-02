"""Mint Home Assistant tokens for paired devices and service peers (section 3.4).

hass.auth is an internal Home Assistant API; CI runs these paths against the
oldest supported release, the current release and the beta.
"""

from __future__ import annotations

from datetime import timedelta
import secrets
from typing import Any, Final

from homeassistant.auth.models import (
    TOKEN_TYPE_LONG_LIVED_ACCESS_TOKEN,
    TOKEN_TYPE_NORMAL,
    RefreshToken,
    User,
)
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError

from .const import IOS_CLIENT_ID, SERVICE_PEER_CLIENT_NAMES

SERVICE_TOKEN_LIFETIME: Final = timedelta(days=3650)


class TokenError(HomeAssistantError):
    """A token can't be minted."""


async def async_selectable_users(hass: HomeAssistant) -> list[User]:
    """Return the users a device may be paired as."""
    return [
        user
        for user in await hass.auth.async_get_users()
        if user.is_active and not user.system_generated
    ]


async def _async_user(hass: HomeAssistant, user_id: str) -> User:
    user = await hass.auth.async_get_user(user_id)
    if user is None or not user.is_active or user.system_generated:
        raise TokenError(f"Home Assistant user {user_id} can't be used")
    return user


def ha_url(hass: HomeAssistant) -> str:
    """Return the loopback URL the agent uses to reach Home Assistant."""
    port = hass.http.server_port if hass.http is not None else 8123
    scheme = "https" if hass.http is not None and hass.http.ssl_certificate else "http"
    return f"{scheme}://127.0.0.1:{port}"


async def async_mint_device_token(
    hass: HomeAssistant, user_id: str, device_name: str
) -> tuple[RefreshToken, dict[str, Any]]:
    """Create a refresh token for a native device.

    The device refreshes it against /auth/token with IOS_CLIENT_ID, the way
    the Companion apps do, and hands access tokens to the frontend through
    the external authentication bridge.
    """
    user = await _async_user(hass, user_id)
    refresh_token = await hass.auth.async_create_refresh_token(
        user,
        client_id=IOS_CLIENT_ID,
        client_name=f"QuicHarc: {device_name}",
        token_type=TOKEN_TYPE_NORMAL,
    )
    return refresh_token, {
        "kind": "refresh_token",
        "refresh_token": refresh_token.token,
        "client_id": IOS_CLIENT_ID,
        "ha_user_id": user.id,
        "ha_url": ha_url(hass),
    }


async def async_mint_service_token(
    hass: HomeAssistant, user_id: str, service: str
) -> tuple[RefreshToken, dict[str, Any]]:
    """Create a long-lived access token for a cloud service peer.

    Home Assistant allows one long-lived token per client name, so each token
    gets a unique suffix; the caller removes the previous token once the new
    one has been delivered.
    """
    user = await _async_user(hass, user_id)
    label = SERVICE_PEER_CLIENT_NAMES.get(service, service)
    client_name = f"{label} (QuicHarc {secrets.token_hex(3)})"
    refresh_token = await hass.auth.async_create_refresh_token(
        user,
        client_name=client_name,
        token_type=TOKEN_TYPE_LONG_LIVED_ACCESS_TOKEN,
        access_token_expiration=SERVICE_TOKEN_LIFETIME,
    )
    access_token = hass.auth.async_create_access_token(refresh_token)
    return refresh_token, {
        "kind": "access_token",
        "access_token": access_token,
        "ha_user_id": user.id,
        "ha_url": ha_url(hass),
    }


def remove_token(hass: HomeAssistant, token_id: str | None) -> None:
    """Delete a refresh token if it still exists."""
    if token_id and (token := hass.auth.async_get_refresh_token(token_id)):
        hass.auth.async_remove_refresh_token(token)
