"""Client for the quicharc service (/api/v4/quicharc/1), through jwt-router-3.

Follows the service's OpenAPI document.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from email.utils import parsedate_to_datetime
import json as json_lib
import logging
from typing import Any

import aiohttp
from yarl import URL

from homeassistant.helpers import config_entry_oauth2_flow
from homeassistant.util import dt as dt_util

from .otel import KIND_CLIENT, child_span, trace_headers

_LOGGER = logging.getLogger(__name__)


class QuicHarcApiError(Exception):
    """The quicharc service returned an error."""

    def __init__(self, status: int, code: str) -> None:
        """Initialize."""
        super().__init__(f"{status} {code}")
        self.status = status
        self.code = code


class QuicHarcAuthError(QuicHarcApiError):
    """The Ezlo session is no longer valid."""


class SubscriptionRequired(QuicHarcApiError):
    """The account has no Home Assistant remote access entitlement.

    The service may say whether the account never had it ("none") or had it
    and lost it ("lapsed"), and where to subscribe or manage it.
    """

    def __init__(self, status: int, code: str, body: dict[str, Any]) -> None:
        """Initialize from the 403 body."""
        super().__init__(status, code)
        entitlement = body.get("entitlement")
        self.entitlement = entitlement if entitlement in ("none", "lapsed") else None
        self.subscribe_url = _https_url(body.get("subscribe_url"))
        self.manage_url = _https_url(body.get("manage_url"))

    @property
    def lapsed(self) -> bool:
        """Return whether the account had the entitlement and lost it."""
        return self.entitlement == "lapsed"


def _https_url(value: Any) -> str | None:
    """Return value if it's an https URL, the only links shown in a repair."""
    if isinstance(value, str) and value.startswith("https://") and len(value) < 2048:
        return value
    return None


class ClockSkewError(QuicHarcApiError):
    """A proof timestamp was outside the service's ±5 minute window."""


class SettingNotApplied(QuicHarcApiError):
    """The service answered but didn't apply a setting (it predates it)."""


class QuicHarcConnectionError(Exception):
    """The quicharc service can't be reached, or answered 5xx."""


@dataclass(slots=True)
class IceServer:
    """A STUN or TURN server, WebRTC RTCIceServer shape."""

    urls: list[str]
    username: str | None = None
    credential: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> IceServer:
        """Build from the API shape."""
        urls = data.get("urls") or []
        return cls(
            urls=[urls] if isinstance(urls, str) else list(urls),
            username=data.get("username"),
            credential=data.get("credential"),
        )

    def as_dict(self) -> dict[str, Any]:
        """Return the API shape."""
        out: dict[str, Any] = {"urls": self.urls}
        if self.username is not None:
            out["username"] = self.username
        if self.credential is not None:
            out["credential"] = self.credential
        return out


@dataclass(slots=True)
class HomeGrant:
    """POST /homes/{id}/grant: the home's grant and what the agent needs."""

    home_id: str
    hostname: str
    web_access: bool
    grant: str
    scopes: list[str]
    expires_at: datetime
    refresh_after: datetime
    grant_keys: dict[str, Any]
    edges: list[dict[str, Any]]
    ice_servers: list[IceServer]
    revocations: list[dict[str, Any]] = field(default_factory=list)
    gate_required: bool = False

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> HomeGrant:
        """Build from the API shape."""
        home = data["home"]
        return cls(
            home_id=home["id"],
            hostname=home["hostname"],
            web_access=bool(home.get("web_access", False)),
            grant=data["grant"],
            scopes=list(data.get("scopes") or []),
            expires_at=_parse_time(data["expires_at"]),
            refresh_after=_parse_time(data["refresh_after"]),
            grant_keys=dict(data.get("grant_keys") or {}),
            edges=list(data.get("edges") or []),
            ice_servers=[IceServer.from_dict(s) for s in data.get("ice_servers") or []],
            revocations=list(data.get("revocations") or []),
            gate_required=bool(home.get("gate_required", False)),
        )


@dataclass(slots=True)
class Registration:
    """POST /homes: the registered home."""

    home_id: str
    hostname: str
    owner_user_uuid: str


def _parse_time(value: str) -> datetime:
    parsed = dt_util.parse_datetime(value)
    if parsed is None:
        raise ValueError(f"bad timestamp {value!r}")
    return parsed


class QuicHarcApi:
    """Authenticated calls to the quicharc service."""

    def __init__(
        self,
        websession: aiohttp.ClientSession,
        oauth_session: config_entry_oauth2_flow.OAuth2Session,
        base_url: str,
    ) -> None:
        """Initialize."""
        self._websession = websession
        self._oauth = oauth_session
        self._base = base_url.rstrip("/")
        self.clock_skew: float | None = None

    async def async_access_token(self) -> dict[str, Any]:
        """Return a valid OAuth token, refreshing it if needed."""
        try:
            await self._oauth.async_ensure_token_valid()
        except aiohttp.ClientResponseError as err:
            # cloud/login answers invalid_grant (4xx) for an expired or
            # revoked refresh token: the user has to sign in again.
            if 400 <= err.status < 500:
                raise QuicHarcAuthError(err.status, "invalid_grant") from err
            raise QuicHarcConnectionError(str(err)) from err
        except aiohttp.ClientError as err:
            raise QuicHarcConnectionError(str(err)) from err
        return self._oauth.token

    async def _request(
        self,
        method: str,
        path: str,
        json: dict[str, Any] | None = None,
        *,
        route: str,
    ) -> dict[str, Any]:
        """Call the service; route is the path template, for telemetry."""
        with child_span(
            f"{method} {route}",
            kind=KIND_CLIENT,
            attributes={
                "http.request.method": method,
                "url.template": route,
                "server.address": URL(self._base).host,
            },
        ) as span:
            return await self._send(method, path, json, span)

    async def _send(
        self, method: str, path: str, json: dict[str, Any] | None, span: Any
    ) -> dict[str, Any]:
        token = (await self.async_access_token())["access_token"]
        try:
            async with self._websession.request(
                method,
                f"{self._base}{path}",
                json=json,
                headers={"Authorization": f"Bearer {token}", **trace_headers()},
                timeout=aiohttp.ClientTimeout(total=30),
            ) as resp:
                self._record_skew(resp.headers.get("Date"))
                text = await resp.text()
                status = resp.status
        except (aiohttp.ClientError, TimeoutError) as err:
            raise QuicHarcConnectionError(str(err)) from err
        span.set_attribute("http.response.status_code", status)

        try:
            parsed = json_lib.loads(text) if text else {}
        except ValueError:
            parsed = {}
        body: dict[str, Any] = parsed if isinstance(parsed, dict) else {}
        if status < 400:
            return body
        code = str(body.get("error") or "error")
        span.set_attribute("error.type", code)
        if status == 401:
            raise QuicHarcAuthError(status, code)
        if code == "not_entitled":
            raise SubscriptionRequired(status, code, body)
        if code == "clock_skew":
            raise ClockSkewError(status, code)
        if status >= 500:
            raise QuicHarcConnectionError(f"{status} {code}")
        raise QuicHarcApiError(status, code)

    def _record_skew(self, date_header: str | None) -> None:
        if not date_header:
            return
        try:
            server = parsedate_to_datetime(date_header)
        except TypeError, ValueError:
            return
        self.clock_skew = (dt_util.utcnow() - server).total_seconds()

    async def async_register_home(
        self,
        *,
        public_key: str,
        proof_ts: int,
        proof: str,
        name: str,
        agent_version: str,
        ha_version: str,
        ha_instance_id: str,
    ) -> Registration:
        """Register this Home Assistant as a home (idempotent per key and user)."""
        data = await self._request(
            "POST",
            "/homes",
            {
                "public_key": public_key,
                "proof_ts": proof_ts,
                "proof": proof,
                "name": name[:128],
                "agent_version": agent_version,
                "ha_version": ha_version,
                "ha_instance_id": ha_instance_id,
            },
            route="/homes",
        )
        return Registration(
            home_id=data["id"],
            hostname=data["hostname"],
            owner_user_uuid=data["owner_user_uuid"],
        )

    async def async_issue_home_grant(
        self,
        home_id: str,
        *,
        proof_ts: int,
        proof: str,
        agent_version: str | None,
        ha_version: str,
    ) -> HomeGrant:
        """Issue or refresh the home's own grant."""
        body: dict[str, Any] = {
            "proof_ts": proof_ts,
            "proof": proof,
            "ha_version": ha_version,
        }
        if agent_version:
            body["agent_version"] = agent_version
        return HomeGrant.from_dict(
            await self._request(
                "POST", f"/homes/{home_id}/grant", body, route="/homes/{id}/grant"
            )
        )

    async def async_set_web_access(self, home_id: str, enabled: bool) -> None:
        """Turn web access on or off."""
        await self._request(
            "PATCH", f"/homes/{home_id}", {"web_access": enabled}, route="/homes/{id}"
        )

    async def async_set_gate_required(self, home_id: str, enabled: bool) -> None:
        """Require the Ezlo sign-in gate for web access, or not.

        A service older than the setting ignores the unknown field, so the
        home view it answers with is read back to confirm.
        """
        home = await self._request(
            "PATCH",
            f"/homes/{home_id}",
            {"gate_required": enabled},
            route="/homes/{id}",
        )
        if home.get("gate_required") is not enabled:
            raise SettingNotApplied(200, "gate_required_not_applied")

    async def async_set_pairing(
        self,
        home_id: str,
        device_id: str,
        *,
        approved: bool,
        ha_user_id: str | None = None,
        ha_user_name: str | None = None,
    ) -> None:
        """Record the administrator's pairing decision."""
        body: dict[str, Any] = {"state": "approved" if approved else "denied"}
        if approved:
            body["ha_user_id"] = ha_user_id
            if ha_user_name:
                body["ha_user_name"] = ha_user_name
        await self._request(
            "PUT",
            f"/homes/{home_id}/devices/{device_id}",
            body,
            route="/homes/{id}/devices/{device_id}",
        )

    async def async_pending_pairings(self, home_id: str) -> list[dict[str, Any]]:
        """Return pairing requests waiting for a decision."""
        data = await self._request(
            "GET",
            f"/homes/{home_id}/devices?state=pending",
            route="/homes/{id}/devices",
        )
        return list(data.get("pairings") or [])

    async def async_revoke_device(self, home_id: str, device_id: str) -> None:
        """Revoke a device's access to this home; already gone counts as done."""
        try:
            await self._request(
                "DELETE",
                f"/homes/{home_id}/devices/{device_id}",
                route="/homes/{id}/devices/{device_id}",
            )
        except QuicHarcApiError as err:
            if err.status != 404:
                raise

    async def async_enrollments(self, home_id: str) -> list[dict[str, Any]]:
        """Return the service peers this home is enrolled with."""
        data = await self._request(
            "GET", f"/homes/{home_id}/enrollments", route="/homes/{id}/enrollments"
        )
        return list(data.get("enrollments") or [])

    async def async_enroll(self, home_id: str, service_peer_id: str) -> None:
        """Enroll the home with a service peer (idempotent)."""
        await self._request(
            "POST",
            f"/homes/{home_id}/enrollments",
            {"service_peer_id": service_peer_id},
            route="/homes/{id}/enrollments",
        )

    async def async_withdraw_enrollment(
        self, home_id: str, service_peer_id: str
    ) -> None:
        """Withdraw an enrollment; already withdrawn counts as done."""
        try:
            await self._request(
                "DELETE",
                f"/homes/{home_id}/enrollments/{service_peer_id}",
                route="/homes/{id}/enrollments/{service_peer_id}",
            )
        except QuicHarcApiError as err:
            if err.status != 404:
                raise

    async def async_delete_home(self, home_id: str) -> None:
        """Unlink the home."""
        await self._request("DELETE", f"/homes/{home_id}", route="/homes/{id}")
