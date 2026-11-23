"""The Ezlo refresh token: rotation, lost answers and a refused token.

cloud/login rotates the refresh token on every use and refuses a retired
one after a short grace. On 2026-11-23 its token endpoint rotated a token
but answered 500; the plugin kept presenting the retired token every five
minutes for hours. These tests pin the behaviour that replaces that.
"""

from __future__ import annotations

import time
from unittest.mock import patch

import pytest

from custom_components.quicharc import oauth
from custom_components.quicharc.api import QuicHarcConnectionError
from custom_components.quicharc.const import ENVIRONMENTS
from homeassistant.core import HomeAssistant

from .harness import AiohttpClientMocker, AiohttpClientMockResponse
from .test_init import (  # noqa: F401  (fixtures)
    entry_minor_version,
    entry_options,
    mock_service,
    setup_entry,
)

TOKEN_URL = ENVIRONMENTS["stg"].token_url


@pytest.fixture(autouse=True)
def no_retry_delay():
    """Retry a lost refresh answer at once."""
    with patch.object(oauth, "REFRESH_RETRY_DELAYS", (0.0, 0.0)):
        yield


def _expire_access_token(hass: HomeAssistant, entry) -> None:
    token = {**entry.data["token"], "expires_at": time.time() - 60}
    hass.config_entries.async_update_entry(entry, data={**entry.data, "token": token})


def _token_calls(mock: AiohttpClientMocker) -> list:
    return [c for c in mock.mock_calls if str(c[1]) == TOKEN_URL]


def _answers(*answers: tuple[int, dict]):
    """A token endpoint giving these answers in turn, then the last one."""
    queue = list(answers)

    async def side_effect(method, url, data):
        status, body = queue.pop(0) if len(queue) > 1 else queue[0]
        return AiohttpClientMockResponse(method, url, status=status, json=body)

    return side_effect


def _rotated(n: int) -> dict:
    return {
        "access_token": f"access-{n}",
        "refresh_token": f"refresh-{n}",
        "expires_in": 600,
        "token_type": "Bearer",
    }


async def test_rotated_refresh_token_is_kept(
    hass: HomeAssistant, setup_entry, mock_service: AiohttpClientMocker
) -> None:
    """Every refresh stores the rotated token before the access token is used."""
    entry = setup_entry
    runtime = entry.runtime_data
    mock_service.post(
        TOKEN_URL, side_effect=_answers((200, _rotated(1)), (200, _rotated(2)))
    )
    _expire_access_token(hass, entry)

    await runtime.async_refresh_config()

    (call,) = _token_calls(mock_service)
    assert call[2]["refresh_token"] == "ezlo-refresh"
    assert entry.data["token"]["refresh_token"] == "refresh-1"
    assert entry.data["token"]["access_token"] == "access-1"
    grant = [c for c in mock_service.mock_calls if str(c[1]).endswith("/grant")][-1]
    assert grant[3]["Authorization"] == "Bearer access-1"

    # The next refresh presents the rotated token, never the first one.
    _expire_access_token(hass, entry)
    await runtime.async_refresh_config()
    assert _token_calls(mock_service)[1][2]["refresh_token"] == "refresh-1"
    assert entry.data["token"]["refresh_token"] == "refresh-2"


async def test_lost_refresh_answer_is_retried_at_once(
    hass: HomeAssistant, setup_entry, mock_service: AiohttpClientMocker
) -> None:
    """A 500 from the token endpoint is retried within seconds, same token."""
    entry = setup_entry
    runtime = entry.runtime_data
    mock_service.post(
        TOKEN_URL,
        side_effect=_answers((500, {"error": "server_error"}), (200, _rotated(1))),
    )
    _expire_access_token(hass, entry)

    await runtime.async_refresh_config()

    calls = _token_calls(mock_service)
    assert [c[2]["refresh_token"] for c in calls] == ["ezlo-refresh", "ezlo-refresh"]
    assert entry.data["token"]["refresh_token"] == "refresh-1"
    assert runtime.last_refresh_error is None


async def test_answer_without_refresh_token_keeps_nothing_old(
    hass: HomeAssistant, setup_entry, mock_service: AiohttpClientMocker
) -> None:
    """An answer without a refresh token is an error, not a reason to reuse ours."""
    entry = setup_entry
    runtime = entry.runtime_data
    before = dict(entry.data["token"])
    answer = {k: v for k, v in _rotated(1).items() if k != "refresh_token"}
    mock_service.post(TOKEN_URL, side_effect=_answers((200, answer)))
    _expire_access_token(hass, entry)

    with pytest.raises(QuicHarcConnectionError):
        await runtime.api.async_access_token()

    # The access token from that answer was never stored or used.
    assert entry.data["token"]["access_token"] == before["access_token"]
    assert entry.data["token"]["refresh_token"] == before["refresh_token"]


async def test_refused_refresh_token_asks_to_sign_in_once(
    hass: HomeAssistant, setup_entry, mock_service: AiohttpClientMocker
) -> None:
    """invalid_grant starts reauthentication and stops presenting the token."""
    entry = setup_entry
    runtime = entry.runtime_data
    mock_service.post(
        TOKEN_URL, side_effect=_answers((400, {"error": "invalid_grant"}))
    )
    _expire_access_token(hass, entry)

    await runtime.async_refresh_config(None)
    await hass.async_block_till_done()

    assert len(_token_calls(mock_service)) == 1
    flows = hass.config_entries.flow.async_progress_by_handler(entry.domain)
    assert [f["context"]["source"] for f in flows] == ["reauth"]
    # No retry is scheduled: only signing in again helps.
    assert runtime._unsub_refresh is None

    # Whatever asks for a token next fails without asking cloud/login again.
    await runtime.async_refresh_config(None)
    await runtime.async_refresh_config(None)
    assert len(_token_calls(mock_service)) == 1
    assert runtime._unsub_refresh is None
    assert len(hass.config_entries.flow.async_progress_by_handler(entry.domain)) == 1


async def test_rate_limited_refresh_is_not_a_dead_session(
    hass: HomeAssistant, setup_entry, mock_service: AiohttpClientMocker
) -> None:
    """429 is retried and, if it persists, retried later, not a sign-in."""
    entry = setup_entry
    runtime = entry.runtime_data
    mock_service.post(TOKEN_URL, side_effect=_answers((429, {"error": "slow_down"})))
    _expire_access_token(hass, entry)

    await runtime.async_refresh_config()
    await hass.async_block_till_done()

    assert len(_token_calls(mock_service)) == 3
    assert not hass.config_entries.flow.async_progress_by_handler(entry.domain)
    assert runtime._unsub_refresh is not None
    assert not runtime.api.session_expired
