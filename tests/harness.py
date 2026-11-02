"""The Home Assistant test helpers, from whichever package is installed.

From 2026.11, Home Assistant publishes them itself as pytest-home-assistant
(pytest_homeassistant), which registers its plugin through an entry point.
Earlier releases use pytest-homeassistant-custom-component, which conftest
loads as a plugin. The two must not be installed together.
"""

from __future__ import annotations

from importlib.util import find_spec

if find_spec("pytest_homeassistant") is not None:
    from pytest_homeassistant.common import (
        MockConfigEntry,
        async_capture_events,
        async_mock_service,
    )
    from pytest_homeassistant.test_util.aiohttp import (
        AiohttpClientMocker,
        AiohttpClientMockResponse,
    )

    PYTEST_PLUGINS: list[str] = []
else:
    from pytest_homeassistant_custom_component.common import (
        MockConfigEntry,
        async_capture_events,
        async_mock_service,
    )
    from pytest_homeassistant_custom_component.test_util.aiohttp import (
        AiohttpClientMocker,
        AiohttpClientMockResponse,
    )

    PYTEST_PLUGINS = ["pytest_homeassistant_custom_component"]

__all__ = [
    "PYTEST_PLUGINS",
    "AiohttpClientMockResponse",
    "AiohttpClientMocker",
    "MockConfigEntry",
    "async_capture_events",
    "async_mock_service",
]
