"""Raise and clear repair issues, recording each change in telemetry."""

from __future__ import annotations

from collections import Counter
import logging
from typing import Any

from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import issue_registry as ir

from .const import (
    DOMAIN,
    ISSUE_AGENT_FAILED,
    ISSUE_AGENT_VERIFY_FAILED,
    ISSUE_CLOCK_SKEW,
    ISSUE_HTTP_CONFIG_MANUAL,
    ISSUE_IDENTITY_CONFLICT,
    ISSUE_PAIRING_PREFIX,
    ISSUE_RESTART_REQUIRED,
    ISSUE_SUBSCRIPTION_LAPSED,
    ISSUE_SUBSCRIPTION_REQUIRED,
    ISSUE_UNSUPPORTED_ARCH,
)
from .otel import get_telemetry
from .otel.otlp import MetricPoint

_LOGGER = logging.getLogger(__name__)

# Reported even at zero, so a fixed issue's series drops to 0 instead of
# ending.
KINDS = (
    ISSUE_AGENT_FAILED,
    ISSUE_AGENT_VERIFY_FAILED,
    ISSUE_UNSUPPORTED_ARCH,
    ISSUE_CLOCK_SKEW,
    ISSUE_RESTART_REQUIRED,
    ISSUE_HTTP_CONFIG_MANUAL,
    ISSUE_SUBSCRIPTION_LAPSED,
    ISSUE_SUBSCRIPTION_REQUIRED,
    ISSUE_IDENTITY_CONFLICT,
    "pairing_request",
)


def issue_kind(issue_id: str) -> str:
    """Return the issue's kind: its id, or pairing_request for any pairing."""
    return "pairing_request" if issue_id.startswith(ISSUE_PAIRING_PREFIX) else issue_id


@callback
def async_raise(hass: HomeAssistant, issue_id: str, **kwargs: Any) -> None:
    """Create or update an issue; a new one is logged and traced."""
    existed = ir.async_get(hass).async_get_issue(DOMAIN, issue_id) is not None
    ir.async_create_issue(hass, DOMAIN, issue_id, **kwargs)
    if not existed:
        severity = kwargs.get("severity")
        _record(hass, "repair.raised", issue_id, getattr(severity, "value", severity))


@callback
def async_clear(hass: HomeAssistant, issue_id: str) -> None:
    """Delete an issue; if there was one, it's logged and traced as fixed."""
    if ir.async_get(hass).async_get_issue(DOMAIN, issue_id) is None:
        return
    ir.async_delete_issue(hass, DOMAIN, issue_id)
    _record(hass, "repair.fixed", issue_id)


def _record(
    hass: HomeAssistant, name: str, issue_id: str, severity: str | None = None
) -> None:
    kind = issue_kind(issue_id)
    _LOGGER.info(
        "Repair issue %s %s", issue_id, "raised" if name == "repair.raised" else "fixed"
    )
    if (telemetry := get_telemetry(hass)) is None:
        return
    with telemetry.span(
        name,
        attributes={
            "quicharc.repair.issue": kind,
            "quicharc.repair.severity": severity,
            "quicharc.device_id": issue_id.removeprefix(ISSUE_PAIRING_PREFIX)
            if kind == "pairing_request"
            else None,
        },
    ):
        pass


@callback
def active_issues(hass: HomeAssistant) -> list[MetricPoint]:
    """Return open (not dismissed) QuicHarc issues counted by kind."""
    counts = Counter(dict.fromkeys(KINDS, 0))
    counts.update(
        issue_kind(issue_id)
        for (domain, issue_id), issue in ir.async_get(hass).issues.items()
        if domain == DOMAIN and issue.active and issue.dismissed_version is None
    )
    return [MetricPoint({"issue": kind}, count) for kind, count in counts.items()]
