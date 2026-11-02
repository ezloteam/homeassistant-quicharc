"""Counters and gauges, exported as cumulative OTLP metrics."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import time
from typing import Final

from .otlp import Metric, MetricPoint
from .trace import AttributeValue

type GaugeCallback = Callable[[], list[MetricPoint]]


@dataclass(frozen=True, slots=True)
class Instrument:
    """A metric's name, unit and description."""

    name: str
    unit: str
    description: str


AGENT_RESTARTS: Final = Instrument(
    "quicharc.agent.restarts", "{restart}", "Times the agent stopped and was restarted"
)
AGENT_CONNECTED: Final = Instrument(
    "quicharc.agent.connected", "1", "1 while the agent's socket connection is up"
)
PAIRING_OUTCOMES: Final = Instrument(
    "quicharc.pairing.outcomes",
    "{pairing}",
    "Pairing requests by outcome: approved, auto_approved, denied, cancelled, failed",
)
REPAIRS_ACTIVE: Final = Instrument(
    "quicharc.repairs.active", "{issue}", "Open QuicHarc repair issues by issue"
)
TELEMETRY_DROPPED: Final = Instrument(
    "quicharc.telemetry.dropped",
    "{record}",
    "Spans and log records dropped because the queue was full or export failed",
)


class Metrics:
    """The integration's metrics; counters live as long as Home Assistant runs."""

    def __init__(self) -> None:
        """Initialize."""
        self.start_ns = time.time_ns()
        self._counters: dict[
            Instrument, dict[tuple[tuple[str, AttributeValue], ...], int]
        ] = {}
        self._gauges: dict[Instrument, GaugeCallback] = {}

    def add(
        self, instrument: Instrument, value: int = 1, **attributes: AttributeValue
    ) -> None:
        """Add to a counter."""
        points = self._counters.setdefault(instrument, {})
        key = tuple(sorted(attributes.items()))
        points[key] = points.get(key, 0) + value

    def counter_value(
        self, instrument: Instrument, **attributes: AttributeValue
    ) -> int:
        """Return a counter's current value (for diagnostics and tests)."""
        return self._counters.get(instrument, {}).get(
            tuple(sorted(attributes.items())), 0
        )

    def register_gauge(
        self, instrument: Instrument, callback: GaugeCallback
    ) -> Callable[[], None]:
        """Read a gauge from callback at each export; returns an unregister."""
        self._gauges[instrument] = callback
        return lambda: self._gauges.pop(instrument, None)

    def collect(self, dropped: int) -> list[Metric]:
        """Return every metric's current points."""
        metrics = [
            Metric(
                instrument.name,
                instrument.unit,
                instrument.description,
                True,
                [MetricPoint(dict(key), value) for key, value in points.items()],
            )
            for instrument, points in self._counters.items()
        ]
        metrics.append(
            Metric(
                TELEMETRY_DROPPED.name,
                TELEMETRY_DROPPED.unit,
                TELEMETRY_DROPPED.description,
                True,
                [MetricPoint({}, dropped)],
            )
        )
        for instrument, callback in list(self._gauges.items()):
            try:
                points = callback()
            except Exception:
                continue
            metrics.append(
                Metric(
                    instrument.name,
                    instrument.unit,
                    instrument.description,
                    False,
                    points,
                )
            )
        return metrics
