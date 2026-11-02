"""OpenTelemetry: traces, logs and metrics to Ezlo's ingest (architecture section 10).

OTLP/HTTP JSON is sent with Home Assistant's own aiohttp session rather than
through the OpenTelemetry SDK, so the integration adds no requirements that
could clash with Home Assistant's pinned packages, and nothing runs outside
the event loop. Records wait in bounded queues and are sent in batches every
few seconds; when a queue is full, or an export fails, records are dropped
and counted. It is always on (architecture section 10.1).
"""

from __future__ import annotations

import asyncio
from collections import deque
from collections.abc import Callable, Iterator
from contextlib import contextmanager
import contextvars
from datetime import datetime, timedelta
import logging
import platform
import time
from typing import Any, Final

import aiohttp

from homeassistant.const import EVENT_HOMEASSISTANT_STOP, __version__ as HA_VERSION
from homeassistant.core import Event, HomeAssistant, callback
from homeassistant.helpers import instance_id
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.event import async_track_time_interval
from homeassistant.helpers.json import json_bytes
from homeassistant.util import dt as dt_util

from ..const import DOMAIN, SERVICE_NAME, TELEMETRY_ENDPOINT, VERSION
from .logs import EXPORTER_LOGGER, LogCapture
from .metrics import Metrics
from .otlp import LogItem, encode_logs, encode_metrics, encode_spans
from .trace import (
    KIND_CLIENT,
    KIND_INTERNAL,
    NOOP,
    AnySpan,
    Attributes,
    AttributeValue,
    Span,
    SpanContext,
    child_span,
    current_span,
    run_span,
    trace_headers,
    traceparent,
    use_span,
)

_LOGGER = logging.getLogger(EXPORTER_LOGGER)

DATA_TELEMETRY: Final = f"{DOMAIN}_telemetry"

FLUSH_INTERVAL: Final = timedelta(seconds=5)
METRICS_INTERVAL: Final = timedelta(seconds=60)
MAX_QUEUE: Final = 2048
MAX_BATCH: Final = 512
MAX_BATCHES_PER_FLUSH: Final = 4
EXPORT_TIMEOUT: Final = 10
STOP_TIMEOUT: Final = 3

_INHERIT: Final = object()


__all__ = [
    "KIND_CLIENT",
    "KIND_INTERNAL",
    "NOOP",
    "AnySpan",
    "Span",
    "SpanContext",
    "Telemetry",
    "async_get_telemetry",
    "child_span",
    "current_span",
    "get_telemetry",
    "trace_headers",
    "traceparent",
    "use_span",
]


class Telemetry:
    """One per Home Assistant: queues, exporter, metrics and the log handler."""

    def __init__(self, hass: HomeAssistant, install_id: str) -> None:
        """Initialize; call async_start() to begin exporting."""
        self.hass = hass
        self.install_id = install_id
        self.environment: str | None = None
        self.endpoint = TELEMETRY_ENDPOINT
        self.attributes: dict[str, AttributeValue] = {}
        self.metrics = Metrics()
        self.dropped = 0
        self.exported = {"traces": 0, "logs": 0, "metrics": 0}
        self.last_export: datetime | None = None
        self.last_export_error: str | None = None
        self._spans: deque[Span] = deque()
        self._logs: deque[LogItem] = deque()
        self._flushing = False
        self._capture = LogCapture(self._record_log)
        self._unsub_timers: list[Callable[[], None]] = []
        self._unsub_stop: Callable[[], None] | None = None
        self._started = False

    @callback
    def async_start(self) -> None:
        """Start the export timers and log capture (once)."""
        if self._started:
            return
        self._started = True
        # Timers capture the context they're created in; an empty one keeps
        # the exporter out of whatever trace happened to be current.
        empty = contextvars.Context()
        self._unsub_timers = [
            empty.run(
                async_track_time_interval,
                self.hass,
                action,
                interval,
                cancel_on_shutdown=True,
            )
            for action, interval in (
                (self._async_flush_tick, FLUSH_INTERVAL),
                (self._async_metrics_tick, METRICS_INTERVAL),
            )
        ]
        self._unsub_stop = self.hass.bus.async_listen_once(
            EVENT_HOMEASSISTANT_STOP, self._async_on_stop
        )
        self._capture.attach()

    @callback
    def async_configure(self, *, environment: str) -> None:
        """Apply the cloud environment."""
        self.environment = environment

    # Spans

    def start_span(
        self,
        name: str,
        *,
        kind: int = KIND_INTERNAL,
        attributes: Attributes | None = None,
        parent: Any = _INHERIT,
        root: bool = False,
    ) -> AnySpan:
        """Start a span; its parent is the current span unless told otherwise.

        root starts a new trace. parent may be a SpanContext (for example one
        received in a traceparent), or None for a new trace.
        """
        if root:
            parent = None
        elif parent is _INHERIT:
            span = current_span()
            parent = span.context if span is not None else None
        return Span(
            self._record_span, name, kind=kind, parent=parent, attributes=attributes
        )

    @contextmanager
    def span(
        self,
        name: str,
        *,
        kind: int = KIND_INTERNAL,
        attributes: Attributes | None = None,
        parent: Any = _INHERIT,
        root: bool = False,
    ) -> Iterator[AnySpan]:
        """Run a block in a new span, recording any exception, then end it."""
        with run_span(
            self.start_span(
                name, kind=kind, attributes=attributes, parent=parent, root=root
            )
        ) as span:
            yield span

    def _record_span(self, span: Span) -> None:
        self._push(self._spans, span)

    def _record_log(self, item: LogItem) -> None:
        self._push(self._logs, item)

    def _push(self, queue: deque[Any], item: Any) -> None:
        # deque.append is atomic, so log records may arrive from any thread.
        if len(queue) >= MAX_QUEUE:
            self.dropped += 1
            return
        queue.append(item)

    @property
    def queued(self) -> dict[str, int]:
        """Return how many records wait for export."""
        return {"spans": len(self._spans), "logs": len(self._logs)}

    # Export

    def resource(self) -> dict[str, AttributeValue]:
        """Return the resource attributes sent with every batch."""
        return {
            "service.name": SERVICE_NAME,
            "service.version": VERSION,
            "service.instance.id": self.install_id,
            "deployment.environment": self.environment or "unknown",
            "homeassistant.version": HA_VERSION,
            "host.arch": platform.machine(),
            "telemetry.sdk.name": SERVICE_NAME,
            "telemetry.sdk.language": "python",
            **self.attributes,
        }

    async def _async_flush_tick(self, _now: datetime) -> None:
        await self.async_flush()

    async def _async_metrics_tick(self, _now: datetime) -> None:
        await self.async_export_metrics()

    async def async_flush(self) -> None:
        """Send queued spans and log records, a few batches at a time."""
        if self._flushing:
            return
        self._flushing = True
        try:
            resource = self.resource()
            for _ in range(MAX_BATCHES_PER_FLUSH):
                spans = _take(self._spans)
                logs = _take(self._logs)
                if not spans and not logs:
                    break
                if spans:
                    await self._async_post(
                        "traces", encode_spans(resource, spans), len(spans)
                    )
                if logs:
                    await self._async_post(
                        "logs", encode_logs(resource, logs), len(logs)
                    )
        finally:
            self._flushing = False

    async def async_export_metrics(self) -> None:
        """Send every metric's current value."""
        metrics = self.metrics.collect(self.dropped)
        await self._async_post(
            "metrics",
            encode_metrics(
                self.resource(),
                metrics,
                self.metrics.start_ns,
                time.time_ns(),
            ),
            len(metrics),
            counts_as_dropped=False,
        )

    async def _async_post(
        self,
        signal: str,
        payload: dict[str, Any],
        count: int,
        *,
        counts_as_dropped: bool = True,
    ) -> None:
        session = async_get_clientsession(self.hass)
        try:
            async with session.post(
                f"{self.endpoint}/{signal}",
                data=json_bytes(payload),
                headers={"Content-Type": "application/json"},
                timeout=aiohttp.ClientTimeout(total=EXPORT_TIMEOUT),
            ) as resp:
                status = resp.status
        except (aiohttp.ClientError, TimeoutError) as err:
            self._failed(
                signal, str(err) or type(err).__name__, count, counts_as_dropped
            )
            return
        except Exception as err:
            self._failed(signal, repr(err), count, counts_as_dropped)
            return
        if status >= 300:
            self._failed(signal, f"HTTP {status}", count, counts_as_dropped)
            return
        self.exported[signal] += count
        self.last_export = dt_util.utcnow()

    def _failed(self, signal: str, error: str, count: int, counts: bool) -> None:
        self.last_export_error = f"{signal}: {error}"
        if counts:
            self.dropped += count
        _LOGGER.debug("Couldn't export %d %s: %s", count, signal, error)

    async def _async_on_stop(self, _event: Event) -> None:
        """Send what is queued, then stop."""
        self._unsub_stop = None
        await self.async_final_flush()
        self.async_shutdown()

    async def async_final_flush(self) -> None:
        """Send what is queued, after any running flush, within a few seconds."""
        try:
            async with asyncio.timeout(STOP_TIMEOUT):
                while self._flushing:
                    await asyncio.sleep(0.05)
                await self.async_flush()
        except TimeoutError:
            _LOGGER.debug("Final telemetry flush timed out")

    @callback
    def async_shutdown(self) -> None:
        """Cancel timers and detach the log handler."""
        for unsub in self._unsub_timers:
            unsub()
        self._unsub_timers = []
        if self._unsub_stop is not None:
            self._unsub_stop()
            self._unsub_stop = None
        self._capture.detach()
        self._started = False


def _take(queue: deque[Any]) -> list[Any]:
    batch: list[Any] = []
    while queue and len(batch) < MAX_BATCH:
        batch.append(queue.popleft())
    return batch


@callback
def get_telemetry(hass: HomeAssistant) -> Telemetry | None:
    """Return the telemetry instance, if one was created."""
    return hass.data.get(DATA_TELEMETRY)


async def async_get_telemetry(hass: HomeAssistant) -> Telemetry:
    """Return the telemetry instance, creating and starting it on first use."""
    if (telemetry := hass.data.get(DATA_TELEMETRY)) is None:
        try:
            install_id = await instance_id.async_get(hass)
        except Exception:
            _LOGGER.debug("Home Assistant's instance id isn't available")
            install_id = "unknown"
        telemetry = hass.data.setdefault(DATA_TELEMETRY, Telemetry(hass, install_id))
    # Starting is idempotent; it restarts telemetry stopped by an unload.
    telemetry.async_start()
    return telemetry
