"""Spans with W3C trace context, carried in a context variable.

asyncio copies the context into every task it creates, so a span started
around some work is the parent of whatever that work starts, including
background tasks. Long-lived tasks (the agent's read loop) are started in an
empty context so they don't parent everything that happens after them.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
import os
import re
import time
from typing import Any, Final

from .scrub import scrub

KIND_INTERNAL: Final = 1
KIND_SERVER: Final = 2
KIND_CLIENT: Final = 3

STATUS_UNSET: Final = 0
STATUS_OK: Final = 1
STATUS_ERROR: Final = 2

MAX_ATTRIBUTES: Final = 32
MAX_EVENTS: Final = 32
MAX_STRING: Final = 512

_TRACEPARENT: Final = re.compile(r"^00-([0-9a-f]{32})-([0-9a-f]{16})-[0-9a-f]{2}$")

type AttributeValue = str | bool | int | float
type Attributes = Mapping[str, AttributeValue | None]


@dataclass(frozen=True, slots=True)
class SpanContext:
    """The identity of a span, local or received in a traceparent."""

    trace_id: str
    span_id: str

    @property
    def traceparent(self) -> str:
        """Return the W3C traceparent header value (sampled)."""
        return f"00-{self.trace_id}-{self.span_id}-01"

    @classmethod
    def from_traceparent(cls, value: Any) -> SpanContext | None:
        """Parse a traceparent; None if it's missing or malformed."""
        if not isinstance(value, str):
            return None
        match = _TRACEPARENT.match(value.strip().lower())
        if match is None or not match[1].strip("0") or not match[2].strip("0"):
            return None
        return cls(match[1], match[2])


def _coerce(value: AttributeValue) -> AttributeValue:
    if isinstance(value, (bool, int, float)):
        return value
    return scrub(str(value))[:MAX_STRING]


class Span:
    """One timed operation. Ended spans go to the sink for export."""

    __slots__ = (
        "_sink",
        "attributes",
        "context",
        "end_ns",
        "events",
        "kind",
        "name",
        "parent",
        "start_ns",
        "status",
        "status_message",
    )

    recording: Final = True  # type: ignore[misc]

    def __init__(
        self,
        sink: Callable[[Span], None],
        name: str,
        *,
        kind: int = KIND_INTERNAL,
        parent: SpanContext | None = None,
        attributes: Attributes | None = None,
    ) -> None:
        """Start the span now."""
        self._sink = sink
        self.name = name
        self.kind = kind
        self.parent = parent
        self.context = SpanContext(
            parent.trace_id if parent else os.urandom(16).hex(), os.urandom(8).hex()
        )
        self.attributes: dict[str, AttributeValue] = {}
        self.events: list[tuple[int, str, dict[str, AttributeValue]]] = []
        self.status = STATUS_UNSET
        self.status_message = ""
        self.start_ns = time.time_ns()
        self.end_ns: int | None = None
        if attributes:
            self.set_attributes(attributes)

    def set_attribute(self, key: str, value: AttributeValue | None) -> None:
        """Set an attribute; None is ignored."""
        if value is None:
            return
        if key not in self.attributes and len(self.attributes) >= MAX_ATTRIBUTES:
            return
        self.attributes[key] = _coerce(value)

    def set_attributes(self, attributes: Attributes) -> None:
        """Set several attributes."""
        for key, value in attributes.items():
            self.set_attribute(key, value)

    def add_event(self, name: str, attributes: Attributes | None = None) -> None:
        """Record something that happened during the span."""
        if len(self.events) >= MAX_EVENTS:
            return
        self.events.append(
            (
                time.time_ns(),
                name,
                {k: _coerce(v) for k, v in (attributes or {}).items() if v is not None},
            )
        )

    def record_exception(self, err: BaseException) -> None:
        """Record an exception and mark the span failed."""
        message = scrub(str(err))
        self.add_event(
            "exception",
            {"exception.type": type(err).__name__, "exception.message": message},
        )
        self.set_error(message or type(err).__name__)

    def set_error(self, message: str) -> None:
        """Mark the span failed."""
        self.status = STATUS_ERROR
        self.status_message = scrub(message)[:MAX_STRING]

    def set_ok(self) -> None:
        """Mark the span explicitly successful."""
        if self.status != STATUS_ERROR:
            self.status = STATUS_OK

    def end(self) -> None:
        """End the span (once) and hand it to the exporter."""
        if self.end_ns is not None:
            return
        self.end_ns = time.time_ns()
        self._sink(self)

    @property
    def telemetry_sink(self) -> Callable[[Span], None]:
        """Return where this span's children are recorded."""
        return self._sink


class NoopSpan:
    """Stands in for a span outside any trace; records nothing."""

    __slots__ = ()

    recording: Final = False  # type: ignore[misc]
    context = None
    parent = None
    attributes: Mapping[str, AttributeValue] = {}

    def set_attribute(self, key: str, value: AttributeValue | None) -> None:
        """Do nothing."""

    def set_attributes(self, attributes: Attributes) -> None:
        """Do nothing."""

    def add_event(self, name: str, attributes: Attributes | None = None) -> None:
        """Do nothing."""

    def record_exception(self, err: BaseException) -> None:
        """Do nothing."""

    def set_error(self, message: str) -> None:
        """Do nothing."""

    def set_ok(self) -> None:
        """Do nothing."""

    def end(self) -> None:
        """Do nothing."""


NOOP: Final = NoopSpan()

type AnySpan = Span | NoopSpan

_CURRENT: ContextVar[Span | None] = ContextVar("quicharc_span", default=None)


def current_span() -> Span | None:
    """Return the span the running code is part of."""
    return _CURRENT.get()


@contextmanager
def use_span(span: AnySpan) -> Iterator[AnySpan]:
    """Make a span current for the block, without ending it."""
    if not isinstance(span, Span):
        yield span
        return
    token = _CURRENT.set(span)
    try:
        yield span
    finally:
        _CURRENT.reset(token)


@contextmanager
def run_span(span: AnySpan) -> Iterator[AnySpan]:
    """Make a span current, record what escapes the block, and end it."""
    with use_span(span):
        try:
            yield span
        except BaseException as err:
            if type(err).__name__ == "CancelledError":
                span.set_error("cancelled")
            else:
                span.record_exception(err)
            raise
        finally:
            span.end()


@contextmanager
def child_span(
    name: str, *, kind: int = KIND_INTERNAL, attributes: Attributes | None = None
) -> Iterator[AnySpan]:
    """Start a child of the current span, or do nothing outside a trace.

    For code without access to Home Assistant (the service client, the agent
    socket client): their spans only make sense inside some operation.
    """
    parent = _CURRENT.get()
    if parent is None:
        yield NOOP
        return
    span = Span(
        parent.telemetry_sink,
        name,
        kind=kind,
        parent=parent.context,
        attributes=attributes,
    )
    with run_span(span):
        yield span


def trace_headers() -> dict[str, str]:
    """Return the traceparent header for the current span, if any."""
    span = _CURRENT.get()
    return {"traceparent": span.context.traceparent} if span is not None else {}


def traceparent() -> str | None:
    """Return the current span's traceparent, if any."""
    span = _CURRENT.get()
    return span.context.traceparent if span is not None else None
