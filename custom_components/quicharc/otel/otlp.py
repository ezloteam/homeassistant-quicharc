"""OTLP/HTTP JSON encoding for traces, logs and metrics.

The JSON mapping of the OTLP protobuf messages: trace and span ids are hex,
64-bit integers are strings.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Final

from ..const import VERSION
from .trace import STATUS_UNSET, AttributeValue, Span

SCOPE: Final = {"name": "custom_components.quicharc", "version": VERSION}

AGGREGATION_CUMULATIVE: Final = 2

_SEVERITY: Final = {10: 5, 20: 9, 30: 13, 40: 17, 50: 21}


@dataclass(frozen=True, slots=True)
class LogItem:
    """A log record, captured when it was emitted."""

    time_ns: int
    level: int
    level_name: str
    body: str
    attributes: dict[str, AttributeValue]
    trace_id: str | None
    span_id: str | None


@dataclass(frozen=True, slots=True)
class MetricPoint:
    """One data point of a counter or gauge."""

    attributes: Mapping[str, AttributeValue]
    value: int


@dataclass(frozen=True, slots=True)
class Metric:
    """A counter (monotonic sum) or a gauge, with its points."""

    name: str
    unit: str
    description: str
    monotonic: bool
    points: list[MetricPoint]


def _value(value: AttributeValue) -> dict[str, Any]:
    if isinstance(value, bool):
        return {"boolValue": value}
    if isinstance(value, int):
        return {"intValue": str(value)}
    if isinstance(value, float):
        return {"doubleValue": value}
    return {"stringValue": str(value)}


def attributes(values: Mapping[str, AttributeValue]) -> list[dict[str, Any]]:
    """Encode attributes as OTLP key-values."""
    return [{"key": key, "value": _value(value)} for key, value in values.items()]


def _resource(values: Mapping[str, AttributeValue]) -> dict[str, Any]:
    return {"attributes": attributes(values)}


def _span(span: Span) -> dict[str, Any]:
    out: dict[str, Any] = {
        "traceId": span.context.trace_id,
        "spanId": span.context.span_id,
        "name": span.name,
        "kind": span.kind,
        "startTimeUnixNano": str(span.start_ns),
        "endTimeUnixNano": str(span.end_ns or span.start_ns),
        "attributes": attributes(span.attributes),
    }
    if span.parent is not None:
        out["parentSpanId"] = span.parent.span_id
    if span.events:
        out["events"] = [
            {"timeUnixNano": str(ts), "name": name, "attributes": attributes(attrs)}
            for ts, name, attrs in span.events
        ]
    if span.status != STATUS_UNSET:
        out["status"] = {"code": span.status, "message": span.status_message}
    return out


def encode_spans(
    resource: Mapping[str, AttributeValue], spans: Iterable[Span]
) -> dict[str, Any]:
    """Return an ExportTraceServiceRequest."""
    return {
        "resourceSpans": [
            {
                "resource": _resource(resource),
                "scopeSpans": [{"scope": SCOPE, "spans": [_span(s) for s in spans]}],
            }
        ]
    }


def _log(item: LogItem) -> dict[str, Any]:
    out: dict[str, Any] = {
        "timeUnixNano": str(item.time_ns),
        "observedTimeUnixNano": str(item.time_ns),
        "severityNumber": _SEVERITY.get(item.level, 9),
        "severityText": item.level_name,
        "body": {"stringValue": item.body},
        "attributes": attributes(item.attributes),
    }
    if item.trace_id and item.span_id:
        out["traceId"] = item.trace_id
        out["spanId"] = item.span_id
    return out


def encode_logs(
    resource: Mapping[str, AttributeValue], items: Iterable[LogItem]
) -> dict[str, Any]:
    """Return an ExportLogsServiceRequest."""
    return {
        "resourceLogs": [
            {
                "resource": _resource(resource),
                "scopeLogs": [{"scope": SCOPE, "logRecords": [_log(i) for i in items]}],
            }
        ]
    }


def _metric(metric: Metric, start_ns: int, now_ns: int) -> dict[str, Any]:
    points = [
        {
            "attributes": attributes(point.attributes),
            "timeUnixNano": str(now_ns),
            "asInt": str(point.value),
            **({"startTimeUnixNano": str(start_ns)} if metric.monotonic else {}),
        }
        for point in metric.points
    ]
    out: dict[str, Any] = {
        "name": metric.name,
        "unit": metric.unit,
        "description": metric.description,
    }
    if metric.monotonic:
        out["sum"] = {
            "aggregationTemporality": AGGREGATION_CUMULATIVE,
            "isMonotonic": True,
            "dataPoints": points,
        }
    else:
        out["gauge"] = {"dataPoints": points}
    return out


def encode_metrics(
    resource: Mapping[str, AttributeValue],
    metrics: Iterable[Metric],
    start_ns: int,
    now_ns: int,
) -> dict[str, Any]:
    """Return an ExportMetricsServiceRequest."""
    return {
        "resourceMetrics": [
            {
                "resource": _resource(resource),
                "scopeMetrics": [
                    {
                        "scope": SCOPE,
                        "metrics": [_metric(m, start_ns, now_ns) for m in metrics],
                    }
                ],
            }
        ]
    }
