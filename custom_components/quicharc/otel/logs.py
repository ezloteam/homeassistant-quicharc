"""Send the integration's log records as OTLP logs."""

from __future__ import annotations

from collections.abc import Callable
import logging
import time
import traceback
from typing import Final

from .otlp import LogItem
from .scrub import scrub
from .trace import AttributeValue, current_span

INTEGRATION_LOGGER: Final = "custom_components.quicharc"
# Log with extra=NOT_EXPORTED when the message may quote the user's
# configuration (configuration check output); it still reaches Home
# Assistant's log.
NOT_EXPORTED: Final = {"quicharc_export": False}
# The exporter's own logger; never exported, so a failing export can't feed
# itself.
EXPORTER_LOGGER: Final = f"{INTEGRATION_LOGGER}.otel"

MAX_BODY: Final = 2048
MAX_STACK: Final = 4096


class TelemetryLogHandler(logging.Handler):
    """Queue each record for export; never blocks, safe from any thread."""

    def __init__(self, record: Callable[[LogItem], None]) -> None:
        """Initialize."""
        super().__init__(logging.INFO)
        self._record = record

    def emit(self, record: logging.LogRecord) -> None:
        """Capture the record with the current trace and span ids."""
        if record.name.startswith(EXPORTER_LOGGER) or not getattr(
            record, "quicharc_export", True
        ):
            return
        try:
            attributes: dict[str, AttributeValue] = {
                "code.namespace": record.name,
                "code.function": record.funcName,
                "code.lineno": record.lineno,
            }
            if record.exc_info and record.exc_info[1] is not None:
                err = record.exc_info[1]
                attributes["exception.type"] = type(err).__name__
                attributes["exception.message"] = scrub(str(err))[:MAX_BODY]
                attributes["exception.stacktrace"] = scrub(
                    "".join(traceback.format_exception(err))
                )[-MAX_STACK:]
            span = current_span()
            self._record(
                LogItem(
                    time_ns=int(record.created * 1e9) or time.time_ns(),
                    level=record.levelno,
                    level_name=record.levelname,
                    body=scrub(record.getMessage())[:MAX_BODY],
                    attributes=attributes,
                    trace_id=span.context.trace_id if span else None,
                    span_id=span.context.span_id if span else None,
                )
            )
        except Exception:
            self.handleError(record)


class LogCapture:
    """Attach the handler to the integration's logger, and detach it again.

    Home Assistant's root logger defaults to WARNING, which would drop the
    integration's INFO records before any handler sees them. Unless the
    integration's level was configured (logger: in configuration.yaml), it is
    set to INFO while telemetry runs, and put back afterwards.
    """

    def __init__(self, record: Callable[[LogItem], None]) -> None:
        """Initialize."""
        self._handler = TelemetryLogHandler(record)
        self._logger = logging.getLogger(INTEGRATION_LOGGER)
        self._previous_level: int | None = None

    def attach(self) -> None:
        """Start capturing."""
        if self._handler in self._logger.handlers:
            return
        self._logger.addHandler(self._handler)
        if self._logger.level == logging.NOTSET and (
            self._logger.getEffectiveLevel() > logging.INFO
        ):
            self._previous_level = self._logger.level
            self._logger.setLevel(logging.INFO)

    def detach(self) -> None:
        """Stop capturing."""
        self._logger.removeHandler(self._handler)
        if self._previous_level is not None:
            if self._logger.level == logging.INFO:
                self._logger.setLevel(self._previous_level)
            self._previous_level = None
