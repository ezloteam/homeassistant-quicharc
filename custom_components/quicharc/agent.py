"""Supervise the QuicHarc agent subprocess."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
import contextlib
import contextvars
import logging
import os
from pathlib import Path
import time
from typing import Any, Final

from homeassistant.core import HomeAssistant

from .agent_binary import AgentBinary, AgentBinaryError
from .agent_client import AgentClient, AgentConnectionError, AgentError
from .const import DEFAULT_LAN_PORT, SOCKET_NAME
from .otel import (
    KIND_CLIENT,
    AnySpan,
    SpanContext,
    Telemetry,
    child_span,
    current_span,
    traceparent,
)
from .otel.metrics import AGENT_RESTARTS
from .otel.trace import run_span

_LOGGER = logging.getLogger(__name__)

BACKOFF_INITIAL: Final = 1.0
BACKOFF_MAX: Final = 300.0
STABLE_AFTER: Final = 60.0
FAILURES_BEFORE_REPAIR: Final = 3
SOCKET_WAIT: Final = 15.0
STOP_TIMEOUT: Final = 5.0
# Turns off the agent's own OpenTelemetry (agent 0.3.1+). Telemetry is always
# on (architecture section 10.1), so it is removed from the agent's environment.
TELEMETRY_OFF_ENV: Final = "QUICHARC_OTEL_DISABLED"
# deployment.environment.name for the agent's telemetry, the same as the
# integration's (agent 0.3.x; it would otherwise guess from the hostname).
TELEMETRY_ENVIRONMENT_ENV: Final = "QUICHARC_OTEL_ENVIRONMENT"

type EventHandler = Callable[[str, dict[str, Any]], None]
type ConnectedHandler = Callable[[], Awaitable[None]]
type FailureHandler = Callable[[Exception | None], None]


class AgentSupervisor:
    """Run the agent, keep a socket connection to it and restart it on failure."""

    def __init__(
        self,
        hass: HomeAssistant,
        data_dir: Path,
        binary: AgentBinary,
        *,
        telemetry: Telemetry,
        on_event: EventHandler,
        on_connected: ConnectedHandler,
        on_failure: FailureHandler,
        on_recovered: Callable[[], None],
        on_disconnected: Callable[[], None],
    ) -> None:
        """Initialize."""
        self._hass = hass
        self._data_dir = data_dir
        self._binary = binary
        self._telemetry = telemetry
        self._on_event = on_event
        self._on_connected = on_connected
        self._on_failure = on_failure
        self._on_recovered = on_recovered
        self._on_disconnected = on_disconnected
        self._process: asyncio.subprocess.Process | None = None
        self._client: AgentClient | None = None
        self._task: asyncio.Task[None] | None = None
        self._stopping = False
        self.failures = 0
        self.last_error: str | None = None
        self.started_at: float | None = None
        self._first_parent: SpanContext | None = None

    @property
    def socket_path(self) -> Path:
        """Return the agent socket path."""
        return self._data_dir / SOCKET_NAME

    @property
    def connected(self) -> bool:
        """Return True when the socket connection is up."""
        return self._client is not None and self._client.connected

    @property
    def agent_version(self) -> str | None:
        """Return the version the running agent reported."""
        return self._client.agent_version if self._client else None

    @property
    def pid(self) -> int | None:
        """Return the agent's process id."""
        return self._process.pid if self._process else None

    def start(self) -> None:
        """Start supervising."""
        self._stopping = False
        # The first start belongs to whatever trace is current (setup); the
        # task itself runs in an empty context, so failures and logs hours
        # later aren't attributed to that trace.
        span = current_span()
        self._first_parent = span.context if span is not None else None
        self._task = contextvars.Context().run(
            self._hass.async_create_background_task,
            self._run(),
            "quicharc agent supervisor",
        )

    async def async_stop(self) -> None:
        """Stop the agent and the supervisor."""
        self._stopping = True
        if self._client is not None and self._client.connected:
            with contextlib.suppress(AgentError):
                await self._client.async_request("shutdown")
        await self._stop_process()
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None

    async def async_request(
        self, method: str, params: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Send a request to the agent."""
        with child_span(
            f"agent {method}",
            kind=KIND_CLIENT,
            attributes={"rpc.system": "quicharc-agent", "rpc.method": method},
        ):
            if self._client is None:
                raise AgentConnectionError("agent not running")
            return await self._client.async_request(
                method, params, traceparent=traceparent()
            )

    async def _run(self) -> None:
        backoff = BACKOFF_INITIAL
        attempt = 0
        while not self._stopping:
            began = time.monotonic()
            error: Exception | None = None
            try:
                await self._run_once(attempt)
            except asyncio.CancelledError:
                raise
            except (AgentBinaryError, AgentError, OSError) as err:
                error = err
            except Exception as err:
                # Anything else (a malformed agent reply, a bug in a callback)
                # must not end supervision; treat it as an agent failure.
                _LOGGER.exception("Unexpected error supervising the QuicHarc agent")
                error = err
            if self._stopping:
                return

            if time.monotonic() - began >= STABLE_AFTER:
                self.failures = 0
                backoff = BACKOFF_INITIAL
            self.failures += 1
            self.last_error = str(error) if error else "agent exited"
            self._telemetry.metrics.add(
                AGENT_RESTARTS, reason=type(error).__name__ if error else "exited"
            )
            _LOGGER.warning(
                "QuicHarc agent stopped (%s); restarting in %.0f s",
                self.last_error,
                backoff,
            )
            if self.failures >= FAILURES_BEFORE_REPAIR or isinstance(
                error, AgentBinaryError
            ):
                self._on_failure(error)
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, BACKOFF_MAX)
            attempt += 1

    async def _run_once(self, attempt: int) -> None:
        """Start the agent, connect, configure it, then wait until it stops.

        Each start is a span: the first is part of the integration's setup
        trace, every restart starts a trace of its own.
        """
        span = self._telemetry.start_span(
            "agent.start",
            parent=self._first_parent if attempt == 0 else None,
            attributes={
                "quicharc.agent.attempt": attempt,
                "quicharc.agent.pinned_version": self._binary.version,
                "quicharc.agent.previous_error": self.last_error if attempt else None,
            },
        )
        stderr_task: asyncio.Task[None] | None = None
        try:
            with run_span(span):
                stderr_task = await self._start(span)
            await self._watch()
        finally:
            if self._client is not None:
                await self._client.async_close()
                self._client = None
                self._on_disconnected()
            await self._stop_process()
            if stderr_task is not None:
                stderr_task.cancel()

    async def _start(self, span: AnySpan) -> asyncio.Task[None]:
        binary = await self._binary.async_ensure()
        await self._hass.async_add_executor_job(self._prepare_dir)
        env = {
            k: v
            for k, v in os.environ.items()
            if k not in (TELEMETRY_OFF_ENV, TELEMETRY_ENVIRONMENT_ENV)
        }
        if self._telemetry.environment:
            env[TELEMETRY_ENVIRONMENT_ENV] = self._telemetry.environment
        self._process = await asyncio.create_subprocess_exec(
            str(binary),
            "--socket",
            str(self.socket_path),
            "--data-dir",
            str(self._data_dir),
            # Direct LAN QUIC for native clients; announced as _quicharc._udp.
            "--lan-listen",
            f":{DEFAULT_LAN_PORT}",
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        self.started_at = time.time()
        span.set_attribute("process.pid", self._process.pid)
        stderr_task = asyncio.create_task(
            self._forward_stderr(self._process), context=contextvars.Context()
        )
        try:
            with child_span("agent.connect"):
                self._client = await self._connect()
            span.set_attribute("quicharc.agent.version", self._client.agent_version)
            await self._on_connected()
        except BaseException:
            stderr_task.cancel()
            raise
        if self.failures:
            self._on_recovered()
        return stderr_task

    async def _watch(self) -> None:
        """Wait until the agent exits or its connection drops."""
        assert self._process is not None and self._client is not None
        stable = asyncio.create_task(self._mark_stable())
        try:
            done, _ = await asyncio.wait(
                [
                    asyncio.create_task(self._process.wait()),
                    asyncio.create_task(self._client.closed.wait()),
                ],
                return_when=asyncio.FIRST_COMPLETED,
            )
            for task in done:
                task.result()
        finally:
            stable.cancel()

    async def _mark_stable(self) -> None:
        await asyncio.sleep(STABLE_AFTER)
        if self.failures:
            self.failures = 0
            self.last_error = None

    async def _connect(self) -> AgentClient:
        deadline = time.monotonic() + SOCKET_WAIT
        while True:
            if self._process is not None and self._process.returncode is not None:
                raise AgentConnectionError(
                    f"agent exited with code {self._process.returncode}"
                )
            client = AgentClient(str(self.socket_path), self._on_event)
            try:
                await client.async_connect()
            except AgentConnectionError:
                if time.monotonic() > deadline:
                    raise
                await asyncio.sleep(0.25)
                continue
            return client

    async def _stop_process(self) -> None:
        process = self._process
        if process is None or process.returncode is not None:
            self._process = None
            return
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(process.wait(), STOP_TIMEOUT)
        if process.returncode is None:
            with contextlib.suppress(ProcessLookupError):
                process.terminate()
            try:
                await asyncio.wait_for(process.wait(), STOP_TIMEOUT)
            except TimeoutError:
                with contextlib.suppress(ProcessLookupError):
                    process.kill()
                await process.wait()
        self._process = None

    def _prepare_dir(self) -> None:
        self._data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._data_dir.chmod(0o700)

    @staticmethod
    async def _forward_stderr(process: asyncio.subprocess.Process) -> None:
        assert process.stderr is not None
        while line := await process.stderr.readline():
            _LOGGER.debug("agent: %s", line.decode(errors="replace").rstrip())
