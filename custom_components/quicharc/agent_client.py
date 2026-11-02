"""Client for the agent's Unix socket protocol (docs/agent-protocol.md)."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
import contextlib
import contextvars
import json
import logging
from typing import Any, Final

from .const import PROTOCOL_MAX, PROTOCOL_MIN, VERSION

_LOGGER = logging.getLogger(__name__)

MAX_LINE: Final = 1024 * 1024
REQUEST_TIMEOUT: Final = 30.0

type EventCallback = Callable[[str, dict[str, Any]], None]


class AgentError(Exception):
    """Base error for agent communication."""


class AgentConnectionError(AgentError):
    """The socket isn't connected or the connection dropped."""


class AgentRequestError(AgentError):
    """The agent answered a request with an error."""

    def __init__(self, code: str, message: str) -> None:
        """Initialize."""
        super().__init__(f"{code}: {message}")
        self.code = code


class AgentClient:
    """One connection to the agent's socket."""

    def __init__(self, socket_path: str, on_event: EventCallback) -> None:
        """Initialize."""
        self._socket_path = socket_path
        self._on_event = on_event
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._next_id = 0
        self._pending: dict[int, asyncio.Future[dict[str, Any]]] = {}
        self._read_task: asyncio.Task[None] | None = None
        self.protocol: int | None = None
        self.agent_version: str | None = None
        self.capabilities: list[str] = []
        self.closed = asyncio.Event()

    @property
    def connected(self) -> bool:
        """Return True while the connection is up."""
        return self._writer is not None and not self.closed.is_set()

    async def async_connect(self) -> None:
        """Connect and run the handshake."""
        try:
            self._reader, self._writer = await asyncio.open_unix_connection(
                self._socket_path, limit=MAX_LINE
            )
        except OSError as err:
            raise AgentConnectionError(str(err)) from err

        await self._send(
            {
                "type": "hello",
                "protocol": {"min": PROTOCOL_MIN, "max": PROTOCOL_MAX},
                "client": f"homeassistant-quicharc/{VERSION}",
            }
        )
        try:
            hello = await asyncio.wait_for(self._read_message(), REQUEST_TIMEOUT)
        except (TimeoutError, AgentConnectionError) as err:
            await self.async_close()
            raise AgentConnectionError(f"handshake failed: {err}") from err

        if hello.get("type") == "error":
            await self.async_close()
            error = hello.get("error") or {}
            raise AgentRequestError(
                error.get("code", "unknown"), error.get("message", "")
            )
        protocol = hello.get("protocol")
        if hello.get("type") != "hello" or not (
            isinstance(protocol, int) and PROTOCOL_MIN <= protocol <= PROTOCOL_MAX
        ):
            await self.async_close()
            raise AgentConnectionError(f"unexpected hello: {hello}")

        self.protocol = protocol
        self.agent_version = hello.get("agent")
        self.capabilities = list(hello.get("capabilities") or [])
        # A fresh context: events the agent sends later aren't part of
        # whatever trace was current when the connection was made.
        self._read_task = asyncio.create_task(
            self._read_loop(), context=contextvars.Context()
        )

    async def async_request(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        *,
        traceparent: str | None = None,
    ) -> dict[str, Any]:
        """Send a request and return its result.

        traceparent, when given, lets the agent continue the caller's trace.
        """
        if not self.connected:
            raise AgentConnectionError("not connected")
        self._next_id += 1
        request_id = self._next_id
        future: asyncio.Future[dict[str, Any]] = (
            asyncio.get_running_loop().create_future()
        )
        self._pending[request_id] = future
        try:
            message: dict[str, Any] = {
                "type": "request",
                "id": request_id,
                "method": method,
                "params": params or {},
            }
            if traceparent:
                message["traceparent"] = traceparent
            await self._send(message)
            response = await asyncio.wait_for(future, REQUEST_TIMEOUT)
        except TimeoutError as err:
            raise AgentConnectionError(f"{method} timed out") from err
        finally:
            self._pending.pop(request_id, None)

        if response.get("ok"):
            return response.get("result") or {}
        error = response.get("error") or {}
        raise AgentRequestError(error.get("code", "unknown"), error.get("message", ""))

    async def async_close(self) -> None:
        """Close the connection."""
        if self._read_task and self._read_task is not asyncio.current_task():
            self._read_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._read_task
        self._teardown()

    def _teardown(self) -> None:
        if self._writer is not None:
            self._writer.close()
        self._writer = None
        for future in self._pending.values():
            if not future.done():
                future.set_exception(AgentConnectionError("connection closed"))
        self._pending.clear()
        self.closed.set()

    async def _send(self, message: dict[str, Any]) -> None:
        if self._writer is None:
            raise AgentConnectionError("not connected")
        line = json.dumps(message, separators=(",", ":")).encode() + b"\n"
        try:
            self._writer.write(line)
            await self._writer.drain()
        except OSError as err:
            self._teardown()
            raise AgentConnectionError(str(err)) from err

    async def _read_message(self) -> dict[str, Any]:
        assert self._reader is not None
        while True:
            try:
                line = await self._reader.readline()
            except (OSError, ValueError) as err:
                raise AgentConnectionError(str(err)) from err
            if not line:
                raise AgentConnectionError("agent closed the connection")
            try:
                message = json.loads(line)
            except ValueError:
                _LOGGER.warning("Ignoring malformed line from agent: %r", line[:200])
                continue
            if isinstance(message, dict):
                return message

    async def _read_loop(self) -> None:
        try:
            while True:
                message = await self._read_message()
                kind = message.get("type")
                if kind == "response":
                    future = self._pending.get(message.get("id"))  # type: ignore[arg-type]
                    if future is not None and not future.done():
                        future.set_result(message)
                elif kind == "event":
                    event = message.get("event")
                    data = message.get("data")
                    if isinstance(event, str):
                        try:
                            self._on_event(
                                event, data if isinstance(data, dict) else {}
                            )
                        except Exception:
                            _LOGGER.exception("Error handling agent event %s", event)
        except AgentConnectionError as err:
            _LOGGER.debug("Agent connection ended: %s", err)
        finally:
            self._teardown()
