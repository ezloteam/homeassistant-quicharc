"""Download and verify the pinned QuicHarc agent binary."""

from __future__ import annotations

import base64
from collections.abc import Awaitable, Callable
import hashlib
import logging
import os
from pathlib import Path
import platform
from typing import Final

import aiohttp
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from yarl import URL

from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .otel import KIND_CLIENT, child_span, trace_headers

_LOGGER = logging.getLogger(__name__)

# Each integration release pins one agent version. The quicharc repository's
# release-agent job (tag agent-v<version>) publishes the binaries with a raw
# Ed25519 .sig each and a SHA256SUMS file; the quicharc service serves them
# to signed-in users at {api}/agent/<version>/<file>. Copy the version and
# the SHA256SUMS lines here when bumping the agent.
AGENT_VERSION: Final[str | None] = "0.3.8"
AGENT_SHA256: Final[dict[str, str]] = {
    "amd64": "b7b1b38324bbddbf3f7e39271398331cb1d515cc321d94a0eac4a84857fcaf19",
    "arm64": "685d8e5ac9a76c0a60432d6da2b244a62238eade9a66a9cdd89e1b9d0ae67bab",
}
# quicharc release/agent-signing-key.pub: raw 32-byte Ed25519 public key, base64.
AGENT_SIGNING_KEY: Final = "3apvG1OHZlTWRim/+jsycoa/TdtjVvZtwo/1aBgXkBs="

_MACHINE_TO_ARCH: Final = {
    "x86_64": "amd64",
    "amd64": "amd64",
    "aarch64": "arm64",
    "arm64": "arm64",
}
_MAX_BINARY_BYTES: Final = 128 * 1024 * 1024


class AgentBinaryError(Exception):
    """The agent binary can't be obtained or failed verification."""


class UnsupportedArchitecture(AgentBinaryError):
    """No agent build exists for this machine."""


class VerificationFailed(AgentBinaryError):
    """The binary's hash or signature doesn't match the pinned values."""


class NoAgentPinned(AgentBinaryError):
    """This integration release doesn't pin an agent yet."""


def agent_arch(machine: str | None = None) -> str:
    """Return the agent build name for this machine."""
    machine = (machine or platform.machine()).lower()
    try:
        return _MACHINE_TO_ARCH[machine]
    except KeyError as err:
        raise UnsupportedArchitecture(machine) from err


def verify(
    data: bytes,
    signature: bytes,
    expected_sha256: str,
    public_key_b64: str = AGENT_SIGNING_KEY,
) -> None:
    """Raise VerificationFailed unless the hash and signature both match."""
    digest = hashlib.sha256(data).hexdigest()
    if digest != expected_sha256.lower():
        raise VerificationFailed(
            f"SHA-256 mismatch: expected {expected_sha256}, got {digest}"
        )
    key = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64))
    try:
        key.verify(signature, data)
    except InvalidSignature as err:
        raise VerificationFailed("signature does not verify") from err


class AgentBinary:
    """The agent binary on disk, kept at the pinned version."""

    def __init__(
        self,
        hass: HomeAssistant,
        data_dir: Path,
        *,
        base_url: str,
        auth: Callable[[], Awaitable[str]],
        version: str | None = AGENT_VERSION,
        hashes: dict[str, str] | None = None,
        signing_key: str = AGENT_SIGNING_KEY,
    ) -> None:
        """Initialize.

        base_url is the quicharc service's agent route ({api}/agent); auth
        returns the signed-in user's access token, which that route requires.
        """
        self._hass = hass
        self._data_dir = data_dir
        self.version = version
        self._base_url = base_url.rstrip("/")
        self._auth = auth
        self._hashes = hashes if hashes is not None else AGENT_SHA256
        self._signing_key = signing_key

    @property
    def path(self) -> Path:
        """Return where the binary for the pinned version lives."""
        return self._data_dir / "bin" / f"quicharc-agent-{self.version}"

    async def async_ensure(self) -> Path:
        """Return the path of a verified binary, downloading it if needed."""
        if self.version is None:
            raise NoAgentPinned("this release of the integration pins no agent yet")
        arch = agent_arch()
        expected = self._hashes.get(arch)
        if expected is None:
            raise UnsupportedArchitecture(arch)

        with child_span(
            "agent.binary",
            attributes={
                "quicharc.agent.pinned_version": self.version,
                "host.arch": arch,
            },
        ) as span:
            cached = await self._hass.async_add_executor_job(
                self._verify_on_disk, expected
            )
            span.set_attribute("quicharc.agent.cached", cached)
            if not cached:
                await self._async_download(arch, expected)
        return self.path

    async def _async_download(self, arch: str, expected: str) -> None:
        name = f"quicharc-agent-linux-{arch}"
        url = f"{self._base_url}/{self.version}/{name}"
        session = async_get_clientsession(self._hass)
        _LOGGER.info("Downloading QuicHarc agent %s from %s", self.version, url)
        with child_span(
            "agent.download",
            kind=KIND_CLIENT,
            attributes={
                "http.request.method": "GET",
                "url.template": "/agent/{version}/{file}",
                "server.address": URL(url).host,
            },
        ) as span:
            data = await self._fetch(session, url)
            signature = await self._fetch(session, f"{url}.sig")
            span.set_attribute("http.response.body.size", len(data))
        with child_span("agent.verify", attributes={"quicharc.agent.sha256": expected}):
            verify(data, signature, expected, self._signing_key)
        await self._hass.async_add_executor_job(self._install, data)

    async def _fetch(self, session: aiohttp.ClientSession, url: str) -> bytes:
        token = await self._auth()
        try:
            async with session.get(
                url,
                headers={"Authorization": f"Bearer {token}", **trace_headers()},
                timeout=aiohttp.ClientTimeout(total=300),
            ) as resp:
                resp.raise_for_status()
                data = await resp.read()
        except (aiohttp.ClientError, TimeoutError) as err:
            raise AgentBinaryError(f"download of {url} failed: {err}") from err
        if len(data) > _MAX_BINARY_BYTES:
            raise AgentBinaryError(f"{url} is too large")
        return data

    def _verify_on_disk(self, expected: str) -> bool:
        """Return True when the installed binary matches the pinned hash.

        Runs before every start, so a binary changed on disk is never run.
        """
        try:
            data = self.path.read_bytes()
        except FileNotFoundError:
            return False
        if hashlib.sha256(data).hexdigest() == expected.lower():
            return True
        _LOGGER.warning("Installed agent %s doesn't match its hash", self.path)
        self.path.unlink(missing_ok=True)
        return False

    def _install(self, data: bytes) -> None:
        bin_dir = self.path.parent
        bin_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_bytes(data)
        tmp.chmod(0o700)
        os.replace(tmp, self.path)
        for old in bin_dir.glob("quicharc-agent-*"):
            if old != self.path:
                old.unlink(missing_ok=True)
