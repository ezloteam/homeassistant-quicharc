"""Make Home Assistant trust forwarded client IPs from the agent (section 7.5).

The agent connects to Home Assistant over loopback, so Home Assistant has to
accept X-Forwarded-For from 127.0.0.1 and ::1. That setting lives in YAML
and is read only at startup.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
import io
import ipaddress
import logging
import os
from pathlib import Path
import shutil
from typing import Any, Final

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap, CommentedSeq, TaggedScalar
from ruamel.yaml.error import YAMLError

from homeassistant.config import async_check_ha_config_file
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.util.yaml import Secrets, load_yaml_dict

from .otel.logs import NOT_EXPORTED

_LOGGER = logging.getLogger(__name__)

LOOPBACK: Final = ("127.0.0.1", "::1")
BACKUP_SUFFIX: Final = ".quicharc-backup"
SNIPPET: Final = """http:
  use_x_forwarded_for: true
  trusted_proxies:
    - 127.0.0.1
    - ::1"""


class Status(StrEnum):
    """Outcome of inspecting the configuration."""

    ALREADY_TRUSTED = "already_trusted"
    EDITABLE = "editable"
    MANUAL = "manual"


@dataclass(frozen=True, slots=True)
class Plan:
    """What the editor will do, or why it can't."""

    status: Status
    target: Path | None = None
    reason: str | None = None


class EditFailed(HomeAssistantError):
    """The edit was rolled back."""


def _yaml() -> YAML:
    yaml = YAML()
    yaml.preserve_quotes = True
    yaml.width = 4096
    yaml.indent(mapping=2, sequence=4, offset=2)
    return yaml


def _covers(proxies: list[Any], addr: str) -> bool:
    """Return True if any trusted_proxies entry contains addr."""
    ip = ipaddress.ip_address(addr)
    for entry in proxies:
        try:
            if ip in ipaddress.ip_network(str(entry), strict=False):
                return True
        except ValueError:
            continue
    return False


def _covers_loopback(proxies: list[Any]) -> bool:
    return all(_covers(proxies, addr) for addr in LOOPBACK)


def _http_is_trusting(http: Any) -> bool:
    if not isinstance(http, dict) or http.get("use_x_forwarded_for") is not True:
        return False
    proxies = http.get("trusted_proxies")
    if isinstance(proxies, str):
        proxies = [proxies]
    return isinstance(proxies, list) and _covers_loopback(proxies)


def _load_resolved(config_dir: Path) -> dict[str, Any]:
    """Load configuration.yaml the way Home Assistant does, resolving tags."""
    return load_yaml_dict(
        str(config_dir / "configuration.yaml"), secrets=Secrets(config_dir)
    )


def _packages_define_http(resolved: dict[str, Any]) -> bool:
    """Return True if any package defines http."""
    packages = (resolved.get("homeassistant") or {}).get("packages") or {}
    if not isinstance(packages, dict):
        return False
    return any(
        isinstance(package, dict) and "http" in package for package in packages.values()
    )


def plan(config_dir: Path) -> Plan:
    """Decide whether and where to edit. Runs in the executor."""
    main = config_dir / "configuration.yaml"
    try:
        resolved = _load_resolved(config_dir)
    except HomeAssistantError as err:
        return Plan(Status.MANUAL, reason=f"configuration.yaml can't be read: {err}")
    if _http_is_trusting(resolved.get("http")):
        return Plan(Status.ALREADY_TRUSTED)
    if _packages_define_http(resolved):
        return Plan(Status.MANUAL, reason="http is configured in a package")

    try:
        return _plan_edit(config_dir, main)
    except (YAMLError, OSError) as err:
        return Plan(Status.MANUAL, reason=f"the YAML can't be edited safely: {err}")


def _plan_edit(config_dir: Path, main: Path) -> Plan:
    doc = _yaml().load(main.read_text(encoding="utf-8"))
    if not isinstance(doc, CommentedMap):
        return Plan(Status.MANUAL, reason="configuration.yaml is not a mapping")

    http = doc.get("http")
    target = main
    if isinstance(http, TaggedScalar):
        if http.tag.value != "!include":
            return Plan(Status.MANUAL, reason=f"http comes from {http.tag.value}")
        target = (main.parent / str(http.value)).resolve()
        if not target.is_relative_to(config_dir.resolve()) or not target.is_file():
            return Plan(Status.MANUAL, reason=f"can't edit {http.value}")
        http = _yaml().load(target.read_text(encoding="utf-8"))
        if http is not None and not isinstance(http, CommentedMap):
            return Plan(Status.MANUAL, reason=f"{target.name} is not a mapping")
    elif http is not None and not isinstance(http, CommentedMap):
        return Plan(Status.MANUAL, reason="http is not a mapping")

    if http is not None:
        for key in ("use_x_forwarded_for", "trusted_proxies"):
            if isinstance(http.get(key), TaggedScalar):
                return Plan(Status.MANUAL, reason=f"http.{key} uses a YAML tag")
    return Plan(Status.EDITABLE, target=target)


def _merge(http: CommentedMap) -> None:
    http["use_x_forwarded_for"] = True
    proxies = http.get("trusted_proxies")
    if proxies is None:
        proxies = CommentedSeq()
    elif isinstance(proxies, str):
        proxies = CommentedSeq([proxies])
    for addr in LOOPBACK:
        if not _covers(list(proxies), addr):
            proxies.append(addr)
    http["trusted_proxies"] = proxies


def render(target: Path, is_main: bool) -> str:
    """Return the edited text of target. Runs in the executor."""
    yaml = _yaml()
    doc = yaml.load(target.read_text(encoding="utf-8"))
    if is_main:
        http = doc.get("http")
        if not isinstance(http, CommentedMap):
            http = CommentedMap()
            doc["http"] = http
        _merge(http)
    else:
        if doc is None:
            doc = CommentedMap()
        _merge(doc)
    out = io.StringIO()
    yaml.dump(doc, out)
    return out.getvalue()


def _backup_path(target: Path) -> Path:
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return target.with_name(f"{target.name}{BACKUP_SUFFIX}-{stamp}")


def _write(target: Path, text: str) -> Path:
    backup = _backup_path(target)
    shutil.copy2(target, backup)
    tmp = target.with_name(f".{target.name}.quicharc-tmp")
    tmp.write_text(text, encoding="utf-8")
    shutil.copymode(target, tmp)
    stat = target.stat()
    with contextlib.suppress(OSError):
        os.chown(tmp, stat.st_uid, stat.st_gid)
    tmp.replace(target)
    return backup


def _restore(target: Path, backup: Path) -> None:
    shutil.copy2(backup, target)


async def _async_check(hass: HomeAssistant) -> str | None:
    """Run Home Assistant's configuration check; return the error, if any."""
    try:
        return await async_check_ha_config_file(hass)
    except Exception as err:
        return str(err)


async def async_plan(hass: HomeAssistant) -> Plan:
    """Inspect the configuration."""
    return await hass.async_add_executor_job(plan, Path(hass.config.config_dir))


async def async_apply(hass: HomeAssistant, edit_plan: Plan) -> Path:
    """Apply an editable plan, verify it, and roll back on failure.

    Returns the backup path. Raises EditFailed after restoring the backup.
    """
    assert edit_plan.status is Status.EDITABLE and edit_plan.target is not None
    # Write through symlinks (for example into a git-managed config) instead
    # of replacing them with regular files.
    target = edit_plan.target.resolve()
    if error := await _async_check(hass):
        raise EditFailed(f"the configuration already has errors: {error}")
    is_main = (
        target.resolve() == Path(hass.config.config_dir, "configuration.yaml").resolve()
    )
    text = await hass.async_add_executor_job(render, target, is_main)
    backup = await hass.async_add_executor_job(_write, target, text)
    if error := await _async_check(hass):
        await hass.async_add_executor_job(_restore, target, backup)
        _LOGGER.error(
            "Configuration check failed after edit, restored backup: %s",
            error,
            extra=NOT_EXPORTED,
        )
        raise EditFailed(f"the configuration check failed after editing: {error}")
    _LOGGER.info("Edited %s to trust the QuicHarc agent; backup at %s", target, backup)
    return backup
