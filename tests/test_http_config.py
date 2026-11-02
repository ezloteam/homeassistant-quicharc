"""Tests for the configuration.yaml trusted-proxy editor (architecture 7.5)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from custom_components.quicharc import http_config
from custom_components.quicharc.const import (
    DOMAIN,
    ISSUE_HTTP_CONFIG_MANUAL,
    ISSUE_RESTART_REQUIRED,
)
from custom_components.quicharc.http_setup import async_ensure_http_config
from homeassistant.core import HomeAssistant
from homeassistant.helpers import issue_registry as ir
from homeassistant.util.yaml import Secrets, load_yaml_dict


@pytest.fixture(autouse=True)
def yaml_http_config():
    """These tests cover the YAML model (Home Assistant before 2026.8)."""
    with patch(
        "custom_components.quicharc.http_store.async_get_store", return_value=None
    ):
        yield


def _http(config_dir: Path) -> dict:
    return load_yaml_dict(
        str(config_dir / "configuration.yaml"), secrets=Secrets(config_dir)
    )["http"]


@pytest.mark.parametrize(
    ("name", "status"),
    [
        ("plain", http_config.Status.EDITABLE),
        ("existing_http", http_config.Status.EDITABLE),
        ("include", http_config.Status.EDITABLE),
        ("secret", http_config.Status.EDITABLE),
        ("already_trusted", http_config.Status.ALREADY_TRUSTED),
        ("cidr", http_config.Status.EDITABLE),
        ("packages_inline", http_config.Status.MANUAL),
        ("packages_dir", http_config.Status.MANUAL),
        ("include_dir", http_config.Status.MANUAL),
    ],
)
def test_plan(http_fixture, name: str, status: http_config.Status) -> None:
    """Each fixture gets the expected decision."""
    assert http_config.plan(http_fixture(name)).status is status


def _apply(config_dir: Path) -> None:
    plan = http_config.plan(config_dir)
    assert plan.target is not None
    is_main = plan.target.name == "configuration.yaml"
    plan.target.write_text(http_config.render(plan.target, is_main), encoding="utf-8")


def test_plain_adds_http_section_and_keeps_tags(http_fixture) -> None:
    """A file without http: gets one; comments and tags survive."""
    config_dir = http_fixture("plain")
    _apply(config_dir)
    text = (config_dir / "configuration.yaml").read_text()
    assert "# Loads default set of integrations. Do not remove." in text
    assert "themes: !include_dir_merge_named themes" in text
    assert "automation: !include automations.yaml" in text
    http = _http(config_dir)
    assert http["use_x_forwarded_for"] is True
    assert http["trusted_proxies"] == ["127.0.0.1", "::1"]
    assert http_config.plan(config_dir).status is http_config.Status.ALREADY_TRUSTED


def test_existing_http_merges(http_fixture) -> None:
    """Existing keys, comments and a scalar trusted_proxies are kept."""
    config_dir = http_fixture("existing_http")
    _apply(config_dir)
    text = (config_dir / "configuration.yaml").read_text()
    assert "# Keep the port explicit." in text
    http = _http(config_dir)
    assert http["server_port"] == 8123
    assert http["ip_ban_enabled"] is True
    assert http["trusted_proxies"] == ["172.30.33.0/24", "127.0.0.1", "::1"]
    assert http["use_x_forwarded_for"] is True
    assert load_yaml_dict(str(config_dir / "configuration.yaml"))["logger"] == {
        "default": "info"
    }


def test_include_edits_included_file(http_fixture) -> None:
    """http: !include http.yaml edits http.yaml, not configuration.yaml."""
    config_dir = http_fixture("include")
    before = (config_dir / "configuration.yaml").read_text()
    _apply(config_dir)
    assert (config_dir / "configuration.yaml").read_text() == before
    assert "# HTTP settings" in (config_dir / "http.yaml").read_text()
    http = _http(config_dir)
    assert http["cors_allowed_origins"] == ["https://example.com"]
    assert http["trusted_proxies"] == ["127.0.0.1", "::1"]


def test_secrets_survive(http_fixture) -> None:
    """!secret values are written back as tags, not resolved."""
    config_dir = http_fixture("secret")
    _apply(config_dir)
    text = (config_dir / "configuration.yaml").read_text()
    assert "ssl_certificate: !secret ssl_cert" in text
    assert "password: !secret smtp_password" in text
    assert "hunter2" not in text
    assert _http(config_dir)["ssl_certificate"] == "/ssl/fullchain.pem"


def test_cidr_adds_only_missing_address(http_fixture) -> None:
    """127.0.0.0/8 already covers 127.0.0.1, so only ::1 is added."""
    config_dir = http_fixture("cidr")
    _apply(config_dir)
    assert _http(config_dir)["trusted_proxies"] == ["127.0.0.0/8", "::1"]


def test_manual_reasons(http_fixture) -> None:
    """Unsafe layouts explain why."""
    assert "package" in (http_config.plan(http_fixture("packages_dir")).reason or "")
    assert "!include_dir_merge_named" in (
        http_config.plan(http_fixture("include_dir")).reason or ""
    )


async def test_ensure_edits_and_asks_for_restart(
    hass: HomeAssistant, http_fixture
) -> None:
    """The edit passes the config check, keeps a backup and raises restart."""
    config_dir = http_fixture("existing_http")
    hass.config.config_dir = str(config_dir)
    with patch.object(http_config, "async_check_ha_config_file", return_value=None):
        status = await async_ensure_http_config(hass)
    assert status is http_config.Status.EDITABLE
    assert list(config_dir.glob("configuration.yaml.quicharc-backup-*"))
    registry = ir.async_get(hass)
    assert registry.async_get_issue(DOMAIN, ISSUE_RESTART_REQUIRED)
    assert registry.async_get_issue(DOMAIN, ISSUE_HTTP_CONFIG_MANUAL) is None


async def test_ensure_rolls_back_on_failed_check(
    hass: HomeAssistant, http_fixture
) -> None:
    """A failing config check restores the original file and raises manual."""
    config_dir = http_fixture("existing_http")
    hass.config.config_dir = str(config_dir)
    before = (config_dir / "configuration.yaml").read_text()
    with patch.object(
        http_config, "async_check_ha_config_file", side_effect=[None, "Invalid config"]
    ):
        status = await async_ensure_http_config(hass)
    assert status is http_config.Status.MANUAL
    assert (config_dir / "configuration.yaml").read_text() == before
    issue = ir.async_get(hass).async_get_issue(DOMAIN, ISSUE_HTTP_CONFIG_MANUAL)
    assert issue is not None
    assert "Invalid config" in issue.translation_placeholders["reason"]


async def test_ensure_real_config_check(hass: HomeAssistant, http_fixture) -> None:
    """Home Assistant's own configuration check accepts the edited file."""
    config_dir = http_fixture("existing_http")
    hass.config.config_dir = str(config_dir)
    status = await async_ensure_http_config(hass)
    assert status is http_config.Status.EDITABLE
    assert _http(config_dir)["use_x_forwarded_for"] is True


async def test_ensure_skips_already_broken_config(
    hass: HomeAssistant, http_fixture
) -> None:
    """A configuration that fails the check before editing is left alone.

    The secret fixture points ssl_certificate at files that don't exist.
    """
    config_dir = http_fixture("secret")
    hass.config.config_dir = str(config_dir)
    before = (config_dir / "configuration.yaml").read_text()
    assert await async_ensure_http_config(hass) is http_config.Status.MANUAL
    assert (config_dir / "configuration.yaml").read_text() == before
    assert not list(config_dir.glob("*.quicharc-backup-*"))
    issue = ir.async_get(hass).async_get_issue(DOMAIN, ISSUE_HTTP_CONFIG_MANUAL)
    assert "already has errors" in issue.translation_placeholders["reason"]


async def test_ensure_manual_raises_snippet(hass: HomeAssistant, http_fixture) -> None:
    """A package-defined http gets the snippet, and no file changes."""
    config_dir = http_fixture("packages_inline")
    hass.config.config_dir = str(config_dir)
    before = (config_dir / "configuration.yaml").read_text()
    assert await async_ensure_http_config(hass) is http_config.Status.MANUAL
    assert (config_dir / "configuration.yaml").read_text() == before
    issue = ir.async_get(hass).async_get_issue(DOMAIN, ISSUE_HTTP_CONFIG_MANUAL)
    assert issue.translation_placeholders["snippet"] == http_config.SNIPPET


async def test_symlinked_configuration_stays_a_symlink(
    hass: HomeAssistant, http_fixture, tmp_path: Path
) -> None:
    """The edit writes through a symlinked configuration.yaml."""
    config_dir = http_fixture("existing_http")
    real = tmp_path / "repo-configuration.yaml"
    (config_dir / "configuration.yaml").rename(real)
    (config_dir / "configuration.yaml").symlink_to(real)
    hass.config.config_dir = str(config_dir)
    with patch.object(http_config, "async_check_ha_config_file", return_value=None):
        assert await async_ensure_http_config(hass) is http_config.Status.EDITABLE
    assert (config_dir / "configuration.yaml").is_symlink()
    assert "use_x_forwarded_for: true" in real.read_text()


def test_invalid_yaml_is_manual(http_fixture) -> None:
    """YAML ruamel can't round-trip leads to the manual snippet, not a crash."""
    config_dir = http_fixture("plain")
    with patch.object(
        http_config, "_plan_edit", side_effect=http_config.YAMLError("bad")
    ):
        plan = http_config.plan(config_dir)
    assert plan.status is http_config.Status.MANUAL
