"""Constants for the QuicHarc integration."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

DOMAIN: Final = "quicharc"
VERSION: Final = "0.2.14"

EVENT_NOTIFICATION: Final = "quicharc_notification"

PROTOCOL_MIN: Final = 1
PROTOCOL_MAX: Final = 1

DATA_DIR_NAME: Final = ".quicharc"
SOCKET_NAME: Final = "agent.sock"
DEFAULT_LAN_PORT: Final = 4433

CONF_ENVIRONMENT: Final = "environment"
CONF_HOME_ID: Final = "home_id"
CONF_HOSTNAME: Final = "hostname"
CONF_EZLO_USER_UUID: Final = "ezlo_user_uuid"
CONF_EZLO_USER_EMAIL: Final = "ezlo_user_email"
CONF_HA_USER_ID: Final = "ha_user_id"
CONF_EDIT_HTTP_CONFIG: Final = "edit_http_config"
# Set by the flow's "Change it and restart now"; cleared once acted on.
CONF_RESTART_AFTER_HTTP_EDIT: Final = "restart_after_http_edit"
# The flow's HTTP step: one choice instead of a checkbox and a later repair.
HTTP_ACTION: Final = "http_action"
HTTP_RESTART_NOW: Final = "restart_now"
HTTP_LATER: Final = "later"
HTTP_SKIP: Final = "skip"
CONF_WEB_ACCESS: Final = "web_access"
CONF_AUTO_APPROVE_OWNER: Final = "auto_approve_owner"
# "Share diagnostics with Ezlo", removed in 0.2.2: telemetry is always on
# (architecture section 10.1). Config entry minor version 2 drops it.
CONF_TELEMETRY: Final = "telemetry"

# OpenTelemetry (architecture section 10): OTLP/HTTP to Ezlo's shared ingest,
# at <endpoint>/traces, /logs and /metrics.
SERVICE_NAME: Final = "homeassistant-quicharc"
TELEMETRY_ENDPOINT: Final = "https://ot.ezlo.com"

# Client id the QuicHarc iOS app presents to Home Assistant's /auth/token when
# it refreshes. Home Assistant binds each refresh token to a client id.
IOS_CLIENT_ID: Final = "https://ezlo.com/quicharc/ios"
IOS_CLIENT_NAME: Final = "QuicHarc"

# Service peers (by quicharc service peer id) that may receive a Home
# Assistant token, and the name the token shows under in Home Assistant.
SERVICE_PEER_CLIENT_NAMES: Final = {
    "integrations-homeassistant": "Ezlo cloud",
}
# Other names a token request may use for a service peer.
SERVICE_PEER_ALIASES: Final = {
    "integrations/homeassistant": "integrations-homeassistant",
}
# The service peer behind the "Ezlo device sync" switch.
DEVICE_SYNC_PEER: Final = "integrations-homeassistant"

# Repair issue ids.
ISSUE_AGENT_FAILED: Final = "agent_failed"
ISSUE_AGENT_VERIFY_FAILED: Final = "agent_verify_failed"
ISSUE_UNSUPPORTED_ARCH: Final = "unsupported_arch"
ISSUE_CLOCK_SKEW: Final = "clock_skew"
ISSUE_RESTART_REQUIRED: Final = "restart_required"
ISSUE_HTTP_CONFIG_MANUAL: Final = "http_config_manual"
# The account had remote access and lost it; subscription_required when it
# never had it (or the service doesn't say).
ISSUE_SUBSCRIPTION_LAPSED: Final = "subscription_lapsed"
ISSUE_SUBSCRIPTION_REQUIRED: Final = "subscription_required"
# Another installation (a restored backup, a cloned machine) runs with this
# home's key and took the edge link; this agent stays off until reclaimed.
ISSUE_IDENTITY_CONFLICT: Final = "identity_conflict"
ISSUE_PAIRING_PREFIX: Final = "pairing_"

CLOCK_SKEW_TOLERANCE_SECONDS: Final = 300


@dataclass(frozen=True, slots=True)
class Environment:
    """One Ezlo cloud environment."""

    key: str
    name: str
    issuer: str
    api_base: str
    client_id: str | None

    @property
    def authorize_url(self) -> str:
        """Return the OpenID Connect authorization endpoint."""
        return f"{self.issuer}/oauth/authorize"

    @property
    def token_url(self) -> str:
        """Return the OpenID Connect token endpoint."""
        return f"{self.issuer}/oauth/token"


# cloud/login's public client for this integration in each environment. An
# environment without one isn't offered at sign-in.
ENVIRONMENTS: Final[dict[str, Environment]] = {
    "live": Environment(
        key="live",
        name="Ezlo",
        issuer="https://api-cloud.ezlo.com/api/v4/login/3",
        api_base="https://api-cloud.ezlo.com/api/v4/quicharc/1",
        client_id="c63290a1-d9ee-4b6f-99b5-3615045941a1",
    ),
    "stg": Environment(
        key="stg",
        name="Ezlo (staging)",
        issuer="https://api-cloud-stg.ezlo.com/api/v4/login/3",
        api_base="https://api-cloud-stg.ezlo.com/api/v4/quicharc/1",
        client_id="bcb6643f-83c4-497f-b895-2cfc1f2e62b5",
    ),
}
DEFAULT_ENVIRONMENT: Final = "live"
# configuration.yaml `quicharc: environment: staging` makes new sign-ins use
# Ezlo staging instead of live. Developers only: users never choose.
CONF_YAML_ENVIRONMENT: Final = "environment"
YAML_ENVIRONMENTS: Final = {"live": "live", "staging": "stg"}
OAUTH_SCOPES: Final = ["openid", "email", "profile"]


def environment_from_config(config: dict) -> str:
    """Return the environment key configuration.yaml chose (live by default)."""
    chosen = (config.get(DOMAIN) or {}).get(CONF_YAML_ENVIRONMENT, "live")
    return YAML_ENVIRONMENTS.get(chosen, DEFAULT_ENVIRONMENT)


def implementation_domain(env: str) -> str:
    """Return the OAuth implementation domain for an environment."""
    return DOMAIN if env == DEFAULT_ENVIRONMENT else f"{DOMAIN}_{env}"


def environment_for_implementation(implementation: str) -> Environment:
    """Return the environment an OAuth implementation domain belongs to."""
    for env in ENVIRONMENTS:
        if implementation_domain(env) == implementation:
            return ENVIRONMENTS[env]
    return ENVIRONMENTS[DEFAULT_ENVIRONMENT]
