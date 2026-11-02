"""Config flow: Sign in with Ezlo, pick the owner, consent to the HTTP edit."""

from __future__ import annotations

from collections.abc import Mapping
import logging
from typing import Any

from homeassistant.config_entries import (
    SOURCE_REAUTH,
    ConfigEntry,
    ConfigFlowResult,
    OptionsFlow,
)
from homeassistant.core import callback
from homeassistant.helpers import config_entry_oauth2_flow
from homeassistant.helpers.selector import (
    BooleanSelector,
    SelectOptionDict,
    SelectSelector,
    SelectSelectorConfig,
)
from homeassistant.setup import async_setup_component

from . import http_config, http_store, identity
from .const import (
    CONF_AUTO_APPROVE_OWNER,
    CONF_EDIT_HTTP_CONFIG,
    CONF_ENVIRONMENT,
    CONF_EZLO_USER_EMAIL,
    CONF_EZLO_USER_UUID,
    CONF_HA_USER_ID,
    CONF_RESTART_AFTER_HTTP_EDIT,
    CONF_WEB_ACCESS,
    DEFAULT_ENVIRONMENT,
    DOMAIN,
    ENVIRONMENTS,
    HTTP_ACTION,
    HTTP_LATER,
    HTTP_RESTART_NOW,
    HTTP_SKIP,
    environment_for_implementation,
    implementation_domain,
)
from .http_setup import async_ensure_http_config
from .oauth import (
    async_get_environment,
    async_register_implementation,
    async_register_implementations,
)
from .otel import NOOP, AnySpan, async_get_telemetry, use_span
from .schema import vol
from .tokens import async_selectable_users

_LOGGER = logging.getLogger(__name__)


async def _async_user_options(hass) -> list[SelectOptionDict]:
    return [
        SelectOptionDict(value=user.id, label=user.name or user.id)
        for user in await async_selectable_users(hass)
    ]


class QuicHarcFlowHandler(
    config_entry_oauth2_flow.AbstractOAuth2FlowHandler, domain=DOMAIN
):
    """Handle the QuicHarc config flow."""

    DOMAIN = DOMAIN
    VERSION = 1
    MINOR_VERSION = 2

    def __init__(self) -> None:
        """Initialize."""
        super().__init__()
        self._oauth_data: dict[str, Any] = {}
        self._ha_user_id: str | None = None
        self._plan: http_config.Plan | None = None
        # Sign in with Ezlo is one trace, from the first step until the flow
        # ends, across the browser round trip.
        self._span: AnySpan = NOOP
        self._outcome = "abandoned"

    @property
    def logger(self) -> logging.Logger:
        """Return the logger."""
        return _LOGGER

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Start Sign in with Ezlo."""
        await self._async_start_trace()
        with use_span(self._span):
            await self._async_prepare_oauth()
            return await super().async_step_user(user_input)

    async def async_step_pick_implementation(
        self, user_input: dict | None = None
    ) -> ConfigFlowResult:
        """Sign in to the one environment new sign-ins use; never ask.

        Reauth passes its entry's implementation, which Home Assistant's own
        step handles, so a staging entry still reauthenticates.
        """
        if user_input is None:
            env = await async_get_environment(self.hass)
            implementations = await config_entry_oauth2_flow.async_get_implementations(
                self.hass, DOMAIN
            )
            if (
                impl := implementations.get(implementation_domain(env.key))
            ) is not None:
                self.flow_impl = impl
                return await self.async_step_auth()
        return await super().async_step_pick_implementation(user_input)

    async def _async_start_trace(self) -> None:
        telemetry = await async_get_telemetry(self.hass)
        self._span = telemetry.start_span(
            "sign_in", root=True, attributes={"quicharc.flow.source": self.source}
        )

    async def async_step_creation(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Redeem the authorization code, as part of the sign-in trace."""
        self._span.add_event("oauth.callback")
        with use_span(self._span):
            return await super().async_step_creation(user_input)

    @callback
    def async_remove(self) -> None:
        """End the sign-in trace when the flow ends, however it ends."""
        self._span.set_attribute("quicharc.flow.outcome", self._outcome)
        if self._outcome not in ("created", "reauthenticated"):
            self._span.set_error(self._outcome)
        self._span.end()
        super().async_remove()

    async def _async_prepare_oauth(self) -> None:
        """Register Sign in with Ezlo and make sure the redirect is my.home-assistant.io.

        cloud/login only accepts the registered redirect
        https://my.home-assistant.io/redirect/oauth, which Home Assistant
        uses only while the my integration is loaded; without default_config
        (or before it has loaded) the redirect would be this instance's own
        URL and the sign-in would be refused.
        """
        await async_register_implementations(self.hass)
        await async_setup_component(self.hass, "my", {})

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> OptionsFlow:
        """Return the options flow."""
        return QuicHarcOptionsFlow()

    async def async_oauth_create_entry(self, data: dict[str, Any]) -> ConfigFlowResult:
        """Identify the Ezlo user, then continue to the remaining steps."""
        env = environment_for_implementation(data["auth_implementation"])
        # The quicharc service identifies the caller by user_uuid, and key
        # proofs must name it, so it comes from the access token's user
        # envelope. (The id_token's sub is a different, numeric user id.)
        user_uuid = identity.user_uuid(data["token"])
        (await async_get_telemetry(self.hass)).async_configure(environment=env.key)
        self._span.set_attributes(
            {"quicharc.environment": env.key, "quicharc.ezlo_user_uuid": user_uuid}
        )
        if user_uuid is None:
            _LOGGER.error("The Ezlo access token carries no user uuid")
            self._outcome = "no_user_uuid"
            return self.async_abort(reason="no_user_uuid")
        email = identity.user_email(data["token"])

        await self.async_set_unique_id(user_uuid)
        data = {
            **data,
            CONF_ENVIRONMENT: env.key,
            CONF_EZLO_USER_UUID: user_uuid,
            CONF_EZLO_USER_EMAIL: email,
        }

        if self.source == SOURCE_REAUTH:
            entry = self._get_reauth_entry()
            if entry.unique_id != user_uuid:
                self._outcome = "wrong_account"
                return self.async_abort(reason="wrong_account")
            self._outcome = "reauthenticated"
            _LOGGER.info("Signed in with Ezlo again")
            return self.async_update_reload_and_abort(
                entry, data={**entry.data, **data}
            )

        self._outcome = "already_configured"
        self._abort_if_unique_id_configured()
        self._outcome = "abandoned"
        self._oauth_data = data
        return await self.async_step_owner()

    async def async_step_owner(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Pick the Home Assistant user the owner's devices and services act as."""
        options = await _async_user_options(self.hass)
        if user_input is not None:
            self._ha_user_id = user_input[CONF_HA_USER_ID]
            with use_span(self._span):
                return await self.async_step_http()
        return self.async_show_form(
            step_id="owner",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_HA_USER_ID,
                        default=options[0]["value"] if options else vol.UNDEFINED,
                    ): SelectSelector(SelectSelectorConfig(options=options)),
                }
            ),
            description_placeholders={
                "email": str(self._oauth_data.get(CONF_EZLO_USER_EMAIL) or "")
            },
        )

    async def async_step_http(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Ask before changing the HTTP settings, and whether to restart now."""
        if self._plan is None:
            self._plan = await self._async_http_plan()
        if self._plan.status is not http_config.Status.EDITABLE:
            return self._async_create()
        if user_input is not None:
            action = user_input[HTTP_ACTION]
            with use_span(self._span):
                return self._async_create(
                    edit_http=action != HTTP_SKIP,
                    restart=action == HTTP_RESTART_NOW,
                )
        return self.async_show_form(
            step_id="http",
            data_schema=vol.Schema(
                {
                    vol.Required(HTTP_ACTION, default=HTTP_RESTART_NOW): SelectSelector(
                        SelectSelectorConfig(
                            options=[HTTP_RESTART_NOW, HTTP_LATER, HTTP_SKIP],
                            translation_key=HTTP_ACTION,
                        )
                    )
                }
            ),
            description_placeholders={
                "file": self._plan.target.name
                if self._plan.target
                else "Settings > System > Network"
            },
        )

    async def _async_http_plan(self) -> http_config.Plan:
        """Decide whether to offer the HTTP change, for either storage model."""
        if (store := await http_store.async_get_store(self.hass)) is None:
            return await http_config.async_plan(self.hass)
        if http_store.is_trusting(http_store.running_config(store)):
            return http_config.Plan(http_config.Status.ALREADY_TRUSTED)
        return http_config.Plan(http_config.Status.EDITABLE)

    def _async_create(
        self, edit_http: bool = False, restart: bool = False
    ) -> ConfigFlowResult:
        self._outcome = "created"
        self._span.set_attribute("quicharc.http_config.edit", edit_http)
        self._span.set_attribute("quicharc.http_config.restart_now", restart)
        _LOGGER.info("Signed in with Ezlo; setting up QuicHarc")
        return self.async_create_entry(
            title=str(self._oauth_data.get(CONF_EZLO_USER_EMAIL) or "QuicHarc"),
            data={
                **self._oauth_data,
                CONF_HA_USER_ID: self._ha_user_id,
                CONF_EDIT_HTTP_CONFIG: edit_http,
                CONF_RESTART_AFTER_HTTP_EDIT: restart,
            },
            options={
                CONF_WEB_ACCESS: False,
                CONF_AUTO_APPROVE_OWNER: True,
            },
        )

    async def async_step_reauth(
        self, entry_data: Mapping[str, Any]
    ) -> ConfigFlowResult:
        """Start reauthentication when the Ezlo session is no longer valid."""
        await self._async_start_trace()
        await self._async_prepare_oauth()
        async_register_implementation(
            self.hass,
            ENVIRONMENTS[entry_data.get(CONF_ENVIRONMENT, DEFAULT_ENVIRONMENT)],
        )
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Confirm reauthentication."""
        if user_input is None:
            return self.async_show_form(step_id="reauth_confirm")
        with use_span(self._span):
            return await self.async_step_pick_implementation(
                user_input={
                    "implementation": self._get_reauth_entry().data[
                        "auth_implementation"
                    ]
                }
            )


class QuicHarcOptionsFlow(OptionsFlow):
    """Options: owner auto-approval and the HTTP edit."""

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Manage the options."""
        if user_input is not None:
            if user_input.pop(CONF_EDIT_HTTP_CONFIG, False):
                await async_ensure_http_config(self.hass)
            return self.async_create_entry(
                data={**self.config_entry.options, **user_input}
            )
        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_AUTO_APPROVE_OWNER,
                        default=self.config_entry.options.get(
                            CONF_AUTO_APPROVE_OWNER, True
                        ),
                    ): BooleanSelector(),
                    vol.Required(
                        CONF_EDIT_HTTP_CONFIG, default=False
                    ): BooleanSelector(),
                }
            ),
        )
