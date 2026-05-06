"""Config flow for Sonoff BMT01 — MAC address + DEVICE_KEY settings window."""
from __future__ import annotations

import re
import uuid

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.core import callback

from .const import DOMAIN, CONF_MAC, CONF_DEVICE_KEY, CONF_APP_UUID

MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}$")
UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I
)


def _normalise_mac(mac: str) -> str:
    return mac.upper().replace("-", ":")


class BMT01ConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle initial setup: user enters MAC + DEVICE_KEY."""

    VERSION = 1

    async def async_step_user(self, user_input=None):
        errors = {}

        if user_input is not None:
            mac        = _normalise_mac(user_input[CONF_MAC].strip())
            device_key = user_input[CONF_DEVICE_KEY].strip()

            if not MAC_RE.match(mac):
                errors[CONF_MAC] = "invalid_mac"
            elif not UUID_RE.match(device_key):
                errors[CONF_DEVICE_KEY] = "invalid_device_key"
            else:
                await self.async_set_unique_id(mac)
                self._abort_if_unique_id_configured()

                # Persist a stable APP_UUID so the device recognises this HA
                # instance across restarts (no re-pairing needed after first bond).
                app_uuid = str(uuid.uuid4())

                return self.async_create_entry(
                    title=f"BMT01 ({mac})",
                    data={
                        CONF_MAC:        mac,
                        CONF_DEVICE_KEY: device_key,
                        CONF_APP_UUID:   app_uuid,
                    },
                )

        schema = vol.Schema({
            vol.Required(CONF_MAC):        str,
            vol.Required(CONF_DEVICE_KEY): str,
        })

        return self.async_show_form(
            step_id="user",
            data_schema=schema,
            errors=errors,
            description_placeholders={
                "pairing_note": (
                    "Hold the device button for 7 seconds during the first connection "
                    "to enter BLE pairing mode. Subsequent connections are automatic."
                )
            },
        )

    @staticmethod
    @callback
    def async_get_options_flow(config_entry):
        return BMT01OptionsFlow(config_entry)


class BMT01OptionsFlow(config_entries.OptionsFlow):
    """Options flow: lets user update MAC or DEVICE_KEY after initial setup."""

    def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
        self._entry = config_entry

    async def async_step_init(self, user_input=None):
        errors = {}

        if user_input is not None:
            mac        = _normalise_mac(user_input[CONF_MAC].strip())
            device_key = user_input[CONF_DEVICE_KEY].strip()

            if not MAC_RE.match(mac):
                errors[CONF_MAC] = "invalid_mac"
            elif not UUID_RE.match(device_key):
                errors[CONF_DEVICE_KEY] = "invalid_device_key"
            else:
                # If MAC changed, generate a fresh APP_UUID so the new device bonds cleanly.
                old_mac   = self._entry.data.get(CONF_MAC, "")
                app_uuid  = (
                    str(uuid.uuid4())
                    if mac != old_mac
                    else self._entry.data.get(CONF_APP_UUID, str(uuid.uuid4()))
                )

                self.hass.config_entries.async_update_entry(
                    self._entry,
                    data={
                        CONF_MAC:        mac,
                        CONF_DEVICE_KEY: device_key,
                        CONF_APP_UUID:   app_uuid,
                    },
                )
                return self.async_create_entry(title="", data={})

        current = self._entry.data
        schema  = vol.Schema({
            vol.Required(CONF_MAC,        default=current.get(CONF_MAC, "")): str,
            vol.Required(CONF_DEVICE_KEY, default=current.get(CONF_DEVICE_KEY, "")): str,
        })

        return self.async_show_form(
            step_id="init",
            data_schema=schema,
            errors=errors,
            description_placeholders={
                "pairing_note": (
                    "Changing the MAC address will generate a new pairing identity. "
                    "Hold the device button for 7 seconds on next connection."
                )
            },
        )
