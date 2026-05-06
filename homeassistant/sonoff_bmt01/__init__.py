"""Sonoff BMT01 BLE BBQ Thermometer integration."""
from __future__ import annotations

import logging

import voluptuous as vol

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, ServiceCall
import homeassistant.helpers.config_validation as cv

from .const import DOMAIN, CONF_MAC, CONF_DEVICE_KEY, CONF_APP_UUID
from .coordinator import BMT01Coordinator

_LOGGER = logging.getLogger(__name__)

PLATFORMS = ["sensor"]

_ENTRY_SCHEMA = vol.Schema({vol.Required("config_entry_id"): cv.string})


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    hass.data.setdefault(DOMAIN, {})

    coordinator = BMT01Coordinator(
        hass,
        mac=entry.data[CONF_MAC],
        device_key=entry.data[CONF_DEVICE_KEY],
        app_uuid=entry.data[CONF_APP_UUID],
    )
    hass.data[DOMAIN][entry.entry_id] = coordinator

    await coordinator.async_start()
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    _register_services(hass)

    entry.async_on_unload(entry.add_update_listener(_async_reload_entry))
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    coordinator: BMT01Coordinator = hass.data[DOMAIN].pop(entry.entry_id, None)
    if coordinator:
        await coordinator.async_stop()

    unloaded = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)

    if not hass.data[DOMAIN]:
        _unregister_services(hass)

    return unloaded


async def _async_reload_entry(hass: HomeAssistant, entry: ConfigEntry) -> None:
    await hass.config_entries.async_reload(entry.entry_id)


# ---------------------------------------------------------------------------
# Service registration
# ---------------------------------------------------------------------------

def _get_coordinator(hass: HomeAssistant, call: ServiceCall) -> BMT01Coordinator | None:
    entry_id = call.data["config_entry_id"]
    coordinator = hass.data.get(DOMAIN, {}).get(entry_id)
    if coordinator is None:
        _LOGGER.error("BMT01 service: unknown config_entry_id %s", entry_id)
    return coordinator


def _register_services(hass: HomeAssistant) -> None:
    if hass.services.has_service(DOMAIN, "set_probe_alarm"):
        return  # already registered (multiple entries share one service set)

    async def handle_set_probe_alarm(call: ServiceCall) -> None:
        coord = _get_coordinator(hass, call)
        if coord:
            result = await coord.set_probe_alarm(
                probe=int(call.data["probe"]),
                temp_c=call.data.get("temp_c"),
            )
            _LOGGER.info("set_probe_alarm: %s", result)

    async def handle_set_probe_range_alarm(call: ServiceCall) -> None:
        coord = _get_coordinator(hass, call)
        if coord:
            result = await coord.set_probe_range_alarm(
                probe=int(call.data["probe"]),
                lower_c=int(call.data["lower_c"]),
                upper_c=int(call.data["upper_c"]),
            )
            _LOGGER.info("set_probe_range_alarm: %s", result)

    async def handle_set_temperature_unit(call: ServiceCall) -> None:
        coord = _get_coordinator(hass, call)
        if coord:
            result = await coord.set_temperature_unit(call.data["unit"].upper() == "F")
            _LOGGER.info("set_temperature_unit: %s", result)

    async def handle_set_probe_calibration(call: ServiceCall) -> None:
        coord = _get_coordinator(hass, call)
        if coord:
            result = await coord.set_probe_calibration(
                probe=int(call.data["probe"]),
                offset_c=float(call.data["offset_c"]),
            )
            _LOGGER.info("set_probe_calibration: %s", result)

    async def handle_request_battery(call: ServiceCall) -> None:
        coord = _get_coordinator(hass, call)
        if coord:
            await coord.request_battery()

    hass.services.async_register(DOMAIN, "set_probe_alarm",       handle_set_probe_alarm)
    hass.services.async_register(DOMAIN, "set_probe_range_alarm", handle_set_probe_range_alarm)
    hass.services.async_register(DOMAIN, "set_temperature_unit",  handle_set_temperature_unit)
    hass.services.async_register(DOMAIN, "set_probe_calibration", handle_set_probe_calibration)
    hass.services.async_register(DOMAIN, "request_battery",       handle_request_battery)


def _unregister_services(hass: HomeAssistant) -> None:
    for service in (
        "set_probe_alarm",
        "set_probe_range_alarm",
        "set_temperature_unit",
        "set_probe_calibration",
        "request_battery",
    ):
        hass.services.async_remove(DOMAIN, service)
