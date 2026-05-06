"""Sensor platform for Sonoff BMT01."""
from __future__ import annotations

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import PERCENTAGE, UnitOfTemperature
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN, CONF_MAC
from .coordinator import BMT01Coordinator


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator: BMT01Coordinator = hass.data[DOMAIN][entry.entry_id]
    mac = entry.data[CONF_MAC]

    entities: list[SensorEntity] = [
        BMT01ProbeSensor(coordinator, entry, mac, probe_idx)
        for probe_idx in range(4)
    ]
    entities.append(BMT01BatterySensor(coordinator, entry, mac))
    async_add_entities(entities)


# ---------------------------------------------------------------------------
# Device info shared across all entities for this entry
# ---------------------------------------------------------------------------

def _device_info(mac: str) -> DeviceInfo:
    return DeviceInfo(
        identifiers={(DOMAIN, mac)},
        name=f"BMT01 ({mac})",
        manufacturer="Sonoff / eWeLink",
        model="BMT01 BLE BBQ Thermometer",
    )


# ---------------------------------------------------------------------------
# Probe temperature sensor
# ---------------------------------------------------------------------------

class BMT01ProbeSensor(CoordinatorEntity[BMT01Coordinator], SensorEntity):
    _attr_device_class  = SensorDeviceClass.TEMPERATURE
    _attr_state_class   = SensorStateClass.MEASUREMENT
    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: BMT01Coordinator,
        entry: ConfigEntry,
        mac: str,
        probe_idx: int,
    ) -> None:
        super().__init__(coordinator)
        self._probe_idx  = probe_idx
        self._attr_unique_id = f"{mac}_probe_{probe_idx + 1}"
        self._attr_name      = f"Probe {probe_idx + 1} Temperature"
        self._attr_device_info = _device_info(mac)
        self._update_unit()

    def _update_unit(self) -> None:
        unit = self.coordinator.data.get("temp_unit", "C")
        self._attr_native_unit_of_measurement = (
            UnitOfTemperature.FAHRENHEIT if unit == "F" else UnitOfTemperature.CELSIUS
        )

    @callback
    def _handle_coordinator_update(self) -> None:
        self._update_unit()
        self.async_write_ha_state()

    @property
    def native_value(self) -> float | None:
        probes = self.coordinator.data.get("probes", [])
        if self._probe_idx >= len(probes):
            return None
        probe = probes[self._probe_idx]
        if probe["status"] != "ok":
            return None
        unit = self.coordinator.data.get("temp_unit", "C")
        return probe["temp_f"] if unit == "F" else probe["temp_c"]

    @property
    def extra_state_attributes(self) -> dict:
        probes = self.coordinator.data.get("probes", [])
        if self._probe_idx >= len(probes):
            return {}
        probe = probes[self._probe_idx]
        attrs: dict = {"status": probe["status"]}
        if probe["temp_c"] is not None:
            attrs["temp_c"] = probe["temp_c"]
            attrs["temp_f"] = probe["temp_f"]
        return attrs

    @property
    def available(self) -> bool:
        if not self.coordinator.data.get("connected", False):
            return False
        probes = self.coordinator.data.get("probes", [])
        if self._probe_idx >= len(probes):
            return False
        return probes[self._probe_idx]["status"] in ("ok", "too_high", "too_low")


# ---------------------------------------------------------------------------
# Battery sensor
# ---------------------------------------------------------------------------

class BMT01BatterySensor(CoordinatorEntity[BMT01Coordinator], SensorEntity):
    _attr_device_class  = SensorDeviceClass.BATTERY
    _attr_state_class   = SensorStateClass.MEASUREMENT
    _attr_native_unit_of_measurement = PERCENTAGE
    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: BMT01Coordinator,
        entry: ConfigEntry,
        mac: str,
    ) -> None:
        super().__init__(coordinator)
        self._attr_unique_id   = f"{mac}_battery"
        self._attr_name        = "Battery"
        self._attr_device_info = _device_info(mac)

    @property
    def native_value(self) -> int | None:
        return self.coordinator.data.get("battery")

    @property
    def available(self) -> bool:
        return (
            self.coordinator.data.get("connected", False)
            and self.coordinator.data.get("battery") is not None
        )
