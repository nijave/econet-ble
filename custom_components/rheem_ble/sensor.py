"""Sensor platform for Rheem HVAC BLE integration."""

from __future__ import annotations

from homeassistant.components.sensor import SensorEntity
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import RheemBLEConfigEntry, RheemBLECoordinator
from .const import DOMAIN, RheemSensorMetadata, SENSOR_DESCRIPTIONS
from .rheem_ble import COMMAND_LABELS


class RheemBLESensor(CoordinatorEntity[RheemBLECoordinator], SensorEntity):
    """Representation of a Rheem BLE sensor."""

    has_entity_name = True

    def __init__(
        self,
        coordinator: RheemBLECoordinator,
        metadata: RheemSensorMetadata,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator)
        self._command = metadata.command
        self._attr_unique_id = f"{coordinator.mac_address}_{metadata.command}"
        self._attr_translation_key = metadata.command.lower()
        self._attr_name = COMMAND_LABELS.get(metadata.command, metadata.command)
        self._attr_device_class = metadata.device_class
        self._attr_state_class = metadata.state_class
        self._attr_native_unit_of_measurement = metadata.native_unit_of_measurement
        self._attr_entity_category = metadata.entity_category
        self._attr_icon = metadata.icon
        self._attr_device_info = coordinator.device_info

    @property
    def available(self) -> bool:
        """Return True if the sensor has valid data."""
        if not super().available or self.coordinator.data is None:
            return False
        result = self.coordinator.data.get(self._command)
        return result is not None and result.error is None

    @property
    def _expects_numeric(self) -> bool:
        """Return True if HA expects a numeric value from this sensor."""
        return self._attr_state_class is not None or self._attr_device_class is not None

    @property
    def native_value(self) -> float | str | None:
        """Return the sensor value."""
        if self.coordinator.data is None:
            return None
        result = self.coordinator.data.get(self._command)
        if result is None or result.error or result.value is None:
            return None

        if self._expects_numeric:
            # Numeric sensor: only return a float. BLE commands can
            # unexpectedly return text (e.g. HTEXOTMP → "Closed",
            # STRENGT2 → "Off") when the equipment is inactive.
            try:
                return round(float(result.value), 1)
            except (ValueError, TypeError):
                return None

        # Text sensor
        return str(result.value).strip()


async def async_setup_entry(
    hass: HomeAssistant,
    entry: RheemBLEConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Rheem BLE sensors from a config entry."""
    coordinator = entry.runtime_data
    equipment_commands = set(coordinator.equipment_commands)

    entities = [
        RheemBLESensor(coordinator, metadata)
        for command, metadata in SENSOR_DESCRIPTIONS.items()
        if command in equipment_commands
    ]
    async_add_entities(entities)
