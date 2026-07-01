"""Binary sensor platform for Rheem HVAC BLE integration."""

from __future__ import annotations

from homeassistant.components.binary_sensor import BinarySensorEntity
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import RheemBLEConfigEntry, RheemBLECoordinator
from .const import BINARY_SENSOR_DESCRIPTIONS, DOMAIN, RheemBinarySensorMetadata
from .rheem_ble import COMMAND_LABELS

_ON_TEXT_VALUES = {"ON", "OPEN", "ACTIVE", "YES", "TRUE", "1", "CLOSED"}


class RheemBLEBinarySensor(
    CoordinatorEntity[RheemBLECoordinator], BinarySensorEntity
):
    """Representation of a Rheem BLE binary sensor."""

    has_entity_name = True

    def __init__(
        self,
        coordinator: RheemBLECoordinator,
        metadata: RheemBinarySensorMetadata,
    ) -> None:
        """Initialize the binary sensor."""
        super().__init__(coordinator)
        self._command = metadata.command
        self._attr_unique_id = f"{coordinator.mac_address}_{metadata.command}"
        self._attr_translation_key = metadata.command.lower()
        self._attr_name = COMMAND_LABELS.get(metadata.command, metadata.command)
        self._attr_device_class = metadata.device_class
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
    def is_on(self) -> bool | None:
        """Return True if the binary sensor is on."""
        if self.coordinator.data is None:
            return None
        result = self.coordinator.data.get(self._command)
        if result is None or result.error:
            return None
        if result.data_type in ("ieee", "enum_number"):
            return result.value is not None and float(result.value) >= 1.0
        if result.data_type in ("text", "enum_text"):
            return str(result.value).strip().upper() in _ON_TEXT_VALUES
        return None


async def async_setup_entry(
    hass: HomeAssistant,
    entry: RheemBLEConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Rheem BLE binary sensors from a config entry."""
    coordinator = entry.runtime_data
    equipment_commands = set(coordinator.equipment_commands)

    entities = [
        RheemBLEBinarySensor(coordinator, metadata)
        for command, metadata in BINARY_SENSOR_DESCRIPTIONS.items()
        if command in equipment_commands
    ]
    async_add_entities(entities)
