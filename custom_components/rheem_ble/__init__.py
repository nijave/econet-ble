"""Rheem HVAC BLE integration for Home Assistant."""

from __future__ import annotations

import logging
from datetime import timedelta

from homeassistant.components.bluetooth import async_ble_device_from_address
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import DEFAULT_SCAN_INTERVAL, DOMAIN
from .rheem_ble import (
    EQUIPMENT_COMMANDS,
    CommandResult,
    EquipmentType,
    RheemBLEClient,
)

_LOGGER = logging.getLogger(__name__)

PLATFORMS = [Platform.SENSOR, Platform.BINARY_SENSOR]

type RheemBLEConfigEntry = ConfigEntry[RheemBLECoordinator]


class RheemBLECoordinator(DataUpdateCoordinator[dict[str, CommandResult]]):
    """Coordinator that polls a Rheem BLE device."""

    config_entry: RheemBLEConfigEntry

    def __init__(self, hass: HomeAssistant, entry: RheemBLEConfigEntry) -> None:
        """Initialize the coordinator."""
        self._mac_address: str = entry.data["mac_address"]
        self._equipment_type = EquipmentType(entry.data["equipment_type"])
        super().__init__(
            hass,
            _LOGGER,
            config_entry=entry,
            name=f"Rheem BLE {self._mac_address}",
            update_interval=timedelta(seconds=DEFAULT_SCAN_INTERVAL),
        )

    @property
    def mac_address(self) -> str:
        """Return the MAC address."""
        return self._mac_address

    @property
    def equipment_type(self) -> EquipmentType:
        """Return the equipment type."""
        return self._equipment_type

    @property
    def equipment_commands(self) -> list[str]:
        """Return the command list for this equipment type."""
        return EQUIPMENT_COMMANDS.get(self._equipment_type, [])

    @property
    def device_info(self) -> DeviceInfo:
        """Return device info for the Rheem device."""
        sw_version = None
        hw_version = None
        if self.data:
            sw_result = self.data.get("SW_VERSN")
            if sw_result and not sw_result.error:
                sw_version = str(sw_result.value)
            hw_result = self.data.get("MDPRTNUM")
            if hw_result and not hw_result.error:
                hw_version = str(hw_result.value)
        return DeviceInfo(
            identifiers={(DOMAIN, self._mac_address)},
            manufacturer="Rheem",
            model=self._equipment_type.value,
            name=f"Rheem {self._equipment_type.value.replace('_', ' ').title()}",
            sw_version=sw_version,
            hw_version=hw_version,
        )

    async def _async_update_data(self) -> dict[str, CommandResult]:
        """Poll the BLE device and return command results keyed by command name."""
        ble_device = async_ble_device_from_address(
            self.hass, self._mac_address, connectable=True
        )
        try:
            async with RheemBLEClient(
                self._mac_address, ble_device=ble_device
            ) as client:
                results = await client.read_system_status(self._equipment_type)
        except Exception as err:
            raise UpdateFailed(f"BLE communication failed: {err}") from err

        return {result.command: result for result in results}


async def async_setup_entry(hass: HomeAssistant, entry: RheemBLEConfigEntry) -> bool:
    """Set up Rheem BLE from a config entry."""
    coordinator = RheemBLECoordinator(hass, entry)
    await coordinator.async_config_entry_first_refresh()
    entry.runtime_data = coordinator
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: RheemBLEConfigEntry) -> bool:
    """Unload a Rheem BLE config entry."""
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
