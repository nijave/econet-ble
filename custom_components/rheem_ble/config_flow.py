"""Config flow for Rheem HVAC BLE integration."""

from __future__ import annotations

import logging
import re

import voluptuous as vol

from homeassistant.components.bluetooth import async_ble_device_from_address
from homeassistant.config_entries import ConfigFlow, ConfigFlowResult

from .const import DOMAIN
from .rheem_ble import EquipmentType, RheemBLEClient

_LOGGER = logging.getLogger(__name__)

MAC_REGEX = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")

STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required("mac_address"): str,
    }
)

WATER_HEATER_TYPES = {EquipmentType.MWH, EquipmentType.HWH}


class CannotConnect(Exception):
    """Error to indicate we cannot connect to the device."""


class UnsupportedDevice(Exception):
    """Error to indicate the device is not supported."""


class RheemBLEConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Rheem HVAC BLE."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, str] | None = None
    ) -> ConfigFlowResult:
        """Handle the initial step."""
        errors: dict[str, str] = {}

        if user_input is not None:
            mac_address = user_input["mac_address"].strip().upper()

            if not MAC_REGEX.match(mac_address):
                errors["mac_address"] = "invalid_mac"
            else:
                await self.async_set_unique_id(mac_address)
                self._abort_if_unique_id_configured()

                try:
                    equipment_type = await self._async_detect_equipment(mac_address)
                except CannotConnect:
                    errors["base"] = "cannot_connect"
                except UnsupportedDevice:
                    errors["base"] = "unsupported_device"
                else:
                    return self.async_create_entry(
                        title=f"Rheem {equipment_type.value} ({mac_address})",
                        data={
                            "mac_address": mac_address,
                            "equipment_type": equipment_type.value,
                        },
                    )

        return self.async_show_form(
            step_id="user",
            data_schema=STEP_USER_DATA_SCHEMA,
            errors=errors,
        )

    async def _async_detect_equipment(self, mac_address: str) -> EquipmentType:
        """Connect to the device and detect equipment type."""
        ble_device = async_ble_device_from_address(
            self.hass, mac_address, connectable=True
        )
        try:
            async with RheemBLEClient(mac_address, ble_device=ble_device) as client:
                equipment_type = await client.detect_equipment_type()
        except Exception as err:
            _LOGGER.error("Failed to connect to %s: %s", mac_address, err)
            raise CannotConnect from err

        if equipment_type is None or equipment_type == EquipmentType.UNKNOWN:
            _LOGGER.error("Could not detect equipment type for %s", mac_address)
            raise CannotConnect

        if equipment_type in WATER_HEATER_TYPES:
            _LOGGER.error(
                "Device %s is a water heater (%s), not supported",
                mac_address,
                equipment_type.value,
            )
            raise UnsupportedDevice

        return equipment_type
