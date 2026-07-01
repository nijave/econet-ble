"""Diagnostics support for Rheem HVAC BLE."""

from __future__ import annotations

from typing import Any

from homeassistant.core import HomeAssistant

from . import RheemBLEConfigEntry
from .rheem_ble import COMMAND_LABELS


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: RheemBLEConfigEntry
) -> dict[str, Any]:
    """Return diagnostics for a config entry."""
    coordinator = entry.runtime_data
    commands: dict[str, Any] = {}

    if coordinator.data:
        for command, result in coordinator.data.items():
            commands[command] = {
                "label": COMMAND_LABELS.get(command, command),
                "data_type": result.data_type,
                "value": result.value if not isinstance(result.value, bytes) else result.value.hex(),
                "min_value": result.min_value,
                "max_value": result.max_value,
                "error": result.error,
            }

    return {
        "mac_address": coordinator.mac_address,
        "equipment_type": coordinator.equipment_type.value,
        "commands": commands,
    }
