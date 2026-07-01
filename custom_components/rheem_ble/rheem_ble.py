#!/usr/bin/env python3
"""
rheem_ble.py - Rheem HVAC BLE Diagnostic Library

Communicates with Rheem HVAC equipment via Bluetooth Low Energy using the
Nordic UART Service (NUS) with Rheem's proprietary command/response protocol.

Reverse-engineered from the decompiled Rheem Contractor Android app.

Dependencies: bleak (pip install bleak)
"""

import asyncio
import struct
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from bleak import BleakClient
from bleak_retry_connector import establish_connection

logger = logging.getLogger(__name__)

# Nordic UART Service UUIDs
NUS_SERVICE_UUID = "6e400001-b5a3-f393-e0a9-e50e24dcca9e"
NUS_TX_UUID = "6e400002-b5a3-f393-e0a9-e50e24dcca9e"  # Write (phone -> device)
NUS_RX_UUID = "6e400003-b5a3-f393-e0a9-e50e24dcca9e"  # Notify (device -> phone)

# Board addresses (destination for commands)
BOARD_ADDR_FURNACE = bytes([0x80, 0x00, 0x01, 0xC0])
BOARD_ADDR_AIR_HANDLER = bytes([0x80, 0x00, 0x03, 0xC0])
BOARD_ADDR_ODU = bytes([0x80, 0x00, 0x04, 0x00])
BOARD_ADDR_HWH = bytes([0x80, 0x00, 0x20, 0x80])
BOARD_ADDR_BLE_CHIP = bytes([0x80, 0x00, 0x03, 0x00])

# Data type identifiers (from DataType.kt)
DATA_TYPE_IEEE = 0x80
DATA_TYPE_TEXT = 0x81
DATA_TYPE_ENUMERATED_TEXT = 0x82
DATA_TYPE_ENUMERATED_NUMBER = 0x83
DATA_TYPE_BYTE_STREAM = 0x84
DATA_TYPE_OBJ_NOT_FOUND = 0x01
DATA_TYPE_OBJ_CANNOT_BE_WRITTEN = 0x02
DATA_TYPE_DATA_TYPE_CONFLICT = 0x04

ERROR_TYPES = {
    DATA_TYPE_OBJ_NOT_FOUND,
    DATA_TYPE_OBJ_CANNOT_BE_WRITTEN,
    DATA_TYPE_DATA_TYPE_CONFLICT,
}


class EquipmentType(Enum):
    """Equipment categories matching BluetoothCategoryData.kt"""
    GAS_FURNACE = "furnace"
    RESI_PAK = "resipak"
    ULNOX_FURNACE = "ulnox"
    AIR_HANDLER = "air_handler"
    ODU = "odu"
    HEAT_PUMP = "heat_pump"
    CONDENSING_UNIT = "condensing_unit"
    MWH = "mwh"
    HWH = "hwh"
    UNKNOWN = "unknown"


EQUIPMENT_BOARD_ADDR = {
    EquipmentType.GAS_FURNACE: BOARD_ADDR_FURNACE,
    EquipmentType.RESI_PAK: BOARD_ADDR_FURNACE,
    EquipmentType.ULNOX_FURNACE: BOARD_ADDR_FURNACE,
    EquipmentType.AIR_HANDLER: BOARD_ADDR_AIR_HANDLER,
    EquipmentType.ODU: BOARD_ADDR_ODU,
    EquipmentType.HEAT_PUMP: BOARD_ADDR_ODU,
    EquipmentType.CONDENSING_UNIT: BOARD_ADDR_ODU,
    EquipmentType.MWH: BOARD_ADDR_ODU,
    EquipmentType.HWH: BOARD_ADDR_HWH,
}


@dataclass
class CommandResult:
    """Result of reading a single command from equipment."""
    command: str
    data_type: str  # "ieee", "text", "enum_text", "byte_stream", "error"
    value: object = None
    min_value: float = 0.0
    max_value: float = 0.0
    raw: bytes = field(default_factory=bytes)
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# CRC - matches CRCHelper.kt
# ---------------------------------------------------------------------------

def calc_crc(packet: bytes) -> tuple:
    """
    Calculate CRC matching CRCHelper.kt.
    Returns (crc1, crc2) as unsigned bytes.
    """
    crc1 = 0
    crc2 = 0

    for byte_val in packet:
        cur = byte_val & 0xFF
        for _ in range(8):
            c = 1 if (cur & 1) else 0
            cur = (cur & 0xFF) >> 1

            xor_bit = c ^ (crc1 & 1)

            if xor_bit == 1:
                crc2 ^= 0x40
                crc1 ^= 0x02

            carry = (crc2 & 1) != 0
            crc2 = (crc2 & 0xFF) >> 1

            if xor_bit == 1:
                crc2 |= 0x80

            crc1 = (crc1 & 0xFF) >> 1

            if carry:
                crc1 |= 0x80

    return (crc1 & 0xFF, crc2 & 0xFF)


# ---------------------------------------------------------------------------
# Packet building - matches CommandBuilder.kt
# ---------------------------------------------------------------------------

def encode_command_name(name: str) -> bytes:
    """Encode a command name as 8 ASCII bytes, null-padded."""
    return name[:8].encode('ascii').ljust(8, b'\x00')


def build_read_packet(command_name: str, board_address: bytes) -> bytes:
    """
    Build a single-command READ packet matching CommandBuilder.kt.

    Packet layout (28 bytes for single command):
      [0-3]   dest board address
      [4]     0x00
      [5-8]   BLE chip address (source)
      [9]     0x00
      [10]    data length  = (n_cmds * 10) + 2
      [11]    0x00
      [12]    0x00
      [13]    0x1E  (READ)
      [14]    class   0x01=single, 0x02=multi
      [15]    property  0x01=SHORT
      [16-17] 0x00 0x00  (command padding)
      [18-25] command name (8 bytes ASCII)
      [26-27] CRC
    """
    cmd_bytes = encode_command_name(command_name)
    data_length = 12  # (1 * 10) + 2

    packet = bytearray()
    packet.extend(board_address)           # 0-3
    packet.append(0x00)                    # 4
    packet.extend(BOARD_ADDR_BLE_CHIP)     # 5-8
    packet.append(0x00)                    # 9
    packet.append(data_length & 0xFF)      # 10
    packet.append(0x00)                    # 11
    packet.append(0x00)                    # 12
    packet.append(0x1E)                    # 13  READ
    packet.append(0x01)                    # 14  class=single
    packet.append(0x01)                    # 15  property=SHORT
    packet.append(0x00)                    # 16
    packet.append(0x00)                    # 17
    packet.extend(cmd_bytes)               # 18-25

    crc1, crc2 = calc_crc(bytes(packet))
    packet.append(crc1)
    packet.append(crc2)

    return bytes(packet)


# ---------------------------------------------------------------------------
# Response parsing - matches ResponseParserReadSingleShort.kt
# ---------------------------------------------------------------------------

def parse_ieee_float(data: bytes) -> float:
    """Parse 4 bytes as big-endian IEEE 754 float."""
    if len(data) < 4:
        return 0.0
    return struct.unpack('>f', data[:4])[0]


def parse_response(data: bytes, command_name: str) -> CommandResult:
    """
    Parse a single-short read response.

    Response layout:
      [0-13]  header (mirrors request header structure)
      [14]    data type byte
      [17-20] min value   (IEEE float, for IEEE/ENUM_TEXT types)
      [21-24] max value   (IEEE float, for IEEE/ENUM_TEXT types)
      [25-28] primary val (IEEE float) or text start
    """
    if len(data) < 15:
        return CommandResult(
            command=command_name, data_type="error",
            error=f"Response too short ({len(data)} bytes)",
        )

    dtype = data[14] & 0xFF

    if dtype in ERROR_TYPES:
        names = {
            DATA_TYPE_OBJ_NOT_FOUND: "OBJ_NOT_FOUND",
            DATA_TYPE_OBJ_CANNOT_BE_WRITTEN: "OBJ_CANNOT_BE_WRITTEN",
            DATA_TYPE_DATA_TYPE_CONFLICT: "DATA_TYPE_CONFLICT",
        }
        return CommandResult(
            command=command_name, data_type="error",
            error=names.get(dtype, f"Unknown error 0x{dtype:02x}"),
        )

    data_len = data[10] & 0xFF

    if dtype == DATA_TYPE_IEEE:
        if len(data) < 29:
            return CommandResult(
                command=command_name, data_type="error",
                error=f"IEEE response too short ({len(data)} bytes)",
            )
        return CommandResult(
            command=command_name, data_type="ieee",
            value=parse_ieee_float(data[25:29]),
            min_value=parse_ieee_float(data[17:21]),
            max_value=parse_ieee_float(data[21:25]),
            raw=bytes(data),
        )

    if dtype == DATA_TYPE_TEXT:
        end = data_len + 13
        chunk = data[25:end] if len(data) >= end else data[25:]
        try:
            text = chunk.decode('utf-8').rstrip('\x00')
        except UnicodeDecodeError:
            text = chunk.hex()
        return CommandResult(
            command=command_name, data_type="text",
            value=text, raw=bytes(data),
        )

    if dtype == DATA_TYPE_ENUMERATED_TEXT:
        end = data_len + 14
        chunk = data[27:end] if len(data) >= end else data[27:]
        try:
            text = chunk.decode('utf-8').rstrip('\x00')
        except UnicodeDecodeError:
            text = chunk.hex()
        return CommandResult(
            command=command_name, data_type="enum_text",
            value=text,
            min_value=parse_ieee_float(data[17:21]) if len(data) >= 21 else 0.0,
            max_value=parse_ieee_float(data[21:25]) if len(data) >= 25 else 0.0,
            raw=bytes(data),
        )

    if dtype == DATA_TYPE_BYTE_STREAM:
        end = data_len + 13
        chunk = data[25:end] if len(data) >= end else data[25:]
        return CommandResult(
            command=command_name, data_type="byte_stream",
            value=chunk, raw=bytes(data),
        )

    if dtype == DATA_TYPE_ENUMERATED_NUMBER:
        return CommandResult(
            command=command_name, data_type="enum_number",
            value=parse_ieee_float(data[25:29]) if len(data) >= 29 else 0.0,
            min_value=parse_ieee_float(data[17:21]) if len(data) >= 21 else 0.0,
            max_value=parse_ieee_float(data[21:25]) if len(data) >= 25 else 0.0,
            raw=bytes(data),
        )

    return CommandResult(
        command=command_name, data_type="error",
        error=f"Unknown data type 0x{dtype:02x}", raw=bytes(data),
    )


# ---------------------------------------------------------------------------
# System-status command sets  (from *SystemStatusObjectReadCommandsFactory.kt)
# ---------------------------------------------------------------------------

FURNACE_COMMANDS = [
    "HVACMODE", "CFM_CMND", "CFM_CURR", "RPM_CURR", "STATIC_P",
    "SAT_TEMP", "RAT_TEMP", "OAT_TEMP", "TEMPSUCT", "TEMP_SST",
    "PRES_SUC", "G_DISCIN", "AUX1_DIN", "AUX2_DIN", "W1DISCIN",
    "W2DISCIN", "Y1DISCIN", "Y2DISCIN", "EXACTUAL", "EXVSUPER",
    "INDSTATE", "INDUCELP", "INDUCEHP", "GASSTATE", "STG1DRIV",
    "STG2DRIV", "FLAMEPRS", "STRENGT2", "ROLL_OUT", "HTEXOTMP",
    "WATRTRIP", "MDPRTNUM", "CDPRTNUM", "ALARMS",  "SW_VERSN",
    "SERIAL_N", "SW_VERSN_BLE",
]

ULNOX_COMMANDS = [
    "HVACMODE", "CFM_CMND", "CFM_CURR", "RPM_CURR", "STATIC_P",
    "SAT_TEMP", "RAT_TEMP", "OAT_TEMP", "TEMPSUCT", "TEMP_SST",
    "PRES_SUC", "G_DISCIN", "CONDENSE", "AUX__DIN", "W1DISCIN",
    "Y1DISCIN", "Y2DISCIN", "EXACTUAL", "EXVSUPER", "STG1DRIV",
    "FLAMEPRS", "ROLL_OUT", "HTEXOTMP", "MDPRTNUM", "CDPRTNUM",
    "ALARMS",  "SW_VERSN", "SERIAL_N", "SW_VERSN_BLE",
]

AIR_HANDLER_COMMANDS = [
    "HVACMODE", "CFM_CMND", "CFM_CURR", "RPM_CURR", "STATIC_P",
    "SAT_TEMP", "RAT_TEMP", "OAT_TEMP", "TEMPSUCT", "TEMP_SST",
    "PRES_SUC", "G_DISCIN", "EXACTUAL", "EXVSUPER", "ECONTROL",
    "ELECDCFM", "EMIDDCFM", "ELOWDCFM", "HTR_SIZE", "HT1_RELY",
    "HT2_RELY", "MDPRTNUM", "CDPRTNUM", "ALARMS",  "CONDENSE",
    "AUX__DIN", "SW_VERSN", "SERIAL_N", "SW_VERSN_BLE",
]

ODU_COMMANDS = [
    "IDUEVPOS", "IDUEXVSH", "IDU_SUCT", "IDU__SST", "IDU_SUCP",
    "HVACMODE", "VSHP_CMD", "INVSPEED", "PRCNTCAP", "ISCSPEED",
    "ODFANRPM", "JAG_MODE", "TEMP_OAT", "TEMP_OLT", "TEMP_CPT",
    "TEMP_SST", "TEMP_SLT", "TEMP_OST", "PRESSUCG", "PRES_SUC",
    "TEMPCOIL", "PRESLIQG", "PRES_LIQ", "TEMP_DIS", "SUB_COOL",
    "EXVSUPER", "ISACINPV", "ISACINPC", "IS_COMPC", "C_MAXCUR",
    "LOCKTIMR", "U__INPUT", "ECONTROL", "MDPRTNUM", "CPPRTNUM",
    "FNPRTNUM", "ALARMS",  "SERIAL_N", "SW_VERSN", "SW_VERSN_BLE",
]

MWH_COMMANDS = [
    "WHTRSETP", "WHTRMODE", "COMP_MOD", "RPMRAMPU", "FANMXRPM",
    "REFGTYPE", "SIZE__KW", "WTR_PRES", "TEMP__IN", "TEMP_OUT",
    "TEMP_AMB", "TEMP_EVP", "TEMPSUCT", "TEMP_SST", "TEMP_OLT",
    "TEMP_SLT", "PRESSUCG", "PRESLIQG", "LIMPENAB", "PUMPTYPE",
    "ALRMALRT", "ALARMS",  "ALERTS",  "SERIAL_N", "SW_VERSN",
    "SW_VERSN_BLE",
]

EQUIPMENT_COMMANDS = {
    EquipmentType.GAS_FURNACE: FURNACE_COMMANDS,
    EquipmentType.RESI_PAK: FURNACE_COMMANDS,
    EquipmentType.ULNOX_FURNACE: ULNOX_COMMANDS,
    EquipmentType.AIR_HANDLER: AIR_HANDLER_COMMANDS,
    EquipmentType.ODU: ODU_COMMANDS,
    EquipmentType.HEAT_PUMP: ODU_COMMANDS,
    EquipmentType.CONDENSING_UNIT: ODU_COMMANDS,
    EquipmentType.MWH: MWH_COMMANDS,
    EquipmentType.HWH: MWH_COMMANDS,
}

# Commands that target the BLE chip instead of the equipment board
BLE_CHIP_COMMANDS = {"SW_VERSN_BLE"}

# Human-readable labels
COMMAND_LABELS = {
    "HVACMODE": "HVAC Mode",
    "CFM_CMND": "CFM Commanded",
    "CFM_CURR": "CFM Current",
    "RPM_CURR": "RPM Current",
    "STATIC_P": "Static Pressure",
    "SAT_TEMP": "Supply Air Temp",
    "RAT_TEMP": "Return Air Temp",
    "OAT_TEMP": "Outdoor Air Temp",
    "TEMPSUCT": "Suction Temp",
    "TEMP_SST": "Saturated Suction Temp",
    "PRES_SUC": "Suction Pressure",
    "PRESSUCG": "Suction Pressure (gauge)",
    "G_DISCIN": "G Discrete Input",
    "AUX1_DIN": "Aux 1 Discrete Input",
    "AUX2_DIN": "Aux 2 Discrete Input",
    "AUX__DIN": "Aux Discrete Input",
    "W1DISCIN": "W1 Discrete Input",
    "W2DISCIN": "W2 Discrete Input",
    "Y1DISCIN": "Y1 Discrete Input",
    "Y2DISCIN": "Y2 Discrete Input",
    "EXACTUAL": "EXV Actual Position",
    "EXVSUPER": "EXV Superheat",
    "INDSTATE": "Inducer State",
    "INDUCELP": "Inducer Low Press",
    "INDUCEHP": "Inducer High Press",
    "GASSTATE": "Gas Valve State",
    "STG1DRIV": "Stage 1 Drive",
    "STG2DRIV": "Stage 2 Drive",
    "FLAMEPRS": "Flame Present",
    "STRENGT2": "Flame Strength",
    "ROLL_OUT": "Rollout Switch",
    "HTEXOTMP": "Heat Exchanger Outlet Temp",
    "WATRTRIP": "Water Trip",
    "MDPRTNUM": "Module Part Number",
    "CDPRTNUM": "Control/Display Part Number",
    "CPPRTNUM": "Compressor Part Number",
    "FNPRTNUM": "Fan Part Number",
    "ALARMS":   "Alarms",
    "ALERTS":   "Alerts",
    "ALRMALRT": "Alarm/Alert",
    "SW_VERSN": "Software Version",
    "SERIAL_N": "Serial Number",
    "SW_VERSN_BLE": "BLE Software Version",
    "PRODTYPE": "Product Type",
    "ECONTROL": "Electric Control",
    "ELECDCFM": "Elec Dehum CFM",
    "EMIDDCFM": "Elec Mid Dehum CFM",
    "ELOWDCFM": "Elec Low Dehum CFM",
    "HTR_SIZE": "Heater Size",
    "HT1_RELY": "Heater 1 Relay",
    "HT2_RELY": "Heater 2 Relay",
    "CONDENSE": "Condensate",
    "IDUEVPOS": "IDU EXV Position",
    "IDUEXVSH": "IDU EXV Superheat",
    "IDU_SUCT": "IDU Suction Temp",
    "IDU__SST": "IDU Sat Suction Temp",
    "IDU_SUCP": "IDU Suction Pressure",
    "VSHP_CMD": "Variable Speed HP Command",
    "INVSPEED": "Inverter Speed",
    "PRCNTCAP": "Percent Capacity",
    "ISCSPEED": "ISC Speed",
    "ODFANRPM": "OD Fan RPM",
    "JAG_MODE": "JAG Mode",
    "TEMP_OAT": "Outdoor Air Temp",
    "TEMP_OLT": "Outdoor Liquid Temp",
    "TEMP_CPT": "Compressor Temp",
    "TEMP_SLT": "Suction Line Temp",
    "TEMP_OST": "Outdoor Suction Temp",
    "TEMPCOIL": "Coil Temp",
    "PRES_LIQ": "Liquid Pressure",
    "PRESLIQG": "Liquid Pressure (gauge)",
    "TEMP_DIS": "Discharge Temp",
    "SUB_COOL": "Subcooling",
    "ISACINPV": "AC Input Voltage",
    "ISACINPC": "AC Input Current",
    "IS_COMPC": "Compressor Current",
    "C_MAXCUR": "Compressor Max Current",
    "LOCKTIMR": "Lockout Timer",
    "U__INPUT": "U Input",
    "WHTRSETP": "Water Heater Setpoint",
    "WHTRMODE": "Water Heater Mode",
    "COMP_MOD": "Compressor Mode",
    "RPMRAMPU": "RPM Ramp Up",
    "FANMXRPM": "Fan Max RPM",
    "REFGTYPE": "Refrigerant Type",
    "SIZE__KW": "Size (kW)",
    "WTR_PRES": "Water Pressure",
    "TEMP__IN": "Inlet Temp",
    "TEMP_OUT": "Outlet Temp",
    "TEMP_AMB": "Ambient Temp",
    "TEMP_EVP": "Evaporator Temp",
    "LIMPENAB": "Limp Enable",
    "PUMPTYPE": "Pump Type",
}

# PRODTYPE response text -> EquipmentType
PRODUCT_TYPE_MAP = {
    "GAS_FURNACE": EquipmentType.GAS_FURNACE,
    "GAS FURNACE": EquipmentType.GAS_FURNACE,
    "FURNACE":     EquipmentType.GAS_FURNACE,
    "RESI_PAK":    EquipmentType.RESI_PAK,
    "RESIPAK":     EquipmentType.RESI_PAK,
    "ULNOX":       EquipmentType.ULNOX_FURNACE,
    "ULNOX_FURNACE": EquipmentType.ULNOX_FURNACE,
    "AIR_HANDLER": EquipmentType.AIR_HANDLER,
    "AIR HANDLER": EquipmentType.AIR_HANDLER,
    "AHU":         EquipmentType.AIR_HANDLER,
    "ODU":         EquipmentType.ODU,
    "HEAT_PUMP":   EquipmentType.HEAT_PUMP,
    "HEAT PUMP":   EquipmentType.HEAT_PUMP,
    "HP":          EquipmentType.HEAT_PUMP,
    "CONDENSING":  EquipmentType.CONDENSING_UNIT,
    "CONDENSING_UNIT": EquipmentType.CONDENSING_UNIT,
    "MWH":         EquipmentType.MWH,
    "HWH":         EquipmentType.HWH,
    "HYBRID":      EquipmentType.HWH,
}


# ---------------------------------------------------------------------------
# BLE Client
# ---------------------------------------------------------------------------

class RheemBLEClient:
    """BLE client for communicating with Rheem HVAC equipment."""

    MAX_CONNECT_ATTEMPTS = 3
    RECONNECT_DELAY = 1.0  # seconds between retries (matches app)

    def __init__(self, address: str, timeout: float = 10.0,
                 command_delay: float = 0.1,
                 ble_device=None):
        self.address = address
        self.timeout = timeout
        self.command_delay = command_delay
        self._ble_device = ble_device
        self._client: Optional[BleakClient] = None
        self._response_data = bytearray()
        self._response_event = asyncio.Event()
        self._notify_uuid: Optional[str] = None
        self._write_uuid: Optional[str] = None

    # -- connection ----------------------------------------------------------

    def _remove_device_cache(self):
        """Remove device from BlueZ cache to clear stale state.

        This clears leftover notification FDs and cached services that can
        cause 'Notify acquired' or 'NotPermitted' errors on reconnection.
        """
        import subprocess
        try:
            result = subprocess.run(
                ["bluetoothctl", "remove", self.address],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                logger.info("Removed %s from BlueZ cache", self.address)
            else:
                logger.debug("bluetoothctl remove: %s",
                             result.stderr.strip())
        except FileNotFoundError:
            logger.debug("bluetoothctl not found")
        except Exception as e:
            logger.debug("Could not remove device: %s", e)

    async def _register_pairing_agent(self):
        """Register a NoInputNoOutput BLE pairing agent on the system D-Bus.

        The furnace sends an SMP Security Request (kernel: "unexpected SMP
        command 0x0b") right after the BLE connection is established.  Without
        a registered agent, BlueZ rejects the request and disconnects the
        device before any GATT operations can run.  This registers a minimal
        Just Works agent so BlueZ can complete ephemeral encryption without
        bonding or an explicit Pair() call.

        Returns (bus, agent_path) on success, (None, None) on failure.  The
        caller is responsible for calling _unregister_pairing_agent with the
        returned values.
        """
        try:
            from dbus_fast.aio import MessageBus
            from dbus_fast.service import ServiceInterface, method
            from dbus_fast import BusType
        except ImportError:
            logger.debug("dbus-fast not available; connecting without pairing agent")
            return None, None

        class _NoInputNoOutput(ServiceInterface):
            def __init__(self):
                super().__init__("org.bluez.Agent1")

            @method()
            def Release(self) -> None:
                pass

            @method()
            def RequestConfirmation(self, device: 'o', passkey: 'u') -> None:
                pass

            @method()
            def RequestPinCode(self, device: 'o') -> 's':
                return ""

            @method()
            def DisplayPinCode(self, device: 'o', pincode: 's') -> None:
                pass

            @method()
            def RequestPasskey(self, device: 'o') -> 'u':
                return 0

            @method()
            def DisplayPasskey(self, device: 'o', passkey: 'u', entered: 'q') -> None:
                pass

            @method()
            def AuthorizeService(self, device: 'o', uuid: 's') -> None:
                pass

            @method()
            def Cancel(self) -> None:
                pass

        agent_path = "/rheem_ble/pairing_agent"
        try:
            bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
            bus.export(agent_path, _NoInputNoOutput())

            introspection = await bus.introspect("org.bluez", "/org/bluez")
            proxy = bus.get_proxy_object("org.bluez", "/org/bluez", introspection)
            agent_mgr = proxy.get_interface("org.bluez.AgentManager1")
            await agent_mgr.call_register_agent(agent_path, "NoInputNoOutput")
            await agent_mgr.call_request_default_agent(agent_path)

            logger.debug("NoInputNoOutput pairing agent registered")
            return bus, agent_path
        except Exception as e:
            logger.warning(
                "Pairing agent registration failed (%s); connecting without agent", e
            )
            return None, None

    async def _unregister_pairing_agent(self, bus, agent_path: str) -> None:
        """Unregister the pairing agent and close the D-Bus connection."""
        if bus is None:
            return
        try:
            introspection = await bus.introspect("org.bluez", "/org/bluez")
            proxy = bus.get_proxy_object("org.bluez", "/org/bluez", introspection)
            agent_mgr = proxy.get_interface("org.bluez.AgentManager1")
            await agent_mgr.call_unregister_agent(agent_path)
        except Exception:
            pass
        try:
            bus.disconnect()
        except Exception:
            pass

    async def _pair_via_dbus(self, bus) -> None:
        """Call BlueZ Pair() to complete SMP key exchange before BleakClient connects.

        The furnace sends an SMP Security Request right after BLE connection.
        Relying on a registered agent to handle it inline during BleakClient's
        service discovery is unreliable — BlueZ needs to complete the SMP
        handshake as the central initiator via an explicit Pair() call first.

        After Pair() succeeds the bond is stored in BlueZ. BleakClient then
        reconnects and inherits the encrypted session, allowing GATT service
        discovery to proceed without another SMP exchange.

        The device D-Bus path is derived from ble_device.details["path"] when
        available (HA always provides this), or found via ObjectManager scan.
        """
        if bus is None:
            return

        try:
            from dbus_fast import Variant
        except ImportError:
            return

        device_path = None
        if self._ble_device is not None:
            details = getattr(self._ble_device, 'details', {}) or {}
            device_path = details.get('path')

        if not device_path:
            addr_key = self.address.upper().replace(':', '_')
            try:
                om_intro = await bus.introspect("org.bluez", "/")
                om_proxy = bus.get_proxy_object("org.bluez", "/", om_intro)
                om = om_proxy.get_interface("org.freedesktop.DBus.ObjectManager")
                objects = await om.call_get_managed_objects()
                for path in objects:
                    if addr_key in str(path):
                        device_path = path
                        break
            except Exception as e:
                logger.debug("ObjectManager lookup failed: %s", e)

        if not device_path:
            logger.warning(
                "Cannot find D-Bus path for %s; skipping Pair()", self.address
            )
            return

        logger.debug("D-Bus pairing device at %s", device_path)
        try:
            dev_intro = await bus.introspect("org.bluez", device_path)
            dev_proxy = bus.get_proxy_object("org.bluez", device_path, dev_intro)
            device_iface = dev_proxy.get_interface("org.bluez.Device1")
            props_iface = dev_proxy.get_interface("org.freedesktop.DBus.Properties")

            paired_var = await props_iface.call_get("org.bluez.Device1", "Paired")
            already_paired = bool(paired_var.value)

            if not already_paired:
                logger.debug("Calling Pair() on %s", device_path)
                await asyncio.wait_for(device_iface.call_pair(), timeout=30.0)
                logger.info("Paired with %s", self.address)
            else:
                logger.debug("Already paired with %s", self.address)

            await props_iface.call_set(
                "org.bluez.Device1", "Trusted", Variant("b", True)
            )

            conn_var = await props_iface.call_get("org.bluez.Device1", "Connected")
            if bool(conn_var.value):
                await device_iface.call_disconnect()
                await asyncio.sleep(1.0)

        except asyncio.TimeoutError:
            logger.warning("Pair() timed out for %s", self.address)
        except Exception as e:
            logger.warning(
                "D-Bus Pair() failed for %s (%s); BleakClient will attempt direct connect",
                self.address, e,
            )

    async def connect(self):
        """Connect to the BLE device via HA's bluetooth infrastructure.

        Sequence:
        1. Register NoInputNoOutput agent (handles Just Works SMP confirmation).
        2. Call BlueZ Pair() via D-Bus — forces SMP exchange to complete before
           BleakClient tries to discover services.
        3. Disconnect the D-Bus-initiated connection so BleakClient can connect.
        4. Unregister agent (no longer needed; bond is stored in BlueZ).
        5. establish_connection() — BleakClient re-uses the stored bond key,
           link comes up encrypted, GATT service discovery succeeds.
        """
        bus, agent_path = await self._register_pairing_agent()
        try:
            await self._pair_via_dbus(bus)
        finally:
            await self._unregister_pairing_agent(bus, agent_path)

        device = self._ble_device if self._ble_device is not None else self.address
        try:
            self._client = await establish_connection(
                BleakClient,
                device,
                self.address,
                max_attempts=self.MAX_CONNECT_ATTEMPTS,
            )
        except Exception as e:
            raise RuntimeError(
                f"Failed to connect after {self.MAX_CONNECT_ATTEMPTS} attempts: {e}"
            ) from e

        logger.info("Connected to %s", self.address)
        self._find_characteristics()

        if not self._client.is_connected:
            await self._cleanup()
            raise RuntimeError("Disconnected after service discovery")

        await self._client.start_notify(
            self._notify_uuid, self._notification_handler,
        )
        logger.info("Subscribed to notifications on %s", self._notify_uuid)

    def _find_characteristics(self):
        """Locate the write and notify characteristics.

        Checks for the standard Nordic UART Service first, then falls back
        to scanning all services for characteristics with the right properties.
        """
        self._write_uuid = None
        self._notify_uuid = None

        for service in self._client.services:
            for char in service.characteristics:
                uuid = char.uuid.lower()
                props = char.properties

                # Prefer the well-known NUS UUIDs
                if uuid == NUS_TX_UUID:
                    self._write_uuid = uuid
                if uuid == NUS_RX_UUID:
                    self._notify_uuid = uuid

        # Fallback: if NUS UUIDs weren't found, look for any char with
        # the right combination of properties (write-no-response + notify).
        if not self._write_uuid or not self._notify_uuid:
            for service in self._client.services:
                for char in service.characteristics:
                    props = char.properties
                    has_write = ("write-without-response" in props
                                 or "write" in props)
                    has_notify = ("notify" in props
                                  or "indicate" in props)
                    if has_write and has_notify:
                        # Universal characteristic (both directions)
                        self._write_uuid = self._write_uuid or char.uuid
                        self._notify_uuid = self._notify_uuid or char.uuid
                    elif has_write and not self._write_uuid:
                        self._write_uuid = char.uuid
                    elif has_notify and not self._notify_uuid:
                        self._notify_uuid = char.uuid

        if not self._write_uuid or not self._notify_uuid:
            available = []
            for service in self._client.services:
                available.append(f"  Service {service.uuid}:")
                for char in service.characteristics:
                    available.append(
                        f"    {char.uuid}  props={char.properties}")
            raise RuntimeError(
                "Could not find write/notify characteristics.\n"
                "Available services:\n" + "\n".join(available)
            )

        logger.info("Write: %s  Notify: %s", self._write_uuid,
                     self._notify_uuid)

    async def _cleanup(self):
        """Best-effort cleanup of a failed connection."""
        if self._client:
            try:
                if self._notify_uuid:
                    await self._client.stop_notify(self._notify_uuid)
            except Exception:
                pass
            try:
                await self._client.disconnect()
            except Exception:
                pass
            self._client = None

    async def disconnect(self):
        """Disconnect from the BLE device."""
        await self._cleanup()
        logger.info("Disconnected")

    async def __aenter__(self):
        await self.connect()
        return self

    async def __aexit__(self, *exc):
        await self.disconnect()

    # -- low-level BLE -------------------------------------------------------

    def _notification_handler(self, _sender, data: bytearray):
        logger.debug("RX %d bytes: %s", len(data), data.hex())
        self._response_data.extend(data)
        self._response_event.set()

    async def _send_and_receive(self, packet: bytes) -> bytes:
        """Send a command and collect the response."""
        self._response_data.clear()
        self._response_event.clear()

        logger.debug("TX %d bytes: %s", len(packet), packet.hex())
        await self._client.write_gatt_char(
            self._write_uuid, packet, response=False,
        )

        loop = asyncio.get_running_loop()
        deadline = loop.time() + self.timeout

        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                break

            self._response_event.clear()
            try:
                await asyncio.wait_for(
                    self._response_event.wait(),
                    timeout=max(remaining, 0),
                )
            except asyncio.TimeoutError:
                break

            # Check if we have a complete packet.
            # Header is 14 bytes; data_len at byte 10 gives payload size.
            if len(self._response_data) >= 15:
                data_len = self._response_data[10] & 0xFF
                if len(self._response_data) >= data_len + 14:
                    break

        return bytes(self._response_data)

    # -- high-level commands -------------------------------------------------

    async def read_command(self, command_name: str,
                           board_address: bytes) -> CommandResult:
        """Send a single READ command and parse the response."""
        wire_name = command_name[:8]
        dest = BOARD_ADDR_BLE_CHIP if command_name in BLE_CHIP_COMMANDS \
            else board_address

        packet = build_read_packet(wire_name, dest)

        try:
            response = await self._send_and_receive(packet)
            if not response:
                return CommandResult(command=command_name, data_type="error",
                                     error="No response received")
            return parse_response(response, command_name)
        except Exception as e:
            return CommandResult(command=command_name, data_type="error",
                                 error=str(e))

    async def detect_equipment_type(self) -> Optional[EquipmentType]:
        """Auto-detect equipment type by sending PRODTYPE to each board."""
        for board_addr in [BOARD_ADDR_FURNACE, BOARD_ADDR_AIR_HANDLER,
                           BOARD_ADDR_ODU, BOARD_ADDR_HWH]:
            result = await self.read_command("PRODTYPE", board_addr)
            await asyncio.sleep(self.command_delay)

            if result.error:
                logger.debug("PRODTYPE on %s: %s",
                             board_addr.hex(), result.error)
                continue

            if result.value is None:
                continue

            prod = str(result.value).strip().upper()
            logger.info("PRODTYPE='%s' from board %s", prod, board_addr.hex())

            if prod in PRODUCT_TYPE_MAP:
                return PRODUCT_TYPE_MAP[prod]

            for key, eq_type in PRODUCT_TYPE_MAP.items():
                if key in prod or prod in key:
                    return eq_type

            # Fall back: infer from whichever board answered
            addr_fallback = {
                BOARD_ADDR_FURNACE: EquipmentType.GAS_FURNACE,
                BOARD_ADDR_AIR_HANDLER: EquipmentType.AIR_HANDLER,
                BOARD_ADDR_ODU: EquipmentType.ODU,
                BOARD_ADDR_HWH: EquipmentType.HWH,
            }
            return addr_fallback.get(board_addr, EquipmentType.UNKNOWN)

        return None

    async def read_system_status(self, equipment_type: EquipmentType,
                                  progress_callback=None):
        """
        Read all system-status parameters for the given equipment type.

        Args:
            equipment_type: Which equipment to query.
            progress_callback: Optional ``callback(current, total, cmd_name)``.

        Returns:
            List of CommandResult.
        """
        commands = EQUIPMENT_COMMANDS.get(equipment_type, FURNACE_COMMANDS)
        board_addr = EQUIPMENT_BOARD_ADDR.get(equipment_type,
                                               BOARD_ADDR_FURNACE)
        results = []
        for i, cmd in enumerate(commands):
            if progress_callback:
                progress_callback(i + 1, len(commands), cmd)

            result = await self.read_command(cmd, board_addr)
            results.append(result)

            if i < len(commands) - 1:
                await asyncio.sleep(self.command_delay)

        return results
