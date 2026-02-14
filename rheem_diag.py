#!/usr/bin/env python3
"""
rheem_diag.py - Rheem HVAC BLE Diagnostic CLI

Connects to a Rheem HVAC unit via Bluetooth and reads system status data,
similar to the "Bluetooth System Status" screen in the Rheem Contractor app.

Usage:
    python rheem_diag.py <MAC_ADDRESS>
    python rheem_diag.py <MAC_ADDRESS> --type furnace
    python rheem_diag.py <MAC_ADDRESS> --type odu --verbose
    python rheem_diag.py scan
"""

import argparse
import asyncio
import logging
import subprocess
import sys

from rheem_ble import (
    RheemBLEClient,
    EquipmentType,
    COMMAND_LABELS,
    EQUIPMENT_COMMANDS,
)

EQUIPMENT_TYPE_CHOICES = {
    "furnace":         EquipmentType.GAS_FURNACE,
    "resipak":         EquipmentType.RESI_PAK,
    "ulnox":           EquipmentType.ULNOX_FURNACE,
    "air_handler":     EquipmentType.AIR_HANDLER,
    "odu":             EquipmentType.ODU,
    "heat_pump":       EquipmentType.HEAT_PUMP,
    "condensing_unit": EquipmentType.CONDENSING_UNIT,
    "mwh":             EquipmentType.MWH,
    "hwh":             EquipmentType.HWH,
}


def format_result(result, show_raw=False):
    """Format a CommandResult for display."""
    label = COMMAND_LABELS.get(result.command, result.command)

    if result.error:
        line = f"  {label:.<40s} ERROR: {result.error}"
    elif result.data_type == "ieee":
        v = result.value
        if v is not None and abs(v - round(v)) < 0.001 and abs(v) < 1e6:
            vs = str(int(round(v)))
        elif v is not None:
            vs = f"{v:.1f}"
        else:
            vs = "N/A"
        if result.min_value != 0.0 or result.max_value != 0.0:
            line = (f"  {label:.<40s} {vs}"
                    f"  (range: {result.min_value:.1f}"
                    f" - {result.max_value:.1f})")
        else:
            line = f"  {label:.<40s} {vs}"
    elif result.data_type in ("text", "enum_text"):
        line = f"  {label:.<40s} {result.value}"
    elif result.data_type == "byte_stream":
        if isinstance(result.value, (bytes, bytearray)):
            line = f"  {label:.<40s} [{result.value.hex()}]"
        else:
            line = f"  {label:.<40s} {result.value}"
    elif result.data_type == "enum_number":
        vs = f"{result.value:.1f}" if result.value else "N/A"
        line = f"  {label:.<40s} {vs}"
    else:
        line = f"  {label:.<40s} ({result.data_type}) {result.value}"

    if show_raw and result.raw:
        line += f"\n    RAW: {result.raw.hex()}"

    return line


async def scan_devices():
    """Scan for nearby Rheem/EcoNet BLE devices."""
    from bleak import BleakScanner

    print("Scanning for Rheem BLE devices (10 seconds)...")
    results = await BleakScanner.discover(
        timeout=10.0, return_adv=True,
    )

    rheem_devices = []
    all_devices = []
    for addr, (device, adv) in results.items():
        name = adv.local_name or device.name or ""
        rssi = adv.rssi
        all_devices.append((device, name, rssi))
        if "econet" in name.lower() or "rheem" in name.lower():
            rheem_devices.append((device, name, rssi))

    if not rheem_devices:
        print("\nNo Rheem/EcoNet devices found.")
        print("Make sure the device is powered on and in BLE range.")
        print("\nAll nearby BLE devices:")
        for device, name, rssi in sorted(all_devices,
                                          key=lambda x: x[2] or -999,
                                          reverse=True):
            name = name or "(unknown)"
            if rssi is not None:
                print(f"  {device.address}  {rssi:>4d} dBm  {name}")
            else:
                print(f"  {device.address}     ? dBm  {name}")
    else:
        print(f"\nFound {len(rheem_devices)} Rheem device(s):\n")
        for device, name, rssi in rheem_devices:
            name = name or "(unknown)"
            if rssi is not None:
                print(f"  {device.address}  {rssi:>4d} dBm  {name}")
            else:
                print(f"  {device.address}     ? dBm  {name}")
        print(f"\nUse:  python rheem_diag.py <ADDRESS>")


def remove_device_bluez(address: str):
    """Remove a device from BlueZ to clear stale bonding/cache."""
    try:
        result = subprocess.run(
            ["bluetoothctl", "remove", address],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            print(f"Removed {address} from BlueZ cache")
        else:
            print(f"bluetoothctl remove: {result.stderr.strip()}")
    except FileNotFoundError:
        print("bluetoothctl not found - skip cache clear")
    except Exception as e:
        print(f"Could not remove device: {e}")


async def run(args):
    if args.unpair:
        remove_device_bluez(args.address)
        await asyncio.sleep(1.0)

    print(f"Connecting to {args.address}...")

    async with RheemBLEClient(
        args.address, timeout=args.timeout, command_delay=args.delay
    ) as client:

        # --- determine equipment type ---
        if args.type:
            equipment_type = EQUIPMENT_TYPE_CHOICES[args.type]
            print(f"Equipment type: {equipment_type.value} (manual)")
        else:
            print("Auto-detecting equipment type...")
            equipment_type = await client.detect_equipment_type()
            if equipment_type is None:
                print("ERROR: Could not detect equipment type.",
                      file=sys.stderr)
                print("Try specifying --type manually.", file=sys.stderr)
                return 1
            print(f"Equipment type: {equipment_type.value} (auto-detected)")

        commands = EQUIPMENT_COMMANDS.get(equipment_type, [])
        print(f"Reading {len(commands)} parameters...\n")

        def progress(cur, total, cmd):
            lbl = COMMAND_LABELS.get(cmd, cmd)
            print(f"\r  [{cur}/{total}] {lbl}...".ljust(60),
                  end="", flush=True)

        results = await client.read_system_status(
            equipment_type, progress_callback=progress,
        )

        # clear progress line
        print("\r" + " " * 60 + "\r", end="")

        # --- print results ---
        sep = "=" * 60
        print(sep)
        print(f"  Rheem {equipment_type.value.replace('_', ' ').upper()}"
              " - System Status")
        print(sep)

        errors = 0
        for r in results:
            print(format_result(r, show_raw=args.raw))
            if r.error:
                errors += 1

        print(sep)
        print(f"  {len(results)} parameters read, {errors} errors")
        print(sep)

    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Rheem HVAC BLE Diagnostic Reader",
        epilog=(
            "Examples:\n"
            "  python rheem_diag.py scan\n"
            "  python rheem_diag.py AA:BB:CC:DD:EE:FF --type furnace\n"
            "  python rheem_diag.py AA:BB:CC:DD:EE:FF --unpair -v\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("address",
                        help="BLE MAC address, or 'scan' to find devices")
    parser.add_argument("--type", "-t",
                        choices=list(EQUIPMENT_TYPE_CHOICES.keys()),
                        default=None,
                        help="Equipment type (auto-detect if omitted)")
    parser.add_argument("--timeout", type=float, default=5.0,
                        help="Response timeout per command in seconds"
                             " (default: 5)")
    parser.add_argument("--delay", type=float, default=0.01,
                        help="Delay between commands in seconds"
                             " (default: 0.01)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Enable debug logging")
    parser.add_argument("--raw", action="store_true",
                        help="Show raw hex response data")
    parser.add_argument("--unpair", action="store_true",
                        help="Remove device from BlueZ cache before "
                             "connecting (fixes stale bonding)")

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )

    # Handle 'scan' subcommand
    if args.address.lower() == "scan":
        try:
            asyncio.run(scan_devices())
        except KeyboardInterrupt:
            print("\nInterrupted.")
        return

    try:
        rc = asyncio.run(run(args))
    except KeyboardInterrupt:
        print("\nInterrupted.")
        rc = 130
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        print("\nTroubleshooting tips:", file=sys.stderr)
        print("  1. Try: python rheem_diag.py scan", file=sys.stderr)
        print("  2. Try: python rheem_diag.py <ADDR> --unpair -v",
              file=sys.stderr)
        print("  3. Make sure device is powered on and in range",
              file=sys.stderr)
        rc = 1

    sys.exit(rc)


if __name__ == "__main__":
    main()
