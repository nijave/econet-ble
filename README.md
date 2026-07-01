# rheem-ble

Home Assistant custom component for Rheem/EcoNet HVAC equipment via Bluetooth Low Energy.

Reverse-engineered from the decompiled Rheem Contractor Android app.

## Supported devices

Any `EcoNet-` prefixed BLE device using the Nordic UART Service (NUS):
- Gas furnaces, UlNOx furnaces, ResiPak
- Air handlers
- Outdoor units, heat pumps, condensing units
- Water heaters (MWH, HWH)

## Installation

Copy `custom_components/rheem_ble/` into your Home Assistant `config/custom_components/` directory and restart HA. The integration will appear under **Settings → Integrations → Add Integration → Rheem BLE**.

HA's Bluetooth integration handles adapter selection automatically (highest RSSI adapter wins).

## Protocol

See [`BLE.md`](BLE.md) for the BLE connection flow, SMP security handling, and command protocol details.

## Diagnostics

`rheem_diag.py` is a standalone CLI for reading furnace status without Home Assistant:

```
pip install bleak bleak-retry-connector dbus-fast
python rheem_diag.py <MAC_ADDRESS>
python rheem_diag.py <MAC_ADDRESS> --type furnace
python rheem_diag.py scan
```

## Tests

```
pip install pytest pytest-asyncio
python -m pytest tests/
```
