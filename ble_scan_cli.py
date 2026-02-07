# ble_scan_cli.py
from bleak import BleakScanner
import time

import asyncio
from bleak import BleakScanner

async def main():
    print("Scanning for 8 seconds...")
    devices = await BleakScanner.discover(timeout=8.0)
    if not devices:
        print("No devices found.")
        return
    for i, d in enumerate(devices, start=1):
        print(f"{i}. name: {d.name!r}, addr: {d.address}, rssi: {d.rssi}")

if __name__ == "__main__":
    asyncio.run(main())
