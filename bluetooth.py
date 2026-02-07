import asyncio
import threading
import tkinter as tk
from tkinter import messagebox, StringVar, OptionMenu, ttk
from bleak import BleakScanner, BleakClient
import math
import subprocess

def get_friendly_name(address):
    try:
        # Convert address format XX:XX:XX:XX:XX:XX -> XX-XX-XX-XX-XX-XX
        addr = address.replace(":", "-")
        cmd = f'Get-PnpDevice -PresentOnly | Where-Object {{$_.InstanceId -like "*{addr}*"}} | Select-Object -ExpandProperty FriendlyName'
        result = subprocess.run(["powershell", "-Command", cmd], capture_output=True, text=True)
        name = result.stdout.strip()
        return name if name else None
    except Exception as e:
        return None
from winrt.windows.devices.enumeration import DeviceInformation

devices = DeviceInformation.find_all_async().get()
for d in devices:
    print(d.name, d.id)
# Example
print(get_friendly_name("XX:XX:XX:XX:XX:XX"))

class BluetoothApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Bluetooth Control App (Python)")
        self.devices = {}  # address → (device, rssi)
        self.client = None

        # --- UI Layout ---
        self.scan_btn = tk.Button(root, text="Scan Devices", command=self.scan_devices)
        self.scan_btn.pack(pady=5)

        # Dropdown: display mode
        self.display_mode = StringVar(value="Name + ID")
        options = ["Name + ID", "Name Only", "ID Only"]
        self.mode_menu = OptionMenu(root, self.display_mode, *options)
        self.mode_menu.pack(pady=5)

        # Treeview for device list
        columns = ("Name", "Address", "RSSI", "Distance", "Signal")
        self.device_table = ttk.Treeview(root, columns=columns, show="headings", height=12)
        for col in columns:
            self.device_table.heading(col, text=col)
            if col == "Name":
                self.device_table.column(col, width=160)
            else:
                self.device_table.column(col, width=120)
        self.device_table.pack(pady=5)

        # Buttons
        self.connect_btn = tk.Button(root, text="Connect", command=self.connect_device)
        self.connect_btn.pack(pady=5)

        self.force_connect_btn = tk.Button(root, text="Force Connect", command=self.force_connect_device, fg="red")
        self.force_connect_btn.pack(pady=5)

        self.disconnect_btn = tk.Button(root, text="Disconnect", command=self.disconnect_device)
        self.disconnect_btn.pack(pady=5)

        # Status
        self.status_label = tk.Label(root, text="Status: Idle", fg="blue")
        self.status_label.pack(pady=5)

    def run_async(self, coro):
        """Run asyncio task in a separate thread"""
        threading.Thread(target=lambda: asyncio.run(coro)).start()

    def scan_devices(self):
        self.status_label.config(text="Status: Scanning...")
        for item in self.device_table.get_children():
            self.device_table.delete(item)
        self.devices.clear()
        self.run_async(self._scan_devices())

    async def _scan_devices(self):
        def detection_callback(device, advertisement_data):
            self.devices[device.address] = (device, advertisement_data.rssi)

        scanner = BleakScanner(detection_callback)
        await scanner.start()
        await asyncio.sleep(5.0)
        await scanner.stop()

        if not self.devices:
            self.status_label.config(text="Status: No devices found")
        else:
            for addr, (dev, rssi) in self.devices.items():
                distance = self.estimate_distance(rssi) if rssi else "N/A"
                signal_bars = self.get_signal_bars(rssi) if rssi else "N/A"

                # Adjust display text based on dropdown selection
                if self.display_mode.get() == "Name + ID":
                    name_display = f"{dev.name or 'Unknown'}"
                    addr_display = addr
                elif self.display_mode.get() == "Name Only":
                    name_display = f"{dev.name or 'Unknown'}"
                    addr_display = "-"
                else:  # ID Only
                    name_display = "-"
                    addr_display = addr

                self.device_table.insert("", tk.END,
                                         values=(name_display, addr_display, rssi, distance, signal_bars))

            self.status_label.config(text=f"Status: Found {len(self.devices)} devices")

    def estimate_distance(self, rssi, tx_power=-59):
        """Estimate distance from RSSI."""
        if not rssi or rssi == 0:
            return "N/A"
        ratio = rssi * 1.0 / tx_power
        if ratio < 1.0:
            return round(pow(ratio, 10), 2)
        else:
            distance = (0.89976) * pow(ratio, 7.7095) + 0.111
            return round(distance, 2)

    def get_signal_bars(self, rssi):
        """Return WiFi-like signal bars based on RSSI"""
        if rssi >= -50:
            return "🟩🟩🟩🟩"  # Excellent
        elif -70 <= rssi < -50:
            return "🟩🟩🟩⬜"  # Good
        elif -90 <= rssi < -70:
            return "🟩🟩⬜⬜"  # Fair
        else:
            return "🟩⬜⬜⬜"  # Weak

    def get_selected_device(self):
        """Get selected device from table"""
        selected = self.device_table.selection()
        if not selected:
            return None, None
        values = self.device_table.item(selected[0], "values")
        addr = values[1] if values[1] != "-" else None
        return self.devices.get(addr, (None, None))

    def connect_device(self):
        device, _ = self.get_selected_device()
        if not device:
            messagebox.showwarning("Warning", "Select a device first")
            return
        self.status_label.config(text=f"Connecting to {device.name or device.address}...")
        self.run_async(self._connect_device(device))

    async def _connect_device(self, device):
        try:
            self.client = BleakClient(device)
            await self.client.connect()
            if self.client.is_connected:
                self.status_label.config(text=f"Connected to {device.name or device.address}")
            else:
                self.status_label.config(text="Connection failed")
        except Exception as e:
            self.status_label.config(text=f"Error: {str(e)}")

    def force_connect_device(self):
        device, _ = self.get_selected_device()
        if not device:
            messagebox.showwarning("Warning", "Select a device first")
            return
        self.status_label.config(text=f"Force-Connecting to {device.name or device.address}...")
        self.run_async(self._force_connect_device(device))

    async def _force_connect_device(self, device, retries=5):
        """Force connection by retrying multiple times"""
        for attempt in range(1, retries + 1):
            try:
                if self.client:
                    try:
                        await self.client.disconnect()
                    except:
                        pass
                    self.client = None

                self.client = BleakClient(device)
                await self.client.connect(timeout=10.0)

                if self.client.is_connected:
                    self.status_label.config(
                        text=f"Force-Connected to {device.name or device.address} (Attempt {attempt})"
                    )
                    return
            except Exception as e:
                self.status_label.config(text=f"Retry {attempt}/{retries} failed: {str(e)}")
                await asyncio.sleep(2)

        self.status_label.config(text=f"Force connection failed after {retries} attempts")

    def disconnect_device(self):
        if self.client:
            self.run_async(self._disconnect_device())
        else:
            self.status_label.config(text="No active connection")

    async def _disconnect_device(self):
        try:
            await self.client.disconnect()
            self.status_label.config(text="Disconnected")
        except Exception as e:
            self.status_label.config(text=f"Error: {str(e)}")
        self.client = None


if __name__ == "__main__":
    root = tk.Tk()
    app = BluetoothApp(root)
    root.mainloop()
