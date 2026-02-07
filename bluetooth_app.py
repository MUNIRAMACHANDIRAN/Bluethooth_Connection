import asyncio
import threading
import tkinter as tk
from tkinter import messagebox
from bleak import BleakScanner, BleakClient

class BluetoothApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Bluetooth Control App (Python)")
        self.devices = []
        self.client = None

        # UI Layout
        self.scan_btn = tk.Button(root, text="Scan Devices", command=self.scan_devices)
        self.scan_btn.pack(pady=5)

        self.device_list = tk.Listbox(root, width=50, height=10)
        self.device_list.pack(pady=5)

        self.connect_btn = tk.Button(root, text="Connect", command=self.connect_device)
        self.connect_btn.pack(pady=5)

        self.disconnect_btn = tk.Button(root, text="Disconnect", command=self.disconnect_device)
        self.disconnect_btn.pack(pady=5)

        self.status_label = tk.Label(root, text="Status: Idle", fg="blue")
        self.status_label.pack(pady=5)

    def run_async(self, coro):
        """Run asyncio task in a separate thread"""
        threading.Thread(target=lambda: asyncio.run(coro)).start()

    def scan_devices(self):
        self.status_label.config(text="Status: Scanning...")
        self.device_list.delete(0, tk.END)
        self.run_async(self._scan_devices())

    async def _scan_devices(self):
        devices = await BleakScanner.discover(timeout=5.0)
        self.devices = devices
        if not devices:
            self.status_label.config(text="Status: No devices found")
        else:
            for d in devices:
                self.device_list.insert(tk.END, f"{d.name or 'Unknown'} ({d.address})")
            self.status_label.config(text=f"Status: Found {len(devices)} devices")

    def connect_device(self):
        index = self.device_list.curselection()
        if not index:
            messagebox.showwarning("Warning", "Select a device first")
            return
        device = self.devices[index[0]]
        self.status_label.config(text=f"Connecting to {device.name}...")
        self.run_async(self._connect_device(device))

    async def _connect_device(self, device):
        try:
            self.client = BleakClient(device)
            await self.client.connect()
            if self.client.is_connected:
                self.status_label.config(text=f"Connected to {device.name}")
            else:
                self.status_label.config(text="Connection failed")
        except Exception as e:
            self.status_label.config(text=f"Error: {str(e)}")

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
