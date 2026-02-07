#!/usr/bin/env python3
"""
ble_gui_advanced.py
Advanced BLE GUI demo using bleak + tkinter.

Save as ble_gui_advanced.py and run:
  python -m venv venv
  venv\Scripts\activate
  pip install bleak
  python ble_gui_advanced.py

ONLY use with devices you own / have permission to test.
"""

import asyncio
import json
import threading
import queue
import traceback
import sys
from datetime import datetime
from functools import partial
from tkinter import (
    Tk, Frame, Label, Button, Listbox, Scrollbar, Entry, Text, StringVar,
    END, SINGLE, Toplevel, messagebox, IntVar, Checkbutton
)

from bleak import BleakScanner, BleakClient, BleakError

# Windows: sometimes selector event loop works more predictably with BLE libraries.
if sys.platform.startswith("win"):
    try:
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    except Exception:
        pass

# -----------------------
# Background asyncio loop
# -----------------------
class AsyncioThread:
    def __init__(self):
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self._run_loop, daemon=True)
        self.thread.start()

    def _run_loop(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    def submit_coro(self, coro):
        """Schedule coroutine in the background loop, return concurrent.futures.Future"""
        return asyncio.run_coroutine_threadsafe(coro, self.loop)

    def stop(self):
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(timeout=1)

# -----------------------
# Main App
# -----------------------
class BLEGuiApp:
    def __init__(self, master):
        self.master = master
        master.title("BLE Advanced GUI (Demo)")

        self.asyncio_thread = AsyncioThread()
        self.ui_queue = queue.Queue()  # background -> ui messages

        # State
        self.devices = []  # list of bleak AdvertisementData objects (bleak returns Device types)
        self.client = None  # BleakClient instance
        self.connected_address = None
        self.notification_handlers = {}  # uuid -> handler active
        self.auto_reconnect = IntVar(value=0)

        # Left: device scan / list
        left = Frame(master)
        left.pack(side="left", fill="y", padx=6, pady=6)

        Label(left, text="Devices (scan results)").pack()
        self.device_listbox = Listbox(left, width=40, height=18, selectmode=SINGLE)
        self.device_listbox.pack(side="left", fill="y")
        sb = Scrollbar(left, command=self.device_listbox.yview)
        sb.pack(side="left", fill="y")
        self.device_listbox.config(yscrollcommand=sb.set)

        Button(left, text="Scan (5s)", command=partial(self.scan, 5)).pack(fill="x", pady=4)
        Button(left, text="Scan (10s)", command=partial(self.scan, 10)).pack(fill="x")
        Button(left, text="Refresh RSSI", command=self.refresh_rssi).pack(fill="x", pady=4)

        Button(left, text="Connect", command=self.connect_selected).pack(fill="x", pady=4)
        Button(left, text="Disconnect", command=self.disconnect).pack(fill="x")

        Checkbutton(left, text="Auto-reconnect", variable=self.auto_reconnect).pack(pady=6)

        Button(left, text="Save JSON report", command=self.save_report).pack(fill="x", pady=8)

        # Right: services/characteristics, actions and log
        right = Frame(master)
        right.pack(side="left", fill="both", expand=True, padx=6, pady=6)

        Label(right, text="GATT Services & Characteristics").pack()
        self.gatt_listbox = Listbox(right, width=80, height=12)
        self.gatt_listbox.pack(fill="both", expand=True)

        # Action frame
        act = Frame(right)
        act.pack(fill="x", pady=6)
        Label(act, text="Char UUID:").grid(row=0, column=0, sticky="w")
        self.char_entry = Entry(act, width=50)
        self.char_entry.grid(row=0, column=1, columnspan=4, sticky="w")

        Button(act, text="Read", command=self.read_char).grid(row=1, column=0, pady=4)
        Button(act, text="Subscribe", command=self.subscribe_char).grid(row=1, column=1)
        Button(act, text="Unsubscribe", command=self.unsubscribe_char).grid(row=1, column=2)
        Button(act, text="Write (text)", command=partial(self.write_char, as_hex=False)).grid(row=1, column=3)
        Button(act, text="Write (hex)", command=partial(self.write_char, as_hex=True)).grid(row=1, column=4)

        Label(act, text="Write value:").grid(row=2, column=0, sticky="w")
        self.write_entry = Entry(act, width=50)
        self.write_entry.grid(row=2, column=1, columnspan=4, sticky="w")

        Button(act, text="Pick from list", command=self.pick_char_from_list).grid(row=3, column=0, pady=6)

        # Log
        Label(right, text="Log").pack()
        self.log_text = Text(right, height=10)
        self.log_text.pack(fill="both", expand=True)
        Button(right, text="Save Log to file", command=self.save_log).pack(pady=4)

        # periodic UI update
        self.master.after(200, self._process_ui_queue)

    # -----------------------
    # Utilities / Logging
    # -----------------------
    def log(self, *args):
        ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{ts}] " + " ".join(str(a) for a in args) + "\n"
        self.log_text.insert(END, line)
        self.log_text.see(END)

    def save_log(self):
        fname = f"ble_log_{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.txt"
        try:
            with open(fname, "w", encoding="utf-8") as f:
                f.write(self.log_text.get("1.0", END))
            messagebox.showinfo("Saved", f"Log saved to {fname}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save log: {e}")

    def save_report(self):
        if not self.connected_address:
            messagebox.showwarning("No device", "Connect to a device first to generate report.")
            return
        # trigger a background task to collect current services and save
        fut = self.asyncio_thread.submit_coro(self._collect_and_save_report())
        # we won't block; result will be in ui queue
        self.log("Report save scheduled...")

    async def _collect_and_save_report(self):
        try:
            if not self.client or not await self.client.is_connected():
                self.ui_queue.put(("log", "Not connected - can't create report."))
                return
            report = {"address": self.connected_address, "timestamp": datetime.utcnow().isoformat(), "services": []}
            for svc in self.client.services:
                svc_entry = {"uuid": str(svc.uuid), "description": svc.description, "characteristics": []}
                for c in svc.characteristics:
                    svc_entry["characteristics"].append({
                        "uuid": str(c.uuid),
                        "properties": c.properties,
                        "description": getattr(c, "description", "")
                    })
                report["services"].append(svc_entry)
            fname = f"ble_report_{self.connected_address.replace(':','')}_{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.json"
            with open(fname, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)
            self.ui_queue.put(("log", f"Saved report to {fname}"))
        except Exception as e:
            self.ui_queue.put(("log", f"Error saving report: {e}\n{traceback.format_exc()}"))

    def _process_ui_queue(self):
        try:
            while True:
                item = self.ui_queue.get_nowait()
                if not item:
                    continue
                typ = item[0]
                if typ == "log":
                    self.log(item[1])
                elif typ == "devices":
                    self._update_device_list(item[1])
                elif typ == "gatt":
                    self._update_gatt_list(item[1])
                elif typ == "rssi":
                    self._update_rssi(item[1])
        except queue.Empty:
            pass
        self.master.after(200, self._process_ui_queue)

    # -----------------------
    # Scanning & Device list
    # -----------------------
    def _update_device_list(self, devices):
        self.devices = devices
        self.device_listbox.delete(0, END)
        for d in devices:
            name = d.name or "Unknown"
            self.device_listbox.insert(END, f"{name}  — {d.address}  (RSSI: {d.rssi})")

    def scan(self, timeout=5.0):
        self.log(f"Starting scan for {timeout} seconds...")
        fut = self.asyncio_thread.submit_coro(self._scan_coro(timeout))
        fut.add_done_callback(lambda f: self.ui_queue.put(("log", "Scan finished.")))

    async def _scan_coro(self, timeout):
        try:
            devices = await BleakScanner.discover(timeout=timeout)
            # ensure we store relevant fields (device object has .name, .address, .rssi)
            self.ui_queue.put(("devices", devices))
            self.ui_queue.put(("log", f"Discovered {len(devices)} device(s)."))
        except Exception as e:
            self.ui_queue.put(("log", f"Scan error: {e}"))

    def refresh_rssi(self):
        # Re-run a short scan to update RSSI values for items we already listed
        self.scan(timeout=2.0)

    # -----------------------
    # Connect / Disconnect
    # -----------------------
    def get_selected_device_address(self):
        sel = self.device_listbox.curselection()
        if not sel:
            return None
        idx = sel[0]
        if idx < len(self.devices):
            return self.devices[idx].address
        return None

    def connect_selected(self):
        addr = self.get_selected_device_address()
        if not addr:
            messagebox.showwarning("Select device", "Please select a device from the list to connect.")
            return
        self.log(f"Connecting to {addr} ...")
        self.asyncio_thread.submit_coro(self._connect_coro(addr))

    async def _connect_coro(self, addr):
        try:
            # avoid multiple connect attempts
            if self.client and await self.client.is_connected():
                self.ui_queue.put(("log", "Already connected; disconnect first."))
                return

            client = BleakClient(addr)
            try:
                await client.connect(timeout=10.0)
            except Exception as e:
                self.ui_queue.put(("log", f"Connect failed: {e}"))
                return

            # set handlers and state
            self.client = client
            self.connected_address = addr
            # ensure services are resolved
            await client.get_services()
            # post gatt to UI
            self.ui_queue.put(("gatt", client.services))
            self.ui_queue.put(("log", f"Connected to {addr}"))
            # set disconnection callback
            def _on_disconnect(client_):
                self.ui_queue.put(("log", f"Device {addr} disconnected."))
                # clear client reference on UI thread
                self.ui_queue.put(("gatt", []))
                # handle auto-reconnect if requested
                if self.auto_reconnect.get():
                    self.ui_queue.put(("log", f"Auto-reconnect is ON. Attempting reconnect to {addr} in 3s..."))
                    # schedule reconnection attempt after delay
                    asyncio.run_coroutine_threadsafe(self._delayed_reconnect(addr, delay=3.0), self.asyncio_thread.loop)

            client.set_disconnected_callback(_on_disconnect)

        except Exception as e:
            self.ui_queue.put(("log", f"Connection error: {e}\n{traceback.format_exc()}"))

    async def _delayed_reconnect(self, address, delay=3.0):
        await asyncio.sleep(delay)
        if self.client and await self.client.is_connected():
            self.ui_queue.put(("log", "Already connected, skipping auto-reconnect."))
            return
        self.ui_queue.put(("log", f"Trying to reconnect to {address}..."))
        try:
            new_client = BleakClient(address)
            await new_client.connect(timeout=10.0)
            self.client = new_client
            self.connected_address = address
            await new_client.get_services()
            self.ui_queue.put(("gatt", new_client.services))
            self.ui_queue.put(("log", f"Reconnected to {address}"))
            def _on_disconnect(c): 
                self.ui_queue.put(("log", f"Device {address} disconnected (post-reconnect)."))
                self.ui_queue.put(("gatt", []))
            new_client.set_disconnected_callback(_on_disconnect)
        except Exception as e:
            self.ui_queue.put(("log", f"Reconnect attempt failed: {e}"))

    def disconnect(self):
        if not self.client:
            self.log("Not connected.")
            return
        self.log("Disconnecting...")
        self.asyncio_thread.submit_coro(self._disconnect_coro())

    async def _disconnect_coro(self):
        try:
            if self.client:
                try:
                    await self.client.disconnect()
                except Exception as e:
                    self.ui_queue.put(("log", f"Disconnect error: {e}"))
                self.client = None
                self.connected_address = None
                self.ui_queue.put(("gatt", []))
                self.ui_queue.put(("log", "Disconnected."))
        except Exception as e:
            self.ui_queue.put(("log", f"Unexpected disconnect error: {e}"))

    # -----------------------
    # GATT actions
    # -----------------------
    def _update_gatt_list(self, services):
        self.gatt_listbox.delete(0, END)
        if not services:
            return
        for svc in services:
            self.gatt_listbox.insert(END, f"[Service] {svc.uuid} — {svc.description}")
            for ch in svc.characteristics:
                props = ",".join(ch.properties)
                self.gatt_listbox.insert(END, f"  - Char {ch.uuid} (props: {props})")

    def pick_char_from_list(self):
        sel = self.gatt_listbox.curselection()
        if not sel:
            messagebox.showwarning("Pick char", "Select a characteristic line in the GATT listbox first.")
            return
        idx = sel[0]
        line = self.gatt_listbox.get(idx)
        # try to extract uuid from line
        import re
        m = re.search(r"([0-9a-fA-F-]{36})", line)
        if m:
            uuid = m.group(1)
            self.char_entry.delete(0, END)
            self.char_entry.insert(0, uuid)
            self.log("Picked char", uuid)
        else:
            messagebox.showwarning("UUID", "Couldn't parse UUID from selection. Please copy/paste manually.")

    def read_char(self):
        uuid = self.char_entry.get().strip()
        if not uuid:
            messagebox.showwarning("Char UUID", "Enter characteristic UUID to read.")
            return
        self.log("Scheduling read for", uuid)
        self.asyncio_thread.submit_coro(self._read_char_coro(uuid))

    async def _read_char_coro(self, uuid):
        try:
            if not self.client or not await self.client.is_connected():
                self.ui_queue.put(("log", "Not connected - cannot read."))
                return
            try:
                val = await self.client.read_gatt_char(uuid)
                # try to decode utf-8
                try:
                    decoded = val.decode("utf-8")
                except Exception:
                    decoded = None
                self.ui_queue.put(("log", f"Read {uuid}: {val} (len={len(val)})"))
                if decoded is not None:
                    self.ui_queue.put(("log", f"Decoded: {decoded}"))
            except Exception as e:
                self.ui_queue.put(("log", f"Read error for {uuid}: {e}"))
        except Exception as e:
            self.ui_queue.put(("log", f"Unexpected read error: {e}\n{traceback.format_exc()}"))

    def write_char(self, as_hex=False):
        uuid = self.char_entry.get().strip()
        if not uuid:
            messagebox.showwarning("Char UUID", "Enter characteristic UUID to write to.")
            return
        text = self.write_entry.get()
        if as_hex:
            try:
                b = bytes.fromhex(text.strip())
            except Exception as e:
                messagebox.showerror("Hex parse", f"Failed to parse hex: {e}")
                return
        else:
            b = text.encode("utf-8")
        self.log("Scheduling write to", uuid, f"(len={len(b)})")
        self.asyncio_thread.submit_coro(self._write_char_coro(uuid, b))

    async def _write_char_coro(self, uuid, b):
        try:
            if not self.client or not await self.client.is_connected():
                self.ui_queue.put(("log", "Not connected - cannot write."))
                return
            try:
                await self.client.write_gatt_char(uuid, b)
                self.ui_queue.put(("log", f"Wrote {len(b)} bytes to {uuid}"))
            except Exception as e:
                self.ui_queue.put(("log", f"Write error for {uuid}: {e}"))
        except Exception as e:
            self.ui_queue.put(("log", f"Unexpected write error: {e}\n{traceback.format_exc()}"))

    def subscribe_char(self):
        uuid = self.char_entry.get().strip()
        if not uuid:
            messagebox.showwarning("Char UUID", "Enter characteristic UUID to subscribe.")
            return
        if uuid in self.notification_handlers:
            self.log("Already subscribed to", uuid)
            return
        self.log("Subscribing to", uuid)
        self.asyncio_thread.submit_coro(self._subscribe_coro(uuid))

    async def _subscribe_coro(self, uuid):
        try:
            if not self.client or not await self.client.is_connected():
                self.ui_queue.put(("log", "Not connected - cannot subscribe."))
                return

            def _handler(sender, data: bytearray):
                # runs in asyncio thread; push to ui queue
                try:
                    # show short info, and hex dump
                    h = " ".join(f"{b:02X}" for b in data)
                    self.ui_queue.put(("log", f"[NOTIF] {sender} ({len(data)} bytes) HEX: {h}"))
                    # optionally, if ascii printable:
                    try:
                        s = data.decode("utf-8")
                        self.ui_queue.put(("log", f"[NOTIF decoded] {s}"))
                    except Exception:
                        pass
                except Exception as e:
                    self.ui_queue.put(("log", f"Notification handler error: {e}"))

            await self.client.start_notify(uuid, _handler)
            self.notification_handlers[uuid] = _handler
            self.ui_queue.put(("log", f"Subscribed to {uuid}"))
        except Exception as e:
            self.ui_queue.put(("log", f"Subscribe error for {uuid}: {e}\n{traceback.format_exc()}"))

    def unsubscribe_char(self):
        uuid = self.char_entry.get().strip()
        if not uuid:
            messagebox.showwarning("Char UUID", "Enter characteristic UUID to unsubscribe.")
            return
        if uuid not in self.notification_handlers:
            self.log("Not subscribed to", uuid)
            return
        self.log("Unsubscribing", uuid)
        self.asyncio_thread.submit_coro(self._unsubscribe_coro(uuid))

    async def _unsubscribe_coro(self, uuid):
        try:
            if not self.client or not await self.client.is_connected():
                self.ui_queue.put(("log", "Not connected - cannot unsubscribe."))
                return
            try:
                await self.client.stop_notify(uuid)
            except Exception as e:
                self.ui_queue.put(("log", f"Stop notify error: {e}"))
            self.notification_handlers.pop(uuid, None)
            self.ui_queue.put(("log", f"Unsubscribed {uuid}"))
        except Exception as e:
            self.ui_queue.put(("log", f"Unexpected unsubscribe error: {e}\n{traceback.format_exc()}"))

    def _update_rssi(self, data):
        # placeholder: not used currently
        pass

    # -----------------------
    # Cleanup
    # -----------------------
    def close(self):
        # disconnect if needed
        self.log("Shutting down...")
        try:
            if self.client:
                asyncio.run_coroutine_threadsafe(self.client.disconnect(), self.asyncio_thread.loop).result(timeout=5)
        except Exception:
            pass
        self.asyncio_thread.stop()
        self.master.destroy()

# -----------------------
# Run app
# -----------------------
def main():
    root = Tk()
    app = BLEGuiApp(root)

    def on_close():
        if messagebox.askokcancel("Quit", "Quit and close the application?"):
            app.close()

    root.protocol("WM_DELETE_WINDOW", on_close)
    root.mainloop()

if __name__ == "__main__":
    main()
    
