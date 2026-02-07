import sys
import asyncio
import threading
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime
import logging
import platform
from typing import Optional, Dict, Callable, Any

# -----------------------------
# Logging (console + file)
# -----------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("ble_gui.log", encoding="utf-8")
    ]
)
log = logging.getLogger("BLE-GUI")

try:
    from bleak import BleakScanner, BleakClient
except ImportError:
    raise SystemExit("Bleak is not installed. Install with: pip install bleak")

# -----------------------------
# Windows policy (important for threaded asyncio)
# -----------------------------
if platform.system() == "Windows":
    try:
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        log.info("WindowsSelectorEventLoopPolicy set.")
    except Exception as e:
        log.warning(f"Could not set WindowsSelectorEventLoopPolicy: {e}")


# -----------------------------
# Asyncio Runner (background loop)
# -----------------------------
class AsyncioRunner:
    """Runs a single asyncio event loop in a dedicated thread and lets you submit coroutines."""
    def __init__(self):
        self.loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        log.info("AsyncioRunner started.")

    def _run_loop(self):
        asyncio.set_event_loop(self.loop)
        try:
            self.loop.run_forever()
        except Exception as e:
            log.exception(f"Event loop crashed: {e}")

    def submit(self, coro):
        """Submit coroutine; returns concurrent.futures.Future"""
        return asyncio.run_coroutine_threadsafe(coro, self.loop)

    def stop(self):
        try:
            if self.loop.is_running():
                self.loop.call_soon_threadsafe(self.loop.stop)
            if self._thread.is_alive():
                self._thread.join(timeout=2)
            log.info("AsyncioRunner stopped.")
        except Exception:
            log.exception("Error while stopping AsyncioRunner")


# -----------------------------
# Bluetooth Manager (all async BLE actions)
# -----------------------------
class BluetoothManager:
    def __init__(self, ui_thread_callback: Callable[[Callable[..., Any], Any], None]):
        """
        ui_thread_callback(fn, *args) schedules fn(*args) on Tk main thread.
        """
        self.ui_callback = ui_thread_callback
        self.scanning = False
        self.scanner: Optional[BleakScanner] = None
        self.devices: Dict[str, Dict[str, Any]] = {}  # address -> info
        self.client: Optional[BleakClient] = None
        self._notification_callbacks: Dict[str, Callable] = {}

    async def start_scan(self, on_device_callback: Callable[[Dict[str, Any]], None]):
        """Start continuous scan; pushes updates to UI via on_device_callback(info)."""
        if self.scanning:
            return
        self.scanning = True
        self.devices.clear()

        def _detection(device, adv_data):
            try:
                name = device.name or getattr(adv_data, "local_name", None) or "Unknown"
                rssi = getattr(device, "rssi", None)
                address = getattr(device, "address", None)
                if not address:
                    return
                info = {
                    "address": address,
                    "name": name,
                    "rssi": rssi,
                    "device": device,
                    "last_seen": datetime.now(),
                }
                self.devices[address] = info
                self.ui_callback(on_device_callback, info)
            except Exception:
                log.exception("Error in detection callback")

        self.scanner = BleakScanner(detection_callback=_detection)
        try:
            await self.scanner.start()
            log.info("Scan started.")
        except Exception as e:
            self.scanning = False
            self.ui_callback(messagebox.showerror, "Scan Error", str(e))
            log.exception("Failed to start scan")

    async def stop_scan(self):
        if self.scanning and self.scanner:
            try:
                await self.scanner.stop()
                log.info("Scan stopped.")
            except Exception:
                log.exception("Error while stopping scan")
        self.scanning = False
        self.scanner = None

    async def connect(self, address_or_device: Any):
        if self.client and self.client.is_connected:
            return
        try:
            self.client = BleakClient(address_or_device)
            await self.client.connect(timeout=15.0)
            if not self.client.is_connected:
                raise RuntimeError("Connection failed")
            log.info("Connected.")
        except Exception as e:
            log.exception("Connect failed")
            await self.disconnect()
            raise e

    async def disconnect(self):
        if self.client:
            try:
                # Stop notifications gracefully
                for char_uuid in list(self._notification_callbacks.keys()):
                    try:
                        await self.client.stop_notify(char_uuid)
                    except Exception:
                        pass
                self._notification_callbacks.clear()
                await self.client.disconnect()
                log.info("Disconnected.")
            except Exception:
                log.exception("Error on disconnect")
            finally:
                self.client = None

    async def get_services(self):
        if not self.client or not self.client.is_connected:
            raise RuntimeError("Not connected")
        services = None
        try:
            # Newer bleak
            services = await self.client.get_services()
        except TypeError:
            # Some versions expose .services
            services = getattr(self.client, "services", None)
        if services is None:
            raise RuntimeError("Could not obtain services from device.")
        return services

    async def start_notify(self, char_uuid: str, handler_ui_thread: Callable[[Any, bytes], None]):
        if not self.client or not self.client.is_connected:
            raise RuntimeError("Not connected")

        def _handler(sender, data: bytearray):
            self.ui_callback(handler_ui_thread, sender, bytes(data))

        await self.client.start_notify(char_uuid, _handler)
        self._notification_callbacks[char_uuid] = _handler
        log.info("Notification started for %s", char_uuid)

    async def stop_notify(self, char_uuid: str):
        if not self.client or not self.client.is_connected:
            return
        if char_uuid in self._notification_callbacks:
            await self.client.stop_notify(char_uuid)
            self._notification_callbacks.pop(char_uuid, None)
            log.info("Notification stopped for %s", char_uuid)

    async def write(self, char_uuid: str, data: bytes, response: bool = True):
        if not self.client or not self.client.is_connected:
            raise RuntimeError("Not connected")
        await self.client.write_gatt_char(char_uuid, data, response=response)

    async def read(self, char_uuid: str) -> bytes:
        if not self.client or not self.client.is_connected:
            raise RuntimeError("Not connected")
        return await self.client.read_gatt_char(char_uuid)

    async def read_descriptor(self, handle: int) -> bytes:
        if not self.client or not self.client.is_connected:
            raise RuntimeError("Not connected")
        return await self.client.read_gatt_descriptor(handle)


# -----------------------------
# Helper functions
# -----------------------------
def normalize_uuid(u: str) -> str:
    """Accepts 'FFF1' and returns full 128-bit UUID; leaves 128-bit as-is."""
    s = (u or "").strip().lower()
    s = s.replace("0x", "").replace("{", "").replace("}", "")
    if len(s) == 4:
        return f"0000{s}-0000-1000-8000-00805f9b34fb"
    return s

def hexstr_to_bytes(s: str) -> bytes:
    s_clean = (s or "").strip().replace(" ", "").replace(",", "")
    if not s_clean:
        return b""
    if len(s_clean) % 2 != 0:
        raise ValueError("Hex string must have even length")
    try:
        return bytes.fromhex(s_clean)
    except Exception:
        raise ValueError("Invalid hex string")

def safe_ascii(b: bytes) -> str:
    try:
        return b.decode("utf-8", errors="ignore")
    except Exception:
        return ""

def hex_or_str(u):
    try:
        return str(u)
    except Exception:
        return repr(u)


# -----------------------------
# Tkinter UI
# -----------------------------
class BluetoothApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Bluetooth Control App (BLE + GATT Commands)")
        self.root.geometry("1040x720")

        self.runner = AsyncioRunner()
        self.ble = BluetoothManager(self._call_on_ui)

        self.selected_address: Optional[str] = None
        self.tree_item_by_addr: Dict[str, str] = {}
        # Tree item id -> { uuid:str, props:set, char:bleak_characteristic }
        self.char_by_item: Dict[str, Dict[str, Any]] = {}

        self._build_ui()
        self._bind_events()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    # ---------- UI helpers ----------
    def _call_on_ui(self, fn: Callable, *args, **kwargs):
        self.root.after(0, lambda: fn(*args, **kwargs))

    def log(self, msg: str):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.configure(state="normal")
        self.log_text.insert("end", f"[{timestamp}] {msg}\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")
        log.info(msg)

    def set_status(self, text: str, color="blue"):
        self.status_var.set(text)
        self.status_label.config(foreground=color)

    # ---------- Build UI ----------
    def _build_ui(self):
        toolbar = ttk.Frame(self.root, padding=6)
        toolbar.pack(fill="x")

        self.btn_scan_start = ttk.Button(toolbar, text="Start Scan", command=self.on_start_scan)
        self.btn_scan_stop = ttk.Button(toolbar, text="Stop Scan", command=self.on_stop_scan, state="disabled")
        self.btn_connect = ttk.Button(toolbar, text="Connect", command=self.on_connect, state="disabled")
        self.btn_disconnect = ttk.Button(toolbar, text="Disconnect", command=self.on_disconnect, state="disabled")
        for w in (self.btn_scan_start, self.btn_scan_stop, self.btn_connect, self.btn_disconnect):
            w.pack(side="left", padx=4)

        self.status_var = tk.StringVar(value="Status: Idle")
        self.status_label = ttk.Label(toolbar, textvariable=self.status_var, foreground="blue")
        self.status_label.pack(side="right")

        main_pane = ttk.Panedwindow(self.root, orient="horizontal")
        main_pane.pack(fill="both", expand=True, padx=6, pady=6)

        # Left: Devices
        left = ttk.Labelframe(main_pane, text="Devices")
        main_pane.add(left, weight=1)

        self.device_tree = ttk.Treeview(left, columns=("name", "address", "rssi"), show="headings", height=16)
        self.device_tree.heading("name", text="Name")
        self.device_tree.heading("address", text="Address")
        self.device_tree.heading("rssi", text="RSSI")
        self.device_tree.column("name", width=300, anchor="w")
        self.device_tree.column("address", width=240, anchor="w")
        self.device_tree.column("rssi", width=60, anchor="center")
        self.device_tree.pack(fill="both", expand=True, padx=6, pady=6)

        # Right: Services/Chars + Actions + Control + Log
        right = ttk.Panedwindow(main_pane, orient="vertical")
        main_pane.add(right, weight=3)

        # Services panel
        svc_frame = ttk.Labelframe(right, text="Services & Characteristics")
        right.add(svc_frame, weight=3)

        self.svc_tree = ttk.Treeview(svc_frame, columns=("type", "uuid", "props"), show="headings", height=12)
        self.svc_tree.heading("type", text="Type")
        self.svc_tree.heading("uuid", text="UUID")
        self.svc_tree.heading("props", text="Properties")
        self.svc_tree.column("type", width=120, anchor="w")
        self.svc_tree.column("uuid", width=560, anchor="w")
        self.svc_tree.column("props", width=240, anchor="w")
        self.svc_tree.pack(fill="both", expand=True, padx=6, pady=6)

        # Actions panel
        action_frame = ttk.Labelframe(right, text="Actions")
        right.add(action_frame, weight=1)

        # Subscribe/Unsubscribe
        nf = ttk.Frame(action_frame)
        nf.pack(fill="x", padx=6, pady=(6, 0))
        self.btn_subscribe = ttk.Button(nf, text="Subscribe", command=self.on_subscribe, state="disabled")
        self.btn_unsubscribe = ttk.Button(nf, text="Unsubscribe", command=self.on_unsubscribe, state="disabled")
        self.btn_subscribe.pack(side="left", padx=(0, 4))
        self.btn_unsubscribe.pack(side="left", padx=4)

        # Read / Read Descriptors
        rw = ttk.Frame(action_frame)
        rw.pack(fill="x", padx=6, pady=6)
        self.btn_read = ttk.Button(rw, text="Read Selected", command=self.on_read_selected, state="disabled")
        self.btn_read_desc = ttk.Button(rw, text="Read Descriptors", command=self.on_read_descriptors, state="disabled")
        self.btn_read.pack(side="left", padx=(0, 6))
        self.btn_read_desc.pack(side="left", padx=6)

        # Write controls
        wf = ttk.Frame(action_frame)
        wf.pack(fill="x", padx=6, pady=6)
        ttk.Label(wf, text="Write Data:").pack(side="left")
        self.write_data_var = tk.StringVar()
        self.entry_write = ttk.Entry(wf, textvariable=self.write_data_var, width=48)
        self.entry_write.pack(side="left", padx=4)
        self.write_mode = tk.StringVar(value="hex")
        ttk.Radiobutton(wf, text="Hex", variable=self.write_mode, value="hex").pack(side="left", padx=2)
        ttk.Radiobutton(wf, text="ASCII", variable=self.write_mode, value="ascii").pack(side="left", padx=2)
        self.write_with_resp = tk.BooleanVar(value=True)
        ttk.Checkbutton(wf, text="Write w/ response", variable=self.write_with_resp).pack(side="left", padx=8)
        self.btn_write = ttk.Button(wf, text="Write to Selected", command=self.on_write, state="disabled")
        self.btn_write.pack(side="left", padx=8)

        # GATT Control panel
        ctrl = ttk.Labelframe(right, text="GATT Control (Play/Pause/Next/Prev/Volume)")
        right.add(ctrl, weight=1)

        top = ttk.Frame(ctrl); top.pack(fill="x", padx=6, pady=6)
        ttk.Label(top, text="Control Char UUID:").pack(side="left")
        self.control_char_var = tk.StringVar()
        ttk.Entry(top, textvariable=self.control_char_var, width=52).pack(side="left", padx=6)
        ttk.Button(top, text="Use Selected", command=self.on_use_selected_as_control).pack(side="left", padx=6)
        ttk.Label(top, text="(Pick a writable char from the list)").pack(side="left")

        grid = ttk.Frame(ctrl); grid.pack(fill="x", padx=6, pady=6)

        # Customize these payloads for your device (left blank by default)
        self.payloads: Dict[str, tk.StringVar] = {
            "Play/Pause": tk.StringVar(value=""),
            "Next":       tk.StringVar(value=""),
            "Previous":   tk.StringVar(value=""),
            "Vol+":       tk.StringVar(value=""),
            "Vol-":       tk.StringVar(value=""),
        }

        row = 0
        for label, var in self.payloads.items():
            ttk.Label(grid, text=label + " Hex:").grid(row=row, column=0, sticky="w", padx=2, pady=3)
            ttk.Entry(grid, textvariable=var, width=20).grid(row=row, column=1, sticky="w", padx=2)
            ttk.Button(grid, text=label, command=lambda l=label: self.on_send_control(l)).grid(row=row, column=2, padx=8)
            row += 1

        ttk.Separator(ctrl, orient="horizontal").pack(fill="x", padx=6, pady=6)
        custom = ttk.Frame(ctrl); custom.pack(fill="x", padx=6, pady=6)
        ttk.Label(custom, text="Custom Hex/ASCII:").pack(side="left")
        self.custom_cmd_var = tk.StringVar()
        ttk.Entry(custom, textvariable=self.custom_cmd_var, width=36).pack(side="left", padx=4)
        self.custom_mode = tk.StringVar(value="hex")
        ttk.Radiobutton(custom, text="Hex", variable=self.custom_mode, value="hex").pack(side="left", padx=2)
        ttk.Radiobutton(custom, text="ASCII", variable=self.custom_mode, value="ascii").pack(side="left", padx=2)
        ttk.Button(custom, text="Send Custom", command=self.on_send_custom).pack(side="left", padx=8)

        # Log panel
        log_frame = ttk.Labelframe(right, text="Log")
        right.add(log_frame, weight=2)
        self.log_text = tk.Text(log_frame, height=12, state="disabled")
        self.log_text.pack(fill="both", expand=True, padx=6, pady=6)

    def _bind_events(self):
        self.device_tree.bind("<<TreeviewSelect>>", self._on_device_selected)
        self.svc_tree.bind("<<TreeviewSelect>>", self._on_characteristic_selected)

    # ---------- Event handlers ----------
    def on_start_scan(self):
        self.set_status("Status: Scanning...", "blue")
        self.btn_scan_start.config(state="disabled")
        self.btn_scan_stop.config(state="normal")
        for child in self.device_tree.get_children():
            self.device_tree.delete(child)
        self.tree_item_by_addr.clear()

        def on_device(info):
            address = info["address"]
            values = (info["name"], address, info.get("rssi"))
            if address in self.tree_item_by_addr:
                iid = self.tree_item_by_addr[address]
                self.device_tree.item(iid, values=values)
            else:
                iid = self.device_tree.insert("", "end", values=values)
                self.tree_item_by_addr[address] = iid
            self.set_status(f"Status: Scanning... {len(self.tree_item_by_addr)} device(s) found", "blue")

        self.runner.submit(self.ble.start_scan(on_device))

    def on_stop_scan(self):
        self.btn_scan_stop.config(state="disabled")
        future = self.runner.submit(self.ble.stop_scan())
        def _done(_fut):
            self.set_status("Status: Scan Stopped", "grey")
            self.btn_scan_start.config(state="normal")
        future.add_done_callback(lambda f: self._call_on_ui(_done, f))

    def _on_device_selected(self, _evt=None):
        sel = self.device_tree.selection()
        if not sel:
            self.selected_address = None
            self.btn_connect.config(state="disabled")
            return
        _name, address, _rssi = self.device_tree.item(sel[0], "values")
        self.selected_address = address
        self.btn_connect.config(state="normal")

    def on_connect(self):
        if not self.selected_address:
            messagebox.showwarning("Warning", "Select a device first")
            return
        addr = self.selected_address
        self.set_status(f"Status: Connecting to {addr}...", "blue")
        self.btn_connect.config(state="disabled")
        self.btn_disconnect.config(state="disabled")
        for child in self.svc_tree.get_children():
            self.svc_tree.delete(child)
        self.char_by_item.clear()

        async def _task():
            await self.ble.stop_scan()
            try:
                await self.ble.connect(addr)
                services = await self.ble.get_services()
                self._call_on_ui(self._populate_services, services)
                self._call_on_ui(self.set_status, f"Status: Connected to {addr}", "green")
                self._call_on_ui(self.btn_disconnect.config, {"state": "normal"})
            except Exception as e:
                self._call_on_ui(messagebox.showerror, "Connection Error", str(e))
                self._call_on_ui(self.set_status, "Status: Idle", "red")
                self._call_on_ui(self.btn_connect.config, {"state": "normal"})

        self.runner.submit(_task())

    def on_disconnect(self):
        self.btn_disconnect.config(state="disabled")

        async def _task():
            try:
                await self.ble.disconnect()
            finally:
                self._call_on_ui(self.set_status, "Status: Disconnected", "grey")
                self._call_on_ui(self.btn_connect.config, {"state": "normal"})
                self._call_on_ui(self._reset_actions)

        self.runner.submit(_task())

    def _populate_services(self, services):
        for child in self.svc_tree.get_children():
            self.svc_tree.delete(child)
        self.char_by_item.clear()

        try:
            for svc in services:
                svc_iid = self.svc_tree.insert("", "end", values=("Service", str(svc.uuid), ""))
                for ch in svc.characteristics:
                    props = ",".join(sorted(ch.properties))
                    ch_iid = self.svc_tree.insert(svc_iid, "end",
                                                  values=("Characteristic", str(ch.uuid), props))
                    # Save metadata for actions
                    self.char_by_item[ch_iid] = {
                        "uuid": str(ch.uuid),
                        "props": set(ch.properties),
                        "char": ch
                    }
        except Exception:
            log.exception("Error populating services")

        self._reset_actions()

    def _on_characteristic_selected(self, _evt=None):
        sel = self.svc_tree.selection()
        if not sel:
            self._reset_actions()
            return
        iid = sel[0]
        meta = self.char_by_item.get(iid)
        if not meta:
            self._reset_actions()
            return
        props = meta["props"]
        self.btn_subscribe.config(state="normal" if ("notify" in props or "indicate" in props) else "disabled")
        self.btn_unsubscribe.config(state="normal")
        can_write = ("write" in props or "write-without-response" in props)
        self.btn_write.config(state="normal" if can_write else "disabled")
        self.btn_read.config(state="normal")
        self.btn_read_desc.config(state="normal")

    def _reset_actions(self):
        self.btn_subscribe.config(state="disabled")
        self.btn_unsubscribe.config(state="disabled")
        self.btn_write.config(state="disabled")
        self.btn_read.config(state="disabled")
        self.btn_read_desc.config(state="disabled")

    def on_subscribe(self):
        sel = self.svc_tree.selection()
        if not sel or sel[0] not in self.char_by_item:
            messagebox.showinfo("Info", "Select a characteristic to subscribe")
            return
        char_uuid = normalize_uuid(self.char_by_item[sel[0]]["uuid"])
        self.log(f"Subscribing to {char_uuid}...")

        def handler(sender, data: bytes):
            self.log(f"Notification from {sender}: {data.hex()} ({len(data)}B) | ASCII: {safe_ascii(data)}")

        async def _task():
            try:
                await self.ble.start_notify(char_uuid, handler)
                self._call_on_ui(self.log, f"Subscribed to {char_uuid}")
            except Exception as e:
                self._call_on_ui(messagebox.showerror, "Subscribe Error", str(e))

        self.runner.submit(_task())

    def on_unsubscribe(self):
        sel = self.svc_tree.selection()
        if not sel or sel[0] not in self.char_by_item:
            messagebox.showinfo("Info", "Select a characteristic to unsubscribe")
            return
        char_uuid = normalize_uuid(self.char_by_item[sel[0]]["uuid"])

        async def _task():
            try:
                await self.ble.stop_notify(char_uuid)
                self._call_on_ui(self.log, f"Unsubscribed from {char_uuid}")
            except Exception as e:
                self._call_on_ui(messagebox.showerror, "Unsubscribe Error", str(e))

        self.runner.submit(_task())

    def on_read_selected(self):
        sel = self.svc_tree.selection()
        if not sel or sel[0] not in self.char_by_item:
            messagebox.showinfo("Info", "Select a characteristic to read")
            return
        char_uuid = normalize_uuid(self.char_by_item[sel[0]]["uuid"])
        self.log(f"Reading {char_uuid}...")

        async def _task():
            try:
                data = await self.ble.read(char_uuid)
                self._call_on_ui(self.log, f"Read {char_uuid}: {data.hex()} | ASCII: {safe_ascii(data)}")
            except Exception as e:
                self._call_on_ui(messagebox.showerror, "Read Error", str(e))

        self.runner.submit(_task())

    def on_read_descriptors(self):
        sel = self.svc_tree.selection()
        if not sel or sel[0] not in self.char_by_item:
            messagebox.showinfo("Info", "Select a characteristic first")
            return
        meta = self.char_by_item[sel[0]]
        ch = meta.get("char")
        if not ch or not getattr(ch, "descriptors", None):
            self.log("No descriptors found for this characteristic.")
            return

        async def _task():
            for d in ch.descriptors:
                try:
                    data = await self.ble.read_descriptor(d.handle)
                    self._call_on_ui(self.log, f"Descriptor {hex_or_str(d.uuid)} (handle {d.handle}): {data.hex()} | ASCII: {safe_ascii(data)}")
                except Exception as e:
                    self._call_on_ui(self.log, f"Descriptor {hex_or_str(d.uuid)} read error: {e}")

        self.runner.submit(_task())

    def on_write(self):
        sel = self.svc_tree.selection()
        if not sel or sel[0] not in self.char_by_item:
            messagebox.showinfo("Info", "Select a characteristic to write")
            return
        meta = self.char_by_item[sel[0]]
        uuid = normalize_uuid(meta["uuid"])
        props = meta["props"]

        s = self.write_data_var.get().strip()
        if not s:
            messagebox.showwarning("Warning", "Write data is empty")
            return
        try:
            data = hexstr_to_bytes(s) if self.write_mode.get() == "hex" else s.encode("utf-8")
        except Exception as e:
            messagebox.showerror("Format Error", f"Invalid data: {e}")
            return

        with_resp = self.write_with_resp.get()
        self._safe_write(uuid, data, prefer_with_response=with_resp, props=props)

    # ---------- GATT Control panel handlers ----------
    def on_use_selected_as_control(self):
        sel = self.svc_tree.selection()
        if not sel or sel[0] not in self.char_by_item:
            messagebox.showinfo("Info", "Select a writable characteristic first")
            return
        meta = self.char_by_item[sel[0]]
        props = meta.get("props", set())
        if not ("write" in props or "write-without-response" in props):
            messagebox.showwarning("Not Writable", "Selected characteristic is not writable.")
            return
        self.control_char_var.set(str(meta["uuid"]))
        self.log(f"Control Char set to {meta['uuid']} (props: {','.join(sorted(props))})")

    def on_send_control(self, label: str):
        uuid = normalize_uuid(self.control_char_var.get())
        if not uuid:
            messagebox.showwarning("Missing UUID", "Enter the Control Char UUID first (or click 'Use Selected').")
            return
        hex_str = self.payloads[label].get().strip()
        if not hex_str:
            messagebox.showwarning("Missing Data", f"Set hex data for '{label}' first.")
            return
        try:
            data = hexstr_to_bytes(hex_str)
        except ValueError as e:
            messagebox.showerror("Format Error", f"{e}")
            return
        with_resp = self.write_with_resp.get()
        self.log(f"[CONTROL] {label} -> {uuid} (resp={with_resp}): {data.hex()}")
        # We may not know props for this UUID if it's typed manually; pass props=None
        self._safe_write(uuid, data, prefer_with_response=with_resp, props=None)

    def on_send_custom(self):
        uuid = normalize_uuid(self.control_char_var.get())
        if not uuid:
            messagebox.showwarning("Missing UUID", "Enter the Control Char UUID first (or click 'Use Selected').")
            return
        s = self.custom_cmd_var.get().strip()
        if not s:
            messagebox.showwarning("Missing Data", "Enter custom data (hex or ASCII)")
            return
        try:
            data = hexstr_to_bytes(s) if self.custom_mode.get() == "hex" else s.encode("utf-8")
        except ValueError as e:
            messagebox.showerror("Format Error", f"{e}")
            return
        with_resp = self.write_with_resp.get()
        self.log(f"[CONTROL] Custom -> {uuid} (resp={with_resp}): {data.hex()}")
        self._safe_write(uuid, data, prefer_with_response=with_resp, props=None)

    # ---------- Safe write helpers ----------
    def _can_write_props(self, props: Optional[set]) -> str:
        """
        Return 'with' if 'write' supported, 'without' if 'write-without-response' supported,
        or '' if not writable. If props is None, return '?' (unknown).
        """
        if props is None:
            return "?"
        if "write" in props:
            return "with"
        if "write-without-response" in props:
            return "without"
        return ""

    def _safe_write(self, uuid: str, data: bytes, prefer_with_response: bool = True, props: Optional[set] = None):
        """
        Try writing with the best mode supported by the characteristic.
        If prefer_with_response=True but char only supports 'without', fallback automatically.
        """
        mode = self._can_write_props(props)
        if mode == "":
            messagebox.showerror("Write Error", "Characteristic is not writable.")
            return

        # Decide response mode:
        use_resp = prefer_with_response
        if mode == "with":
            use_resp = True
        elif mode == "without":
            use_resp = False
        # If mode is '?', we don't know—try the user's preference first.
        self.log(f"Writing to {uuid} (resp={use_resp}): {data.hex()}")

        async def _task():
            try:
                await self.ble.write(uuid, data, response=use_resp)
                self._call_on_ui(self.log, f"Write complete ({len(data)}B)")
            except Exception as e:
                # If failed and mode was unknown, try the opposite response mode once
                if mode == "?":
                    try:
                        fallback = not use_resp
                        self._call_on_ui(self.log, f"Retrying with resp={fallback} due to error: {type(e).__name__}: {e}")
                        await self.ble.write(uuid, data, response=fallback)
                        self._call_on_ui(self.log, f"Write complete with fallback ({len(data)}B)")
                        return
                    except Exception as e2:
                        self._call_on_ui(messagebox.showerror, "Write Error", f"{type(e2).__name__}: {e2}")
                        return
                self._call_on_ui(messagebox.showerror, "Write Error", f"{type(e).__name__}: {e}")

        self.runner.submit(_task())

    def on_close(self):
        async def _shutdown():
            try:
                await self.ble.stop_scan()
            except Exception:
                pass
            try:
                await self.ble.disconnect()
            except Exception:
                pass
            self._call_on_ui(self.root.destroy)

        self.runner.submit(_shutdown())
        self.root.after(200, self.runner.stop)


# -----------------------------
# Main
# -----------------------------
if __name__ == "__main__":
    root = tk.Tk()
    # Optional: apply a ttk theme if available
    try:
        style = ttk.Style()
        if "clam" in style.theme_names():
            style.theme_use("clam")
    except Exception:
        pass
    app = BluetoothApp(root)
    root.mainloop()
