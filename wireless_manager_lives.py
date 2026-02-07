import asyncio
import threading
import queue
import subprocess
import json
from datetime import datetime
from tkinter import *
from tkinter import messagebox

from bleak import BleakScanner, BleakClient
import sys
if sys.platform.startswith("win"):
    try:
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    except Exception:
        pass

# ----------------------------
# Background asyncio thread for BLE
# ----------------------------
class AsyncioThread:
    def __init__(self):
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self._run_loop, daemon=True)
        self.thread.start()

    def _run_loop(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    def submit_coro(self, coro):
        return asyncio.run_coroutine_threadsafe(coro, self.loop)

# ----------------------------
# Main App
# ----------------------------
class WirelessManagerApp:
    def __init__(self, master):
        self.master = master
        master.title("Wireless Manager Live Scan (BLE + Wi-Fi Debug)")

        self.asyncio_thread = AsyncioThread()
        self.ui_queue = queue.Queue()

        # BLE state
        self.ble_devices = {}
        self.ble_client = None
        self.connected_address = None
        self.ble_scan_interval = 5  # seconds

        # Wi-Fi state
        self.wifi_networks = {}
        self.wifi_scan_interval = 10  # seconds

        # ----------------------------
        # Side-by-side panels
        # ----------------------------
        self.main_frame = Frame(master)
        self.main_frame.pack(fill=BOTH, expand=True)

        self.left_panel = Frame(self.main_frame)
        self.left_panel.pack(side=LEFT, fill=BOTH, expand=True, padx=5, pady=5)

        self.right_panel = Frame(self.main_frame)
        self.right_panel.pack(side=LEFT, fill=BOTH, expand=True, padx=5, pady=5)

        # Build panels
        self.build_ble_panel(self.left_panel)
        self.build_wifi_panel(self.right_panel)

        # Shared log panel
        self.log_text = Text(master, height=10)
        self.log_text.pack(fill=BOTH, padx=5, pady=5)
        self.save_log_btn = Button(master, text="Save Log", command=self.save_log)
        self.save_log_btn.pack(pady=2)

        # Start live scanning
        self.start_live_scanning()

        # Periodic UI update
        self.master.after(200, self._process_ui_queue)

    # ----------------------------
    # Logging
    # ----------------------------
    def log(self, *args):
        ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{ts}] " + " ".join(str(a) for a in args) + "\n"
        self.log_text.insert(END, line)
        self.log_text.see(END)
        print(line, end='')  # Debug print

    def save_log(self):
        fname = f"wireless_log_{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.txt"
        with open(fname, "w", encoding="utf-8") as f:
            f.write(self.log_text.get("1.0", END))
        self.log(f"Saved log to {fname}")

    def _process_ui_queue(self):
        try:
            while True:
                item = self.ui_queue.get_nowait()
                if not item:
                    continue
                typ = item[0]
                if typ == "log":
                    self.log(item[1])
                elif typ == "ble_devices":
                    self.update_ble_list(item[1])
                elif typ == "wifi_networks":
                    self.update_wifi_list(item[1])
        except queue.Empty:
            pass
        self.master.after(200, self._process_ui_queue)

    # ----------------------------
    # BLE Panel
    # ----------------------------
    def build_ble_panel(self, frame):
        Label(frame, text="Bluetooth (BLE)").pack()
        self.ble_listbox = Listbox(frame, width=50)
        self.ble_listbox.pack(fill=BOTH, padx=5, pady=5)

        btn_frame = Frame(frame)
        btn_frame.pack(pady=4)
        Button(btn_frame, text="Connect", command=self.ble_connect_selected).grid(row=0,column=0,padx=2)
        Button(btn_frame, text="Disconnect", command=self.ble_disconnect).grid(row=0,column=1,padx=2)
        Button(btn_frame, text="Save BLE report", command=self.ble_save_report).grid(row=0,column=2,padx=2)

        # Manual Scan button
        Button(frame, text="Scan BLE Now", command=self.ble_scan_once).pack(pady=2)

    def update_ble_list(self, devices):
        self.ble_devices = {d.address: d for d in devices}
        self.ble_listbox.delete(0, END)
        if not devices:
            self.ble_listbox.insert(END, "(No BLE devices found)")
        for d in devices:
            name = d.name or "Unknown"
            self.ble_listbox.insert(END, f"{name} — {d.address} (RSSI: {d.rssi})")

    def ble_scan_live(self):
        async def scan():
            try:
                self.ui_queue.put(("log", "Starting BLE live scan..."))
                devices = await BleakScanner.discover(timeout=5)
                self.ui_queue.put(("ble_devices", devices))
                self.ui_queue.put(("log", f"BLE scan complete ({len(devices)} devices)"))
            except Exception as e:
                self.ui_queue.put(("log", f"BLE live scan error: {e}"))
            finally:
                self.master.after(self.ble_scan_interval*1000, self.ble_scan_live)
        self.asyncio_thread.submit_coro(scan())

    def ble_scan_once(self):
        async def scan():
            try:
                self.ui_queue.put(("log", "Starting manual BLE scan..."))
                devices = await BleakScanner.discover(timeout=5)
                self.ui_queue.put(("ble_devices", devices))
                self.ui_queue.put(("log", f"Manual BLE scan complete ({len(devices)} devices)"))
            except Exception as e:
                self.ui_queue.put(("log", f"BLE scan error: {e}"))
        self.asyncio_thread.submit_coro(scan())

    def ble_connect_selected(self):
        sel = self.ble_listbox.curselection()
        if not sel: 
            messagebox.showwarning("Select device", "Select a BLE device first")
            return
        addr = list(self.ble_devices.keys())[sel[0]]
        self.ui_queue.put(("log", f"Connecting to {addr}..."))
        self.asyncio_thread.submit_coro(self._ble_connect_coro(addr))

    async def _ble_connect_coro(self, addr):
        try:
            if self.ble_client and await self.ble_client.is_connected():
                self.ui_queue.put(("log","Already connected"))
                return
            client = BleakClient(addr)
            await client.connect()
            self.ble_client = client
            self.connected_address = addr
            await client.get_services()
            self.ui_queue.put(("log", f"Connected to {addr}"))
        except Exception as e:
            self.ui_queue.put(("log", f"BLE connect error: {e}"))

    def ble_disconnect(self):
        if not self.ble_client:
            self.log("Not connected")
            return
        self.asyncio_thread.submit_coro(self._ble_disconnect_coro())

    async def _ble_disconnect_coro(self):
        try:
            await self.ble_client.disconnect()
            self.ui_queue.put(("log", "BLE disconnected"))
            self.ble_client = None
            self.connected_address = None
        except Exception as e:
            self.ui_queue.put(("log", f"BLE disconnect error: {e}"))

    def ble_save_report(self):
        if not self.ble_devices:
            self.log("No BLE devices to save")
            return
        fname = f"ble_scan_{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.json"
        data = [{"name": d.name,"address":d.address,"rssi":d.rssi} for d in self.ble_devices.values()]
        with open(fname,"w") as f:
            json.dump(data,f,indent=2)
        self.log(f"Saved BLE scan report to {fname}")

    # ----------------------------
    # Wi-Fi Panel
    # ----------------------------
    def build_wifi_panel(self, frame):
        Label(frame, text="Wi-Fi Networks").pack()
        self.wifi_listbox = Listbox(frame, width=50)
        self.wifi_listbox.pack(fill=BOTH, padx=5, pady=5)

        btn_frame = Frame(frame)
        btn_frame.pack(pady=4)
        Button(btn_frame, text="Connect", command=self.wifi_connect_selected).grid(row=0,column=0,padx=2)
        Button(btn_frame, text="Disconnect", command=self.wifi_disconnect).grid(row=0,column=1,padx=2)
        Button(btn_frame, text="Save Wi-Fi report", command=self.wifi_save_report).grid(row=0,column=2,padx=2)

        # Manual Scan button
        Button(frame, text="Scan Wi-Fi Now", command=self.wifi_scan_once).pack(pady=2)

    def update_wifi_list(self, networks):
        self.wifi_networks = {n['SSID']: n for n in networks}
        self.wifi_listbox.delete(0, END)
        if not networks:
            self.wifi_listbox.insert(END, "(No Wi-Fi networks found)")
        for n in networks:
            self.wifi_listbox.insert(END, f"{n.get('SSID','')} (Signal: {n.get('Signal',0)}%) Auth:{n.get('Auth','')}")

    def wifi_scan_live(self):
        def scan():
            try:
                self.ui_queue.put(("log","Starting Wi-Fi live scan..."))
                output = subprocess.run("netsh wlan show networks mode=bssid", capture_output=True, text=True, shell=True).stdout
                networks = []
                current_ssid = None
                for line in output.splitlines():
                    line = line.strip()
                    if line.startswith("SSID "):
                        current_ssid = line.split(":",1)[1].strip()
                        networks.append({"SSID": current_ssid})
                    elif line.startswith("Signal") and current_ssid:
                        signal = line.split(":",1)[1].strip().replace("%","")
                        networks[-1]["Signal"] = int(signal)
                    elif line.startswith("Authentication") and current_ssid:
                        networks[-1]["Auth"] = line.split(":",1)[1].strip()
                self.ui_queue.put(("wifi_networks", networks))
                self.ui_queue.put(("log", f"Wi-Fi scan complete ({len(networks)} networks)"))
            except Exception as e:
                self.ui_queue.put(("log", f"Wi-Fi live scan error: {e}"))
            finally:
                self.master.after(self.wifi_scan_interval*1000, self.wifi_scan_live)
        threading.Thread(target=scan, daemon=True).start()

    def wifi_scan_once(self):
        def scan():
            try:
                self.ui_queue.put(("log","Starting manual Wi-Fi scan..."))
                output = subprocess.run("netsh wlan show networks mode=bssid", capture_output=True, text=True, shell=True).stdout
                networks = []
                current_ssid = None
                for line in output.splitlines():
                    line = line.strip()
                    if line.startswith("SSID "):
                        current_ssid = line.split(":",1)[1].strip()
                        networks.append({"SSID": current_ssid})
                    elif line.startswith("Signal") and current_ssid:
                        signal = line.split(":",1)[1].strip().replace("%","")
                        networks[-1]["Signal"] = int(signal)
                    elif line.startswith("Authentication") and current_ssid:
                        networks[-1]["Auth"] = line.split(":",1)[1].strip()
                self.ui_queue.put(("wifi_networks", networks))
                self.ui_queue.put(("log", f"Manual Wi-Fi scan complete ({len(networks)} networks)"))
            except Exception as e:
                self.ui_queue.put(("log", f"Wi-Fi scan error: {e}"))
        threading.Thread(target=scan, daemon=True).start()

    # ----------------------------
    # Start live scanning
    # ----------------------------
    def start_live_scanning(self):
        self.ble_scan_live()
        self.wifi_scan_live()

# ----------------------------
# Simple input dialog for Wi-Fi password
# ----------------------------
def simple_input(title, prompt):
    input_win = Toplevel()
    input_win.title(title)
    Label(input_win, text=prompt).pack(padx=10, pady=5)
    entry = Entry(input_win, show="*")
    entry.pack(padx=10, pady=5)
    result = {"value": None}

    def ok():
        result["value"] = entry.get()
        input_win.destroy()
    Button(input_win, text="OK", command=ok).pack(pady=5)
    input_win.grab_set()
    input_win.wait_window()
    return result["value"]

# ----------------------------
# Run app
# ----------------------------
if __name__ == "__main__":
    root = Tk()
    app = WirelessManagerApp(root)
    root.mainloop()
