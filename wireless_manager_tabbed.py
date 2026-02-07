import asyncio
import threading
import queue
import subprocess
import json
from datetime import datetime
from tkinter import *
from tkinter import messagebox, simpledialog
from bleak import BleakScanner, BleakClient

# Fix for Windows asyncio event loop policy
import sys
if sys.platform.startswith("win"):
    try:
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    except Exception:
        pass

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

class WirelessManagerApp:
    def __init__(self, root):
        self.root = root
        root.title("Wireless Manager (BLE + Wi-Fi)")

        self.asyncio_thread = AsyncioThread()
        self.ui_queue = queue.Queue()

        # BLE state
        self.ble_devices = []
        self.ble_client = None
        self.connected_address = None

        # Wi-Fi state
        self.wifi_networks = []

        # UI Setup
        self.setup_ui()

        # Periodic UI update from queue
        self.root.after(100, self.process_ui_queue)

    def setup_ui(self):
        main_frame = Frame(self.root)
        main_frame.pack(fill=BOTH, expand=True)

        # BLE panel
        ble_frame = Frame(main_frame)
        ble_frame.pack(side=LEFT, fill=BOTH, expand=True, padx=5, pady=5)

        Label(ble_frame, text="Bluetooth (BLE)").pack()
        self.ble_listbox = Listbox(ble_frame, width=50)
        self.ble_listbox.pack(fill=BOTH, expand=True, pady=5)

        ble_btn_frame = Frame(ble_frame)
        ble_btn_frame.pack()
        Button(ble_btn_frame, text="Scan BLE", command=self.ble_scan).grid(row=0, column=0, padx=3)
        Button(ble_btn_frame, text="Connect", command=self.ble_connect).grid(row=0, column=1, padx=3)
        Button(ble_btn_frame, text="Disconnect", command=self.ble_disconnect).grid(row=0, column=2, padx=3)
        Button(ble_btn_frame, text="Save BLE report", command=self.ble_save_report).grid(row=0, column=3, padx=3)

        self.ble_status = Label(ble_frame, text="No BLE devices found", fg="blue")
        self.ble_status.pack(pady=3)

        # Wi-Fi panel
        wifi_frame = Frame(main_frame)
        wifi_frame.pack(side=LEFT, fill=BOTH, expand=True, padx=5, pady=5)

        Label(wifi_frame, text="Wi-Fi Networks").pack()
        self.wifi_listbox = Listbox(wifi_frame, width=50)
        self.wifi_listbox.pack(fill=BOTH, expand=True, pady=5)

        wifi_btn_frame = Frame(wifi_frame)
        wifi_btn_frame.pack()
        Button(wifi_btn_frame, text="Scan Wi-Fi", command=self.wifi_scan).grid(row=0, column=0, padx=3)
        Button(wifi_btn_frame, text="Connect", command=self.wifi_connect).grid(row=0, column=1, padx=3)
        Button(wifi_btn_frame, text="Disconnect", command=self.wifi_disconnect).grid(row=0, column=2, padx=3)
        Button(wifi_btn_frame, text="Save Wi-Fi report", command=self.wifi_save_report).grid(row=0, column=3, padx=3)

        self.wifi_status = Label(wifi_frame, text="No Wi-Fi networks found", fg="blue")
        self.wifi_status.pack(pady=3)

        # Log panel
        self.log_text = Text(self.root, height=10)
        self.log_text.pack(fill=BOTH, padx=5, pady=5)

        Button(self.root, text="Save Log", command=self.save_log).pack(pady=3)

    # Logging helper
    def log(self, msg):
        ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        self.log_text.insert(END, f"[{ts}] {msg}\n")
        self.log_text.see(END)

    def save_log(self):
        fname = f"wireless_log_{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.txt"
        with open(fname, "w", encoding="utf-8") as f:
            f.write(self.log_text.get("1.0", END))
        self.log(f"Log saved to {fname}")

    # UI queue processing
    def process_ui_queue(self):
        try:
            while True:
                item = self.ui_queue.get_nowait()
                if not item:
                    continue
                cmd, data = item
                if cmd == "log":
                    self.log(data)
                elif cmd == "ble_update":
                    self.update_ble_list(data)
                elif cmd == "wifi_update":
                    self.update_wifi_list(data)
        except queue.Empty:
            pass
        self.root.after(100, self.process_ui_queue)

    # --- BLE functions ---
    def update_ble_list(self, devices):
        self.ble_devices = devices
        self.ble_listbox.delete(0, END)
        for d in devices:
            name = d.name or "Unknown"
            addr = d.address or "No Address"
            rssi = getattr(d, 'rssi', "N/A")
            self.ble_listbox.insert(END, f"{name} ({addr}) RSSI: {rssi}")
        self.ble_status.config(text=f"Found {len(devices)} device(s)")

    def ble_scan(self):
        self.ble_status.config(text="Scanning BLE devices...")
        self.ui_queue.put(("log", "Starting BLE scan (5 sec)..."))
        self.asyncio_thread.submit_coro(self._ble_scan())

    async def _ble_scan(self):
        try:
            devices = await BleakScanner.discover(timeout=5.0)
            self.ui_queue.put(("ble_update", devices))
            self.ui_queue.put(("log", f"Discovered {len(devices)} BLE device(s)."))
        except Exception as e:
            self.ui_queue.put(("log", f"BLE scan error: {e}"))
            self.ui_queue.put(("ble_update", []))

    def ble_connect(self):
        sel = self.ble_listbox.curselection()
        if not sel:
            messagebox.showwarning("Select device", "Please select a BLE device to connect.")
            return
        device = self.ble_devices[sel[0]]
        self.ui_queue.put(("log", f"Connecting to BLE device {device.address}..."))
        self.asyncio_thread.submit_coro(self._ble_connect(device.address))

    async def _ble_connect(self, address):
        try:
            if self.ble_client and self.ble_client.is_connected:
                self.ui_queue.put(("log", "Already connected. Disconnect first."))
                return
            client = BleakClient(address)
            await client.connect()
            self.ble_client = client
            self.connected_address = address
            self.ui_queue.put(("log", f"Connected to BLE device {address}"))
        except Exception as e:
            self.ui_queue.put(("log", f"BLE connect error: {e}"))

    def ble_disconnect(self):
        if not self.ble_client:
            self.log("No BLE device connected")
            return
        self.ui_queue.put(("log", "Disconnecting BLE device..."))
        self.asyncio_thread.submit_coro(self._ble_disconnect())

    async def _ble_disconnect(self):
        try:
            await self.ble_client.disconnect()
            self.ui_queue.put(("log", "BLE device disconnected"))
            self.ble_client = None
            self.connected_address = None
        except Exception as e:
            self.ui_queue.put(("log", f"BLE disconnect error: {e}"))

    def ble_save_report(self):
        if not self.ble_devices:
            self.log("No BLE devices to save")
            return
        fname = f"ble_scan_{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.json"
        data = [{"name": d.name, "address": d.address, "rssi": getattr(d, "rssi", None)} for d in self.ble_devices]
        with open(fname, "w") as f:
            json.dump(data, f, indent=2)
        self.log(f"BLE scan report saved to {fname}")

    # --- Wi-Fi functions ---
    def update_wifi_list(self, networks):
        self.wifi_networks = networks
        self.wifi_listbox.delete(0, END)
        for n in networks:
            ssid = n.get("SSID", "")
            signal = n.get("Signal", 0)
            auth = n.get("Auth", "Unknown")
            self.wifi_listbox.insert(END, f"{ssid} (Signal: {signal}%) Auth: {auth}")
        self.wifi_status.config(text=f"Found {len(networks)} Wi-Fi network(s)")

    def wifi_scan(self):
        self.wifi_status.config(text="Scanning Wi-Fi networks...")
        self.ui_queue.put(("log", "Scanning Wi-Fi networks..."))
        threading.Thread(target=self._wifi_scan_thread, daemon=True).start()

    def _wifi_scan_thread(self):
        try:
            result = subprocess.run("netsh wlan show networks mode=bssid", capture_output=True, text=True, shell=True)
            output = result.stdout
            networks = []
            current = {}
            for line in output.splitlines():
                line = line.strip()
                if line.startswith("SSID "):
                    if current:
                        networks.append(current)
                    current = {"SSID": line.split(":", 1)[1].strip()}
                elif line.startswith("Signal") and current:
                    current["Signal"] = int(line.split(":", 1)[1].strip().replace("%", ""))
                elif line.startswith("Authentication") and current:
                    current["Auth"] = line.split(":", 1)[1].strip()
            if current:
                networks.append(current)
            self.ui_queue.put(("wifi_update", networks))
            self.ui_queue.put(("log", f"Discovered {len(networks)} Wi-Fi network(s)."))
        except Exception as e:
            self.ui_queue.put(("log", f"Wi-Fi scan error: {e}"))
            self.ui_queue.put(("wifi_update", []))

    def wifi_connect(self):
        sel = self.wifi_listbox.curselection()
        if not sel:
            messagebox.showwarning("Select network", "Please select a Wi-Fi network to connect.")
            return
        network = self.wifi_networks[sel[0]]
        ssid = network.get("SSID")
        auth = network.get("Auth", "")

        password = None
        if "WPA" in auth or "WEP" in auth:
            password = simpledialog.askstring("Wi-Fi Password", f"Enter password for {ssid}:", show='*')
            if password is None:
                self.log("Wi-Fi connect cancelled by user")
                return

        threading.Thread(target=self._wifi_connect_thread, args=(ssid, password), daemon=True).start()

    def _wifi_connect_thread(self, ssid, password):
        try:
            if password:
                profile_xml = f"""
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>{ssid}</name>
    <SSIDConfig>
        <SSID><name>{ssid}</name></SSID>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>auto</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                <authentication>WPA2PSK</authentication>
                <encryption>AES</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
            <sharedKey>
                <keyType>passPhrase</keyType>
                <protected>false</protected>
                <keyMaterial>{password}</keyMaterial>
            </sharedKey>
        </security>
    </MSM>
</WLANProfile>
"""
                filename = f"{ssid}.xml"
                with open(filename, "w") as f:
                    f.write(profile_xml)
                subprocess.run(f'netsh wlan add profile filename="{filename}"', shell=True)
            result = subprocess.run(f'netsh wlan connect name="{ssid}" ssid="{ssid}"', capture_output=True, text=True, shell=True)
            self.ui_queue.put(("log", result.stdout.strip()))
        except Exception as e:
            self.ui_queue.put(("log", f"Wi-Fi connect error: {e}"))

    def wifi_disconnect(self):
        try:
            result = subprocess.run("netsh wlan disconnect", capture_output=True, text=True, shell=True)
            self.ui_queue.put(("log", result.stdout.strip()))
        except Exception as e:
            self.ui_queue.put(("log", f"Wi-Fi disconnect error: {e}"))

    def wifi_save_report(self):
        if not self.wifi_networks:
            self.log("No Wi-Fi networks to save")
            return
        fname = f"wifi_scan_{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.json"
        with open(fname, "w") as f:
            json.dump(self.wifi_networks, f, indent=2)
        self.log(f"Wi-Fi scan report saved to {fname}")

if __name__ == "__main__":
    root = Tk()
    app = WirelessManagerApp(root)
    root.mainloop()
