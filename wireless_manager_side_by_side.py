import asyncio
import threading
import queue
import subprocess
import json
import traceback
from datetime import datetime
from tkinter import *
from tkinter import messagebox

# Bleak for BLE
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
        master.title("Wireless Manager (BLE + Wi-Fi)")

        self.asyncio_thread = AsyncioThread()
        self.ui_queue = queue.Queue()

        # BLE state
        self.ble_devices = []
        self.ble_client = None
        self.connected_address = None

        # Wi-Fi state
        self.wifi_networks = []

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
        Button(btn_frame, text="Scan BLE", command=lambda: self.ble_scan(5)).grid(row=0,column=0,padx=2)
        Button(btn_frame, text="Connect", command=self.ble_connect_selected).grid(row=0,column=1,padx=2)
        Button(btn_frame, text="Disconnect", command=self.ble_disconnect).grid(row=0,column=2,padx=2)
        Button(btn_frame, text="Save BLE report", command=self.ble_save_report).grid(row=0,column=3,padx=2)

    def update_ble_list(self, devices):
        self.ble_devices = devices
        self.ble_listbox.delete(0, END)
        for d in devices:
            name = d.name or "Unknown"
            self.ble_listbox.insert(END, f"{name} — {d.address} (RSSI: {d.rssi})")

    def ble_scan(self, timeout=5):
        self.ui_queue.put(("log", f"Scanning BLE for {timeout} seconds..."))
        self.asyncio_thread.submit_coro(self._ble_scan_coro(timeout))

    async def _ble_scan_coro(self, timeout):
        try:
            devices = await BleakScanner.discover(timeout=timeout)
            self.ui_queue.put(("ble_devices", devices))
            self.ui_queue.put(("log", f"Discovered {len(devices)} BLE device(s)."))
        except Exception:
            err = traceback.format_exc()
            self.ui_queue.put(("log", f"BLE scan error:\n{err}"))

    def ble_connect_selected(self):
        sel = self.ble_listbox.curselection()
        if not sel: 
            messagebox.showwarning("Select device", "Select a BLE device first")
            return
        addr = self.ble_devices[sel[0]].address
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
        except Exception:
            err = traceback.format_exc()
            self.ui_queue.put(("log", f"BLE connect error:\n{err}"))

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
        except Exception:
            err = traceback.format_exc()
            self.ui_queue.put(("log", f"BLE disconnect error:\n{err}"))

    def ble_save_report(self):
        if not self.ble_devices:
            self.log("No BLE devices to save")
            return
        fname = f"ble_scan_{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.json"
        data = [{"name": d.name,"address":d.address,"rssi":d.rssi} for d in self.ble_devices]
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
        Button(btn_frame, text="Scan Wi-Fi", command=self.wifi_scan).grid(row=0,column=0,padx=2)
        Button(btn_frame, text="Connect", command=self.wifi_connect_selected).grid(row=0,column=1,padx=2)
        Button(btn_frame, text="Disconnect", command=self.wifi_disconnect).grid(row=0,column=2,padx=2)
        Button(btn_frame, text="Save Wi-Fi report", command=self.wifi_save_report).grid(row=0,column=3,padx=2)

    def update_wifi_list(self, networks):
        self.wifi_networks = networks
        self.wifi_listbox.delete(0, END)
        for n in networks:
            self.wifi_listbox.insert(END, f"{n.get('SSID','')} (Signal: {n.get('Signal',0)}%) Auth:{n.get('Auth','')}")

    def wifi_scan(self):
        self.ui_queue.put(("log", "Scanning Wi-Fi networks..."))
        threading.Thread(target=self._wifi_scan_thread, daemon=True).start()

    def _wifi_scan_thread(self):
        try:
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
            self.ui_queue.put(("log", f"Discovered {len(networks)} Wi-Fi network(s)."))
        except Exception:
            err = traceback.format_exc()
            self.ui_queue.put(("log", f"Wi-Fi scan error:\n{err}"))

    def wifi_connect_selected(self):
        sel = self.wifi_listbox.curselection()
        if not sel:
            messagebox.showwarning("Select network", "Select a Wi-Fi network first")
            return
        ssid = self.wifi_networks[sel[0]]['SSID']
        password = None
        if "WPA" in self.wifi_networks[sel[0]]['Auth'] or "WEP" in self.wifi_networks[sel[0]]['Auth']:
            # Use non-blocking input dialog now:
            self.simple_input_async("Enter password for Wi-Fi", f"Password for {ssid}:", lambda pw: self._wifi_connect_with_password(ssid, pw))
        else:
            # No password needed
            threading.Thread(target=self._wifi_connect_thread, args=(ssid, None), daemon=True).start()

    def simple_input_async(self, title, prompt, callback):
        # Create dialog without blocking mainloop
        input_win = Toplevel()
        input_win.title(title)
        Label(input_win, text=prompt).pack(padx=10, pady=5)
        entry = Entry(input_win, show="*")
        entry.pack(padx=10, pady=5)

        def ok():
            pw = entry.get()
            input_win.destroy()
            callback(pw)

        Button(input_win, text="OK", command=ok).pack(pady=5)
        input_win.grab_set()
        entry.focus_set()

    def _wifi_connect_with_password(self, ssid, password):
        if not password:
            self.ui_queue.put(("log", "Wi-Fi password not entered, aborting connection"))
            return
        threading.Thread(target=self._wifi_connect_thread, args=(ssid,password), daemon=True).start()

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
    <MSM><security>
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
    </security></MSM>
</WLANProfile>
"""
                tmp_file = f"{ssid}.xml"
                with open(tmp_file,"w") as f:
                    f.write(profile_xml)
                subprocess.run(f'netsh wlan add profile filename="{tmp_file}"', shell=True)
            result = subprocess.run(f'netsh wlan connect name="{ssid}" ssid="{ssid}"', capture_output=True, text=True, shell=True)
            self.ui_queue.put(("log", f"Wi-Fi connect result: {result.stdout.strip()}"))
        except Exception:
            err = traceback.format_exc()
            self.ui_queue.put(("log", f"Wi-Fi connect error:\n{err}"))

    def wifi_disconnect(self):
        self.ui_queue.put(("log", "Disconnecting Wi-Fi..."))
        threading.Thread(target=self._wifi_disconnect_thread, daemon=True).start()

    def _wifi_disconnect_thread(self):
        try:
            result = subprocess.run("netsh wlan disconnect", capture_output=True, text=True, shell=True)
            self.ui_queue.put(("log", f"Wi-Fi disconnect result: {result.stdout.strip()}"))
        except Exception:
            err = traceback.format_exc()
            self.ui_queue.put(("log", f"Wi-Fi disconnect error:\n{err}"))

    def wifi_save_report(self):
        if not self.wifi_networks:
            self.log("No Wi-Fi networks to save")
            return
        fname = f"wifi_scan_{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.json"
        with open(fname,"w") as f:
            json.dump(self.wifi_networks,f,indent=2)
        self.log(f"Saved Wi-Fi scan report to {fname}")

# ----------------------------
# Main entry
# ----------------------------
def main():
    root = Tk()
    app = WirelessManagerApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()


# ----------------------------
# Run app
# ----------------------------
if __name__ == "__main__":
    root = Tk()
    app = WirelessManagerApp(root)
    root.mainloop()
