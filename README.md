# SelfishNet Pro Max ULTIMATE – Network Control Tool

![Python](https://img.shields.io/badge/Python-3.14%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Platform](https://img.shields.io/badge/Platform-Windows%2011%20x64-0078d7)

**Enterprise‑grade network controller** with real‑time per‑device traffic monitoring, vendor lookup, ARP spoofing, bandwidth graphs, and persistence.

> **Disclaimer**  
> This tool is for **educational purposes** and for testing networks you own or have explicit permission to audit. Unauthorised ARP spoofing or traffic interception may violate laws. Use at your own risk.

---

## ✨ Features

- 📡 **Automatic device discovery** – scans your local network and identifies IP, MAC, hostname and vendor (OUI).
- 🔒 **One‑click device blocking** – uses ARP spoofing to isolate any device (except the gateway).
- 🚦 **Bandwidth throttling** (visual) – mark devices with a speed limit (real enforcement requires WFP, but the label is shown).
- 📊 **Live traffic graphs** – per‑device upload/download rates (requires `matplotlib`).
- 📈 **System monitoring** – total upload/download speed and event logging.
- 🖧 **Wi‑Fi & Ethernet support** – choose the correct interface from a dropdown; works with Npcap 802.11 mode.
- 💾 **Persistence** – blocked and throttled devices are saved and restored on restart.
- 🎨 **Dark theme GUI** – clear, professional interface.
- 📤 **Export logs** – save the event log to a text file.

---

## 🛠️ Installation

### 1. Install Python 3.14 or newer
- Download from [python.org](https://python.org/downloads/)
- **Check** ✅ *“Add Python to PATH”*

### 2. Install Npcap (REQUIRED)
- Download from [npcap.com](https://npcap.com)
- During installation **tick**:
  - ✅ *“Install in WinPcap API‑compatible Mode”*
  - ✅ *“Support 802.11 (Wi‑Fi) radio capture”* (if you use Wi‑Fi)

### 3. Install Python dependencies
Open **PowerShell as Administrator** and run:

```powershell
pip install scapy psutil matplotlib requests
