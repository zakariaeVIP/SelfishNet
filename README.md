# SelfishNet - Network Control Tool

![Python](https://img.shields.io/badge/Python-3.7%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)

SelfishNet is a network management tool designed for educational purposes to demonstrate ARP spoofing techniques and network monitoring. It provides a graphical interface to analyze and control devices on your local network.

**Disclaimer**: This tool should only be used on networks you own or have permission to test. Unauthorized use may be illegal.

## Features

- 📡 Network device discovery
- 🔒 ARP spoofing-based device blocking
- 🚦 Bandwidth throttling (experimental)
- 📊 Network monitoring
- 🔍 Basic security checks
- 🖥️ User-friendly GUI

## Installation

### Prerequisites
- Python 3.7+
- Root/admin privileges (for ARP operations)

### Dependencies
```bash
pip install kamene netifaces psutil
