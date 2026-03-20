# Wi-Fi Radar (Python + Pygame)

A desktop radar-style visualizer that shows devices connected to your local network.

## Features
- Real-time radar display of discovered devices
- Router-centered topology visualization
- Device list panel with scrolling
- Search/filter in UI
- Router controller panel with live router status
- Router reachability + latency monitor
- Manual network rescan trigger
- Quick open router admin page in browser
- Device export to CSV (`devices_export.csv`)
- Device join/leave activity notifications
- Windows fallback scanner using `arp -a` when low-level packet capture is unavailable

## Requirements
- Python 3.10+
- Packages:
  - `pygame`
  - `scapy`

Install packages:

```bash
pip install pygame scapy
```

## Run

```bash
python wifi_radar.py
```

## Optional: Better Device Discovery on Windows
For more complete LAN discovery, install **Npcap** (recommended for Scapy layer-2 scanning):
- https://npcap.com/download/

Without Npcap, the app uses ARP-cache based fallback discovery.

## Controls
- `Space`: Pause/Resume sweep
- `Esc`: Clear search
- `Backspace`: Delete search text
- `Up/Down`: Scroll device panel
- `Mouse Wheel`: Scroll device panel
- `R`: Open router admin page (`http://ROUTER_IP`)
- `P`: Ping router now and refresh router status
- `N`: Trigger manual network rescan
- `E`: Export discovered devices to CSV

## Project Structure
- `wifi_radar.py` - Main application

## Notes
- If your LAN subnet is different, update `NETWORK_CIDR` in `wifi_radar.py`.
- If your router address is different, update `ROUTER_IP` in `wifi_radar.py`.
- Some devices may hide from ping/ARP depending on firewall or power-saving behavior.

## CSV Export
Press `E` while the app is running to export the currently tracked devices to:

- `devices_export.csv`

Columns include timestamp, IP, MAC, label, device type, signal, first seen, and last seen.

## Troubleshooting (Windows)
- Install Npcap if Scapy discovery is incomplete.
  - Download: https://npcap.com/download/
  - During install, enabling WinPcap compatibility mode can help some environments.
- Run terminal/IDE as Administrator if packet capture appears blocked.
- Allow Python through Windows Defender Firewall for Private networks.
  - If discovery looks empty, temporarily disable firewall for a quick test, then re-enable and add proper allow rules.
- ARP fallback behavior:
  - Without Npcap, the app relies on `arp -a` cache entries.
  - Devices may not appear until they respond to traffic.
  - The app pings subnet hosts to warm ARP cache, but sleeping/mobile devices may still stay hidden.
- Verify network settings in code:
  - `NETWORK_CIDR` must match your LAN (example: `192.168.0.0/24`).
  - `ROUTER_IP` must match your router (example: `192.168.0.1`).
- Quick checks in PowerShell:

```powershell
arp -a
ping 192.168.1.1
```

- If router status stays Offline:
  - Confirm the router IP is correct.
  - Ensure ICMP/ping is not disabled on router settings.
  - Some routers block ping from Wi-Fi clients by default.

## Common Symptoms -> Likely Cause
| Symptom | Likely Cause |
|---|---|
| No devices appear in radar | Wrong `NETWORK_CIDR`, firewall blocking traffic, or empty ARP cache |
| Only a few devices appear | Running without Npcap (ARP fallback limits visibility) |
| Router status shows Offline | Wrong `ROUTER_IP` or router blocks ICMP/ping |
| Router ping works but no new devices | Client isolation on Wi-Fi or sleeping devices not responding |
| Device list updates slowly | `SCAN_INTERVAL` is high or subnet is large |
| Export file is empty | No active devices in memory at export time |
