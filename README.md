# Wi-Fi Radar (Python + Pygame)

A desktop radar-style visualizer that shows devices connected to your local network.

## Features
- Real-time radar display of discovered devices
- Router-centered topology visualization
- Device list panel with scrolling
- Search/filter in UI
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

## Project Structure
- `wifi_radar.py` - Main application

## Notes
- If your LAN subnet is different, update `NETWORK_CIDR` in `wifi_radar.py`.
- Some devices may hide from ping/ARP depending on firewall or power-saving behavior.
