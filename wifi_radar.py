import math
import random
import socket
import struct
import subprocess
import threading
import time
import ipaddress
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

import pygame

try:
    from scapy.all import ARP, Ether, srp
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False


# -----------------------------
# Configuration
# -----------------------------
WIDTH, HEIGHT = 1400, 800
CENTER = (WIDTH // 2, HEIGHT // 2)
RADAR_RADIUS = 280
SCAN_INTERVAL = 2  # seconds
STALE_TIMEOUT = 10  # seconds
BACKGROUND = (2, 8, 5)
RADAR_GREEN = (0, 200, 100)
DIM_GREEN = (0, 80, 40)
SOFT_GREEN = (100, 220, 150)
BRIGHT_GREEN = (0, 255, 150)
WHITE = (240, 255, 240)
RED = (255, 80, 80)
YELLOW = (255, 200, 50)
BLUE = (100, 180, 255)

NETWORK_CIDR = "192.168.1.0/24"   # Change this to your LAN if needed
ROUTER_IP = "192.168.1.1"  # Your router's IP address

# Device type MAC prefixes (manufacturer OUI)
MAC_PREFIXES = {
    "apple": ("00:03:93", "00:05:02", "00:07:E9", "00:0A:95", "00:0D:93", "00:0F:B5", "00:11:24", "00:13:3B", "00:14:6C", "00:16:CB", "00:17:F2", "00:19:E3", "00:1A:A0", "00:1D:4F", "00:1E:52", "00:1F:5B", "00:21:82", "00:22:41", "00:23:6C", "00:24:36", "00:25:84", "00:26:B0", "00:27:10", "00:50:F4", "00:73:E0", "00:A0:DE", "00:BD:3B", "40:6C:8F", "50:EA:D6", "70:CD:60", "88:63:DF", "A4:D1:D2", "A8:5E:60", "AC:BC:32", "B0:34:95", "B8:27:EB", "D0:27:88", "D4:6E:0E", "D8:3A:DD", "DC:A9:04", "E0:AC:69", "E8:8D:28", "F4:CA:E5", "F8:FF:C2"),
    "samsung": ("00:07:AB", "00:0C:6E", "00:12:FB", "00:16:32", "00:19:C6", "00:1E:E1", "00:1F:72", "00:22:B0", "00:23:39", "00:26:37", "00:37:B6", "00:50:F2", "08:86:3B", "0C:4D:E9", "50:F5:DA", "98:52:B6", "D0:5F:B8"),
    "samsung_tv": ("00:12:FB", "00:1E:3D", "00:1F:72", "00:22:B0", "00:26:37", "1C:52:16", "50:F5:DA", "60:38:0E", "70:A8:D3"),
    "google": ("00:1A:11", "44:03:3C", "54:27:1E", "54:60:09"),
    "amazon": ("00:0A:95", "34:C3:FC", "44:65:0D", "50:F5:DA", "7C:83:34", "B0:A2:87", "D0:92:A2"),
    "windows": ("00:11:09", "00:15:17", "00:50:F2", "52:54:00"),
    "linux": ("00:16:3E", "08:00:27", "52:54:00"),
}


@dataclass
class Device:
    ip: str
    mac: str
    label: str
    angle: float = field(default_factory=lambda: random.uniform(0, 360))
    distance: float = field(default_factory=lambda: random.uniform(40, RADAR_RADIUS - 30))
    last_seen: float = field(default_factory=time.time)
    first_seen: float = field(default_factory=time.time)
    strength: int = field(default_factory=lambda: random.randint(40, 100))
    strength_history: list = field(default_factory=list)
    device_type: str = field(default="unknown")


devices = {}
devices_lock = threading.Lock()


def detect_device_type(mac: str) -> str:
    """Detect device type based on MAC address manufacturer"""
    mac_upper = mac.upper()
    
    for device_type, prefixes in MAC_PREFIXES.items():
        for prefix in prefixes:
            if mac_upper.startswith(prefix.upper()):
                return device_type
    
    # Guess by hostname patterns if type still unknown
    return "unknown"


def get_device_icon(device_type: str) -> str:
    """Get a symbol for the device type"""
    icons = {
        "apple": "🍎",
        "samsung": "📱", 
        "samsung_tv": "📺",
        "google": "🔵",
        "amazon": "🛒",
        "windows": "🪟",
        "linux": "🐧",
        "unknown": "⚙"
    }
    return icons.get(device_type, "⚙")


def get_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "Unknown"


def ping_host(ip: str, timeout_ms: int = 200) -> bool:
    """Best-effort ping used to populate ARP cache in Windows fallback mode."""
    try:
        result = subprocess.run(
            ["ping", "-n", "1", "-w", str(timeout_ms), ip],
            capture_output=True,
            text=True,
            timeout=2,
        )
        return result.returncode == 0
    except Exception:
        return False


def iter_network_hosts(cidr: str):
    """Return host IP strings from a CIDR, safely handling invalid input."""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return [str(ip) for ip in network.hosts()]
    except Exception:
        return []


def parse_windows_arp_table(output: str):
    """Parse arp -a output into candidate device dict."""
    candidates = {}
    for line in output.split("\n"):
        parts = line.split()
        if len(parts) >= 3 and "." in parts[0]:
            try:
                ip = parts[0]
                mac = parts[1]
                socket.inet_aton(ip)
                hostname = get_hostname(ip)
                label = hostname if hostname != "Unknown" else ip
                candidates[ip] = {
                    "ip": ip,
                    "mac": mac,
                    "label": label,
                }
            except Exception:
                continue
    return candidates


def warmup_arp_cache(cidr: str):
    """Trigger ARP population by pinging the local subnet in parallel."""
    hosts = iter_network_hosts(cidr)
    if not hosts:
        return

    # Limit worker count to keep CPU/network usage reasonable.
    max_workers = min(64, max(8, len(hosts) // 4))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        list(executor.map(ping_host, hosts))


def network_scan():
    """
    Scan the local network for connected devices.
    Uses ARP discovery via Scapy if available, otherwise uses Windows ARP cache.
    """
    global devices

    # First, try using arp -a to get connected devices on Windows
    def scan_with_windows_arp():
        try:
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=5)
            found = parse_windows_arp_table(result.stdout)

            # If ARP cache is sparse, probe subnet once and re-read ARP table.
            if len(found) < 3:
                warmup_arp_cache(NETWORK_CIDR)
                result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=5)
                found = parse_windows_arp_table(result.stdout)

            return found
        except Exception as e:
            print(f"Windows ARP scan error: {e}")
            return {}

    # Try Scapy first (requires Npcap)
    def scan_with_scapy():
        if not SCAPY_AVAILABLE:
            return None
        try:
            arp = ARP(pdst=NETWORK_CIDR)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp
            result = srp(packet, timeout=2, verbose=0)[0]

            found = {}
            for _, received in result:
                ip = received.psrc
                mac = received.hwsrc
                hostname = get_hostname(ip)
                label = hostname if hostname != "Unknown" else ip

                found[ip] = {
                    "ip": ip,
                    "mac": mac,
                    "label": label,
                }
            return found
        except Exception as e:
            print(f"Scapy scan error: {e}")
            return None

    while True:
        try:
            # Try Scapy first
            found = scan_with_scapy()
            
            # Fallback to Windows ARP if Scapy fails
            if found is None:
                found = scan_with_windows_arp()

            with devices_lock:
                now = time.time()

                for ip, info in found.items():
                    if ip in devices:
                        devices[ip].last_seen = now
                        devices[ip].strength = random.randint(55, 100)
                        devices[ip].strength_history.append(devices[ip].strength)
                        # Keep only last 60 measurements
                        if len(devices[ip].strength_history) > 60:
                            devices[ip].strength_history.pop(0)
                    else:
                        new_device = Device(
                            ip=info["ip"],
                            mac=info["mac"],
                            label=info["label"],
                            angle=random.uniform(0, 360),
                            distance=random.uniform(50, RADAR_RADIUS - 20),
                            last_seen=now,
                            first_seen=now,
                            strength=random.randint(50, 100),
                        )
                        new_device.device_type = detect_device_type(info["mac"])
                        new_device.strength_history = [new_device.strength]
                        devices[ip] = new_device

                # Remove devices not seen recently even when scan returns empty.
                stale_ips = []
                for ip, dev in devices.items():
                    if now - dev.last_seen > STALE_TIMEOUT:
                        stale_ips.append(ip)

                for ip in stale_ips:
                    del devices[ip]

        except Exception as e:
            print("Scan error:", e)

        time.sleep(SCAN_INTERVAL)


def polar_to_cartesian(angle_deg: float, radius: float):
    angle_rad = math.radians(angle_deg - 90)
    x = CENTER[0] + radius * math.cos(angle_rad)
    y = CENTER[1] + radius * math.sin(angle_rad)
    return int(x), int(y)


def draw_radar_background(screen, font_small):
    screen.fill(BACKGROUND)

    # Outer rings with gradient effect
    for r in [RADAR_RADIUS // 4, RADAR_RADIUS // 2, 3 * RADAR_RADIUS // 4, RADAR_RADIUS]:
        pygame.draw.circle(screen, DIM_GREEN, CENTER, r, 2)
        pygame.draw.circle(screen, DIM_GREEN, CENTER, r - 1, 1)

    # Cross lines
    pygame.draw.line(screen, DIM_GREEN, (CENTER[0] - RADAR_RADIUS, CENTER[1]),
                     (CENTER[0] + RADAR_RADIUS, CENTER[1]), 2)
    pygame.draw.line(screen, DIM_GREEN, (CENTER[0], CENTER[1] - RADAR_RADIUS),
                     (CENTER[0], CENTER[1] + RADAR_RADIUS), 2)

    # Angle spokes
    for angle in range(0, 360, 30):
        x, y = polar_to_cartesian(angle, RADAR_RADIUS)
        pygame.draw.line(screen, (0, 60, 30), CENTER, (x, y), 1)
        # Add angle labels
        label_x, label_y = polar_to_cartesian(angle, RADAR_RADIUS + 30)
        angle_text = font_small.render(f"{angle}°", True, (0, 100, 50))
        screen.blit(angle_text, (label_x - 10, label_y - 8))

    # Draw Router at Center with enhanced design
    router_radius = 20
    pygame.draw.circle(screen, BRIGHT_GREEN, CENTER, router_radius, 4)
    pygame.draw.circle(screen, (0, 150, 80), CENTER, router_radius - 3)
    pygame.draw.polygon(screen, BRIGHT_GREEN, 
                       [(CENTER[0], CENTER[1] - 8),
                        (CENTER[0] + 8, CENTER[1] + 4),
                        (CENTER[0], CENTER[1] + 2),
                        (CENTER[0] - 8, CENTER[1] + 4)])
    router_label = pygame.font.SysFont("consolas", 14, bold=True).render("ROUTER", True, BRIGHT_GREEN)
    screen.blit(router_label, (CENTER[0] - 30, CENTER[1] + router_radius + 8))

    # Labels
    title = pygame.font.SysFont("consolas", 32, bold=True).render("◉ Wi-Fi Radar Interface", True, RADAR_GREEN)
    screen.blit(title, (40, 20))

    subtitle = pygame.font.SysFont("consolas", 16).render("Real-time Network Topology Visualization", True, SOFT_GREEN)
    screen.blit(subtitle, (40, 60))

    # Side panel
    pygame.draw.rect(screen, (5, 25, 15), (900, 100, 480, 680), border_radius=12)
    pygame.draw.rect(screen, RADAR_GREEN, (900, 100, 480, 680), 2, border_radius=12)
    panel_title = pygame.font.SysFont("consolas", 24, bold=True).render("Connected Devices", True, RADAR_GREEN)
    screen.blit(panel_title, (920, 120))


def draw_sweep(screen, sweep_angle):
    """Draw sweep lines for a realistic radar effect"""
    for i in range(25):
        alpha_factor = max(0.0, 1.0 - i / 25.0)
        angle = sweep_angle - i * 1.5
        x, y = polar_to_cartesian(angle, RADAR_RADIUS)

        color = (
            int(100 * alpha_factor),
            int(255 * alpha_factor),
            int(150 * alpha_factor),
        )
        thickness = 3 if i == 0 else 1
        pygame.draw.line(screen, color, CENTER, (x, y), thickness)


def draw_devices(screen, font_small, search_text="", paused=False, panel_scroll=0):
    now = time.time()
    panel_top = 155
    panel_bottom = 740
    row_height = 100

    with devices_lock:
        sorted_devices = sorted(devices.values(), key=lambda d: d.ip)
        filtered_devices = []

        for dev in sorted_devices:
            # Filter by search text
            if search_text and search_text.lower() not in dev.label.lower() and search_text not in dev.ip:
                continue
            filtered_devices.append(dev)

        visible_rows = max(1, (panel_bottom - panel_top) // row_height)
        max_scroll = max(0, len(filtered_devices) - visible_rows)
        panel_scroll = max(0, min(panel_scroll, max_scroll))

        panel_y = panel_top
        shown = 0
        for dev in filtered_devices[panel_scroll:]:
            if shown >= visible_rows:
                break

            age = now - dev.last_seen
            fade = max(60, 255 - int(age * 20)) if not paused else 150
            color = (fade, 40, 40)

            x, y = polar_to_cartesian(dev.angle, dev.distance)

            # Draw connection line from device to router
            line_color = (int(fade * 0.7), 20, 20) if not paused else (100, 100, 100)
            pygame.draw.line(screen, line_color, CENTER, (x, y), 1)

            # Glow with device type icon position
            pygame.draw.circle(screen, color, (x, y), 10, 2)
            pygame.draw.circle(screen, color, (x, y), 6)
            pygame.draw.circle(screen, (min(255, int(fade * 0.9)), 20, 20), (x, y), 3)

            label = font_small.render(dev.label[:18], True, SOFT_GREEN)
            screen.blit(label, (x + 14, y - 12))

            # Side panel text - enhanced with stats
            uptime = now - dev.first_seen
            uptime_str = f"{int(uptime/60)}m" if uptime < 3600 else f"{int(uptime/3600)}h"
            avg_signal = int(sum(dev.strength_history) / len(dev.strength_history)) if dev.strength_history else dev.strength
            icon = get_device_icon(dev.device_type)

            line1 = font_small.render(f"{icon} {dev.label[:20]}", True, RADAR_GREEN)
            line2 = font_small.render(f"IP: {dev.ip}", True, SOFT_GREEN)
            line3 = font_small.render(f"Type: {dev.device_type.capitalize()}", True, BLUE)
            strength_color = (100, 255, 100) if dev.strength > 70 else (255, 220, 100) if dev.strength > 40 else (255, 100, 100)
            line4 = font_small.render(f"Signal: {dev.strength}% (avg: {avg_signal}%)", True, strength_color)
            line5 = font_small.render(f"Uptime: {uptime_str}", True, WHITE)

            screen.blit(line1, (920, panel_y))
            screen.blit(line2, (920, panel_y + 20))
            screen.blit(line3, (920, panel_y + 38))
            screen.blit(line4, (920, panel_y + 56))
            screen.blit(line5, (920, panel_y + 74))

            panel_y += row_height
            shown += 1

        # Panel status text (shows whether more devices exist above/below).
        status_text = font_small.render(
            f"Showing {panel_scroll + 1 if filtered_devices else 0}-{panel_scroll + shown} / {len(filtered_devices)}  (Wheel: scroll)",
            True,
            SOFT_GREEN,
        )
        screen.blit(status_text, (920, 755))

    return max_scroll


def main():
    pygame.init()
    screen = pygame.display.set_mode((WIDTH, HEIGHT))
    pygame.display.set_caption("Wi-Fi Radar - Network Monitor")
    clock = pygame.time.Clock()
    font_small = pygame.font.SysFont("consolas", 14)

    # Start scanner thread
    thread = threading.Thread(target=network_scan, daemon=True)
    thread.start()

    sweep_angle = 0
    running = True
    paused = False
    search_text = ""
    panel_scroll = 0
    max_scroll = 0

    while running:
        clock.tick(60)

        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                running = False
            elif event.type == pygame.KEYDOWN:
                if event.key == pygame.K_SPACE:
                    paused = not paused
                elif event.key == pygame.K_ESCAPE:
                    search_text = ""
                    panel_scroll = 0
                elif event.key == pygame.K_BACKSPACE:
                    search_text = search_text[:-1]
                    panel_scroll = 0
                elif event.key == pygame.K_DOWN:
                    panel_scroll = min(panel_scroll + 1, max_scroll)
                elif event.key == pygame.K_UP:
                    panel_scroll = max(panel_scroll - 1, 0)
                elif event.unicode.isprintable():
                    search_text += event.unicode
                    panel_scroll = 0
            elif event.type == pygame.MOUSEWHEEL:
                panel_scroll = max(0, min(panel_scroll - event.y, max_scroll))

        draw_radar_background(screen, font_small)
        if not paused:
            draw_sweep(screen, sweep_angle)
        max_scroll = draw_devices(screen, font_small, search_text, paused, panel_scroll)
        panel_scroll = min(panel_scroll, max_scroll)

        # Dynamic footer with device count
        with devices_lock:
            device_count = len(devices)
        
        status = "⏸ PAUSED" if paused else "● SCANNING"
        footer = font_small.render(
            f"Network: {NETWORK_CIDR} | Devices: {device_count} | Status: {status} | SPACE: Pause | ESC: Clear Search | ↑↓/Wheel: Scroll",
            True,
            SOFT_GREEN
        )
        screen.blit(footer, (40, HEIGHT - 30))
        
        # Search box
        search_label = font_small.render("Search: ", True, RADAR_GREEN)
        screen.blit(search_label, (40, HEIGHT - 55))
        search_box = font_small.render(search_text + "_", True, SOFT_GREEN)
        screen.blit(search_box, (130, HEIGHT - 55))

        pygame.display.flip()
        if not paused:
            sweep_angle = (sweep_angle + 1.2) % 360

    pygame.quit()


if __name__ == "__main__":
    main()