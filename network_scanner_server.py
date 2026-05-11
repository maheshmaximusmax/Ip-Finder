#!/usr/bin/env python3
"""
Network Device Scanner - Backend Server
Run: python3 network_scanner_server.py
Then open: http://localhost:8765 in your browser
"""

import http.server
import json
import socket
import subprocess
import struct
import threading
import time
import os
import sys
import re
import platform
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed

PORT = 8765
IS_WINDOWS = platform.system() == "Windows"

# ---------- OUI vendor lookup (common industrial / network vendors) ----------
OUI_DB = {
    # Industrial / PLC / HMI
    "00:1B:1E": ("Siemens", "plc"),
    "00:1C:06": ("Siemens", "plc"),
    "00:0E:8C": ("Siemens", "plc"),
    "00:1B:A9": ("Siemens", "plc"),
    "00:80:63": ("Schneider Electric", "plc"),
    "00:0B:AB": ("Schneider Electric", "plc"),
    "00:1D:9C": ("Schneider Electric", "plc"),
    "00:A0:45": ("Allen-Bradley / Rockwell", "plc"),
    "00:00:BC": ("Allen-Bradley / Rockwell", "plc"),
    "00:09:56": ("Rockwell Automation", "plc"),
    "00:1D:60": ("Beckhoff", "plc"),
    "00:01:05": ("Beckhoff", "plc"),
    "00:E0:7F": ("Omron", "plc"),
    "00:00:18": ("Omron", "plc"),
    "00:00:03": ("Mitsubishi Electric", "plc"),
    "00:00:4F": ("Mitsubishi Electric", "plc"),
    "00:21:6C": ("Delta Electronics", "plc"),
    "00:90:C2": ("Moxa", "gateway"),
    "00:90:E8": ("Moxa", "gateway"),
    # Cameras / NVR
    "00:40:48": ("Hikvision", "camera"),
    "44:19:B6": ("Hikvision", "camera"),
    "C0:56:E3": ("Hikvision", "camera"),
    "00:0F:EB": ("Hikvision", "camera"),
    "EC:71:DB": ("Dahua", "camera"),
    "90:02:A9": ("Dahua", "camera"),
    "3C:EF:8C": ("Dahua", "camera"),
    "00:12:12": ("Axis Communications", "camera"),
    "00:40:8C": ("Axis Communications", "camera"),
    "AC:CC:8E": ("Hanwha / Samsung", "camera"),
    "00:09:18": ("Hanwha / Samsung", "camera"),
    "00:13:E2": ("Vivotek", "camera"),
    "00:02:D1": ("Vivotek", "camera"),
    "E4:24:6C": ("Uniview", "nvr"),
    "00:24:1D": ("Avigilon", "camera"),
    # Routers / Switches / AP
    "00:1A:2B": ("Cisco", "router"),
    "00:0C:29": ("VMware (Virtual)", "server"),
    "00:50:56": ("VMware (Virtual)", "server"),
    "00:1E:BD": ("Cisco", "router"),
    "00:16:47": ("Cisco", "router"),
    "FC:FB:FB": ("Cisco", "router"),
    "00:18:F8": ("Huawei", "router"),
    "00:E0:FC": ("Huawei", "router"),
    "54:89:98": ("Huawei", "router"),
    "00:90:7F": ("WatchGuard", "router"),
    "B4:FB:E4": ("TP-Link", "router"),
    "50:C7:BF": ("TP-Link", "router"),
    "F4:EC:38": ("TP-Link", "router"),
    "B0:95:8E": ("Mikrotik", "router"),
    "00:0C:42": ("Mikrotik", "router"),
    "D4:CA:6D": ("Mikrotik", "router"),
    "B8:27:EB": ("Raspberry Pi", "iot"),
    "DC:A6:32": ("Raspberry Pi", "iot"),
    "E4:5F:01": ("Raspberry Pi", "iot"),
    "00:04:A3": ("MICROCHIP", "iot"),
    "00:1B:63": ("Apple", "workstation"),
    "3C:22:FB": ("Apple", "workstation"),
    "00:50:B6": ("Good Way Technology", "iot"),
}

DEVICE_ICONS = {
    "plc":         "⚙️",
    "hmi":         "🖥️",
    "camera":      "📷",
    "nvr":         "💾",
    "router":      "🌐",
    "gateway":     "🔀",
    "iot":         "📡",
    "workstation": "💻",
    "server":      "🖧",
    "unknown":     "❓",
}

# ---------- Helpers ----------

def get_local_ips():
    """Return list of (iface, ip, netmask) for all active interfaces."""
    results = []
    hostname = socket.gethostname()
    try:
        # Enumerate via socket
        addrs = socket.getaddrinfo(hostname, None)
        seen = set()
        for a in addrs:
            ip = a[4][0]
            if ip.startswith("127.") or ip.startswith("169.254") or ":" in ip:
                continue
            if ip not in seen:
                seen.add(ip)
                results.append({"iface": "auto", "ip": ip, "netmask": "255.255.255.0"})
    except Exception:
        pass

    # Try platform-specific for better info
    try:
        if IS_WINDOWS:
            out = subprocess.check_output(["ipconfig"], text=True, timeout=5)
            iface = "Unknown"
            for line in out.splitlines():
                line = line.strip()
                m = re.match(r"^(.+):$", line)
                if m:
                    iface = m.group(1).strip()
                m = re.search(r"IPv4 Address.*?:\s*([\d.]+)", line)
                if m:
                    ip = m.group(1)
                    if not ip.startswith("127.") and not ip.startswith("169.254"):
                        exists = any(r["ip"] == ip for r in results)
                        if not exists:
                            results.append({"iface": iface, "ip": ip, "netmask": "255.255.255.0"})
                m = re.search(r"Subnet Mask.*?:\s*([\d.]+)", line)
                if m and results:
                    results[-1]["netmask"] = m.group(1)
        else:
            # Linux / Mac
            try:
                out = subprocess.check_output(["ip", "addr"], text=True, timeout=5)
                iface = "Unknown"
                for line in out.splitlines():
                    m = re.match(r"^\d+:\s+(\S+):", line)
                    if m:
                        iface = m.group(1)
                    m = re.search(r"inet ([\d.]+)/([\d]+)", line)
                    if m:
                        ip = m.group(1)
                        prefix = int(m.group(2))
                        if ip.startswith("127.") or ip.startswith("169.254"):
                            continue
                        mask = prefix_to_mask(prefix)
                        exists = any(r["ip"] == ip for r in results)
                        if not exists:
                            results.append({"iface": iface, "ip": ip, "netmask": mask})
                        else:
                            for r in results:
                                if r["ip"] == ip:
                                    r["iface"] = iface
                                    r["netmask"] = mask
            except FileNotFoundError:
                pass  # ip command not found, use ifconfig
    except Exception:
        pass

    if not results:
        results.append({"iface": "lo", "ip": "127.0.0.1", "netmask": "255.255.255.0"})
    return results


def prefix_to_mask(prefix):
    mask = (0xFFFFFFFF >> (32 - prefix)) << (32 - prefix)
    return socket.inet_ntoa(struct.pack(">I", mask))


def ip_to_int(ip):
    return struct.unpack(">I", socket.inet_aton(ip))[0]


def int_to_ip(n):
    return socket.inet_ntoa(struct.pack(">I", n))


def get_subnet_ips(ip, netmask):
    """Return list of all host IPs in the subnet."""
    ip_int = ip_to_int(ip)
    mask_int = ip_to_int(netmask)
    network = ip_int & mask_int
    broadcast = network | (~mask_int & 0xFFFFFFFF)
    hosts = []
    for i in range(network + 1, broadcast):
        hosts.append(int_to_ip(i))
    return hosts


def ping(ip, timeout=1):
    """Return True if host responds to ping."""
    try:
        if IS_WINDOWS:
            cmd = ["ping", "-n", "1", "-w", str(timeout * 1000), ip]
        else:
            cmd = ["ping", "-c", "1", "-W", str(timeout), "-q", ip]
        result = subprocess.run(cmd, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=timeout + 1)
        return result.returncode == 0
    except Exception:
        return False


def tcp_probe(ip, ports=(80, 443, 102, 502, 44818, 9600, 4840, 554, 8080, 22, 23, 161)):
    """Try connecting to common industrial/camera ports. Return open ports."""
    open_ports = []
    for port in ports:
        try:
            with socket.create_connection((ip, port), timeout=0.5):
                open_ports.append(port)
        except Exception:
            pass
    return open_ports


PORT_SERVICE = {
    80: "HTTP", 443: "HTTPS", 22: "SSH", 23: "Telnet",
    102: "S7/Siemens", 502: "Modbus TCP", 44818: "EtherNet/IP",
    9600: "Omron FINS", 4840: "OPC-UA", 554: "RTSP/Camera",
    8080: "HTTP-Alt", 161: "SNMP", 8554: "RTSP-Alt",
    9100: "Printing", 21: "FTP", 3389: "RDP",
}

DEVICE_HINT_FROM_PORT = {
    102: ("plc", "Siemens S7 PLC"),
    502: ("plc", "Modbus Device (PLC/Drive)"),
    44818: ("plc", "EtherNet/IP (Allen-Bradley/Rockwell)"),
    9600: ("plc", "Omron PLC"),
    4840: ("plc", "OPC-UA Device"),
    554: ("camera", "IP Camera (RTSP)"),
    8554: ("camera", "IP Camera (RTSP)"),
    3389: ("workstation", "Windows RDP"),
}


def get_arp_table():
    """Parse system ARP table -> {ip: mac}"""
    arp_map = {}
    try:
        if IS_WINDOWS:
            out = subprocess.check_output(["arp", "-a"], text=True, timeout=5)
            for line in out.splitlines():
                m = re.search(r"([\d.]+)\s+([\w-]{17})", line)
                if m:
                    ip = m.group(1)
                    mac = m.group(2).replace("-", ":").upper()
                    arp_map[ip] = mac
        else:
            # Try /proc/net/arp first (Linux)
            try:
                with open("/proc/net/arp") as f:
                    for line in f.readlines()[1:]:
                        parts = line.split()
                        if len(parts) >= 4 and parts[2] != "0x0":
                            ip = parts[0]
                            mac = parts[3].upper()
                            if mac != "00:00:00:00:00:00":
                                arp_map[ip] = mac
            except Exception:
                pass
            # Fallback: arp -a
            try:
                out = subprocess.check_output(["arp", "-a"], text=True, timeout=5)
                for line in out.splitlines():
                    m = re.search(r"\(([\d.]+)\)\s+at\s+([\w:]{17})", line)
                    if m:
                        arp_map[m.group(1)] = m.group(2).upper()
            except Exception:
                pass
    except Exception:
        pass
    return arp_map


def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def lookup_vendor(mac):
    if not mac or mac == "Unknown":
        return ("Unknown Vendor", "unknown")
    prefix3 = ":".join(mac.split(":")[:3]).upper()
    if prefix3 in OUI_DB:
        return OUI_DB[prefix3]
    return ("Unknown Vendor", "unknown")


def guess_device_type(open_ports, vendor_type, hostname):
    # Port-based hint wins
    for port in open_ports:
        if port in DEVICE_HINT_FROM_PORT:
            return DEVICE_HINT_FROM_PORT[port]

    # Vendor-based
    if vendor_type and vendor_type != "unknown":
        type_labels = {
            "plc": "Programmable Logic Controller",
            "hmi": "Human Machine Interface",
            "camera": "IP Camera",
            "nvr": "Network Video Recorder",
            "router": "Router / Switch",
            "gateway": "Protocol Gateway",
            "iot": "IoT Device",
            "workstation": "Workstation / PC",
            "server": "Server",
        }
        return (vendor_type, type_labels.get(vendor_type, vendor_type.upper()))

    # Hostname hints
    if hostname:
        hn = hostname.lower()
        if any(k in hn for k in ["plc", "siemens", "beckhoff", "omron", "mitsubishi"]):
            return ("plc", "PLC (hostname hint)")
        if any(k in hn for k in ["cam", "camera", "nvr", "dvr", "hik", "dahua"]):
            return ("camera", "Camera/NVR (hostname hint)")
        if any(k in hn for k in ["router", "gw", "gateway", "switch", "cisco", "mikrotik"]):
            return ("router", "Router/Switch (hostname hint)")
        if any(k in hn for k in ["pi", "raspberr", "iot", "sensor"]):
            return ("iot", "IoT Device (hostname hint)")
        if any(k in hn for k in ["pc", "desktop", "laptop", "win", "ubuntu"]):
            return ("workstation", "Workstation (hostname hint)")

    return ("unknown", "Unknown Device")


def scan_ip(ip, arp_map):
    alive = ping(ip)
    if not alive:
        return None

    # Flush ARP and re-read after ping
    mac = arp_map.get(ip, "")
    if not mac:
        # Re-read ARP after ping so new entries appear
        fresh = get_arp_table()
        mac = fresh.get(ip, "Unknown")

    hostname = resolve_hostname(ip)
    open_ports = tcp_probe(ip)
    vendor_name, vendor_type = lookup_vendor(mac)
    device_type, device_label = guess_device_type(open_ports, vendor_type, hostname)

    port_services = [{"port": p, "service": PORT_SERVICE.get(p, f"Port {p}")} for p in open_ports]

    return {
        "ip": ip,
        "mac": mac if mac else "Unknown",
        "hostname": hostname if hostname else "",
        "vendor": vendor_name,
        "device_type": device_type,
        "device_label": device_label,
        "open_ports": port_services,
        "icon": DEVICE_ICONS.get(device_type, "❓"),
        "scanned_at": time.strftime("%H:%M:%S"),
    }


# ---------- HTTP API server ----------

scan_results = []
scan_progress = {"running": False, "done": 0, "total": 0, "phase": "idle"}


def run_scan(ip, netmask, max_threads=50):
    global scan_results, scan_progress
    scan_results = []
    ips = get_subnet_ips(ip, netmask)
    scan_progress = {"running": True, "done": 0, "total": len(ips), "phase": "pinging"}

    arp_map = get_arp_table()

    with ThreadPoolExecutor(max_workers=max_threads) as ex:
        futures = {ex.submit(scan_ip, i, arp_map): i for i in ips}
        for f in as_completed(futures):
            scan_progress["done"] += 1
            result = f.result()
            if result:
                scan_results.append(result)

    scan_progress["running"] = False
    scan_progress["phase"] = "done"


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # silence request logs

    def send_json(self, data, code=200):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_file(self, path, ctype):
        with open(path, "rb") as f:
            data = f.read()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)

        if path == "/" or path == "/index.html":
            html_path = os.path.join(os.path.dirname(__file__), "network_scanner_portal.html")
            if os.path.exists(html_path):
                self.send_file(html_path, "text/html")
            else:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"HTML file not found. Place network_scanner_portal.html in same folder.")

        elif path == "/api/interfaces":
            self.send_json(get_local_ips())

        elif path == "/api/scan":
            ip = qs.get("ip", [""])[0]
            netmask = qs.get("netmask", ["255.255.255.0"])[0]
            if not ip:
                self.send_json({"error": "ip required"}, 400)
                return
            if scan_progress["running"]:
                self.send_json({"error": "Scan already running"}, 409)
                return
            t = threading.Thread(target=run_scan, args=(ip, netmask), daemon=True)
            t.start()
            self.send_json({"status": "started"})

        elif path == "/api/progress":
            self.send_json({**scan_progress, "results": scan_results})

        elif path == "/api/arp":
            self.send_json(get_arp_table())

        else:
            self.send_response(404)
            self.end_headers()


if __name__ == "__main__":
    print(f"\n{'='*55}")
    print("  🌐  Network Device Scanner  –  Backend Ready")
    print(f"{'='*55}")
    print(f"  Open this URL in your browser:")
    print(f"  ➜  http://localhost:{PORT}")
    print(f"{'='*55}\n")
    server = http.server.HTTPServer(("0.0.0.0", PORT), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
