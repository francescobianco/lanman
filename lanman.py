#!/usr/bin/env python3
"""lanman - a tiny LAN manager.

Periodically ping-sweeps the local subnet, reads the kernel neighbour table
for MAC addresses, identifies each device (vendor, type, model) and shows
everything on a minimal web panel. Devices are keyed by MAC address, so the
identification cache survives DHCP address changes.

Stdlib only (Python >= 3.7). Usage:
    python3 lanman.py [--port 7780] [--iface eth0] [--interval 60]
"""
import argparse
import ipaddress
import json
import os
import re
import socket
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import identify

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("LANMAN_DATA", os.path.expanduser("~/.lanman"))
DB_FILE = os.path.join(DATA_DIR, "devices.json")
REPROBE_AFTER = 6 * 3600

lock = threading.Lock()
devices = {}  # key (mac, or "ip:<addr>") -> dict
state = {"iface": None, "network": None, "self_ip": None, "gateway": None,
         "last_scan": None, "scanning": False, "probing": False}
scan_now = threading.Event()
vendors = identify.Vendors(DATA_DIR)
LOCAL = identify.local_info()


# ---------------------------------------------------------------- network ---
def sh(*cmd):
    return subprocess.run(cmd, capture_output=True, text=True).stdout


def own_mac(iface):
    try:
        with open("/sys/class/net/%s/address" % iface) as f:
            return f.read().strip().lower() or None
    except OSError:
        return None


def detect_iface():
    """First default-route interface with a real MAC (skips tun/VPN links)."""
    devs = re.findall(r"\bdev (\S+)", sh("ip", "-4", "route", "show", "default"))
    for dev in devs:
        mac = own_mac(dev)
        if mac and mac != "00:00:00:00:00:00":
            return dev
    return devs[0] if devs else None


def own_ips(iface):
    return [ipaddress.ip_interface(a) for a in
            re.findall(r"inet (\S+)", sh("ip", "-4", "-o", "addr", "show", "dev", iface))]


def gateway(iface):
    m = re.search(r"default via (\S+)", sh("ip", "-4", "route", "show", "default", "dev", iface))
    return m.group(1) if m else None


def ping(ip):
    r = subprocess.run(["ping", "-c", "1", "-W", "1", "-n", "-q", ip],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return r.returncode == 0


def neighbours(iface):
    """ip -> mac for neighbours with a usable link-layer address."""
    out = {}
    for line in sh("ip", "-4", "neigh", "show", "dev", iface).splitlines():
        parts = line.split()
        if "lladdr" in parts and "FAILED" not in parts and "INCOMPLETE" not in parts:
            out[parts[0]] = parts[parts.index("lladdr") + 1].lower()
    return out


def resolve(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def ipn(ip):
    return int(ipaddress.ip_address(ip))


# ------------------------------------------------------------------- scan ---
def scan():
    iface, net = state["iface"], state["network"]
    state["scanning"] = True
    hosts = [str(h) for h in net.hosts()]
    with ThreadPoolExecutor(max_workers=64) as ex:
        alive = {ip for ip, ok in zip(hosts, ex.map(ping, hosts)) if ok}
    neigh = neighbours(iface)
    mymac = own_mac(iface)
    mine = [str(i.ip) for i in own_ips(iface) if i.ip in net]
    for ip in mine:
        neigh[ip] = mymac
    online = alive | set(neigh)
    ips = sorted(online, key=ipn)
    with ThreadPoolExecutor(max_workers=16) as ex:
        names = dict(zip(ips, ex.map(resolve, ips)))
    names.update({ip: socket.gethostname() for ip in mine})
    gw = state["gateway"]
    gw_mac = neigh.get(gw)

    # group addresses by device key
    groups = {}
    for ip in ips:
        mac = neigh.get(ip)
        via_router = bool(mac and gw_mac and mac == gw_mac and ip != gw)  # proxy-ARP (VPN clients)
        key = mac if mac and not via_router else "ip:" + ip
        groups.setdefault(key, {"ips": [], "mac": mac, "via_router": via_router})["ips"].append(ip)

    now = int(time.time())
    with lock:
        for key, g in groups.items():
            if g["mac"] and not g["via_router"]:
                for ip in g["ips"]:  # merge earlier MAC-less entries of this device
                    old = devices.pop("ip:" + ip, None)
                    if old and key not in devices:
                        devices[key] = old
            d = devices.setdefault(key, {"first_seen": now})
            prev = d.get("ip")
            d["ip"] = prev if prev in g["ips"] else g["ips"][0]
            d["ips"] = g["ips"]
            d["mac"] = g["mac"]
            d["via_router"] = g["via_router"]
            d["is_gateway"] = gw in g["ips"]
            d["is_self"] = bool(set(mine) & set(g["ips"]))
            if d["is_self"]:
                d.setdefault("probe", {})["local"] = LOCAL
            d["last_seen"] = now
            d["online"] = True
            d["ping"] = any(ip in alive for ip in g["ips"])
            host = next((names[ip] for ip in g["ips"] if names.get(ip) and names[ip] != "_gateway"), None)
            if host:
                d["hostname"] = host
        for key, d in devices.items():
            if key not in groups:
                d["online"] = False
                d["ping"] = False
        state["last_scan"] = now
        save()
    state["scanning"] = False


def probe():
    """Identify devices that are new, moved, stale or flagged for re-probe."""
    now = time.time()
    with lock:
        online = {d["ip"]: k for k, d in devices.items() if d.get("online")}
        need = [d["ip"] for d in devices.values() if d.get("online") and (
            not d.get("probed_at") or d.get("probed_ip") != d["ip"]
            or now - d["probed_at"] > REPROBE_AFTER or d.get("probe_version") != identify.PROBE_VERSION)]
    if not need:
        return
    state["probing"] = True
    print("probing %d device(s)" % len(need), flush=True)
    res = identify.probe(state["self_ip"], sorted(online, key=ipn), need)
    with lock:
        for ip, r in res.items():
            d = devices.get(online.get(ip))
            if not d:
                continue
            p = d.setdefault("probe", {})
            if ip in need:
                p.update(r)
                d["probed_at"] = int(now)
                d["probed_ip"] = ip
                d["probe_version"] = identify.PROBE_VERSION
            else:  # passive multicast answers from devices not being probed
                p.update({k: v for k, v in r.items() if v and k in ("mdns", "ssdp_server")})
        save()
    state["probing"] = False


def scanner(interval):
    while True:
        for step in (scan, probe):
            try:
                step()
            except Exception as e:  # keep the loop alive
                print("%s error: %r" % (step.__name__, e), flush=True)
            finally:
                state["scanning"] = state["probing"] = False
        scan_now.wait(interval)
        scan_now.clear()


# ---------------------------------------------------------------- storage ---
def load():
    try:
        with open(DB_FILE) as f:
            raw = json.load(f)
    except (OSError, ValueError):
        return
    for key, d in raw.items():
        if re.fullmatch(r"[\d.]+", key):  # v1 file keyed by IP
            d.setdefault("ip", key)
            key = d.get("mac") or "ip:" + key
            if key in devices:  # merge duplicates of the same MAC
                o = devices[key]
                o["first_seen"] = min(o.get("first_seen", 0), d.get("first_seen", 0))
                continue
        devices[key] = d


def save():
    os.makedirs(DATA_DIR, exist_ok=True)
    tmp = DB_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(devices, f, indent=1)
    os.replace(tmp, DB_FILE)


def public(key, d):
    out = {k: v for k, v in d.items() if k not in ("probe", "name", "type", "reprobe")}
    out["id"] = key
    vendor = None if d.get("via_router") else vendors.lookup(d.get("mac"))
    out.update(identify.classify(d, vendor))
    if d.get("via_router"):
        out["note"] = "raggiunto tramite il router (VPN / proxy-ARP)"
    p = d.get("probe") or {}
    m = p.get("mdns") or {}
    out["details"] = {
        "mdns_services": m.get("services") or [],
        "mdns_hostname": m.get("hostname"),
        "netbios": p.get("netbios"),
        "upnp": p.get("upnp"),
        "ssdp_server": p.get("ssdp_server"),
        "ports": p.get("ports"),
        "ssh": p.get("ssh"),
        "http": p.get("http"),
    }
    return out


# -------------------------------------------------------------------- web ---
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send(self, code, body, ctype="application/json"):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/":
            with open(os.path.join(HERE, "index.html"), "rb") as f:
                return self.send(200, f.read(), "text/html")
        if self.path == "/api/devices":
            with lock:
                payload = {
                    "iface": state["iface"],
                    "network": str(state["network"]),
                    "self_ip": state["self_ip"],
                    "last_scan": state["last_scan"],
                    "scanning": state["scanning"],
                    "probing": state["probing"],
                    "types": identify.TYPES,
                    "devices": [public(k, d) for k, d in devices.items()],
                }
            return self.send(200, json.dumps(payload))
        self.send(404, '{"error":"not found"}')

    def do_POST(self):
        if self.path == "/api/scan":
            scan_now.set()
            return self.send(202, '{"ok":true}')
        self.send(404, '{"error":"not found"}')


def main():
    ap = argparse.ArgumentParser(description="tiny LAN manager")
    ap.add_argument("--port", type=int, default=int(os.environ.get("LANMAN_PORT", 7780)))
    ap.add_argument("--bind", default=os.environ.get("LANMAN_BIND", "0.0.0.0"))
    ap.add_argument("--iface", default=os.environ.get("LANMAN_IFACE"))
    ap.add_argument("--interval", type=int, default=int(os.environ.get("LANMAN_INTERVAL", 60)))
    a = ap.parse_args()

    iface = a.iface or detect_iface()
    if not iface:
        raise SystemExit("cannot detect interface, use --iface")
    addrs = own_ips(iface)
    if not addrs:
        raise SystemExit("no IPv4 address on %s" % iface)
    net = addrs[0].network
    if net.num_addresses > 1024:  # don't sweep huge subnets
        net = ipaddress.ip_network("%s/22" % addrs[0].ip, strict=False)
    state.update(iface=iface, network=net, self_ip=str(addrs[0].ip), gateway=gateway(iface))

    load()
    vendors.load()
    threading.Thread(target=scanner, args=(a.interval,), daemon=True).start()
    print("lanman on http://%s:%d  (%s, %s, gw %s)" % (a.bind, a.port, iface, net, state["gateway"]), flush=True)
    ThreadingHTTPServer((a.bind, a.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
