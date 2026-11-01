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

import freebox
import identify
import notify

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("LANMAN_DATA", os.path.expanduser("~/.lanman"))
DB_FILE = os.path.join(DATA_DIR, "devices.json")
REPROBE_AFTER = 6 * 3600

lock = threading.Lock()
devices = {}  # key (mac, or "ip:<addr>") -> dict
state = {"iface": None, "network": None, "self_ip": None, "gateway": None, "host_wired": False,
         "router_api": None,
         "last_scan": None, "scanning": False, "probing": False}
scan_now = threading.Event()
vendors = identify.Vendors(DATA_DIR)
fbx = freebox.Client(os.path.join(DATA_DIR, "freebox.json"))
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


FRESH_NEIGH = {"REACHABLE", "DELAY", "PROBE", "PERMANENT"}


def neighbours(iface):
    """-> (ip -> mac for every neighbour with a link-layer address,
           set of ips whose entry was confirmed recently).
    STALE entries linger long after a device has left: good for MAC lookup only."""
    macs, fresh = {}, set()
    for line in sh("ip", "-4", "neigh", "show", "dev", iface).splitlines():
        parts = line.split()
        if "lladdr" in parts and "FAILED" not in parts and "INCOMPLETE" not in parts:
            macs[parts[0]] = parts[parts.index("lladdr") + 1].lower()
            if FRESH_NEIGH & set(parts):
                fresh.add(parts[0])
    return macs, fresh


def resolve(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def ipn(ip):
    return int(ipaddress.ip_address(ip))


# ------------------------------------------------------------------- scan ---
ONLINE_GRACE = 300  # a device stays online this long after any layer last saw it
LAYERS = ("ping", "arp", "dhcp", "router", "mdns", "ssdp")
passive = {}  # ip -> {"mdns": ts, "ssdp": ts}, filled by probe()


def scan():
    """Overlay several discovery layers by IP, then fold IPs into devices by MAC."""
    iface, net = state["iface"], state["network"]
    state["scanning"] = True
    now = int(time.time())
    hosts = [str(h) for h in net.hosts()]
    with ThreadPoolExecutor(max_workers=64) as ex:
        alive = {ip for ip, ok in zip(hosts, ex.map(ping, hosts)) if ok}
    neigh, fresh = neighbours(iface)
    mymac = own_mac(iface)
    mine = [str(i.ip) for i in own_ips(iface) if i.ip in net]
    gw = state["gateway"]
    rhosts = None
    if gw and (state["router_api"] is None or state["router_api"] is True or time.time() - state["router_api"] > 600):
        rhosts = fbx.hosts(gw)  # paired Iliadbox / Freebox
        if rhosts is None:
            rhosts = identify.router_hosts(gw)  # FRITZ!Box; retry unsupported routers every 10 min
        state["router_api"] = True if rhosts is not None else time.time()

    # --- layers: ip -> set of layers that saw it in this round; ip -> mac when known
    seen, macs = {}, {}

    def saw(ip, layer, mac=None):
        try:
            if ipaddress.ip_address(ip) not in net:
                return
        except ValueError:
            return
        seen.setdefault(ip, set()).add(layer)
        if mac:
            macs.setdefault(ip, mac)

    for ip in alive:
        saw(ip, "ping")
    for ip, mac in neigh.items():
        if ip in fresh:
            saw(ip, "arp", mac)
        else:
            macs.setdefault(ip, mac)  # MAC still useful to fold other layers' sightings
    for ip in mine:
        saw(ip, "arp", mymac)
    for key, r in (rhosts or {}).items():
        if r.get("active") and r.get("ip"):
            saw(r["ip"], "router", None if key.startswith("ip:") else key)
    with lock:
        for mac, info in dhcp_seen.items():
            if info.get("requested_ip") and now - info.get("seen", 0) < ONLINE_GRACE:
                saw(info["requested_ip"], "dhcp", mac)
    for ip, layers in passive.items():
        for layer, ts in layers.items():
            if now - ts < ONLINE_GRACE:
                saw(ip, layer)

    ips = sorted(seen, key=ipn)
    names = identify.reverse_dns(gw, ips) if gw else {}  # gateway DNS knows DHCP names
    missing = [ip for ip in ips if ip not in names]
    with ThreadPoolExecutor(max_workers=16) as ex:
        names.update({ip: n for ip, n in zip(missing, ex.map(resolve, missing)) if n})
    names.update({ip: socket.gethostname() for ip in mine})
    gw_mac = macs.get(gw)

    # group addresses by device key
    groups = {}
    for ip in ips:
        mac = macs.get(ip)
        via_router = bool(mac and gw_mac and mac == gw_mac and ip != gw)  # proxy-ARP (VPN clients)
        key = mac if mac and not via_router else "ip:" + ip
        g = groups.setdefault(key, {"ips": [], "mac": mac, "via_router": via_router, "layers": set()})
        g["ips"].append(ip)
        g["layers"] |= seen[ip]
    # a DNS name claimed by several devices is a stale/confused lease (e.g. behind MAC-NAT extenders)
    owners = {}
    for key, g in groups.items():
        for ip in g["ips"]:
            if names.get(ip):
                owners.setdefault(names[ip].lower(), set()).add(key)
    ambiguous = {n for n, ks in owners.items() if len(ks) > 1}

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
            d["ping"] = any(ip in alive for ip in g["ips"])
            sb = d.setdefault("seen_by", {})
            for layer in g["layers"]:
                sb[layer] = now
            if key in dhcp_seen:
                d["dhcp"] = dhcp_seen[key]
            if rhosts is not None:
                rh = rhosts.get(key) or (rhosts.get("ip:" + d["ip"]) if g["via_router"] else None)
                if rh:
                    d["router"] = rh
                else:
                    d.pop("router", None)
            if any((names.get(ip) or "").lower() in ambiguous for ip in g["ips"]):
                # the gateway gives this IP a name shared with others: its DNS is unreliable here
                # (typically clients of a MAC-NAT range extender) -> drop DNS names for a day
                d["dns_shared"] = now
                d.pop("hostname", None)
            elif now - d.get("dns_shared", 0) > 86400:
                host = next((names[ip] for ip in g["ips"] if names.get(ip) and names[ip] != "_gateway"), None)
                if host:
                    d["hostname"] = host
        for key, d in devices.items():
            d["present"] = key in groups  # seen in this round
            if not d["present"]:
                d["ping"] = False
            d["online"] = now - d.get("last_seen", 0) < ONLINE_GRACE  # present, or in standby
        state["last_scan"] = now
        save()
    state["scanning"] = False


def probe():
    """Identify devices that are new, moved, stale or flagged for re-probe."""
    now = time.time()
    with lock:
        online = {ip: k for k, d in devices.items() if d.get("online") for ip in d.get("ips") or [d["ip"]]}
        need = [d["ip"] for d in devices.values()
                if d.get("last_seen", 0) >= (state["last_scan"] or 0) and (
            not d.get("probed_at") or d.get("probed_ip") != d["ip"]
            or now - d["probed_at"] > REPROBE_AFTER or d.get("probe_version") != identify.PROBE_VERSION)]
    if not need:
        return
    state["probing"] = True
    print("probing %d device(s)" % len(need), flush=True)
    res = identify.probe(state["self_ip"], sorted(online, key=ipn), need, measure_rtt=state["host_wired"])
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
            if r.get("mdns"):
                passive.setdefault(ip, {})["mdns"] = int(now)
            if r.get("ssdp_server") or r.get("upnp"):
                passive.setdefault(ip, {})["ssdp"] = int(now)
        save()
    state["probing"] = False


# ------------------------------------------------------------------- DHCP ---
dhcp_seen = {}  # mac -> {"hostname", "vendor_class", "seen"}; merged into devices by scan()


def dhcp_listener():
    """Passively read DHCP requests broadcast by clients joining the network:
    they carry the device name (option 12) and vendor class (option 60).
    Needs port 67 (CAP_NET_BIND_SERVICE); silently disabled otherwise."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    try:
        s.bind(("0.0.0.0", 67))
    except OSError as e:
        state["dhcp"] = False
        print("dhcp listener disabled: %s (needs CAP_NET_BIND_SERVICE)" % e, flush=True)
        return
    state["dhcp"] = True
    print("dhcp listener on :67", flush=True)
    while True:
        try:
            data, _ = s.recvfrom(4096)
            info = identify.parse_dhcp(data)
        except Exception:
            continue
        if info:
            mac = info.pop("mac")
            info["seen"] = int(time.time())
            with lock:
                prev = dhcp_seen.get(mac) or (devices.get(mac) or {}).get("dhcp") or {}
                merged = dict(prev, **{k: v for k, v in info.items() if v})
                dhcp_seen[mac] = merged
                if mac in devices:
                    devices[mac]["dhcp"] = merged
            print("dhcp: %s %s" % (mac, merged), flush=True)


# ----------------------------------------------------------------- events ---
NOTIFY_OFFLINE_AFTER = 900  # silence needed before an "offline" notification (sleeping phones)


def events():
    """Notify (ntfy) new devices and online/offline changes.

    d["notified"] keeps the last state that was announced, so restarts don't
    repeat notifications. Runs after probe() so new devices carry brand/model."""
    url = notify.target(DATA_DIR)
    now = time.time()
    out = []
    with lock:
        quiet = state.pop("quiet_events", False)  # fresh install: learn the network silently
        for key, d in devices.items():
            prev = d.get("notified")
            if d.get("present"):
                cur = "online"
            elif now - d.get("last_seen", 0) > NOTIFY_OFFLINE_AFTER:
                cur = "offline"
            else:
                cur = prev or "online"
            if prev == cur:
                continue
            d["notified"] = cur
            if quiet or not url:
                continue
            if prev is None and not d.get("probed_at") and d.get("present"):
                d.pop("notified")  # wait for identification before announcing it
                continue
            pub = public(key, d)
            # privacy: channels may be read by others -> no user-chosen names (they often contain
            # people's names) and no MAC; describe the device by type/brand/model and IP suffix
            what = " ".join(x for x in (pub.get("brand"), pub.get("model")) if x) or \
                identify.TYPE_NOUNS[pub["type"]].capitalize()
            name = "%s (.%s)" % (what, pub["ip"].rsplit(".", 1)[-1])
            typ = dict(identify.TYPES).get(pub["type"], pub["type"])
            link = {"wifi": "Wi-Fi", "wired": "cavo", "vpn": "VPN"}.get(pub.get("link"))
            info = " · ".join(x for x in (typ, link) if x)
            if prev is None:
                out.append(("Nuovo dispositivo: %s" % name, info, "new"))
            elif cur == "online":
                out.append(("%s è online" % name, info, "green_circle"))
            else:
                out.append(("%s è offline" % name, "%s · ultimo avvistamento %s" % (
                    info, time.strftime("%H:%M", time.localtime(d["last_seen"]))), "red_circle"))
        if out or quiet:
            save()
    for title, message, tags in out:
        print("notify: %s" % title, flush=True)
        notify.send(url, title, message, tags)


def scanner(interval):
    while True:
        for step in (scan, probe, events):
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
        # devices known before notifications existed: don't announce them as new
        d.setdefault("notified", "online" if d.get("online") else "offline")
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
    out = {k: v for k, v in d.items() if k not in ("probe", "name", "type", "reprobe", "router")}
    out["dhcp_listener"] = state.get("dhcp")
    out["router_name"] = (d.get("router") or {}).get("name")
    out["id"] = key
    vendor = None if d.get("via_router") else vendors.lookup(d.get("mac"))
    out.update(identify.classify(d, vendor))
    out["link"], out["link_source"] = identify.link_guess(d, out["type"], vendor, state["host_wired"], out.get("model"))
    if d.get("dns_shared") and time.time() - d["dns_shared"] < 86400 and not d.get("is_gateway"):
        out["note"] = ("il DNS del router dà a questo IP un nome condiviso con altri dispositivi: "
                       "probabilmente è collegato tramite un range extender (nomi DNS ignorati)")
    if d.get("via_router"):
        out["note"] = "il router risponde per suo conto (proxy-ARP): MAC e produttore sono quelli del router"
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
        "device_info": p.get("device_info"),
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
                    "ntfy": notify.target(DATA_DIR),
                    "devices": [public(k, d) for k, d in devices.items()],
                }
            return self.send(200, json.dumps(payload))
        self.send(404, '{"error":"not found"}')

    def do_POST(self):
        if self.path == "/api/scan":
            if state["scanning"] or state["probing"] or scan_now.is_set():
                return self.send(409, '{"ok":false,"busy":true}')
            scan_now.set()
            return self.send(202, '{"ok":true}')
        self.send(404, '{"error":"not found"}')


def main():
    ap = argparse.ArgumentParser(description="tiny LAN manager")
    ap.add_argument("--port", type=int, default=int(os.environ.get("LANMAN_PORT", 7780)))
    ap.add_argument("--bind", default=os.environ.get("LANMAN_BIND", "0.0.0.0"))
    ap.add_argument("--iface", default=os.environ.get("LANMAN_IFACE"))
    ap.add_argument("--pair", action="store_true",
                    help="associa lanman al router (Iliadbox/Freebox): richiede conferma sul box")
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
    wireless = os.path.exists("/sys/class/net/%s/wireless" % iface) or os.path.exists("/sys/class/net/%s/phy80211" % iface)
    state.update(iface=iface, network=net, self_ip=str(addrs[0].ip), gateway=gateway(iface), host_wired=not wireless)
    LOCAL["link"] = "wifi" if wireless else "wired"

    if a.pair:
        raise SystemExit(0 if freebox.pair(state["gateway"], fbx.path) else 1)
    load()
    if not devices:
        state["quiet_events"] = True  # first run: don't announce the whole network
    vendors.load()
    threading.Thread(target=dhcp_listener, daemon=True).start()
    threading.Thread(target=scanner, args=(a.interval,), daemon=True).start()
    print("lanman on http://%s:%d  (%s, %s, gw %s, ntfy %s)" % (
        a.bind, a.port, iface, net, state["gateway"], notify.target(DATA_DIR) or "off"), flush=True)
    ThreadingHTTPServer((a.bind, a.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
