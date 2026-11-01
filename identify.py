"""Device identification for lanman.

- MAC vendor lookup (Wireshark manuf database, cached locally)
- network probes: mDNS/DNS-SD, SSDP/UPnP, NetBIOS, TCP ports, HTTP banner
- rule based classification into a device type, brand and model

Stdlib only, Python >= 3.7.
"""
import html
import http.client
import os
import re
import socket
import ssl
import struct
import subprocess
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

import freebox

# ------------------------------------------------------------ device types --
TYPES = [
    ("router", "Router e rete"),
    ("vpn", "Connessi in VPN"),
    ("server", "Server e NAS"),
    ("computer", "Computer"),
    ("mobile", "Smartphone e tablet"),
    ("media", "TV e multimedia"),
    ("printer", "Stampanti"),
    ("camera", "Telecamere"),
    ("iot", "Domotica e IoT"),
    ("console", "Console"),
    ("unknown", "Sconosciuti"),
]
TYPE_KEYS = [k for k, _ in TYPES]
PROBE_VERSION = 6  # bump when probes change: cached devices get re-identified
TYPE_NOUNS = {
    "router": "router", "vpn": "client VPN", "server": "server", "computer": "computer", "mobile": "smartphone/tablet",
    "media": "dispositivo multimediale", "printer": "stampante", "camera": "telecamera",
    "iot": "dispositivo smart", "console": "console", "unknown": "dispositivo",
}


def is_random_mac(mac):
    return bool(mac) and int(mac[1], 16) & 2 == 2


# ------------------------------------------------------------ MAC vendors ---
MANUF_URL = "https://www.wireshark.org/download/automated/data/manuf"
SYSTEM_DBS = ["/usr/share/wireshark/manuf", "/usr/share/ieee-data/oui.txt"]
_SUFFIX = re.compile(
    r"[\s,.]+(inc|incorporated|ltd|limited|llc|corp|corporation|co|company|gmbh|ag|sa|s\.?a\.?s|spa|"
    r"s\.?p\.?a|bv|b\.v|ab|oy|as|pte|pty|plc|kg|srl|technologies|technology|tech|electronics|"
    r"international|holdings?|group|industrial|manufacturing|communications?|systems)\.?$", re.I)
BRAND_ALIASES = [
    ("avm audiovis", "AVM"), ("hon hai", "Foxconn"), ("cloud network technology", "Foxconn"),
    ("tp-link", "TP-Link"), ("seiko epson", "Epson"), ("hewlett", "HP"), ("lcfc", "Lenovo"),
    ("samsung", "Samsung"), ("lg electronics", "LG"), ("lg innotek", "LG"), ("sony interactive", "Sony PlayStation"),
    ("sony", "Sony"), ("xiaomi", "Xiaomi"), ("huawei", "Huawei"), ("espressif", "Espressif"),
    ("raspberry", "Raspberry Pi"), ("micro-star", "MSI"), ("giga-byte", "Gigabyte"), ("asustek", "ASUS"),
    ("intel", "Intel"), ("realtek", "Realtek"), ("amazon", "Amazon"), ("google", "Google"),
    ("nintendo", "Nintendo"), ("synology", "Synology"), ("qnap", "QNAP"), ("ubiquiti", "Ubiquiti"),
    ("murata", "Murata"), ("azurewave", "AzureWave"), ("liteon", "Lite-On"), ("chongqing fugui", "Fugui"),
    ("brother", "Brother"), ("canon", "Canon"), ("signify", "Philips Hue"), ("tp vision", "Philips TV"),
    ("allterco", "Shelly"), ("shelly", "Shelly"), ("tuya", "Tuya"), ("hangzhou hikvision", "Hikvision"),
    ("zhejiang dahua", "Dahua"), ("motorola mobility", "Motorola"), ("oneplus", "OnePlus"),
    ("guangdong oppo", "OPPO"), ("vivo mobile", "vivo"), ("nest labs", "Google Nest"), ("bsh ", "Bosch Siemens"),
    ("fritz", "AVM"), ("sagemcom", "Sagemcom"), ("technicolor", "Technicolor"), ("arcadyan", "Arcadyan"), ("zte", "ZTE"),
]


def short_brand(name):
    if not name:
        return None
    low = name.lower()
    for key, alias in BRAND_ALIASES:
        if key in low:
            return alias
    name = name.split(",")[0].strip()
    prev = None
    while prev != name:
        prev, name = name, _SUFFIX.sub("", name).strip()
    if len(name) > 22:
        name = name.split()[0]
    return name


class Vendors:
    def __init__(self, data_dir):
        self.path = os.path.join(data_dir, "manuf")
        self.tables = {}  # prefix length in bits -> {prefix: name}

    def load(self):
        try:
            if not os.path.exists(self.path) or time.time() - os.path.getmtime(self.path) > 30 * 86400:
                os.makedirs(os.path.dirname(self.path), exist_ok=True)
                with urllib.request.urlopen(MANUF_URL, timeout=60) as r:
                    data = r.read()
                with open(self.path + ".tmp", "wb") as f:
                    f.write(data)
                os.replace(self.path + ".tmp", self.path)
        except Exception as e:
            print("vendor db download failed:", e, flush=True)
        for p in [self.path] + SYSTEM_DBS:
            if os.path.exists(p):
                self._parse(p)
                if self.tables:
                    print("vendor db: %s (%d prefixes)" % (p, sum(map(len, self.tables.values()))), flush=True)
                    return

    def _parse(self, path):
        tables = {}
        ieee = re.compile(r"^([0-9A-F]{2})-([0-9A-F]{2})-([0-9A-F]{2})\s+\(hex\)\s+(.+)$")
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                m = ieee.match(line)
                if m:
                    tables.setdefault(24, {})[int("".join(m.groups()[:3]), 16)] = m.group(4).strip()
                    continue
                if not line.strip() or line.startswith("#"):
                    continue
                parts = line.rstrip("\n").split("\t")
                if len(parts) < 2:
                    continue
                prefix, _, bits = parts[0].partition("/")
                hexs = re.sub(r"[^0-9A-Fa-f]", "", prefix)
                if not hexs:
                    continue
                bits = int(bits) if bits else len(hexs) * 4
                value = (int(hexs, 16) << (48 - len(hexs) * 4)) >> (48 - bits)
                tables.setdefault(bits, {})[value] = (parts[2] if len(parts) > 2 else parts[1]).strip()
        self.tables = tables

    def lookup(self, mac):
        if not mac or is_random_mac(mac):
            return None
        n = int(mac.replace(":", ""), 16)
        for bits in sorted(self.tables, reverse=True):
            v = self.tables[bits].get(n >> (48 - bits))
            if v:
                return v
        return None


# -------------------------------------------------------------------- DNS ---
def _qname(name):
    out = b""
    for part in name.rstrip(".").split("."):
        b = part.encode()[:63]
        out += bytes([len(b)]) + b
    return out + b"\0"


def dns_query(questions):
    pkt = struct.pack(">HHHHHH", 0, 0, len(questions), 0, 0, 0)
    for name, qtype in questions:
        pkt += _qname(name) + struct.pack(">HH", qtype, 1)
    return pkt


def _rname(data, off):
    labels, end, hops = [], None, 0
    while True:
        n = data[off]
        if n == 0:
            off += 1
            break
        if n & 0xC0 == 0xC0:
            if end is None:
                end = off + 2
            off = ((n & 0x3F) << 8) | data[off + 1]
            hops += 1
            if hops > 30:
                raise ValueError("loop")
            continue
        labels.append(data[off + 1:off + 1 + n].decode("utf-8", "replace"))
        off += 1 + n
    return ".".join(labels), (end if end is not None else off)


def dns_parse(data):
    """-> list of (name, type, value) for PTR/SRV/TXT/A records."""
    _, _, qd, an, ns, ar = struct.unpack_from(">HHHHHH", data, 0)
    off = 12
    for _ in range(qd):
        _, off = _rname(data, off)
        off += 4
    recs = []
    for _ in range(an + ns + ar):
        name, off = _rname(data, off)
        rtype, _, _, rlen = struct.unpack_from(">HHIH", data, off)
        off += 10
        start, rd = off, data[off:off + rlen]
        off += rlen
        if rtype == 12:
            val = _rname(data, start)[0]
        elif rtype == 33:
            val = (struct.unpack_from(">H", data, start + 4)[0], _rname(data, start + 6)[0])
        elif rtype == 16:
            val, i = [], 0
            while i < len(rd):
                val.append(rd[i + 1:i + 1 + rd[i]].decode("utf-8", "replace"))
                i += 1 + rd[i]
        elif rtype == 1 and rlen == 4:
            val = socket.inet_ntoa(rd)
        else:
            continue
        recs.append((name, rtype, val))
    return recs


def reverse_dns(server, ips, timeout=2):
    """PTR lookups sent straight to the gateway's DNS (it knows the DHCP names,
    and the system resolver may be pointing to a VPN). -> {ip: name}"""
    out = {}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except OSError:
        return out
    with s:
        for i, ip in enumerate(ips):
            q = dns_query([(".".join(reversed(ip.split("."))) + ".in-addr.arpa", 12)])
            q = struct.pack(">HH", i + 1, 0x0100) + q[4:]  # id, recursion desired
            try:
                s.sendto(q, (server, 53))
            except OSError:
                return out

        def handle(data, src):
            if src != server:
                return
            qid = struct.unpack_from(">H", data)[0]
            for name, rtype, val in dns_parse(data):
                if rtype == 12 and 0 < qid <= len(ips):
                    out[ips[qid - 1]] = val
        _recv_all(s, timeout, handle)
    return out


MDNS = ("224.0.0.251", 5353)
SERVICES_ENUM = "_services._dns-sd._udp.local"
INTERESTING = [
    "_device-info._tcp", "_googlecast._tcp", "_ipp._tcp", "_ipps._tcp", "_printer._tcp", "_pdl-datastream._tcp",
    "_airplay._tcp", "_raop._tcp", "_companion-link._tcp", "_apple-mobdev2._tcp", "_hap._tcp", "_homekit._tcp",
    "_smb._tcp", "_afpovertcp._tcp", "_adisk._tcp", "_workstation._tcp", "_ssh._tcp", "_sftp-ssh._tcp",
    "_rfb._tcp", "_sonos._tcp", "_spotify-connect._tcp", "_amzn-wplay._tcp", "_androidtvremote2._tcp",
    "_esphomelib._tcp", "_hue._tcp", "_shelly._tcp", "_home-assistant._tcp", "_matterc._udp", "_http._tcp",
    "_sleep-proxy._udp", "_scanner._tcp", "_uscan._tcp", "_qdiscover._tcp", "_nvstream._tcp",
]


def _udp_socket(self_ip, multicast=False):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if multicast:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(self_ip))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
    s.bind((self_ip, 0))
    return s


def _recv_all(sock, timeout, handle):
    deadline = time.time() + timeout
    while True:
        left = deadline - time.time()
        if left <= 0:
            return
        sock.settimeout(left)
        try:
            data, addr = sock.recvfrom(9000)
        except socket.timeout:
            return
        except OSError:
            return
        try:
            handle(data, addr[0])
        except Exception:
            pass


def mdns_browse(self_ip, ips):
    """Query mDNS both via multicast and unicast to each ip.

    -> {ip: {"hostname", "services": [...], "instances": {svc: name}, "txt": {svc: {k: v}}}}
    """
    res = {}
    found_types = set()

    def entry(ip):
        return res.setdefault(ip, {"hostname": None, "services": set(), "instances": {}, "txt": {}})

    def handle(data, src):
        recs = dns_parse(data)
        amap = {n: v for n, t, v in recs if t == 1}
        srv = {n: v for n, t, v in recs if t == 33}

        def owner(instance):
            target = srv.get(instance, (0, None))[1]
            return amap.get(target, src)

        for name, rtype, val in recs:
            if rtype == 12 and name == SERVICES_ENUM:
                svc = val.replace(".local", "")
                found_types.add(svc)
                entry(src)["services"].add(svc)
            elif rtype == 12 and name.endswith(".in-addr.arpa"):
                ip = ".".join(reversed(name.split(".")[:4]))
                entry(ip)["hostname"] = val.replace(".local", "")
            elif rtype == 12 and name.endswith(".local"):
                svc = name[:-len(".local")]
                e = entry(owner(val))
                e["services"].add(svc)
                e["instances"].setdefault(svc, val[:-len(name) - 1] if val.endswith(name) else val)
            elif rtype == 16 and "._" in name:
                svc = "_" + name.split("._", 1)[1].replace(".local", "")
                kv = {}
                for s in val:
                    k, _, v = s.partition("=")
                    if k:
                        kv[k.lower()] = v
                if kv:
                    e = entry(owner(name))
                    e["txt"].setdefault(svc, {}).update(kv)
                    e["instances"].setdefault(svc, name.split("._", 1)[0])
                    e["services"].add(svc)
        for name, rtype, val in recs:  # hostnames from SRV targets
            if rtype == 33:
                e = entry(owner(name))
                e["hostname"] = e["hostname"] or val[1].replace(".local", "")

    try:
        s = _udp_socket(self_ip, multicast=True)
    except OSError as e:
        print("mdns socket:", e, flush=True)
        return {}
    with s:
        # 1. service enumeration + reverse lookup
        s.sendto(dns_query([(SERVICES_ENUM, 12)]), MDNS)
        for ip in ips:
            rev = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
            try:
                s.sendto(dns_query([(SERVICES_ENUM, 12), (rev, 12)]), (ip, 5353))
            except OSError:
                pass
        _recv_all(s, 2.5, handle)
        # 2. browse every service type we know or have seen
        types = sorted(found_types | set(INTERESTING))
        for i in range(0, len(types), 10):
            q = dns_query([(t + ".local", 12) for t in types[i:i + 10]])
            s.sendto(q, MDNS)
            for ip in res:
                try:
                    s.sendto(q, (ip, 5353))
                except OSError:
                    pass
        _recv_all(s, 3, handle)
        # 3. Apple device-info (model identifier) for anyone with an instance name
        for ip, e in res.items():
            if "_device-info._tcp" not in e["txt"] and e["instances"]:
                inst = next(iter(e["instances"].values()))
                try:
                    s.sendto(dns_query([(inst + "._device-info._tcp.local", 16)]), (ip, 5353))
                except OSError:
                    pass
        _recv_all(s, 1.5, handle)
    for e in res.values():
        e["services"] = sorted(e["services"])
    return res


# ------------------------------------------------------------- SSDP/UPnP ---
# some devices ignore ssdp:all and only answer their own search target (Fire TV: DIAL)
SSDP_TARGETS = ["ssdp:all", "upnp:rootdevice", "urn:dial-multiscreen-org:service:dial:1",
                "urn:schemas-upnp-org:device:MediaRenderer:1"]


def ssdp_search(self_ip, ips=(), timeout=3):
    """-> {ip: {"locations": [...], "server": str}}"""
    res = {}

    def msg(host, st):
        return ("M-SEARCH * HTTP/1.1\r\nHOST: %s:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: %s\r\n\r\n"
                % (host, st)).encode()

    def handle(data, src):
        headers = {}
        for line in data.decode("utf-8", "replace").split("\r\n")[1:]:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()
        e = res.setdefault(src, {"locations": [], "server": None})
        loc = headers.get("location")
        if loc and loc not in e["locations"] and len(e["locations"]) < 6:
            e["locations"].append(loc)
        e["server"] = e["server"] or headers.get("server")

    try:
        s = _udp_socket(self_ip, multicast=True)
    except OSError as e:
        print("ssdp socket:", e, flush=True)
        return {}
    with s:
        for st in SSDP_TARGETS:
            s.sendto(msg("239.255.255.250", st), ("239.255.255.250", 1900))
            for ip in ips:  # unicast too: range extenders / Wi-Fi often drop multicast
                try:
                    s.sendto(msg(ip, st), (ip, 1900))
                except OSError:
                    pass
        _recv_all(s, timeout, handle)
    return res


def _xml_tag(xml, tag):
    m = re.search(r"<(?:\w+:)?%s>\s*(.*?)\s*</(?:\w+:)?%s>" % (tag, tag), xml, re.S)
    return html.unescape(m.group(1)).strip()[:80] if m and m.group(1).strip() else None


def upnp_describe(ip, locations):
    out = {"device_types": []}
    for loc in locations:
        m = re.match(r"(https?://)([\d.]+)([:/].*)$", loc)
        if not m:
            continue
        if m.group(2) != ip:  # e.g. Fire TV advertises its Wi-Fi Direct address (192.168.49.1)
            loc = m.group(1) + ip + m.group(3)
        try:
            with urllib.request.urlopen(loc, timeout=3) as r:
                xml = r.read(262144).decode("utf-8", "replace")
        except Exception:
            continue
        for k in ("friendlyName", "manufacturer", "modelName", "modelNumber", "modelDescription"):
            out.setdefault(k, _xml_tag(xml, k))
            if not out[k]:
                out[k] = _xml_tag(xml, k)
        for t in re.findall(r"<(?:\w+:)?deviceType>\s*urn:[^:]+:device:([^:<]+)", xml):
            if t not in out["device_types"]:
                out["device_types"].append(t)
        if out.get("modelName"):
            break
    return {k: v for k, v in out.items() if v}


# ---------------------------------------------------------------- NetBIOS ---
NBSTAT = (struct.pack(">HHHHHH", 0x4c4d, 0, 1, 0, 0, 0) + b"\x20" + b"CK" + b"A" * 30 + b"\x00"
          + struct.pack(">HH", 0x21, 1))


def netbios(self_ip, ips, timeout=2):
    """-> {ip: {"name", "group"}}"""
    res = {}

    def handle(data, src):
        off = 12
        off = off + 34 if data[off] == 0x20 else off + 2
        off += 10
        n = data[off]
        off += 1
        e = {}
        for _ in range(n):
            name = data[off:off + 15].decode("ascii", "replace").strip()
            suffix, flags = data[off + 15], struct.unpack_from(">H", data, off + 16)[0]
            off += 18
            if suffix == 0 and not flags & 0x8000:
                e.setdefault("name", name)
            elif suffix == 0:
                e.setdefault("group", name)
        if e:
            res[src] = e

    try:
        s = _udp_socket(self_ip)
    except OSError:
        return {}
    with s:
        for ip in ips:
            try:
                s.sendto(NBSTAT, (ip, 137))
            except OSError:
                pass
        _recv_all(s, timeout, handle)
    return res


# ------------------------------------------------------------ TCP / HTTP ---
PORTS = [22, 23, 53, 80, 139, 443, 445, 548, 554, 631, 1400, 1883, 3389, 5000, 5001, 5555,
         6668, 7000, 8008, 8009, 8080, 8123, 8443, 9100, 32400, 62078]


def _port_open(ip, port):
    try:
        with socket.create_connection((ip, port), timeout=0.8):
            return True
    except OSError:
        return False


def port_scan(ips):
    pairs = [(ip, p) for ip in ips for p in PORTS]
    res = {ip: [] for ip in ips}
    with ThreadPoolExecutor(max_workers=64) as ex:
        for (ip, p), ok in zip(pairs, ex.map(lambda a: _port_open(*a), pairs)):
            if ok:
                res[ip].append(p)
    return res


def ssh_banner(ip):
    try:
        with socket.create_connection((ip, 22), timeout=2) as s:
            s.settimeout(2)
            line = s.recv(256).split(b"\n")[0].decode("utf-8", "replace").strip()
            return line if line.startswith("SSH-") else None
    except OSError:
        return None


def http_info(ip, port):
    try:
        if port in (443, 8443, 5001):
            c = http.client.HTTPSConnection(ip, port, timeout=3, context=ssl._create_unverified_context())
        else:
            c = http.client.HTTPConnection(ip, port, timeout=3)
        c.request("GET", "/", headers={"User-Agent": "lanman", "Host": ip})
        r = c.getresponse()
        body = r.read(65536).decode("utf-8", "replace")
        c.close()
    except Exception:
        return None
    t = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    title = re.sub(r"\s+", " ", html.unescape(t.group(1))).strip()[:80] if t else None
    if title and re.fullmatch(r"(opening|loading|redirect\w*|please wait)\W*", title, re.I):
        title = None  # single page app placeholder
    server = r.getheader("Server")
    hint = next((h for rx, h in WEB_HINTS if re.search(rx, body)), None)
    if not title and not server and not hint:
        return None
    out = {"port": port, "title": title, "server": server}
    if hint:
        out["hint"] = hint
    return out


# fingerprints found in a device's web UI (single page apps have no useful <title>)
WEB_HINTS = [
    (r"tplinkrepeater\.net", "tplink-extender"),
    (r"tplinkdeco\.net", "tplink-deco"),
    (r"tplinkwifi\.net|tplinklogin\.net|tplinkap\.net", "tplink-router"),
]


def tplink_device_block(ip, port=80):
    """Read the public DEVICE data block of TP-Link "TDDP" web UIs (range
    extenders, some routers/APs). No login needed, read only."""
    try:
        c = http.client.HTTPConnection(ip, port, timeout=3)
        c.request("POST", "/?code=2&asyn=0", body=b"0|1,0,0",
                  headers={"Content-Type": "text/plain;charset=UTF-8", "Referer": "http://%s/" % ip,
                           "User-Agent": "lanman"})
        text = c.getresponse().read(16384).decode("utf-8", "replace")
        c.close()
    except Exception:
        return None
    f = {}
    for line in text.splitlines()[1:]:
        k, _, v = line.partition(" ")
        if k:
            f[k] = urllib.parse.unquote(v.strip())
    if not f.get("modelName"):
        return None
    return {k: v for k, v in {
        "name": f.get("fullName"), "brand": f.get("facturer"), "model": f.get("modelName"),
        "model_ver": f.get("modelVer"), "hardware": f.get("hardVer"), "firmware": f.get("softVer"),
    }.items() if v}


# ------------------------------------------------------------ round trip ---
def rtt(ip):
    """-> {"min": ms, "mdev": ms} from 5 quick pings, or None."""
    out = subprocess.run(["ping", "-c", "5", "-i", "0.2", "-W", "1", "-n", "-q", ip],
                         capture_output=True, text=True).stdout
    m = re.search(r"= ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms", out)
    return {"min": float(m.group(1)), "mdev": float(m.group(4))} if m else None


# ------------------------------------------------------- router host table ---
TR064 = ('<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
         's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
         '<u:{a} xmlns:u="urn:dslforum-org:service:Hosts:1">{args}</u:{a}></s:Body></s:Envelope>')


def _tr064(gw, action, args=""):
    req = urllib.request.Request(
        "http://%s:49000/upnp/control/hosts" % gw, data=TR064.format(a=action, args=args).encode(),
        headers={"Content-Type": 'text/xml; charset="utf-8"',
                 "SoapAction": "urn:dslforum-org:service:Hosts:1#" + action})
    with urllib.request.urlopen(req, timeout=3) as r:
        return r.read(65536).decode("utf-8", "replace")


def router_hosts(gw):
    """FRITZ!Box host table via TR-064 (readable without login from the LAN).

    -> {mac or "ip:<addr>": {"name", "link", "active", "ip"}} or None if unsupported
    """
    try:
        n = int(re.search(r"<NewHostNumberOfEntries>(\d+)<", _tr064(gw, "GetHostNumberOfEntries")).group(1))
    except Exception:
        return None

    def entry(i):
        try:
            return _tr064(gw, "GetGenericHostEntry", "<NewIndex>%d</NewIndex>" % i)
        except Exception:
            return ""

    out = {}
    with ThreadPoolExecutor(max_workers=8) as ex:
        for xml in ex.map(entry, range(min(n, 512))):
            f = dict(re.findall(r"<New(\w+)>([^<]*)<", xml))
            if not f:
                continue
            name = f.get("HostName") or None
            if name and re.fullmatch(r"PC-\d+-\d+-\d+-\d+", name):  # FRITZ!Box placeholder
                name = None
            mac = (f.get("MACAddress") or "").lower()
            out[mac or "ip:" + f.get("IPAddress", "")] = {
                "name": name, "ip": f.get("IPAddress"), "active": f.get("Active") == "1",
                "link": {"802.11": "wifi", "Ethernet": "wired"}.get(f.get("InterfaceType")),
            }
    return out


WIFI_ONLY_VENDORS = re.compile(r"espressif|azurewave|murata|fn-link|chongqing fugui|tuya|shelly|allterco|"
                               r"itead|universal global scientific|hui zhou gaoshengda|realtek semiconductor", re.I)


WIFI_ONLY_MODELS = re.compile(r"fire tv stick|chromecast|home mini|nest mini|nest audio|"
                              r"echo dot|tapo [hplts]", re.I)


def link_guess(d, type_, vendor, host_wired, model=None):
    """-> (link, source): link in wifi / wired / vpn / None."""
    if d.get("is_self"):
        link = (d.get("probe") or {}).get("local", {}).get("link")
        return link, "interfaccia di questo host"
    if d.get("via_router"):
        return "vpn", "client remoto instradato dal router"
    if d.get("is_gateway"):
        return None, None
    r = (d.get("router") or {}).get("link")
    if r:
        return r, "tabella del router"
    if is_random_mac(d.get("mac")):
        return "wifi", "MAC privato (solo Wi-Fi)"
    t = (d.get("probe") or {}).get("rtt")
    if host_wired and t:
        if t["min"] < 0.8 and t["mdev"] < 0.2:
            return "wired", "tempo di risposta (%.2f ms)" % t["min"]
        if t["min"] > 1.0 or t["mdev"] > 0.3:
            return "wifi", "tempo di risposta (%.2f ms ±%.2f)" % (t["min"], t["mdev"])
    if type_ == "mobile":
        return "wifi", "tipo di dispositivo"
    if model and WIFI_ONLY_MODELS.search(model):
        return "wifi", "modello senza porta Ethernet"
    if vendor and WIFI_ONLY_VENDORS.search(vendor):
        return "wifi", "produttore di moduli Wi-Fi"
    return None, None


# ------------------------------------------------------------ probe round ---
def probe(self_ip, all_ips, targets, measure_rtt=False):
    """Run every probe. Network-wide ones (mDNS, SSDP) cover all_ips, the
    per-host ones (NetBIOS, ports, HTTP, UPnP description) only targets.

    -> {ip: partial probe dict}
    """
    out = {}
    with ThreadPoolExecutor(max_workers=3) as ex:
        f_mdns = ex.submit(mdns_browse, self_ip, all_ips)
        f_ssdp = ex.submit(ssdp_search, self_ip, targets)
        f_nb = ex.submit(netbios, self_ip, targets)
        f_ports = ex.submit(port_scan, targets)
        mdns, ssdp, nb, ports = f_mdns.result(), f_ssdp.result(), f_nb.result(), f_ports.result()

    for ip, v in mdns.items():
        if ip in all_ips:
            out.setdefault(ip, {})["mdns"] = v
    for ip, v in nb.items():
        out.setdefault(ip, {})["netbios"] = v
    for ip, v in ports.items():
        out.setdefault(ip, {})["ports"] = v

    jobs = []
    for ip in targets:
        for p in [p for p in (80, 8080, 5000, 443, 8443) if p in ports.get(ip, [])][:2]:
            jobs.append(("http", ip, p))
    for ip in targets:
        if "_fbx-api._tcp" in (mdns.get(ip) or {}).get("services", []):
            jobs.append(("fbx", ip, None))
        if 22 in ports.get(ip, []):
            jobs.append(("ssh", ip, None))
        if measure_rtt and ip != self_ip:
            jobs.append(("rtt", ip, None))
    for ip, v in ssdp.items():
        if ip in all_ips:
            out.setdefault(ip, {})["ssdp_server"] = v["server"]
            if ip in targets:
                jobs.append(("upnp", ip, v["locations"]))

    def run(job):
        kind, ip, arg = job
        if kind == "ssh":
            return job, ssh_banner(ip)
        if kind == "rtt":
            return job, rtt(ip)
        if kind == "fbx":
            info = freebox.api_version(ip) or {}
            return job, {k: v for k, v in {
                "name": info.get("device_name"), "brand": None, "model": info.get("box_model_name"),
                "hardware": info.get("box_model"), "firmware": info.get("api_version") and
                "API Freebox OS %s" % info["api_version"]}.items() if v} or None
        if kind == "http":
            r = http_info(ip, arg)
            if r and (r.get("hint") or "").startswith("tplink"):
                r["device_info"] = tplink_device_block(ip, arg)
            return job, r
        return job, (http_info(ip, arg) if kind == "http" else upnp_describe(ip, arg))

    with ThreadPoolExecutor(max_workers=16) as ex:
        for (kind, ip, _), r in ex.map(run, jobs):
            if not r:
                continue
            if kind in ("ssh", "rtt"):
                out.setdefault(ip, {})[kind] = r
            elif kind == "fbx":
                out.setdefault(ip, {})["device_info"] = r
            elif kind == "http":
                di = r.pop("device_info", None)
                if di:
                    out.setdefault(ip, {})["device_info"] = di
                out.setdefault(ip, {}).setdefault("http", []).append(r)
            else:
                out.setdefault(ip, {})["upnp"] = r
    for ip in targets:  # mark as probed even if silent
        e = out.setdefault(ip, {})
        e.setdefault("http", [])
        e.setdefault("ports", [])
    return out


# ------------------------------------------------------------- local host ---
_GENERIC = re.compile(r"^(to be filled|system product|system manufacturer|default string|not applicable|"
                      r"none|o\.?e\.?m|unknown|type1|0123456789|x\.x)", re.I)


def _read(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            v = f.read().replace("\0", "").strip()
            return v if v and not _GENERIC.match(v) else None
    except OSError:
        return None


def local_info():
    """Hardware/OS facts about the host lanman runs on."""
    info = {}
    dmi = "/sys/class/dmi/id/"
    vendor, name, version = _read(dmi + "sys_vendor"), _read(dmi + "product_name"), _read(dmi + "product_version")
    if vendor:
        info["brand"] = short_brand(vendor.title() if vendor.isupper() else vendor)
        if version and vendor.upper() == "LENOVO":  # Lenovo keeps the marketing name in product_version
            info["model"] = "%s (%s)" % (version, name) if name else version
        else:
            info["model"] = name
        chassis = _read(dmi + "chassis_type")
        info["type"] = "server" if chassis in ("17", "23", "28") else "computer"
    dt = _read("/proc/device-tree/model")
    if dt:  # ARM boards
        info["model"] = dt
        low = dt.lower()
        info["brand"] = ("Orange Pi" if "orange pi" in low else "Raspberry Pi" if "raspberry" in low
                         else dt.split()[0])
        info["type"] = "server"
    os_release = {}
    for line in (_read("/etc/os-release") or "").splitlines():
        k, _, v = line.partition("=")
        os_release[k] = v.strip('"')
    info["os"] = os_release.get("PRETTY_NAME") or os.uname().sysname
    info["kernel"] = os.uname().release
    cpu = None
    for line in (_read("/proc/cpuinfo") or "").splitlines():
        if line.startswith(("model name", "Hardware")) and not cpu:
            cpu = line.split(":", 1)[1].strip()
    info["cpu"] = "%s, %d core" % (re.sub(r"\s+", " ", cpu or "?"), os.cpu_count() or 1)
    mem = re.search(r"MemTotal:\s+(\d+)", _read("/proc/meminfo") or "")
    if mem:
        gb = int(mem.group(1)) / 1048576
        info["ram"] = "%.1f GB" % gb if gb >= 1 else "%d MB" % (int(mem.group(1)) / 1024)
    return {k: v for k, v in info.items() if v}


# --------------------------------------------------------- operating system ---
def os_guess(p, apple_model, fire, names, ports, vendor):
    mdns = p.get("mdns") or {}
    services = mdns.get("services") or []
    txt = mdns.get("txt") or {}
    if (p.get("local") or {}).get("os"):
        return p["local"]["os"]
    vc = p.get("dhcp_vendor_class") or ""
    m = re.match(r"android-dhcp-(\d+)", vc)
    if m:
        return "Android %s" % m.group(1)
    if vc.startswith("MSFT"):
        return "Windows"
    if apple_model:
        for prefix, os_name in (("iPhone", "iOS"), ("iPad", "iPadOS"), ("Watch", "watchOS"),
                                ("AppleTV", "tvOS"), ("AudioAccessory", "audioOS"), ("Mac", "macOS"),
                                ("iMac", "macOS")):
            if apple_model.startswith(prefix):
                return os_name
    if fire:
        return "Fire OS"
    if "_androidtvremote2._tcp" in services:
        return "Android TV"
    if "_googlecast._tcp" in services:
        return "Google Cast"
    ssh = p.get("ssh") or ""
    m = re.search(r"deb(\d+)u", ssh)
    if m:
        return "Debian %s" % m.group(1)
    for rx, os_name in ((r"ubuntu", "Ubuntu"), (r"raspbian", "Raspberry Pi OS"), (r"debian", "Debian"),
                        (r"freebsd", "FreeBSD"), (r"openbsd", "OpenBSD"), (r"windows|for_windows", "Windows"),
                        (r"rosssh", "MikroTik RouterOS"), (r"dropbear", "Linux embedded")):
        if re.search(rx, ssh, re.I):
            return os_name
    blob = " ".join("%s %s" % (h.get("server") or "", h.get("title") or "") for h in p.get("http") or [])
    for rx, os_name in ((r"fritz!", "FRITZ!OS"), (r"synology|diskstation", "Synology DSM"),
                        (r"\(ubuntu\)", "Ubuntu"), (r"\(debian\)", "Debian"), (r"\(raspbian\)", "Raspberry Pi OS"),
                        (r"win32|win64|microsoft-iis", "Windows"), (r"routeros", "MikroTik RouterOS"),
                        (r"openwrt|luci", "OpenWrt")):
        if re.search(rx, blob, re.I):
            return os_name
    if vendor and re.search(r"synology", vendor, re.I):
        return "Synology DSM"
    if (txt.get("_device-info._tcp") or {}).get("model") == "MacSamba" or "_workstation._tcp" in services:
        return "Linux"
    if 62078 in ports:
        return "iOS"
    if re.search(r"android|galaxy|pixel|redmi", names, re.I):
        return "Android"
    if (p.get("netbios") or {}).get("name") and (3389 in ports or 445 in ports) and 22 not in ports:
        return "Windows"
    return None


# ------------------------------------------------------------------- DHCP ---
def parse_dhcp(data):
    """BOOTREQUEST -> {"mac", "hostname", "vendor_class", "requested_ip"} or None."""
    if len(data) < 240 or data[0] != 1 or data[236:240] != b"\x63\x82\x53\x63":
        return None
    hlen = data[2]
    if hlen != 6:
        return None
    mac = ":".join("%02x" % b for b in data[28:34])
    opts, i = {}, 240
    while i < len(data):
        code = data[i]
        if code == 255:
            break
        if code == 0:
            i += 1
            continue
        n = data[i + 1]
        opts[code] = data[i + 2:i + 2 + n]
        i += 2 + n
    txt = lambda b: b.decode("utf-8", "replace").strip("\0 ") or None  # noqa: E731
    return {
        "mac": mac,
        "hostname": txt(opts[12]) if 12 in opts else None,
        "vendor_class": txt(opts[60]) if 60 in opts else None,
        "requested_ip": socket.inet_ntoa(opts[50]) if len(opts.get(50, b"")) == 4 else None,
    }


# brand / model from user-visible device names ("Galaxy-Note9-di-Francesco", "Redmi-Note-12", "Pixel-7a")
NAME_MODELS = [
    (r"galaxy[-_ ]?((?:note|tab[-_ ]?s?|[a-z])\d+[a-z]?(?:[-_ ]?(?:plus|ultra|lite|fe|edge|5g))?)", "Samsung", "Galaxy %s"),
    (r"(redmi[-_ ]?(?:note[-_ ]?)?\d+[a-z]?(?:[-_ ]?pro)?)", "Xiaomi", "%s"),
    (r"(poco[-_ ]?[a-z]\d+(?:[-_ ]?pro)?)", "Xiaomi", "%s"),
    (r"pixel[-_ ]?(\d+[a-z]?(?:[-_ ]?(?:pro|xl|a))?)", "Google", "Pixel %s"),
    (r"(oneplus[-_ ]?\w+)", "OnePlus", "%s"),
    (r"(iphone(?:[-_ ]?\d+)?(?:[-_ ]?(?:pro|max|mini|plus))*)", "Apple", "%s"),
    (r"(ipad(?:[-_ ]?(?:pro|air|mini))?)", "Apple", "%s"),
]


def name_model(names):
    for n in names:
        for rx, brand, fmt in NAME_MODELS:
            m = re.search(rx, n, re.I)
            if m:
                model = fmt % re.sub(r"[-_]+", " ", m.group(1)).strip()
                return brand, model[0].upper() + model[1:]
    return None, None


# --------------------------------------------------------- classification ---
UPNP_TYPES = {
    "InternetGatewayDevice": ("router", 8), "WANDevice": ("router", 4), "WANConnectionDevice": ("router", 4),
    "WLANAccessPointDevice": ("router", 6), "MediaRenderer": ("media", 5), "MediaServer": ("server", 2),
    "Printer": ("printer", 8), "DigitalSecurityCamera": ("camera", 8), "ZonePlayer": ("media", 8),
    "dial": ("media", 6), "HomeAutomationDevice": ("iot", 5), "Basic": ("unknown", 0),
}
MDNS_TYPES = {
    "_ipp._tcp": [("printer", 8)], "_ipps._tcp": [("printer", 8)], "_printer._tcp": [("printer", 8)],
    "_pdl-datastream._tcp": [("printer", 8)], "_scanner._tcp": [("printer", 5)], "_uscan._tcp": [("printer", 5)],
    "_googlecast._tcp": [("media", 7)], "_airplay._tcp": [("media", 3)], "_raop._tcp": [("media", 2)],
    "_spotify-connect._tcp": [("media", 4)], "_sonos._tcp": [("media", 8)], "_amzn-wplay._tcp": [("media", 7)],
    "_androidtvremote2._tcp": [("media", 8)], "_sleep-proxy._udp": [("media", 3)], "_nvstream._tcp": [("computer", 3)],
    "_companion-link._tcp": [("mobile", 2), ("computer", 1)], "_apple-mobdev2._tcp": [("mobile", 6)],
    "_hap._tcp": [("iot", 6)], "_homekit._tcp": [("iot", 4)], "_hue._tcp": [("iot", 8)],
    "_esphomelib._tcp": [("iot", 8)], "_shelly._tcp": [("iot", 8)], "_matterc._udp": [("iot", 5)],
    "_smb._tcp": [("computer", 2), ("server", 2)], "_afpovertcp._tcp": [("server", 2), ("computer", 1)],
    "_adisk._tcp": [("server", 4)], "_workstation._tcp": [("computer", 3), ("server", 1)],
    "_ssh._tcp": [("server", 2), ("computer", 1)], "_sftp-ssh._tcp": [("server", 1)],
    "_rfb._tcp": [("computer", 3)], "_home-assistant._tcp": [("server", 8)], "_qdiscover._tcp": [("server", 8)],
}
PORT_TYPES = {
    9100: [("printer", 5)], 631: [("printer", 3)], 554: [("camera", 3)], 62078: [("mobile", 8)],
    5555: [("media", 2)], 3389: [("computer", 5)], 445: [("computer", 2), ("server", 2)],
    139: [("computer", 1)], 22: [("server", 2), ("computer", 1)], 548: [("server", 2)],
    8123: [("server", 6)], 32400: [("server", 4)], 1400: [("media", 5)], 8008: [("media", 4)],
    8009: [("media", 4)], 7000: [("media", 1)], 6668: [("iot", 6)], 1883: [("server", 3)],
    53: [("router", 3)], 23: [("router", 1)],
}
VENDOR_TYPES = [
    # router / network
    (r"avm audiovis|ubiquiti|mikrotik|routerboard|zyxel|technicolor|sagemcom|arcadyan|aruba|ruckus|"
     r"linksys|tenda|juniper|draytek|fortinet|eero|cisco|d-link|netgear|askey", [("router", 4)]),
    (r"tp-link", [("router", 2), ("iot", 2)]),
    (r"tuya", [("iot", 2)]),
    # printers
    (r"seiko epson|brother|kyocera|lexmark|xerox|ricoh|konica|canon|oki electric", [("printer", 6)]),
    (r"hewlett", [("printer", 3), ("computer", 2)]),
    # cameras
    (r"hikvision|dahua|reolink|axis comm|ezviz|amcrest|foscam|uniview|hanwha", [("camera", 7)]),
    # servers / nas / sbc
    (r"synology|qnap|asustor|supermicro", [("server", 8)]),
    (r"raspberry|xunlong|western digital|buffalo", [("server", 4)]),
    # computers
    (r"intel corporate|lcfc|lenovo|dell|liteon|azurewave|hon hai|cloud network technology|micro-star|"
     r"giga-byte|acer|quanta|compal|wistron|chicony|rivet networks|framework", [("computer", 4)]),
    (r"asustek|realtek", [("computer", 3), ("router", 1)]),
    (r"microsoft", [("computer", 2), ("console", 2)]),
    (r"apple", [("mobile", 1), ("computer", 1)]),
    # phones
    (r"oneplus|guangdong oppo|vivo mobile|motorola mobility|realme|honor device|fairphone|nothing tech|"
     r"hmd global|sony mobile", [("mobile", 5)]),
    (r"samsung", [("mobile", 2), ("media", 2)]),
    (r"xiaomi", [("mobile", 2), ("iot", 2)]),
    (r"huawei", [("mobile", 2), ("router", 1)]),
    (r"google", [("mobile", 2), ("media", 2)]),
    # media
    (r"roku|sonos|tp vision|vizio|sound united|bose", [("media", 6)]),
    (r"lg electronics|sony|tcl|hisense|panasonic|sharp|yamaha|harman|sky ", [("media", 3)]),
    (r"amazon", [("media", 3), ("iot", 2)]),
    # iot
    (r"espressif|shelly|allterco|itead|signify|nest labs|ecobee|netatmo|bsh |miele|irobot|roborock|"
     r"tado|broadlink|ikea|wiz connected|silicon lab", [("iot", 6)]),
    (r"murata|texas instruments|chongqing fugui|fn-link", [("iot", 2)]),
    # consoles
    (r"nintendo|sony interactive|valve", [("console", 8)]),
]
NAME_TYPES = [
    (r"iphone|ipad", [("mobile", 8)]),
    (r"android|galaxy|pixel|redmi|oneplus|phone|smartphone|tablet", [("mobile", 6)]),
    (r"macbook|imac|mac-?mini|mac-?pro", [("computer", 8)]),
    (r"desktop-|laptop|notebook|thinkpad|yoga|workstation|ubuntu|fedora|win-|-pc\b|^pc", [("computer", 6)]),
    (r"\bnas|diskstation|synology|qnap|server|raspberrypi|orangepi|pi-?hole|homeassistant|proxmox|truenas",
     [("server", 6)]),
    (r"printer|laserjet|officejet|deskjet|envy|epson|canon|^brn|^brw|kyocera", [("printer", 6)]),
    (r"\btv\b|-tv|tv-|bravia|chromecast|fire-?tv|roku|shield|apple-?tv|webos|tizen|television|sonos|"
     r"soundbar", [("media", 6)]),
    (r"cam\b|camera|ipc|doorbell|nvr|dvr", [("camera", 5)]),
    (r"esp[-_]|esp32|esp8266|shelly|tasmota|tuya|sonoff|plug|bulb|\bhue\b|wled|zigbee|vacuum|roborock|"
     r"roomba|dyson|thermostat|smart", [("iot", 5)]),
    (r"playstation|ps4|ps5|xbox|nintendo", [("console", 6)]),
    (r"fritz|router|gateway|repeater|\bmesh|openwrt|unifi|access.?point", [("router", 6)]),
]
HTTP_TYPES = [
    (r"fritz!(box|repeater|powerline)|routeros|mikrotik|openwrt|luci|unifi|router|modem|gateway", ("router", 8)),
    (r"synology|diskstation|qnap|truenas|proxmox|home assistant|pi-hole|portainer|nextcloud|plex", ("server", 7)),
    (r"printer|laserjet|officejet|deskjet|epson|brother|ricoh|kyocera|lexmark", ("printer", 7)),
    (r"webcam|ipcam|network camera|nvr|dvr|hikvision", ("camera", 7)),
    (r"tasmota|shelly|esphome|wled|tuya", ("iot", 8)),
    (r"caddy|apache|nginx|traefik|vtiger|qbittorrent|transmission|jellyfin|grafana|gitea|wordpress", ("server", 3)),
]
# voice assistants / smart speakers & displays belong to home automation
SMART_ASSISTANT = re.compile(r"google[ -]?home|google nest|nest[ -]?(mini|audio|hub)|home mini|\becho\b|alexa|"
                             r"homepod", re.I)
# TP-Link Tapo / Kasa model codes -> (type, family)
TAPO_MODELS = [
    (r"H[12]\d\d", "iot", "hub domotica"), (r"(?:P|KP|HS|EP)\d{3}", "iot", "presa smart"),
    (r"(?:L|KL)\d{3}", "iot", "lampadina smart"), (r"T\d{3}", "iot", "sensore"),
    (r"S\d{3}", "iot", "interruttore smart"), (r"KE\d{3}", "iot", "termostato"),
    (r"(?:C|TC)\d{3}", "camera", "telecamera"), (r"D\d{3}", "camera", "videocitofono"),
    (r"RV\d{2,3}", "iot", "robot aspirapolvere"),
]
FIRE_TV = {
    "AFTM": "Fire TV Stick (1ª gen.)", "AFTT": "Fire TV Stick (2ª gen.)", "AFTSSS": "Fire TV Stick (3ª gen.)",
    "AFTSS": "Fire TV Stick Lite", "AFTMM": "Fire TV Stick 4K", "AFTKM": "Fire TV Stick 4K (2ª gen.)",
    "AFTKA": "Fire TV Stick 4K Max", "AFTKRT": "Fire TV Stick 4K Max (2ª gen.)", "AFTB": "Fire TV (1ª gen.)",
    "AFTS": "Fire TV (2ª gen.)", "AFTN": "Fire TV (3ª gen.)", "AFTR": "Fire TV Cube (1ª gen.)",
    "AFTA": "Fire TV Cube (2ª gen.)", "AFTGAZL": "Fire TV Cube (3ª gen.)",
}
# ISP / consumer gateways, matched on names + web titles: (regex, brand, model, os)
ISP_BOXES = [
    (r"iliadbox", "Iliad", "Iliadbox", "iliadbox OS"),
    (r"freebox", "Free", "Freebox", "Freebox OS"),
    (r"vodafone.?(station|power ?station)", "Vodafone", "Vodafone Station", None),
    (r"tim.?hub|timhub", "TIM", "TIM HUB", None),
    (r"fastgate", "Fastweb", "FASTGate", None),
    (r"sky.?wi-?fi.?hub|skyhub", "Sky", "Sky Wi-Fi Hub", None),
    (r"windtre|wind tre|infostrada", "WindTre", "WindTre Router", None),
    (r"livebox", "Orange", "Livebox", None),
    (r"bbox", "Bouygues", "Bbox", None),
]
APPLE_MODELS = [
    ("iPhone", "iPhone", "mobile"), ("iPad", "iPad", "mobile"), ("Watch", "Apple Watch", "mobile"),
    ("MacBookPro", "MacBook Pro", "computer"), ("MacBookAir", "MacBook Air", "computer"),
    ("MacBook", "MacBook", "computer"), ("iMac", "iMac", "computer"), ("Macmini", "Mac mini", "computer"),
    ("MacPro", "Mac Pro", "computer"), ("Mac", "Mac", "computer"), ("AppleTV", "Apple TV", "media"),
    ("AudioAccessory", "HomePod", "iot"),
]
DOMAIN_SUFFIX = re.compile(r"\.(fritz\.box|lan|local|home|localdomain|home\.arpa|station|box)$", re.I)


def _clean_host(h):
    if not h or h in ("_gateway", "localhost"):
        return None
    return DOMAIN_SUFFIX.sub("", h)


def classify(d, vendor):
    """d: device record with probe data. -> dict of derived fields."""
    p = d.get("probe") or {}
    mdns = p.get("mdns") or {}
    upnp = p.get("upnp") or {}
    nb = p.get("netbios") or {}
    txt = mdns.get("txt") or {}
    ports = p.get("ports") or []
    https = p.get("http") or []
    score = {}

    def vote(t, w):
        score[t] = score.get(t, 0) + w

    brand = model = None
    di = p.get("device_info") or {}
    hints = {h.get("hint") for h in https if h.get("hint")}
    if di.get("model"):
        role = ("range extender" if re.search(r"extender|repeater", di.get("name", ""), re.I) or
                "tplink-extender" in hints else
                "access point" if re.search(r"access point", di.get("name", ""), re.I) else None)
        brand = short_brand(di.get("brand")) or None
        model = di["model"] + (" v%s" % di["model_ver"] if di.get("model_ver") else "") + \
            (" (%s)" % role if role else "")
        vote("router", 12)
    elif hints & {"tplink-extender", "tplink-deco", "tplink-router"}:
        brand = "TP-Link"
        model = {"tplink-extender": "range extender", "tplink-deco": "Deco mesh"}.get(next(iter(hints)))
        vote("router", 10)
    local = p.get("local") or {}
    if local:
        brand, model = local.get("brand"), local.get("model")
        vote(local.get("type", "computer"), 20)
    # Apple model identifier
    apple = (txt.get("_device-info._tcp") or {}).get("model") or (txt.get("_airplay._tcp") or {}).get("model") \
        or (txt.get("_raop._tcp") or {}).get("am")
    if apple and vendor and "apple" not in vendor.lower():
        apple = None  # third-party AirPlay receiver apps fake an Apple model id
    if apple:
        for prefix, nice, t in APPLE_MODELS:
            if apple.startswith(prefix) and (prefix != "Mac" or re.match(r"Mac\d", apple)):
                brand, model = brand or "Apple", model or "%s (%s)" % (nice, apple)
                vote(t, 12)
                break
    if any(s in mdns.get("services", []) for s in ("_companion-link._tcp", "_apple-mobdev2._tcp")):
        brand = brand or "Apple"
    # Chromecast / Google TV
    gc = txt.get("_googlecast._tcp") or {}
    if gc.get("md"):
        model = model or gc["md"]
    # printers
    ipp = txt.get("_ipp._tcp") or txt.get("_ipps._tcp") or txt.get("_printer._tcp") or {}
    if ipp.get("ty"):
        model = model or ipp["ty"]
    # CUPS/Samba print server: "Brother HL-2130 series @ host" is a shared queue, not the printer itself
    instances = mdns.get("instances") or {}
    shared = next((v.split(" @ ")[0] for k, v in instances.items()
                   if " @ " in v and k in ("_ipp._tcp", "_ipps._tcp", "_printer._tcp")), None)
    if shared:
        model = None
        vote("server", 4)
    if (txt.get("_device-info._tcp") or {}).get("model") == "MacSamba":
        vote("server", 3)  # Samba on Linux
    hap = txt.get("_hap._tcp") or {}
    if hap.get("md"):
        model = model or hap["md"]

    for t in upnp.get("device_types", []):
        if t in UPNP_TYPES:
            vote(*UPNP_TYPES[t])
    if upnp.get("manufacturer"):
        brand = brand or short_brand(upnp["manufacturer"])
    if upnp.get("modelName"):
        mn, num = upnp["modelName"], upnp.get("modelNumber")
        digits = re.findall(r"\d{3,}", mn)
        same = num and (num in mn or mn in num or any(x in num for x in digits))
        model = model or (mn + (" " + num if num and not same and len(num) < 20 else ""))
    for s in mdns.get("services", []):
        for t, w in MDNS_TYPES.get(s, []):
            if not (shared and t == "printer"):
                vote(t, w)
    for port in ports:
        for t, w in PORT_TYPES.get(port, []):
            vote(t, w)
    if 5000 in ports and 5001 in ports:
        vote("server", 5)
    if vendor:
        low = vendor.lower()
        for rx, votes in VENDOR_TYPES:
            if re.search(rx, low):
                for t, w in votes:
                    vote(t, w)
    router = d.get("router") or {}
    rname = (d.get("dhcp") or {}).get("hostname") or router.get("name")
    rtype = freebox.HOST_TYPES.get(router.get("host_type"))
    if rtype:
        vote(rtype, 10)  # type known to the router (Freebox host_type)
    if not vendor and router.get("vendor"):
        vendor = router["vendor"]
    names = [x for x in (d.get("hostname"), mdns.get("hostname"), nb.get("name"), upnp.get("friendlyName"),
                         gc.get("fn"), rname) if x]
    names += list((mdns.get("instances") or {}).values())
    joined = " ".join(names).lower()
    for rx, votes in NAME_TYPES:
        if re.search(rx, joined):
            for t, w in votes:
                vote(t, w)
    fire = re.search(r"\b(?:\w+-)?(AFT[A-Z0-9]{1,6})\b", " ".join(names + [upnp.get("modelName") or ""]))
    if fire:  # Amazon Fire TV model codes (AFTSS, AFTMM, AFTKA, ...)
        code = fire.group(1)
        brand = "Amazon"
        model = "%s (%s)" % (FIRE_TV[code], code) if code in FIRE_TV else "Fire TV (%s)" % code
        vote("media", 8)
    for h in https:
        blob = " ".join(x for x in (h.get("title"), h.get("server")) if x).lower()
        for rx, (t, w) in HTTP_TYPES:
            if re.search(rx, blob):
                vote(t, w)
        m = re.search(r"(FRITZ!(?:Box|Repeater|Powerline)[\w ]*\d[\w ]*)", h.get("title") or "")
        if m:
            model = model or m.group(1).strip()
    if SMART_ASSISTANT.search((model or "") + " " + joined):
        vote("iot", 30)  # declared model beats the generic cast hints
    nb_brand, nb_model = name_model(names)
    if nb_model and not model:
        brand, model = brand or nb_brand, nb_model
    tapo_web = any("SHIP 2.0" in ((h.get("title") or "") + (h.get("server") or "")) for h in https)
    if (vendor and "tp-link" in vendor.lower()) or tapo_web:
        for n in names:
            for rx, t, family in TAPO_MODELS:
                m = re.fullmatch(r"(?:tapo[-_ ]?)?(%s)(?:[-_ ].*)?" % rx, n, re.I)
                if m:
                    brand, model = "TP-Link", model or "Tapo %s (%s)" % (m.group(1).upper(), family)
                    vote(t, 15)
                    break
            else:
                continue
            break
        if tapo_web:
            vote("iot", 8)  # Tapo/Kasa embedded web server
        elif score.get("iot", 0) < 10:
            vote("router", 3)  # plain TP-Link: router / access point / mesh
    box = None
    blob_all = (joined + " " + " ".join("%s %s" % (h.get("title") or "", h.get("server") or "") for h in https)).lower()
    for rx, b_brand, b_model, b_os in ISP_BOXES:
        if re.search(rx, blob_all):
            box = (b_brand, b_model, b_os)
            brand, model = b_brand, model if model and b_model.lower() in model.lower() else b_model
            vote("router", 10)
            break
    if d.get("is_gateway"):
        vote("router", 20)
    if is_random_mac(d.get("mac")) and not d.get("is_self"):
        vote("mobile", 1)  # private Wi-Fi addresses are mostly phones/tablets

    if "printer" in score and (22 in ports or 445 in ports):
        score["printer"] *= 0.3  # real printers hardly ever run ssh or smb
    score.pop("unknown", None)
    if d.get("via_router"):  # remote client reaching the LAN through the router's VPN
        score = {"vpn": 100}
        model = model or "Client VPN"
    if score:
        type_, best = max(score.items(), key=lambda kv: kv[1])
    else:
        type_, best = "unknown", 0
    brand = brand or short_brand(vendor)
    if not brand and nb.get("name") and 3389 in ports:
        brand = "Windows"
    auto_name = (gc.get("fn") or upnp.get("friendlyName") or di.get("name")
                 or next((v for k, v in (mdns.get("instances") or {}).items()
                          if k in ("_device-info._tcp", "_companion-link._tcp", "_airplay._tcp", "_googlecast._tcp",
                                   "_ipp._tcp", "_hap._tcp", "_smb._tcp", "_workstation._tcp")), None)
                 or rname or _clean_host(d.get("hostname")) or _clean_host(mdns.get("hostname")) or nb.get("name"))
    if auto_name and "_workstation._tcp" in (mdns.get("instances") or {}):
        auto_name = re.sub(r"\s*\[[0-9a-f:]{17}\]$", "", auto_name)
    noun = TYPE_NOUNS[type_]
    if brand and model:
        fallback = model if model.lower().startswith(brand.lower()) else "%s %s" % (brand, model)
    elif brand or model:
        fallback = "%s %s" % (brand or model, noun)
    else:
        fallback = noun[0].upper() + noun[1:]
    if box and auto_name and re.search(r"freebox", auto_name, re.I) and box[0] != "Free":
        auto_name = None  # Iliad boxes advertise themselves as "Freebox Server"
    p = dict(p, dhcp_vendor_class=(d.get("dhcp") or {}).get("vendor_class"))
    os_name = (box and box[2]) or (di.get("firmware") and "firmware " + re.sub(r" Rel\..*", "", di["firmware"])) \
        or os_guess(p, apple, fire, " ".join(names), ports, vendor)
    if not os_name:
        m = next((re.match(r"^([\w!][\w! .-]{1,30}) OS$", h.get("title") or "") for h in https
                  if re.match(r"^[\w!][\w! .-]{1,30} OS$", h.get("title") or "")), None)
        os_name = m.group(0) if m else None
    return {
        "display_name": auto_name or fallback,
        "os": os_name,
        "local": local or None,
        "type": type_,
        "type_guess": best < 4,
        "brand": brand,
        "model": model,
        "auto_name": auto_name,
        "vendor": vendor,
        "shared_printer": shared,
    }
