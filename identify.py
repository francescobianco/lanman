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
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor

# ------------------------------------------------------------ device types --
TYPES = [
    ("router", "Router e rete"),
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
PROBE_VERSION = 2  # bump when probes change: cached devices get re-identified
TYPE_NOUNS = {
    "router": "router", "server": "server", "computer": "computer", "mobile": "smartphone/tablet",
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
def ssdp_search(self_ip, timeout=3):
    """-> {ip: {"locations": [...], "server": str}}"""
    res = {}
    msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\n"
           "MX: 2\r\nST: ssdp:all\r\n\r\n").encode()

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
        for _ in range(2):
            s.sendto(msg, ("239.255.255.250", 1900))
        _recv_all(s, timeout, handle)
    return res


def _xml_tag(xml, tag):
    m = re.search(r"<(?:\w+:)?%s>\s*(.*?)\s*</(?:\w+:)?%s>" % (tag, tag), xml, re.S)
    return html.unescape(m.group(1)).strip()[:80] if m and m.group(1).strip() else None


def upnp_describe(ip, locations):
    out = {"device_types": []}
    for loc in locations:
        m = re.match(r"https?://([\d.]+)[:/]", loc)
        if not m or m.group(1) != ip:
            continue
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
    server = r.getheader("Server")
    if not title and not server:
        return None
    return {"port": port, "title": title, "server": server}


# ------------------------------------------------------------ probe round ---
def probe(self_ip, all_ips, targets):
    """Run every probe. Network-wide ones (mDNS, SSDP) cover all_ips, the
    per-host ones (NetBIOS, ports, HTTP, UPnP description) only targets.

    -> {ip: partial probe dict}
    """
    out = {}
    with ThreadPoolExecutor(max_workers=3) as ex:
        f_mdns = ex.submit(mdns_browse, self_ip, all_ips)
        f_ssdp = ex.submit(ssdp_search, self_ip)
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
        if 22 in ports.get(ip, []):
            jobs.append(("ssh", ip, None))
    for ip, v in ssdp.items():
        if ip in all_ips:
            out.setdefault(ip, {})["ssdp_server"] = v["server"]
            if ip in targets:
                jobs.append(("upnp", ip, v["locations"]))

    def run(job):
        kind, ip, arg = job
        if kind == "ssh":
            return job, ssh_banner(ip)
        return job, (http_info(ip, arg) if kind == "http" else upnp_describe(ip, arg))

    with ThreadPoolExecutor(max_workers=16) as ex:
        for (kind, ip, _), r in ex.map(run, jobs):
            if not r:
                continue
            if kind == "ssh":
                out.setdefault(ip, {})["ssh"] = r
            elif kind == "http":
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
     r"linksys|tenda|juniper|draytek|fortinet|eero|cisco|d-link|netgear|tp-link|askey", [("router", 4)]),
    (r"tp-link|tuya", [("iot", 2)]),
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
     r"homepod|echo|alexa|google-?home|nest-?(hub|mini|audio)|soundbar|speaker", [("media", 6)]),
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
    ("AudioAccessory", "HomePod", "media"),
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
    names = [x for x in (d.get("hostname"), mdns.get("hostname"), nb.get("name"), upnp.get("friendlyName"),
                         gc.get("fn")) if x]
    names += list((mdns.get("instances") or {}).values())
    joined = " ".join(names).lower()
    for rx, votes in NAME_TYPES:
        if re.search(rx, joined):
            for t, w in votes:
                vote(t, w)
    fire = re.search(r"\b(?:\w+-)?(AFT[A-Z0-9]{1,6})\b", " ".join(names))
    if fire:  # Amazon Fire TV model codes (AFTSS, AFTMM, AFTKA, ...)
        brand, model = brand if brand != "Apple" else None, "Fire TV (%s)" % fire.group(1)
        vote("media", 8)
    for h in https:
        blob = " ".join(x for x in (h.get("title"), h.get("server")) if x).lower()
        for rx, (t, w) in HTTP_TYPES:
            if re.search(rx, blob):
                vote(t, w)
        m = re.search(r"(FRITZ!(?:Box|Repeater|Powerline)[\w ]*\d[\w ]*)", h.get("title") or "")
        if m:
            model = model or m.group(1).strip()
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
    if score:
        type_, best = max(score.items(), key=lambda kv: kv[1])
    else:
        type_, best = "unknown", 0
    brand = brand or short_brand(vendor)
    if not brand and nb.get("name") and 3389 in ports:
        brand = "Windows"
    auto_name = (gc.get("fn") or upnp.get("friendlyName")
                 or next((v for k, v in (mdns.get("instances") or {}).items()
                          if k in ("_device-info._tcp", "_companion-link._tcp", "_airplay._tcp", "_googlecast._tcp",
                                   "_ipp._tcp", "_hap._tcp", "_smb._tcp", "_workstation._tcp")), None)
                 or _clean_host(d.get("hostname")) or _clean_host(mdns.get("hostname")) or nb.get("name"))
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
    os_name = (box and box[2]) or os_guess(p, apple, fire, " ".join(names), ports, vendor)
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
