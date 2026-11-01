"""Freebox OS API client (Iliadbox, Freebox) for lanman.

Read-only use: lanman only lists the LAN hosts the box knows about.
Pairing is a one-off, user-confirmed step:

    python3 lanman.py --pair

The box shows an authorization request (on its display or in the iliadbox /
Freebox Connect app); once accepted, the app token is stored in
~/.lanman/freebox.json (mode 600) and can be revoked from the box UI.
"""
import hashlib
import hmac
import json
import os
import socket
import time
import urllib.error
import urllib.request

APP_ID = "lanman"
APP_NAME = "lanman"
APP_VERSION = "1"

HOST_TYPES = {  # Freebox host_type -> lanman type
    "workstation": "computer", "laptop": "computer", "smartphone": "mobile", "tablet": "mobile",
    "printer": "printer", "vg_console": "console", "television": "media", "nas": "server",
    "ip_camera": "camera", "ip_phone": "iot", "freebox_player": "media", "freebox_hd": "media",
    "freebox_crystal": "media", "freebox_mini": "media", "freebox_delta": "media", "freebox_one": "media",
    "freebox_wifi": "router", "freebox_pop": "media", "networking_device": "router",
    "multimedia_device": "media", "car": "iot",
}


def api_version(gw):
    """Public box info, no auth. -> dict or None"""
    try:
        with urllib.request.urlopen("http://%s/api_version" % gw, timeout=3) as r:
            info = json.loads(r.read(8192))
        return info if info.get("api_base_url") else None
    except Exception:
        return None


def _base(gw, info):
    major = int(float(info.get("api_version", "8")))
    return "http://%s%sv%d/" % (gw, info["api_base_url"], major)


def _call(url, data=None, token=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-Fbx-App-Auth"] = token
    req = urllib.request.Request(url, data=json.dumps(data).encode() if data is not None else None,
                                 headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return json.loads(r.read(4 * 1024 * 1024))
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read(65536))
        except Exception:
            return {"success": False, "error_code": "http_%d" % e.code}


def pair(gw, path, wait=180):
    """Request an app token and wait for the user to accept it on the box."""
    info = api_version(gw)
    if not info:
        print("Il gateway %s non espone l'API Freebox OS." % gw)
        return False
    base = _base(gw, info)
    r = _call(base + "login/authorize/", {
        "app_id": APP_ID, "app_name": APP_NAME, "app_version": APP_VERSION,
        "device_name": socket.gethostname()})
    if not r.get("success"):
        print("Richiesta rifiutata:", r)
        return False
    token, track = r["result"]["app_token"], r["result"]["track_id"]
    print("Richiesta inviata a %s (%s)." % (info.get("box_model_name"), gw))
    print("Conferma l'accesso di \"lanman\" sul box (display o app iliadbox). Attendo fino a %ds..." % wait)
    deadline = time.time() + wait
    status = "pending"
    while time.time() < deadline:
        status = (_call(base + "login/authorize/%d" % track).get("result") or {}).get("status")
        if status != "pending":
            break
        time.sleep(2)
    if status != "granted":
        print("Associazione non riuscita: stato '%s'." % status)
        return False
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({"gateway": gw, "uid": info.get("uid"), "app_token": token}, f)
    print("Associato. Token salvato in %s (revocabile dall'interfaccia del box)." % path)
    return True


class Client:
    def __init__(self, path):
        self.path = path
        self.session = None

    def config(self):
        try:
            with open(self.path) as f:
                return json.load(f)
        except (OSError, ValueError):
            return None

    def _login(self, base, app_token):
        ch = (_call(base + "login/").get("result") or {}).get("challenge")
        if not ch:
            return None
        pw = hmac.new(app_token.encode(), ch.encode(), hashlib.sha1).hexdigest()
        r = _call(base + "login/session/", {"app_id": APP_ID, "password": pw})
        return (r.get("result") or {}).get("session_token") if r.get("success") else None

    def hosts(self, gw):
        """-> {mac or "ip:<addr>": {"name", "link", "active", "ip", "host_type", "vendor"}} or None"""
        cfg = self.config()
        if not cfg or cfg.get("gateway") != gw:
            return None
        info = api_version(gw)
        if not info:
            return None
        base = _base(gw, info)
        for _ in range(2):
            if not self.session:
                self.session = self._login(base, cfg["app_token"])
                if not self.session:
                    print("freebox: login failed (token revoked?)", flush=True)
                    return None
            r = _call(base + "lan/browser/pub/", token=self.session)
            if r.get("success"):
                break
            self.session = None  # expired session: log in again once
        else:
            print("freebox: lan browser failed: %s" % r.get("error_code"), flush=True)
            return None
        out = {}
        for h in r.get("result") or []:
            mac = ((h.get("l2ident") or {}).get("id") or "").lower()
            ips = [c.get("addr") for c in h.get("l3connectivities") or []
                   if c.get("af") == "ipv4" and c.get("addr")]
            act = [c.get("addr") for c in h.get("l3connectivities") or []
                   if c.get("af") == "ipv4" and c.get("active")]
            conn = (h.get("access_point") or {}).get("connectivity_type")
            name = h.get("primary_name") or None
            if name and name.lower() == mac.replace(":", "-"):
                name = None
            out[mac or "ip:%s" % (ips[0] if ips else "")] = {
                "name": name,
                "ip": (act or ips or [None])[0],
                "active": bool(h.get("active")),
                "link": {"wifi": "wifi", "ethernet": "wired"}.get(conn),
                "host_type": h.get("host_type"),
                "vendor": h.get("vendor_name") or None,
            }
        return out
