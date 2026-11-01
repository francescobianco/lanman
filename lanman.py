#!/usr/bin/env python3
"""lanman - a tiny LAN manager.

Periodically ping-sweeps the local subnet, reads the kernel neighbour table
for MAC addresses and shows every device seen on a minimal web panel.

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

DATA_DIR = os.environ.get("LANMAN_DATA", os.path.expanduser("~/.lanman"))
DB_FILE = os.path.join(DATA_DIR, "devices.json")

lock = threading.Lock()
devices = {}  # ip -> dict
state = {"iface": None, "network": None, "self_ip": None, "last_scan": None, "scanning": False}
scan_now = threading.Event()


# ---------------------------------------------------------------- network ---
def sh(*cmd):
    return subprocess.run(cmd, capture_output=True, text=True).stdout


def detect_iface():
    """First default-route interface with a real MAC (skips tun/VPN links)."""
    devs = re.findall(r"\bdev (\S+)", sh("ip", "-4", "route", "show", "default"))
    for dev in devs:
        mac = own_mac(dev)
        if mac and mac != "00:00:00:00:00:00":
            return dev
    return devs[0] if devs else None


def iface_network(iface):
    m = re.search(r"inet (\S+)", sh("ip", "-4", "-o", "addr", "show", "dev", iface))
    if not m:
        raise SystemExit("no IPv4 address on %s" % iface)
    itf = ipaddress.ip_interface(m.group(1))
    net = itf.network
    if net.num_addresses > 1024:  # don't sweep huge subnets
        net = ipaddress.ip_network("%s/22" % itf.ip, strict=False)
    return str(itf.ip), net


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


def own_mac(iface):
    try:
        with open("/sys/class/net/%s/address" % iface) as f:
            return f.read().strip().lower()
    except OSError:
        return None


def resolve(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


# ------------------------------------------------------------------- scan ---
def scan():
    iface, net = state["iface"], state["network"]
    state["scanning"] = True
    hosts = [str(h) for h in net.hosts()]
    with ThreadPoolExecutor(max_workers=64) as ex:
        alive = {ip for ip, ok in zip(hosts, ex.map(ping, hosts)) if ok}
    neigh = neighbours(iface)
    # a host is online if it answered ping or the kernel just saw it
    online = alive | set(neigh)
    online.add(state["self_ip"])
    neigh[state["self_ip"]] = own_mac(iface)
    ips = sorted(online)
    with ThreadPoolExecutor(max_workers=16) as ex:
        names = dict(zip(ips, ex.map(resolve, ips)))

    now = int(time.time())
    with lock:
        for ip in online:
            d = devices.setdefault(ip, {"ip": ip, "first_seen": now, "name": ""})
            d["last_seen"] = now
            d["online"] = True
            d["ping"] = ip in alive
            if neigh.get(ip):
                d["mac"] = neigh[ip]
            if names.get(ip):
                d["hostname"] = names[ip]
        for ip, d in devices.items():
            if ip not in online:
                d["online"] = False
                d["ping"] = False
        state["last_scan"] = now
        save()
    state["scanning"] = False


def scanner(interval):
    while True:
        try:
            scan()
        except Exception as e:  # keep the loop alive
            state["scanning"] = False
            print("scan error:", e, flush=True)
        scan_now.wait(interval)
        scan_now.clear()


def load():
    try:
        with open(DB_FILE) as f:
            devices.update(json.load(f))
    except (OSError, ValueError):
        pass


def save():
    os.makedirs(DATA_DIR, exist_ok=True)
    tmp = DB_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(devices, f, indent=1)
    os.replace(tmp, DB_FILE)


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
            return self.send(200, PAGE, "text/html")
        if self.path == "/api/devices":
            with lock:
                payload = {
                    "iface": state["iface"],
                    "network": str(state["network"]),
                    "self_ip": state["self_ip"],
                    "last_scan": state["last_scan"],
                    "scanning": state["scanning"],
                    "devices": list(devices.values()),
                }
            return self.send(200, json.dumps(payload))
        self.send(404, '{"error":"not found"}')

    def do_POST(self):
        if self.path == "/api/scan":
            scan_now.set()
            return self.send(202, '{"ok":true}')
        m = re.fullmatch(r"/api/devices/([\d.]+)", self.path)
        if m:
            length = int(self.headers.get("Content-Length") or 0)
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
            except ValueError:
                return self.send(400, '{"error":"bad json"}')
            with lock:
                d = devices.get(m.group(1))
                if not d:
                    return self.send(404, '{"error":"unknown device"}')
                if body.get("forget"):
                    del devices[m.group(1)]
                elif "name" in body:
                    d["name"] = str(body["name"])[:64]
                save()
            return self.send(200, '{"ok":true}')
        self.send(404, '{"error":"not found"}')


PAGE = r"""<!doctype html>
<html lang="it"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>lanman</title>
<style>
:root{--bg:#fafafa;--fg:#222;--mut:#888;--line:#e5e5e5;--on:#1a9c4b;--off:#c9c9c9;--acc:#2a6df4}
@media (prefers-color-scheme:dark){:root{--bg:#141414;--fg:#e6e6e6;--mut:#8a8a8a;--line:#2a2a2a;--off:#444}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.4 system-ui,sans-serif}
main{max-width:960px;margin:0 auto;padding:24px 16px}
header{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap;margin-bottom:16px}
h1{font-size:20px;margin:0}
.mut{color:var(--mut)}
.sp{flex:1}
button{font:inherit;background:none;border:1px solid var(--line);color:var(--fg);border-radius:6px;padding:4px 10px;cursor:pointer}
button:hover{border-color:var(--acc)}
input{font:inherit;background:none;border:1px solid var(--line);color:var(--fg);border-radius:6px;padding:4px 8px}
.wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:8px 6px;border-bottom:1px solid var(--line);white-space:nowrap}
th{font-weight:500;color:var(--mut);font-size:12px;text-transform:uppercase;letter-spacing:.04em;cursor:pointer;user-select:none}
td.n{cursor:text}
tr.off td{color:var(--mut)}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--off)}
tr.on .dot{background:var(--on)}
code{font:12px ui-monospace,monospace}
.x{border:0;color:var(--mut);padding:0 4px}
.tag{font-size:11px;color:var(--mut);border:1px solid var(--line);border-radius:4px;padding:0 4px;margin-left:4px}
</style></head><body><main>
<header>
  <h1>lanman</h1><span class="mut" id="net"></span><span class="sp"></span>
  <span class="mut" id="cnt"></span>
  <label class="mut"><input type="checkbox" id="onlyOn"> solo online</label>
  <button id="scan">Scansiona</button>
</header>
<div class="wrap"><table>
<thead><tr><th></th><th data-k="ip">IP</th><th data-k="label">Nome</th><th data-k="mac">MAC</th><th data-k="last_seen">Visto</th><th></th></tr></thead>
<tbody id="tb"></tbody></table></div>
<p class="mut" id="foot"></p>
</main>
<script>
let data={devices:[]},sortK='ip',sortD=1;
const $=s=>document.querySelector(s);
const ipn=ip=>ip.split('.').reduce((a,b)=>a*256+ +b,0);
const ago=t=>{if(!t)return'';const s=Date.now()/1000-t;
  if(s<90)return'ora';if(s<3600)return Math.round(s/60)+' min fa';
  if(s<86400)return Math.round(s/3600)+' h fa';return Math.round(s/86400)+' g fa'};
const esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const label=d=>d.name||d.hostname||'';
try{$('#onlyOn').checked=localStorage.lanmanOnly==='1'}catch(e){}

function render(){
  let ds=data.devices.slice();
  if($('#onlyOn').checked)ds=ds.filter(d=>d.online);
  ds.sort((a,b)=>{
    if(a.online!==b.online)return a.online?-1:1;
    let x,y;
    if(sortK==='ip'){x=ipn(a.ip);y=ipn(b.ip)}
    else if(sortK==='label'){x=label(a).toLowerCase();y=label(b).toLowerCase()}
    else{x=a[sortK]||'';y=b[sortK]||''}
    return (x<y?-1:x>y?1:0)*sortD});
  $('#tb').innerHTML=ds.map(d=>{
    const me=d.ip===data.self_ip?'<span class="tag">questo host</span>':'';
    const rnd=d.mac&&/^.[26ae]/.test(d.mac)?'<span class="tag" title="MAC randomizzato">rnd</span>':'';
    const sub=d.name&&d.hostname?` <span class="mut">${esc(d.hostname)}</span>`:'';
    return `<tr class="${d.online?'on':'off'}">
      <td><span class="dot" title="${d.online?(d.ping?'online':'online (no ping)'):'offline'}"></span></td>
      <td><code>${esc(d.ip)}</code>${me}</td>
      <td class="n" data-ip="${esc(d.ip)}" title="clic per rinominare">${esc(label(d))||'<span class="mut">—</span>'}${sub}</td>
      <td><code>${esc(d.mac)}</code>${rnd}</td>
      <td title="primo: ${new Date(d.first_seen*1000).toLocaleString()}">${d.online?'online':ago(d.last_seen)}</td>
      <td>${d.online?'':`<button class="x" data-forget="${esc(d.ip)}" title="dimentica">×</button>`}</td></tr>`}).join('');
  const on=data.devices.filter(d=>d.online).length;
  $('#cnt').textContent=`${on} online / ${data.devices.length}`;
  $('#net').textContent=`${data.network||''} su ${data.iface||''}`;
  $('#foot').textContent=data.scanning?'scansione in corso…':
    (data.last_scan?'ultima scansione: '+new Date(data.last_scan*1000).toLocaleTimeString():'');
}
async function load(){try{data=await (await fetch('/api/devices')).json();render()}catch(e){$('#foot').textContent='server non raggiungibile'}}
async function post(u,b){await fetch(u,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b||{})})}

$('#scan').onclick=async()=>{await post('/api/scan');setTimeout(load,500)};
$('#onlyOn').onchange=()=>{try{localStorage.lanmanOnly=$('#onlyOn').checked?'1':'0'}catch(e){}render()};
document.querySelectorAll('th[data-k]').forEach(th=>th.onclick=()=>{
  sortD=sortK===th.dataset.k?-sortD:1;sortK=th.dataset.k;render()});
$('#tb').onclick=async e=>{
  const f=e.target.closest('[data-forget]');
  if(f){await post('/api/devices/'+f.dataset.forget,{forget:true});return load()}
  const td=e.target.closest('td.n');if(!td||td.querySelector('input'))return;
  const d=data.devices.find(x=>x.ip===td.dataset.ip);
  td.innerHTML=`<input value="${esc(d.name)}" placeholder="${esc(d.hostname||'nome')}">`;
  const i=td.firstChild;i.focus();
  const done=async ok=>{if(ok)await post('/api/devices/'+d.ip,{name:i.value.trim()});load()};
  i.onkeydown=ev=>{if(ev.key==='Enter')done(true);if(ev.key==='Escape')done(false)};
  i.onblur=()=>done(true);
};
load();setInterval(()=>{if(!document.querySelector('td.n input'))load()},5000);
</script></body></html>
"""


def main():
    ap = argparse.ArgumentParser(description="tiny LAN manager")
    ap.add_argument("--port", type=int, default=int(os.environ.get("LANMAN_PORT", 7780)))
    ap.add_argument("--bind", default=os.environ.get("LANMAN_BIND", "0.0.0.0"))
    ap.add_argument("--iface", default=os.environ.get("LANMAN_IFACE"))
    ap.add_argument("--interval", type=int, default=int(os.environ.get("LANMAN_INTERVAL", 60)))
    a = ap.parse_args()

    state["iface"] = a.iface or detect_iface()
    if not state["iface"]:
        raise SystemExit("cannot detect interface, use --iface")
    state["self_ip"], state["network"] = iface_network(state["iface"])
    load()
    threading.Thread(target=scanner, args=(a.interval,), daemon=True).start()
    print("lanman on http://%s:%d  (%s, %s)" % (a.bind, a.port, state["iface"], state["network"]), flush=True)
    ThreadingHTTPServer((a.bind, a.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
