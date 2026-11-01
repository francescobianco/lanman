#!/usr/bin/env bash
# Install lanman as a system service so it can passively read DHCP requests
# (port 67). It still runs as your user, with only CAP_NET_BIND_SERVICE added.
#
#   sudo ./install-system.sh            # install / update
#   sudo ./install-system.sh --remove   # back to the plain user service
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
RUN_USER="${SUDO_USER:?run with sudo from your user}"
DIR="$(cd "$(dirname "$0")" && pwd)"
HOME_DIR="$(getent passwd "$RUN_USER" | cut -d: -f6)"
UNIT=/etc/systemd/system/lanman.service
user_systemctl() { sudo -u "$RUN_USER" XDG_RUNTIME_DIR="/run/user/$(id -u "$RUN_USER")" systemctl --user "$@"; }

if [ "${1:-}" = "--remove" ]; then
  systemctl disable --now lanman 2>/dev/null || true
  rm -f "$UNIT"; systemctl daemon-reload
  echo "system service removed (re-enable the user one with: systemctl --user enable --now lanman)"
  exit 0
fi

# stop the user-level instance (unit or transient) so port 7780 is free
user_systemctl disable --now lanman 2>/dev/null || user_systemctl stop lanman 2>/dev/null || true

cat > "$UNIT" <<UNIT
[Unit]
Description=lanman - tiny LAN manager
After=network-online.target
Wants=network-online.target

[Service]
User=$RUN_USER
Environment=LANMAN_DATA=$HOME_DIR/.lanman
ExecStart=/usr/bin/python3 $DIR/lanman.py --port 7780
Restart=always
RestartSec=5
# only extra right: bind port 67 to read DHCP broadcasts
AmbientCapabilities=CAP_NET_BIND_SERVICE
# upper bound for the whole service (ping needs NET_RAW via its file caps / setuid)
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=$HOME_DIR/.lanman
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
UNIT
mkdir -p "$HOME_DIR/.lanman" && chown "$RUN_USER:" "$HOME_DIR/.lanman"
systemctl daemon-reload
systemctl enable lanman
systemctl restart lanman
sleep 3
systemctl --no-pager status lanman | head -5
journalctl -u lanman --no-pager -n 5 | grep -E "dhcp|lanman on" || true
