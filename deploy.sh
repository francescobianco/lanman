#!/usr/bin/env bash
# Deploy lanman to a remote host as a systemd user service.
#   ./deploy.sh [user@host]      (default: 192.168.144.44)
set -euo pipefail
HOST="${1:-192.168.144.44}"
cd "$(dirname "$0")"
ssh "$HOST" 'mkdir -p ~/lanman ~/.config/systemd/user'
rsync -a lanman.py identify.py index.html "$HOST":lanman/
rsync -a deploy/lanman.service "$HOST":.config/systemd/user/
ssh "$HOST" 'systemctl --user daemon-reload && systemctl --user enable lanman && systemctl --user restart lanman
  loginctl enable-linger 2>/dev/null || echo "WARN: run once: sudo loginctl enable-linger $USER  (start at boot)"
  sleep 2; systemctl --user --no-pager status lanman | head -5'
echo "→ http://${HOST#*@}:7780"
