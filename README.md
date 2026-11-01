# lanman

Un semplicissimo LAN manager: scansiona la sottorete locale (ping sweep + tabella ARP)
e mostra tutti i dispositivi in un pannello web minimale sulla porta **7780**.

- Python 3 solo stdlib, un unico file (`lanman.py`), nessuna dipendenza
- stato online/offline, IP, hostname (DNS inverso), MAC, ultimo avvistamento
- nomi personalizzati (clic sul nome), "dimentica" dispositivi offline
- scansione automatica ogni 60s o manuale dal pulsante
- dati salvati in `~/.lanman/devices.json`

## Avvio

    python3 lanman.py [--port 7780] [--iface eth0] [--interval 60]

## Deploy

    ./deploy.sh            # default 192.168.144.44, servizio systemd utente

Per l'avvio automatico al boot serve una volta sul server:
`sudo loginctl enable-linger $USER`

## API

- `GET  /api/devices` — elenco dispositivi
- `POST /api/scan` — avvia una scansione
- `POST /api/devices/<ip>` — `{"name": "..."}` rinomina, `{"forget": true}` rimuove
