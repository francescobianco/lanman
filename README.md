# lanman

Un semplicissimo LAN manager: scansiona la sottorete locale (ping sweep + tabella ARP)
e mostra tutti i dispositivi in un pannello web minimale sulla porta **7780**.

- Python 3 solo stdlib, un unico file (`lanman.py`), nessuna dipendenza
- stato online/offline, IP, hostname, MAC, ultimo avvistamento
- riconoscimento di **tipologia, marca e modello**: produttore dal MAC (database Wireshark,
  scaricato in `~/.lanman/manuf`), mDNS/Bonjour, UPnP/SSDP, NetBIOS, porte aperte, titolo web
- lista raggruppata per tipologia (router, server/NAS, computer, smartphone, TV/media,
  stampanti, telecamere, domotica, console, sconosciuti)
- cache per MAC address: l'identificazione sopravvive ai cambi di IP e viene rifatta
  solo per dispositivi nuovi, con IP cambiato, ogni 6 ore o su richiesta
- clic su un dispositivo: dettagli, nome personalizzato, tipologia manuale, "identifica di nuovo"
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
- `POST /api/devices/<id>` (id = MAC) — `{"name": "..."}`, `{"type": "printer"}` (`""` = automatico),
  `{"reprobe": true}`, `{"forget": true}`
