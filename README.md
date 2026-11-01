# lanman

Un semplicissimo LAN manager: scansiona la sottorete locale (ping sweep + tabella ARP)
e mostra tutti i dispositivi in un pannello web minimale sulla porta **7780**.

- Python 3 solo stdlib, un unico file (`lanman.py`), nessuna dipendenza
- stato online/offline, IP, hostname, MAC, ultimo avvistamento
- riconoscimento di **tipologia, marca e modello**: produttore dal MAC (database Wireshark,
  scaricato in `~/.lanman/manuf`), mDNS/Bonjour, UPnP/SSDP, NetBIOS, porte aperte, titolo web,
  dati pubblici delle interfacce web (es. TP-Link: modello, hardware, firmware dei range extender)
- lista raggruppata per tipologia (router, server/NAS, computer, smartphone, TV/media,
  stampanti, telecamere, domotica, console, sconosciuti)
- cache per MAC address: l'identificazione sopravvive ai cambi di IP e viene rifatta
  solo per dispositivi nuovi, con IP cambiato, ogni 6 ore o su richiesta
- clic su un dispositivo: scheda di dettaglio con pulsante "Copia scheda" (testo negli appunti)
- connessione **Wi-Fi / cavo / VPN** con icona: dalla tabella host del router (FRITZ!Box via TR-064,
  senza password), MAC privati, tempi di risposta (se l'host di lanman è cablato), modelli solo Wi-Fi
- sola lettura: la classificazione è automatica e non modificabile dal pannello
- scansione automatica ogni 60s o manuale dal pulsante
- dati salvati in `~/.lanman/devices.json`

## Avvio

    python3 lanman.py [--port 7780] [--iface eth0] [--interval 60]

## Deploy

    ./deploy.sh            # default 192.168.144.44, servizio systemd utente

Per l'avvio automatico al boot serve una volta sul server:
`sudo loginctl enable-linger $USER`

## Associazione con Iliadbox / Freebox (facoltativa)

    python3 lanman.py --pair

Invia al box una richiesta di accesso per l'app "lanman", da confermare sul box
(display o app iliadbox). Il token viene salvato in `~/.lanman/freebox.json` (permessi 600)
ed è revocabile dall'interfaccia del box. lanman lo usa solo per leggere l'elenco dei
dispositivi (nomi DHCP, Wi-Fi/cavo, tipo di dispositivo). Il FRITZ!Box non richiede associazione.

## Nomi dei telefoni (ascolto DHCP, facoltativo)

Gli Android/iPhone moderni non espongono nulla in rete: il loro nome (es. "Galaxy-Note9-di-…")
viaggia solo nella richiesta DHCP che inviano in broadcast quando si collegano al Wi-Fi.
lanman la legge in modo passivo se può ascoltare sulla porta 67:

    sudo ./install-system.sh            # servizio di sistema, gira col tuo utente + CAP_NET_BIND_SERVICE
    sudo ./install-system.sh --remove   # torna al servizio utente

Senza questo passo l'ascolto DHCP resta semplicemente disattivato.

## Notifiche ntfy (facoltative)

lanman invia su [ntfy](https://ntfy.sh) i nuovi dispositivi e i passaggi online/offline
(offline = nessun avvistamento da 15 minuti). Solo invio, nessun controllo remoto.
Il canale si configura per installazione:

    echo piave49 > ~/.lanman/ntfy        # topic su ntfy.sh, oppure un URL completo
    # oppure: LANMAN_NTFY=piave49

## API

- `GET  /api/devices` — elenco dispositivi
- `POST /api/scan` — avvia una scansione
