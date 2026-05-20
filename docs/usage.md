# Usage Guide

## Quick Start

```bash
# 1. Install
pip install -e ".[dev]"

# 2. Configure
cp config/config.example.yaml config/config.yaml

# 3. Start monitoring + dashboard
sudo homenetguard start
# → Open http://127.0.0.1:5000
```

## Command Reference

### `homenetguard start`

Starts packet capture and (optionally) the dashboard.

```bash
# Auto-detect interface, indefinite capture
sudo homenetguard start

# Specific interface, 5 minute capture
sudo homenetguard start --interface eth0 --duration 300

# Save capture to file, no dashboard
sudo homenetguard start --output data/captures/session.pcap --no-dashboard
```

### `homenetguard dashboard`

Launch the web UI without capturing traffic (useful for reviewing stored data).

```bash
homenetguard dashboard --port 8080
```

### `homenetguard analyze`

Analyze a saved .pcap file.

```bash
homenetguard analyze --file session.pcap
homenetguard analyze --file session.pcap --report   # also generate HTML report
```

### `homenetguard report`

Generate a report from stored data.

```bash
homenetguard report --type daily
homenetguard report --type weekly --format pdf
homenetguard report --type custom --from 2026-05-01 --to 2026-05-14 --format both
```

### `homenetguard alerts`

```bash
homenetguard alerts --list                    # show unacknowledged alerts
homenetguard alerts --acknowledge 5           # ack alert #5
homenetguard alerts --clear-all               # clear all
```

### `homenetguard status`

Shows current system state — interface, flow count, alert count.

### `homenetguard config`

```bash
homenetguard config --show     # dump current config (passwords masked)
homenetguard config --init     # create config.yaml from template
```

## Running Without Root

### Linux (CAP_NET_RAW)

```bash
sudo setcap cap_net_raw+eip $(which python3)
homenetguard start   # no sudo needed
```

### macOS (access_bpf group)

```bash
sudo dseditgroup -o edit -a $USER -t user access_bpf
# Log out and back in, then:
homenetguard start   # no sudo needed
```

## Terminal de Comandos

El terminal de HomeNetGuard es un panel de comandos accesible desde cualquier página del dashboard.

### Abrir el terminal

- **Atajo de teclado:** `Ctrl+\``
- **Barra de búsqueda:** Haz clic en `CMD_SEARCH...` en la barra superior
- **Click-to-fill:** Haz clic en cualquier IP, MAC o dominio en las tablas del dashboard

### Comandos de aplicación

```
block 192.168.1.50 malicious host    # Bloquea IP en el firewall
unblock 192.168.1.50                 # Elimina regla por IP o ID
quarantine aa:bb:cc:dd:ee:ff         # Pone dispositivo en cuarentena
release aa:bb:cc:dd:ee:ff            # Libera cuarentena
sinkhole evil.com                    # Bloquea dominio en DNS sinkhole
unsinkhole evil.com                  # Elimina del sinkhole
flows 192.168.1.50                   # Últimos flows de esa IP
alerts 192.168.1.50                  # Alertas activas (filtradas por IP)
whois 8.8.8.8                        # Geo + organización + reputación
devices                              # Lista dispositivos conocidos
help                                 # Muestra todos los comandos
```

### Utilidades de red

```
ping 8.8.8.8 -c 4                   # Ping (máx. 10 paquetes)
dig example.com MX                   # DNS lookup (A/AAAA/MX/TXT/NS)
nslookup example.com                 # Resolución DNS
traceroute 1.1.1.1                   # Ruta de red
nmap 192.168.1.1 -sn                 # Ping scan (solo IPs individuales)
nmap 192.168.1.1 -p 80,443           # Scan de puertos específicos
```

### Seguridad

El terminal nunca ejecuta comandos de shell directamente. El servidor valida cada comando contra una lista cerrada de operaciones permitidas antes de ejecutar nada. Los caracteres de shell (`&&`, `|`, `;`, `>`, `$(`, `` ` ``) son rechazados tanto en el navegador como en el servidor. Los comandos de red se ejecutan con `subprocess(shell=False)` con argumentos tipados, sin herencia de variables de entorno.
