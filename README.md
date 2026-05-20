# HomeNetGuard

[![CI](https://github.com/sergioflores/homenetguard/actions/workflows/ci.yml/badge.svg)](https://github.com/sergioflores/homenetguard/actions)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**Open-source network security monitor for home and personal use.** Capture, analyze, and audit network traffic in real time from any Linux or macOS machine — no cloud required, no subscriptions, all data stays local.

HomeNetGuard gives you full visibility into what's happening on your network: which IPs communicate with your machine, what protocols are in use, whether there are known threats, what domains are being resolved, and how much traffic each connection generates.

## ⚠️ Legal Notice

> **HomeNetGuard is intended for use ONLY on networks you own or have explicit written permission to monitor.**
> Capturing network traffic on networks you do not own or without authorization may violate local laws (CFAA, GDPR, and similar legislation). The authors and contributors assume no liability for unauthorized use.

---

## Features

- 🔍 **Real-time packet capture** — Scapy-powered live sniffing with automatic interface detection
- 🛡 **Threat detection** — Port scans, traffic floods, beaconing, ARP spoofing, DNS tunneling, blacklisted IPs
- 🌍 **Geolocation** — Offline MaxMind GeoLite2 IP geolocation (no API calls)
- 📊 **Cyber SOC dashboard** — Dark-mode real-time web UI with Chart.js traffic graphs and Leaflet world map
- 🔔 **Alerts** — Email and Telegram notifications with configurable severity thresholds
- 📋 **Reports** — Auto-generated HTML and PDF reports (daily, weekly, on-demand)
- 🗄 **Local persistence** — SQLite database, no external dependencies
- 🔎 **DNS analysis** — Query timeline, top domains, anomaly detection
- 🌐 **Reputation checks** — AbuseIPDB integration (optional, free API)
- ⌨️ **Full CLI** — Click-based CLI with 14 command groups
- 🧪 **Tested** — 190 pytest unit tests enforced in CI
- 🖥 **Network device discovery** — ARP scan with vendor lookup (IEEE OUI) and OS fingerprinting
- 🔥 **Integrated firewall** — Block IPs/CIDRs/ports via iptables/nftables/pf from CLI or dashboard
- 🌀 **DNS Sinkhole** — Block malicious domains at DNS level, synced with threat feeds
- 📡 **MITRE ATT&CK mapping** — All alerts mapped to tactics/techniques
- 🤖 **ML anomaly detection** — Isolation Forest trained on traffic baselines
- 📰 **Threat intelligence feeds** — Auto-updated from Feodo Tracker, SSL Blacklist, URLhaus
- 🔌 **REST API + Swagger** — Full REST API at `/api/v1/` with Swagger UI at `/api/docs`
- 📤 **SIEM export** — CEF/syslog to Splunk, Elastic, Graylog
- 🖥 **TUI live monitor** — Rich-based terminal UI (htop-style) with traffic sparklines
- 🔬 **Forensics timeline** — Event timeline per IP or MAC with drill-down
- 🔎 **Deep Packet Inspection** — App-layer protocol identification (HTTP, TLS, SSH, BitTorrent, Stratum)
- 🔐 **JA3/JA3S fingerprinting** — TLS client/server fingerprinting with malicious hash detection
- 🏠 **IP Ownership** — Org/ISP/ASN shown inline via ip-api.com (no API key needed)
- ⌨️ **Dashboard Terminal** — Slide-up command terminal in the web UI. Execute firewall, quarantine, sinkhole, and network diagnostic commands directly from any dashboard page. Click any IP/MAC to pre-fill commands. `Ctrl+\`` to open.

---

## System Requirements

| | Requirement |
|---|---|
| **OS** | Linux (Ubuntu 20.04+, Fedora 36+) or macOS 12+ |
| **Python** | 3.11 or higher |
| **System packages** | `tshark`, `libpcap-dev`, `tc` (iproute2, for rate limiter), `iptables`/`pf` (for firewall) |
| **Privileges** | `sudo` / root, or `CAP_NET_RAW` capability (Linux) / `access_bpf` group (macOS) |
| **RAM** | 256 MB minimum |
| **Disk** | 500 MB (including GeoIP database) |

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/sergioflores/homenetguard.git
cd homenetguard
```

### 2. Create and activate a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate      # Linux/macOS
```

### 3. Install system dependencies

```bash
bash scripts/install_system_deps.sh
```

This installs `tshark`, `libpcap`, and WeasyPrint dependencies.

### 4. Install Python dependencies

```bash
pip install -e ".[dev]"
# or: make install-dev
```

### 5. Configure

```bash
cp config/config.example.yaml config/config.yaml
cp .env.example .env
# Edit config/config.yaml as needed
```

### 6. (Optional) Download GeoIP database

```bash
# Get a free license key at https://www.maxmind.com/en/geolite2/signup
MAXMIND_LICENSE_KEY=your_key bash scripts/download_geoip.sh
```

---

## Configuration

All settings live in `config/config.yaml`. API keys and passwords go in `.env`:

```env
ABUSEIPDB_API_KEY=your_key_here
EMAIL_PASSWORD=your_smtp_password
TELEGRAM_BOT_TOKEN=your_bot_token
```

Key config options:

| Setting | Default | Description |
|---|---|---|
| `network.interface` | `auto` | Network interface to capture on |
| `network.capture_filter` | `""` | BPF filter (e.g. `"not port 22"`) |
| `dashboard.port` | `5000` | Web dashboard port |
| `detection.port_scan.threshold_ports` | `15` | Ports per IP per minute to trigger port scan alert |
| `alerts.email.enabled` | `false` | Enable email alerts |

See [`docs/configuration.md`](docs/configuration.md) for the full reference.

---

## Usage

### Start monitoring

```bash
sudo homenetguard start
# or with venv: sudo .venv/bin/homenetguard start

# On specific interface:
sudo homenetguard start --interface eth0

# For 5 minutes, save capture:
sudo homenetguard start --duration 300 --output captures/session.pcap
```

Expected output:
```
⚠  LEGAL NOTICE: HomeNetGuard is intended for use ONLY on networks you own...

Starting capture on en0 — press Ctrl+C to stop
2026-05-15T10:00:01 | INFO     | Dashboard at http://127.0.0.1:5000
```

### Dashboard only (no capture)

```bash
homenetguard dashboard
# Open http://127.0.0.1:5000 in your browser
```

> **⚠ Common pitfall — dashboard shows no data**
>
> `homenetguard monitor` is an **interactive TUI** (like htop). It **does not capture packets**.
> If you open the dashboard after running `monitor`, the flow table will be empty because nothing was written to the database.
>
> **Rule:** if you want live data in the dashboard, always start with:
> ```bash
> sudo homenetguard start --interface <iface>
> ```
> This starts both the packet sniffer **and** the dashboard together.
> The dashboard polls the database every 2 seconds — you will see flows appear within a few seconds of launch.

### Analyze a PCAP file

```bash
homenetguard analyze --file capture.pcap
homenetguard analyze --file capture.pcap --report
```

### Generate a report

```bash
homenetguard report --type daily --format html
homenetguard report --type weekly --format pdf
homenetguard report --type custom --from 2026-05-01 --to 2026-05-14 --format both
```

### Manage alerts

```bash
homenetguard alerts --list
homenetguard alerts --acknowledge 42
homenetguard alerts --clear-all
```

### System status

```bash
homenetguard status
```

### Configuration

```bash
homenetguard config --show
homenetguard config --init    # create config.yaml from template
```

---

## Dashboard

Access at `http://127.0.0.1:5000` after starting.

**Views:**
- **Overview** — Live traffic graph, protocol distribution, geo map, alert feed
- **Alerts** — Filterable alert list with acknowledge/export
- **Flows** — Paginated flow explorer with IP/protocol filters
- **DNS** — Query timeline, top domains, suspicious domain detection
- **Reports** — Generate and download HTML/PDF reports
- **Config** — Active configuration viewer + integration status

The dashboard uses a dark "Cyber SOC" theme with real-time WebSocket updates every 2 seconds.

---

## Dashboard Terminal

Press **`Ctrl+\``** (or click the `CMD_SEARCH` bar) on any dashboard page to open the terminal overlay.

### App commands

| Command | Description |
|---------|-------------|
| `block <ip> [reason]` | Add firewall block rule |
| `unblock <ip\|rule_id>` | Remove firewall rule |
| `quarantine <mac>` | Quarantine a device |
| `release <mac>` | Release device from quarantine |
| `sinkhole <domain>` | Block domain at DNS level |
| `unsinkhole <domain>` | Remove domain from sinkhole |
| `flows <ip>` | Show recent flows for an IP |
| `alerts [ip]` | Show active alerts |
| `whois <ip>` | Show geo, org, and reputation data |
| `devices` | List all known devices |
| `help` | Show all commands |

### Network utilities

| Command | Description |
|---------|-------------|
| `ping <host> [-c N]` | Ping (max 10 packets) |
| `dig <domain> [type]` | DNS lookup (A/AAAA/MX/TXT/NS) |
| `nslookup <domain>` | DNS name resolution |
| `traceroute <host>` | Trace network path |
| `nmap <ip> [-sn\|-sV\|-p ports]` | Port scan (single IPs only) |

### Shortcuts

| Key | Action |
|-----|--------|
| `Ctrl+\`` | Open / close terminal |
| `Escape` | Close terminal |
| `Tab` | Autocomplete IP / MAC / domain from live DB |
| `↑ / ↓` | Navigate command history |

Click any **IP address**, **MAC address**, or **domain** in the dashboard tables to pre-fill a command in the terminal.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        HomeNetGuard                              │
├──────────────┬──────────────────────────────────────────────────┤
│  Presentation│  CLI (Click) │ Dashboard (Flask+SocketIO) │ Reports│
├──────────────┼──────────────────────────────────────────────────┤
│  Analysis    │  TrafficAnalyzer │ ThreatDetector │ DNSAnalyzer   │
│              │  GeoLookup │ ReputationChecker                    │
├──────────────┼──────────────────────────────────────────────────┤
│  Storage     │  SQLite (WAL mode) │ Repository pattern          │
│              │  Tables: flows, alerts, dns_queries, reputation  │
├──────────────┼──────────────────────────────────────────────────┤
│  Capture     │  Sniffer (Scapy) │ PcapReader (PyShark)          │
│              │  InterfaceDetector                               │
└──────────────┴──────────────────────────────────────────────────┘
```

See [`docs/architecture.md`](docs/architecture.md) for detail.

---

## Contributing

1. Fork the repo and create a feature branch
2. Install dev dependencies: `make install-dev`
3. Write tests first (TDD)
4. Ensure tests pass: `make test`
5. Lint: `make lint`
6. Format: `make format`
7. Open a pull request

### Running tests

```bash
make test              # all tests
make test-cov          # with coverage (requires 70%)
pytest tests/unit/     # unit tests only
```

### Code style

- Black (`line-length = 100`)
- Ruff linting (E, F, I, UP, B rules)
- Type hints on all public functions
- No bare `except` clauses

---

## Roadmap

### v2.0 — Released ✅
- [x] ML anomaly detection (Isolation Forest on traffic baselines)
- [x] DNS Sinkhole with threat feed sync
- [x] Integrated firewall (iptables/pf)
- [x] Network device discovery + OS fingerprinting
- [x] MITRE ATT&CK mapping for all alert types
- [x] Threat intelligence feeds (Feodo Tracker, SSL Blacklist, URLhaus)
- [x] REST API v1 with Swagger UI
- [x] SIEM export (CEF/syslog, Elastic, Graylog)
- [x] TUI live monitor (rich-based)
- [x] JA3/JA3S TLS fingerprinting
- [x] Deep Packet Inspection (HTTP, TLS, SSH, BitTorrent, Stratum/crypto-mining)
- [x] Forensics timeline per IP/MAC
- [x] Compliance checker with security score
- [x] IP quarantine per device MAC

### v2.1
- [ ] Multi-host monitoring (central collector)
- [ ] Docker container deployment
- [ ] Process-to-connection mapping (which app owns each connection)
- [ ] Mobile app companion

### v3.0
- [ ] Vulnerability correlation with CVE database
- [ ] Distributed sensor architecture
- [ ] AI-powered threat hunting

---

## Cyber Academy

HomeNetGuard includes a built-in educational section at `/learn` — **60 articles** covering networking and cybersecurity, anchored to real data from your network.

### Why it's different

Most security education uses abstract examples. Cyber Academy uses **live data from your own network** — queries that run against your HomeNetGuard database and show real numbers from your devices, flows, and alerts. When you read about DNS tunneling, you see how many suspicious DNS queries your network has generated. When you read about beaconing, you see how many C2 alerts HomeNetGuard has detected.

### Structure

| Category | Topics | Levels |
|----------|--------|--------|
| **A — Network Fundamentals** | OSI model, TCP/IP, IP addressing, subnets, DNS, MAC/ARP, TCP handshake, ports, NAT, ICMP, BGP, IPv6 | Beginner → Advanced |
| **B — Security Protocols** | TLS/SSL, SSH, certificates, VPN, firewalls, IDS/IPS, cryptography, Zero Trust, PKI, DoH/DoT | Beginner → Advanced |
| **C — Threats & Attacks** | Port scanning, malware, phishing, DDoS, MITM, ARP spoofing, DNS poisoning, C2 beaconing, data exfiltration, cryptojacking, ransomware, APT, supply chain, LotL, zero-day, lateral movement | Beginner → Advanced |
| **D — Analysis & Forensics** | Logs, packet capture, NetFlow, threat hunting, IOCs, MITRE ATT&CK, SIEM, network forensics | Beginner → Advanced |
| **E — Defenses & Hardening** | CIA triad, defense-in-depth, least privilege, VLANs, CIS benchmarks, vulnerability management, Zero Trust home, STRIDE | Beginner → Advanced |
| **F — Tools & Labs** | Scapy, Nmap, Wireshark, build-your-own-detector | Beginner → Advanced |

### Learning paths

Four guided paths with progress tracking (stored locally in your browser):

- **De cero a monitorizar tu red** — 8 articles, ~90 min, beginner
- **Entiende las amenazas que detecta HomeNetGuard** — 10 articles, ~120 min, intermediate
- **Ciberseguridad defensiva** — 12 articles, ~150 min, intermediate
- **Análisis y forense avanzado** — 8 articles, ~120 min, advanced

### Contextual tooltips

Every technical term in the dashboard UI (TCP, ARP, beaconing, JA3, MITRE…) shows an inline ⓘ tooltip linking directly to the relevant article. Tooltips are non-invasive — they inject without modifying existing behaviour.

### Adding content

All content lives in `homenetguard/dashboard/static/data/curriculum.json`. Each topic follows this schema:

```json
{
  "slug": "tcp-protocol",
  "title": "TCP — Transmission Control Protocol",
  "category": "fundamentals",
  "level": "beginner",
  "estimated_minutes": 8,
  "ui_terms": ["TCP", "SYN", "ACK"],
  "standards": ["RFC 793"],
  "sections": [
    { "type": "concept",      "title": "¿Qué es TCP?",           "content": "..." },
    { "type": "live_example", "title": "En tu red ahora mismo",  "query": "SELECT COUNT(*) FROM flows WHERE protocol='TCP'", "description": "..." },
    { "type": "security",     "title": "Por qué importa",        "content": "...", "mitre_techniques": ["T1046"] },
    { "type": "deeper",       "title": "Más profundo",           "content": "...", "references": ["RFC 793"] }
  ]
}
```

Add a new term to `TOOLTIP_TERMS` in `learn.js` to wire it to the UI. See `CLAUDE.md` for full documentation.

---

## License

MIT License — see [LICENSE](LICENSE).

Copyright (c) 2026 HomeNetGuard Contributors
