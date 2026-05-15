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
- ⌨️ **Full CLI** — Click-based CLI with 8 subcommands
- 🧪 **Tested** — Pytest unit tests, 70%+ coverage enforced

---

## System Requirements

| | Requirement |
|---|---|
| **OS** | Linux (Ubuntu 20.04+, Fedora 36+) or macOS 12+ |
| **Python** | 3.11 or higher |
| **System packages** | `tshark` (Wireshark CLI), `libpcap-dev` |
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

### v1.1
- [ ] Beaconing detection (C2 traffic pattern recognition)
- [ ] Process-to-connection mapping (which app owns which connection)
- [ ] Automatic IP blocking via iptables/nftables/pf

### v1.2
- [ ] Multi-host monitoring (central collector)
- [ ] SIEM export (CEF/LEEF format)
- [ ] Docker container deployment

### v1.3
- [ ] Machine learning anomaly detection
- [ ] Vulnerability correlation with CVE database
- [ ] Mobile app companion

---

## License

MIT License — see [LICENSE](LICENSE).

Copyright (c) 2026 HomeNetGuard Contributors
