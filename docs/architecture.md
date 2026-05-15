# Architecture

HomeNetGuard uses a **layered architecture** with strict unidirectional dependencies.

## Layers

```
Presentation → Analysis → Storage ← Capture
```

### Capture Layer (`homenetguard/capture/`)
- `sniffer.py` — Scapy-based live packet capture, spawns daemon thread
- `pcap_reader.py` — PyShark wrapper for offline .pcap analysis
- `interface_detector.py` — Auto-detects active network interface

### Analysis Layer (`homenetguard/analysis/`)
- `traffic_analyzer.py` — Rolling BPS counter, top-IP aggregation
- `threat_detector.py` — Port scan, flood, blacklist, ARP spoofing detection
- `dns_analyzer.py` — DNS packet processing, anomaly detection
- `geo_lookup.py` — MaxMind GeoLite2 offline IP geolocation
- `reputation.py` — AbuseIPDB integration with 24h cache

### Storage Layer (`homenetguard/storage/`)
- `models.py` — SQL schema (5 tables + indexes)
- `database.py` — SQLite connection manager (WAL mode, context manager)
- `repository.py` — Repository pattern CRUD for all entities

### Presentation Layer
- `main.py` — Click CLI (8 subcommands)
- `dashboard/` — Flask + Flask-SocketIO real-time dashboard
- `reports/` — Jinja2 HTML reports + WeasyPrint PDF export
- `alerts/` — Email + Telegram notification dispatch

### Utils (`homenetguard/utils/`)
- `config_loader.py` — YAML config + dotenv secret injection
- `logger.py` — Rotating file + console logger
- `permissions.py` — CAP_NET_RAW / access_bpf verification

## Data Flow

```
Network Interface
      ↓
  Sniffer._capture_loop()
      ↓
  _packet_to_flow() — Scapy packet → flow dict
      ↓
  ┌─────────────────────────────────────┐
  │  repository.insert_flow()           │  → SQLite flows table
  │  ThreatDetector.analyze_flow()      │  → SQLite alerts table
  │  DNSAnalyzer.process_dns_packet()   │  → SQLite dns_queries table
  │  TrafficAnalyzer.record_bytes()     │  → in-memory BPS ring buffer
  └─────────────────────────────────────┘
      ↓
  WebSocket push (every 2s)
      ↓
  Dashboard browser (Chart.js + Leaflet)
```

## Concurrency Model

- Main thread: CLI + Flask server
- Daemon thread: Sniffer capture loop
- Daemon thread: WebSocket push loop
- SQLite WAL mode allows concurrent reads during writes
