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
