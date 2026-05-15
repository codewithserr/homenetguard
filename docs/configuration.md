# Configuration Reference

All settings in `config/config.yaml`. Secrets in `.env`.

## network

| Key | Type | Default | Description |
|---|---|---|---|
| `interface` | string | `auto` | Interface to capture on. `auto` = detect active interface |
| `capture_filter` | string | `""` | BPF filter expression (e.g. `"not port 22"`) |
| `max_pcap_size_mb` | int | `500` | Max size per .pcap file before rotation |
| `rotate_pcap_hours` | int | `24` | Rotate capture file every N hours |

## storage

| Key | Type | Default | Description |
|---|---|---|---|
| `db_path` | path | `data/homenetguard.db` | SQLite database path |
| `captures_path` | path | `data/captures` | Directory for .pcap files |
| `reports_path` | path | `data/reports` | Directory for generated reports |
| `retention_days` | int | `30` | Delete records older than N days (0 = keep forever) |

## dashboard

| Key | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `true` | Start dashboard with `homenetguard start` |
| `host` | string | `127.0.0.1` | Bind address — **never change to 0.0.0.0 on untrusted networks** |
| `port` | int | `5000` | HTTP port |
| `auto_open_browser` | bool | `true` | Open browser on dashboard start |
| `update_interval_seconds` | int | `5` | Dashboard refresh interval |
| `auth.enabled` | bool | `false` | Enable HTTP Basic Auth |
| `auth.username` | string | `admin` | Basic auth username |
| `auth.password` | string | `changeme` | Basic auth password (use `.env` in production) |

## detection

### port_scan
| Key | Default | Description |
|---|---|---|
| `enabled` | `true` | Enable port scan detection |
| `threshold_ports` | `15` | Distinct ports contacted by one IP within `threshold_seconds` |
| `threshold_seconds` | `60` | Time window for port scan counting |

### flood
| Key | Default | Description |
|---|---|---|
| `threshold_mb` | `10` | MB received from one IP within `threshold_seconds` |
| `threshold_seconds` | `30` | Time window for flood counting |

### dns_anomaly
| Key | Default | Description |
|---|---|---|
| `max_domain_length` | `50` | Domains longer than this flag as potential DNS tunneling |
| `max_nxdomain_per_minute` | `20` | NXDOMAIN responses per minute before alerting |

## alerts

### email
Requires SMTP credentials. Set `EMAIL_PASSWORD` in `.env`.

### telegram
Requires a Telegram Bot token. Set `TELEGRAM_BOT_TOKEN` in `.env`.
Get a bot token from [@BotFather](https://t.me/BotFather).
Get your chat ID from [@userinfobot](https://t.me/userinfobot).
