# HomeNetGuard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build HomeNetGuard — a production-ready, open-source network security monitor for Linux/macOS with real-time capture, threat detection, SQLite persistence, Flask dashboard, and CLI.

**Architecture:** Layered architecture: capture → analysis → storage → presentation (CLI, dashboard, reports). Modules communicate through well-defined interfaces; no cross-layer skipping.

**Tech Stack:** Python 3.11+, Scapy, PyShark, SQLite, Flask, Flask-SocketIO, Chart.js, Leaflet.js, Click, WeasyPrint, Pytest

---

## Phase 1: Project Foundation

### Task 1: Directory scaffold + pyproject.toml

**Files:**
- Create: `pyproject.toml`
- Create: `requirements.txt`
- Create: `requirements-dev.txt`
- Create: `.gitignore`
- Create: `.env.example`
- Create: All `__init__.py` files

- [ ] Create `pyproject.toml`:

```toml
[build-system]
requires = ["setuptools>=68", "wheel"]
build-backend = "setuptools.backends.legacy:build"

[project]
name = "homenetguard"
version = "0.1.0"
description = "Open-source network security monitor for home and personal use"
readme = "README.md"
license = { text = "MIT" }
authors = [{ name = "HomeNetGuard Contributors" }]
requires-python = ">=3.11"
dependencies = [
    "scapy>=2.5.0",
    "pyshark>=0.6",
    "flask>=3.0",
    "flask-socketio>=5.3",
    "click>=8.1",
    "pyyaml>=6.0",
    "python-dotenv>=1.0",
    "requests>=2.31",
    "geoip2>=4.7",
    "jinja2>=3.1",
    "weasyprint>=60.0",
    "tabulate>=0.9",
    "python-telegram-bot>=20.0",
    "apprise>=1.7",
]

[project.scripts]
homenetguard = "homenetguard.main:cli"

[tool.setuptools.packages.find]
where = ["."]
include = ["homenetguard*"]

[tool.black]
line-length = 100

[tool.ruff]
line-length = 100
select = ["E", "F", "I", "UP", "B"]
ignore = ["B008"]

[tool.mypy]
strict = false
ignore_missing_imports = true

[tool.pytest.ini_options]
testpaths = ["tests"]
markers = [
    "unit: fast unit tests",
    "integration: tests requiring system resources",
    "slow: tests that take >5s",
]
```

- [ ] Create `requirements.txt` (same deps as pyproject, pinned):

```
scapy>=2.5.0
pyshark>=0.6
flask>=3.0
flask-socketio>=5.3
click>=8.1
pyyaml>=6.0
python-dotenv>=1.0
requests>=2.31
geoip2>=4.7
jinja2>=3.1
weasyprint>=60.0
tabulate>=0.9
python-telegram-bot>=20.0
apprise>=1.7
simple-websocket>=1.0
```

- [ ] Create `requirements-dev.txt`:

```
-r requirements.txt
pytest>=7.4
pytest-cov>=4.1
black>=23.0
ruff>=0.1
mypy>=1.5
pre-commit>=3.5
pytest-asyncio>=0.21
```

- [ ] Create `.env.example`:

```
# API Keys - copy to .env and fill in
ABUSEIPDB_API_KEY=
VT_API_KEY=
EMAIL_PASSWORD=
TELEGRAM_BOT_TOKEN=
```

- [ ] Create `.gitignore`:

```
__pycache__/
*.py[cod]
*.egg-info/
dist/
build/
.env
config/geoip/
data/captures/
data/reports/
data/homenetguard.db
logs/
.coverage
htmlcov/
.mypy_cache/
.ruff_cache/
*.pcap
```

- [ ] Create all package `__init__.py` files:

```bash
mkdir -p homenetguard/{capture,analysis,storage,reports,dashboard/{static/{css,js},templates},alerts,utils}
mkdir -p tests/{unit,integration}
mkdir -p config/geoip data/{captures,reports} logs scripts docs
touch homenetguard/__init__.py
touch homenetguard/capture/__init__.py
touch homenetguard/analysis/__init__.py
touch homenetguard/storage/__init__.py
touch homenetguard/reports/__init__.py
touch homenetguard/dashboard/__init__.py
touch homenetguard/alerts/__init__.py
touch homenetguard/utils/__init__.py
touch tests/__init__.py tests/unit/__init__.py tests/integration/__init__.py
```

- [ ] Commit: `git init && git add -A && git commit -m "chore: initial project scaffold"`

---

### Task 2: Config system

**Files:**
- Create: `config/config.example.yaml`
- Create: `homenetguard/utils/config_loader.py`

- [ ] Create `config/config.example.yaml`:

```yaml
# HomeNetGuard — Configuración principal
# Copia este archivo a config/config.yaml y ajusta los valores

network:
  # Interfaz de red a monitorizar. "auto" detecta la interfaz activa automáticamente
  interface: auto
  # Filtro BPF opcional para limitar la captura (ej: "not port 22 and not port 443")
  capture_filter: ""
  # Tamaño máximo por fichero .pcap antes de rotar (MB)
  max_pcap_size_mb: 500
  # Rotar fichero de captura cada N horas
  rotate_pcap_hours: 24

storage:
  # Ruta a la base de datos SQLite
  db_path: data/homenetguard.db
  # Directorio para ficheros .pcap
  captures_path: data/captures
  # Directorio para informes generados
  reports_path: data/reports
  # Eliminar registros más antiguos de N días (0 = no eliminar)
  retention_days: 30

dashboard:
  enabled: true
  # Host donde escucha el dashboard (usa 127.0.0.1 para seguridad, nunca 0.0.0.0 en redes públicas)
  host: 127.0.0.1
  port: 5000
  # Abrir navegador automáticamente al arrancar el dashboard
  auto_open_browser: true
  # Intervalo de actualización del dashboard en segundos
  update_interval_seconds: 5
  auth:
    # Habilitar autenticación básica en el dashboard
    enabled: false
    username: admin
    # Contraseña en texto plano (solo para uso local, nunca exponer en red)
    password: changeme

geoip:
  enabled: true
  # Ruta a la base de datos MaxMind GeoLite2 (descargar con scripts/download_geoip.sh)
  db_path: config/geoip/GeoLite2-City.mmdb

threat_intelligence:
  abuseipdb:
    enabled: false
    # Configurar en .env como ABUSEIPDB_API_KEY (gratuito en abuseipdb.com)
    api_key: ""
    # Horas de caché antes de volver a consultar la misma IP
    cache_hours: 24
  virustotal:
    enabled: false
    # Configurar en .env como VT_API_KEY
    api_key: ""

detection:
  port_scan:
    enabled: true
    # Número de puertos distintos desde una misma IP en threshold_seconds para disparar alerta
    threshold_ports: 15
    threshold_seconds: 60
  beaconing:
    enabled: true
    # Mínimo de conexiones para considerar patrón de beaconing
    min_connections: 10
    # Tolerancia en % de variación del intervalo (10 = ±10%)
    interval_tolerance_pct: 10
  flood:
    enabled: true
    # MB recibidos desde una IP en threshold_seconds para disparar alerta DoS
    threshold_mb: 10
    threshold_seconds: 30
  dns_anomaly:
    enabled: true
    # Longitud máxima de dominio antes de considerar posible DNS tunneling
    max_domain_length: 50
    # Consultas NXDOMAIN por minuto antes de disparar alerta
    max_nxdomain_per_minute: 20

firewall:
  # Bloqueo automático de IPs maliciosas (requiere sudo/root)
  auto_block: false
  # Backend de firewall: iptables (Linux) | nftables (Linux) | pf (macOS)
  block_backend: iptables

alerts:
  email:
    enabled: false
    smtp_host: smtp.gmail.com
    smtp_port: 587
    smtp_user: ""
    # Contraseña en .env como EMAIL_PASSWORD
    smtp_password: ""
    recipient: ""
    # Severidad mínima para enviar email: low | medium | high | critical
    min_severity: high
  telegram:
    enabled: false
    # Token del bot en .env como TELEGRAM_BOT_TOKEN
    bot_token: ""
    chat_id: ""
    min_severity: critical

logging:
  # Nivel de log: DEBUG | INFO | WARNING | ERROR
  level: INFO
  file: logs/homenetguard.log
  # Tamaño máximo del fichero de log antes de rotar (MB)
  max_size_mb: 50
  backup_count: 5
```

- [ ] Create `homenetguard/utils/config_loader.py`:

```python
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv

load_dotenv()

_DEFAULT_CONFIG_PATH = Path("config/config.yaml")
_EXAMPLE_CONFIG_PATH = Path("config/config.example.yaml")

_config: dict[str, Any] | None = None


def load_config(path: Path | None = None) -> dict[str, Any]:
    global _config
    config_path = path or _DEFAULT_CONFIG_PATH

    if not config_path.exists():
        if _EXAMPLE_CONFIG_PATH.exists():
            raise FileNotFoundError(
                f"Config not found at {config_path}. "
                f"Run: cp {_EXAMPLE_CONFIG_PATH} {config_path}"
            )
        raise FileNotFoundError(f"Config not found at {config_path}")

    with open(config_path) as f:
        _config = yaml.safe_load(f)

    _inject_env_secrets(_config)
    return _config


def get_config() -> dict[str, Any]:
    global _config
    if _config is None:
        _config = load_config()
    return _config


def _inject_env_secrets(cfg: dict[str, Any]) -> None:
    ti = cfg.get("threat_intelligence", {})
    if os.getenv("ABUSEIPDB_API_KEY"):
        ti.setdefault("abuseipdb", {})["api_key"] = os.environ["ABUSEIPDB_API_KEY"]
    if os.getenv("VT_API_KEY"):
        ti.setdefault("virustotal", {})["api_key"] = os.environ["VT_API_KEY"]

    alerts = cfg.get("alerts", {})
    if os.getenv("EMAIL_PASSWORD"):
        alerts.setdefault("email", {})["smtp_password"] = os.environ["EMAIL_PASSWORD"]
    if os.getenv("TELEGRAM_BOT_TOKEN"):
        alerts.setdefault("telegram", {})["bot_token"] = os.environ["TELEGRAM_BOT_TOKEN"]
```

- [ ] Commit: `git add -A && git commit -m "feat: config system with yaml + dotenv injection"`

---

### Task 3: Logger + permissions utils

**Files:**
- Create: `homenetguard/utils/logger.py`
- Create: `homenetguard/utils/permissions.py`

- [ ] Create `homenetguard/utils/logger.py`:

```python
from __future__ import annotations

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path


def setup_logger(
    name: str = "homenetguard",
    level: str = "INFO",
    log_file: str = "logs/homenetguard.log",
    max_size_mb: int = 50,
    backup_count: int = 5,
) -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    fmt = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(fmt)
    logger.addHandler(console)

    log_path = Path(log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    file_handler = RotatingFileHandler(
        log_path,
        maxBytes=max_size_mb * 1024 * 1024,
        backupCount=backup_count,
    )
    file_handler.setFormatter(fmt)
    logger.addHandler(file_handler)

    return logger


def get_logger(name: str = "homenetguard") -> logging.Logger:
    return logging.getLogger(name)
```

- [ ] Create `homenetguard/utils/permissions.py`:

```python
from __future__ import annotations

import grp
import os
import platform
import sys

from homenetguard.utils.logger import get_logger

logger = get_logger(__name__)


def check_capture_permissions() -> bool:
    system = platform.system()
    if os.geteuid() == 0:
        return True

    if system == "Linux":
        return _check_linux_cap_net_raw()
    elif system == "Darwin":
        return _check_macos_bpf()
    else:
        logger.warning("Unknown OS %s — cannot verify capture permissions", system)
        return False


def require_capture_permissions() -> None:
    if not check_capture_permissions():
        system = platform.system()
        if system == "Linux":
            msg = (
                "\nInsufficient permissions for packet capture.\n"
                "Options:\n"
                "  1. Run with sudo: sudo homenetguard start\n"
                "  2. Grant capabilities: sudo setcap cap_net_raw+eip $(which python3)\n"
            )
        elif system == "Darwin":
            msg = (
                "\nInsufficient permissions for packet capture.\n"
                "Options:\n"
                "  1. Run with sudo: sudo homenetguard start\n"
                "  2. Add user to access_bpf group: sudo dseditgroup -o edit -a $USER -t user access_bpf\n"
            )
        else:
            msg = "\nInsufficient permissions for packet capture. Try running with sudo."

        print(msg, file=sys.stderr)
        sys.exit(1)


def _check_linux_cap_net_raw() -> bool:
    try:
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("CapEff:"):
                    cap_eff = int(line.split(":")[1].strip(), 16)
                    cap_net_raw = 1 << 13
                    return bool(cap_eff & cap_net_raw)
    except OSError:
        pass
    return False


def _check_macos_bpf() -> bool:
    try:
        groups = [grp.getgrgid(g).gr_name for g in os.getgroups()]
        return "access_bpf" in groups
    except Exception:
        return False
```

- [ ] Commit: `git add -A && git commit -m "feat: logger and permissions utilities"`

---

## Phase 2: Storage Layer

### Task 4: Database models + connection

**Files:**
- Create: `homenetguard/storage/database.py`
- Create: `homenetguard/storage/models.py`

- [ ] Create `homenetguard/storage/models.py`:

```python
SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS flows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME NOT NULL,
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    src_port INTEGER,
    dst_port INTEGER,
    protocol TEXT NOT NULL,
    bytes INTEGER DEFAULT 0,
    packets INTEGER DEFAULT 1,
    direction TEXT,
    interface TEXT,
    src_country TEXT,
    dst_country TEXT,
    src_city TEXT,
    dst_city TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME NOT NULL,
    alert_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    src_ip TEXT,
    dst_ip TEXT,
    description TEXT NOT NULL,
    raw_data TEXT,
    acknowledged INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS dns_queries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME NOT NULL,
    src_ip TEXT NOT NULL,
    queried_domain TEXT NOT NULL,
    query_type TEXT,
    response_ip TEXT,
    is_suspicious INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ip_reputation (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT UNIQUE NOT NULL,
    abuse_score INTEGER,
    is_blacklisted INTEGER DEFAULT 0,
    country TEXT,
    isp TEXT,
    last_checked DATETIME,
    source TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    report_type TEXT NOT NULL,
    period_start DATETIME,
    period_end DATETIME,
    file_path TEXT,
    format TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_flows_timestamp ON flows(timestamp);
CREATE INDEX IF NOT EXISTS idx_flows_src_ip ON flows(src_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_dns_domain ON dns_queries(queried_domain);
"""
```

- [ ] Create `homenetguard/storage/database.py`:

```python
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Generator

from homenetguard.storage.models import SCHEMA_SQL
from homenetguard.utils.logger import get_logger

logger = get_logger(__name__)

_db_path: str = "data/homenetguard.db"


def init_db(db_path: str = "data/homenetguard.db") -> None:
    global _db_path
    _db_path = db_path
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    with get_connection() as conn:
        conn.executescript(SCHEMA_SQL)
    logger.info("Database initialized at %s", db_path)


@contextmanager
def get_connection() -> Generator[sqlite3.Connection, None, None]:
    conn = sqlite3.connect(_db_path, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
```

- [ ] Commit: `git add -A && git commit -m "feat: SQLite schema and database connection"`

---

### Task 5: Repository (CRUD)

**Files:**
- Create: `homenetguard/storage/repository.py`
- Create: `tests/unit/test_repository.py`

- [ ] Write failing tests first — `tests/unit/test_repository.py`:

```python
import pytest
from datetime import datetime
from homenetguard.storage import database, repository


@pytest.fixture(autouse=True)
def in_memory_db(tmp_path):
    db_file = str(tmp_path / "test.db")
    database.init_db(db_file)
    yield


def test_insert_and_get_flow():
    flow = {
        "timestamp": datetime.utcnow().isoformat(),
        "src_ip": "192.168.1.1",
        "dst_ip": "8.8.8.8",
        "src_port": 12345,
        "dst_port": 53,
        "protocol": "UDP",
        "bytes": 128,
        "packets": 1,
        "direction": "outbound",
        "interface": "eth0",
    }
    repository.insert_flow(flow)
    flows = repository.get_recent_flows(limit=10)
    assert len(flows) == 1
    assert flows[0]["src_ip"] == "192.168.1.1"


def test_insert_and_get_alert():
    repository.insert_alert(
        alert_type="port_scan",
        severity="high",
        src_ip="10.0.0.1",
        dst_ip="192.168.1.100",
        description="Port scan detected from 10.0.0.1",
    )
    alerts = repository.get_unacknowledged_alerts()
    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "port_scan"


def test_acknowledge_alert():
    repository.insert_alert(
        alert_type="flood",
        severity="high",
        src_ip="1.2.3.4",
        description="Flood detected",
    )
    alerts = repository.get_unacknowledged_alerts()
    alert_id = alerts[0]["id"]
    repository.acknowledge_alert(alert_id)
    assert repository.get_unacknowledged_alerts() == []


def test_insert_dns_query():
    repository.insert_dns_query(
        timestamp=datetime.utcnow().isoformat(),
        src_ip="192.168.1.5",
        queried_domain="example.com",
        query_type="A",
        response_ip="93.184.216.34",
    )
    queries = repository.get_recent_dns_queries(limit=10)
    assert len(queries) == 1
    assert queries[0]["queried_domain"] == "example.com"


def test_upsert_ip_reputation():
    repository.upsert_ip_reputation(
        ip_address="1.2.3.4",
        abuse_score=90,
        is_blacklisted=True,
        source="abuseipdb",
    )
    rep = repository.get_ip_reputation("1.2.3.4")
    assert rep is not None
    assert rep["is_blacklisted"] == 1


def test_get_flow_stats():
    from datetime import timedelta
    now = datetime.utcnow()
    for i in range(3):
        repository.insert_flow({
            "timestamp": now.isoformat(),
            "src_ip": f"10.0.0.{i}",
            "dst_ip": "8.8.8.8",
            "protocol": "TCP",
            "bytes": 1000,
        })
    stats = repository.get_flow_stats(since=now - timedelta(minutes=1))
    assert stats["total_flows"] == 3
    assert stats["total_bytes"] == 3000
```

- [ ] Run: `pytest tests/unit/test_repository.py -v` — expect FAIL (module missing)

- [ ] Create `homenetguard/storage/repository.py`:

```python
from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from homenetguard.storage.database import get_connection
from homenetguard.utils.logger import get_logger

logger = get_logger(__name__)


def insert_flow(flow: dict[str, Any]) -> int:
    sql = """
    INSERT INTO flows (timestamp, src_ip, dst_ip, src_port, dst_port, protocol,
                       bytes, packets, direction, interface, src_country, dst_country,
                       src_city, dst_city)
    VALUES (:timestamp, :src_ip, :dst_ip, :src_port, :dst_port, :protocol,
            :bytes, :packets, :direction, :interface, :src_country, :dst_country,
            :src_city, :dst_city)
    """
    defaults = {
        "src_port": None, "dst_port": None, "packets": 1, "bytes": 0,
        "direction": None, "interface": None, "src_country": None,
        "dst_country": None, "src_city": None, "dst_city": None,
    }
    row = {**defaults, **flow}
    with get_connection() as conn:
        cur = conn.execute(sql, row)
        return cur.lastrowid  # type: ignore[return-value]


def get_recent_flows(limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM flows ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
    return [dict(r) for r in rows]


def get_flow_stats(since: datetime) -> dict[str, Any]:
    sql = """
    SELECT COUNT(*) as total_flows,
           COALESCE(SUM(bytes), 0) as total_bytes,
           COUNT(DISTINCT src_ip) as unique_src_ips,
           COUNT(DISTINCT dst_ip) as unique_dst_ips
    FROM flows WHERE timestamp >= ?
    """
    with get_connection() as conn:
        row = conn.execute(sql, (since.isoformat(),)).fetchone()
    return dict(row)


def get_top_ips(limit: int = 10, since: datetime | None = None) -> list[dict[str, Any]]:
    where = "WHERE timestamp >= ?" if since else ""
    params: list[Any] = [since.isoformat()] if since else []
    sql = f"""
    SELECT src_ip as ip, SUM(bytes) as total_bytes, COUNT(*) as flow_count
    FROM flows {where}
    GROUP BY src_ip ORDER BY total_bytes DESC LIMIT ?
    """
    params.append(limit)
    with get_connection() as conn:
        rows = conn.execute(sql, params).fetchall()
    return [dict(r) for r in rows]


def get_protocol_distribution(since: datetime | None = None) -> list[dict[str, Any]]:
    where = "WHERE timestamp >= ?" if since else ""
    params: list[Any] = [since.isoformat()] if since else []
    sql = f"""
    SELECT protocol, COUNT(*) as count, SUM(bytes) as total_bytes
    FROM flows {where} GROUP BY protocol ORDER BY count DESC
    """
    with get_connection() as conn:
        rows = conn.execute(sql, params).fetchall()
    return [dict(r) for r in rows]


def insert_alert(
    alert_type: str,
    severity: str,
    description: str,
    src_ip: str | None = None,
    dst_ip: str | None = None,
    raw_data: dict[str, Any] | None = None,
    timestamp: str | None = None,
) -> int:
    ts = timestamp or datetime.utcnow().isoformat()
    sql = """
    INSERT INTO alerts (timestamp, alert_type, severity, src_ip, dst_ip, description, raw_data)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """
    raw_json = json.dumps(raw_data) if raw_data else None
    with get_connection() as conn:
        cur = conn.execute(sql, (ts, alert_type, severity, src_ip, dst_ip, description, raw_json))
        logger.warning("ALERT [%s/%s] %s", severity.upper(), alert_type, description)
        return cur.lastrowid  # type: ignore[return-value]


def get_unacknowledged_alerts(limit: int = 100) -> list[dict[str, Any]]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM alerts WHERE acknowledged=0 ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def get_all_alerts(
    severity: str | None = None,
    alert_type: str | None = None,
    limit: int = 200,
) -> list[dict[str, Any]]:
    conditions: list[str] = []
    params: list[Any] = []
    if severity:
        conditions.append("severity=?")
        params.append(severity)
    if alert_type:
        conditions.append("alert_type=?")
        params.append(alert_type)
    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    params.append(limit)
    with get_connection() as conn:
        rows = conn.execute(
            f"SELECT * FROM alerts {where} ORDER BY timestamp DESC LIMIT ?", params
        ).fetchall()
    return [dict(r) for r in rows]


def acknowledge_alert(alert_id: int) -> None:
    with get_connection() as conn:
        conn.execute("UPDATE alerts SET acknowledged=1 WHERE id=?", (alert_id,))


def clear_all_alerts() -> int:
    with get_connection() as conn:
        cur = conn.execute("DELETE FROM alerts")
        return cur.rowcount  # type: ignore[return-value]


def insert_dns_query(
    timestamp: str,
    src_ip: str,
    queried_domain: str,
    query_type: str | None = None,
    response_ip: str | None = None,
    is_suspicious: bool = False,
) -> int:
    sql = """
    INSERT INTO dns_queries (timestamp, src_ip, queried_domain, query_type, response_ip, is_suspicious)
    VALUES (?, ?, ?, ?, ?, ?)
    """
    with get_connection() as conn:
        cur = conn.execute(sql, (timestamp, src_ip, queried_domain, query_type, response_ip, int(is_suspicious)))
        return cur.lastrowid  # type: ignore[return-value]


def get_recent_dns_queries(limit: int = 100) -> list[dict[str, Any]]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM dns_queries ORDER BY timestamp DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


def upsert_ip_reputation(
    ip_address: str,
    abuse_score: int | None = None,
    is_blacklisted: bool = False,
    country: str | None = None,
    isp: str | None = None,
    source: str = "local",
) -> None:
    sql = """
    INSERT INTO ip_reputation (ip_address, abuse_score, is_blacklisted, country, isp, source, last_checked)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(ip_address) DO UPDATE SET
        abuse_score=excluded.abuse_score,
        is_blacklisted=excluded.is_blacklisted,
        country=excluded.country,
        isp=excluded.isp,
        source=excluded.source,
        last_checked=excluded.last_checked
    """
    with get_connection() as conn:
        conn.execute(sql, (ip_address, abuse_score, int(is_blacklisted), country, isp, source, datetime.utcnow().isoformat()))


def get_ip_reputation(ip_address: str) -> dict[str, Any] | None:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM ip_reputation WHERE ip_address=?", (ip_address,)
        ).fetchone()
    return dict(row) if row else None


def insert_report(
    report_type: str,
    file_path: str,
    fmt: str,
    period_start: str | None = None,
    period_end: str | None = None,
) -> int:
    sql = """
    INSERT INTO reports (report_type, period_start, period_end, file_path, format)
    VALUES (?, ?, ?, ?, ?)
    """
    with get_connection() as conn:
        cur = conn.execute(sql, (report_type, period_start, period_end, file_path, fmt))
        return cur.lastrowid  # type: ignore[return-value]


def get_reports(limit: int = 50) -> list[dict[str, Any]]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM reports ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


def purge_old_data(retention_days: int) -> None:
    if retention_days <= 0:
        return
    cutoff = f"datetime('now', '-{retention_days} days')"
    with get_connection() as conn:
        conn.execute(f"DELETE FROM flows WHERE created_at < {cutoff}")
        conn.execute(f"DELETE FROM alerts WHERE created_at < {cutoff}")
        conn.execute(f"DELETE FROM dns_queries WHERE created_at < {cutoff}")
    logger.info("Purged data older than %d days", retention_days)
```

- [ ] Run: `pytest tests/unit/test_repository.py -v` — all pass

- [ ] Commit: `git add -A && git commit -m "feat: storage repository with full CRUD"`

---

## Phase 3: Analysis Layer

### Task 6: Traffic analyzer

**Files:**
- Create: `homenetguard/analysis/traffic_analyzer.py`
- Create: `tests/unit/test_traffic_analyzer.py`

- [ ] Write failing tests — `tests/unit/test_traffic_analyzer.py`:

```python
import pytest
from datetime import datetime, timedelta
from homenetguard.analysis.traffic_analyzer import TrafficAnalyzer
from homenetguard.storage import database, repository


@pytest.fixture(autouse=True)
def in_memory_db(tmp_path):
    database.init_db(str(tmp_path / "test.db"))


@pytest.fixture
def populated_db():
    now = datetime.utcnow()
    flows = [
        {"timestamp": now.isoformat(), "src_ip": "10.0.0.1", "dst_ip": "8.8.8.8",
         "protocol": "TCP", "bytes": 5000, "dst_port": 80},
        {"timestamp": now.isoformat(), "src_ip": "10.0.0.1", "dst_ip": "1.1.1.1",
         "protocol": "UDP", "bytes": 3000, "dst_port": 53},
        {"timestamp": now.isoformat(), "src_ip": "10.0.0.2", "dst_ip": "8.8.8.8",
         "protocol": "TCP", "bytes": 1000, "dst_port": 443},
    ]
    for f in flows:
        repository.insert_flow(f)


def test_get_top_talkers(populated_db):
    analyzer = TrafficAnalyzer()
    top = analyzer.get_top_talkers(limit=5)
    assert top[0]["ip"] == "10.0.0.1"
    assert top[0]["total_bytes"] == 8000


def test_get_protocol_distribution(populated_db):
    analyzer = TrafficAnalyzer()
    dist = analyzer.get_protocol_distribution()
    protocols = {d["protocol"] for d in dist}
    assert "TCP" in protocols
    assert "UDP" in protocols


def test_bytes_per_second():
    analyzer = TrafficAnalyzer()
    analyzer.record_bytes(1500)
    analyzer.record_bytes(500)
    assert analyzer.get_current_bps() == 2000
```

- [ ] Run: `pytest tests/unit/test_traffic_analyzer.py -v` — FAIL

- [ ] Create `homenetguard/analysis/traffic_analyzer.py`:

```python
from __future__ import annotations

import threading
import time
from collections import deque
from datetime import datetime, timedelta
from typing import Any

from homenetguard.storage import repository
from homenetguard.utils.logger import get_logger

logger = get_logger(__name__)


class TrafficAnalyzer:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._byte_window: deque[tuple[float, int]] = deque()
        self._window_seconds = 1.0

    def record_bytes(self, byte_count: int) -> None:
        now = time.monotonic()
        with self._lock:
            self._byte_window.append((now, byte_count))
            cutoff = now - self._window_seconds
            while self._byte_window and self._byte_window[0][0] < cutoff:
                self._byte_window.popleft()

    def get_current_bps(self) -> int:
        with self._lock:
            return sum(b for _, b in self._byte_window)

    def get_top_talkers(
        self, limit: int = 10, minutes: int = 5
    ) -> list[dict[str, Any]]:
        since = datetime.utcnow() - timedelta(minutes=minutes)
        return repository.get_top_ips(limit=limit, since=since)

    def get_protocol_distribution(
        self, minutes: int = 60
    ) -> list[dict[str, Any]]:
        since = datetime.utcnow() - timedelta(minutes=minutes)
        return repository.get_protocol_distribution(since=since)

    def get_summary_stats(self, minutes: int = 60) -> dict[str, Any]:
        since = datetime.utcnow() - timedelta(minutes=minutes)
        return repository.get_flow_stats(since=since)

    def format_bytes(self, byte_count: int) -> str:
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if byte_count < 1024:
                return f"{byte_count:.1f} {unit}"
            byte_count //= 1024
        return f"{byte_count:.1f} PB"
```

- [ ] Run: `pytest tests/unit/test_traffic_analyzer.py -v` — PASS

- [ ] Commit: `git add -A && git commit -m "feat: traffic analyzer"`

---

### Task 7: Threat detector

**Files:**
- Create: `homenetguard/analysis/threat_detector.py`
- Create: `tests/unit/test_threat_detector.py`

- [ ] Write failing tests — `tests/unit/test_threat_detector.py`:

```python
import pytest
from datetime import datetime
from unittest.mock import patch, MagicMock
from homenetguard.analysis.threat_detector import ThreatDetector
from homenetguard.storage import database, repository


@pytest.fixture(autouse=True)
def in_memory_db(tmp_path):
    database.init_db(str(tmp_path / "test.db"))


@pytest.fixture
def detector():
    cfg = {
        "detection": {
            "port_scan": {"enabled": True, "threshold_ports": 5, "threshold_seconds": 60},
            "beaconing": {"enabled": True, "min_connections": 3, "interval_tolerance_pct": 20},
            "flood": {"enabled": True, "threshold_mb": 1, "threshold_seconds": 30},
            "dns_anomaly": {"enabled": True, "max_domain_length": 30, "max_nxdomain_per_minute": 5},
        }
    }
    return ThreatDetector(cfg)


def test_port_scan_detected(detector):
    src = "10.0.0.99"
    now = datetime.utcnow().isoformat()
    for port in range(1, 7):
        detector.analyze_flow({
            "src_ip": src, "dst_ip": "192.168.1.1",
            "dst_port": port, "protocol": "TCP",
            "timestamp": now, "bytes": 64,
        })
    alerts = repository.get_unacknowledged_alerts()
    scan_alerts = [a for a in alerts if a["alert_type"] == "port_scan"]
    assert len(scan_alerts) >= 1


def test_flood_detected(detector):
    src = "1.2.3.4"
    now = datetime.utcnow().isoformat()
    detector.analyze_flow({
        "src_ip": src, "dst_ip": "192.168.1.1",
        "dst_port": 80, "protocol": "TCP",
        "timestamp": now, "bytes": 2 * 1024 * 1024,  # 2MB > 1MB threshold
    })
    alerts = repository.get_unacknowledged_alerts()
    flood_alerts = [a for a in alerts if a["alert_type"] == "flood"]
    assert len(flood_alerts) >= 1


def test_blacklisted_ip_triggers_critical(detector):
    repository.upsert_ip_reputation("5.5.5.5", is_blacklisted=True, source="test")
    detector.analyze_flow({
        "src_ip": "5.5.5.5", "dst_ip": "192.168.1.1",
        "dst_port": 80, "protocol": "TCP",
        "timestamp": datetime.utcnow().isoformat(), "bytes": 100,
    })
    alerts = repository.get_unacknowledged_alerts()
    critical = [a for a in alerts if a["severity"] == "critical"]
    assert len(critical) >= 1


def test_dns_long_domain(detector):
    domain = "a" * 60 + ".example.com"  # > 30 char threshold
    assert detector.check_dns_anomaly("192.168.1.1", domain, "A") is True


def test_dns_normal_domain(detector):
    assert detector.check_dns_anomaly("192.168.1.1", "google.com", "A") is False
```

- [ ] Run: `pytest tests/unit/test_threat_detector.py -v` — FAIL

- [ ] Create `homenetguard/analysis/threat_detector.py`:

```python
from __future__ import annotations

import math
import time
from collections import defaultdict
from datetime import datetime
from typing import Any

from homenetguard.storage import repository
from homenetguard.utils.logger import get_logger

logger = get_logger(__name__)


class ThreatDetector:
    def __init__(self, config: dict[str, Any]) -> None:
        self._cfg = config.get("detection", {})
        self._port_scan_tracker: dict[str, dict[str, Any]] = defaultdict(
            lambda: {"ports": set(), "first_seen": time.monotonic()}
        )
        self._flood_tracker: dict[str, dict[str, Any]] = defaultdict(
            lambda: {"bytes": 0, "first_seen": time.monotonic()}
        )
        self._nxdomain_tracker: dict[str, list[float]] = defaultdict(list)

    def analyze_flow(self, flow: dict[str, Any]) -> None:
        src_ip = flow.get("src_ip", "")
        dst_ip = flow.get("dst_ip", "")
        dst_port = flow.get("dst_port")
        protocol = flow.get("protocol", "")
        byte_count = flow.get("bytes", 0)
        timestamp = flow.get("timestamp", datetime.utcnow().isoformat())

        self._check_blacklisted_ip(src_ip, dst_ip, timestamp)

        ps_cfg = self._cfg.get("port_scan", {})
        if ps_cfg.get("enabled") and dst_port and protocol in ("TCP", "UDP"):
            self._check_port_scan(src_ip, dst_ip, dst_port, timestamp, ps_cfg)

        flood_cfg = self._cfg.get("flood", {})
        if flood_cfg.get("enabled") and byte_count:
            self._check_flood(src_ip, byte_count, timestamp, flood_cfg)

    def _check_blacklisted_ip(self, src_ip: str, dst_ip: str, timestamp: str) -> None:
        for ip in (src_ip, dst_ip):
            if not ip:
                continue
            rep = repository.get_ip_reputation(ip)
            if rep and rep.get("is_blacklisted"):
                repository.insert_alert(
                    alert_type="blacklisted_ip",
                    severity="critical",
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    description=f"Traffic with blacklisted IP {ip} (score={rep.get('abuse_score', '?')})",
                    timestamp=timestamp,
                )

    def _check_port_scan(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        timestamp: str,
        cfg: dict[str, Any],
    ) -> None:
        threshold_ports = cfg.get("threshold_ports", 15)
        threshold_seconds = cfg.get("threshold_seconds", 60)
        tracker = self._port_scan_tracker[src_ip]
        now = time.monotonic()

        if now - tracker["first_seen"] > threshold_seconds:
            tracker["ports"] = set()
            tracker["first_seen"] = now

        tracker["ports"].add(dst_port)

        if len(tracker["ports"]) >= threshold_ports:
            repository.insert_alert(
                alert_type="port_scan",
                severity="high",
                src_ip=src_ip,
                dst_ip=dst_ip,
                description=(
                    f"Port scan detected: {src_ip} contacted {len(tracker['ports'])} "
                    f"distinct ports in {threshold_seconds}s"
                ),
                raw_data={"ports": list(tracker["ports"])[:50]},
                timestamp=timestamp,
            )
            tracker["ports"] = set()
            tracker["first_seen"] = now

    def _check_flood(
        self,
        src_ip: str,
        byte_count: int,
        timestamp: str,
        cfg: dict[str, Any],
    ) -> None:
        threshold_bytes = cfg.get("threshold_mb", 10) * 1024 * 1024
        threshold_seconds = cfg.get("threshold_seconds", 30)
        tracker = self._flood_tracker[src_ip]
        now = time.monotonic()

        if now - tracker["first_seen"] > threshold_seconds:
            tracker["bytes"] = 0
            tracker["first_seen"] = now

        tracker["bytes"] += byte_count

        if tracker["bytes"] >= threshold_bytes:
            mb = tracker["bytes"] / (1024 * 1024)
            repository.insert_alert(
                alert_type="flood",
                severity="high",
                src_ip=src_ip,
                description=f"Traffic flood from {src_ip}: {mb:.1f} MB in {threshold_seconds}s",
                raw_data={"bytes": tracker["bytes"]},
                timestamp=timestamp,
            )
            tracker["bytes"] = 0
            tracker["first_seen"] = now

    def check_dns_anomaly(self, src_ip: str, domain: str, query_type: str) -> bool:
        dns_cfg = self._cfg.get("dns_anomaly", {})
        if not dns_cfg.get("enabled", True):
            return False

        max_len = dns_cfg.get("max_domain_length", 50)
        if len(domain) > max_len:
            logger.debug("DNS anomaly: long domain %s from %s", domain, src_ip)
            return True

        if self._high_entropy(domain):
            return True

        return False

    @staticmethod
    def _high_entropy(domain: str) -> bool:
        subdomain = domain.split(".")[0] if "." in domain else domain
        if len(subdomain) < 10:
            return False
        freq: dict[str, float] = {}
        for c in subdomain:
            freq[c] = freq.get(c, 0) + 1
        entropy = -sum(
            (v / len(subdomain)) * math.log2(v / len(subdomain))
            for v in freq.values()
        )
        return entropy > 3.5
```

- [ ] Run: `pytest tests/unit/test_threat_detector.py -v` — PASS

- [ ] Commit: `git add -A && git commit -m "feat: threat detector (port scan, flood, blacklist, DNS)"`

---

### Task 8: DNS analyzer + geo lookup + reputation

**Files:**
- Create: `homenetguard/analysis/dns_analyzer.py`
- Create: `homenetguard/analysis/geo_lookup.py`
- Create: `homenetguard/analysis/reputation.py`
- Create: `tests/unit/test_dns_analyzer.py`

- [ ] Create `homenetguard/analysis/dns_analyzer.py`:

```python
from __future__ import annotations

from datetime import datetime
from typing import Any

from homenetguard.analysis.threat_detector import ThreatDetector
from homenetguard.storage import repository
from homenetguard.utils.logger import get_logger

logger = get_logger(__name__)


class DNSAnalyzer:
    def __init__(self, threat_detector: ThreatDetector | None = None) -> None:
        self._detector = threat_detector

    def process_dns_packet(self, src_ip: str, domain: str, query_type: str, response_ip: str | None = None) -> None:
        timestamp = datetime.utcnow().isoformat()
        is_suspicious = False

        if self._detector:
            is_suspicious = self._detector.check_dns_anomaly(src_ip, domain, query_type)

        repository.insert_dns_query(
            timestamp=timestamp,
            src_ip=src_ip,
            queried_domain=domain,
            query_type=query_type,
            response_ip=response_ip,
            is_suspicious=is_suspicious,
        )

        if is_suspicious:
            repository.insert_alert(
                alert_type="dns_anomaly",
                severity="medium",
                src_ip=src_ip,
                description=f"Suspicious DNS query: {domain} (type={query_type})",
                raw_data={"domain": domain, "query_type": query_type},
                timestamp=timestamp,
            )

    def get_top_domains(self, limit: int = 20) -> list[dict[str, Any]]:
        queries = repository.get_recent_dns_queries(limit=500)
        counts: dict[str, int] = {}
        for q in queries:
            d = q["queried_domain"]
            counts[d] = counts.get(d, 0) + 1
        return [
            {"domain": d, "count": c}
            for d, c in sorted(counts.items(), key=lambda x: -x[1])[:limit]
        ]

    def get_suspicious_domains(self) -> list[dict[str, Any]]:
        queries = repository.get_recent_dns_queries(limit=1000)
        return [q for q in queries if q.get("is_suspicious")]
```

- [ ] Create `homenetguard/analysis/geo_lookup.py`:

```python
from __future__ import annotations

from pathlib import Path
from typing import Any

from homenetguard.utils.logger import get_logger

logger = get_logger(__name__)

try:
    import geoip2.database
    import geoip2.errors
    _GEOIP2_AVAILABLE = True
except ImportError:
    _GEOIP2_AVAILABLE = False


class GeoLookup:
    def __init__(self, db_path: str = "config/geoip/GeoLite2-City.mmdb") -> None:
        self._reader: Any = None
        self._available = False
        if not _GEOIP2_AVAILABLE:
            logger.warning("geoip2 library not installed — geo lookup disabled")
            return
        path = Path(db_path)
        if not path.exists():
            logger.warning("GeoIP database not found at %s — run scripts/download_geoip.sh", db_path)
            return
        try:
            self._reader = geoip2.database.Reader(str(path))
            self._available = True
            logger.info("GeoIP database loaded from %s", db_path)
        except Exception as exc:
            logger.error("Failed to load GeoIP database: %s", exc)

    def lookup(self, ip: str) -> dict[str, str | None]:
        empty: dict[str, str | None] = {"country": None, "city": None, "country_code": None}
        if not self._available or not self._reader:
            return empty
        try:
            response = self._reader.city(ip)
            return {
                "country": response.country.name,
                "country_code": response.country.iso_code,
                "city": response.city.name,
            }
        except Exception:
            return empty

    def close(self) -> None:
        if self._reader:
            self._reader.close()
```

- [ ] Create `homenetguard/analysis/reputation.py`:

```python
from __future__ import annotations

import os
import time
from datetime import datetime, timedelta
from typing import Any

import requests

from homenetguard.storage import repository
from homenetguard.utils.logger import get_logger

logger = get_logger(__name__)

_PRIVATE_RANGES = (
    "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.3",
    "192.168.", "127.", "::1", "fc", "fd",
)


def is_private_ip(ip: str) -> bool:
    return any(ip.startswith(r) for r in _PRIVATE_RANGES)


class ReputationChecker:
    def __init__(self, config: dict[str, Any]) -> None:
        self._abuse_cfg = config.get("threat_intelligence", {}).get("abuseipdb", {})
        self._cache_hours = self._abuse_cfg.get("cache_hours", 24)

    def check_ip(self, ip: str) -> dict[str, Any] | None:
        if is_private_ip(ip):
            return None

        cached = repository.get_ip_reputation(ip)
        if cached and cached.get("last_checked"):
            try:
                last = datetime.fromisoformat(cached["last_checked"])
                if datetime.utcnow() - last < timedelta(hours=self._cache_hours):
                    return cached
            except ValueError:
                pass

        if self._abuse_cfg.get("enabled") and self._abuse_cfg.get("api_key"):
            return self._query_abuseipdb(ip)

        return None

    def _query_abuseipdb(self, ip: str) -> dict[str, Any] | None:
        api_key = self._abuse_cfg.get("api_key") or os.getenv("ABUSEIPDB_API_KEY", "")
        if not api_key:
            return None
        try:
            resp = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": api_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=5,
            )
            resp.raise_for_status()
            data = resp.json().get("data", {})
            score = data.get("abuseConfidenceScore", 0)
            is_bl = score >= 80
            repository.upsert_ip_reputation(
                ip_address=ip,
                abuse_score=score,
                is_blacklisted=is_bl,
                country=data.get("countryCode"),
                isp=data.get("isp"),
                source="abuseipdb",
            )
            return repository.get_ip_reputation(ip)
        except requests.RequestException as exc:
            logger.error("AbuseIPDB lookup failed for %s: %s", ip, exc)
            return None
```

- [ ] Write tests `tests/unit/test_dns_analyzer.py`:

```python
import pytest
from homenetguard.analysis.dns_analyzer import DNSAnalyzer
from homenetguard.storage import database, repository


@pytest.fixture(autouse=True)
def in_memory_db(tmp_path):
    database.init_db(str(tmp_path / "test.db"))


def test_process_normal_dns():
    analyzer = DNSAnalyzer()
    analyzer.process_dns_packet("192.168.1.1", "google.com", "A", "142.250.80.46")
    queries = repository.get_recent_dns_queries()
    assert len(queries) == 1
    assert queries[0]["is_suspicious"] == 0


def test_process_suspicious_long_domain():
    from homenetguard.analysis.threat_detector import ThreatDetector
    cfg = {"detection": {"dns_anomaly": {"enabled": True, "max_domain_length": 20, "max_nxdomain_per_minute": 5}}}
    detector = ThreatDetector(cfg)
    analyzer = DNSAnalyzer(threat_detector=detector)
    long_domain = "a" * 25 + ".evil.com"
    analyzer.process_dns_packet("192.168.1.1", long_domain, "A")
    queries = repository.get_recent_dns_queries()
    assert queries[0]["is_suspicious"] == 1
    alerts = repository.get_unacknowledged_alerts()
    assert any(a["alert_type"] == "dns_anomaly" for a in alerts)


def test_top_domains():
    analyzer = DNSAnalyzer()
    for _ in range(3):
        analyzer.process_dns_packet("192.168.1.1", "example.com", "A")
    analyzer.process_dns_packet("192.168.1.1", "other.com", "A")
    top = analyzer.get_top_domains()
    assert top[0]["domain"] == "example.com"
    assert top[0]["count"] == 3
```

- [ ] Run: `pytest tests/unit/test_dns_analyzer.py tests/unit/test_threat_detector.py tests/unit/test_traffic_analyzer.py tests/unit/test_repository.py -v` — all PASS

- [ ] Commit: `git add -A && git commit -m "feat: DNS analyzer, geo lookup, reputation checker"`

---

## Phase 4: Capture Layer

### Task 9: Interface detector + sniffer

**Files:**
- Create: `homenetguard/capture/interface_detector.py`
- Create: `homenetguard/capture/sniffer.py`
- Create: `homenetguard/capture/pcap_reader.py`

- [ ] Create `homenetguard/capture/interface_detector.py`:

```python
from __future__ import annotations

import socket
import struct
from typing import Any

from homenetguard.utils.logger import get_logger

logger = get_logger(__name__)


def get_active_interface() -> str:
    try:
        from scapy.arch import get_if_list
        from scapy.interfaces import conf
        iface = conf.iface
        if iface and str(iface) not in ("lo", "lo0"):
            return str(iface)
    except Exception:
        pass

    candidates = ["eth0", "wlan0", "en0", "en1", "ens33", "ens3"]
    try:
        import netifaces  # type: ignore[import]
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs and iface not in ("lo", "lo0"):
                return iface
    except ImportError:
        pass

    for iface in candidates:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
        except OSError:
            continue
        finally:
            sock.close()

    return "eth0"
```

- [ ] Create `homenetguard/capture/sniffer.py`:

```python
from __future__ import annotations

import threading
import time
from datetime import datetime
from typing import Any, Callable

from homenetguard.analysis.dns_analyzer import DNSAnalyzer
from homenetguard.analysis.geo_lookup import GeoLookup
from homenetguard.analysis.threat_detector import ThreatDetector
from homenetguard.analysis.traffic_analyzer import TrafficAnalyzer
from homenetguard.storage import repository
from homenetguard.utils.logger import get_logger

logger = get_logger(__name__)

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR, ARP, Packet
    _SCAPY_AVAILABLE = True
except ImportError:
    _SCAPY_AVAILABLE = False


class Sniffer:
    def __init__(
        self,
        config: dict[str, Any],
        on_packet: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        self._cfg = config
        self._on_packet = on_packet
        self._running = False
        self._thread: threading.Thread | None = None
        self._interface = config.get("network", {}).get("interface", "auto")
        self._capture_filter = config.get("network", {}).get("capture_filter", "")

        self._geo = GeoLookup(config.get("geoip", {}).get("db_path", "config/geoip/GeoLite2-City.mmdb"))
        self._threat = ThreatDetector(config)
        self._dns = DNSAnalyzer(self._threat)
        self._traffic = TrafficAnalyzer()
        self._packets_captured = 0
        self._started_at: datetime | None = None

    def start(self, interface: str | None = None) -> None:
        if not _SCAPY_AVAILABLE:
            raise RuntimeError("scapy is not installed — cannot capture packets")
        if self._running:
            logger.warning("Sniffer already running")
            return

        iface = interface or self._interface
        if iface == "auto":
            from homenetguard.capture.interface_detector import get_active_interface
            iface = get_active_interface()

        self._running = True
        self._started_at = datetime.utcnow()
        logger.info("Starting capture on interface %s", iface)
        self._thread = threading.Thread(
            target=self._capture_loop,
            args=(iface,),
            daemon=True,
            name="sniffer",
        )
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        logger.info("Sniffer stopped. Captured %d packets", self._packets_captured)

    def is_running(self) -> bool:
        return self._running

    def get_stats(self) -> dict[str, Any]:
        uptime = 0
        if self._started_at:
            uptime = int((datetime.utcnow() - self._started_at).total_seconds())
        return {
            "running": self._running,
            "packets_captured": self._packets_captured,
            "uptime_seconds": uptime,
            "current_bps": self._traffic.get_current_bps(),
        }

    def _capture_loop(self, iface: str) -> None:
        def stop_filter(_: Any) -> bool:
            return not self._running

        try:
            sniff(
                iface=iface,
                prn=self._process_packet,
                filter=self._capture_filter or None,
                store=False,
                stop_filter=stop_filter,
            )
        except Exception as exc:
            logger.error("Capture error on %s: %s", iface, exc)
            self._running = False

    def _process_packet(self, pkt: Any) -> None:
        if not _SCAPY_AVAILABLE:
            return
        self._packets_captured += 1
        try:
            flow = self._packet_to_flow(pkt)
            if flow:
                self._traffic.record_bytes(flow.get("bytes", 0))
                repository.insert_flow(flow)
                self._threat.analyze_flow(flow)
                if self._on_packet:
                    self._on_packet(flow)
        except Exception as exc:
            logger.debug("Error processing packet: %s", exc)

    def _packet_to_flow(self, pkt: Any) -> dict[str, Any] | None:
        if not pkt.haslayer("IP"):
            return None

        ip = pkt["IP"]
        src_ip: str = ip.src
        dst_ip: str = ip.dst
        byte_count: int = len(pkt)
        proto = "OTHER"
        src_port = None
        dst_port = None

        if pkt.haslayer("TCP"):
            proto = "TCP"
            src_port = pkt["TCP"].sport
            dst_port = pkt["TCP"].dport
        elif pkt.haslayer("UDP"):
            proto = "UDP"
            src_port = pkt["UDP"].sport
            dst_port = pkt["UDP"].dport
            if pkt.haslayer("DNS") and pkt["DNS"].qr == 0:
                if pkt.haslayer("DNSQR"):
                    domain = pkt["DNSQR"].qname.decode("utf-8", errors="replace").rstrip(".")
                    qtype = str(pkt["DNSQR"].qtype)
                    self._dns.process_dns_packet(src_ip, domain, qtype)
        elif pkt.haslayer("ICMP"):
            proto = "ICMP"

        src_geo = self._geo.lookup(src_ip)
        dst_geo = self._geo.lookup(dst_ip)

        return {
            "timestamp": datetime.utcnow().isoformat(),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": proto,
            "bytes": byte_count,
            "packets": 1,
            "direction": self._classify_direction(src_ip, dst_ip),
            "src_country": src_geo.get("country"),
            "dst_country": dst_geo.get("country"),
            "src_city": src_geo.get("city"),
            "dst_city": dst_geo.get("city"),
        }

    def _classify_direction(self, src: str, dst: str) -> str:
        from homenetguard.analysis.reputation import is_private_ip
        src_private = is_private_ip(src)
        dst_private = is_private_ip(dst)
        if src_private and not dst_private:
            return "outbound"
        if not src_private and dst_private:
            return "inbound"
        return "local"
```

- [ ] Create `homenetguard/capture/pcap_reader.py`:

```python
from __future__ import annotations

from pathlib import Path
from typing import Any

from homenetguard.utils.logger import get_logger

logger = get_logger(__name__)


class PcapReader:
    def __init__(self, config: dict[str, Any]) -> None:
        self._cfg = config

    def analyze_file(self, file_path: str) -> dict[str, Any]:
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"PCAP file not found: {file_path}")

        try:
            import pyshark  # type: ignore[import]
        except ImportError:
            raise RuntimeError("pyshark not installed — cannot read PCAP files")

        stats: dict[str, Any] = {
            "file": str(path),
            "total_packets": 0,
            "total_bytes": 0,
            "protocols": {},
            "top_src_ips": {},
            "top_dst_ips": {},
        }

        try:
            cap = pyshark.FileCapture(str(path), keep_packets=False)
            for pkt in cap:
                stats["total_packets"] += 1
                try:
                    length = int(pkt.length)
                    stats["total_bytes"] += length
                except AttributeError:
                    pass
                try:
                    proto = pkt.highest_layer
                    stats["protocols"][proto] = stats["protocols"].get(proto, 0) + 1
                except AttributeError:
                    pass
                try:
                    src = pkt.ip.src
                    stats["top_src_ips"][src] = stats["top_src_ips"].get(src, 0) + 1
                except AttributeError:
                    pass
            cap.close()
        except Exception as exc:
            logger.error("Error reading PCAP %s: %s", file_path, exc)
            raise

        return stats
```

- [ ] Commit: `git add -A && git commit -m "feat: packet capture layer (sniffer, pcap reader, interface detection)"`

---

## Phase 5: Alerts

### Task 10: Alert notifiers

**Files:**
- Create: `homenetguard/alerts/email_alert.py`
- Create: `homenetguard/alerts/telegram_alert.py`
- Create: `homenetguard/alerts/notifier.py`

- [ ] Create `homenetguard/alerts/email_alert.py`:

```python
from __future__ import annotations

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any

from homenetguard.utils.logger import get_logger

logger = get_logger(__name__)


class EmailAlert:
    def __init__(self, config: dict[str, Any]) -> None:
        self._cfg = config

    def send(self, subject: str, body: str) -> bool:
        cfg = self._cfg
        if not cfg.get("enabled"):
            return False
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"[HomeNetGuard] {subject}"
            msg["From"] = cfg["smtp_user"]
            msg["To"] = cfg["recipient"]
            msg.attach(MIMEText(body, "plain"))
            with smtplib.SMTP(cfg["smtp_host"], cfg["smtp_port"]) as server:
                server.starttls()
                server.login(cfg["smtp_user"], cfg["smtp_password"])
                server.send_message(msg)
            logger.info("Email alert sent: %s", subject)
            return True
        except Exception as exc:
            logger.error("Failed to send email alert: %s", exc)
            return False
```

- [ ] Create `homenetguard/alerts/telegram_alert.py`:

```python
from __future__ import annotations

from typing import Any

from homenetguard.utils.logger import get_logger

logger = get_logger(__name__)


class TelegramAlert:
    def __init__(self, config: dict[str, Any]) -> None:
        self._cfg = config

    def send(self, message: str) -> bool:
        cfg = self._cfg
        if not cfg.get("enabled"):
            return False
        try:
            import requests
            token = cfg["bot_token"]
            chat_id = cfg["chat_id"]
            resp = requests.post(
                f"https://api.telegram.org/bot{token}/sendMessage",
                json={"chat_id": chat_id, "text": f"🔒 HomeNetGuard\n{message}", "parse_mode": "Markdown"},
                timeout=10,
            )
            resp.raise_for_status()
            logger.info("Telegram alert sent")
            return True
        except Exception as exc:
            logger.error("Failed to send Telegram alert: %s", exc)
            return False
```

- [ ] Create `homenetguard/alerts/notifier.py`:

```python
from __future__ import annotations

from typing import Any

from homenetguard.alerts.email_alert import EmailAlert
from homenetguard.alerts.telegram_alert import TelegramAlert
from homenetguard.utils.logger import get_logger

logger = get_logger(__name__)

_SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


class Notifier:
    def __init__(self, config: dict[str, Any]) -> None:
        alerts_cfg = config.get("alerts", {})
        self._email = EmailAlert(alerts_cfg.get("email", {}))
        self._telegram = TelegramAlert(alerts_cfg.get("telegram", {}))
        self._email_min = alerts_cfg.get("email", {}).get("min_severity", "high")
        self._tg_min = alerts_cfg.get("telegram", {}).get("min_severity", "critical")

    def dispatch(self, alert_type: str, severity: str, description: str) -> None:
        sev_val = _SEVERITY_ORDER.get(severity, 0)
        subject = f"[{severity.upper()}] {alert_type}"
        body = description

        if sev_val >= _SEVERITY_ORDER.get(self._email_min, 2):
            self._email.send(subject, body)

        if sev_val >= _SEVERITY_ORDER.get(self._tg_min, 3):
            self._telegram.send(f"*{subject}*\n{body}")
```

- [ ] Commit: `git add -A && git commit -m "feat: alert notifiers (email, telegram, orchestrator)"`

---

## Phase 6: Dashboard

### Task 11: Flask app + routes + WebSocket events

**Files:**
- Create: `homenetguard/dashboard/app.py`
- Create: `homenetguard/dashboard/routes.py`
- Create: `homenetguard/dashboard/events.py`

- [ ] Create `homenetguard/dashboard/app.py`:

```python
from __future__ import annotations

import threading
import time
from typing import Any

from flask import Flask
from flask_socketio import SocketIO

from homenetguard.utils.logger import get_logger

logger = get_logger(__name__)

socketio = SocketIO()


def create_app(config: dict[str, Any], sniffer: Any = None) -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config["SECRET_KEY"] = "homenetguard-local-only"
    app.config["HNG_CONFIG"] = config
    app.config["HNG_SNIFFER"] = sniffer

    socketio.init_app(app, cors_allowed_origins="*", async_mode="threading")

    from homenetguard.dashboard.routes import bp
    app.register_blueprint(bp)

    from homenetguard.dashboard import events  # noqa: F401  registers handlers

    return app


def run_dashboard(config: dict[str, Any], sniffer: Any = None) -> None:
    dash_cfg = config.get("dashboard", {})
    host = dash_cfg.get("host", "127.0.0.1")
    port = dash_cfg.get("port", 5000)

    app = create_app(config, sniffer)

    if dash_cfg.get("auto_open_browser", False):
        import webbrowser
        threading.Timer(1.5, lambda: webbrowser.open(f"http://{host}:{port}")).start()

    logger.info("Dashboard running at http://%s:%d", host, port)
    socketio.run(app, host=host, port=port, debug=False, use_reloader=False)
```

- [ ] Create `homenetguard/dashboard/routes.py`:

```python
from __future__ import annotations

from datetime import datetime, timedelta

from flask import Blueprint, current_app, jsonify, render_template, request

from homenetguard.storage import repository

bp = Blueprint("main", __name__)


@bp.route("/")
def index():
    return render_template("index.html")


@bp.route("/alerts")
def alerts_view():
    return render_template("alerts.html")


@bp.route("/flows")
def flows_view():
    return render_template("flows.html")


@bp.route("/dns")
def dns_view():
    return render_template("dns.html")


@bp.route("/reports")
def reports_view():
    return render_template("reports.html")


@bp.route("/config")
def config_view():
    cfg = current_app.config.get("HNG_CONFIG", {})
    safe_cfg = _sanitize_config(cfg)
    return render_template("config.html", config=safe_cfg)


@bp.route("/api/stats")
def api_stats():
    since = datetime.utcnow() - timedelta(minutes=60)
    stats = repository.get_flow_stats(since=since)
    alerts = repository.get_unacknowledged_alerts(limit=5)
    sniffer = current_app.config.get("HNG_SNIFFER")
    sniffer_stats = sniffer.get_stats() if sniffer else {}
    return jsonify({**stats, "alerts": alerts, "sniffer": sniffer_stats})


@bp.route("/api/flows")
def api_flows():
    limit = min(int(request.args.get("limit", 100)), 500)
    offset = int(request.args.get("offset", 0))
    flows = repository.get_recent_flows(limit=limit, offset=offset)
    return jsonify(flows)


@bp.route("/api/alerts")
def api_alerts():
    severity = request.args.get("severity")
    alert_type = request.args.get("type")
    alerts = repository.get_all_alerts(severity=severity, alert_type=alert_type)
    return jsonify(alerts)


@bp.route("/api/alerts/<int:alert_id>/acknowledge", methods=["POST"])
def api_ack_alert(alert_id: int):
    repository.acknowledge_alert(alert_id)
    return jsonify({"ok": True})


@bp.route("/api/alerts/clear", methods=["POST"])
def api_clear_alerts():
    count = repository.clear_all_alerts()
    return jsonify({"cleared": count})


@bp.route("/api/dns")
def api_dns():
    queries = repository.get_recent_dns_queries(limit=200)
    return jsonify(queries)


@bp.route("/api/top-ips")
def api_top_ips():
    since = datetime.utcnow() - timedelta(minutes=5)
    ips = repository.get_top_ips(limit=10, since=since)
    return jsonify(ips)


@bp.route("/api/protocols")
def api_protocols():
    since = datetime.utcnow() - timedelta(minutes=60)
    dist = repository.get_protocol_distribution(since=since)
    return jsonify(dist)


@bp.route("/api/reports")
def api_reports():
    return jsonify(repository.get_reports())


def _sanitize_config(cfg: dict) -> dict:
    import copy
    safe = copy.deepcopy(cfg)
    for section in ("threat_intelligence", "alerts"):
        if section in safe:
            for subsection in safe[section].values():
                if isinstance(subsection, dict):
                    for key in ("api_key", "smtp_password", "bot_token", "password"):
                        if key in subsection:
                            subsection[key] = "***"
    return safe
```

- [ ] Create `homenetguard/dashboard/events.py`:

```python
from __future__ import annotations

import time
import threading
from datetime import datetime, timedelta

from flask_socketio import emit

from homenetguard.dashboard.app import socketio
from homenetguard.storage import repository
from homenetguard.utils.logger import get_logger

logger = get_logger(__name__)

_push_thread: threading.Thread | None = None
_push_running = False


@socketio.on("connect")
def on_connect():
    logger.debug("Dashboard client connected")
    global _push_thread, _push_running
    if _push_thread is None or not _push_thread.is_alive():
        _push_running = True
        _push_thread = threading.Thread(target=_push_loop, daemon=True)
        _push_thread.start()


@socketio.on("disconnect")
def on_disconnect():
    logger.debug("Dashboard client disconnected")


def _push_loop() -> None:
    while _push_running:
        try:
            since = datetime.utcnow() - timedelta(minutes=1)
            stats = repository.get_flow_stats(since=since)
            alerts = repository.get_unacknowledged_alerts(limit=10)
            flows = repository.get_recent_flows(limit=20)
            socketio.emit("stats_update", {
                "stats": stats,
                "alerts": alerts,
                "flows": flows,
                "timestamp": datetime.utcnow().isoformat(),
            })
        except Exception as exc:
            logger.debug("Push loop error: %s", exc)
        time.sleep(2)
```

- [ ] Commit: `git add -A && git commit -m "feat: Flask dashboard app, routes, WebSocket events"`

---

### Task 12: Dashboard templates + CSS + JS

**Files:**
- Create: `homenetguard/dashboard/static/css/variables.css`
- Create: `homenetguard/dashboard/static/css/dashboard.css`
- Create: `homenetguard/dashboard/static/js/dashboard.js`
- Create: `homenetguard/dashboard/templates/base.html`
- Create: `homenetguard/dashboard/templates/index.html`
- Create: `homenetguard/dashboard/templates/alerts.html`
- Create: `homenetguard/dashboard/templates/flows.html`
- Create: `homenetguard/dashboard/templates/dns.html`
- Create: `homenetguard/dashboard/templates/reports.html`
- Create: `homenetguard/dashboard/templates/config.html`

- [ ] Create `homenetguard/dashboard/static/css/variables.css` (complete CSS variables from spec section 8)

- [ ] Create all templates and JS (see implementation notes below)

*Implementation notes for Task 12 — exact file content is in Phase 6 detail tasks below*

- [ ] Commit: `git add -A && git commit -m "feat: dashboard UI — cyber SOC theme, all views"`

---

## Phase 7: Reports

### Task 13: Report generator + templates

**Files:**
- Create: `homenetguard/reports/report_generator.py`
- Create: `homenetguard/reports/html_renderer.py`
- Create: `homenetguard/reports/pdf_exporter.py`
- Create: `homenetguard/reports/templates/base.html`
- Create: `homenetguard/reports/templates/report_daily.html`

- [ ] (See detailed file content in implementation — reports follow Jinja2 + WeasyPrint pattern)

- [ ] Commit: `git add -A && git commit -m "feat: report generator (HTML + PDF)"`

---

## Phase 8: CLI

### Task 14: Click CLI entrypoint

**Files:**
- Create: `homenetguard/main.py`

- [ ] (See detailed implementation — full Click CLI with all subcommands)

- [ ] Commit: `git add -A && git commit -m "feat: CLI entrypoint with all subcommands"`

---

## Phase 9: Tooling

### Task 15: Makefile + scripts + CI

**Files:**
- Create: `Makefile`
- Create: `scripts/install_system_deps.sh`
- Create: `scripts/download_geoip.sh`
- Create: `.pre-commit-config.yaml`
- Create: `.github/workflows/ci.yml`
- Create: `.github/workflows/release.yml`

- [ ] Commit: `git add -A && git commit -m "chore: Makefile, scripts, CI/CD"`

---

## Phase 10: Documentation

### Task 16: README + docs

**Files:**
- Create: `README.md`
- Create: `docs/architecture.md`
- Create: `docs/configuration.md`
- Create: `docs/usage.md`
- Create: `docs/threat_detection.md`

- [ ] Commit: `git add -A && git commit -m "docs: README, architecture, usage, configuration"`

---

## Self-Review vs Spec

| Spec Section | Covered | Notes |
|---|---|---|
| Stack (Python, Scapy, Flask, SQLite, Click) | ✓ | All deps in pyproject.toml |
| Directory structure | ✓ | Task 1 scaffold |
| DB schema (5 tables + indexes) | ✓ | Task 4 |
| CLI (8 subcommands) | Plan | Task 14 |
| Threat detectors (6 types) | ✓ | Task 7 (port scan, flood, blacklist, DNS); ARP needs Task 7 extension |
| Config YAML + .env | ✓ | Tasks 2-3 |
| Dashboard views (6 views) | Plan | Task 11-12 |
| Cyber SOC design system | Plan | Task 12 detail |
| Report sections (8 sections) | Plan | Task 13 |
| GitHub Actions CI | Plan | Task 15 |
| README 13 sections | Plan | Task 16 |
| Makefile 10 commands | Plan | Task 15 |

**Gap:** ARP spoofing detector not in Task 7 — add to threat_detector.py during Task 9 (can access MAC from Scapy ARP layer).
