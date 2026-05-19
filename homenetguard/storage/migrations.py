from __future__ import annotations

import sqlite3

from homenetguard.utils.logger import get_logger

logger = get_logger(__name__)

_V2_COLUMNS = [
    ("flows",  "ALTER TABLE flows ADD COLUMN app_protocol TEXT"),
    ("flows",  "ALTER TABLE flows ADD COLUMN session_id TEXT"),
    ("flows",  "ALTER TABLE flows ADD COLUMN ja3_hash TEXT"),
    ("alerts", "ALTER TABLE alerts ADD COLUMN mitre_tactic TEXT"),
    ("alerts", "ALTER TABLE alerts ADD COLUMN mitre_technique TEXT"),
    ("alerts", "ALTER TABLE alerts ADD COLUMN device_mac TEXT"),
]

_V2_TABLES = """
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mac_address TEXT UNIQUE NOT NULL,
    ip_address TEXT,
    vendor TEXT,
    hostname TEXT,
    os_guess TEXT,
    os_confidence REAL,
    first_seen DATETIME NOT NULL,
    last_seen DATETIME NOT NULL,
    is_trusted INTEGER DEFAULT 0,
    is_quarantined INTEGER DEFAULT 0,
    notes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS device_ip_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mac_address TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    seen_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS firewall_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_type TEXT NOT NULL,
    target TEXT NOT NULL,
    direction TEXT,
    reason TEXT,
    auto_added INTEGER DEFAULT 0,
    expires_at DATETIME,
    is_active INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS sinkhole_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT UNIQUE NOT NULL,
    reason TEXT,
    source TEXT,
    is_active INTEGER DEFAULT 1,
    hits INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    src_port INTEGER,
    dst_port INTEGER,
    protocol TEXT,
    app_protocol TEXT,
    start_time DATETIME NOT NULL,
    end_time DATETIME,
    duration_seconds REAL,
    total_bytes INTEGER DEFAULT 0,
    total_packets INTEGER DEFAULT 0,
    upload_bytes INTEGER DEFAULT 0,
    download_bytes INTEGER DEFAULT 0,
    ja3_hash TEXT,
    ja3s_hash TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS traffic_metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    window_start DATETIME NOT NULL,
    window_seconds INTEGER NOT NULL,
    bytes_total INTEGER DEFAULT 0,
    packets_total INTEGER DEFAULT 0,
    unique_src_ips INTEGER DEFAULT 0,
    unique_dst_ips INTEGER DEFAULT 0,
    unique_ports INTEGER DEFAULT 0,
    tcp_flows INTEGER DEFAULT 0,
    udp_flows INTEGER DEFAULT 0,
    dns_queries INTEGER DEFAULT 0,
    alerts_count INTEGER DEFAULT 0,
    anomaly_score REAL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac_address);
CREATE INDEX IF NOT EXISTS idx_sessions_src ON sessions(src_ip);
CREATE INDEX IF NOT EXISTS idx_metrics_window ON traffic_metrics(window_start);
"""


def run_migrations(conn: sqlite3.Connection) -> None:
    """Idempotent — safe to call on every startup."""
    for _, sql in _V2_COLUMNS:
        try:
            conn.execute(sql)
            logger.debug("Migration applied: %s", sql[:60])
        except sqlite3.OperationalError:
            pass  # column already exists

    conn.executescript(_V2_TABLES)
    logger.debug("V2 table migrations complete")
