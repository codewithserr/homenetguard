import os
import pytest
from pathlib import Path
from homenetguard.utils import config_loader


@pytest.fixture(autouse=True)
def reset_config():
    config_loader.reset_config()
    yield
    config_loader.reset_config()


def test_load_config_from_file(tmp_path):
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text("""
network:
  interface: eth0
  capture_filter: ""
storage:
  db_path: data/test.db
  captures_path: data/captures
  reports_path: data/reports
  retention_days: 30
dashboard:
  enabled: true
  host: 127.0.0.1
  port: 5000
  auto_open_browser: false
  update_interval_seconds: 5
geoip:
  enabled: false
  db_path: config/geoip/GeoLite2-City.mmdb
threat_intelligence:
  abuseipdb:
    enabled: false
    api_key: ""
    cache_hours: 24
  virustotal:
    enabled: false
    api_key: ""
detection:
  port_scan:
    enabled: true
    threshold_ports: 15
    threshold_seconds: 60
  beaconing:
    enabled: true
    min_connections: 10
    interval_tolerance_pct: 10
  flood:
    enabled: true
    threshold_mb: 10
    threshold_seconds: 30
  dns_anomaly:
    enabled: true
    max_domain_length: 50
    max_nxdomain_per_minute: 20
firewall:
  auto_block: false
  block_backend: iptables
alerts:
  email:
    enabled: false
    smtp_host: ""
    smtp_port: 587
    smtp_user: ""
    smtp_password: ""
    recipient: ""
    min_severity: high
  telegram:
    enabled: false
    bot_token: ""
    chat_id: ""
    min_severity: critical
logging:
  level: INFO
  file: logs/test.log
  max_size_mb: 10
  backup_count: 3
""")
    cfg = config_loader.load_config(cfg_file)
    assert cfg["network"]["interface"] == "eth0"
    assert cfg["storage"]["db_path"] == "data/test.db"
    assert cfg["dashboard"]["port"] == 5000


def test_load_config_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        config_loader.load_config(tmp_path / "nonexistent.yaml")


def test_get_config_caches(tmp_path):
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text("network:\n  interface: wlan0\nstorage:\n  db_path: x.db\n")
    cfg1 = config_loader.load_config(cfg_file)
    cfg2 = config_loader.get_config()
    assert cfg1 is cfg2


def test_inject_env_secrets(tmp_path, monkeypatch):
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text("threat_intelligence:\n  abuseipdb:\n    enabled: true\n    api_key: \"\"\nalerts:\n  email:\n    enabled: false\n    smtp_password: \"\"\n  telegram:\n    enabled: false\n    bot_token: \"\"\n")
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test_key_123")
    cfg = config_loader.load_config(cfg_file)
    assert cfg["threat_intelligence"]["abuseipdb"]["api_key"] == "test_key_123"
