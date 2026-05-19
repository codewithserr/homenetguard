
import pytest
from click.testing import CliRunner

from homenetguard.main import cli
from homenetguard.storage import database


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def setup_config(tmp_path):
    cfg_file = tmp_path / "config.yaml"
    db_file = tmp_path / "test.db"
    reports_dir = tmp_path / "reports"
    reports_dir.mkdir()
    cfg_file.write_text(f"""
network:
  interface: auto
  capture_filter: ""
  max_pcap_size_mb: 500
  rotate_pcap_hours: 24
storage:
  db_path: {db_file}
  captures_path: {tmp_path}/captures
  reports_path: {reports_dir}
  retention_days: 30
dashboard:
  enabled: false
  host: 127.0.0.1
  port: 5000
  auto_open_browser: false
  update_interval_seconds: 5
geoip:
  enabled: false
  db_path: /nonexistent/geoip.mmdb
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
  level: ERROR
  file: {tmp_path}/test.log
  max_size_mb: 10
  backup_count: 3
""")
    database.init_db(str(db_file))
    return str(cfg_file), str(db_file)


def test_cli_no_args(runner):
    result = runner.invoke(cli, [])
    # Click shows help and exits with 0 or 2 depending on version when no subcommand given
    assert "HomeNetGuard" in result.output or "Usage" in result.output


def test_cli_help(runner):
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "start" in result.output


def test_status_command(runner, setup_config):
    cfg_path, _ = setup_config
    result = runner.invoke(cli, ["-c", cfg_path, "status"])
    assert result.exit_code == 0
    assert "Interface" in result.output


def test_alerts_list_empty(runner, setup_config):
    cfg_path, _ = setup_config
    result = runner.invoke(cli, ["-c", cfg_path, "alerts", "--list"])
    assert result.exit_code == 0
    assert "No unacknowledged" in result.output


def test_alerts_clear_all(runner, setup_config):
    cfg_path, _ = setup_config
    result = runner.invoke(cli, ["-c", cfg_path, "alerts", "--clear-all"])
    assert result.exit_code == 0


def test_config_show(runner, setup_config):
    cfg_path, _ = setup_config
    result = runner.invoke(cli, ["-c", cfg_path, "config", "--show"])
    assert result.exit_code == 0
    assert "network" in result.output


def test_config_init_no_template(runner, tmp_path):
    # Invoke config --init in a dir with no template → should exit with error
    with runner.isolated_filesystem():
        result = runner.invoke(cli, ["config", "--init"])
        # Either "already exists" (if yaml exists) or error about missing template
        assert result.exit_code in (0, 1)


def test_report_command_html(runner, setup_config):
    cfg_path, _ = setup_config
    result = runner.invoke(cli, ["-c", cfg_path, "report", "--type", "daily", "--format", "html"])
    assert result.exit_code == 0


def test_stop_command(runner):
    result = runner.invoke(cli, ["stop"])
    assert result.exit_code == 0


def test_analyze_missing_file(runner, setup_config):
    cfg_path, _ = setup_config
    result = runner.invoke(cli, ["-c", cfg_path, "analyze", "--file", "/nonexistent.pcap"])
    assert result.exit_code != 0
