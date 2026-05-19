from unittest.mock import MagicMock, patch

import pytest


# ─── permissions ────────────────────────────────────────────────
def test_permissions_root_always_ok():
    from homenetguard.utils.permissions import check_capture_permissions
    with patch("os.geteuid", return_value=0):
        assert check_capture_permissions() is True


def test_permissions_linux_cap_net_raw_present(tmp_path):
    from homenetguard.utils.permissions import _check_linux_cap_net_raw
    status_file = tmp_path / "status"
    # cap_net_raw = 1 << 13 = 0x2000
    status_file.write_text("CapEff:\t0000000000002000\n")
    with patch("builtins.open", return_value=open(status_file)):
        result = _check_linux_cap_net_raw()
    assert result is True


def test_permissions_linux_cap_net_raw_absent(tmp_path):
    from homenetguard.utils.permissions import _check_linux_cap_net_raw
    status_file = tmp_path / "status"
    status_file.write_text("CapEff:\t0000000000000000\n")
    with patch("builtins.open", return_value=open(status_file)):
        result = _check_linux_cap_net_raw()
    assert result is False


def test_permissions_macos_access_bpf_present():
    from homenetguard.utils.permissions import _check_macos_bpf
    with patch("os.getgroups", return_value=[1, 2, 3]):
        with patch("grp.getgrgid") as mock_grp:
            mock_grp.side_effect = lambda g: MagicMock(gr_name={1: "staff", 2: "access_bpf", 3: "admin"}[g])
            assert _check_macos_bpf() is True


def test_permissions_macos_no_access_bpf():
    from homenetguard.utils.permissions import _check_macos_bpf
    with patch("os.getgroups", return_value=[1, 2]):
        with patch("grp.getgrgid") as mock_grp:
            mock_grp.side_effect = lambda g: MagicMock(gr_name={1: "staff", 2: "admin"}[g])
            assert _check_macos_bpf() is False


def test_check_permissions_unknown_os():
    from homenetguard.utils.permissions import check_capture_permissions
    with patch("os.geteuid", return_value=1000):
        with patch("platform.system", return_value="Windows"):
            result = check_capture_permissions()
    assert result is False


# ─── interface_detector ─────────────────────────────────────────
def test_get_active_interface_fallback():
    from homenetguard.capture.interface_detector import get_active_interface
    with patch("homenetguard.capture.interface_detector.socket.socket") as mock_sock_cls:
        mock_sock = MagicMock()
        mock_sock_cls.return_value = mock_sock
        mock_sock.getsockname.return_value = ("192.168.1.100", 0)
        iface = get_active_interface()
    # Returns something (either from scapy or fallback)
    assert isinstance(iface, str)
    assert len(iface) > 0


def test_list_interfaces_fallback():
    from homenetguard.capture.interface_detector import list_interfaces
    with patch("homenetguard.capture.interface_detector.get_if_list", create=True, side_effect=Exception("no scapy")):
        ifaces = list_interfaces()
    assert isinstance(ifaces, list)


# ─── sniffer non-network paths ───────────────────────────────────
def test_sniffer_stats_before_start():
    from homenetguard.capture.sniffer import Sniffer
    cfg = {
        "network": {"interface": "auto", "capture_filter": ""},
        "geoip": {"db_path": "/nonexistent"},
        "detection": {
            "port_scan": {"enabled": False},
            "flood": {"enabled": False},
            "dns_anomaly": {"enabled": False},
        }
    }
    sniffer = Sniffer(cfg)
    stats = sniffer.get_stats()
    assert stats["running"] is False
    assert stats["packets_captured"] == 0
    assert stats["uptime_seconds"] == 0


def test_sniffer_classify_direction():
    from homenetguard.capture.sniffer import Sniffer
    cfg = {
        "network": {"interface": "auto", "capture_filter": ""},
        "geoip": {"db_path": "/nonexistent"},
        "detection": {"port_scan": {"enabled": False}, "flood": {"enabled": False}, "dns_anomaly": {"enabled": False}},
    }
    s = Sniffer(cfg)
    assert s._classify_direction("192.168.1.1", "8.8.8.8") == "outbound"
    assert s._classify_direction("8.8.8.8", "192.168.1.1") == "inbound"
    assert s._classify_direction("192.168.1.1", "192.168.1.2") == "local"


def test_sniffer_no_scapy_raises():
    from homenetguard.capture import sniffer as sniffer_mod
    cfg = {
        "network": {"interface": "lo", "capture_filter": ""},
        "geoip": {"db_path": "/nonexistent"},
        "detection": {"port_scan": {"enabled": False}, "flood": {"enabled": False}, "dns_anomaly": {"enabled": False}},
    }
    original = sniffer_mod._SCAPY_AVAILABLE
    try:
        sniffer_mod._SCAPY_AVAILABLE = False
        s = sniffer_mod.Sniffer(cfg)
        with pytest.raises(RuntimeError, match="scapy not installed"):
            s.start()
    finally:
        sniffer_mod._SCAPY_AVAILABLE = original


def test_sniffer_stop_not_started():
    from homenetguard.capture.sniffer import Sniffer
    cfg = {
        "network": {"interface": "auto", "capture_filter": ""},
        "geoip": {"db_path": "/nonexistent"},
        "detection": {"port_scan": {"enabled": False}, "flood": {"enabled": False}, "dns_anomaly": {"enabled": False}},
    }
    s = Sniffer(cfg)
    s.stop()  # should not raise
    assert s.is_running() is False
