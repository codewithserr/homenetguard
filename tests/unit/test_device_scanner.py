from unittest.mock import patch

import pytest

from homenetguard.network.device_scanner import DeviceScanner, _detect_subnet, lookup_vendor
from homenetguard.storage import database


@pytest.fixture(autouse=True)
def in_memory_db(tmp_path):
    database.init_db(str(tmp_path / "test.db"))


def test_detect_subnet_returns_cidr():
    subnet = _detect_subnet()
    assert "/" in subnet
    assert subnet.endswith("/24")


def test_lookup_vendor_unknown_without_db():
    result = lookup_vendor("AA:BB:CC:DD:EE:FF")
    assert result == "Unknown"


def test_scan_returns_list():
    scanner = DeviceScanner({})
    with patch.object(scanner, "_arp_scan", return_value=[]):
        result = scanner.scan("192.168.1.0/24")
    assert isinstance(result, list)


def test_update_device_db_inserts_new():
    scanner = DeviceScanner({})
    discovered = [{"mac": "AA:BB:CC:DD:EE:FF", "ip": "192.168.1.100", "vendor": "TestVendor", "hostname": None}]
    new_macs = scanner._update_device_db(discovered)
    assert "AA:BB:CC:DD:EE:FF" in new_macs

    from homenetguard.storage.database import get_connection
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM devices WHERE mac_address='AA:BB:CC:DD:EE:FF'").fetchone()
    assert row is not None
    assert row["ip_address"] == "192.168.1.100"


def test_update_device_db_updates_existing():
    scanner = DeviceScanner({})
    d1 = [{"mac": "11:22:33:44:55:66", "ip": "192.168.1.1", "vendor": "V1", "hostname": None}]
    scanner._update_device_db(d1)

    d2 = [{"mac": "11:22:33:44:55:66", "ip": "192.168.1.2", "vendor": "V1", "hostname": None}]
    new_macs = scanner._update_device_db(d2)
    assert "11:22:33:44:55:66" not in new_macs  # not new

    from homenetguard.storage.database import get_connection
    with get_connection() as conn:
        row = conn.execute("SELECT ip_address FROM devices WHERE mac_address='11:22:33:44:55:66'").fetchone()
    assert row["ip_address"] == "192.168.1.2"


def test_scan_mocked_arp():
    scanner = DeviceScanner({})
    mock_devices = [
        {"mac": "00:11:22:33:44:55", "ip": "192.168.1.10", "vendor": "Apple", "hostname": "iphone"},
        {"mac": "AA:BB:CC:DD:EE:FF", "ip": "192.168.1.20", "vendor": "Unknown", "hostname": None},
    ]
    with patch.object(scanner, "_arp_scan", return_value=mock_devices):
        result = scanner.scan("192.168.1.0/24")
    assert len(result) == 2
    assert result[0]["mac"] == "00:11:22:33:44:55"
