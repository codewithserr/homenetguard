import pytest
from homenetguard.intelligence.mitre_mapper import (
    map_alert, enrich_alert, get_all_tactics, get_techniques_by_tactic, MITRE_MAPPING,
)


def test_all_alert_types_have_mapping():
    expected_types = [
        "port_scan", "beaconing", "dns_tunneling", "arp_spoofing",
        "cryptomining", "flood", "tls_anomaly", "blacklisted_ip",
        "new_device", "dns_anomaly",
    ]
    for alert_type in expected_types:
        mapping = map_alert(alert_type)
        assert mapping is not None, f"Missing MITRE mapping for: {alert_type}"
        assert "tactic" in mapping
        assert "technique" in mapping
        assert "name" in mapping


def test_map_alert_port_scan():
    m = map_alert("port_scan")
    assert m["tactic"] == "Discovery"
    assert m["technique"] == "T1046"


def test_map_alert_unknown_returns_none():
    assert map_alert("nonexistent_type") is None


def test_enrich_alert_adds_fields():
    alert = {"alert_type": "flood", "severity": "high", "description": "test"}
    enriched = enrich_alert(alert)
    assert "mitre_tactic" in enriched
    assert enriched["mitre_tactic"] == "Impact"
    assert "mitre_technique" in enriched


def test_enrich_alert_unknown_type_no_crash():
    alert = {"alert_type": "unknown_type", "description": "x"}
    enriched = enrich_alert(alert)
    assert "mitre_tactic" not in enriched


def test_get_all_tactics():
    tactics = get_all_tactics()
    assert "Discovery" in tactics
    assert "Command & Control" in tactics
    assert "Impact" in tactics
    assert len(tactics) >= 4


def test_get_techniques_by_tactic():
    techniques = get_techniques_by_tactic("Discovery")
    assert len(techniques) >= 1
    assert all("technique" in t for t in techniques)


def test_mapping_has_required_fields():
    for key, val in MITRE_MAPPING.items():
        assert "tactic" in val, f"{key} missing tactic"
        assert "technique" in val, f"{key} missing technique"
        assert "name" in val, f"{key} missing name"
        assert val["technique"].startswith("T"), f"{key} technique should start with T"
