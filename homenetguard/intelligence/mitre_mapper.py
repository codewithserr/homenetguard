from __future__ import annotations

from typing import Any

MITRE_MAPPING: dict[str, dict[str, str]] = {
    "port_scan":      {"tactic": "Discovery",         "technique": "T1046",     "name": "Network Service Discovery"},
    "beaconing":      {"tactic": "Command & Control", "technique": "T1071",     "name": "Application Layer Protocol"},
    "dns_tunneling":  {"tactic": "Exfiltration",      "technique": "T1048.003", "name": "Exfiltration Over DNS"},
    "arp_spoofing":   {"tactic": "Credential Access", "technique": "T1557.002", "name": "ARP Cache Poisoning"},
    "cryptomining":   {"tactic": "Impact",            "technique": "T1496",     "name": "Resource Hijacking"},
    "flood":          {"tactic": "Impact",            "technique": "T1499",     "name": "Endpoint Denial of Service"},
    "tls_anomaly":    {"tactic": "Command & Control", "technique": "T1573",     "name": "Encrypted Channel"},
    "blacklisted_ip": {"tactic": "Command & Control", "technique": "T1071",     "name": "Application Layer Protocol"},
    "new_device":     {"tactic": "Discovery",         "technique": "T1018",     "name": "Remote System Discovery"},
    "dns_rebinding":  {"tactic": "Defense Evasion",   "technique": "T1071.004", "name": "DNS"},
    "dns_anomaly":    {"tactic": "Exfiltration",      "technique": "T1048.003", "name": "Exfiltration Over DNS"},
    "os_anomaly":     {"tactic": "Discovery",         "technique": "T1082",     "name": "System Information Discovery"},
    "ja3_malicious":  {"tactic": "Command & Control", "technique": "T1573.001", "name": "Symmetric Cryptography"},
}


def map_alert(alert_type: str) -> dict[str, str] | None:
    return MITRE_MAPPING.get(alert_type)


def enrich_alert(alert: dict[str, Any]) -> dict[str, Any]:
    alert_type = alert.get("alert_type", "")
    mapping = map_alert(alert_type)
    if mapping:
        alert["mitre_tactic"] = mapping["tactic"]
        alert["mitre_technique"] = mapping["technique"]
    return alert


def get_all_tactics() -> list[str]:
    return sorted({m["tactic"] for m in MITRE_MAPPING.values()})


def get_techniques_by_tactic(tactic: str) -> list[dict[str, str]]:
    return [
        {"alert_type": k, **v}
        for k, v in MITRE_MAPPING.items()
        if v["tactic"] == tactic
    ]
