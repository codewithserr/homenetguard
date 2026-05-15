# Threat Detection

HomeNetGuard implements 6 detectors in `homenetguard/analysis/threat_detector.py`.

## Port Scan Detection

**Trigger:** One source IP contacts ≥ `threshold_ports` (default: 15) distinct destination ports within `threshold_seconds` (default: 60s).

**Severity:** `high`

**How it works:** Each source IP maintains an in-memory set of destination ports seen within the time window. When the window expires, the counter resets. SYN-only packets (no response) are still counted.

## Traffic Flood / DoS

**Trigger:** Total bytes from one source IP exceeds `threshold_mb` (default: 10 MB) within `threshold_seconds` (default: 30s).

**Severity:** `high`

**How it works:** Per-IP byte accumulator resets after each time window. Counts all traffic (TCP, UDP, ICMP) from the source.

## Blacklisted IP

**Trigger:** Any flow involving an IP with `is_blacklisted = true` in the `ip_reputation` table.

**Severity:** `critical`

**How it works:** Every flow is checked against the local reputation database. Populate it via AbuseIPDB integration (`threat_intelligence.abuseipdb.enabled = true`) or manually via `repository.upsert_ip_reputation()`.

## DNS Anomaly

**Trigger (domain length):** Queried domain name exceeds `max_domain_length` (default: 50 chars). Unusually long domains suggest DNS tunneling (data encoded in subdomains).

**Trigger (high entropy):** Subdomain portion of the domain has Shannon entropy > 3.5 bits. Random-looking subdomains suggest automated/malicious generation.

**Severity:** `medium`

## ARP Spoofing

**Trigger:** Same IP address seen with two or more different MAC addresses in ARP traffic.

**Severity:** `high`

**How it works:** In-memory dict maps `ip → {mac1, mac2, ...}`. First time a new MAC is seen for an existing IP, an alert fires. This detects classic ARP poisoning/Man-in-the-Middle attacks.

## Adding Custom Detectors

Subclass or extend `ThreatDetector`:

```python
def analyze_flow(self, flow: dict) -> None:
    super().analyze_flow(flow)
    # your logic here
    if my_condition(flow):
        repository.insert_alert(
            alert_type="my_custom_type",
            severity="medium",
            src_ip=flow["src_ip"],
            description="My custom detection triggered",
        )
```
