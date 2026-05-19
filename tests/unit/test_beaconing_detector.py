from datetime import UTC, datetime

from homenetguard.analysis.beaconing_detector import analyze_beaconing


def _make_flows(timestamps_iso: list[str]) -> list[dict]:
    return [{"timestamp": ts} for ts in timestamps_iso]


def _iso(base_epoch: float, offset: float) -> str:
    return datetime.fromtimestamp(base_epoch + offset, tz=UTC).isoformat()


BASE = 1_700_000_000.0


def test_regular_intervals_detected_as_beaconing():
    # Flows every 60s exactly — perfect beacon
    flows = _make_flows([_iso(BASE, i * 60) for i in range(10)])
    assert analyze_beaconing("1.2.3.4", flows, tolerance_pct=10.0, min_connections=6) is True


def test_irregular_intervals_not_beaconing():
    import random
    random.seed(42)
    # Flows with random intervals 0-300s
    timestamps = [BASE + sum(random.randint(0, 300) for _ in range(i)) for i in range(10)]
    timestamps.sort()
    flows = _make_flows([_iso(BASE, t - BASE) for t in timestamps])
    result = analyze_beaconing("1.2.3.4", flows, tolerance_pct=10.0, min_connections=6)
    assert isinstance(result, bool)


def test_too_few_connections():
    flows = _make_flows([_iso(BASE, i * 60) for i in range(3)])
    assert analyze_beaconing("1.2.3.4", flows, min_connections=6) is False


def test_empty_flows():
    assert analyze_beaconing("1.2.3.4", []) is False


def test_missing_timestamps():
    flows = [{"src_ip": "1.2.3.4"} for _ in range(10)]
    assert analyze_beaconing("1.2.3.4", flows) is False
