import pytest

from homenetguard.analysis.anomaly_detector import AnomalyDetector, _row_to_features
from homenetguard.storage import database


@pytest.fixture(autouse=True)
def in_memory_db(tmp_path):
    database.init_db(str(tmp_path / "test.db"))


def _insert_metrics(n: int = 30, anomalous: bool = False) -> None:
    from datetime import UTC, datetime, timedelta

    from homenetguard.storage.database import get_connection
    base = datetime.now(UTC)
    with get_connection() as conn:
        for i in range(n):
            ts = (base - timedelta(minutes=i)).isoformat()
            bytes_total = 10_000_000 if anomalous else 50_000
            conn.execute(
                "INSERT INTO traffic_metrics (window_start, window_seconds, bytes_total, packets_total, "
                "unique_src_ips, unique_dst_ips, unique_ports, tcp_flows, udp_flows, dns_queries) "
                "VALUES (?,60,?,100,5,10,20,80,20,15)",
                (ts, bytes_total),
            )


def test_is_trained_false_initially():
    detector = AnomalyDetector()
    assert detector.is_trained() is False


def test_train_requires_enough_data():
    detector = AnomalyDetector()
    with pytest.raises(ValueError, match="at least 20"):
        detector.train(days=7)


def test_train_and_score(tmp_path):
    _insert_metrics(n=30, anomalous=False)
    detector = AnomalyDetector(model_path=str(tmp_path / "model.pkl"))
    detector.train(days=7)
    assert detector.is_trained()

    normal_metrics = {"bytes_total": 50_000, "packets_total": 100, "unique_src_ips": 5,
                      "unique_dst_ips": 10, "unique_ports": 20, "tcp_flows": 80,
                      "udp_flows": 20, "dns_queries": 15, "window_seconds": 60}
    normal_score = detector.score(normal_metrics)

    anomalous_metrics = {**normal_metrics, "bytes_total": 100_000_000, "unique_src_ips": 500}
    anomalous_score = detector.score(anomalous_metrics)

    assert 0.0 <= normal_score <= 1.0
    assert 0.0 <= anomalous_score <= 1.0
    assert anomalous_score >= normal_score


def test_score_zero_when_untrained():
    detector = AnomalyDetector()
    score = detector.score({"bytes_total": 1000, "window_seconds": 60})
    assert score == 0.0


def test_save_and_load(tmp_path):
    _insert_metrics(n=30)
    model_path = str(tmp_path / "model.pkl")
    d1 = AnomalyDetector(model_path=model_path)
    d1.train(days=7)
    d2 = AnomalyDetector(model_path=model_path)
    d2.load()
    assert d2.is_trained()


def test_row_to_features():
    row = {"bytes_total": 60_000, "packets_total": 600, "unique_src_ips": 10,
           "unique_dst_ips": 20, "unique_ports": 30, "tcp_flows": 400, "udp_flows": 100,
           "dns_queries": 50, "window_seconds": 60}
    features = _row_to_features(row)
    assert len(features) == 7
    assert all(isinstance(f, float) for f in features)
