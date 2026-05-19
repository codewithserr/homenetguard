from __future__ import annotations

import pickle
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from homenetguard.utils.logger import get_logger

logger = get_logger(__name__)

_FEATURE_COLS = [
    "bytes_per_sec", "packets_per_sec", "unique_src_ips",
    "unique_dst_ips", "unique_ports", "tcp_ratio", "dns_ratio",
]


class AnomalyDetector:
    def __init__(self, model_path: str = "data/anomaly_model.pkl") -> None:
        self._model_path = model_path
        self._model: Any = None
        self._trained_at: datetime | None = None

    def is_trained(self) -> bool:
        return self._model is not None

    def train(self, days: int = 7) -> dict[str, Any]:
        from homenetguard.storage.database import get_connection
        try:
            import numpy as np
            from sklearn.ensemble import IsolationForest
        except ImportError:
            raise RuntimeError("scikit-learn and numpy required for ML training") from None

        since = datetime.now(UTC) - timedelta(days=days)
        with get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM traffic_metrics WHERE window_start >= ? ORDER BY window_start",
                (since.isoformat(),),
            ).fetchall()

        if len(rows) < 20:
            raise ValueError(f"Need at least 20 metric windows, got {len(rows)}. Run capture longer.")

        X = np.array([_row_to_features(dict(r)) for r in rows])
        clf = IsolationForest(contamination=0.05, random_state=42, n_estimators=100)
        clf.fit(X)
        self._model = clf
        self._trained_at = datetime.now(UTC)
        self.save(self._model_path)
        logger.info("Anomaly model trained on %d windows", len(rows))
        return {"windows": len(rows), "trained_at": self._trained_at.isoformat()}

    def score(self, metrics: dict[str, Any]) -> float:
        """Returns anomaly score 0.0 (normal) to 1.0 (anomalous)."""
        if not self._model:
            return 0.0
        try:
            import numpy as np
            features = np.array([_row_to_features(metrics)])
            raw = self._model.decision_function(features)[0]
            # decision_function: negative = anomalous, positive = normal
            # Normalize to 0-1 where 1 = most anomalous
            return float(max(0.0, min(1.0, 0.5 - raw * 0.5)))
        except Exception as exc:
            logger.error("Anomaly scoring failed: %s", exc)
            return 0.0

    def save(self, path: str | None = None) -> None:
        out = Path(path or self._model_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "wb") as f:
            pickle.dump({"model": self._model, "trained_at": self._trained_at}, f)
        logger.info("Anomaly model saved to %s", out)

    def load(self, path: str | None = None) -> None:
        p = Path(path or self._model_path)
        if not p.exists():
            logger.warning("No anomaly model at %s", p)
            return
        with open(p, "rb") as f:
            data = pickle.load(f)
        self._model = data["model"]
        self._trained_at = data.get("trained_at")
        logger.info("Anomaly model loaded from %s", p)

    def status(self) -> dict[str, Any]:
        return {
            "trained": self.is_trained(),
            "trained_at": self._trained_at.isoformat() if self._trained_at else None,
            "model_path": self._model_path,
        }


def _row_to_features(row: dict[str, Any]) -> list[float]:
    window = max(row.get("window_seconds", 60), 1)
    total_flows = max(row.get("tcp_flows", 0) + row.get("udp_flows", 0), 1)
    return [
        row.get("bytes_total", 0) / window,
        row.get("packets_total", 0) / window,
        float(row.get("unique_src_ips", 0)),
        float(row.get("unique_dst_ips", 0)),
        float(row.get("unique_ports", 0)),
        row.get("tcp_flows", 0) / total_flows,
        row.get("dns_queries", 0) / max(row.get("packets_total", 1), 1),
    ]


_detector: AnomalyDetector | None = None


def get_detector() -> AnomalyDetector:
    global _detector
    if _detector is None:
        _detector = AnomalyDetector()
        try:
            _detector.load()
        except Exception:
            pass
    return _detector
