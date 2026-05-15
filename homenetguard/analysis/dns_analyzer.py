from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from homenetguard.storage import repository
from homenetguard.utils.logger import get_logger

if TYPE_CHECKING:
    from homenetguard.analysis.threat_detector import ThreatDetector

logger = get_logger(__name__)


class DNSAnalyzer:
    def __init__(self, threat_detector: ThreatDetector | None = None) -> None:
        self._detector = threat_detector

    def process_dns_packet(
        self,
        src_ip: str,
        domain: str,
        query_type: str,
        response_ip: str | None = None,
    ) -> None:
        timestamp = datetime.now(UTC).isoformat()
        is_suspicious = False

        if self._detector:
            is_suspicious = self._detector.check_dns_anomaly(src_ip, domain, query_type)

        repository.insert_dns_query(
            timestamp=timestamp,
            src_ip=src_ip,
            queried_domain=domain,
            query_type=query_type,
            response_ip=response_ip,
            is_suspicious=is_suspicious,
        )

        if is_suspicious:
            repository.insert_alert(
                alert_type="dns_anomaly",
                severity="medium",
                src_ip=src_ip,
                description=f"Suspicious DNS query: {domain} (type={query_type})",
                raw_data={"domain": domain, "query_type": query_type},
                timestamp=timestamp,
            )

    def get_top_domains(self, limit: int = 20) -> list[dict[str, Any]]:
        queries = repository.get_recent_dns_queries(limit=500)
        counts: dict[str, int] = {}
        for q in queries:
            d = q["queried_domain"]
            counts[d] = counts.get(d, 0) + 1
        return [
            {"domain": d, "count": c}
            for d, c in sorted(counts.items(), key=lambda x: -x[1])[:limit]
        ]

    def get_suspicious_domains(self) -> list[dict[str, Any]]:
        queries = repository.get_recent_dns_queries(limit=1000)
        return [q for q in queries if q.get("is_suspicious")]
