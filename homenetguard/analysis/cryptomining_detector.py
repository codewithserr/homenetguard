from __future__ import annotations

STRATUM_PORTS: frozenset[int] = frozenset({
    3333, 4444, 8333, 14433, 45700, 9999, 7777,
    14444, 9980, 3032, 3256, 5555, 6666, 8008,
})

MINING_POOL_DOMAINS: frozenset[str] = frozenset({
    "pool.supportxmr.com", "xmrpool.eu", "minexmr.com",
    "nanopool.org", "ethermine.org", "f2pool.com",
    "pool.hashvault.pro", "moneroocean.stream",
    "xmrig.com", "miningpoolhub.com", "2miners.com",
    "nicehash.com", "antpool.com", "btc.com",
    "slushpool.com", "poolin.com", "viabtc.com",
    "foundryusapool.com", "luxor.tech", "marathon.io",
    "pool.minexmr.com", "xmr.pool.minergate.com",
    "us-east.stratum.slushpool.com", "cn.ss.btc.com",
    "unmineable.com", "k1pool.com", "zergpool.com",
    "prohashing.com", "zpool.ca", "coinfoundry.org",
})


def is_cryptomining_traffic(
    dst_port: int,
    dst_ip: str = "",
    dst_domain: str | None = None,
) -> bool:
    """Detect crypto mining traffic by Stratum port or known pool domain."""
    if dst_port in STRATUM_PORTS:
        return True
    if dst_domain:
        domain_lower = dst_domain.lower().rstrip(".")
        if domain_lower in MINING_POOL_DOMAINS:
            return True
        for pool in MINING_POOL_DOMAINS:
            if domain_lower.endswith("." + pool) or domain_lower == pool:
                return True
    return False


def get_stratum_ports() -> frozenset[int]:
    return STRATUM_PORTS


def get_mining_pool_domains() -> frozenset[str]:
    return MINING_POOL_DOMAINS
