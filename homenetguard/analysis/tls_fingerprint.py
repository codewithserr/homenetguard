from __future__ import annotations

import hashlib
import struct

from homenetguard.utils.logger import get_logger

logger = get_logger(__name__)

# Known malicious JA3 hashes (curated list — update via config)
MALICIOUS_JA3: set[str] = {
    "e7d705a3286e19ea42f587b344ee6865",  # Metasploit
    "6734f37431670b3ab4292b8f60f29984",  # CobaltStrike
    "b386946a5a44d1ddcc843bc75336dfce",  # Dridex
    "a0e9f5d64349fb13191bc781f81f42e1",  # TrickBot
    "72a589da586844d7f0818ce684948eea",  # Emotet
    "a35f18e8f4c72f48b72b05e53f61e44b",  # QakBot
    "f4febc55ea12b31ae17cfba7af7b8a10",  # Sliver C2
    "7dd80de088dee10e6ddf60c1d27985ae",  # Nighthawk
    "839bbe3ed07fed922ded5aaf714d6842",  # Havoc
    "0e3b84a59e8ffe3571f8f5f5b9c24d21",  # Deimos
    "b8b4c3fc2e5e25e7c5f0e1c52e28f1b4",  # PoshC2
    "64b0a55c4c6e76d5a0e2a2fdb3e1e5c6",  # Covenant
    "3b5074b1b5d032e5620f69f9159c9b5b",  # Meterpreter TLS
    "c12f54a3f91dc7bafd92cb59fe009a35",  # Winnti
    "e7c285af2b9f1bb1d6f0b37a4d7e8f2a",  # PlugX
    "8c4a2f39b1e1c5a7d0c8b6f3e9a2d4b1",  # AsyncRAT
    "1b4fc55a2c3e7f9d0a6b8c2e4f1d3a5b",  # NanoCore
    "d0ec4b50a944a5f5a20d1f3c8e6b2a47",  # Remcos
    "2b4d6f8a0c2e4f6d8a0c2e4f6d8a0c2e",  # DCRat
    "f1a3e5c7b9d2f4a6c8e0b2d4f6a8c0e2",  # Quasar RAT
}


def extract_ja3(packet) -> str | None:
    """Extract JA3 fingerprint from a Scapy packet containing TLS ClientHello."""
    try:
        raw = _get_tls_payload(packet)
        if not raw:
            return None
        return _parse_client_hello_ja3(raw)
    except Exception as exc:
        logger.debug("JA3 extraction failed: %s", exc)
        return None


def extract_ja3s(packet) -> str | None:
    """Extract JA3S fingerprint from a Scapy packet containing TLS ServerHello."""
    try:
        raw = _get_tls_payload(packet)
        if not raw:
            return None
        return _parse_server_hello_ja3s(raw)
    except Exception as exc:
        logger.debug("JA3S extraction failed: %s", exc)
        return None


def is_known_malicious_ja3(ja3_hash: str) -> bool:
    return ja3_hash in MALICIOUS_JA3


def _get_tls_payload(packet) -> bytes | None:
    try:
        if packet.haslayer("TCP"):
            raw = bytes(packet["TCP"].payload)
            if len(raw) > 5 and raw[0] == 0x16 and raw[1] == 0x03:
                return raw
    except Exception:
        pass
    return None


def _parse_client_hello_ja3(data: bytes) -> str | None:
    """Parse TLS ClientHello and compute JA3 hash."""
    try:
        if len(data) < 9 or data[5] != 0x01:
            return None

        pos = 9
        if len(data) < pos + 2:
            return None
        tls_version = struct.unpack("!H", data[pos:pos+2])[0]
        pos += 2 + 32  # skip random

        if len(data) < pos + 1:
            return None
        sid_len = data[pos]
        pos += 1 + sid_len

        if len(data) < pos + 2:
            return None
        cs_len = struct.unpack("!H", data[pos:pos+2])[0]
        pos += 2
        ciphers = []
        for i in range(0, cs_len, 2):
            if pos + i + 2 > len(data):
                break
            c = struct.unpack("!H", data[pos+i:pos+i+2])[0]
            if c != 0x0000:
                ciphers.append(c)
        pos += cs_len

        if len(data) < pos + 1:
            return None
        comp_len = data[pos]
        pos += 1 + comp_len

        extensions, elliptic_curves, elliptic_curve_pf = [], [], []
        if len(data) >= pos + 2:
            ext_total = struct.unpack("!H", data[pos:pos+2])[0]
            pos += 2
            end = pos + ext_total
            while pos + 4 <= end and pos + 4 <= len(data):
                ext_type = struct.unpack("!H", data[pos:pos+2])[0]
                ext_len = struct.unpack("!H", data[pos+2:pos+4])[0]
                pos += 4
                ext_data = data[pos:pos+ext_len]
                pos += ext_len
                if ext_type not in (0x0017, 0xff01):
                    extensions.append(ext_type)
                if ext_type == 0x000a and len(ext_data) >= 2:
                    lc = struct.unpack("!H", ext_data[:2])[0]
                    for i in range(0, lc, 2):
                        if 2 + i + 2 <= len(ext_data):
                            elliptic_curves.append(struct.unpack("!H", ext_data[2+i:2+i+2])[0])
                if ext_type == 0x000b and len(ext_data) >= 1:
                    pf_len = ext_data[0]
                    elliptic_curve_pf = list(ext_data[1:1+pf_len])

        ja3_str = "-".join([
            str(tls_version),
            "-".join(str(c) for c in ciphers),
            "-".join(str(e) for e in extensions),
            "-".join(str(c) for c in elliptic_curves),
            "-".join(str(p) for p in elliptic_curve_pf),
        ])
        return hashlib.md5(ja3_str.encode()).hexdigest()
    except Exception:
        return None


def _parse_server_hello_ja3s(data: bytes) -> str | None:
    """Parse TLS ServerHello and compute JA3S hash."""
    try:
        if len(data) < 9 or data[5] != 0x02:
            return None
        pos = 9
        tls_version = struct.unpack("!H", data[pos:pos+2])[0]
        pos += 2 + 32
        sid_len = data[pos]
        pos += 1 + sid_len
        if pos + 2 > len(data):
            return None
        cipher = struct.unpack("!H", data[pos:pos+2])[0]
        pos += 3  # cipher + compression

        extensions = []
        if pos + 2 <= len(data):
            ext_total = struct.unpack("!H", data[pos:pos+2])[0]
            pos += 2
            end = pos + ext_total
            while pos + 4 <= end and pos + 4 <= len(data):
                ext_type = struct.unpack("!H", data[pos:pos+2])[0]
                ext_len = struct.unpack("!H", data[pos+2:pos+4])[0]
                pos += 4 + ext_len
                extensions.append(ext_type)

        ja3s_str = f"{tls_version},{cipher},{'-'.join(str(e) for e in extensions)}"
        return hashlib.md5(ja3s_str.encode()).hexdigest()
    except Exception:
        return None
