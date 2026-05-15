from __future__ import annotations

import grp
import os
import platform
import sys

from homenetguard.utils.logger import get_logger

logger = get_logger(__name__)


def check_capture_permissions() -> bool:
    if os.geteuid() == 0:
        return True

    system = platform.system()
    if system == "Linux":
        return _check_linux_cap_net_raw()
    elif system == "Darwin":
        return _check_macos_bpf()
    else:
        logger.warning("Unknown OS %s — cannot verify capture permissions", system)
        return False


def require_capture_permissions() -> None:
    if not check_capture_permissions():
        system = platform.system()
        if system == "Linux":
            msg = (
                "\nInsufficient permissions for packet capture.\n"
                "Options:\n"
                "  1. Run with sudo: sudo homenetguard start\n"
                "  2. Grant capabilities: sudo setcap cap_net_raw+eip $(which python3)\n"
            )
        elif system == "Darwin":
            msg = (
                "\nInsufficient permissions for packet capture.\n"
                "Options:\n"
                "  1. Run with sudo: sudo homenetguard start\n"
                "  2. Add to access_bpf group: sudo dseditgroup -o edit -a $USER -t user access_bpf\n"
            )
        else:
            msg = "\nInsufficient permissions. Try running with sudo."

        print(msg, file=sys.stderr)
        sys.exit(1)


def _check_linux_cap_net_raw() -> bool:
    try:
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("CapEff:"):
                    cap_eff = int(line.split(":")[1].strip(), 16)
                    cap_net_raw = 1 << 13
                    return bool(cap_eff & cap_net_raw)
    except OSError:
        pass
    return False


def _check_macos_bpf() -> bool:
    try:
        groups = [grp.getgrgid(g).gr_name for g in os.getgroups()]
        return "access_bpf" in groups
    except Exception:
        return False
