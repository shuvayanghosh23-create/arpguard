import subprocess
import re
from scapy.all import get_if_hwaddr  # type: ignore

def _run(cmd: str) -> str:
    return subprocess.check_output(cmd, shell=True, text=True).strip()

def auto_detect_iface() -> str:
    out = _run("ip route show default")
    m = re.search(r"\bdev\s+(\S+)", out)
    if not m:
        raise RuntimeError("Could not auto-detect interface from default route.")
    return m.group(1)

def auto_detect_gateway() -> str:
    out = _run("ip route show default")
    m = re.search(r"\bvia\s+(\S+)", out)
    if not m:
        raise RuntimeError("Could not auto-detect gateway from default route.")
    return m.group(1)

def get_local_ip(iface: str) -> str:
    out = _run(f"ip -4 addr show dev {iface}")
    m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", out)
    if not m:
        raise RuntimeError(f"Could not find IPv4 on interface {iface}.")
    return m.group(1)

def get_local_mac(iface: str) -> str:
    return get_if_hwaddr(iface)
