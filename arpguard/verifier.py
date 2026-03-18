from typing import List
from scapy.all import ARP, Ether, srp  # type: ignore

def verify_ip_arp(iface: str, ip: str, count: int = 5, timeout: float = 1.0) -> List[str]:
    seen = set()
    macs: List[str] = []
    for _ in range(max(1, count)):
        request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        ans, _ = srp(request, iface=iface, timeout=timeout, verbose=0, retry=0, inter=0.05, multi=True)
        for _, recv in ans:
            mac = str(recv.hwsrc).lower()
            if mac not in seen:
                seen.add(mac)
                macs.append(mac)
    return macs
