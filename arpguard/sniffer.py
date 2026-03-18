from typing import Callable
import time
import logging

from scapy.all import sniff, ARP  # type: ignore
from scapy.error import Scapy_Exception  # type: ignore


def start_arp_sniffer(iface: str, on_arp_packet: Callable[[str, str, int], None]):
    """
    Continuously sniff ARP packets (passive).

    During Wi‑Fi reconnects, scapy may emit scary runtime warnings like:
      "WARNING: Socket ... failed with '[Errno 100] Network is down'..."
    We suppress scapy runtime warnings and handle reconnect by retrying.
    """

    # Hide scapy runtime warnings (keeps user output clean)
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

    def _handler(pkt):
        if ARP in pkt:
            arp = pkt[ARP]
            sender_ip = str(arp.psrc)
            sender_mac = str(arp.hwsrc).lower()
            opcode = int(arp.op)
            on_arp_packet(sender_ip, sender_mac, opcode)

    while True:
        try:
            sniff(iface=iface, filter="arp", prn=_handler, store=False)
        except (OSError, Scapy_Exception) as e:
            # Interface likely went down during switch; retry.
            print(f"[WARN] ARP sniffer temporarily down on {iface}: {e}. Retrying in 2s...")
            time.sleep(2)
        except Exception as e:
            # Unexpected error: still retry, but show it.
            print(f"[WARN] ARP sniffer error on {iface}: {e}. Retrying in 2s...")
            time.sleep(2)
