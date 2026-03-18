from typing import Callable, Union
import time
import logging

from scapy.all import sniff, ARP  # type: ignore
from scapy.error import Scapy_Exception  # type: ignore


def start_arp_sniffer(
    iface_provider: Union[str, Callable[[], str]],
    on_arp_packet: Callable[[str, str, int], None],
):
    """
    Continuously sniff ARP packets (passive).

    ``iface_provider`` may be either a plain interface name string *or* a
    zero-argument callable that returns the current interface name.  The
    callable form lets callers (e.g. the CLI network-watch loop) update the
    interface without restarting this thread – the new interface is picked up
    automatically on every retry after a sniff session ends.

    During Wi‑Fi reconnects, scapy may emit scary runtime warnings like:
      "WARNING: Socket ... failed with '[Errno 100] Network is down'..."
    We suppress scapy runtime warnings and handle reconnect by retrying.
    """

    # Hide scapy runtime warnings (keeps user output clean)
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

    def _get_iface() -> str:
        return iface_provider() if callable(iface_provider) else iface_provider

    def _handler(pkt):
        if ARP in pkt:
            arp = pkt[ARP]
            sender_ip = str(arp.psrc)
            sender_mac = str(arp.hwsrc).lower()
            opcode = int(arp.op)
            on_arp_packet(sender_ip, sender_mac, opcode)

    while True:
        current_iface = _get_iface()
        try:
            sniff(iface=current_iface, filter="arp", prn=_handler, store=False)
        except (OSError, Scapy_Exception) as e:
            # Interface likely went down during switch; retry.
            print(f"[WARN] ARP sniffer temporarily down on {current_iface}: {e}. Retrying in 2s...")
            time.sleep(2)
        except Exception as e:
            # Unexpected error: still retry, but show it.
            print(f"[WARN] ARP sniffer error on {current_iface}: {e}. Retrying in 2s...")
            time.sleep(2)
