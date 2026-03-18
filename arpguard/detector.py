import threading
import time
from collections import defaultdict
from typing import Dict, Set, Optional

from .models import Config, AlertEvent
from .verifier import verify_ip_arp
from .output import print_event, learning_countdown
from .logging_utils import DualLogger


class Detector:
    def __init__(self, cfg: Config, iface: str, gateway_ip: str, logger: DualLogger):
        self.cfg = cfg
        self.iface = iface
        self.gateway_ip = gateway_ip
        self.logger = logger
        self.ip_to_mac: Dict[str, str] = {}
        self.recent_claims: Dict[str, Dict[str, float]] = defaultdict(dict)
        self.gateway_baseline_mac: Optional[str] = None
        self.gateway_state = "LEARNING"
        self._lock = threading.Lock()

    def reset_for_network(self, iface: str, gateway_ip: str):
        """
        Called when the host switches networks (e.g., Wi-Fi changes).
        Clears learned state and prepares to relearn the gateway baseline.
        """
        with self._lock:
            self.iface = iface
            self.gateway_ip = gateway_ip
            self.ip_to_mac.clear()
            self.recent_claims.clear()
            self.gateway_baseline_mac = None
            self.gateway_state = "LEARNING"

    def _emit(self, event: AlertEvent):
        print_event(event, quiet=self.cfg.quiet)
        self.logger.log_event(event)

    def _purge_old_claims(self):
        now = time.time()
        for ip in list(self.recent_claims.keys()):
            for mac in list(self.recent_claims[ip].keys()):
                if now - self.recent_claims[ip][mac] > self.cfg.window_seconds:
                    del self.recent_claims[ip][mac]
            if not self.recent_claims[ip]:
                del self.recent_claims[ip]

    def _mark_claim(self, ip: str, mac: str):
        self.recent_claims[ip][mac] = time.time()

    def _get_claiming_macs(self, ip: str) -> Set[str]:
        self._purge_old_claims()
        return set(self.recent_claims.get(ip, {}).keys())

    def on_packet(self, ip: str, mac: str, opcode: int):
        with self._lock:
            self._mark_claim(ip, mac)
            if self.cfg.verbose:
                op = "who-has" if opcode == 1 else "is-at" if opcode == 2 else f"op:{opcode}"
                print(f"[ARP] {ip} {op} {mac}")

            known = self.ip_to_mac.get(ip)
            suspicious = False
            if known and known != mac:
                suspicious = True
            if len(self._get_claiming_macs(ip)) >= 2:
                suspicious = True
            if self.cfg.verify_new and known is None:
                suspicious = True

            if known is None:
                self.ip_to_mac[ip] = mac

            if suspicious:
                self._handle_suspicious(ip, known, mac)

    def _handle_suspicious(self, ip: str, old_mac: Optional[str], new_mac: str):
        category = "gateway" if ip == self.gateway_ip else "host"
        self._emit(
            AlertEvent(
                level="WARN",
                category=category,
                message=f"ARP conflict/change detected for {category}. Verifying...",
                target_ip=ip,
                baseline_mac=self.gateway_baseline_mac if ip == self.gateway_ip else old_mac,
                current_mac=new_mac,
                observed_macs=list(self._get_claiming_macs(ip)),
            )
        )

        reply_macs = verify_ip_arp(self.iface, ip, self.cfg.verify_count, self.cfg.verify_timeout)

        if len(reply_macs) >= 2:
            self._emit(
                AlertEvent(
                    level="CRITICAL",
                    category=category,
                    message=f"ARP SPOOFING LIKELY: multiple MACs claimed same IP ({category})",
                    target_ip=ip,
                    baseline_mac=self.gateway_baseline_mac if ip == self.gateway_ip else old_mac,
                    current_mac=new_mac,
                    observed_macs=reply_macs,
                )
            )
            if ip == self.gateway_ip:
                self.gateway_state = "ALERT"
            return

        if len(reply_macs) == 1:
            verified_mac = reply_macs[0]
            if ip == self.gateway_ip and self.gateway_baseline_mac and verified_mac != self.gateway_baseline_mac:
                self._emit(
                    AlertEvent(
                        level="CRITICAL",
                        category="gateway",
                        message="Gateway MAC differs from trusted baseline after verification",
                        target_ip=ip,
                        baseline_mac=self.gateway_baseline_mac,
                        current_mac=verified_mac,
                        observed_macs=reply_macs,
                    )
                )
                self.gateway_state = "ALERT"
            else:
                self.ip_to_mac[ip] = verified_mac
                self._emit(
                    AlertEvent(
                        level="INFO",
                        category=category,
                        message=f"{category.capitalize()} mapping changed but verified stable",
                        target_ip=ip,
                        baseline_mac=self.gateway_baseline_mac if ip == self.gateway_ip else old_mac,
                        current_mac=verified_mac,
                        observed_macs=reply_macs,
                    )
                )
            return

        self._emit(
            AlertEvent(
                level="WARN",
                category=category,
                message=f"No ARP replies received during verification for {ip}",
                target_ip=ip,
                baseline_mac=self.gateway_baseline_mac if ip == self.gateway_ip else old_mac,
                current_mac=new_mac,
                observed_macs=[],
            )
        )

    def gateway_learning_phase(self) -> bool:
        """
        Returns:
          True  -> baseline established (SAFE/TRUSTED)
          False -> baseline not established (VERIFYING) or ALERT triggered
        """
        learning_countdown(self.cfg.learn_seconds, quiet=self.cfg.quiet)
        claim_macs = self._get_claiming_macs(self.gateway_ip)
        active_macs = verify_ip_arp(self.iface, self.gateway_ip, self.cfg.verify_count, self.cfg.verify_timeout)
        all_macs = set(claim_macs) | set(active_macs)

        if len(all_macs) >= 2:
            self._emit(
                AlertEvent(
                    level="CRITICAL",
                    category="gateway",
                    message="Gateway unstable during learning: multiple MACs claimed gateway IP",
                    target_ip=self.gateway_ip,
                    observed_macs=sorted(all_macs),
                )
            )
            self.gateway_state = "ALERT"
            self.gateway_baseline_mac = (
                active_macs[0]
                if active_macs
                else (sorted(claim_macs)[0] if claim_macs else None)
            )
            return False

        if len(all_macs) == 1:
            trusted = list(all_macs)[0]
            self.gateway_baseline_mac = trusted
            self.ip_to_mac[self.gateway_ip] = trusted
            self.gateway_state = "TRUSTED"
            self._emit(
                AlertEvent(
                    level="SAFE",
                    category="gateway",
                    message="Network stable. Gateway baseline trusted.",
                    target_ip=self.gateway_ip,
                    baseline_mac=trusted,
                    observed_macs=[trusted],
                )
            )

            # Show this after EVERY SAFE baseline (initial + reconnect + network switch)
            if not self.cfg.quiet:
                print("[INFO] Monitoring started. Press Ctrl+C to stop.")

            return True

        self._emit(
            AlertEvent(
                level="WARN",
                category="gateway",
                message="Could not establish gateway baseline (no ARP evidence). Continuing monitoring.",
                target_ip=self.gateway_ip,
            )
        )
        self.gateway_state = "VERIFYING"
        return False
