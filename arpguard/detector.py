import threading
import time
from collections import defaultdict
from typing import Dict, Set, Optional

from .models import Config, AlertEvent
from .verifier import verify_ip_arp
from .output import print_event, learning_countdown
from .logging_utils import DualLogger

# Minimum seconds between verify_ip_arp calls for the same target IP.
_VERIFY_DEBOUNCE_SECONDS = 10.0


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
        # Debounce tracking: ip -> timestamp of last verify start
        self._verify_last: Dict[str, float] = {}
        # Set of IPs currently being actively verified (network I/O in flight)
        self._verify_in_progress: Set[str] = set()

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
            self._verify_last.clear()
            self._verify_in_progress.clear()

    def _emit(self, event: AlertEvent):
        print_event(event, quiet=self.cfg.quiet)
        self.logger.log_event(event)

    def _purge_old_claims(self):
        """Must be called with self._lock held."""
        now = time.time()
        for ip in list(self.recent_claims.keys()):
            for mac in list(self.recent_claims[ip].keys()):
                if now - self.recent_claims[ip][mac] > self.cfg.window_seconds:
                    del self.recent_claims[ip][mac]
            if not self.recent_claims[ip]:
                del self.recent_claims[ip]

    def _mark_claim(self, ip: str, mac: str):
        """Must be called with self._lock held."""
        self.recent_claims[ip][mac] = time.time()

    def _get_claiming_macs(self, ip: str) -> Set[str]:
        """Must be called with self._lock held."""
        self._purge_old_claims()
        return set(self.recent_claims.get(ip, {}).keys())

    def _should_verify(self, ip: str) -> bool:
        """
        Return True if a fresh verify_ip_arp call is allowed for this IP.
        Must be called with self._lock held.
        """
        if ip in self._verify_in_progress:
            return False
        if time.time() - self._verify_last.get(ip, 0) < _VERIFY_DEBOUNCE_SECONDS:
            return False
        return True

    def on_packet(self, ip: str, mac: str, opcode: int):
        # Perform all shared-state access under the lock, but do NOT hold the
        # lock across the network I/O in _handle_suspicious.
        with self._lock:
            self._mark_claim(ip, mac)
            if self.cfg.verbose:
                op = "who-has" if opcode == 1 else "is-at" if opcode == 2 else f"op:{opcode}"
                print(f"[ARP] {ip} {op} {mac}")

            known = self.ip_to_mac.get(ip)
            suspicious = False
            # Use `is not None` so that an empty-string MAC ("") stored in
            # ip_to_mac is still treated as a known mapping, not ignored.
            if known is not None and known != mac:
                suspicious = True
            if len(self._get_claiming_macs(ip)) >= 2:
                suspicious = True
            if self.cfg.verify_new and known is None:
                suspicious = True

            if known is None:
                self.ip_to_mac[ip] = mac

        # Lock is released here – safe to do network I/O now.
        if suspicious:
            self._handle_suspicious(ip, known, mac)

    def _handle_suspicious(self, ip: str, old_mac: Optional[str], new_mac: str):
        # Capture all state needed for the WARN emit and the I/O call under
        # the lock, then release before doing any network operations.
        with self._lock:
            category = "gateway" if ip == self.gateway_ip else "host"
            baseline_mac = self.gateway_baseline_mac if ip == self.gateway_ip else old_mac
            observed = list(self._get_claiming_macs(ip))
            current_iface = self.iface
            should_verify = self._should_verify(ip)
            if should_verify:
                self._verify_last[ip] = time.time()
                self._verify_in_progress.add(ip)

        # Emit the initial warning (no lock needed – logger/print have own sync).
        self._emit(
            AlertEvent(
                level="WARN",
                category=category,
                message=f"ARP conflict/change detected for {category}. Verifying...",
                target_ip=ip,
                baseline_mac=baseline_mac,
                current_mac=new_mac,
                observed_macs=observed,
            )
        )

        if not should_verify:
            # Debounced: skip active verification for this IP right now.
            return

        # Network I/O – lock NOT held.
        try:
            reply_macs = verify_ip_arp(current_iface, ip, self.cfg.verify_count, self.cfg.verify_timeout)
        finally:
            with self._lock:
                self._verify_in_progress.discard(ip)

        # Re-read gateway context under lock for result processing.
        with self._lock:
            category = "gateway" if ip == self.gateway_ip else "host"
            gw_baseline = self.gateway_baseline_mac
            baseline_mac = gw_baseline if ip == self.gateway_ip else old_mac

        if len(reply_macs) >= 2:
            self._emit(
                AlertEvent(
                    level="CRITICAL",
                    category=category,
                    message=f"ARP SPOOFING LIKELY: multiple MACs claimed same IP ({category})",
                    target_ip=ip,
                    baseline_mac=baseline_mac,
                    current_mac=new_mac,
                    observed_macs=reply_macs,
                )
            )
            with self._lock:
                if ip == self.gateway_ip:
                    self.gateway_state = "ALERT"
            return

        if len(reply_macs) == 1:
            verified_mac = reply_macs[0]
            if ip == self.gateway_ip and gw_baseline and verified_mac != gw_baseline:
                self._emit(
                    AlertEvent(
                        level="CRITICAL",
                        category="gateway",
                        message="Gateway MAC differs from trusted baseline after verification",
                        target_ip=ip,
                        baseline_mac=gw_baseline,
                        current_mac=verified_mac,
                        observed_macs=reply_macs,
                    )
                )
                with self._lock:
                    self.gateway_state = "ALERT"
            else:
                with self._lock:
                    self.ip_to_mac[ip] = verified_mac
                self._emit(
                    AlertEvent(
                        level="INFO",
                        category=category,
                        message=f"{category.capitalize()} mapping changed but verified stable",
                        target_ip=ip,
                        baseline_mac=baseline_mac,
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
                baseline_mac=baseline_mac,
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

        # Capture shared state under lock, then do network I/O outside lock.
        with self._lock:
            claim_macs = self._get_claiming_macs(self.gateway_ip)
            gateway_ip = self.gateway_ip
            current_iface = self.iface

        active_macs = verify_ip_arp(current_iface, gateway_ip, self.cfg.verify_count, self.cfg.verify_timeout)
        all_macs = set(claim_macs) | set(active_macs)

        if len(all_macs) >= 2:
            with self._lock:
                self.gateway_state = "ALERT"
                self.gateway_baseline_mac = (
                    active_macs[0]
                    if active_macs
                    else (sorted(claim_macs)[0] if claim_macs else None)
                )
            self._emit(
                AlertEvent(
                    level="CRITICAL",
                    category="gateway",
                    message="Gateway unstable during learning: multiple MACs claimed gateway IP",
                    target_ip=gateway_ip,
                    observed_macs=sorted(all_macs),
                )
            )
            return False

        if len(all_macs) == 1:
            trusted = list(all_macs)[0]
            with self._lock:
                self.gateway_baseline_mac = trusted
                self.ip_to_mac[gateway_ip] = trusted
                self.gateway_state = "TRUSTED"
            self._emit(
                AlertEvent(
                    level="SAFE",
                    category="gateway",
                    message="Network stable. Gateway baseline trusted.",
                    target_ip=gateway_ip,
                    baseline_mac=trusted,
                    observed_macs=[trusted],
                )
            )

            # Show this after EVERY SAFE baseline (initial + reconnect + network switch)
            if not self.cfg.quiet:
                print("[INFO] Monitoring started. Press Ctrl+C to stop.")

            return True

        with self._lock:
            self.gateway_state = "VERIFYING"
        self._emit(
            AlertEvent(
                level="WARN",
                category="gateway",
                message="Could not establish gateway baseline (no ARP evidence). Continuing monitoring.",
                target_ip=gateway_ip,
            )
        )
        return False
