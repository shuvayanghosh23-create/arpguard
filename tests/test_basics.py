"""
Lightweight unit tests for AlertEvent timestamp correctness and Detector debounce.

Run with:  python -m pytest tests/
"""
import time
import threading
import unittest
from collections import defaultdict
from unittest.mock import MagicMock, patch

from arpguard.models import AlertEvent, Config
from arpguard.detector import Detector, _VERIFY_DEBOUNCE_SECONDS


# ---------------------------------------------------------------------------
# AlertEvent.ts – must be per-instance, not frozen at class definition time
# ---------------------------------------------------------------------------
class TestAlertEventTimestamp(unittest.TestCase):
    def test_ts_is_float(self):
        ev = AlertEvent(level="INFO", category="test", message="hello")
        self.assertIsInstance(ev.ts, float)

    def test_ts_is_approximately_now(self):
        before = time.time()
        ev = AlertEvent(level="INFO", category="test", message="hello")
        after = time.time()
        self.assertGreaterEqual(ev.ts, before)
        self.assertLessEqual(ev.ts, after)

    def test_two_instances_have_different_ts(self):
        ev1 = AlertEvent(level="INFO", category="test", message="first")
        time.sleep(0.01)
        ev2 = AlertEvent(level="INFO", category="test", message="second")
        self.assertLess(ev1.ts, ev2.ts,
                        "Each AlertEvent must capture the current time, not a shared frozen value")


# ---------------------------------------------------------------------------
# Detector debounce – verify_ip_arp must not fire more than once per 10 s
# ---------------------------------------------------------------------------
def _make_detector(learn_seconds: int = 0) -> Detector:
    cfg = Config(
        iface=None,
        gateway_override=None,
        verbose=False,
        quiet=True,
        logfile=None,
        json_logfile=None,
        pro_mode=False,
        learn_seconds=learn_seconds,
        window_seconds=30,
        verify_count=1,
        verify_timeout=0.1,
        verify_new=False,
    )
    logger = MagicMock()
    return Detector(cfg=cfg, iface="eth0", gateway_ip="10.0.0.1", logger=logger)


class TestDetectorDebounce(unittest.TestCase):
    def test_should_verify_allows_first_call(self):
        det = _make_detector()
        with det._lock:
            self.assertTrue(det._should_verify("192.168.1.2"))

    def test_should_verify_blocks_while_in_progress(self):
        det = _make_detector()
        with det._lock:
            det._verify_in_progress.add("192.168.1.2")
            self.assertFalse(det._should_verify("192.168.1.2"))

    def test_should_verify_blocks_within_debounce_window(self):
        det = _make_detector()
        with det._lock:
            det._verify_last["192.168.1.2"] = time.time()
            self.assertFalse(det._should_verify("192.168.1.2"))

    def test_should_verify_allows_after_debounce_window(self):
        det = _make_detector()
        with det._lock:
            # Pretend last verify was done well before the debounce window.
            det._verify_last["192.168.1.2"] = time.time() - (_VERIFY_DEBOUNCE_SECONDS + 1)
            self.assertTrue(det._should_verify("192.168.1.2"))

    def test_verify_ip_arp_called_at_most_once_during_storm(self):
        """Rapid suspicious packets for the same IP must trigger verify_ip_arp only once."""
        det = _make_detector()

        # Patch verify_ip_arp to avoid real network calls; return a stable single MAC.
        with patch("arpguard.detector.verify_ip_arp", return_value=["aa:bb:cc:dd:ee:ff"]) as mock_verify:
            # Seed ip_to_mac so the first packet looks like a MAC change.
            with det._lock:
                det.ip_to_mac["10.0.0.2"] = "11:22:33:44:55:66"

            threads = [
                threading.Thread(target=det._handle_suspicious, args=("10.0.0.2", "11:22:33:44:55:66", "aa:bb:cc:dd:ee:ff"))
                for _ in range(5)
            ]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            # Debounce: only one verification should have run, not five.
            self.assertEqual(mock_verify.call_count, 1,
                             "verify_ip_arp must be debounced; expected 1 call, got "
                             f"{mock_verify.call_count}")

    def test_reset_for_network_clears_debounce_state(self):
        det = _make_detector()
        with det._lock:
            det._verify_last["10.0.0.2"] = time.time()
            det._verify_in_progress.add("10.0.0.2")

        det.reset_for_network("wlan0", "192.168.0.1")

        with det._lock:
            self.assertEqual(det._verify_last, {})
            self.assertEqual(det._verify_in_progress, set())


if __name__ == "__main__":
    unittest.main()
