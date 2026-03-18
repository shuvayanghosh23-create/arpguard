import argparse
import threading
import time

from .models import Config, AlertEvent
from .logging_utils import DualLogger
from .netinfo import auto_detect_iface, auto_detect_gateway, get_local_ip, get_local_mac
from .sniffer import start_arp_sniffer
from .detector import Detector


def build_parser():
    parser = argparse.ArgumentParser(prog="arpguard", description="ARP spoofing detection tool (Linux-first CLI)")
    subparsers = parser.add_subparsers(dest="mode")

    parser.add_argument("--iface", type=str, default=None, help="Network interface (auto-detect if omitted)")
    parser.add_argument("--gateway", type=str, default=None, help="Override auto-detected gateway IP")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--quiet", action="store_true", help="Show only WARN/CRITICAL")
    parser.add_argument("--logfile", type=str, default=None, help="Human-readable log file path")
    parser.add_argument("--json-logfile", type=str, default=None, help="JSON log file path")

    pro = subparsers.add_parser("pro", help="Advanced mode")
    pro.add_argument("--iface", type=str, default=None, help="Network interface (auto-detect if omitted)")
    pro.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    pro.add_argument("--quiet", action="store_true", help="Show only WARN/CRITICAL")
    pro.add_argument("--logfile", type=str, default=None, help="Human-readable log file path")
    pro.add_argument("--json-logfile", type=str, default=None, help="JSON log file path")
    pro.add_argument("--gateway", type=str, default=None, help="Override auto-detected gateway IP")
    pro.add_argument("--learn-seconds", type=int, default=60)
    pro.add_argument("--window-seconds", type=int, default=30)
    pro.add_argument("--verify-count", type=int, default=5)
    pro.add_argument("--verify-timeout", type=float, default=1.0)
    pro.add_argument("--verify-new", action="store_true", help="Actively verify every new host (noisy)")
    return parser


def run():
    parser = build_parser()
    args = parser.parse_args()
    pro_mode = args.mode == "pro"

    cfg = Config(
        iface=args.iface,
        gateway_override=getattr(args, "gateway", None),
        verbose=args.verbose,
        quiet=args.quiet,
        logfile=args.logfile,
        json_logfile=args.json_logfile,
        pro_mode=pro_mode,
        learn_seconds=getattr(args, "learn_seconds", 60) if pro_mode else 60,
        window_seconds=getattr(args, "window_seconds", 30) if pro_mode else 30,
        verify_count=getattr(args, "verify_count", 5) if pro_mode else 5,
        verify_timeout=getattr(args, "verify_timeout", 1.0) if pro_mode else 1.0,
        verify_new=getattr(args, "verify_new", False) if pro_mode else False,
    )

    logger = DualLogger(text_path=cfg.logfile, json_path=cfg.json_logfile)

    try:
        iface = cfg.iface or auto_detect_iface()
        gateway = cfg.gateway_override or auto_detect_gateway()
        local_ip = get_local_ip(iface)
        local_mac = get_local_mac(iface)
    except Exception as e:
        print(f"[CRITICAL] Startup failed: {e}")
        return

    print(f"[INFO] Interface: {iface}{' (auto-detected)' if cfg.iface is None else ''}")
    print(f"[INFO] Local: {local_ip}  MAC: {local_mac}")
    print(f"[INFO] Gateway: {gateway}{' (auto-detected)' if cfg.gateway_override is None else ' (override)'}")
    logger.log_event(AlertEvent(level="INFO", category="system", message="ARPGuard starting"))

    detector = Detector(cfg=cfg, iface=iface, gateway_ip=gateway, logger=logger)

    # Start sniffer (daemon so program exits cleanly on Ctrl+C)
    t_sniff = threading.Thread(target=start_arp_sniffer, args=(iface, detector.on_packet), daemon=True)
    t_sniff.start()

    # ---- Baseline helper: retry until baseline is established (or ALERT happens) ----
    baseline_lock = threading.Lock()

    def ensure_baseline_until_ok():
        """
        Try to establish gateway baseline.
        If it fails due to 'no ARP evidence', keep retrying every 5 seconds.
        This does NOT mean spoofing; it just means we haven't learned yet.

        NOTE: The "Monitoring started..." line is printed by Detector after SAFE.
        """
        while True:
            ok = detector.gateway_learning_phase()

            if ok:
                return

            # If detector went to ALERT during learning, do not loop forever.
            if detector.gateway_state == "ALERT":
                return

            # Baseline not established (VERIFYING). Retry.
            time.sleep(5)

    # Initial baseline learning (with retries)
    with baseline_lock:
        ensure_baseline_until_ok()

    def network_watch_loop():
        """
        Periodically detect if the network changed (gateway/local IP/iface) and
        automatically reset + relearn baseline.
        """
        nonlocal iface, gateway, local_ip

        last_iface = iface
        last_gateway = gateway
        last_local_ip = local_ip

        while True:
            time.sleep(2)

            try:
                cur_iface = cfg.iface or auto_detect_iface()
                cur_gateway = cfg.gateway_override or auto_detect_gateway()
                cur_local_ip = get_local_ip(cur_iface)
            except Exception:
                # During Wi-Fi switching these commands can fail briefly.
                continue

            if (cur_iface, cur_gateway, cur_local_ip) != (last_iface, last_gateway, last_local_ip):
                last_iface, last_gateway, last_local_ip = cur_iface, cur_gateway, cur_local_ip

                iface = cur_iface
                gateway = cur_gateway
                local_ip = cur_local_ip

                detector._emit(
                    AlertEvent(
                        level="WARN",
                        category="system",
                        message="Network change detected (iface/gateway/IP). Resetting and relearning gateway baseline...",
                        target_ip=cur_gateway,
                    )
                )

                detector.reset_for_network(cur_iface, cur_gateway)

                # Relearn baseline for the new network (with retries)
                with baseline_lock:
                    ensure_baseline_until_ok()

    t_watch = threading.Thread(target=network_watch_loop, daemon=True)
    t_watch.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[INFO] Stopping ARPGuard. In-memory tables will be cleared.")
        logger.log_text("[INFO] Stopped by user")
