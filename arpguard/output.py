import time
from .models import AlertEvent

def print_event(event: AlertEvent, quiet: bool = False):
    if quiet and event.level not in ("WARN", "CRITICAL"):
        return
    lvl = event.level.upper()
    print(f"[{lvl}] {event.message}")
    if event.target_ip:
        print(f"       Target IP: {event.target_ip}")
    if event.baseline_mac:
        print(f"       Baseline MAC: {event.baseline_mac}")
    if event.current_mac:
        print(f"       Current MAC: {event.current_mac}")
    if event.observed_macs:
        print("       Claiming/Observed MACs:")
        for m in event.observed_macs:
            print(f"         - {m}")

def learning_countdown(seconds: int, quiet: bool = False):
    if quiet:
        return
    print("[INFO] Network status: UNSTABLE (learning gateway baseline)")
    for remaining in range(seconds, 0, -1):
        if remaining % 5 == 0 or remaining <= 5:
            print(f"[INFO] Learning time remaining: {remaining}s")
        time.sleep(1)
