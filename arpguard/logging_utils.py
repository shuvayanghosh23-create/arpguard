import json
import threading
from datetime import datetime
from typing import Optional
from .models import AlertEvent

class DualLogger:
    def __init__(self, text_path: Optional[str] = None, json_path: Optional[str] = None):
        self.text_path = text_path
        self.json_path = json_path
        self._lock = threading.Lock()

    def _ts(self):
        return datetime.utcnow().isoformat() + "Z"

    def log_text(self, line: str):
        if not self.text_path:
            return
        with self._lock:
            with open(self.text_path, "a", encoding="utf-8") as f:
                f.write(f"{self._ts()} {line}\n")

    def log_event(self, event: AlertEvent):
        if not self.text_path and not self.json_path:
            return
        macs = ", ".join(event.observed_macs or [])
        line = f"[{event.level}] {event.category} {event.message}"
        if event.target_ip:
            line += f" ip={event.target_ip}"
        if event.baseline_mac:
            line += f" baseline={event.baseline_mac}"
        if event.current_mac:
            line += f" current={event.current_mac}"
        if macs:
            line += f" observed=[{macs}]"
        ts = self._ts()
        with self._lock:
            if self.text_path:
                with open(self.text_path, "a", encoding="utf-8") as f:
                    f.write(f"{ts} {line}\n")
            if self.json_path:
                with open(self.json_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(event.to_dict(), ensure_ascii=False) + "\n")
