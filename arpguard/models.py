from dataclasses import dataclass, field, asdict
from typing import List, Optional
import time

@dataclass
class Config:
    iface: Optional[str]
    gateway_override: Optional[str]
    verbose: bool
    quiet: bool
    logfile: Optional[str]
    json_logfile: Optional[str]
    pro_mode: bool
    learn_seconds: int = 60
    window_seconds: int = 30
    verify_count: int = 5
    verify_timeout: float = 1.0
    verify_new: bool = False

@dataclass
class AlertEvent:
    level: str
    category: str
    message: str
    target_ip: Optional[str] = None
    baseline_mac: Optional[str] = None
    observed_macs: Optional[List[str]] = None
    current_mac: Optional[str] = None
    ts: float = field(default_factory=time.time)
    def to_dict(self):
        return asdict(self)
