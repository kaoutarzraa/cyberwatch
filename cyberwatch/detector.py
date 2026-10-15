"""Detection engine: parses SSH auth log lines and raises alerts."""
import re
import time
from collections import defaultdict, deque
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Optional

IP = r"(?P<ip>[0-9a-fA-F:.]+)"
FAILED = re.compile(rf"Failed password for (?:invalid user )?(?P<user>\S+) from {IP}")
ACCEPTED = re.compile(rf"Accepted (?:password|publickey) for (?P<user>\S+) from {IP}")

MITRE = {
    "BRUTE_FORCE": "T1110.001 - Brute Force: Password Guessing",
    "LOGIN_AFTER_FAILURES": "T1078 - Valid Accounts",
}


@dataclass
class Alert:
    ts: float
    type: str
    severity: str
    source_ip: str
    message: str
    mitre: str = ""

    def to_dict(self):
        return asdict(self)


@dataclass
class AuthEvent:
    ts: float
    kind: str  # "failed" | "accepted"
    user: str
    ip: str


def parse_auth_line(line: str, year: Optional[int] = None) -> Optional[AuthEvent]:
    """Turns one SSH auth-log line (syslog or ISO timestamp) into an AuthEvent."""
    line = line.strip()
    if not line:
        return None
    try:
        if line[:4].isdigit() and "T" in line[:20]:
            ts = datetime.fromisoformat(line.split()[0]).timestamp()
        else:
            y = year or datetime.now().year
            ts = datetime.strptime(f"{y} {line[:15]}", "%Y %b %d %H:%M:%S").timestamp()
    except ValueError:
        return None
    for kind, rx in (("failed", FAILED), ("accepted", ACCEPTED)):
        m = rx.search(line)
        if m:
            return AuthEvent(ts, kind, m.group("user"), m.group("ip"))
    return None


class AuthAnalyzer:
    """Sliding-window brute-force detector, with alert cooldown."""

    def __init__(self, threshold: int = 5, window: int = 60, cooldown: int = 300):
        self.threshold, self.window, self.cooldown = threshold, window, cooldown
        self.failures = defaultdict(deque)   # ip -> deque[ts]
        self.last_alert = {}                 # (type, ip) -> ts
        self.stats = defaultdict(int)        # ip -> total failed attempts

    def _purge(self, ip: str, now: float):
        dq = self.failures[ip]
        while dq and now - dq[0] > self.window:
            dq.popleft()

    def _emit(self, atype, severity, ip, ts, msg):
        key = (atype, ip)
        if ts - self.last_alert.get(key, -1e18) < self.cooldown:
            return None
        self.last_alert[key] = ts
        return Alert(ts, atype, severity, ip, msg, MITRE[atype])

    def feed(self, ev: AuthEvent) -> list:
        alerts = []
        if ev.kind == "failed":
            self.stats[ev.ip] += 1
            self.failures[ev.ip].append(ev.ts)
            self._purge(ev.ip, ev.ts)
            n = len(self.failures[ev.ip])
            if n >= self.threshold:
                a = self._emit("BRUTE_FORCE", "high", ev.ip, ev.ts,
                               f"{n} failed SSH logins in {self.window}s from {ev.ip}")
                if a:
                    alerts.append(a)
        elif ev.kind == "accepted":
            self._purge(ev.ip, ev.ts)
            n = len(self.failures[ev.ip])
            if n >= 2:
                a = self._emit("LOGIN_AFTER_FAILURES", "critical", ev.ip, ev.ts,
                               f"Successful login as '{ev.user}' from {ev.ip} after {n} failed attempts")
                if a:
                    alerts.append(a)
        return alerts

    def top_ips(self, n: int = 5):
        return sorted(self.stats.items(), key=lambda x: x[1], reverse=True)[:n]
