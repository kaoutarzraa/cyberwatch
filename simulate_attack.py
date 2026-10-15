"""Sends fake SSH auth-log lines to the running API to demo the detection (no real network traffic)."""
import sys
import time

import requests

URL = "http://localhost:5000/api/feed"


def line(msg):
    return f"Oct 13 10:00:00 demo sshd[1]: {msg}"


attack = (
    [line(f"Failed password for root from 203.0.113.10 port 51000 ssh2") for _ in range(5)]
    + [line("Accepted password for root from 203.0.113.10 port 51000 ssh2")]
)

print("Sending a simulated SSH brute-force attack...\n")
for l in attack:
    r = requests.post(URL, json={"line": l})
    for a in r.json().get("alerts", []):
        print(f"ALERT [{a['severity']}] {a['type']}: {a['message']} | {a['mitre']}")
    time.sleep(0.3)

print("\nDone. Check GET /api/alerts and /api/summary.")
