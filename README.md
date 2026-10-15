# CyberWatch API

A small REST API that detects SSH brute-force attacks in real time.

## What it does
It reads SSH auth-log lines (from a real `/var/log/auth.log` or a simulated
file), detects brute-force login attempts using a sliding time window, maps
each alert to a MITRE ATT&CK technique, stores them in SQLite, and exposes
everything through a REST API.

## Architecture
```
auth.log  ──tail──► parse_auth_line ──► AuthAnalyzer (sliding window)
                                              │
                                              ▼
                                           Alert ──► SQLite ──► Flask API
```

## Endpoints
| Method | Path            | Description                              |
|--------|-----------------|-------------------------------------------|
| GET    | `/health`       | Liveness check                            |
| GET    | `/api/alerts`   | Most recent alerts                        |
| GET    | `/api/summary`  | Alert counts by type + top suspicious IPs |
| POST   | `/api/feed`     | Feed one raw log line (used for demos)    |

## Detection rules
| Rule | Condition | MITRE ATT&CK |
|---|---|---|
| Brute force | ≥ 5 failed logins / 60s from one IP | T1110.001 |
| Login after failures | successful login from an IP with ≥ 2 recent failures | T1078 |

Thresholds are configurable via `BF_THRESHOLD` and `BF_WINDOW`. A cooldown
avoids repeated alerts for the same IP.

## Run locally

**Windows (PowerShell) — tested, no errors:**
```powershell
py -m pip install -r requirements.txt
New-Item demo_auth.log
$env:AUTH_LOG="demo_auth.log"
py app.py
```
Open http://localhost:5000 in your browser.
In a second terminal, in the same folder:
```powershell
py simulate_attack.py
```
Refresh the dashboard page: two alerts appear.

**macOS / Linux:**
```bash
pip install -r requirements.txt
touch demo_auth.log
AUTH_LOG=demo_auth.log python3 app.py       # http://localhost:5000
```
In a second terminal:
```bash
python3 simulate_attack.py
```

**Note (Windows):** if `python` or `pip` are not recognized, use `py` and
`py -m pip` instead — this is the reliable way on Windows.

**Note (Ubuntu 23.04+ / Debian 12+):** `pip install` may refuse with
`error: externally-managed-environment` (PEP 668). For a quick local test,
install with:
```bash
pip install -r requirements.txt --break-system-packages
```
(A proper alternative is a virtual environment: `python3 -m venv venv &&
source venv/bin/activate && pip install -r requirements.txt`.)

## Real attack test (two VMs: Ubuntu target + Kali attacker)

This project can also be tested against a **real** SSH brute-force attack,
using two virtual machines on a private (Host-only) network.

**On the Ubuntu VM (target):**
```bash
sudo apt update
sudo apt install -y openssh-server rsyslog python3-pip unzip
sudo systemctl enable --now ssh
sudo systemctl enable --now rsyslog
sudo usermod -aG adm $USER
sudo reboot
```
After reboot, find the Host-only IP (not the `10.0.2.x` NAT one):
```bash
ip addr show
```
Then run the API against the real log file:
```bash
cd cyberwatch
pip install -r requirements.txt --break-system-packages
AUTH_LOG=/var/log/auth.log python3 app.py
```
Open `http://localhost:5000` in the VM's browser.

**On the Kali VM (attacker):**
```bash
ping -c 4 <UBUNTU_HOST_ONLY_IP>
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://<UBUNTU_HOST_ONLY_IP> -t 4
```

Refresh the Ubuntu dashboard: a `BRUTE_FORCE` alert appears with Kali's IP
and the MITRE technique `T1110.001`.

**Only attack machines you own, on an isolated Host-only network.**

## Run with Docker
```bash
docker build -t cyberwatch .
docker run -p 5000:5000 -e AUTH_LOG=demo_auth.log cyberwatch
```

## Demo the detection (no real attack needed)
With the API running:
```bash
python simulate_attack.py
curl http://localhost:5000/api/alerts
curl http://localhost:5000/api/summary
```

## Tests
```bash
CYBERWATCH_NO_AUTOSTART=1 pytest -q
```
GitHub Actions runs these tests and builds the Docker image on every push
(`.github/workflows/ci.yml`).

## Known limitations
- Single-host log source (no multi-machine aggregation).
- Threshold-based detection, not ML-based: possible false positives behind
  a shared NAT.
