"""CyberWatch API - Flask app exposing SSH brute-force detection as REST endpoints."""
import logging
import os
import threading
import time

from datetime import datetime

from flask import Flask, jsonify, render_template, request

from cyberwatch.detector import AuthAnalyzer, parse_auth_line
from cyberwatch.storage import Storage

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
log = logging.getLogger("cyberwatch")


def create_app(start_log_thread: bool = True, db_path: str = None) -> Flask:
    app = Flask(__name__)

    cfg = {
        "auth_log": os.getenv("AUTH_LOG", "demo_auth.log"),
        "threshold": int(os.getenv("BF_THRESHOLD", "5")),
        "window": int(os.getenv("BF_WINDOW", "60")),
        "from_start": os.getenv("READ_FROM_START", "0") == "1",
    }
    analyzer = AuthAnalyzer(threshold=cfg["threshold"], window=cfg["window"])
    storage = Storage(db_path or os.getenv("DB_PATH", "cyberwatch.db"))
    app.extensions["cw"] = {"analyzer": analyzer, "storage": storage, "cfg": cfg}

    def handle(alert):
        storage.add_alert(alert)
        log.warning("ALERT [%s] %s | %s", alert.severity, alert.message, alert.mitre)

    def log_loop():
        path = cfg["auth_log"]
        while not os.path.exists(path):
            log.info("Waiting for log file: %s", path)
            time.sleep(2)
        with open(path, "r", errors="ignore") as fh:
            if not cfg["from_start"]:
                fh.seek(0, os.SEEK_END)
            while True:
                line = fh.readline()
                if not line:
                    time.sleep(1)
                    continue
                ev = parse_auth_line(line)
                if ev:
                    for a in analyzer.feed(ev):
                        handle(a)

    if start_log_thread:
        threading.Thread(target=log_loop, daemon=True).start()

    @app.get("/")
    def dashboard():
        raw_alerts = storage.recent_alerts()
        alerts = []
        for a in raw_alerts:
            a = dict(a)
            a["time"] = datetime.fromtimestamp(a["ts"]).strftime("%H:%M:%S")
            alerts.append(a)
        top = analyzer.top_ips()
        return render_template(
            "index.html",
            alerts=alerts,
            total=len(raw_alerts),
            top_ip=top[0] if top else None,
        )

    @app.get("/health")
    def health():
        return jsonify(status="ok")

    @app.get("/api/alerts")
    def api_alerts():
        return jsonify(storage.recent_alerts())

    @app.get("/api/summary")
    def api_summary():
        return jsonify({
            "alerts_by_type": storage.count_by_type(),
            "top_suspicious_ips": analyzer.top_ips(),
        })

    @app.post("/api/feed")
    def api_feed():
        """Feed one raw auth-log line to the analyzer (used by simulate_attack.py)."""
        line = (request.get_json(silent=True) or {}).get("line", "")
        ev = parse_auth_line(line)
        alerts = []
        if ev:
            alerts = analyzer.feed(ev)
            for a in alerts:
                handle(a)
        return jsonify({"alerts": [a.to_dict() for a in alerts]})

    return app


app = create_app() if os.getenv("CYBERWATCH_NO_AUTOSTART") != "1" else None

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
