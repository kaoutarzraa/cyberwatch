"""SQLite persistence for alerts."""
import sqlite3
import threading


class Storage:
    def __init__(self, path: str = "cyberwatch.db"):
        self.lock = threading.Lock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute("""CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, type TEXT,
            severity TEXT, source_ip TEXT, message TEXT, mitre TEXT)""")
        self.db.commit()

    def add_alert(self, a):
        with self.lock:
            self.db.execute(
                "INSERT INTO alerts (ts,type,severity,source_ip,message,mitre) VALUES (?,?,?,?,?,?)",
                (a.ts, a.type, a.severity, a.source_ip, a.message, a.mitre))
            self.db.commit()

    def recent_alerts(self, limit: int = 50):
        with self.lock:
            rows = self.db.execute(
                "SELECT ts,type,severity,source_ip,message,mitre FROM alerts ORDER BY id DESC LIMIT ?",
                (limit,)).fetchall()
        keys = ("ts", "type", "severity", "source_ip", "message", "mitre")
        return [dict(zip(keys, r)) for r in rows]

    def count_by_type(self):
        with self.lock:
            rows = self.db.execute("SELECT type, COUNT(*) FROM alerts GROUP BY type").fetchall()
        return dict(rows)
