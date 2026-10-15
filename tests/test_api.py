from app import create_app


def client(tmp_path):
    return create_app(start_log_thread=False, db_path=str(tmp_path / "t.db")).test_client()


def test_health(tmp_path):
    r = client(tmp_path).get("/health")
    assert r.status_code == 200
    assert r.get_json()["status"] == "ok"


def test_feed_detects_brute_force(tmp_path):
    c = client(tmp_path)
    line = "Oct 13 10:00:0{0} demo sshd[1]: Failed password for root from 9.9.9.9 port 1 ssh2"
    for i in range(5):
        r = c.post("/api/feed", json={"line": line.format(min(i, 9))})
    data = r.get_json()
    assert any(a["type"] == "BRUTE_FORCE" for a in data["alerts"])


def test_alerts_endpoint_returns_stored_alerts(tmp_path):
    c = client(tmp_path)
    line = "Oct 13 10:00:0{0} demo sshd[1]: Failed password for root from 8.8.8.8 port 1 ssh2"
    for i in range(5):
        c.post("/api/feed", json={"line": line.format(min(i, 9))})
    r = c.get("/api/alerts")
    assert r.status_code == 200
    assert len(r.get_json()) == 1


def test_summary_endpoint(tmp_path):
    c = client(tmp_path)
    line = "Oct 13 10:00:0{0} demo sshd[1]: Failed password for root from 7.7.7.7 port 1 ssh2"
    for i in range(5):
        c.post("/api/feed", json={"line": line.format(min(i, 9))})
    r = c.get("/api/summary")
    body = r.get_json()
    assert body["alerts_by_type"]["BRUTE_FORCE"] == 1
    assert body["top_suspicious_ips"][0][0] == "7.7.7.7"
