from cyberwatch.detector import AuthAnalyzer, AuthEvent, parse_auth_line


def ev(ts, kind="failed", user="root", ip="203.0.113.10"):
    return AuthEvent(ts, kind, user, ip)


def test_parse_syslog_failed_line():
    e = parse_auth_line(
        "Oct 13 10:00:01 h sshd[1]: Failed password for invalid user bob from 1.2.3.4 port 22 ssh2", 2026)
    assert e.kind == "failed" and e.user == "bob" and e.ip == "1.2.3.4"


def test_parse_iso_accepted_line():
    e = parse_auth_line("2026-10-13T10:00:01+00:00 h sshd[1]: Accepted publickey for ali from 5.6.7.8 port 22")
    assert e.kind == "accepted" and e.ip == "5.6.7.8"


def test_parse_ignores_unrelated_lines():
    assert parse_auth_line("Oct 13 10:00:01 h cron[1]: job done", 2026) is None


def test_brute_force_triggers_at_threshold():
    a = AuthAnalyzer(threshold=5, window=60)
    alerts = [x for t in range(5) for x in a.feed(ev(t))]
    assert len(alerts) == 1
    assert alerts[0].type == "BRUTE_FORCE"
    assert "T1110" in alerts[0].mitre


def test_no_alert_below_threshold():
    a = AuthAnalyzer(threshold=5, window=60)
    alerts = [x for t in range(4) for x in a.feed(ev(t))]
    assert alerts == []


def test_old_failures_outside_window_are_ignored():
    a = AuthAnalyzer(threshold=5, window=60)
    alerts = [x for t in range(5) for x in a.feed(ev(t * 100))]
    assert alerts == []


def test_cooldown_prevents_alert_flood():
    a = AuthAnalyzer(threshold=3, window=60, cooldown=300)
    alerts = [x for t in range(20) for x in a.feed(ev(t))]
    assert len(alerts) == 1


def test_login_after_failures_is_critical():
    a = AuthAnalyzer(threshold=6, window=60)
    for t in range(3):
        a.feed(ev(t))
    alerts = a.feed(ev(4, kind="accepted"))
    assert len(alerts) == 1
    assert alerts[0].severity == "critical"
    assert alerts[0].type == "LOGIN_AFTER_FAILURES"


def test_top_ips_ranks_by_failed_attempts():
    a = AuthAnalyzer(threshold=100, window=60)
    for _ in range(3):
        a.feed(ev(1, ip="1.1.1.1"))
    for _ in range(5):
        a.feed(ev(1, ip="2.2.2.2"))
    top = a.top_ips()
    assert top[0] == ("2.2.2.2", 5)
