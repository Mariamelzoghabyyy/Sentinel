"""Tests focus on the things that actually break SOC tooling:
parsing resilience, detection precision/recall, and the safety gates around
agent output. Run: pytest -q
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sentinel.agents import AnalystAgent, ResponderAgent, TriageAgent
from sentinel.judge import OutcomeJudge, ReportJudge, cohens_kappa, interpret_kappa
from sentinel.graph import Sentinel
from sentinel.llm import Backend, LocalBackend, extract_json
from sentinel.models import LogRecord
from sentinel.parser import parse_logs
from sentinel.rules import build_profiles

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
BASE = datetime(2026, 1, 1, 12, 0, 0)


def rec(ip, path, i=0, status=200, ua="Mozilla/5.0 (test)"):
    return LogRecord(ip=ip, ts=BASE + timedelta(seconds=i), method="GET", path=path,
                     status=status, size=500, user_agent=ua)


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #
def test_clf_parses_and_normalises_timezone(tmp_path):
    p = tmp_path / "a.log"
    p.write_text('1.2.3.4 - - [14/May/2024:03:12:44 +0200] "GET /x HTTP/1.1" 200 512 "-" "curl/8"\n')
    recs, stats = parse_logs(p)
    assert len(recs) == 1 and stats["lines_malformed"] == 0
    assert recs[0].ts == datetime(2024, 5, 14, 1, 12, 44)   # normalised to UTC
    assert recs[0].method == "GET" and recs[0].status == 200


def test_json_format_detected_automatically(tmp_path):
    p = tmp_path / "a.jsonl"
    p.write_text(json.dumps({
        "time_iso8601": "2024-05-14T03:12:44+00:00", "remote_addr": "9.9.9.9",
        "request_method": "POST", "request_uri": "/login", "status": 401,
        "body_bytes_sent": 12, "http_user_agent": "x",
    }) + "\n")
    recs, stats = parse_logs(p)
    assert stats["format"] == "json" and recs[0].ip == "9.9.9.9" and recs[0].status == 401


def test_malformed_lines_are_counted_not_fatal(tmp_path):
    p = tmp_path / "a.log"
    good = '1.2.3.4 - - [14/May/2024:03:12:44 +0000] "GET / HTTP/1.1" 200 5 "-" "x"\n'
    p.write_text(good + "garbage line\n" + good.replace("1.2.3.4", "5.6.7.8"))
    recs, stats = parse_logs(p)
    assert len(recs) == 2 and stats["lines_malformed"] == 1
    assert stats["malformed_samples"]


def test_missing_file_raises_clearly(tmp_path):
    with pytest.raises(FileNotFoundError):
        parse_logs(tmp_path / "nope.log")


def test_clf_and_json_samples_are_equivalent():
    a, _ = parse_logs(SAMPLES / "access.log")
    b, _ = parse_logs(SAMPLES / "access.jsonl")
    assert len(a) == len(b) == 3034
    assert [r.ip for r in a] == [r.ip for r in b]


# --------------------------------------------------------------------------- #
# Detection
# --------------------------------------------------------------------------- #
def test_benign_traffic_produces_no_signals():
    recs = []
    for i in range(40):
        ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0"
        recs.append(rec("203.0.113.5", "/static/app.js", i * 2, ua=ua))
        recs.append(rec("203.0.113.5", ["/", "/pricing", "/docs/api"][i % 3], i * 2 + 1, ua=ua))
    profiles, fleet = build_profiles(sorted(recs, key=lambda r: r.ts))
    p = profiles[0]
    assert p.verdict == "benign", [s.rule_id for s in p.signals]
    assert fleet["ips_flagged"] == 0


def test_scanner_detected_high_risk():
    recs = [rec("6.6.6.6", p, i, status=404,
                ua="Mozilla/5.0 (compatible; Nmap Scripting Engine)")
            for i, p in enumerate(["/wp-login.php", "/.env", "/phpmyadmin/", "/.git/config"])
            for _ in range(6)]
    profiles, _ = build_profiles(sorted(recs, key=lambda r: r.ts))
    p = profiles[0]
    ids = {s.rule_id for s in p.signals}
    assert {"BOT-001", "SCAN-001"} <= ids
    assert p.verdict == "malicious" and p.risk_score >= 60


def test_sqli_payload_flagged_critical():
    recs = [rec("7.7.7.7", "/search?q=1%20UNION%20SELECT%20password%20FROM%20users--", i)
            for i in range(3)]
    profiles, _ = build_profiles(recs)
    sig = [s for s in profiles[0].signals if s.rule_id == "EXPL-002"]
    assert sig and sig[0].severity == "critical"


def test_bruteforce_then_success_is_compromise_signal():
    recs = [rec("8.8.8.8", f"/login?u=user{i}", i, status=401) for i in range(12)]
    recs.append(rec("8.8.8.8", "/login?u=admin", 99, status=200))
    profiles, _ = build_profiles(sorted(recs, key=lambda r: r.ts))
    p = profiles[0]
    ids = {s.rule_id for s in p.signals}
    assert "AUTH-001" in ids and "AUTH-002" in ids
    assert p.compromised_identity == "admin"
    assert p.verdict == "malicious"


def test_auth_failures_without_success_is_not_compromise():
    recs = [rec("9.9.9.9", f"/login?u=u{i}", i, status=401) for i in range(15)]
    p = build_profiles(sorted(recs, key=lambda r: r.ts))[0][0]
    assert "AUTH-001" in {s.rule_id for s in p.signals}
    assert "AUTH-002" not in {s.rule_id for s in p.signals}


def test_honeypot_hit_alone_flags_bot():
    p = build_profiles([rec("5.5.5.5", "/admin-prod-do-not-exist.php", 0, status=404)])[0][0]
    assert "HONEY-001" in {s.rule_id for s in p.signals}


def test_metronomic_cadence_detected():
    # fast + perfectly regular = bot
    recs = [rec("4.4.4.4", f"/catalogue/{i}", i * 5) for i in range(30)]
    p = build_profiles(recs)[0][0]
    assert "BOT-002" in {s.rule_id for s in p.signals}
    # ...but a 60s uptime monitor must stay silent
    monitor = [rec("4.4.4.5", "/health", i * 60) for i in range(40)]
    p2 = build_profiles(monitor)[0][0]
    assert "BOT-002" not in {s.rule_id for s in p2.signals}
    assert p2.verdict == "benign"


def test_risk_score_is_capped():
    recs = [rec("3.3.3.3", "/.env?q=1%20UNION%20SELECT", i, status=404,
                ua="sqlmap/1.0") for i in range(200)]
    profiles, _ = build_profiles(recs)
    assert all(0 <= p.risk_score <= 100 for p in profiles)


# --------------------------------------------------------------------------- #
# Agent safety contracts
# --------------------------------------------------------------------------- #
class ScriptedBackend(Backend):
    """Returns whatever the test wants, so we can prove the validators bite."""

    name = "scripted"

    def __init__(self, replies):
        self.replies = replies

    def complete(self, system, user, max_tokens=1200):
        for key, val in self.replies.items():
            if key in system:
                return val
        return None


def _profile(ip="1.1.1.1", risk=80, verdict="malicious", signals=None, auth=0):
    return {
        "ip": ip, "risk_score": risk, "verdict": verdict, "requests": 10,
        "unique_paths": 4, "req_per_min_peak": 5.0, "error_4xx": 2,
        "auth_failures": auth, "signals": signals or [
            {"rule_id": "SCAN-001", "title": "enum", "severity": "high",
             "evidence": ["x"], "mitre": "T1595"}],
        "span_seconds": 100.0, "status_histogram": {"2xx": 8}, "methods": {"GET": 10},
        "user_agents": ["curl"], "top_paths": ["/x ×3"], "conf_placeholder": 0.7,
        "first_seen": "2026-01-01T12:00:00", "last_seen": "2026-01-01T12:01:40",
        "confidence": 0.7, "compromised_identity": "",
    }


def test_triage_drops_hallucinated_ips():
    backend = ScriptedBackend({"triage lead": json.dumps({
        "escalate": [{"ip": "9.9.9.9", "priority": "P1", "reason": "invented"},
                     {"ip": "1.1.1.1", "priority": "P2", "reason": "real"}],
        "dismiss": [], "summary": "x"})})
    out = TriageAgent(backend).run([_profile()], {"ips_total": 1})
    assert [e["ip"] for e in out["escalate"]] == ["1.1.1.1"]


def test_triage_cannot_upgrade_weak_ip_to_p1():
    backend = ScriptedBackend({"triage lead": json.dumps({
        "escalate": [{"ip": "1.1.1.1", "priority": "P1", "reason": "inflated"}],
        "dismiss": [], "summary": "x"})})
    out = TriageAgent(backend).run([_profile(risk=22, verdict="suspicious")], {"ips_total": 1})
    # risk 22 < 35 -> P4; the model asked for P1 and was overruled by the score
    assert out["escalate"][0]["priority"] == "P4"


def test_triage_falls_back_when_model_is_junk():
    out = TriageAgent(ScriptedBackend({"triage lead": "lol not json"})) \
        .run([_profile()], {"ips_total": 1})
    assert out["source"] == "heuristic" and out["escalate"]


def test_analyst_clamps_confidence_and_requires_narrative():
    backend = ScriptedBackend({"senior SOC analyst": json.dumps({
        "narrative": "did things", "confidence": 4.2, "attck": ["T1595"],
        "next_steps": ["check"], "false_positive_check": "none"})})
    out = AnalystAgent(backend).run(_profile(), [], "reason")
    assert out["confidence"] == 0.99 and out["narrative"] == "did things"


def test_analyst_rejects_non_json():
    out = AnalystAgent(ScriptedBackend({"senior SOC analyst": "sorry I can't"})) \
        .run(_profile(), [], "reason")
    assert out["source"] == "heuristic" and out["narrative"]


def test_responder_gate_blocks_low_risk():
    out = ResponderAgent(LocalBackend()).run(_profile(risk=40, verdict="suspicious"), {})
    assert out["gated"] is True
    assert [a["action"] for a in out["proposed"]] == ["monitor"]


def test_responder_rejects_disallowed_and_unevidenced_actions():
    backend = ScriptedBackend({"incident responder": json.dumps({"actions": [
        {"action": "delete_database", "target": "x", "rationale": "no"},
        {"action": "reset_credentials", "target": "acct", "rationale": "no auth evidence"},
        {"action": "block_ip", "target": "1.1.1.1", "rationale": "yes",
         "reversible": True, "urgency": "immediate"},
    ]})})
    out = ResponderAgent(backend).run(_profile(auth=0), {})
    assert [a["action"] for a in out["proposed"]] == ["block_ip"]


def test_responder_allows_credential_actions_with_auth_evidence():
    backend = ScriptedBackend({"incident responder": json.dumps({"actions": [
        {"action": "force_logout", "target": "acct", "rationale": "ok",
         "reversible": True, "urgency": "immediate"}]})})
    out = ResponderAgent(backend).run(_profile(auth=9), {})
    assert out["proposed"][0]["action"] == "force_logout"


# --------------------------------------------------------------------------- #
# LLM plumbing
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("raw,expected", [
    ('{"a":1}', {"a": 1}),
    ('```json\n{"a":2}\n```', {"a": 2}),
    ('Sure! {"a":3} cheers', {"a": 3}),
    ("no json here", None),
    (None, None),
    ('[{"b":1}]', {"items": [{"b": 1}]}),
])
def test_extract_json_is_forgiving_but_safe(raw, expected):
    assert extract_json(raw) == expected


def test_local_backend_returns_none_not_raises():
    assert LocalBackend().complete("s", "u") is None


# --------------------------------------------------------------------------- #
# End-to-end graph
# --------------------------------------------------------------------------- #
def test_end_to_end_suspends_and_resumes(tmp_path):
    out = tmp_path / "r.md"
    pipe = Sentinel(backend=LocalBackend())
    r = pipe.run(str(SAMPLES / "incident.log"), thread_id="e2e", auto_approve=False)
    assert r["status"] == "awaiting_approval"
    assert r["state"]["escalations"]

    r2 = pipe.resume("e2e", {"91.240.118.9": "approve"}, out_path=str(out))
    assert r2["status"] == "complete"
    assert out.exists()
    md = out.read_text()
    for section in ("# Sentinel", "## Executive summary", "## Priority queue",
                    "## Detailed findings", "## Automated critic review",
                    "## Recommended next shift actions"):
        assert section in md

    approved = [a for a in r2["state"]["actions"] if a.get("approvals") == "approved"]
    assert approved and approved[0]["executed"][0]["mode"] == "dry-run"


def test_end_to_end_auto_approve_quiet_day():
    """A quiet day must not escalate to P1, and must not batch-action noise."""
    r = Sentinel(backend=LocalBackend()).run(str(SAMPLES / "quiet.log"),
                                             thread_id="quiet", auto_approve=True)
    assert r["status"] == "complete"
    priorities = {e["priority"] for e in r["state"]["escalations"]}
    assert "P1" not in priorities, priorities
    assert len(r["state"]["escalations"]) <= 2, "quiet day should not flood the queue"


def test_critic_high_issue_triggers_bounded_revise():
    class CriticBackend(ScriptedBackend):
        def complete(self, system, user, max_tokens=1200):
            if "skeptical reviewing analyst" in system:
                return json.dumps({"issues": [{"severity": "high", "finding": "f", "fix": "x"}],
                                   "overall": "bad", "ship": False})
            return super().complete(system, user, max_tokens)

    r = Sentinel(backend=CriticBackend({})).run(str(SAMPLES / "incident.log"),
                                                thread_id="rev", auto_approve=True)
    assert r["state"]["run_meta"]["critic_rounds"] == 1     # bounded, not a livelock
    assert "Reviewer addendum" in r["report"]


def test_no_escalations_skips_analyst_and_still_reports(tmp_path):
    p = tmp_path / "clean.log"
    lines = []
    for i in range(40):
        ts = (BASE + timedelta(seconds=i * 3)).strftime("%d/%b/%Y:%H:%M:%S +0000")
        path = ["/static/app.js", "/", "/pricing"][i % 3]
        lines.append(f'203.0.113.9 - - [{ts}] "GET {path} HTTP/1.1" 200 1000 "-" '
                     f'"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0"')
    p.write_text("\n".join(lines))
    r = Sentinel(backend=LocalBackend()).run(str(p), thread_id="clean", auto_approve=True)
    assert r["status"] == "complete"
    assert r["state"]["escalations"] == []
    assert "No malicious activity confirmed" in r["report"]


# --------------------------------------------------------------------------- #
# Priority calibration (regression: severity-only priority inflated a 1-request
# honeypot hit to P1, identical to a confirmed compromise)
# --------------------------------------------------------------------------- #
def test_priority_is_risk_derived_not_severity_derived():
    from sentinel.agents import risk_to_priority
    assert risk_to_priority(100) == "P1"
    assert risk_to_priority(85) == "P1"
    assert risk_to_priority(61) == "P2"
    assert risk_to_priority(40) == "P3"
    assert risk_to_priority(10) == "P4"


def test_lone_honeypot_hit_is_not_p1():
    """A single honeypot request is a real finding but zero-impact: P2, not P1."""
    recs = [rec("5.5.5.5", "/admin-prod-do-not-exist.php", 0, status=404,
                ua="curl/8.7.1")]
    profiles, fleet = build_profiles(recs)
    p = profiles[0].to_dict()
    out = TriageAgent(LocalBackend()).run([p], fleet)
    prio = out["escalate"][0]["priority"]
    assert prio == "P2", f"expected P2, got {prio} for risk {p['risk_score']}"


# --------------------------------------------------------------------------- #
# LLM-as-judge
# --------------------------------------------------------------------------- #
class _MockJudge(Backend):
    def __init__(self, verdict):
        self.name = "mock-judge"
        self._v = verdict
    def complete(self, system, user, max_tokens=1200):
        if "independent senior SOC analyst" in system:
            return json.dumps({"verdict": self._v, "confidence": 0.7,
                               "reasoning": "mock", "key_evidence": [],
                               "would_contain": self._v == "malicious"})
        if "SOC shift lead" in system:
            return json.dumps({"faithfulness": 4, "prioritisation": 4, "actionability": 3,
                               "calibration": 4, "fabrications": ["invented a CVE"],
                               "overall": 4, "verdict": "revise", "top_issue": "minor"})
        return None


def test_judge_bundle_is_blind():
    """The judge must not see rule IDs, risk scores, or the system's verdict."""
    p = _profile()
    bundle = OutcomeJudge.blind_bundle(p, ["GET /x 200", "BOT-001 fired risk_score 90"])
    blob = json.dumps(bundle)
    for leak in ("rule_id", "SCAN-", "BOT-", "EXPL-", "AUTH-", "HONEY-",
                 "RATE-", "risk_score", '"verdict"'):
        assert leak not in blob, f"leaked {leak} into judge bundle"


def test_judge_abstains_without_backend():
    out = OutcomeJudge(LocalBackend()).judge(_profile(), [])
    assert out["verdict"] is None and out["source"] == "abstain"
    assert out["confidence"] == 0.0


def test_judge_validates_invalid_verdict():
    class Bad(Backend):
        name = "bad"
        def complete(self, system, user, max_tokens=1200):
            return json.dumps({"verdict": "probably-fine"})
    out = OutcomeJudge(Bad()).judge(_profile(), [])
    assert out["verdict"] is None        # rejected, falls back to abstain


def test_judge_parses_valid_verdict_and_clamps_confidence():
    class Loud(Backend):
        name = "loud"
        def complete(self, system, user, max_tokens=1200):
            return json.dumps({"verdict": "MALICIOUS", "confidence": 9.5,
                               "reasoning": "x", "key_evidence": ["a"]})
    out = OutcomeJudge(Loud()).judge(_profile(), [])
    assert out["verdict"] == "malicious" and out["confidence"] == 1.0


def test_report_judge_flags_fabrications():
    out = ReportJudge(_MockJudge("benign")).judge("# report", {"parse_stats": {}})
    assert out["fabrications"] == ["invented a CVE"]
    assert out["verdict"] == "revise" and out["overall"] == 4


def test_cohens_kappa_catches_constant_judge():
    """66.7% raw agreement but zero information — kappa must expose it."""
    r = cohens_kappa(["benign"] * 9, ["benign"] * 6 + ["malicious"] * 3,
                     ["benign", "malicious"])
    assert r["agreement"] > 0.6 and r["kappa"] == 0.0
    assert interpret_kappa(0.0) == "slight"


def test_cohens_kappa_perfect_and_edge_cases():
    assert cohens_kappa(["a"], ["a"], ["a"])["kappa"] == 1.0
    assert cohens_kappa([], [], ["a"])["kappa"] is None
