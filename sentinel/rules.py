"""Deterministic bot/hostile-behaviour detection.

Design principle: the *rules* are boring, auditable, and non-hallucinable;
the *agents* later explain, prioritize and write up what the rules found.
That split is what keeps an LLM pipeline trustworthy in a SOC context.

Every rule emits a Signal with concrete evidence strings so the analyst can
verify each claim against the raw log.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import timedelta
from statistics import median
from urllib.parse import unquote

from .models import IpProfile, LogRecord, Signal

SEVERITY_WEIGHT = {"low": 5, "medium": 15, "high": 30, "critical": 50}

# --------------------------------------------------------------------------- #
# Known-bad / automation signatures
# --------------------------------------------------------------------------- #
# Tier 1: offensive tooling. Presence alone is a finding.
OFFENSIVE_UA_TOKENS = (
    "sqlmap", "nikto", "nmap", "masscan", "zgrab", "nuclei", "dirbuster",
    "gobuster", "ffuf", "wfuzz", "hydra", "nessus", "acunetix", "wpscan",
    "burp", "zap/", "metasploit", "openvas", "arachni",
)
# Tier 2: generic HTTP clients / bot frameworks. Entirely normal for SOAR jobs,
# CI pipelines, and first-party services — weight accordingly. This distinction
# came out of the benchmark: treating curl like sqlmap poisoned real detections.
CLIENT_UA_TOKENS = (
    "curl/", "wget/", "python-requests", "python-urllib", "go-http-client",
    "libwww-perl", "scrapy", "axios/", "okhttp", "java/", "httpie",
)
BOT_UA_TOKENS = OFFENSIVE_UA_TOKENS + CLIENT_UA_TOKENS

SCANNER_PATHS = (
    "/wp-login.php", "/wp-admin", "/xmlrpc.php", "/phpmyadmin", "/.env",
    "/.git/config", "/admin", "/administrator", "/cgi-bin/", "/shell.php",
    "/etc/passwd", "/config.php", "/backup", "/.aws/credentials", "/vendor/phpunit",
    "/actuator/env", "/actuator/health", "/solr/admin", "/console", "/.svn/",
    "/boaform/", "/hnap1", "/GponForm/", "/login.action", "/owa/auth",
)

TRAVERSAL_TOKENS = ("../", "..%2f", "%2e%2e", "/etc/passwd", "..\\")
XSS_TOKENS = ("<script", "%3cscript", "javascript:", "onerror=", "alert(")
SQLI_TOKENS = ("union select", "' or '1'='1", "sleep(", "benchmark(",
               "information_schema", "concat(", "'--", "1=1--")
CMD_INJECTION_TOKENS = (";id", "|id", "$(", "`id`", "&&whoami", ";wget", ";curl")

AUTH_PATHS = ("/login", "/signin", "/auth", "/session", "/oauth/token", "/api/token")


# --------------------------------------------------------------------------- #
# Rule helpers
# --------------------------------------------------------------------------- #
def _norm(path: str) -> str:
    return unquote(path).lower()


def _prefix_concentration(recs: list[LogRecord]) -> float:
    """Share of requests falling under the single most-common first path segment.

    0.95 means "everything hit /old-blog/..." — a broken-link pattern from one
    user, not a scan. Scanners walk *unrelated* top-level words, so their
    prefix concentration is low. This is the feature that separates the two.
    """
    if not recs:
        return 0.0
    tops = Counter()
    for r in recs:
        parts = [p for p in _norm(r.path).split("/") if p]
        tops[parts[0] if parts else "/"] += 1
    return tops.most_common(1)[0][1] / len(recs)


def _window_counts(times: list, seconds: int) -> int:
    """Max number of timestamps inside any sliding `seconds` window."""
    if len(times) < 2:
        return len(times)
    times = sorted(times)
    hi, best = 0, 1
    for lo in range(len(times)):
        while hi < len(times) and (times[hi] - times[lo]).total_seconds() <= seconds:
            hi += 1
        best = max(best, hi - lo)
    return best


def _sig(rule_id: str, title: str, severity: str, evidence: list[str],
         mitre: str = "", recommendation: str = "", score: int | None = None) -> Signal:
    return Signal(
        rule_id=rule_id,
        title=title,
        severity=severity,
        score=SEVERITY_WEIGHT[severity] if score is None else score,
        evidence=evidence[:6],
        mitre=mitre,
        recommendation=recommendation,
    )


# --------------------------------------------------------------------------- #
# Individual rules — each takes one IP's records
# --------------------------------------------------------------------------- #
def rule_automation_ua(recs: list[LogRecord]) -> list[Signal]:
    hits = Counter()
    for r in recs:
        ua = r.user_agent.lower()
        for tok in BOT_UA_TOKENS:
            if tok in ua:
                hits[tok] += 1
                break
    if not hits:
        return []
    offensive = [t for t in hits if t in OFFENSIVE_UA_TOKENS]
    ev = [f"{n} request(s) with automation UA token '{t}'" for t, n in hits.most_common(4)]
    if offensive:
        ev.append(f"offensive tooling present: {', '.join(sorted(offensive))}")
        return [_sig("BOT-001", "Offensive-tool user agent", "high", ev,
                     mitre="T1595 Active Scanning",
                     recommendation="Block UA at the edge; tool identity alone is strong evidence.")]
    return [_sig("BOT-001", "Automation HTTP client user agent", "low", ev,
                 mitre="T1593 Search Open Websites", score=6,
                 recommendation="Common for CI/SOAR/integrations — judge by behaviour, not the UA.")]


def rule_scan_paths(recs: list[LogRecord]) -> list[Signal]:
    hit = [r for r in recs if any(s in _norm(r.path) for s in SCANNER_PATHS)]
    if not hit:
        return []
    uniq = sorted({r.path for r in hit})
    ratio = len(uniq) / max(1, len({r.path for r in recs}))
    ev = [f"{len(hit)} request(s) to {len(uniq)} sensitive path(s), e.g. {', '.join(uniq[:4])}"]
    if ratio > 0.6 and len(uniq) >= 3:
        ev.append(f"{ratio:.0%} of this IP's unique paths are scanner targets (broad sweep)")
    sev = "high" if len(uniq) >= 5 else ("medium" if len(uniq) >= 2 else "low")
    return [_sig(
        "SCAN-001", "Sensitive-path enumeration", sev, ev,
        mitre="T1595.002 Vulnerability Scanning",
        recommendation="404 noise on these paths is expected; confirm WAF virtual-patching rule is active.",
    )]


def rule_web_exploit_payloads(recs: list[LogRecord]) -> list[Signal]:
    out: list[Signal] = []
    for token_set, rule_id, name, sev, mitre in (
        (TRAVERSAL_TOKENS, "EXPL-001", "Path traversal attempt", "high", "T1190 Exploit Public-Facing Application"),
        (SQLI_TOKENS, "EXPL-002", "SQL injection payload", "critical", "T1190 Exploit Public-Facing Application"),
        (XSS_TOKENS, "EXPL-003", "Cross-site scripting payload", "high", "T1059.007 JavaScript"),
        (CMD_INJECTION_TOKENS, "EXPL-004", "OS command injection payload", "critical", "T1059 Command Execution"),
    ):
        hit = [r for r in recs if any(t in _norm(r.path) for t in token_set)]
        if hit:
            accepted = [r for r in hit if r.status < 400]
            ev = [f"{r.method} {r.path[:110]} -> {r.status}" for r in hit[:4]]
            eff_score = SEVERITY_WEIGHT[sev]
            if accepted:
                # Same payload, very different implication: the app SERVED it.
                ev.append(f"{len(accepted)}/{len(hit)} payload(s) accepted by the application "
                          f"(status <400) — possible successful exploitation")
                eff_score = min(100, eff_score + 20)
            elif all(r.status >= 400 for r in hit):
                ev.append("all payloads rejected by the app (status >=400) — probe, not a win")
            out.append(_sig(rule_id, name, sev, ev, mitre=mitre, score=eff_score,
                            recommendation="Treat payloads as hostile input; verify parameterised queries and no traversal sinks."))
    return out


def rule_brute_force(recs: list[LogRecord]) -> list[Signal]:
    auth = [r for r in recs if any(a in _norm(r.path) for a in AUTH_PATHS)]
    fails = [r for r in auth if r.status in (401, 403)]
    if len(fails) < 8:
        return []
    peak = _window_counts([r.ts for r in fails], 300)
    # >25 attempts (however slow) is deliberate tooling, not a forgotten password.
    sev = "high" if len(fails) >= 25 or peak >= 15 else ("medium" if len(fails) >= 10 else "low")
    # Distinct identities are the real tell: a human retries ONE account, a
    # sprayer walks a user list. 25 attempts against 1 account = clumsy human.
    usernames = set()
    for r in fails:
        m = re.search(r"[?&](?:u|user|username|email)=([^&]+)", r.path)
        if m:
            usernames.add(unquote(m.group(1)))
    if len(usernames) >= 5:
        sev = "high" if sev == "medium" else sev
        score = {"high": 35, "medium": 22, "low": 10}[sev]
    else:
        score = {"high": 35, "medium": 15, "low": 8}[sev]
    endpoints = {r.path.split("?")[0] for r in auth}
    ev = [f"{len(fails)} failed auth response(s) against {len(endpoints)} endpoint(s) "
          f"({', '.join(sorted(endpoints)[:3])})",
          f"peak {peak} failures within 5 minutes"]
    if usernames:
        ev.append(f"{len(usernames)} distinct identities targeted"
                  + (" — spray pattern" if len(usernames) >= 5 else " — single-account guessing"))
    return [_sig("AUTH-001", "Credential brute force / password spraying", sev, ev, score=score,
                 mitre="T1110.001 Password Guessing" if len(usernames) >= 5 else "T1110.001 Password Guessing",
                 recommendation="Rate-limit + lockout on auth endpoints; check for any 200 response in the auth path.")]


def rule_auth_success_after_failures(recs: list[LogRecord]) -> list[Signal]:
    auth = [r for r in recs if any(a in _norm(r.path) for a in AUTH_PATHS)]
    ok = [r for r in auth if r.status == 200]
    fails_before = [r for r in auth if r.status in (401, 403) and ok and r.ts < ok[0].ts]
    if ok and len(fails_before) >= 8:
        ev = [f"{len(fails_before)} failures before first 200 at {ok[0].ts.isoformat()} ({ok[0].path})"]
        return [_sig("AUTH-002", "Successful auth after failure burst (possible account compromise)",
                     "critical", ev, mitre="T1078 Valid Accounts",
                     recommendation="Force session revocation + credential reset for the affected account; pull app-side auth logs.")]
    return []


def rule_error_rate_404(recs: list[LogRecord]) -> list[Signal]:
    """4xx storms indicate fuzzing — unless they're concentrated under one path
    prefix, which is what a real user clicking dead archive links looks like.
    That distinction was a measured false positive before this guard existed."""
    if len(recs) < 20:
        return []
    err = sum(1 for r in recs if 400 <= r.status < 500)
    rate = err / len(recs)
    if rate < 0.7 or err < 20:
        return []
    concentration = _prefix_concentration([r for r in recs if 400 <= r.status < 500])
    if concentration >= 0.9:
        return []          # one broken section of the site, not enumeration
    codes = Counter(r.status for r in recs if r.status >= 400)
    top = ", ".join(f"{c}:{n}" for c, n in codes.most_common(3))
    sev = "high" if rate >= 0.9 else "medium"
    return [_sig("SCAN-002", "High 4xx rate (fuzzing / enumeration)", sev,
                 [f"{err}/{len(recs)} requests were 4xx ({rate:.0%}); status mix {top}",
                  f"4xx spread across unrelated paths (top prefix = {concentration:.0%} of traffic)"],
                 mitre="T1595 Active Scanning",
                 recommendation="Edge block after threshold; 4xx storms are cheap to absorb but hide real probing.")]


def rule_path_enumeration(recs: list[LogRecord]) -> list[Signal]:
    paths = [r.path.split("?")[0] for r in recs]
    uniq = len(set(paths))
    if len(recs) < 10 or uniq < 25:
        return []
    ratio = uniq / len(recs)
    if ratio < 0.8:
        return []
    if _prefix_concentration(recs) >= 0.9:
        return []          # deep crawl of one section ≠ directory discovery
    exts = Counter(p.rsplit(".", 1)[-1].lower() for p in paths if "." in p.split("/")[-1])
    ext_txt = ", ".join(f".{e}×{n}" for e, n in exts.most_common(4)) or "extensionless paths"
    return [_sig("SCAN-003", "Directory/content enumeration", "medium",
                 [f"{uniq} unique paths over {len(recs)} requests ({ratio:.0%} novel)",
                  f"extension spread: {ext_txt}"],
                 mitre="T1083 File and Directory Discovery",
                 recommendation="Serve a catch-all 404 quickly; consider tar-pit for this IP.")]


def rule_high_rate(recs: list[LogRecord]) -> list[Signal]:
    # A fast browser on an asset-heavy page can briefly hit ~60 req/min; a human
    # cannot *sustain* 120+/min for a full minute. Below that, stay quiet.
    if len(recs) < 30:
        return []
    peak = _window_counts([r.ts for r in recs], 60)
    if peak < 120:
        return []
    # Severity should scale with how far past human capacity the burst is.
    # 120/min is abusive; 1000/min is infrastructure damage.
    if peak >= 600:
        sev, score = "critical", 50
    elif peak >= 300:
        sev, score = "high", 30
    else:
        sev, score = "medium", 15
    err_ratio = sum(1 for r in recs if r.status >= 400) / len(recs)
    if err_ratio >= 0.8:
        ev_note = (f"{err_ratio:.0%} of the burst returned errors — high-volume but ineffective "
                   f"(crude script, not a successful attack)")
        score = max(15, score - 20)
    else:
        ev_note = f"{1-err_ratio:.0%} of the burst succeeded — the flood is landing and consuming capacity"
        if peak >= 240:
            score = min(70, score + 25)   # sustained abuse of endpoints that are working
    return [_sig("RATE-001", "Burst request rate inconsistent with humans", sev,
                 [f"peak {peak} req/min from this IP ({peak/60:.1f} req/s sustained)", ev_note],
                 mitre="T1498 Network DoS (potential)", score=score,
                 recommendation="Apply per-IP rate limiting; verify no cache-bypass amplification.")]


def rule_fixed_interval(recs: list[LogRecord]) -> list[Signal]:
    """Bots hit on a metronomic cadence — but so do uptime monitors, which are
    benign and usually poll every 30-60s. So this rule only fires on *fast*
    metronomes (<= 15s) and is deliberately low severity: it corroborates,
    it never convicts on its own. Without this guard, every health-check IP in
    the estate becomes a false positive."""
    if len(recs) < 25:
        return []
    ts = sorted(r.ts for r in recs)
    gaps = [(b - a).total_seconds() for a, b in zip(ts, ts[1:])]
    gaps = [g for g in gaps if g > 0]
    if len(gaps) < 20:
        return []
    med = median(gaps)
    if med <= 0 or med > 15:          # >15s apart = health check, not a bot sweep
        return []
    mad = median([abs(g - med) for g in gaps])
    jitter = mad / med
    if jitter < 0.05:
        return [_sig("BOT-002", "Machine-regular request cadence", "low",
                     [f"{len(recs)} requests, median gap {med:.1f}s with MAD {mad:.2f}s "
                      f"(jitter {jitter:.1%}) — faster and more regular than human clicking"],
                     mitre="T1071 Application Layer Protocol", score=5,
                     recommendation="Corroborating signal only; also matches busy uptime monitors.")]
    return []


def rule_no_assets(recs: list[LogRecord]) -> list[Signal]:
    """Real browsers pull JS/CSS/images; scanners only hit endpoints."""
    n = len(recs)
    if n < 15:
        return []
    asset = sum(1 for r in recs if any(
        r.path.split("?")[0].lower().endswith(e)
        for e in (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".webp")
    ))
    if asset / n < 0.02:
        # Measured 54% precision in benchmark/ — many benign clients (API consumers,
        # CI jobs, mobile apps) never fetch assets. Scored at 2 to make that explicit.
        return [_sig("BOT-003", "No static-asset fetches (headless/scanner profile)", "low",
                     [f"{asset}/{n} requests were static assets ({asset/n:.1%})"],
                     mitre="T1592 Gather Victim Host Information", score=2,
                     recommendation="Corroborating only — 54% precision standalone; never act on this alone.")]
    return []


def rule_missing_ua(recs: list[LogRecord]) -> list[Signal]:
    miss = sum(1 for r in recs if not r.user_agent.strip() or r.user_agent == "-")
    if miss >= 10 and miss / len(recs) > 0.5:
        return [_sig("BOT-004", "Missing/blank user agent", "low",
                     [f"{miss}/{len(recs)} requests had no UA"],
                     mitre="T1036 Masquerading",
                     recommendation="Combine with rate/scan signals before acting.")]
    return []


def rule_ua_rotation(recs: list[LogRecord]) -> list[Signal]:
    """Same IP presenting many distinct UAs smells like a distributed botnet node
    or a rotation-based evasion tool."""
    uas = {r.user_agent for r in recs if r.user_agent}
    if len(uas) >= 8:
        return [_sig("BOT-005", "User-agent rotation from one IP", "medium",
                     [f"{len(uas)} distinct UAs, e.g. " + " | ".join(list(sorted(uas))[:3])[:150]],
                     mitre="T1036 Masquerading",
                     recommendation="Any single UA is plausible; the rotation is the tell.")]
    return []


def rule_honeypot_hits(recs: list[LogRecord]) -> list[Signal]:
    """A hit on /admin-prod-do-not-exist.php is proof of scanning, no heuristics."""
    hp = [r for r in recs if "do-not-exist" in r.path.lower() or "honeypot" in r.path.lower()]
    if hp:
        # Not a probabilistic hint: no legitimate client can reach this path,
        # because nothing links to it and it does not exist. Treat as conviction.
        return [_sig("HONEY-001", "Honeypot path touched (proof of scanning)", "critical",
                     [f"{r.method} {r.path} -> {r.status}" for r in hp[:4]],
                     mitre="T1595 Active Scanning", score=50,
                     recommendation="Zero-false-positive indicator; safe to auto-block at the edge.")]
    return []



def rule_sequential_ids(recs: list[LogRecord]) -> list[Signal]:
    """Detect systematic walking of numbered/countable resources.

    /catalogue/page/1 ... /catalogue/page/120 is enumeration — just not of
    *directories*. The existing SCAN-003 misses it because it deliberately
    ignores single-prefix traffic (which is how a crawler looks). This rule
    closes that gap by checking path *shape* rather than path spread.
    """
    import re as _re
    if len(recs) < 20:
        return []
    numeric = [r for r in recs if _re.search(r"[/=]\d{1,6}(?:[/?.]|$)", r.path)]
    if len(numeric) / len(recs) < 0.85:
        return []
    ids = []
    for r in numeric:
        m = _re.search(r"[/=](\d{1,6})(?:[/?.]|$)", r.path)
        if m:
            ids.append(int(m.group(1)))
    if len(set(ids)) < 15:
        return []
    ordered = sum(1 for a, b in zip(ids, ids[1:]) if 0 < b - a <= 3)
    monotonic = ordered / max(1, len(ids) - 1)
    if monotonic < 0.9:
        return []
    return [_sig("SCAN-004", "Sequential resource walking", "medium",
                 [f"{len(set(ids))} distinct numeric IDs requested across {len(numeric)} requests",
                  f"{monotonic:.0%} of consecutive requests advanced by 1-3 — machine-driven walk"],
                 mitre="T1083 File and Directory Discovery",
                 recommendation="Confirm whether the endpoint is an API meant for bulk access; "
                                "add pagination rate limits or require auth.")]


RULES = [
    rule_automation_ua, rule_scan_paths, rule_web_exploit_payloads, rule_brute_force,
    rule_auth_success_after_failures, rule_error_rate_404, rule_path_enumeration,
    rule_sequential_ids, rule_high_rate, rule_fixed_interval, rule_no_assets,
    rule_missing_ua, rule_ua_rotation, rule_honeypot_hits,
]


# --------------------------------------------------------------------------- #
# Aggregation
# --------------------------------------------------------------------------- #
def build_profiles(records: list[LogRecord]) -> tuple[list[IpProfile], dict]:
    by_ip: dict[str, list[LogRecord]] = {}
    for r in records:
        by_ip.setdefault(r.ip, []).append(r)

    profiles: list[IpProfile] = []
    for ip, recs in by_ip.items():
        recs.sort(key=lambda r: r.ts)
        times = [r.ts for r in recs]
        span = (times[-1] - times[0]).total_seconds()
        status_hist = Counter(f"{r.status // 100}xx" for r in recs)
        methods = Counter(r.method for r in recs)
        uniq_paths = {r.path.split("?")[0] for r in recs}
        uas = sorted({r.user_agent for r in recs if r.user_agent})
        auth_fail = sum(1 for r in recs if r.status in (401, 403)
                        and any(a in _norm(r.path) for a in AUTH_PATHS))
        compromised = ""
        for r_ in recs:
            if r_.status == 200 and any(a in _norm(r_.path) for a in AUTH_PATHS):
                m = re.search(r"[?&](?:u|user|username|email)=([^&]+)", r_.path)
                compromised = unquote(m.group(1)) if m else "(unknown identity)"
                break

        signals: list[Signal] = []
        for rule in RULES:
            signals.extend(rule(recs))

        risk = min(100, sum(s.score for s in signals))
        if risk >= 60:
            verdict, conf = "malicious", min(0.98, 0.55 + risk / 250)
        elif risk >= 25:
            verdict, conf = "suspicious", 0.5 + (risk - 25) / 100
        else:
            verdict, conf = "benign", 0.6 + (25 - risk) / 60

        path_counts = Counter(r.path for r in recs)
        profiles.append(IpProfile(
            ip=ip,
            requests=len(recs),
            first_seen=times[0].isoformat(),
            last_seen=times[-1].isoformat(),
            span_seconds=round(span, 1),
            req_per_min_peak=round(_window_counts(times, 60), 1),
            unique_paths=len(uniq_paths),
            error_4xx=sum(1 for r in recs if 400 <= r.status < 500),
            status_histogram=dict(status_hist),
            methods=dict(methods),
            user_agents=uas[:6],
            top_paths=[f"{p} ×{n}" for p, n in path_counts.most_common(5)],
            auth_failures=auth_fail,
            compromised_identity=compromised,
            signals=signals,
            risk_score=risk,
            verdict=verdict,
            confidence=round(conf, 2),
        ))

    profiles.sort(key=lambda p: (-p.risk_score, -p.requests))

    flagged = [p for p in profiles if p.verdict != "benign"]
    fleet = {
        "ips_total": len(profiles),
        "ips_flagged": len(flagged),
        "ips_malicious": sum(1 for p in profiles if p.verdict == "malicious"),
        "requests_total": len(records),
        "requests_flagged": sum(p.requests for p in flagged),
        "signal_counts": _signal_counts(profiles),
    }
    return profiles, fleet


def _signal_counts(profiles: list[IpProfile]) -> dict[str, int]:
    c: Counter = Counter()
    for p in profiles:
        for s in p.signals:
            c[s.rule_id] += 1
    return dict(c.most_common())
