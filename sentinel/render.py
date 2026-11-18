"""Deterministic SOC-report renderer.

This is the floor of the system, not a fallback afterthought: with no LLM the
pipeline still produces a complete, accurate, handover-ready report. When an
LLM is available the ReportAgent writes the prose and this renderer is unused.
"""

from __future__ import annotations

from collections import Counter

SEV_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "⚪"}


def _pl(n: int, word: str, plural: str | None = None) -> str:
    """1 request / 2 requests — keeps generated prose from reading like a robot."""
    if n == 1:
        return f"1 {word}"
    return f"{n:,} {plural or word + 's'}"
PRIO_ICON = {"P1": "🚨", "P2": "🟠", "P3": "🟡", "P4": "⚪"}
VERDICT_TAG = {"malicious": "**MALICIOUS**", "suspicious": "_suspicious_", "benign": "benign"}


def _status_line(state: dict) -> str:
    ps = state.get("parse_stats", {})
    fs = state.get("fleet_stats", {})
    tr = ps.get("time_range", {})
    return (
        f"**Window:** `{tr.get('start')}` → `{tr.get('end')}` · "
        f"**Log lines:** {ps.get('lines_parsed', 0):,} parsed "
        f"({ps.get('lines_malformed', 0)} malformed, format `{ps.get('format')}`) · "
        f"**IPs:** {fs.get('ips_total', 0)} · **Flagged:** {fs.get('ips_flagged', 0)} "
        f"({fs.get('ips_malicious', 0)} malicious)"
    )


def _priority_table(escalations: list[dict]) -> str:
    if not escalations:
        return "_No IPs escalated this window._"
    rows = ["| Priority | IP | Verdict | Risk | Why |", "|---|---|---|---|---|"]
    for e in escalations:
        rows.append(
            f"| {PRIO_ICON.get(e['priority'], '')} {e['priority']} | `{e['ip']}` | "
            f"{VERDICT_TAG.get(e['verdict'], e['verdict'])} | {e.get('risk_score', '—')} | "
            f"{e.get('reason', '')[:120]} |"
        )
    return "\n".join(rows)


def _detail(profile: dict, analysis: dict) -> str:
    out = [f"### `{profile['ip']}` — {analysis.get('priority', '')} · risk {profile['risk_score']}/100 "
           f"· confidence {analysis.get('confidence', 0):.0%}", ""]
    out.append(analysis.get("narrative", "_no narrative_"))
    out.append("")
    if analysis.get("false_positive_check"):
        out.append(f"**False-positive check.** {analysis['false_positive_check']}")
        out.append("")
    out.append("| Rule | Severity | Evidence |")
    out.append("|---|---|---|")
    for s in profile["signals"]:
        ev = "<br>".join(x.replace("|", "\\|")[:180] for x in s["evidence"][:3])
        out.append(f"| `{s['rule_id']}` {s['title']} | {SEV_ICON.get(s['severity'],'')} {s['severity']} | {ev} |")
    out.append("")
    traffic = (f"{_pl(profile['requests'], 'request')} over {profile['span_seconds']:.0f}s · "
               f"peak {profile['req_per_min_peak']:.0f} req/min · "
               f"{_pl(profile['unique_paths'], 'unique path')} · {_pl(profile['error_4xx'], '4xx')} · "
               f"{_pl(profile['auth_failures'], 'auth failure')}")
    out.append(f"**Traffic:** {traffic}")
    if profile.get("compromised_identity"):
        out.append(f"**Identity at risk:** `{profile['compromised_identity']}` (successful auth after failures)")
    if analysis.get("attck"):
        out.append(f"**ATT&CK:** {', '.join(analysis['attck'])}")
    if analysis.get("next_steps"):
        out.append("**Next steps:**")
        out += [f"{i}. {s}" for i, s in enumerate(analysis["next_steps"], 1)]
    out.append("")
    return "\n".join(out)


def render_fallback_report(state: dict) -> str:
    ps = state.get("parse_stats", {})
    fs = state.get("fleet_stats", {})
    triage = state.get("triage", {})
    escs = state.get("escalations", [])
    analyses = {a["ip"]: a for a in state.get("analyses", [])}
    actions = state.get("actions", [])
    critic = state.get("critic")

    lines: list[str] = []
    lines.append("# Sentinel — SOC Triage Report")
    lines.append("")
    lines.append(_status_line(state))
    lines.append("")

    # ---- Exec summary ---------------------------------------------------- #
    lines.append("## Executive summary")
    lines.append("")
    malicious = [e for e in escs if e["verdict"] == "malicious"]
    p1 = [e for e in escs if e["priority"] == "P1"]
    if malicious:
        worst = malicious[0]
        lines.append(f"- **{len(malicious)} malicious IP(s)** confirmed; highest risk `{worst['ip']}` "
                     f"(risk {worst['risk_score']}/100) — {worst.get('reason','')[:160]}")
    else:
        lines.append("- **No malicious activity confirmed** in this window.")
    if p1:
        lines.append(f"- {len(p1)} P1 item(s) require immediate attention: "
                     + ", ".join(f"`{e['ip']}`" for e in p1))
    dismissed = triage.get("dismiss", [])
    if dismissed:
        lines.append(f"- {len(dismissed)} low-signal IP{'s' if len(dismissed) != 1 else ''} dismissed as benign "
                     f"automation (see Dismissed section) — no analyst time needed.")
    approved = [a for a in actions if a.get("approvals") == "approved"]
    deferred_n = len([a for a in actions if a.get("approvals") == "deferred"])
    gated_n = len([a for a in actions if a.get("gated")])
    lines.append(f"- Containment: {len(approved)} approved · {deferred_n} deferred · "
                 f"{gated_n} below the auto-action gate.")
    lines.append("")

    # ---- Priority queue -------------------------------------------------- #
    lines.append("## Priority queue")
    lines.append("")
    lines.append(_priority_table(escs))
    lines.append("")

    # ---- Details --------------------------------------------------------- #
    details = [e for e in escs if e["ip"] in analyses and e["priority"] in {"P1", "P2", "P3"}]
    lines.append("## Detailed findings")
    lines.append("")
    if not details:
        lines.append("_No findings to detail._")
        lines.append("")
    for e in details:
        profile = next((p for p in state["profiles"] if p["ip"] == e["ip"]), None)
        if profile:
            lines.append(_detail(profile, analyses[e["ip"]]))

    # ---- Dismissed ------------------------------------------------------- #
    lines.append("## False positives / dismissed")
    lines.append("")
    if dismissed:
        for d in dismissed:
            lines.append(f"- `{d['ip']}` — {d['reason']}")
    else:
        lines.append("_None dismissed._")
    lines.append("")

    # ---- Actions --------------------------------------------------------- #
    lines.append("## Response actions")
    lines.append("")
    if not actions:
        lines.append("_No response proposals._")
    for a in actions:
        badge = {"approved": "✅ approved", "deferred": "⏸ deferred", "pending": "⏳ pending"}.get(
            a.get("approvals"), "")
        if a.get("gated"):
            lines.append(f"- `{a['ip']}` — **gated** ({a['reason']})")
            continue
        lines.append(f"- `{a['ip']}` — {badge}")
        for act in a.get("proposed", []):
            lines.append(f"  - `{act['action']}` → {act['target']} ({act['urgency']}) — {act['rationale'][:160]}")
    lines.append("")

    # ---- Coverage -------------------------------------------------------- #
    lines.append("## Coverage gaps & limitations")
    lines.append("")
    if ps.get("lines_malformed"):
        lines.append(f"- {_pl(ps['lines_malformed'], 'log line')} failed to parse "
                     f"({ps['parse_rate']:.1%} parse rate) — evidence may be incomplete. "
                     f"Sample: `{ps['malformed_samples'][0][:120]}`")
    lines.append("- Detection is behavioural (rate, cadence, path and UA shape); "
                 "single-request attacks with a clean profile can be missed.")
    lines.append("- Geo/ASN reputation is not consulted; a residential IP behaving like a bot "
                 "is still flagged, which is intentional.")
    lines.append("- Response actions are dry-run plans only; enforcement lives in your edge layer.")
    lines.append("")

    # ---- Critic ---------------------------------------------------------- #
    if critic:
        lines.append("## Automated critic review")
        lines.append("")
        lines.append(f"_{critic.get('overall','')}_")
        lines.append("")
        for i in critic.get("issues", []):
            lines.append(f"- **[{i['severity'].upper()}]** {i['finding']} — _{i['fix']}_")
        lines.append("")

    # ---- Next shift ------------------------------------------------------ #
    lines.append("## Recommended next shift actions")
    lines.append("")
    nxt: list[str] = []
    for e in escs[:4]:
        a = analyses.get(e["ip"])
        if a and a.get("next_steps"):
            nxt.append(f"- `{e['ip']}` ({e['priority']}): {a['next_steps'][0]}")
    if any(a.get("approvals") == "deferred" for a in actions):
        nxt.append("- Re-review deferred containment proposals before the next traffic peak.")
    if ps.get("lines_malformed"):
        nxt.append("- Fix the log emitter producing malformed lines; blind spots compound.")
    if not nxt:
        nxt.append("- No outstanding items; continue routine monitoring.")
    lines += nxt
    lines.append("")

    # ---- Appendix -------------------------------------------------------- #
    sigs = fs.get("signal_counts", {})
    if sigs:
        lines.append("<details><summary>Rule hit distribution</summary>")
        lines.append("")
        lines.append("| Rule | IPs triggering |")
        lines.append("|---|---|")
        for rule_id, n in sorted(sigs.items(), key=lambda kv: -kv[1]):
            lines.append(f"| `{rule_id}` | {n} |")
        lines.append("")
        lines.append("</details>")
        lines.append("")

    lines.append("---")
    lines.append(f"*Generated by Sentinel · backend `{state.get('run_meta', {}).get('backend','?')}` · "
                 f"detection rules v1 · all containment actions are proposals until human approval.*")
    return "\n".join(lines)
