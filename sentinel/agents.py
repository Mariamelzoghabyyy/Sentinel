"""The agents.

Each agent has one job, a strict output contract, and a deterministic fallback.
The contract is enforced *after* the model responds, so a hallucinated or
malformed reply degrades to the fallback instead of corrupting the report.

  TriageAgent   – fleet-level: which IPs matter, in what order, and why
  AnalystAgent  – per-IP: narrative, false-positive check, ATT&CK mapping
  ResponderAgent– per-IP: pick containment actions (passed by a risk gate)
  ReportAgent   – weave everything into a SOC shift report
  CriticAgent   – adversarial self-review before the report ships
"""

from __future__ import annotations

import json
from typing import Any

from .llm import Backend, LLMError, extract_json

SEV_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def risk_to_priority(risk: int) -> str:
    """Priority is a monotone function of the calibrated aggregate risk score.

    This was originally `worst_rule_severity -> priority`, which meant a single
    honeypot hit (a 1-request event with no impact) escalated to P1, identical
    to a confirmed credential compromise. Aggregate risk already encodes how
    many signals agree and how strong each is; severity alone does not.
    """
    if risk >= 85:
        return "P1"
    if risk >= 60:
        return "P2"
    if risk >= 35:
        return "P3"
    return "P4"

ALLOWED_ACTIONS = {
    "block_ip", "rate_limit_ip", "tarpit_ip", "block_user_agent",
    "force_logout", "reset_credentials", "waf_virtual_patch",
    "open_ticket", "monitor",
}


def _call(backend: Backend, system: str, user: str, max_tokens: int = 1400) -> dict | None:
    try:
        raw = backend.complete(system, user, max_tokens=max_tokens)
    except LLMError as e:
        return {"_error": str(e)}
    return extract_json(raw)


def _worst_severity(signals: list[dict]) -> str:
    if not signals:
        return "low"
    return max((s["severity"] for s in signals), key=lambda s: SEV_ORDER.get(s, 0))


def _as_list(v: Any, limit: int = 6) -> list[str]:
    if not isinstance(v, list):
        return []
    return [str(x)[:300] for x in v][:limit]


# --------------------------------------------------------------------------- #
# Triage agent
# --------------------------------------------------------------------------- #
TRIAGE_SYS = """You are the triage lead in a Security Operations Centre.
You receive deterministic rule hits for every IP seen in a web-server log window.
Rules are trustworthy but can co-occur on innocent traffic (uptime monitors, search
crawlers, internal health checks). Your job: rank and decide which identities merit
analyst attention, and explicitly dismiss benign automation.

Return ONLY minified JSON, no prose, exactly this shape:
{"escalate":[{"ip":str,"priority":"P1|P2|P3|P4","verdict":"malicious|suspicious","reason":str}],
 "dismiss":[{"ip":str,"reason":str}],
 "summary":str}
Rules: at most 8 escalate entries. Never escalate an IP with risk_score < 20.
Dismissing an IP means a human should NOT spend time on it."""


class TriageAgent:
    name = "triage"

    def __init__(self, backend: Backend):
        self.backend = backend

    def run(self, profiles: list[dict], fleet: dict) -> dict:
        flagged = [p for p in profiles if p["verdict"] != "benign"]
        payload = [
            {
                "ip": p["ip"], "risk_score": p["risk_score"], "requests": p["requests"],
                "unique_paths": p["unique_paths"], "peak_rpm": p["req_per_min_peak"],
                "err4xx": p["error_4xx"], "auth_failures": p["auth_failures"],
                "signals": [f'{s["rule_id"]}/{s["severity"]}: {s["title"]}' for s in p["signals"]],
                "user_agents": p["user_agents"][:2],
            }
            for p in flagged[:25]
        ]
        user = (
            f"Window fleet stats: {json.dumps(fleet)}\n"
            f"Candidate IPs (rule-flagged): {json.dumps(payload, indent=None)}"
        )
        out = _call(self.backend, TRIAGE_SYS, user, max_tokens=1200)
        if out and "_error" not in out:
            validated = self._validate(out, flagged)
            if validated:
                validated["source"] = self.backend.name
                return validated
        return self._fallback(flagged, fleet, error=(out or {}).get("_error") if out else None)

    def _validate(self, out: dict, flagged: list[dict]) -> dict | None:
        by_ip = {p["ip"]: p for p in flagged}
        esc, dismissed, seen = [], [], set()
        for e in out.get("escalate") or []:
            if not isinstance(e, dict):
                continue
            ip = str(e.get("ip", "")).strip()
            if ip not in by_ip or ip in seen:
                continue                       # model invented an IP -> drop it
            seen.add(ip)
            recommended = risk_to_priority(by_ip[ip]["risk_score"])
            prio = str(e.get("priority", "")).upper()
            if prio not in {"P1", "P2", "P3", "P4"}:
                prio = recommended
            # Gate: a P1/P2 claim must be backed by either a malicious verdict or
            # a high risk score. The model may raise alarm only as far as evidence allows.
            # The model may raise urgency, but never above what the score supports.
            prof = by_ip[ip]
            order = ["P1", "P2", "P3", "P4"]
            if order.index(prio) < order.index(recommended):
                prio = recommended
            if prof["risk_score"] < 20:
                prio = "P4"
            esc.append({
                "ip": ip, "priority": prio,
                "verdict": by_ip[ip]["verdict"],
                "reason": str(e.get("reason", ""))[:400],
                "risk_score": by_ip[ip]["risk_score"],
            })
        for d in out.get("dismiss") or []:
            if isinstance(d, dict) and str(d.get("ip")) in by_ip:
                dismissed.append({"ip": str(d["ip"]), "reason": str(d.get("reason", ""))[:300]})
        if not esc:
            return None
        esc.sort(key=lambda e: (e["priority"], -e["risk_score"]))
        return {"escalate": esc, "dismiss": dismissed,
                "summary": str(out.get("summary", ""))[:600]}

    def _fallback(self, flagged: list[dict], fleet: dict, error: str | None = None) -> dict:
        esc = []
        for p in flagged:
            top = sorted(p["signals"], key=lambda s: -SEV_ORDER.get(s["severity"], 0))[:2]
            esc.append({
                "ip": p["ip"],
                "priority": risk_to_priority(p["risk_score"]),
                "verdict": p["verdict"],
                "risk_score": p["risk_score"],
                "reason": "; ".join(f'{s["rule_id"]} {s["title"]}' for s in top) or "rule hits",
            })
        esc.sort(key=lambda e: (e["priority"], -e["risk_score"]))
        dismissed = []
        for p in flagged:
            if p["risk_score"] < 25:
                dismissed.append({"ip": p["ip"],
                                  "reason": "low risk score; single weak signal, no hostile payloads"})
        res = {"escalate": esc[:8], "dismiss": dismissed,
               "summary": (f"{len(flagged)} of {fleet['ips_total']} IPs produced rule hits; "
                           f"{len(esc)} escalated by risk score."),
               "source": "heuristic"}
        if error:
            res["llm_error"] = error[:300]
        return res


# --------------------------------------------------------------------------- #
# Analyst agent
# --------------------------------------------------------------------------- #
ANALYST_SYS = """You are a senior SOC analyst writing the investigation note for ONE source IP.
You are given: the raw rule signals with evidence, and a bundle of representative raw
log lines. Your job is judgement, not repetition.

Return ONLY minified JSON:
{"narrative":str,            // 3-5 sentences: what the actor did, in what order, what it implies
 "false_positive_check":str, // strongest innocent explanation AND why it is/ isn't sufficient
 "attck":["T1xxx ..."],      // techniques actually supported by evidence
 "confidence":0.0-1.0,
 "next_steps":["..."]}       // concrete verification steps for a human

Hard rules: cite only evidence present in the input. Do not invent CVEs, hostnames,
or outcomes. If evidence is thin, say so and lower confidence. Never claim data
exfiltration you cannot see in the logs (size anomalies are hints, not proof)."""


class AnalystAgent:
    name = "analyst"

    def __init__(self, backend: Backend):
        self.backend = backend

    def run(self, profile: dict, raw_samples: list[dict], triage_reason: str) -> dict:
        slim_signals = [
            {"rule": s["rule_id"], "title": s["title"], "severity": s["severity"],
             "evidence": s["evidence"], "mitre": s["mitre"]}
            for s in profile["signals"]
        ]
        samples = [
            f'{r["ts"]} {r["method"]} {r["path"][:120]} -> {r["status"]} '
            f'({r["size"]}B) UA="{r["user_agent"][:80]}"'
            for r in raw_samples[:25]
        ]
        user = (
            f"IP: {profile['ip']}\n"
            f"Traffic: {profile['requests']} req in {profile['span_seconds']}s, "
            f"peak {profile['req_per_min_peak']} req/min, {profile['unique_paths']} unique paths, "
            f"{profile['error_4xx']} 4xx, {profile['auth_failures']} auth failures, "
            f"status mix {profile['status_histogram']}\n"
            f"Top paths: {profile['top_paths']}\n"
            f"UAs: {profile['user_agents']}\n"
            f"Identity seen on successful auth: {profile.get('compromised_identity') or 'n/a'}\n"
            f"Deterministic signals: {json.dumps(slim_signals)}\n"
            f"Triage note: {triage_reason}\n"
            f"Representative raw lines:\n" + "\n".join(samples)
        )
        out = _call(self.backend, ANALYST_SYS, user, max_tokens=1400)
        if out and "_error" not in out and isinstance(out.get("narrative"), str):
            conf = out.get("confidence", profile["confidence"])
            try:
                conf = min(0.99, max(0.0, float(conf)))
            except (TypeError, ValueError):
                conf = profile["confidence"]
            return {
                "narrative": out["narrative"][:2000],
                "false_positive_check": str(out.get("false_positive_check", ""))[:800],
                "attck": _as_list(out.get("attck"), 5),
                "confidence": round(conf, 2),
                "next_steps": _as_list(out.get("next_steps"), 5),
                "source": self.backend.name,
            }
        return self._fallback(profile, error=(out or {}).get("_error") if out else None)

    def _fallback(self, p: dict, error: str | None = None) -> dict:
        rules = sorted(p["signals"], key=lambda s: -SEV_ORDER.get(s["severity"], 0))
        steps_by_rule = {
            "AUTH-001": "Pull IdP logs for the auth endpoint and confirm no account was locked/enabled unexpectedly.",
            "AUTH-002": "Revoke sessions for the affected account and force a credential reset; review post-login activity.",
            "EXPL-001": "Confirm the app rejected traversal input server-side; check for any 2xx on traversal payloads.",
            "EXPL-002": "Verify parameterised queries on the targeted endpoint; inspect DB error/alerting for injection artefacts.",
            "EXPL-003": "Check reflected/stored rendering of the payload parameter; confirm CSP is enforced.",
            "EXPL-004": "Confirm no shell metacharacters reach an exec sink; review process-audit logs on the host.",
            "SCAN-001": "Confirm WAF virtual-patch is covering the enumerated paths.",
            "SCAN-002": "Confirm catch-all 404 handling is cheap and nothing sensitive returns 200.",
            "SCAN-003": "Check for content exposure behind the enumerated paths (backups, configs).",
            "HONEY-001": "Honeypot hit is a high-fidelity bot indicator — safe to feed the IP into edge blocklists.",
            "RATE-001": "Verify rate limiting at the edge and whether the burst degraded latency for others.",
            "BOT-005": "UA rotation suggests evasion tooling; treat any single UA as untrustworthy for this IP.",
        }
        steps: list[str] = []
        for s in rules:
            step = steps_by_rule.get(s["rule_id"])
            if step and step not in steps:
                steps.append(step)
        if not steps:
            steps = ["No hostile indicators found; retain as baseline traffic."]

        order = ", ".join(f'{s["rule_id"]} ({s["title"]})' for s in rules[:3]) or "no rule hits"
        narrative = (
            f"{p['ip']} made {'1 request' if p['requests'] == 1 else f'{p['requests']} requests'} "
            f"in {p['span_seconds']:.0f}s ({p['unique_paths']} unique "
            f"{'path' if p['unique_paths'] == 1 else 'paths'}, peak {p['req_per_min_peak']} req/min). "
            f"Deterministic detection fired on: {order}. "
            f"Raw evidence includes {rules[0]['evidence'][0] if rules and rules[0]['evidence'] else 'no notable payloads'}. "
            f"The combination of {_worst_severity(p['signals'])}-severity signals yields risk score "
            f"{p['risk_score']}/100 → {p['verdict']}."
        )
        fp = (
            "Plausible innocents: a monitoring/uptime probe or a sanctioned crawler. "
            "That explanation is insufficient here because "
            + ("hostile payloads were observed in request paths, which no monitor sends."
               if any(s["rule_id"].startswith("EXPL") for s in p["signals"])
               else "the request cadence and path selection match tooled enumeration rather than a curated probe."
               if p["unique_paths"] > 20
               else "the UA/cadence pair is machine-regular and paths target sensitive locations.")
        )
        attck = [s["mitre"] for s in rules if s["mitre"]]
        return {
            "narrative": narrative,
            "false_positive_check": fp,
            "attck": list(dict.fromkeys(attck))[:5],
            "confidence": p["confidence"],
            "next_steps": steps,
            "source": "heuristic",
            **({"llm_error": error[:300]} if error else {}),
        }


# --------------------------------------------------------------------------- #
# Responder agent (behind a deterministic risk gate + human approval)
# --------------------------------------------------------------------------- #
RESPONDER_SYS = """You are an incident responder. Given a confirmed hostile IP profile, propose
containment actions. Prefer proportionate, reversible actions. Escalate to credential
actions only when auth evidence exists.

Return ONLY minified JSON:
{"actions":[{"action":str,"target":str,"rationale":str,"reversible":bool,"urgency":"immediate|hours|next-shift"}]}
Allowed action values: block_ip, rate_limit_ip, tarpit_ip, block_user_agent,
force_logout, reset_credentials, waf_virtual_patch, open_ticket, monitor."""


class ResponderAgent:
    name = "responder"

    def __init__(self, backend: Backend):
        self.backend = backend

    def gate(self, profile: dict) -> bool:
        """Deterministic gate: nothing is actioned automatically below this bar."""
        return profile["verdict"] == "malicious" and profile["risk_score"] >= 60

    def run(self, profile: dict, analysis: dict) -> dict:
        if not self.gate(profile):
            return {
                "ip": profile["ip"],
                "gated": True,
                "reason": f"risk_score {profile['risk_score']} / verdict {profile['verdict']} "
                          f"is below the auto-action gate (needs malicious + ≥60).",
                "proposed": [{"action": "monitor", "target": profile["ip"],
                              "rationale": "Watch for further signals; no containment warranted yet.",
                              "reversible": True, "urgency": "next-shift"}],
            }
        user = (
            f"IP {profile['ip']} | risk {profile['risk_score']} | verdict {profile['verdict']}\n"
            f"Signals: {json.dumps([{ 'rule': s['rule_id'], 'sev': s['severity'], 'ev': s['evidence'][:2]} for s in profile['signals']])}\n"
            f"Analyst: {analysis.get('narrative','')}\n"
            f"Auth failures: {profile['auth_failures']} | UA(s): {profile['user_agents'][:3]}"
        )
        out = _call(self.backend, RESPONDER_SYS, user, max_tokens=900)
        proposed = self._validate(out, profile) if out and "_error" not in out else None
        if proposed is None:
            proposed = self._fallback(profile)
            src = "heuristic"
        else:
            src = self.backend.name
        return {"ip": profile["ip"], "gated": False, "source": src, "proposed": proposed}

    def _validate(self, out: dict, profile: dict) -> list[dict] | None:
        actions = []
        for a in out.get("actions") or []:
            if not isinstance(a, dict):
                continue
            act = str(a.get("action", "")).strip().lower()
            if act not in ALLOWED_ACTIONS:
                continue                                  # model tried an unapproved action
            if act in {"force_logout", "reset_credentials"} and profile["auth_failures"] == 0:
                continue                                  # contract: auth evidence required
            actions.append({
                "action": act,
                "target": profile["ip"],
                "rationale": str(a.get("rationale", ""))[:300],
                "reversible": bool(a.get("reversible", True)),
                "urgency": a.get("urgency") if a.get("urgency") in {"immediate", "hours", "next-shift"} else "hours",
            })
        return actions[:6] or None

    def _fallback(self, p: dict) -> list[dict]:
        rules = {s["rule_id"] for s in p["signals"]}
        acts = [{"action": "block_ip", "target": p["ip"],
                 "rationale": f"Risk {p['risk_score']}/100 with {', '.join(sorted(rules)[:3])}.",
                 "reversible": True, "urgency": "immediate"}]
        if "RATE-001" in rules or "SCAN-002" in rules:
            acts.append({"action": "rate_limit_ip", "target": p["ip"],
                         "rationale": "Volumetric/4xx burst — rate limit absorbs the flood cheaply.",
                         "reversible": True, "urgency": "immediate"})
        if any(r.startswith("EXPL") for r in rules):
            acts.append({"action": "waf_virtual_patch", "target": p["ip"],
                         "rationale": "Hostile payload class observed; virtual-patch blocks the pattern fleet-wide, not just this IP.",
                         "reversible": True, "urgency": "immediate"})
        if "AUTH-002" in rules:
            who = p.get("compromised_identity") or "(unknown identity)"
            acts.append({"action": "force_logout", "target": who,
                         "rationale": "Successful auth after failure burst — session may be attacker-controlled.",
                         "reversible": True, "urgency": "immediate"})
            acts.append({"action": "reset_credentials", "target": who,
                         "rationale": "Same evidence; rotate credentials after logout.",
                         "reversible": True, "urgency": "immediate"})
        if "HONEY-001" in rules:
            acts.append({"action": "tarpit_ip", "target": p["ip"],
                         "rationale": "Honeypot grader; tarpitting wastes attacker time at no cost.",
                         "reversible": True, "urgency": "hours"})
        acts.append({"action": "open_ticket", "target": "SOC queue",
                     "rationale": "Track containment and follow-up verification.",
                     "reversible": True, "urgency": "hours"})
        return acts


# --------------------------------------------------------------------------- #
# Report agent
# --------------------------------------------------------------------------- #
REPORT_SYS = """You are writing the end-of-window SOC report for a shift handover.
Audience: the oncoming analyst who has 60 seconds. Be dense, specific, and
actionable; zero filler. Use only the supplied findings.

Structure (markdown, no code fences around the whole document):
## Executive summary   (3-4 bullets, lead with worst thing that happened)
## Priority queue      (table: IP | P-level | verdict | risk | one-line why)
## Detailed findings   (per P1/P2 IP: what happened, evidence, ATT&CK, confidence, next step)
## False positives / dismissed
## Coverage gaps & limitations
## Recommended next shift actions

Never invent IOCs, CVEs, or exfiltrated data. Flag uncertainty explicitly."""


class ReportAgent:
    name = "reporter"

    def __init__(self, backend: Backend):
        self.backend = backend

    def run(self, ctx: dict) -> str | None:
        """ctx is the trimmed bundle of everything the report needs."""
        try:
            raw = self.backend.complete(REPORT_SYS, json.dumps(ctx, indent=None)[:24000], max_tokens=3000)
        except LLMError:
            return None
        if not raw or len(raw.strip()) < 200:
            return None
        return raw.strip()


# --------------------------------------------------------------------------- #
# Critic agent — adversarial review of the finished analysis
# --------------------------------------------------------------------------- #
CRITIC_SYS = """You are a skeptical reviewing analyst. Your job is to catch errors before the
report reaches the CISO: unsupported claims, over-confidence, missed benign explanations,
priority inflation, and anything an attacker could exploit in our process.

Return ONLY minified JSON:
{"issues":[{"severity":"high|medium|low","finding":str,"fix":str}],
 "overall":str, // one sentence
 "ship":true|false}  // false only for high-severity problems"""


class CriticAgent:
    name = "critic"

    def __init__(self, backend: Backend):
        self.backend = backend

    def run(self, ctx: dict, triage: dict, analyses: list[dict]) -> dict:
        user = json.dumps({
            "triage": triage,
            "analyses": [{k: a[k] for k in ("ip", "narrative", "confidence") if k in a} for a in analyses],
            "window": ctx.get("window"),
        })[:16000]
        out = _call(self.backend, CRITIC_SYS, user, max_tokens=900)
        if out and "_error" not in out and isinstance(out.get("issues"), list):
            issues = [
                {"severity": i.get("severity", "low"), "finding": str(i.get("finding", ""))[:400],
                 "fix": str(i.get("fix", ""))[:400]}
                for i in out["issues"] if isinstance(i, dict)
            ][:8]
            return {"issues": issues, "overall": str(out.get("overall", ""))[:400],
                    "ship": bool(out.get("ship", True)), "source": self.backend.name}
        return self._fallback(triage, analyses)

    def _fallback(self, triage: dict, analyses: list[dict]) -> dict:
        issues = []
        for a in analyses:
            if a.get("confidence", 1) >= 0.95 and a.get("verdict") != "malicious":
                issues.append({"severity": "low",
                               "finding": f"{a['ip']} confidence {a['confidence']} but verdict is not malicious.",
                               "fix": "Re-check whether signals justify the stated confidence."})
        p1s = [e for e in triage.get("escalate", []) if e.get("priority") == "P1"]
        if len(p1s) > 3:
            issues.append({"severity": "medium",
                           "finding": f"{len(p1s)} simultaneous P1s is likely priority inflation.",
                           "fix": "Confirm each P1 has an exploit-success or compromise indicator, not just scanning."})
        if not issues:
            issues.append({"severity": "low", "finding": "Deterministic cross-check found no inconsistencies.",
                           "fix": "None required."})
        return {"issues": issues, "overall": "Heuristic consistency review only; no model available.",
                "ship": not any(i["severity"] == "high" for i in issues), "source": "heuristic"}


# --------------------------------------------------------------------------- #
# Reporter helper: assemble the report from validated pieces
# --------------------------------------------------------------------------- #
def build_report_context(state: dict) -> dict:
    return {
        "window": state["parse_stats"]["time_range"],
        "fleet": state["fleet_stats"],
        "triage": state["triage"],
        "analyses": state["analyses"],
        "actions": state["actions"],
        "critic": state.get("critic"),
        "parse_stats": {k: state["parse_stats"][k] for k in
                        ("format", "lines_total", "lines_parsed", "lines_malformed", "parse_rate")},
    }
