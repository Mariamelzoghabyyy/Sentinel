"""LLM-as-judge, in two distinct roles that answer different questions.

ROLE 1 — OUTCOME JUDGE ("was this call right?")
    Judges the pipeline's *decision* for one IP against a deliberately
    judge-blind evidence bundle (raw log lines + numeric facts, with the
    rules' own rule IDs and verdicts stripped out). Blind because otherwise
    the judge just agrees with the system it is grading, which measures
    nothing.

ROLE 2 — REPORT JUDGE ("is this report good?")
    Grades the generated SOC report on faithfulness, prioritisation,
    actionability, and calibrated uncertainty. This catches the failure mode
    rules-based tests cannot: a report that is grammatically perfect and
    factually wrong.

Design rules, learned the hard way from published LLM-judge failures:
  * Structured JSON + validation, same as every other agent.
  * Binary/categorical verdicts where possible; scored scales (1-5) drift.
  * Ties go to the system (benefit of the doubt) — a judge that can't decide
    should not manufacture a failure.
  * The judge never sees the answer key. A judge that scores 1.00 agreement
    with ground truth is a judge that has been shown the ground truth.
  * Availability is measured: `agreement()` reports kappa, not just "yes".
"""

from __future__ import annotations

import json
import re
from collections import Counter
from typing import Any

from .llm import Backend, LLMError, extract_json

FORBIDDEN_LEAKS = ("rule_id", "SCAN-", "BOT-", "EXPL-", "AUTH-", "HONEY-", "RATE-",
                   "risk_score", "verdict")


# --------------------------------------------------------------------------- #
# Role 1: outcome judge
# --------------------------------------------------------------------------- #
OUTCOME_SYS = """You are an independent senior SOC analyst reviewing another analyst's call
on ONE source IP. You are given only raw evidence: request lines and traffic statistics.
You are NOT told what any automated tool concluded, and you must not speculate about it.

Decide whether this IP should be treated as hostile.

Return ONLY minified JSON:
{"verdict":"malicious|suspicious|benign",
 "confidence":0.0-1.0,
 "reasoning":str,        // 2-3 sentences citing specific observed evidence
 "key_evidence":[str],   // up to 3 concrete observations that drove the call
 "would_contain":bool}   // would you block/contain this IP today?

Calibration rules:
- "malicious" requires evidence of hostile INTENT (exploit payloads, credential
  attack, tooling that cannot be benign) or demonstrated IMPACT. Volume alone
  is not intent.
- "suspicious" is for tooled/abusive automation without hostile intent proven.
- "benign" covers real users, sanctioned crawlers, monitors, CI jobs, and
  first-party API clients.
- A known-benign crawler or monitor is benign even if it is fast or repetitive.
- If evidence is genuinely ambiguous, say so and lower confidence."""


class OutcomeJudge:
    name = "outcome_judge"

    def __init__(self, backend: Backend):
        self.backend = backend

    def available(self) -> bool:
        return self.backend.name != "local"

    # -- evidence bundle ---------------------------------------------------- #
    @staticmethod
    def blind_bundle(profile: dict, raw_lines: list[str], max_lines: int = 40) -> dict:
        """Strip everything that reveals the rules' opinion.

        This is the crux of a useful judge: if the bundle contains rule IDs or
        a risk score, the judge is doing autocomplete, not review.
        """
        stats = {
            "requests": profile.get("requests"),
            "duration_seconds": profile.get("span_seconds"),
            "peak_requests_per_minute": profile.get("req_per_min_peak"),
            "unique_paths": profile.get("unique_paths"),
            "error_4xx": profile.get("error_4xx"),
            "auth_failures": profile.get("auth_failures"),
            "status_mix": profile.get("status_histogram"),
            "methods": profile.get("methods"),
            "user_agents": profile.get("user_agents", [])[:4],
            "top_paths": profile.get("top_paths", [])[:5],
        }
        # Defence in depth: scrub any leaked rule identifiers from the text.
        clean_lines = []
        for ln in raw_lines[:max_lines]:
            for tok in FORBIDDEN_LEAKS:
                ln = ln.replace(tok, "[redacted]")
            clean_lines.append(ln)
        return {"ip": profile.get("ip"), "traffic_statistics": stats,
                "raw_request_lines": clean_lines}

    def judge(self, profile: dict, raw_lines: list[str]) -> dict:
        if not self.available():
            return self._fallback(profile)
        bundle = self.blind_bundle(profile, raw_lines)
        try:
            raw = self.backend.complete(
                OUTCOME_SYS, "Evidence bundle:\n" + json.dumps(bundle, indent=None)[:14000],
                max_tokens=900,
            )
        except LLMError as e:
            return {**self._fallback(profile), "error": str(e)[:200]}
        out = extract_json(raw)
        if not out or not isinstance(out.get("verdict"), str):
            return {**self._fallback(profile), "error": "unparseable judge response"}
        verdict = out["verdict"].strip().lower()
        if verdict not in {"malicious", "suspicious", "benign"}:
            return {**self._fallback(profile), "error": f"invalid verdict {verdict!r}"}
        try:
            conf = min(1.0, max(0.0, float(out.get("confidence", 0.5))))
        except (TypeError, ValueError):
            conf = 0.5
        return {
            "ip": profile.get("ip"),
            "verdict": verdict,
            "confidence": round(conf, 2),
            "reasoning": str(out.get("reasoning", ""))[:700],
            "key_evidence": [str(x)[:200] for x in (out.get("key_evidence") or [])][:3],
            "would_contain": bool(out.get("would_contain", verdict == "malicious")),
            "source": self.backend.name,
        }

    def _fallback(self, profile: dict) -> dict:
        """No model available: the judge abstains rather than faking a verdict.

        An abstaining judge is honest; a judge that silently copies the system's
        own verdict would report 100% agreement and mean nothing.
        """
        return {
            "ip": profile.get("ip"),
            "verdict": None,
            "confidence": 0.0,
            "reasoning": "ABSTAIN — no LLM backend configured; judge cannot form an opinion.",
            "key_evidence": [],
            "would_contain": None,
            "source": "abstain",
        }


# --------------------------------------------------------------------------- #
# Role 2: report judge
# --------------------------------------------------------------------------- #
REPORT_SYS = """You are a SOC shift lead reviewing a triage report before it goes to the CISO.
You have the report AND a compact ground-truth digest of what the rules actually found.

Grade it. Return ONLY minified JSON:
{"faithfulness":1-5,      // every claim traceable to the digest? 5=fully, 1=fabrications
 "prioritisation":1-5,    // are the worst things at the top? 5=correct ordering
 "actionability":1-5,     // could an on-call engineer act on this without asking questions?
 "calibration":1-5,       // does confidence match evidence? 5=appropriately humble
 "fabrications":[str],    // any claim NOT supported by the digest (empty list if none)
 "overall":1-5,
 "verdict":"ship|revise|reject",
 "top_issue":str}

Be strict on faithfulness: a plausible-sounding sentence with no support in the
digest counts as a fabrication. Do not reward length. Do not reward confidence."""


class ReportJudge:
    name = "report_judge"

    def __init__(self, backend: Backend):
        self.backend = backend

    def available(self) -> bool:
        return self.backend.name != "local"

    @staticmethod
    def digest(state: dict) -> dict:
        """Ground truth for faithfulness checking: what did the rules actually find?"""
        return {
            "window": state.get("parse_stats", {}).get("time_range"),
            "fleet": state.get("fleet_stats"),
            "escalations": [
                {k: e.get(k) for k in ("ip", "priority", "verdict", "risk_score")}
                for e in state.get("escalations", [])
            ],
            "signals_by_ip": {
                p["ip"]: [{"rule": s["rule_id"], "title": s["title"],
                           "evidence": s["evidence"][:2]}
                          for s in p.get("signals", [])]
                for p in state.get("profiles", []) if p.get("signals")
            },
            "approved_actions": [
                {"ip": a["ip"], "actions": [x["action"] for x in a.get("proposed", [])]}
                for a in state.get("actions", []) if a.get("approvals") == "approved"
            ],
        }

    def judge(self, report_md: str, state: dict) -> dict:
        if not self.available():
            return self._fallback()
        payload = json.dumps({
            "report_markdown": report_md[:18000],
            "ground_truth_digest": self.digest(state),
        })
        try:
            raw = self.backend.complete(REPORT_SYS, payload, max_tokens=1100)
        except LLMError as e:
            return {**self._fallback(), "error": str(e)[:200]}
        out = extract_json(raw)
        if not out:
            return {**self._fallback(), "error": "unparseable judge response"}

        def score(key: str) -> int | None:
            try:
                return max(1, min(5, int(out.get(key))))
            except (TypeError, ValueError):
                return None

        scores = {k: score(k) for k in ("faithfulness", "prioritisation",
                                        "actionability", "calibration", "overall")}
        if scores["overall"] is None:
            return {**self._fallback(), "error": "judge omitted overall score"}
        verdict = str(out.get("verdict", "")).lower()
        if verdict not in {"ship", "revise", "reject"}:
            verdict = "revise" if scores["overall"] < 4 else "ship"
        return {
            **scores,
            "fabrications": [str(x)[:300] for x in (out.get("fabrications") or [])][:8],
            "verdict": verdict,
            "top_issue": str(out.get("top_issue", ""))[:400],
            "source": self.backend.name,
        }

    def _fallback(self) -> dict:
        return {
            "faithfulness": None, "prioritisation": None, "actionability": None,
            "calibration": None, "overall": None, "fabrications": [],
            "verdict": "unjudged",
            "top_issue": "ABSTAIN — no LLM backend configured.",
            "source": "abstain",
        }


# --------------------------------------------------------------------------- #
# Reliability math — is the judge trustworthy at all?
# --------------------------------------------------------------------------- #
def cohens_kappa(a: list, b: list, categories: list[str]) -> dict:
    """Cohen's kappa between judge and ground truth.

    Raw agreement is a vanity metric: on a 60%-benign dataset, a judge that
    always says "benign" scores 60% agreement and 0 kappa. Report both.
    """
    if len(a) != len(b) or not a:
        return {"kappa": None, "agreement": None, "n": 0}
    n = len(a)
    agreement = sum(1 for x, y in zip(a, b) if x == y) / n
    po = agreement
    pe = sum((Counter(a)[c] / n) * (Counter(b)[c] / n) for c in categories)
    kappa = (po - pe) / (1 - pe) if pe < 1 else 1.0
    return {"kappa": round(kappa, 3), "agreement": round(agreement, 3), "n": n}


KAPPA_GUIDE = [
    (0.81, "almost perfect"),
    (0.61, "substantial"),
    (0.41, "moderate"),
    (0.21, "fair"),
    (0.00, "slight"),
]


def interpret_kappa(k: float | None) -> str:
    if k is None:
        return "not measured"
    for threshold, label in KAPPA_GUIDE:
        if k >= threshold:
            return label
    return "poor (worse than chance)"
