#!/usr/bin/env python3
"""Judge evaluation: does the LLM judge agree with human labels, and with itself?

Reports three numbers that matter:
  1. agreement + Cohen's kappa vs ground truth  (is the judge calibrated?)
  2. containment confusion                       (safety-critical: FPs vs FNs)
  3. self-consistency                            (same case, N runs — is it stable?)

    python3 benchmark/judge_eval.py                     # auto-detect backend
    python3 benchmark/judge_eval.py --backend groq
    python3 benchmark/judge_eval.py --report reports/access_report.md
    python3 benchmark/judge_eval.py --repeat 3          # self-consistency

With no backend configured, the judge ABSTAINS and this prints
"not measured" rather than inventing a score.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from benchmark.cases import CASES
from benchmark.evaluate import run_case
from sentinel.graph import Sentinel
from sentinel.judge import ReportJudge, OutcomeJudge, cohens_kappa, interpret_kappa
from sentinel.llm import get_backend


def _raw_lines(case, limit=40):
    return case.lines[:limit]


def run_outcome_eval(backend, repeat: int = 1) -> dict:
    judge = OutcomeJudge(backend)
    label_map = {"malicious": "malicious", "suspicious": "suspicious", "benign": "benign"}
    rows = []

    for case in CASES:
        profile, _ = run_case(case)
        if profile is None:
            continue
        p = profile.to_dict()
        runs = [judge.judge(p, _raw_lines(case)) for _ in range(repeat)]
        first = runs[0]
        rows.append({
            "case": case.name,
            "truth": case.label,
            "system": p["verdict"],
            "judge": first["verdict"],
            "judge_confidence": first["confidence"],
            "reasoning": first["reasoning"],
            "would_contain": first["would_contain"],
            "hard": case.hard,
            "abstained": first["verdict"] is None,
            "self_consistent": len({r["verdict"] for r in runs}) == 1,
            "runs": [r["verdict"] for r in runs],
        })

    answered = [r for r in rows if not r["abstained"]]
    if not answered:
        return {"measured": False, "abstained": len(rows), "n": len(rows),
                "reason": "no LLM backend — judge abstained on every case",
                "rows": rows}

    cats = ["malicious", "suspicious", "benign"]
    kt = cohens_kappa([r["judge"] for r in answered], [r["truth"] for r in answered], cats)
    ks = cohens_kappa([r["judge"] for r in answered], [r["system"] for r in answered], cats)

    # Containment view: would the judge block? vs should-it-be-blocked?
    should = [r["truth"] == "malicious" for r in answered]
    did = [bool(r["would_contain"]) for r in answered]
    tp = sum(1 for s, d in zip(should, did) if s and d)
    fp = sum(1 for s, d in zip(should, did) if not s and d)
    tn = sum(1 for s, d in zip(should, did) if not s and not d)
    fn = sum(1 for s, d in zip(should, did) if s and not d)

    return {
        "measured": True,
        "n": len(rows),
        "answered": len(answered),
        "abstained": len(rows) - len(answered),
        "kappa_vs_truth": kt,
        "kappa_interpretation": interpret_kappa(kt["kappa"]),
        "kappa_vs_system": ks,
        "agreement_with_system": ks["agreement"],
        "containment": {
            "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "precision": round(tp / (tp + fp), 3) if tp + fp else None,
            "recall": round(tp / (tp + fn), 3) if tp + fn else None,
        },
        "self_consistency": round(sum(1 for r in answered if r["self_consistent"]) / len(answered), 3),
        "disagreements": [
            {"case": r["case"], "truth": r["truth"], "system": r["system"],
             "judge": r["judge"], "why": r["reasoning"][:200]}
            for r in answered if r["judge"] != r["truth"]
        ],
        "rows": rows,
        "backend": backend.name,
    }


def run_report_eval(backend, logfile: str) -> dict:
    judge = ReportJudge(backend)
    pipe = Sentinel(backend=get_backend())
    run = pipe.run(logfile, thread_id="judge-report", auto_approve=True)
    state = run["state"]
    verdict = judge.judge(run["report"], state)
    return {"measured": verdict.get("overall") is not None, "verdict": verdict,
            "report_chars": len(run["report"]), "logfile": logfile}


def print_outcome(res: dict) -> None:
    print("=" * 78)
    print("  LLM-AS-JUDGE — OUTCOME EVALUATION")
    print("=" * 78)
    if not res["measured"]:
        print(f"\n  NOT MEASURED — {res['reason']}")
        print(f"  {res['abstained']}/{res['n']} cases abstained.")
        print("\n  This is the correct behaviour: a judge with no model must not")
        print("  fabricate verdicts, and copying the system's own answer would")
        print("  report 100% agreement while measuring nothing.")
        print("=" * 78)
        return

    kt, ks = res["kappa_vs_truth"], res["kappa_vs_system"]
    print(f"  backend: {res['backend']}   answered {res['answered']}/{res['n']} "
          f"(abstained {res['abstained']})")
    print(f"\n  vs GROUND TRUTH : agreement {kt['agreement']:.1%}  "
          f"kappa {kt['kappa']:.3f} ({res['kappa_interpretation']})")
    print(f"  vs SYSTEM       : agreement {ks['agreement']:.1%}  kappa {ks['kappa']:.3f}")
    c = res["containment"]
    print(f"\n  containment: tp={c['tp']} fp={c['fp']} tn={c['tn']} fn={c['fn']}"
          f"  precision={c['precision']} recall={c['recall']}")
    print(f"  self-consistency: {res['self_consistency']:.0%}")

    if ks["kappa"] > 0.95:
        print("\n  ⚠️  Judge agrees with the system almost perfectly. Verify the")
        print("     evidence bundle is actually blind before trusting this.")
    if res["disagreements"]:
        print("\n  DISAGREEMENTS (judge vs human label)")
        for d in res["disagreements"]:
            print(f"    • {d['case']:32s} truth={d['truth']:10s} "
                  f"system={d['system']:10s} judge={d['judge']}")
            print(f"      judge said: {d['why'][:150]}")
    print("=" * 78)


def print_report(res: dict) -> None:
    print("\n" + "=" * 78)
    print("  LLM-AS-JUDGE — REPORT QUALITY")
    print("=" * 78)
    v = res["verdict"]
    if not res["measured"]:
        print(f"\n  NOT MEASURED — {v.get('top_issue')}")
        print("=" * 78)
        return
    print(f"  {res['logfile']}  ({res['report_chars']:,} chars)")
    for k in ("faithfulness", "prioritisation", "actionability", "calibration", "overall"):
        val = v.get(k)
        stars = "★" * val + "☆" * (5 - val) if val else "—"
        print(f"    {k:16s} {stars}  ({val}/5)")
    print(f"\n  verdict: {v['verdict'].upper()}")
    if v.get("top_issue"):
        print(f"  top issue: {v['top_issue'][:300]}")
    if v.get("fabrications"):
        print("\n  FABRICATED CLAIMS:")
        for f in v["fabrications"]:
            print(f"    ✗ {f[:200]}")
    else:
        print("\n  no fabrications detected")
    print("=" * 78)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--backend", help="groq|openai|anthropic|ollama|local")
    ap.add_argument("--repeat", type=int, default=1, help="runs per case (self-consistency)")
    ap.add_argument("--report", help="also judge a report from this log file")
    ap.add_argument("--json", help="write full results here")
    args = ap.parse_args()

    if args.backend:
        import os
        os.environ["SENTINEL_BACKEND"] = args.backend
    backend = get_backend()
    print(f"judge backend: {backend.name} ({backend.model})\n")

    outcome = run_outcome_eval(backend, repeat=args.repeat)
    print_outcome(outcome)

    out = {"outcome": outcome}
    if args.report:
        rep = run_report_eval(backend, args.report)
        print_report(rep)
        out["report"] = rep

    if args.json:
        Path(args.json).write_text(json.dumps(out, indent=2, default=str))
        print(f"\nwrote {args.json}")
