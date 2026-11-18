#!/usr/bin/env python3
"""Rules-only benchmark: precision / recall / F1 for the deterministic layer.

This is the number every LLM claim must be compared AGAINST. If the agents
don't beat this baseline, they are decoration.

    python3 benchmark/evaluate.py
    python3 benchmark/evaluate.py --json out.json
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from benchmark.cases import CASES, Case
from sentinel.models import LogRecord
from sentinel.parser import parse_logs
from sentinel.rules import build_profiles

import tempfile


def run_case(case: Case):
    """Write the case to a temp file, run the real parser + real rules."""
    with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as fh:
        fh.write("\n".join(case.lines) + "\n")
        path = fh.name
    try:
        recs, stats = parse_logs(path)
        profiles, _ = build_profiles(recs)
    finally:
        Path(path).unlink(missing_ok=True)

    profile = next((p for p in profiles if p.ip == case.ip), None)
    if profile is None and profiles:
        profile = profiles[0]
    return profile, stats


def evaluate(cases: list[Case]) -> dict:
    rows = []
    for case in cases:
        profile, stats = run_case(case)
        fired = {s.rule_id for s in profile.signals} if profile else set()

        missing = [r for r in case.expect_rules if r not in fired]
        unexpected = [r for r in case.forbid_rules if r in fired]
        verdict = profile.verdict if profile else "benign"

        # A case "passes" if the verdict is right AND no forbidden rule fired
        # AND every required rule did fire.
        verdict_ok = verdict == case.label
        ok = verdict_ok and not missing and not unexpected

        rows.append({
            "name": case.name, "label": case.label, "verdict": verdict,
            "risk": profile.risk_score if profile else 0,
            "rules": sorted(fired),
            "missing": missing, "unexpected": unexpected,
            "hard": case.hard, "ok": ok, "verdict_ok": verdict_ok,
            "note": case.note,
        })
    return {"rows": rows, **metrics(rows)}


def metrics(rows: list[dict]) -> dict:
    labels = ["malicious", "suspicious", "benign"]
    m = {}

    # Binary view (hostile = malicious|suspicious) — the security-relevant cut.
    tp = sum(1 for r in rows if r["label"] != "benign" and r["verdict"] != "benign")
    fp = sum(1 for r in rows if r["label"] == "benign" and r["verdict"] != "benign")
    tn = sum(1 for r in rows if r["label"] == "benign" and r["verdict"] == "benign")
    fn = sum(1 for r in rows if r["label"] != "benign" and r["verdict"] == "benign")
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0

    m["binary"] = {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": round(prec, 3), "recall": round(rec, 3),
        "f1": round(f1, 3),
        "false_positive_rate": round(fp / (fp + tn), 3) if fp + tn else 0.0,
        "accuracy": round((tp + tn) / len(rows), 3),
    }

    # Per-label confusion
    table = {a: {b: 0 for b in labels} for a in labels}
    for r in rows:
        table[r["label"]][r["verdict"]] += 1
    m["confusion"] = table
    m["exact_match"] = round(sum(1 for r in rows if r["verdict_ok"]) / len(rows), 3)
    m["case_pass_rate"] = round(sum(1 for r in rows if r["ok"]) / len(rows), 3)
    m["n"] = len(rows)

    hard = [r for r in rows if r["hard"]]
    m["hard_cases"] = {
        "n": len(hard),
        "pass": sum(1 for r in hard if r["ok"]),
        "false_positives": [r["name"] for r in hard if r["label"] == "benign" and not r["ok"]],
        "false_negatives_of_note": [r["name"] for r in hard if r["label"] != "benign" and not r["ok"]],
    }

    rule_stats = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})
    for r in rows:
        for rule in r["rules"]:
            if r["label"] == "benign":
                rule_stats[rule]["fp"] += 1
            else:
                rule_stats[rule]["tp"] += 1
        for rule in r["missing"]:
            rule_stats[rule]["fn"] += 1
    m["per_rule"] = {
        k: {**v, "precision": round(v["tp"] / (v["tp"] + v["fp"]), 3) if v["tp"] + v["fp"] else None}
        for k, v in sorted(rule_stats.items())
    }
    return m


def print_report(res: dict) -> None:
    b = res["binary"]
    print("=" * 78)
    print("  SENTINEL — RULES-ONLY BASELINE")
    print("=" * 78)
    print(f"  cases: {res['n']}   hostile/benign split: "
          f"{sum(1 for r in res['rows'] if r['label'] != 'benign')}/"
          f"{sum(1 for r in res['rows'] if r['label'] == 'benign')}")
    print(f"\n  PRECISION {b['precision']:.1%}   RECALL {b['recall']:.1%}   F1 {b['f1']:.3f}")
    print(f"  false-positive rate {b['false_positive_rate']:.1%}   "
          f"accuracy {b['accuracy']:.1%}")
    print(f"  confusion: tp={b['tp']} fp={b['fp']} tn={b['tn']} fn={b['fn']}")

    print("\n  " + "-" * 74)
    print(f"  {'case':34s} {'label':11s} {'verdict':11s} {'risk':>4s}  result")
    print("  " + "-" * 74)
    for r in res["rows"]:
        mark = "PASS" if r["ok"] else ("VERDICT" if r["verdict_ok"] else "FAIL")
        flag = " [hard]" if r["hard"] else ""
        detail = ""
        if r["missing"]:
            detail += f" missing={','.join(r['missing'])}"
        if r["unexpected"]:
            detail += f" unexpected={','.join(r['unexpected'])}"
        print(f"  {r['name'][:34]:34s} {r['label']:11s} {r['verdict']:11s} "
              f"{r['risk']:>4d}  {mark}{flag}{detail}")

    h = res["hard_cases"]
    print(f"\n  HARD CASES: {h['pass']}/{h['n']} pass")
    if h["false_positives"]:
        print(f"    ✗ flagged benign: {', '.join(h['false_positives'])}")
    if h["false_negatives_of_note"]:
        print(f"    ✗ missed:         {', '.join(h['false_negatives_of_note'])}")

    print("\n  PER-RULE PRECISION")
    for rule, s in res["per_rule"].items():
        p = f"{s['precision']:.0%}" if s["precision"] is not None else "n/a"
        print(f"    {rule:12s} fired-on {s['tp']:2d} hostile, {s['fp']:2d} benign → precision {p}")
    print("=" * 78)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", help="write full results as JSON here")
    args = ap.parse_args()
    res = evaluate(CASES)
    print_report(res)
    if args.json:
        Path(args.json).write_text(json.dumps(res, indent=2))
        print(f"wrote {args.json}")
