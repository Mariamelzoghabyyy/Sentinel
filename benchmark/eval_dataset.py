#!/usr/bin/env python3
"""Evaluate Sentinel against a CONVERTED dataset with a labels.csv.

This is the honest test: rules run on data whose labels they never saw.

    python3 benchmark/eval_dataset.py --data data/csic2010/
    python3 benchmark/eval_dataset.py --data data/cicids2017/ --json out.json

Prints precision/recall and a per-IP confusion, plus a "blind spot" warning
listing rules that could not have fired because the source data lacks URLs,
status codes, or user agents.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sentinel.parser import parse_logs
from sentinel.rules import build_profiles

URL_DEPENDENT = {"SCAN-001", "SCAN-002", "SCAN-003", "SCAN-004",
                 "EXPL-001", "EXPL-002", "EXPL-003", "EXPL-004", "HONEY-001",
                 "AUTH-001", "AUTH-002"}


def load_labels(path: Path) -> dict[str, str]:
    labels = {}
    with path.open(newline="") as fh:
        for row in csv.DictReader(fh):
            lab = (row.get("label") or "").strip().lower()
            if lab and lab != "unlabeled":
                labels[row["ip"]] = "malicious" if lab in ("malicious", "1", "attack") else lab
    return labels


def evaluate(data_dir: Path) -> dict:
    log = data_dir / "access.log"
    lab_file = data_dir / "labels.csv"
    if not log.exists():
        raise SystemExit(f"no access.log in {data_dir}")
    if not lab_file.exists():
        raise SystemExit(f"no labels.csv in {data_dir} — convert first, or build "
                         f"labels with benchmark/review_queue.py")

    recs, stats = parse_logs(log)
    profiles, fleet = build_profiles(recs)
    labels = load_labels(lab_file)

    rows = []
    for p in profiles:
        truth = labels.get(p.ip)
        if truth is None:
            continue
        rows.append({"ip": p.ip, "truth": truth, "pred": p.verdict,
                     "risk": p.risk_score, "requests": p.requests,
                     "rules": [s.rule_id for s in p.signals]})

    tp = sum(1 for r in rows if r["truth"] == "malicious" and r["pred"] == "malicious")
    fp = sum(1 for r in rows if r["truth"] != "malicious" and r["pred"] == "malicious")
    tn = sum(1 for r in rows if r["truth"] != "malicious" and r["pred"] != "malicious")
    fn = sum(1 for r in rows if r["truth"] == "malicious" and r["pred"] != "malicious")

    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0

    fired = Counter(rule for r in rows for rule in r["rules"])
    blind = sorted(URL_DEPENDENT - set(fired))

    return {
        "dataset": str(data_dir),
        "parse_stats": stats,
        "labeled_ips": len(rows),
        "evaluated_ips": len(rows),
        "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "precision": round(prec, 3), "recall": round(rec, 3), "f1": round(f1, 3),
        "rules_that_fired": dict(fired.most_common()),
        "rules_that_could_not_fire": blind,
        "false_positives": [r for r in rows if r["truth"] != "malicious" and r["pred"] == "malicious"][:10],
        "false_negatives": [r for r in rows if r["truth"] == "malicious" and r["pred"] != "malicious"][:10],
        "fleet": fleet,
    }


def print_report(res: dict) -> None:
    print("=" * 78)
    print(f"  DATASET EVALUATION — {res['dataset']}")
    print("=" * 78)
    c = res["confusion"]
    print(f"  labeled IPs: {res['labeled_ips']}   "
          f"parse rate: {res['parse_stats']['parse_rate']:.1%}")
    print(f"  PRECISION {res['precision']:.1%}   RECALL {res['recall']:.1%}   F1 {res['f1']:.3f}")
    print(f"  tp={c['tp']} fp={c['fp']} tn={c['tn']} fn={c['fn']}")
    print(f"\n  rules that fired: {json.dumps(res['rules_that_fired'])}")
    if res["rules_that_could_not_fire"]:
        print(f"\n  ⚠️  COULD NOT FIRE (source data lacks URLs/status/UA):")
        print(f"     {', '.join(res['rules_that_could_not_fire'])}")
        print("     Recall here is a FLOOR, not a ceiling — but also not a valid")
        print("     measure of those rules' quality.")
    if res["false_positives"]:
        print("\n  FALSE POSITIVES")
        for r in res["false_positives"]:
            print(f"    • {r['ip']:18s} risk={r['risk']:3d} rules={r['rules']}")
    if res["false_negatives"]:
        print("\n  FALSE NEGATIVES")
        for r in res["false_negatives"]:
            print(f"    • {r['ip']:18s} risk={r['risk']:3d} rules={r['rules']}")
    print("=" * 78)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True, help="directory with access.log + labels.csv")
    ap.add_argument("--json", help="write results here")
    a = ap.parse_args()
    res = evaluate(Path(a.data))
    print_report(res)
    if a.json:
        Path(a.json).write_text(json.dumps(res, indent=2, default=str))
        print(f"wrote {a.json}")
