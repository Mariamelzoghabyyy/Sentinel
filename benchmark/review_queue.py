#!/usr/bin/env python3
"""Review queue: turn your own real logs into a labelled benchmark.

This is the thing that makes "how do I test on other datasets" have a real
answer. Public datasets are stale and don't look like your traffic; your own
logs are current and do. The missing ingredient is labels — so this tool
manufactures them with a human in the loop.

Workflow:
    # 1. convert your real logs (unlabeled)
    python3 -m benchmark.adapters --dataset nginx --src /var/log/nginx/access.log --out data/mine/

    # 2. generate the review queue (highest-risk first)
    python3 benchmark/review_queue.py --data data/mine/ --build

    # 3. an analyst rules on each one (y/n/skip), and the LLM judge pre-fills
    #    a suggestion when a backend is configured
    python3 benchmark/review_queue.py --data data/mine/ --review

    # 4. evaluate against the grown label set
    python3 benchmark/eval_dataset.py --data data/mine/

Label economy: 30 ruled-on IPs already beats a stale public dataset for
tuning thresholds on YOUR traffic. Consolidate the rulings, then promote
disagreements into benchmark/cases.py as permanent regression cases.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sentinel.judge import OutcomeJudge
from sentinel.llm import get_backend
from sentinel.parser import parse_logs
from sentinel.rules import build_profiles

QUEUE = "review_queue.json"


def build(data_dir: Path, top: int = 40) -> None:
    recs, _ = parse_logs(data_dir / "access.log")
    profiles, fleet = build_profiles(recs)
    by_ip: dict[str, list] = {}
    for r in recs:
        by_ip.setdefault(r.ip, []).append(r)

    queue = []
    # Sample across the risk spectrum — reviewing only the scariest IPs tells
    # you nothing about false positives, which is the failure that erodes trust.
    ordered = profiles
    head = ordered[:top // 2]
    tail_pool = [p for p in ordered[len(ordered) // 2:]]
    step = max(1, len(tail_pool) // max(1, top // 2))
    tail = tail_pool[::step][:top // 2]
    for p in head + tail:
        samples = [ln for ln in by_ip.get(p.ip, [])][:12]
        queue.append({
            "ip": p.ip, "risk_score": p.risk_score, "verdict": p.verdict,
            "requests": p.requests, "unique_paths": p.unique_paths,
            "signals": [{"rule": s.rule_id, "sev": s.severity,
                         "evidence": s.evidence[:2]} for s in p.signals],
            "sample_lines": [
                f'{r.ts.isoformat()} {r.method} {r.path[:100]} -> {r.status} UA="{r.user_agent[:60]}"'
                for r in samples
            ],
            "ruling": None, "judge_suggestion": None,
        })
    (data_dir / QUEUE).write_text(json.dumps(queue, indent=2))
    print(f"wrote {data_dir / QUEUE} — {len(queue)} IPs "
          f"({sum(1 for q in queue if q['verdict'] != 'benign')} flagged, "
          f"{sum(1 for q in queue if q['verdict'] == 'benign')} control/benign)")


def review(data_dir: Path, use_judge: bool = True) -> None:
    qp = data_dir / QUEUE
    if not qp.exists():
        raise SystemExit("no review_queue.json — run --build first")
    queue = json.loads(qp.read_text())
    judge = OutcomeJudge(get_backend()) if use_judge else None
    if judge and not judge.available():
        judge = None
        print("(no LLM backend — judge suggestions disabled, human ruling only)\n")

    pending = [q for q in queue if q["ruling"] is None]
    print(f"{len(pending)} IPs awaiting a ruling. "
          f"Answer: m=malicious  s=suspicious  b=benign  skip  quit\n")

    for i, q in enumerate(pending, 1):
        suggestion = None
        if judge:
            prof = {k: q.get(k) for k in
                    ("ip", "requests", "unique_paths", "risk_score")}
            prof.setdefault("span_seconds", 0)
            prof["signals"] = [{"rule_id": s["rule"], "severity": s["sev"],
                                "title": "", "evidence": s["evidence"]} for s in q["signals"]]
            raw = q["sample_lines"]
            suggestion = judge.judge(prof, raw)
            q["judge_suggestion"] = suggestion.get("verdict")

        print("─" * 76)
        print(f"[{i}/{len(pending)}] {q['ip']}  risk={q['risk_score']} "
              f"verdict={q['verdict']}  requests={q['requests']} "
              f"paths={q['unique_paths']}")
        for s in q["signals"][:4]:
            print(f"   {s['rule']} ({s['sev']}): {s['evidence'][0][:90] if s['evidence'] else ''}")
        print("   sample:")
        for ln in q["sample_lines"][:5]:
            print(f"     {ln[:110]}")
        if suggestion and suggestion.get("verdict"):
            print(f"   🤖 judge suggests: {suggestion['verdict']} "
                  f"({suggestion.get('confidence', 0):.0%}) — {suggestion.get('reasoning','')[:110]}")

        try:
            ans = input("   ruling [m/s/b/skip/q]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            break
        if ans in ("q", "quit"):
            break
        mapping = {"m": "malicious", "s": "suspicious", "b": "benign"}
        if ans in mapping:
            q["ruling"] = mapping[ans]
        elif ans == "skip":
            continue
        else:
            print("   (no ruling recorded)")
            continue

    qp.write_text(json.dumps(queue, indent=2))
    ruled = [q for q in queue if q["ruling"]]
    sync_labels(data_dir, ruled)
    print(f"\n{ruled} → {len(ruled)} rulings recorded, labels.csv updated")


def sync_labels(data_dir: Path, ruled: list[dict]) -> None:
    lp = data_dir / "labels.csv"
    existing: dict[str, str] = {}
    if lp.exists():
        with lp.open(newline="") as fh:
            for row in csv.DictReader(fh):
                existing[row["ip"]] = row["label"]
    for q in ruled:
        existing[q["ip"]] = q["ruling"]
    with lp.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["ip", "label", "binary"])
        for ip, lab in sorted(existing.items()):
            w.writerow([ip, lab, 1 if lab == "malicious" else 0])


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True)
    ap.add_argument("--build", action="store_true")
    ap.add_argument("--review", action="store_true")
    ap.add_argument("--top", type=int, default=40)
    ap.add_argument("--no-judge", action="store_true")
    a = ap.parse_args()
    d = Path(a.data)
    if a.build:
        build(d, a.top)
    elif a.review:
        review(d, use_judge=not a.no_judge)
    else:
        ap.print_help()
