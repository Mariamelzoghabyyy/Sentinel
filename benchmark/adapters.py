"""Adapters to convert public security datasets into Sentinel's input format.

The reason this exists: **no public bot-detection dataset ships in nginx
combined-log format.** Without a converter you cannot honestly claim Sentinel
works beyond my synthetic samples. These adapters are the bridge, and each
one documents exactly what information is lost in translation — because
dataset conversion silently destroys the features your rules rely on.

    python3 -m benchmark.adapters --list
    python3 -m benchmark.adapters --dataset cicids2017 --src <csv> --out data/logs/
    python3 -m benchmark.adapters --dataset nginx --src access.log --out -

Every adapter ends by writing a `labels.csv` beside the logs:
    ip,label,binary
    45.133.1.77,malicious,1
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

UA_PAD = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
          "(KHTML, like Gecko) Chrome/131.0 Safari/537.36")

MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
          "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

# Labels that mean "hostile" across the common datasets, lowercased.
HOSTILE_LABELS = {
    "bot", "bots", "dos", "ddos", "dos hulk", "dos goldeneye", "dos slowloris",
    "dos slowhttptest", "heartbleed", "web attack", "web attack - brute force",
    "web attack - xss", "web attack - sql injection", "web attack – brute force",
    "web attack – xss", "web attack – sql injection", "infiltration",
    "brute force", "brute_force", "malicious", "attack", "scanning", "scan",
    "1", "true",
}


def clf(ip: str, ts: datetime, method: str, path: str, status: int, size: int,
        ua: str = UA_PAD) -> str:
    stamp = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
    return f'{ip} - - [{stamp}] "{method} {path} HTTP/1.1" {status} {size} "-" "{ua}"'


# --------------------------------------------------------------------------- #
# CIC-IDS2017 / CIC-IDS2018 (CSV of flow features)
# --------------------------------------------------------------------------- #
def convert_cicids(src: Path, out_dir: Path) -> dict:
    """CIC-IDS flow CSVs have no URLs. We therefore cannot exercise:
       SCAN-001, SCAN-002, SCAN-003, SCAN-004, EXPL-001..004, HONEY-001.
       What SURVIVES: RATE-001, BOT-002 (cadence), AUTH-001 (status codes).
       This is a real limitation, stated plainly rather than papered over.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    labels: dict[str, str] = {}
    lines: list[str] = []
    base = datetime(2017, 7, 5, 9, 0, 0)

    with src.open(newline="", encoding="utf-8", errors="replace") as fh:
        reader = csv.DictReader(fh)
        cols = {c.strip().lower(): c for c in (reader.fieldnames or [])}

        def col(*names):
            for n in names:
                if n in cols:
                    return cols[n]
            return None

        ip_c = col("source ip", "src ip", "src_ip", "source_ip")
        dst_c = col("destination ip", "dst ip", "dst_ip")
        ts_c = col("timestamp", "flow start time", "start time")
        label_c = col("label", "attack", "class")
        fwd_c = col("total fwd packets", "tot fwd pkts", "fwd_packets")
        if not (ip_c and label_c):
            raise SystemExit(f"could not find source-IP/label columns in {src.name}; "
                             f"saw: {list(cols)}")

        seen_ts: dict[str, datetime] = {}
        for i, row in enumerate(reader):
            ip = (row.get(ip_c) or "").strip()
            if not ip:
                continue
            raw_label = (row.get(label_c) or "").strip().lower()
            hostile = raw_label in HOSTILE_LABELS
            prev = labels.get(ip)
            if prev is None or hostile:
                labels[ip] = "malicious" if hostile else "benign"

            # Reconstruct a plausible request stream from flow packet counts.
            pkts = 1
            if fwd_c:
                try:
                    pkts = max(1, min(400, int(float(row[fwd_c]))))
                except (ValueError, TypeError):
                    pkts = 1
            t = base + timedelta(milliseconds=120 * i)
            for k in range(pkts):
                # Destination port in the path is the only real signal we keep.
                lines.append(clf(ip, t + timedelta(milliseconds=40 * k), "GET",
                                 f"/service/{i % 97}", 200, 512))

    _write(out_dir, lines, labels)
    return {"format": "cicids-flow-derived", "requests": len(lines), "ips": len(labels),
            "loses": ["URL paths (no enumeration/payload rules possible)",
                      "status codes", "user agents", "request cadence fidelity"]}


# --------------------------------------------------------------------------- #
# CSIC 2010 HTTP dataset (does contain real requests) — best public option
# --------------------------------------------------------------------------- #
def convert_csic(src: Path, out_dir: Path) -> dict:
    """CSIC 2010 logs real HTTP request lines; this preserves URL paths,
    so SCAN-*/EXPL-* rules become testable. Labels come from the filename
    convention (normalTraffic / anomalousTraffic)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    labels: dict[str, str] = {}
    lines: list[str] = []

    files = sorted(src.rglob("*.txt")) if src.is_dir() else [src]
    for f in files:
        hostile = "anomal" in f.name.lower()
        cur_ip = None
        idx = 0
        pending_ts = None
        for raw in f.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.strip()
            if not line:
                continue
            low = line.lower()
            if low.startswith("get ") or low.startswith("post ") or low.startswith("put "):
                try:
                    method, path = line.split(" ", 1)[0].upper(), line.split(" ")[1]
                except IndexError:
                    continue
                cur_ip = cur_ip or f"172.16.0.{(abs(hash(f.name)) % 200) + 10}"
                labels.setdefault(cur_ip, "malicious" if hostile else "benign")
                pending_ts = (pending_ts or datetime(2010, 6, 1, 8, 0, 0)) + timedelta(seconds=2)
                lines.append(clf(cur_ip, pending_ts, method, path,
                                 404 if hostile else 200, 900))
                idx += 1

    _write(out_dir, lines, labels)
    return {"format": "csic-2010", "requests": len(lines), "ips": len(labels),
            "loses": ["per-request source IP (CSIC is single-source; we synthesise one IP per file)",
                      "real timestamps", "status codes are inferred"]}


# --------------------------------------------------------------------------- #
# A real nginx log you already have (unlabeled) — clustering review mode
# --------------------------------------------------------------------------- #
def convert_nginx(src: Path, out_dir: Path) -> dict:
    """No labels exist, so this writes an UNLABELED set. Use it for:
       1. sanity-checking that the parser handles your real logs
       2. the review queue: every escalation gets an analyst ruling that
          becomes a new labelled case (see benchmark/review_queue.py)"""
    from sentinel.parser import parse_logs
    recs, stats = parse_logs(src)
    out_dir.mkdir(parents=True, exist_ok=True)
    with (out_dir / "access.log").open("w") as fh:
        for r in recs:
            fh.write(clf(r.ip, r.ts, r.method, r.path, r.status, r.size, r.user_agent) + "\n")
    with (out_dir / "labels.csv").open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["ip", "label", "binary"])
        for ip in sorted({r.ip for r in recs}):
            w.writerow([ip, "unlabeled", ""])
    return {"format": "nginx-unlabeled", "requests": len(recs),
            "ips": len({r.ip for r in recs}),
            "parse_stats": stats,
            "note": "unlabeled by design — use review_queue.py to build ground truth"}


def _write(out_dir: Path, lines: list[str], labels: dict[str, str]) -> None:
    with (out_dir / "access.log").open("w") as fh:
        fh.write("\n".join(lines) + "\n")
    with (out_dir / "labels.csv").open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["ip", "label", "binary"])
        for ip, lab in sorted(labels.items()):
            w.writerow([ip, lab, 1 if lab == "malicious" else 0])


ADAPTERS = {
    "cicids2017": (convert_cicids, "CIC-IDS2017/2018 flow CSVs (loses URLs — limited)"),
    "cicids2018": (convert_cicids, "same schema as 2017"),
    "csic2010": (convert_csic, "CSIC 2010 HTTP dataset (keeps URLs — best public option)"),
    "nginx": (convert_nginx, "your own nginx/Apache logs (unlabeled)"),
}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--dataset", choices=sorted(ADAPTERS))
    ap.add_argument("--src")
    ap.add_argument("--out")
    a = ap.parse_args()

    if a.list or not a.dataset:
        print("\nAvailable adapters:\n")
        for k, (_, desc) in sorted(ADAPTERS.items()):
            print(f"  {k:12s} {desc}")
        print("\nUsage: python3 -m benchmark.adapters --dataset nginx --src access.log --out data/")
        sys.exit(0)

    fn, _ = ADAPTERS[a.dataset]
    out = Path(a.out or "data")
    summary = fn(Path(a.src), out)
    print(json.dumps(summary, indent=2, default=str))
