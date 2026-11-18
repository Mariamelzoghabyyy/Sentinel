"""Web-server log parsing (nginx/Apache).

Supports:
  * Combined Log Format (CLF) with optional leading virtual-host token
  * nginx-style JSON-lines logs
  * auto-detection between the two

Design choice: parsing never raises on a bad line. Bad lines are counted and
sampled so the report can tell the analyst "input was 99.3% parseable" instead
of silently dropping data.
"""

from __future__ import annotations

import gzip
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from .models import LogRecord

# 1.2.3.4 - frank [10/Oct/2000:13:55:36 -0700] "GET /x HTTP/1.0" 200 2326 "ref" "ua"
CLF_RE = re.compile(
    r'^(?:(?P<vhost>\S+)\s+)?'                       # optional vhost prefix
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+'                    # ip ident user
    r'\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+|-)\s+(?P<path>\S+)(?:\s+HTTP/[\d.]+)?"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\d+|-)\s*'
    r'(?:"(?P<referer>[^"]*)"\s*)?'
    r'(?:"(?P<ua>[^"]*)")?\s*$'
)

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}
CLF_TS_RE = re.compile(r"(\d{2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-])(\d{2})(\d{2})")


def _parse_clf_ts(raw: str) -> datetime:
    m = CLF_TS_RE.match(raw.strip())
    if not m:
        raise ValueError(f"unparseable timestamp: {raw!r}")
    day, mon, year, hh, mm, ss, sign, oh, om = m.groups()
    offset_min = (int(oh) * 60 + int(om)) * (1 if sign == "+" else -1)
    naive = datetime(
        int(year), MONTHS[mon], int(day), int(hh), int(mm), int(ss),
        tzinfo=timezone.utc,
    )
    # Normalise to UTC so windows/peak-rate math is timezone-safe.
    return naive.replace(tzinfo=None) - _td(offset_min)


def _td(minutes: int):
    from datetime import timedelta
    return timedelta(minutes=minutes)


def _parse_combined(line: str) -> LogRecord:
    m = CLF_RE.match(line)
    if not m:
        raise ValueError("line does not match Combined Log Format")
    g = m.groupdict()
    size = 0 if g["size"] in (None, "-") else int(g["size"])
    return LogRecord(
        ip=g["ip"],
        ts=_parse_clf_ts(g["ts"]),
        method=g["method"] or "-",
        path=g["path"],
        status=int(g["status"]),
        size=size,
        user_agent=g["ua"] or "",
        referer=g["referer"] or "",
    )


def _parse_json(line: str) -> LogRecord:
    j = json.loads(line)
    # Common nginx json_log field names (nginx's own and popular presets)
    ip = j.get("remote_addr") or j.get("client_ip") or j.get("ip") or ""
    if not ip:
        raise ValueError("json log line has no remote_addr/client_ip field")
    ts_raw = j.get("time_iso8601") or j.get("time_local") or j.get("timestamp") or ""
    ts = _parse_any_ts(str(ts_raw))
    method = j.get("request_method") or j.get("method") or "-"
    path = j.get("request_uri") or j.get("uri") or j.get("path") or "/"
    status = int(j.get("status", 0) or 0)
    size = int(j.get("body_bytes_sent", j.get("bytes", 0)) or 0)
    ua = j.get("http_user_agent") or j.get("user_agent") or ""
    ref = j.get("http_referer") or j.get("referer") or ""
    return LogRecord(ip=ip, ts=ts, method=method, path=path, status=status,
                     size=size, user_agent=ua, referer=ref)


def _parse_any_ts(raw: str) -> datetime:
    raw = raw.strip()
    # nginx ISO8601: 2024-05-14T03:12:44+02:00
    try:
        dt = datetime.fromisoformat(raw)
        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt
    except ValueError:
        pass
    # Apache: 14/May/2024:03:12:44 +0200
    try:
        return _parse_clf_ts(raw)
    except ValueError:
        pass
    raise ValueError(f"unrecognised timestamp: {raw!r}")


def _open_text(path: Path):
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return path.open("rt", encoding="utf-8", errors="replace")


def detect_format(path: Path) -> str:
    """Sniff the first non-empty line to choose a parser."""
    with _open_text(path) as fh:
        for _ in range(5):
            line = fh.readline()
            if not line:
                break
            s = line.strip()
            if not s:
                continue
            if s.startswith("{"):
                return "json"
            return "combined"
    return "combined"


def parse_logs(path: str | Path, fmt: str = "auto") -> tuple[list[LogRecord], dict]:
    """Parse a log file into records (sorted by time) plus parse statistics."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(path)
    if fmt == "auto":
        fmt = detect_format(path)

    parser = _parse_json if fmt == "json" else _parse_combined
    records: list[LogRecord] = []
    bad = 0
    bad_samples: list[str] = []
    total = 0

    with _open_text(path) as fh:
        for line in fh:
            if not line.strip():
                continue
            total += 1
            try:
                records.append(parser(line.rstrip("\n")))
            except Exception:
                bad += 1
                if len(bad_samples) < 5:
                    bad_samples.append(line.strip()[:160])

    records.sort(key=lambda r: r.ts)
    stats = {
        "format": fmt,
        "lines_total": total,
        "lines_parsed": len(records),
        "lines_malformed": bad,
        "parse_rate": round(len(records) / total, 4) if total else 0.0,
        "malformed_samples": bad_samples,
        "time_range": {
            "start": records[0].ts.isoformat() if records else None,
            "end": records[-1].ts.isoformat() if records else None,
        },
        "unique_ips": len({r.ip for r in records}),
    }
    return records, stats
