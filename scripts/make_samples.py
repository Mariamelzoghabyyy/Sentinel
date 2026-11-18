#!/usr/bin/env python3
"""Generate realistic sample access logs for Sentinel.

Produces three scenarios so you can see the pipeline flex:
  samples/access.log       – CLF, mixed traffic, ~5 distinct actors
  samples/access.jsonl     – same traffic as nginx JSON lines (format parity test)
  samples/quiet.log        – mostly-benign day (should report LOW / informational)
  samples/incident.log     – sustained campaign (should trigger P1 + response actions)
"""

from __future__ import annotations

import json
import random
from datetime import datetime, timedelta
from pathlib import Path

random.seed(1337)
HERE = Path(__file__).resolve().parent.parent / "samples"
BASE = datetime(2026, 11, 18, 6, 0, 0)

NORMAL_IPS = [f"203.0.113.{i}" for i in range(10, 40)] + [f"198.51.100.{i}" for i in range(50, 75)]
BROWSERS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1",
]
ASSETS = ["/static/app.js", "/static/app.css", "/img/logo.svg", "/img/hero.webp",
          "/fonts/inter.woff2", "/favicon.ico", "/static/vendor.js"]
PAGES = ["/", "/pricing", "/docs/getting-started", "/docs/api", "/blog/2026-roadmap",
         "/about", "/careers", "/signup", "/login", "/dashboard", "/api/v1/items",
         "/api/v1/profile", "/status"]


def rec(ip, ts, method, path, status, size, ua, ref="https://app.example.com/"):
    return dict(ip=ip, ts=ts, method=method, path=path, status=status,
                size=size, ua=ua, ref=ref)


def clf_line(r):
    ts = r["ts"].strftime("%d/%b/%Y:%H:%M:%S +0000")
    return (f'{r["ip"]} - - [{ts}] "{r["method"]} {r["path"]} HTTP/1.1" '
            f'{r["status"]} {r["size"]} "{r["ref"]}" "{r["ua"]}"')


def json_line(r):
    return json.dumps({
        "time_iso8601": r["ts"].strftime("%Y-%m-%dT%H:%M:%S+00:00"),
        "remote_addr": r["ip"],
        "request_method": r["method"],
        "request_uri": r["path"],
        "status": r["status"],
        "body_bytes_sent": r["size"],
        "http_user_agent": r["ua"],
        "http_referer": r["ref"],
        "server_name": "app.example.com",
    })


def normal_traffic(start, end, rate_per_min=3.0, ips=None):
    out, t = [], start
    ips = ips or NORMAL_IPS
    while t < end:
        t += timedelta(seconds=random.expovariate(rate_per_min / 60))
        ip = random.choice(ips)
        ua = random.choice(BROWSERS)
        if random.random() < 0.45:
            out.append(rec(ip, t, "GET", random.choice(ASSETS), 200,
                           random.randint(800, 90000), ua))
            out.append(rec(ip, t, "GET", random.choice(PAGES), 200,
                           random.randint(2000, 60000), ua))
        else:
            path = random.choice(PAGES)
            status = 200 if random.random() > 0.06 else random.choice([301, 304, 404])
            out.append(rec(ip, t, "GET", path, status, random.randint(300, 40000), ua))
    return out


# --------------------------------------------------------------------------- #
# Actors
# --------------------------------------------------------------------------- #
def actor_scanner():
    """Off-the-shelf vulnerability scanner: broad sweep, 404s, known UA."""
    out, t = [], BASE + timedelta(minutes=40)
    paths = ["/", "/wp-login.php", "/wp-admin/", "/xmlrpc.php", "/.env", "/.git/config",
             "/phpmyadmin/", "/admin", "/backup.zip", "/config.php", "/cgi-bin/test.cgi",
             "/shell.php", "/.aws/credentials", "/actuator/env", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"]
    for i in range(70):
        t += timedelta(milliseconds=random.randint(350, 900))
        p = paths[i % len(paths)]
        status = 404 if p != "/" else 200
        out.append(rec("45.133.1.77", t, "GET", p, status, random.randint(150, 600) if status == 404 else 12000,
                       "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
                       ref=""))
    return out


def actor_sqli():
    """Targeted injection attempts against a search endpoint."""
    out, t = [], BASE + timedelta(hours=2, minutes=5)
    payloads = [
        "/search?q=1%27%20OR%20%271%27%3D%271",
        "/search?q=1%20UNION%20SELECT%20username,password%20FROM%20users--",
        "/product?id=1%20AND%20SLEEP(5)",
        "/search?q=%27%20OR%20%271%27%3D%271%27--",
        "/api/v1/items?filter=1%3D1--",
        "/search?q=1%27%20AND%20(SELECT%20COUNT(*)%20FROM%20information_schema.tables)%3E0--",
    ]
    for i, p in enumerate(payloads * 3):
        t += timedelta(seconds=random.randint(20, 90))
        out.append(rec("185.220.101.44", t, "GET", p, 500 if "SLEEP" in p else 200,
                       random.randint(400, 5000),
                       "sqlmap/1.8.7#stable (https://sqlmap.org)" if i % 2 == 0
                       else "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0",
                       ref="https://app.example.com/search"))
    return out


def actor_bruteforce(compromise=True):
    """Password spraying across many usernames, then a success (credential stuffing win)."""
    out, t = [], BASE + timedelta(hours=3)
    for i in range(48):
        t += timedelta(seconds=random.randint(4, 11))
        user = f"user{random.randint(1, 300)}"
        out.append(rec("91.240.118.9", t, "POST", f"/login?u={user}", 401, 512,
                       "python-requests/2.32.3", ref="https://app.example.com/login"))
    if compromise:
        t += timedelta(seconds=25)
        out.append(rec("91.240.118.9", t, "POST", "/login?u=svc_billing", 200, 2048,
                       "python-requests/2.32.3", ref="https://app.example.com/login"))
        for j in range(6):
            t += timedelta(seconds=random.randint(30, 80))
            out.append(rec("91.240.118.9", t, "GET", f"/api/v1/export?format=csv&page={j}", 200,
                           random.randint(40000, 300000), "python-requests/2.32.3",
                           ref="https://app.example.com/dashboard"))
    return out


def actor_scraper():
    """Polite-ish scraper: rotating UAs, steady cadence, pulls every catalogue page."""
    out, t = [], BASE + timedelta(hours=4, minutes=12)
    uas = [f"Mozilla/5.0 (compatible; Bot/{i}.{random.randint(0,9)}; +http://bots.example.net)" for i in range(12)]
    for i in range(120):
        t += timedelta(seconds=5 + random.random() * 0.4)   # metronomic
        out.append(rec("77.88.55.20", t, "GET", f"/catalogue/page/{i+1}", 200,
                       random.randint(20000, 50000), random.choice(uas),
                       ref="https://app.example.com/catalogue"))
    return out


def actor_honeypot():
    out, t = [], BASE + timedelta(hours=5, minutes=30)
    for p in ["/admin-prod-do-not-exist.php", "/honeypot/trap"]:
        out.append(rec("5.188.206.14", t, "GET", p, 404, 300, "curl/8.7.1"))
        t += timedelta(seconds=40)
    return out


def actor_highrate(start, minutes=3, rpm=420):
    """Volumetric burst on API endpoints."""
    out, t = [], start
    for _ in range(minutes * rpm):
        t += timedelta(seconds=60 / rpm)
        out.append(rec("103.21.244.8", t, "GET", "/api/v1/items?page=1", 200, 1200,
                       "Go-http-client/1.1", ref=""))
    return out


def write(path: Path, records, fmt):
    records.sort(key=lambda r: r["ts"])
    with path.open("w") as fh:
        for r in records:
            fh.write((clf_line(r) if fmt == "clf" else json_line(r)) + "\n")
    print(f"wrote {path.name}: {len(records)} lines")


if __name__ == "__main__":
    HERE.mkdir(exist_ok=True)

    # --- mixed day ---------------------------------------------------------- #
    day = normal_traffic(BASE, BASE + timedelta(hours=8))
    day += actor_scanner() + actor_sqli() + actor_bruteforce() + actor_scraper() + actor_honeypot()
    day += actor_highrate(BASE + timedelta(hours=6, minutes=10), minutes=2, rpm=300)

    # one deliberately malformed line to exercise parse accounting
    write(HERE / "access.log", day, "clf")
    with (HERE / "access.log").open("a") as fh:
        fh.write("this is not a valid log line — parser must count it, not crash\n")
        fh.write("10.0.0.1 - - [bad timestamp] \"GET / HTTP/1.1\" 200 100 \"-\" \"x\"\n")

    write(HERE / "access.jsonl", day, "json")

    # --- quiet day ---------------------------------------------------------- #
    quiet = normal_traffic(BASE, BASE + timedelta(hours=8), rate_per_min=2.0)
    quiet += [rec("5.188.206.14", BASE + timedelta(hours=2), "GET",
                  "/admin-prod-do-not-exist.php", 404, 300, "curl/8.7.1")]
    write(HERE / "quiet.log", quiet, "clf")

    # --- incident day ------------------------------------------------------- #
    incident = normal_traffic(BASE, BASE + timedelta(hours=2), rate_per_min=2.0)
    incident += actor_bruteforce(compromise=True)
    incident += actor_scanner()
    incident += actor_highrate(BASE + timedelta(hours=1, minutes=5), minutes=4, rpm=500)
    incident += actor_sqli()
    write(HERE / "incident.log", incident, "clf")
