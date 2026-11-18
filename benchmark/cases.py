"""Labeled benchmark cases.

Each case is a small, hand-written log (3 lines to ~250) plus the ground-truth
label a human analyst would assign. The labels live HERE, in the test harness,
and are never visible to rules or agents — which is what makes the evaluation
mean something.

Labels
  malicious  : hostile intent, would justify containment
  suspicious : tooled/abusive automation, not proven hostile
  benign     : legitimate traffic, including sanctioned crawlers and monitors

`hard` cases exist specifically to punish naive rules: they are the false
positives and false negatives a real deployment hits. If the benchmark can't
fool the system, it isn't measuring anything.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

BASE = datetime(2026, 6, 1, 9, 0, 0)

UA_CHROME = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/131.0 Safari/537.36")
UA_SAFARI = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
             "(KHTML, like Gecko) Version/17.6 Safari/605.1.15")
UA_FIREFOX = "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0"


@dataclass
class Case:
    name: str
    label: str                    # malicious | suspicious | benign
    ip: str
    lines: list[str]              # raw CLF lines
    expect_rules: list[str] = field(default_factory=list)   # rule IDs that MUST fire
    forbid_rules: list[str] = field(default_factory=list)   # rule IDs that must NOT fire
    hard: bool = False            # adversarial / previously-misclassified case
    note: str = ""


def clf(ip: str, t: datetime, path: str, status: int = 200, size: int = 4200,
        ua: str = UA_CHROME, method: str = "GET", ref: str = "https://app.example.com/") -> str:
    ts = t.strftime("%d/%b/%Y:%H:%M:%S +0000")
    return f'{ip} - - [{ts}] "{method} {path} HTTP/1.1" {status} {size} "{ref}" "{ua}"'


def normal(case_ip: str, n: int = 40, gap: float = 7.0, start: datetime | None = None,
           ua: str | None = None) -> list[str]:
    """A believable human session: pages + assets, jittery cadence."""
    import random
    rng = random.Random(hash(case_ip) & 0xFFFF)
    pages = ["/", "/pricing", "/docs/api", "/blog/post-1", "/about"]
    assets = ["/static/app.js", "/static/app.css", "/img/logo.svg", "/favicon.ico"]
    t = start or BASE
    out = []
    ua = ua or UA_CHROME
    for i in range(n):
        t += timedelta(seconds=gap * rng.uniform(0.4, 1.8))
        if i % 3 == 0:
            out.append(clf(case_ip, t, rng.choice(assets), 200, rng.randint(900, 90000), ua))
        else:
            out.append(clf(case_ip, t, rng.choice(pages), 200, rng.randint(2000, 50000), ua))
    return out


# --------------------------------------------------------------------------- #
# Cases
# --------------------------------------------------------------------------- #
def build_cases() -> list[Case]:
    cases: list[Case] = []

    # ---------------- malicious ---------------- #
    t0 = BASE
    cases.append(Case(
        name="nmap_scanner",
        label="malicious", ip="45.133.1.77",
        lines=[clf("45.133.1.77", t0 + timedelta(milliseconds=600 * i), p, 404 if p != "/" else 200, 300,
                   "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)")
               for i, p in enumerate(["/wp-login.php", "/.env", "/phpmyadmin/", "/.git/config",
                                      "/admin", "/backup.zip", "/config.php", "/shell.php",
                                      "/cgi-bin/test.cgi", "/.aws/credentials"] * 4)],
        expect_rules=["BOT-001", "SCAN-001", "SCAN-002"],
        note="off-the-shelf scanner: known UA, sensitive paths, 404 storm",
    ))

    cases.append(Case(
        name="sqli_union",
        label="malicious", ip="185.220.101.44",
        lines=[clf("185.220.101.44", t0 + timedelta(seconds=30 * i),
                   p, 500 if "SLEEP" in p else 200, 1200,
                   "sqlmap/1.8.7#stable (https://sqlmap.org)")
               for i, p in enumerate([
                   "/search?q=1%27%20OR%20%271%27%3D%271",
                   "/search?q=1%20UNION%20SELECT%20username,password%20FROM%20users--",
                   "/product?id=1%20AND%20SLEEP(5)",
                   "/api/v1/items?filter=1%3D1--",
                   "/search?q=1%27%20AND%20(SELECT%20COUNT(*)%20FROM%20information_schema.tables)%3E0--",
               ] * 3)],
        expect_rules=["EXPL-002", "BOT-001"],
        note="targeted injection with explicit payloads",
    ))

    cases.append(Case(
        name="bruteforce_then_success",
        label="malicious", ip="91.240.118.9",
        lines=[clf("91.240.118.9", t0 + timedelta(seconds=6 * i), f"/login?u=user{100+i}", 401, 512,
                   "python-requests/2.32.3", method="POST") for i in range(40)]
              + [clf("91.240.118.9", t0 + timedelta(seconds=260), "/login?u=admin", 200, 2048,
                     "python-requests/2.32.3", method="POST")]
              + [clf("91.240.118.9", t0 + timedelta(seconds=300 + 40 * i),
                     f"/api/v1/export?page={i}", 200, 220000, "python-requests/2.32.3")
                 for i in range(5)],
        expect_rules=["AUTH-001", "AUTH-002"],
        note="spray succeeds, then bulk export — the compromise pattern",
    ))

    cases.append(Case(
        name="path_traversal",
        label="malicious", ip="193.32.162.9",
        lines=[clf("193.32.162.9", t0 + timedelta(seconds=12 * i), p, 403 if i % 2 else 200, 800,
                   "Mozilla/5.0 zgrab/0.x")
               for i, p in enumerate([
                   "/download?file=../../../../etc/passwd",
                   "/download?file=..%2f..%2f..%2fetc%2fpasswd",
                   "/img?src=../../config.php",
                   "/static/../.env",
               ] * 3)],
        expect_rules=["EXPL-001"],
        note="traversal encoding variants",
    ))

    cases.append(Case(
        name="command_injection",
        label="malicious", ip="66.240.205.34",
        lines=[clf("66.240.205.34", t0 + timedelta(seconds=15 * i), p, 200, 900, "curl/8.5.0")
               for i, p in enumerate([
                   "/ping?host=127.0.0.1;id",
                   "/ping?host=127.0.0.1&&whoami",
                   "/convert?f=$(wget%20-t1%20x)",
                   "/ping?host=|id",
               ] * 2)],
        expect_rules=["EXPL-004"],
        note="OS command injection into a diagnostics endpoint",
    ))

    cases.append(Case(
        name="honeypot_hit",
        label="malicious", ip="5.188.206.14",
        lines=[clf("5.188.206.14", t0, "/admin-prod-do-not-exist.php", 404, 300, "curl/8.7.1")],
        expect_rules=["HONEY-001"],
        note="single request, but a guaranteed bot",
    ))

    cases.append(Case(
        name="xss_probe",
        label="suspicious", ip="209.141.55.26",
        lines=[clf("209.141.55.26", t0 + timedelta(seconds=20 * i), p, 200, 1100)
               for i, p in enumerate([
                   "/search?q=%3Cscript%3Ealert(1)%3C/script%3E",
                   "/comment?body=<script>document.location='//x.io'</script>",
                   "/search?q=javascript:alert(1)",
                   "/profile?bio=<img src=x onerror=alert(1)>",
               ] * 3)],
        expect_rules=["EXPL-003"],
        note="reflected XSS probing that the app ACCEPTED (200). Labeled suspicious, not "
             "malicious: payload presence proves intent, but 200 on a GET does not prove "
             "execution — that needs a browser or stored-XSS confirmation.",
    ))

    cases.append(Case(
        name="volumetric_flood",
        label="malicious", ip="103.21.244.8",
        lines=[clf("103.21.244.8", t0 + timedelta(seconds=i * 0.2), "/api/v1/items?page=1", 200, 1200,
                   "Go-http-client/1.1", ref="") for i in range(300)],
        expect_rules=["RATE-001"],
        note="300 req/min sustained — infrastructure abuse",
    ))

    # ---------------- suspicious ---------------- #
    cases.append(Case(
        name="ua_rotating_scraper",
        label="suspicious", ip="77.88.55.20",
        lines=[clf("77.88.55.20", t0 + timedelta(seconds=5 + 0.2 * (i % 3)),
                   f"/catalogue/page/{i+1}", 200, 30000,
                   f"Mozilla/5.0 (compatible; Bot/{i % 12}.{i % 7}; +http://bots.example.net)",
                   ref="https://app.example.com/catalogue")
               for i in range(120)],
        expect_rules=["BOT-005", "SCAN-004"],
        note="polite rate, but rotating UAs and walking every page in sequence",
    ))

    cases.append(Case(
        name="directory_enumeration",
        label="malicious", ip="141.98.10.73",
        lines=[clf("141.98.10.73", t0 + timedelta(seconds=1.1 * i),
                   f"/{word}", 404, 250, "Mozilla/5.0 (X11; Linux x86_64) Go-http-client/2.0")
               for i, word in enumerate(["admin", "api", "backup", "db", "dev", "staging", "test",
                                         "old", "new", "v1", "v2", "internal", "private", "secret",
                                         "keys", "config", "logs", "tmp", "data", "files",
                                         "uploads", "assets2", "portal", "staff", "manage"])],
        expect_rules=["SCAN-003", "BOT-001"],
        note="wordlist-style discovery at low rate — evades rate rules by design. "
             "Labeled malicious: 25 unrelated 404s is deliberate tooling, not curiosity.",
    ))

    cases.append(Case(
        name="slow_credential_stuffing",
        label="suspicious", ip="194.26.29.113",
        lines=[clf("194.26.29.113", t0 + timedelta(seconds=45 * i), f"/login?u=a{i}@x.com", 401, 480,
                   UA_CHROME, method="POST") for i in range(14)],
        expect_rules=["AUTH-001"],
        note="deliberately slow spray — below the 5-minute burst window",
    ))

    # ---------------- benign (the important ones) ---------------- #
    cases.append(Case(
        name="normal_human_session",
        label="benign", ip="203.0.113.44",
        lines=normal("203.0.113.44", n=60),
        forbid_rules=["SCAN-001", "SCAN-002", "AUTH-001", "BOT-001", "RATE-001"],
        note="ordinary browsing with assets",
    ))

    cases.append(Case(
        name="sanctioned_googlebot",
        label="benign", ip="66.249.66.1",
        lines=[clf("66.249.66.1", t0 + timedelta(seconds=12 * i),
                   ["/", "/pricing", "/blog/post-1", "/docs/api"][i % 4], 200, 30000,
                   "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
                   ref="https://www.google.com/")
               for i in range(45)],
        forbid_rules=["SCAN-001", "SCAN-002", "EXPL-001", "EXPL-002"],
        note="hits every page on a schedule — must not be treated as hostile",
    ))

    cases.append(Case(
        name="uptime_monitor_60s",
        label="benign", ip="198.51.100.9",
        lines=[clf("198.51.100.9", t0 + timedelta(seconds=60 * i), "/health", 200, 220,
                   "kube-probe/1.29") for i in range(50)],
        forbid_rules=["BOT-002", "RATE-001"],
        hard=True,
        note="PERFECTLY metronomic — the original false positive I had to fix",
    ))

    cases.append(Case(
        name="load_balancer_healthcheck",
        label="benign", ip="10.0.0.14",
        lines=[clf("10.0.0.14", t0 + timedelta(seconds=5 * i), "/healthz", 200, 180, "ELB-HealthChecker/2.0")
               for i in range(120)],
        forbid_rules=["SCAN-001", "EXPL-001", "EXPL-002", "AUTH-001"],
        hard=True,
        note="120 requests in 10 min from RFC1918 space; high volume, zero threat",
    ))

    cases.append(Case(
        name="asset_heavy_first_load",
        label="benign", ip="203.0.113.77",
        lines=([clf("203.0.113.77", t0 + timedelta(milliseconds=350 * i),
                    f"/static/chunk-{i}.js", 200, 45000, UA_CHROME) for i in range(22)]
               + [clf("203.0.113.77", t0 + timedelta(seconds=9), "/app/dashboard", 200, 8000, UA_CHROME)]),
        forbid_rules=["SCAN-001", "SCAN-002", "EXPL-001"],
        hard=True,
        note="22 parallel JS chunks in 8s — looks like a burst, is a browser",
    ))

    cases.append(Case(
        name="genuine_404_during_migration",
        label="benign", ip="203.0.113.91",
        lines=[clf("203.0.113.91", t0 + timedelta(seconds=20 * i),
                   f"/old-blog/2019/post-{i}", 404, 300, UA_SAFARI,
                   ref="https://app.example.com/old-blog")
               for i in range(35)],
        forbid_rules=["BOT-001", "SCAN-001", "EXPL-001", "EXPL-002"],
        hard=True,
        note="35 404s from a real user clicking dead archive links — 4xx rate alone must not convict",
    ))

    cases.append(Case(
        name="mobile_app_api_client",
        label="benign", ip="203.0.113.120",
        lines=[clf("203.0.113.120", t0 + timedelta(seconds=3 * i), f"/api/v1/sync?since={i}", 200, 5000,
                   "MyApp/4.2.1 (iOS 18.1; iPhone15,2)", ref="") for i in range(80)],
        forbid_rules=["SCAN-001", "EXPL-001", "AUTH-001"],
        hard=True,
        note="a first-party mobile client: repetitive API calls with a custom UA",
    ))

    cases.append(Case(
        name="user_with_password_typos",
        label="benign", ip="203.0.113.155",
        lines=[clf("203.0.113.155", t0 + timedelta(seconds=25 * i), "/login?u=me@corp.com", 401, 480,
                   UA_FIREFOX, method="POST") for i in range(4)]
              + [clf("203.0.113.155", t0 + timedelta(seconds=120), "/login?u=me@corp.com", 200, 2048,
                     UA_FIREFOX, method="POST")],
        forbid_rules=["AUTH-002"],
        hard=True,
        note="4 failures then success = human typo, NOT compromise. Threshold must hold.",
    ))

    cases.append(Case(
        name="ci_runner_curl",
        label="benign", ip="203.0.113.200",
        lines=[clf("203.0.113.200", t0 + timedelta(seconds=90 * i), "/api/v1/deploy-status", 200, 300,
                   "curl/8.4.0") for i in range(30)],
        forbid_rules=["SCAN-001", "SCAN-002", "EXPL-001", "BOT-002"],
        hard=True,
        note="curl UA is not a crime; an internal CI job polling status",
    ))

    # ---------------- adversarial: deliberate ambiguity ---------------- #
    cases.append(Case(
        name="low_and_slow_scanner",
        label="suspicious", ip="171.25.193.20",
        lines=[clf("171.25.193.20", t0 + timedelta(seconds=90 * i),
                   p, 404, 280, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0")
               for i, p in enumerate(["/wp-login.php", "/.env", "/admin", "/phpmyadmin/",
                                      "/.git/config", "/backup.zip", "/config.php", "/shell.php"])],
        expect_rules=["SCAN-001"],
        forbid_rules=["RATE-001", "BOT-001"],
        hard=True,
        note="evades rate + UA rules entirely; only path selection betrays it",
    ))

    cases.append(Case(
        name="spoofed_googlebot",
        label="suspicious", ip="45.9.148.37",
        lines=[clf("45.9.148.37", t0 + timedelta(seconds=2 * i),
                   f"/crawl/item/{i}", 200, 25000,
                   "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)") for i in range(90)]
              + [clf("45.9.148.37", t0 + timedelta(seconds=200), "/.env", 404, 300,
                     "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)")],
        expect_rules=["SCAN-001"],
        hard=True,
        note="claims to be Googlebot but probes /.env — UA trust is a trap (no rDNS check exists)",
    ))

    return cases


CASES = build_cases()
