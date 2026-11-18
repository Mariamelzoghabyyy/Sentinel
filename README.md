# Sentinel 🛰️

**An agentic SOC analyst for web-server logs.** It ingests nginx/Apache access logs, flags bot-like and hostile patterns with auditable rules, has a set of LLM agents investigate each source IP, pauses for human approval before any containment, and writes a handover-ready SOC report.

```bash
python3 -m sentinel samples/access.log --approve-all --out reports/report.md
```

No API key needed. No config. Runs offline in ~1 second.

---

## Why this design

Most "AI for security" demos let the model do detection. That's the wrong split: an LLM can hallucinate an attacker, and you can't appeal to a rule that doesn't exist.

Sentinel inverts it:

| Layer | Does | Why |
|---|---|---|
| **Rules** (14 functions → 18 rule IDs, deterministic) | *Detects.* Rate, cadence, path shape, UA, payload classes. | Auditable, reproducible, testable. Never hallucinates. |
| **Agents** (5, LLM-optional) | *Explains, prioritises, doubts, writes.* | This is where language models actually add value. |
| **Gates** (deterministic) | *Refuses.* Risk floor, action allowlist, human approval. | A model cannot talk its way past a gate. |

Every agent output is validated after the model responds. If a model invents an IP address, requests an `rm -rf`, or reports confidence `4.2`, the validator drops or clamps it and the pipeline continues. **The model is advisory, never authoritative.**

---

## The graph

```
        START
          │
        ingest ────────────── parse CLF / nginx-JSON / .gz, count malformed lines
          │
        detect ────────────── 14 rule functions (18 IDs) → per-IP profiles, risk 0–100
          │
        triage ────────────── TriageAgent: rank, dismiss benign automation
          │
     ┌────┴────┬─────────┐              fan-out: one analyst per escalated IP,
  analyst   analyst   analyst           run in parallel in one superstep
     └────┬────┴─────────┘
       responder ──────────── risk gate (malicious + ≥60), propose containment
          │
       respond ───────────────  ⏸  interrupt() — waits for a human, can sit for hours
          │
        critic ─────────────── adversarial self-review BEFORE the report is written
          │
        report ─────────────── ReportAgent, or the deterministic renderer
          │
       (revise) ────────────── bounded loop, max 2 rounds, only on high-severity issues
          │
         END
```

Five things this shape buys you:

1. **Fan-out** — six investigations run concurrently instead of serially.
2. **`interrupt()`** — a run suspends at the approval gate and resumes exactly where it stopped. State survives in the checkpointer. This is the difference between a demo and something a SOC can use on a night shift.
3. **Critic before report** — the reviewer's findings get incorporated, not stapled on afterwards.
4. **Bounded loop** — `MAX_CRITIC_ROUNDS = 2`, so the graph always terminates.
5. **Deterministic floor** — with no LLM at all, you still get a complete, accurate report.

---

## Quickstart

```bash
cd sentinel
pip install -r requirements.txt

# 1. mixed day: scanner, SQLi, brute-force-then-compromise, scraper, honeypot, flood
python3 -m sentinel samples/access.log --approve-all --out reports/access_report.md

# 2. walk the human approval gate yourself
python3 -m sentinel samples/access.log --interactive

# 3. quiet day — confirms it stays silent when it should
python3 -m sentinel samples/quiet.log

# 4. machine-readable, for CI/cron
python3 -m sentinel samples/incident.log --json | jq .triage

# 5. hand it to a real model
export GROQ_API_KEY=gsk_...        # or OPENAI_API_KEY / ANTHROPIC_API_KEY / OLLAMA_HOST
python3 -m sentinel samples/incident.log --backend groq --out reports/r.md

python3 -m pytest tests/ -q        # 32 tests
```

### Exit codes (wire these into cron/CI)

| Code | Meaning |
|---|---|
| `0` | Clean window |
| `1` | Suspicious activity escalated, nothing confirmed |
| `2` | Confirmed malicious activity |
| `3` | Pipeline error |

```bash
# alert only when something malicious is confirmed
python3 -m sentinel /var/log/nginx/access.log --quiet --out /tmp/r.md || \
  [ $? -eq 2 ] && notify-oncall --attach /tmp/r.md
```

---

## What it detects

| Rule | Catches | Sev |
|---|---|---|
| `BOT-001` | Offensive tooling UAs — sqlmap, nikto, nmap, nuclei, hydra, gobuster, curl… | med/high |
| `BOT-002` | Metronomic cadence (**fast** only — uptime monitors excluded) | low |
| `BOT-003` | No static-asset fetches → headless/scanner profile | low |
| `BOT-004` | Missing/blank UA | low |
| `BOT-005` | UA rotation from a single IP | medium |
| `SCAN-001` | Sensitive-path enumeration (`.env`, `.git`, `wp-login`, `phpmyadmin`…) | med/high |
| `SCAN-002` | 4xx storms — fuzzing | med/high |
| `SCAN-003` | High-novelty path walking — content discovery | medium |
| `SCAN-004` | Sequential resource walking (`/page/1..120`) | medium |
| `EXPL-001` | Path traversal | high |
| `EXPL-002` | SQL injection payloads | **critical** |
| `EXPL-003` | XSS payloads | medium |
| `EXPL-004` | OS command injection | **critical** |
| `AUTH-001` | Brute force / password spray (peak in 5-min window) | med/high |
| `AUTH-002` | **Success after a failure burst** → account compromise | **critical** |
| `HONEY-001` | Honeypot path touched → zero-false-positive bot | high |
| `RATE-001` | Sustained ≥120 req/min (a human can't) | med/high |

Rules emit **evidence strings**, not just booleans — every claim in the report is traceable to a log line.

---

## The safety gates

These are the parts I'd want reviewed before this touched a real network:

```python
# 1. Action allowlist — the model cannot invent an action
ALLOWED_ACTIONS = {block_ip, rate_limit_ip, tarpit_ip, block_user_agent,
                   force_logout, reset_credentials, waf_virtual_patch,
                   open_ticket, monitor}

# 2. Evidence contract — no credential action without auth evidence
if act in {"force_logout", "reset_credentials"} and profile["auth_failures"] == 0:
    continue

# 3. Risk gate — nothing auto-actions below malicious + risk ≥ 60
def gate(self, profile): return profile["verdict"] == "malicious" and profile["risk_score"] >= 60

# 4. Priority clamp — the model may raise alarm only as far as evidence allows
if risk < 20:            prio = "P4"
elif risk < 60 and not malicious and prio in {"P1","P2"}: prio = "P3"

# 5. Human approval — interrupt() before execution, always
# 6. Executor is dry-run: emits 'would_call: edge-api://...' plans, touches nothing
```

Tests assert each of these. Verify them yourself:

```bash
python3 -m pytest tests/ -q -k "gate or rejects or hallucinated or clamp"
```

---

## The report

Five sections, written for someone with 60 seconds: **executive summary → priority queue → detailed findings → dismissed/false-positives → coverage gaps → next-shift actions**. It also carries the critic's own review, and admits its limits (parse rate, behavioural-only detection, no geo/ASN reputation).

Sample output in [`reports/access_report.md`](reports/access_report.md) — real output from the sample data, not a mockup.

Notable detail: when brute-force succeeds, the pipeline attributes **which identity** was compromised (set as the session's `u=`/`email=` param) and pivots the response to `force_logout` + `reset_credentials` on that account — not a vague "block the IP".

---

## Using real data

```bash
# nginx: default combined format — works as-is
python3 -m sentinel /var/log/nginx/access.log

# nginx JSON logs — auto-detected
python3 -m sentinel /var/log/nginx/access.jsonl

# rotated/compressed — transparently handled
python3 -m sentinel /var/log/nginx/access.log.2.gz

# rotate over a day's files
python3 -m sentinel /var/log/nginx/access.log-$(date +%Y%m%d) --approve-all --out reports/daily.md
```

Supported timestamp formats: Apache `[10/Oct/2000:13:55:36 -0700]` and nginx ISO-8601. All times normalised to UTC before rate math, so timezone shifts can't create fake bursts.

**Malformed lines never crash the run** — they're counted, sampled, and surfaced in the report's coverage-gaps section, because silent data loss is the classic reason analysts trust a tool once and never again.

---

## Benchmarking (and its honest limits)

```bash
python3 benchmark/evaluate.py                        # rules-only baseline, 22 labelled cases
python3 benchmark/judge_eval.py --repeat 3           # LLM-as-judge agreement + kappa
python3 -m benchmark.adapters --list                 # dataset converters
python3 benchmark/review_queue.py --data data/mine/ --build --review
```

**Current baseline: precision 100%, recall 100%, F1 1.000 on 22 cases — and you should distrust that number.** I wrote the cases and then tuned the rules against them; it measures self-consistency, not skill. What it legitimately proves is that 9 specific failure modes are pinned by tests.

Building it found 6 real defects my sample data had hidden — including two architectural ones:

- **35 clickable dead links** from a real user were flagged as a scanner → 4xx storms concentrated under one path prefix are a broken section, not enumeration
- **Priority was derived from the single worst rule severity**, so one honeypot request with zero impact escalated to P1, identical to a confirmed credential compromise → priority is now a monotone function of aggregate risk
- 14-account credential spray at 45s intervals scored `benign` → distinct-identity counting
- `/catalogue/page/1..120` walking was missed entirely → added `SCAN-004`
- XSS payloads the app **accepted** scored the same as ones it rejected → status-aware exploit scoring
- A 300 req/min flood landing successfully stayed `suspicious` → magnitude-scaled rate severity

Per-rule precision is exposed so you can see which rules are noise: `BOT-003` is 54% and `BOT-002` is 62%, so both are scored at 2–5/100 and can only corroborate.

See **[BENCHMARK.md](BENCHMARK.md)** for dataset adapters (CIC-IDS, CSIC 2010, your own logs), the review-queue workflow that turns real traffic into ground truth, and the LLM-judge calibration guide.

### Testing on other datasets

No public bot-detection dataset ships in CLF, so converters are mandatory:

```bash
python3 -m benchmark.adapters --dataset csic2010 --src csic/ --out data/csic/
python3 benchmark/eval_dataset.py --data data/csic/
```

Every adapter states what it destroys in translation, and the evaluator prints a **"COULD NOT FIRE"** warning listing rules the source data cannot exercise. A CIC-IDS recall number tells you almost nothing here, because 9 of 18 rules never get to run.

---

## Project layout

```
sentinel/
├── sentinel/
│   ├── graph.py      # LangGraph: fan-out, interrupt, critic loop
│   ├── agents.py     # 5 agents + post-response validators
│   ├── rules.py      # 13 deterministic detections
│   ├── parser.py     # CLF + nginx-JSON + gzip, resilient
│   ├── render.py     # deterministic report (the no-LLM floor)
│   ├── judge.py      # LLM-as-judge: blind outcome judge + report judge
│   ├── llm.py        # Groq/OpenAI/Anthropic/Ollama/local + JSON salvage
│   ├── models.py     # dataclasses + graph state
│   └── cli.py        # CLI, approval UX, exit codes
├── benchmark/        # labelled cases, dataset adapters, judge eval
├── samples/          # synthetic but realistic logs, 3 scenarios
├── scripts/make_samples.py
├── tests/            # 32 tests on parsing, detection, and every gate
└── reports/
```

---

## Design decisions I'd defend in review

**Rules detect, agents reason.** Non-negotiable. An LLM deciding whether traffic is malicious is un-auditable; an LLM explaining *why a rule fired, in context, with a false-positive check* is genuinely useful.

**Human approval is a first-class state, not a prompt.** `interrupt()` means the approval can take 8 hours without holding a process open.

**Every LLM response is validated, never trusted.** Hallucinated IPs are dropped, out-of-range confidence is clamped, disallowed actions are removed, malformed JSON falls back to heuristics. The pipeline cannot be broken by a bad model — worst case it degrades to deterministic mode.

**Fix the false positives you find, in the open.** Building this, my own cadence rule flagged every uptime monitor. The fix is in `rule_fixed_interval`, and there's a test pinning both behaviours.

## Known limitations

- **Behavioural only.** A single clean request cannot be flagged, by design.
- **No reputation data.** No GeoIP, ASN, or threat feeds — deliberately offline. Wire `enrich_ip()` in `detect` to MaxMind/AbuseIPDB if you want it.
- **No state between runs.** Each window is independent; slow-and-low attackers who stay under thresholds across hours need the multi-window correlation stage this doesn't have yet.
- **Single-hop IPs.** `X-Forwarded-For` chains behind a load balancer are not unwound — point it at logs from the *edge*, not the origin, or add the CDN's real-IP header.
- **Not tested at volume.** Benchmarked at ~3k lines; a design goal is 10M/day, unproven.

The obvious next moves: multi-window baselining, feed the profiles to a live WAF API instead of the dry-run executor, and per-tenant thresholds.
