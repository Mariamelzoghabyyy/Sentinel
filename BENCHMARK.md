# Benchmarking Sentinel

## The honest headline

**There is no standard benchmark for this task, and the one I built is small.**

Anyone claiming a number for "bot detection in web logs" is claiming it on a
dataset they chose, usually synthetically. The public options are all flawed
for this use case:

| Dataset | Has URLs? | Has status codes? | Has UA? | Verdict |
|---|---|---|---|---|
| **CIC-IDS2017/2018** | ✗ | ✗ | ✗ | Flow features only. 9 of my 16 rules cannot fire on it. |
| **CSIC 2010** | ✓ | inferred | ✗ | Real HTTP requests — the best public option, but 2010-era and single-source. |
| **NSL-KDD / KDD99** | ✗ | ✗ | ✗ | Superseded, well-known leakage. Don't. |
| **Your own logs** | ✓ | ✓ | ✓ | **The only dataset that actually matters.** Use the review queue. |

So I built a small, honest benchmark (22 hand-written cases) and made the
tools to escape it. Here's what it says and what it can't.

---

## 1. The rules-only baseline

```bash
python3 benchmark/evaluate.py
```

```
cases: 22   hostile/benign: 13/9
PRECISION 100.0%   RECALL 100.0%   F1 1.000
false-positive rate 0.0%   accuracy 100.0%
HARD CASES: 9/9 pass
```

### Read this number with suspicion — I do

**F1 = 1.000 is a red flag, not a trophy.** I wrote the cases, then tuned the
rules until they passed. That is fitting to a test set, and it measures
self-consistency, not real-world skill. A 22-case suite with 9 "hard" cases
has wide confidence intervals and zero protection against the attacks I
didn't think of.

What it *does* legitimately prove: **the rules are self-consistent, and 9
specific failure modes I care about are pinned by tests.** That's regression
protection, which is genuinely valuable — it's just not a capability claim.

### What the benchmark actually found

This is the part I'd point to. Building it surfaced **6 real defects** that
my own sample data had hidden:

| Defect | Type | Fix |
|---|---|---|
| 35 clickable dead links from a real user → flagged as a scanner | **false positive** | 4xx storms concentrated under one path prefix are a broken section, not enumeration |
| Single honeypot hit → P1, same as a full compromise | **design flaw** | Priority became a function of aggregate risk, not worst-rule severity |
| XSS payloads scored 15 → verdict `benign` | under-scoring | graduated exploit scoring: a payload the app **accepted** (2xx) scores +20 over one it rejected |
| 300 req/min landing successfully → still `suspicious` | under-scoring | rate severity scales with magnitude; sustained success adds weight |
| 14-account credential spray at 45s intervals → `benign` | **missed detection** | distinct-identity counting distinguishes spraying from a typo-prone human |
| `/catalogue/page/1..120` walking → missed entirely | **missing rule** | added `SCAN-004` sequential-resource walking |

Two of those were *architecture*, not tuning. The priority one is the best
example: a system can be perfectly accurate per-IP and still be useless if it
escalates a 1-request event to P1.

### Per-rule precision (the number to tune on)

```
BOT-003  (no static assets)   54% precision  ← near-noise; scored 2/100
BOT-002  (metronomic cadence) 62% precision  ← scored 5/100
SCAN-002 (4xx rate)           75%
SCAN-003 (directory enum)     75%
everything else              100% (in this small sample)
```

Low-precision rules are deliberately kept at near-zero weight so they can
corroborate without convicting. That's a design decision the benchmark
justifies — `BOT-003` alone would be a false-positive factory.

---

## 2. LLM-as-judge

```bash
python3 benchmark/judge_eval.py --repeat 3
```

Two judge roles, because they answer different questions:

**Outcome judge** — re-decides each IP from a *judge-blind* bundle (raw request
lines + traffic stats, with rule IDs, risk scores, and the system's verdict
stripped out). Blind because a judge shown the system's conclusion just agrees
with it, which measures nothing.

**Report judge** — grades the generated report on faithfulness, prioritisation,
actionability and calibration against a ground-truth digest, and lists any
**fabricated claims**.

### Without a backend, the judge abstains

```
NOT MEASURED — no LLM backend — judge abstained on every case
22/22 cases abstained.
```

This is the correct behavior and it's deliberate. A judge with no model that
invented verdicts would be worse than useless; a judge that copied the
system's answer would report 100% agreement and mean nothing.

### The metric that matters: kappa, not agreement

The harness reports Cohen's κ alongside raw agreement, because raw agreement
is a vanity metric. Demonstrated in the test suite:

```
always-say-benign judge vs 2/3-benign truth:
  agreement 66.7%   ← looks great
  kappa      0.000  ← "slight", i.e. no information at all
```

**A judge that agrees with the system >95% of the time is a broken judge** —
the harness prints a warning when it sees it. Real judges disagree; that's
what makes their agreement meaningful.

### Calibrating a real judge

Run with a real backend, then check:

| Metric | Healthy range | What a bad value means |
|---|---|---|
| κ vs ground truth | 0.4–0.8 | >0.9 → likely leaking; <0.2 → judge is noise |
| κ vs system | 0.3–0.7 | >0.95 → judge is rubber-stamping |
| self-consistency | ≥0.9 | <0.8 → verdicts are unstable; raise temperature=0 |
| fabrication count | low | any → the report is over-claiming |

I have **not** been able to run this against a real model in this environment.
The plumbing is tested with mock backends; the calibration is not. That's a
gap you should close on day one.

---

## 3. Testing on other datasets

### Public datasets

```bash
# CIC-IDS2017 (realistic but lossy — see the blind-spot warning)
python3 -m benchmark.adapters --dataset cicids2017 --src Friday-WorkingHours.pcap_ISCX.csv --out data/cicids/
python3 benchmark/eval_dataset.py --data data/cicids/

# CSIC 2010 (keeps URLs — the better test for this pipeline)
python3 -m benchmark.adapters --dataset csic2010 --src csic_database/ --out data/csic/
python3 benchmark/eval_dataset.py --data data/csic/
```

Both adapters print exactly what they destroy in translation. The evaluator
then prints **"COULD NOT FIRE"** for rules the source data can't exercise:

```
⚠️  COULD NOT FIRE (source data lacks URLs/status/UA):
   EXPL-001, EXPL-003, EXPL-004, SCAN-003, SCAN-004
   Recall here is a FLOOR, not a ceiling — but also not a valid
   measure of those rules' quality.
```

That warning is the most important line in this document. **A CIC-IDS recall
number tells you almost nothing about Sentinel**, because half the detectors
never got to run. Anyone quoting a single F1 across datasets is hiding this.

### Your own logs — the only dataset that matters

Public datasets are stale, lab-generated, and don't resemble your traffic.
Your logs are current and do. The missing ingredient is labels, so the tool
manufactures them:

```bash
# 1. convert (unlabeled)
python3 -m benchmark.adapters --dataset nginx --src /var/log/nginx/access.log --out data/mine/

# 2. build the review queue — highest risk first, PLUS benign controls
python3 benchmark/review_queue.py --data data/mine/ --build --top 40

# 3. an analyst rules on each: m / s / b / skip
#    the LLM judge pre-fills a suggestion when a backend is configured
python3 benchmark/review_queue.py --data data/mine/ --review

# 4. evaluate against the grown label set
python3 benchmark/eval_dataset.py --data data/mine/
```

The queue deliberately samples the **middle and bottom** of the risk
distribution too, not just the scariest IPs — reviewing only scary IPs tells
you nothing about false positives, which is the failure that destroys trust in
a detection tool.

**30 labeled IPs from your own traffic beats a stale public dataset** for
threshold tuning. Then promote every disagreement into
`benchmark/cases.py` as a permanent regression case.

---

## 4. What this benchmark does not do

Being explicit, because this list is more useful than the F1 number:

- **22 cases is small.** Confidence intervals are wide; I don't report them
  because they'd give false comfort.
- **I wrote both the data and the rules.** Classic circularity. Escaped only
  by running on real logs via the review queue.
- **No evasion testing.** I don't test adversarially-crafted traffic designed
  to fool these specific rules. A real red team would.
- **No temporal evaluation.** Every case is a static window. Drift — where
  today's benign traffic looks like last month's attack — is untested.
- **Judge calibration is unproven.** Mock-tested only.
- **Single-source IPs.** No CDN/NAT traffic where thousands of users share an
  IP; every real deployment has this and it will inflate false positives.

## 5. The metric I'd actually optimize

Not F1. **Analyst minutes saved per true positive, and false positives per
week.** A tool that finds every attacker but generates 40 false alarms a day
gets switched off in a month. That's why the rules are tuned for precision at
the top of the queue, why low-precision rules are scored near zero, and why
`--approve-all` is labelled DEMO ONLY.

Instrument that in production. The benchmark is the floor.
