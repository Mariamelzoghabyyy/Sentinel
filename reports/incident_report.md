# Sentinel — SOC Triage Report

**Window:** `2026-11-18T06:00:02` → `2026-11-18T09:11:38` · **Log lines:** 2,496 parsed (0 malformed, format `combined`) · **IPs:** 58 · **Flagged:** 4 (4 malicious)

## Executive summary

- **4 malicious IP(s)** confirmed; highest risk `91.240.118.9` (risk 100/100) — AUTH-002 Successful auth after failure burst (possible account compromise); AUTH-001 Credential brute force / password spraying
- 3 P1 item(s) require immediate attention: `91.240.118.9`, `185.220.101.44`, `45.133.1.77`
- Containment: 4 approved · 0 deferred · 0 below the auto-action gate.

## Priority queue

| Priority | IP | Verdict | Risk | Why |
|---|---|---|---|---|
| 🚨 P1 | `91.240.118.9` | **MALICIOUS** | 100 | AUTH-002 Successful auth after failure burst (possible account compromise); AUTH-001 Credential brute force / password s |
| 🚨 P1 | `185.220.101.44` | **MALICIOUS** | 100 | EXPL-002 SQL injection payload; BOT-001 Offensive-tool user agent |
| 🚨 P1 | `45.133.1.77` | **MALICIOUS** | 97 | BOT-001 Offensive-tool user agent; SCAN-001 Sensitive-path enumeration |
| 🟠 P2 | `103.21.244.8` | **MALICIOUS** | 68 | RATE-001 Burst request rate inconsistent with humans; BOT-001 Automation HTTP client user agent |

## Detailed findings

### `91.240.118.9` — P1 · risk 100/100 · confidence 95%

91.240.118.9 made 55 requests in 687s (2 unique paths, peak 12 req/min). Deterministic detection fired on: AUTH-002 (Successful auth after failure burst (possible account compromise)), AUTH-001 (Credential brute force / password spraying), SCAN-002 (High 4xx rate (fuzzing / enumeration)). Raw evidence includes 48 failures before first 200 at 2026-11-18T09:06:09 (/login?u=svc_billing). The combination of critical-severity signals yields risk score 100/100 → malicious.

**False-positive check.** Plausible innocents: a monitoring/uptime probe or a sanctioned crawler. That explanation is insufficient here because the UA/cadence pair is machine-regular and paths target sensitive locations.

| Rule | Severity | Evidence |
|---|---|---|
| `BOT-001` Automation HTTP client user agent | ⚪ low | 55 request(s) with automation UA token 'python-requests' |
| `AUTH-001` Credential brute force / password spraying | 🟠 high | 48 failed auth response(s) against 1 endpoint(s) (/login)<br>peak 44 failures within 5 minutes<br>43 distinct identities targeted — spray pattern |
| `AUTH-002` Successful auth after failure burst (possible account compromise) | 🔴 critical | 48 failures before first 200 at 2026-11-18T09:06:09 (/login?u=svc_billing) |
| `SCAN-002` High 4xx rate (fuzzing / enumeration) | 🟡 medium | 48/55 requests were 4xx (87%); status mix 401:48<br>4xx spread across unrelated paths (top prefix = 4% of traffic) |
| `BOT-003` No static-asset fetches (headless/scanner profile) | ⚪ low | 0/55 requests were static assets (0.0%) |

**Traffic:** 55 requests over 687s · peak 12 req/min · 2 unique paths · 48 4xxs · 48 auth failures
**Identity at risk:** `svc_billing` (successful auth after failures)
**ATT&CK:** T1078 Valid Accounts, T1110.001 Password Guessing, T1595 Active Scanning, T1593 Search Open Websites, T1592 Gather Victim Host Information
**Next steps:**
1. Revoke sessions for the affected account and force a credential reset; review post-login activity.
2. Pull IdP logs for the auth endpoint and confirm no account was locked/enabled unexpectedly.
3. Confirm catch-all 404 handling is cheap and nothing sensitive returns 200.

### `185.220.101.44` — P1 · risk 100/100 · confidence 95%

185.220.101.44 made 18 requests in 800s (3 unique paths, peak 2 req/min). Deterministic detection fired on: EXPL-002 (SQL injection payload), BOT-001 (Offensive-tool user agent), BOT-003 (No static-asset fetches (headless/scanner profile)). Raw evidence includes GET /search?q=1%27%20OR%20%271%27%3D%271 -> 200. The combination of critical-severity signals yields risk score 100/100 → malicious.

**False-positive check.** Plausible innocents: a monitoring/uptime probe or a sanctioned crawler. That explanation is insufficient here because hostile payloads were observed in request paths, which no monitor sends.

| Rule | Severity | Evidence |
|---|---|---|
| `BOT-001` Offensive-tool user agent | 🟠 high | 9 request(s) with automation UA token 'sqlmap'<br>offensive tooling present: sqlmap |
| `EXPL-002` SQL injection payload | 🔴 critical | GET /search?q=1%27%20OR%20%271%27%3D%271 -> 200<br>GET /search?q=1%20UNION%20SELECT%20username,password%20FROM%20users-- -> 200<br>GET /product?id=1%20AND%20SLEEP(5) -> 500 |
| `BOT-003` No static-asset fetches (headless/scanner profile) | ⚪ low | 0/18 requests were static assets (0.0%) |

**Traffic:** 18 requests over 800s · peak 2 req/min · 3 unique paths · 0 4xxs · 0 auth failures
**ATT&CK:** T1190 Exploit Public-Facing Application, T1595 Active Scanning, T1592 Gather Victim Host Information
**Next steps:**
1. Verify parameterised queries on the targeted endpoint; inspect DB error/alerting for injection artefacts.

### `45.133.1.77` — P1 · risk 97/100 · confidence 94%

45.133.1.77 made 70 requests in 44s (15 unique paths, peak 70 req/min). Deterministic detection fired on: BOT-001 (Offensive-tool user agent), SCAN-001 (Sensitive-path enumeration), SCAN-002 (High 4xx rate (fuzzing / enumeration)). Raw evidence includes 70 request(s) with automation UA token 'nmap'. The combination of high-severity signals yields risk score 97/100 → malicious.

**False-positive check.** Plausible innocents: a monitoring/uptime probe or a sanctioned crawler. That explanation is insufficient here because the UA/cadence pair is machine-regular and paths target sensitive locations.

| Rule | Severity | Evidence |
|---|---|---|
| `BOT-001` Offensive-tool user agent | 🟠 high | 70 request(s) with automation UA token 'nmap'<br>offensive tooling present: nmap |
| `SCAN-001` Sensitive-path enumeration | 🟠 high | 65 request(s) to 14 sensitive path(s), e.g. /.aws/credentials, /.env, /.git/config, /actuator/env<br>93% of this IP's unique paths are scanner targets (broad sweep) |
| `SCAN-002` High 4xx rate (fuzzing / enumeration) | 🟠 high | 65/70 requests were 4xx (93%); status mix 404:65<br>4xx spread across unrelated paths (top prefix = 8% of traffic) |
| `BOT-002` Machine-regular request cadence | ⚪ low | 70 requests, median gap 1.0s with MAD 0.00s (jitter 0.0%) — faster and more regular than human clicking |
| `BOT-003` No static-asset fetches (headless/scanner profile) | ⚪ low | 0/70 requests were static assets (0.0%) |

**Traffic:** 70 requests over 44s · peak 70 req/min · 15 unique paths · 65 4xxs · 0 auth failures
**ATT&CK:** T1595 Active Scanning, T1595.002 Vulnerability Scanning, T1071 Application Layer Protocol, T1592 Gather Victim Host Information
**Next steps:**
1. Confirm WAF virtual-patch is covering the enumerated paths.
2. Confirm catch-all 404 handling is cheap and nothing sensitive returns 200.

### `103.21.244.8` — P2 · risk 68/100 · confidence 82%

103.21.244.8 made 2000 requests in 240s (1 unique path, peak 509 req/min). Deterministic detection fired on: RATE-001 (Burst request rate inconsistent with humans), BOT-001 (Automation HTTP client user agent), BOT-002 (Machine-regular request cadence). Raw evidence includes peak 509 req/min from this IP (8.5 req/s sustained). The combination of high-severity signals yields risk score 68/100 → malicious.

**False-positive check.** Plausible innocents: a monitoring/uptime probe or a sanctioned crawler. That explanation is insufficient here because the UA/cadence pair is machine-regular and paths target sensitive locations.

| Rule | Severity | Evidence |
|---|---|---|
| `BOT-001` Automation HTTP client user agent | ⚪ low | 2000 request(s) with automation UA token 'go-http-client' |
| `RATE-001` Burst request rate inconsistent with humans | 🟠 high | peak 509 req/min from this IP (8.5 req/s sustained)<br>100% of the burst succeeded — the flood is landing and consuming capacity |
| `BOT-002` Machine-regular request cadence | ⚪ low | 2000 requests, median gap 1.0s with MAD 0.00s (jitter 0.0%) — faster and more regular than human clicking |
| `BOT-003` No static-asset fetches (headless/scanner profile) | ⚪ low | 0/2000 requests were static assets (0.0%) |

**Traffic:** 2,000 requests over 240s · peak 509 req/min · 1 unique path · 0 4xxs · 0 auth failures
**ATT&CK:** T1498 Network DoS (potential), T1593 Search Open Websites, T1071 Application Layer Protocol, T1592 Gather Victim Host Information
**Next steps:**
1. Verify rate limiting at the edge and whether the burst degraded latency for others.

## False positives / dismissed

_None dismissed._

## Response actions

- `91.240.118.9` — ✅ approved
  - `block_ip` → 91.240.118.9 (immediate) — Risk 100/100 with AUTH-001, AUTH-002, BOT-001.
  - `rate_limit_ip` → 91.240.118.9 (immediate) — Volumetric/4xx burst — rate limit absorbs the flood cheaply.
  - `force_logout` → svc_billing (immediate) — Successful auth after failure burst — session may be attacker-controlled.
  - `reset_credentials` → svc_billing (immediate) — Same evidence; rotate credentials after logout.
  - `open_ticket` → SOC queue (hours) — Track containment and follow-up verification.
- `185.220.101.44` — ✅ approved
  - `block_ip` → 185.220.101.44 (immediate) — Risk 100/100 with BOT-001, BOT-003, EXPL-002.
  - `waf_virtual_patch` → 185.220.101.44 (immediate) — Hostile payload class observed; virtual-patch blocks the pattern fleet-wide, not just this IP.
  - `open_ticket` → SOC queue (hours) — Track containment and follow-up verification.
- `45.133.1.77` — ✅ approved
  - `block_ip` → 45.133.1.77 (immediate) — Risk 97/100 with BOT-001, BOT-002, BOT-003.
  - `rate_limit_ip` → 45.133.1.77 (immediate) — Volumetric/4xx burst — rate limit absorbs the flood cheaply.
  - `open_ticket` → SOC queue (hours) — Track containment and follow-up verification.
- `103.21.244.8` — ✅ approved
  - `block_ip` → 103.21.244.8 (immediate) — Risk 68/100 with BOT-001, BOT-002, BOT-003.
  - `rate_limit_ip` → 103.21.244.8 (immediate) — Volumetric/4xx burst — rate limit absorbs the flood cheaply.
  - `open_ticket` → SOC queue (hours) — Track containment and follow-up verification.

## Coverage gaps & limitations

- Detection is behavioural (rate, cadence, path and UA shape); single-request attacks with a clean profile can be missed.
- Geo/ASN reputation is not consulted; a residential IP behaving like a bot is still flagged, which is intentional.
- Response actions are dry-run plans only; enforcement lives in your edge layer.

## Automated critic review

_Heuristic consistency review only; no model available._

- **[LOW]** Deterministic cross-check found no inconsistencies. — _None required._

## Recommended next shift actions

- `91.240.118.9` (P1): Revoke sessions for the affected account and force a credential reset; review post-login activity.
- `185.220.101.44` (P1): Verify parameterised queries on the targeted endpoint; inspect DB error/alerting for injection artefacts.
- `45.133.1.77` (P1): Confirm WAF virtual-patch is covering the enumerated paths.
- `103.21.244.8` (P2): Verify rate limiting at the edge and whether the burst degraded latency for others.

<details><summary>Rule hit distribution</summary>

| Rule | IPs triggering |
|---|---|
| `BOT-001` | 4 |
| `BOT-003` | 4 |
| `SCAN-002` | 2 |
| `BOT-002` | 2 |
| `AUTH-001` | 1 |
| `AUTH-002` | 1 |
| `EXPL-002` | 1 |
| `SCAN-001` | 1 |
| `RATE-001` | 1 |

</details>

---
*Generated by Sentinel · backend `local` · detection rules v1 · all containment actions are proposals until human approval.*