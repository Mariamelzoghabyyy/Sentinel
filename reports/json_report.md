# Sentinel — SOC Triage Report

**Window:** `2026-11-18T06:00:19` → `2026-11-18T14:01:33` · **Log lines:** 3,034 parsed (0 malformed, format `json`) · **IPs:** 61 · **Flagged:** 6 (3 malicious)

## Executive summary

- **3 malicious IP(s)** confirmed; highest risk `91.240.118.9` (risk 100/100) — AUTH-002 Successful auth after failure burst (possible account compromise); AUTH-001 Credential brute force / password spraying
- 2 P1 item(s) require immediate attention: `91.240.118.9`, `185.220.101.44`
- Containment: 3 approved · 0 deferred · 3 below the auto-action gate.

## Priority queue

| Priority | IP | Verdict | Risk | Why |
|---|---|---|---|---|
| 🚨 P1 | `91.240.118.9` | **MALICIOUS** | 100 | AUTH-002 Successful auth after failure burst (possible account compromise); AUTH-001 Credential brute force / password s |
| 🚨 P1 | `185.220.101.44` | **MALICIOUS** | 85 | EXPL-002 SQL injection payload; BOT-001 Automation / offensive-tool user agent |
| 🟠 P2 | `45.133.1.77` | **MALICIOUS** | 100 | BOT-001 Automation / offensive-tool user agent; SCAN-001 Sensitive-path enumeration |
| 🟠 P2 | `103.21.244.8` | _suspicious_ | 58 | RATE-001 Burst request rate inconsistent with humans; BOT-001 Automation / offensive-tool user agent |
| 🟠 P2 | `5.188.206.14` | _suspicious_ | 50 | HONEY-001 Honeypot path touched (high-confidence bot); BOT-001 Automation / offensive-tool user agent |
| 🟡 P3 | `77.88.55.20` | _suspicious_ | 43 | SCAN-003 Directory/content enumeration; BOT-005 User-agent rotation from one IP |

## Detailed findings

### `91.240.118.9` — P1 · risk 100/100 · confidence 95%

91.240.118.9 made 55 requests in 687s (2 unique paths, peak 10 req/min). Deterministic detection fired on: AUTH-002 (Successful auth after failure burst (possible account compromise)), AUTH-001 (Credential brute force / password spraying), BOT-001 (Automation / offensive-tool user agent). Raw evidence includes 48 failures before first 200 at 2026-11-18T09:06:16 (/login?u=svc_billing). The combination of critical-severity signals yields risk score 100/100 → malicious.

**False-positive check.** Plausible innocents: a monitoring/uptime probe or a sanctioned crawler. That explanation is insufficient here because the UA/cadence pair is machine-regular and paths target sensitive locations.

| Rule | Severity | Evidence |
|---|---|---|
| `BOT-001` Automation / offensive-tool user agent | 🟡 medium | 55 request(s) with automation UA token 'python-requests' |
| `AUTH-001` Credential brute force / password spraying | 🟠 high | 48 failed auth response(s) against 1 endpoint(s) (/login)<br>peak 41 failures within 5 minutes |
| `AUTH-002` Successful auth after failure burst (possible account compromise) | 🔴 critical | 48 failures before first 200 at 2026-11-18T09:06:16 (/login?u=svc_billing) |
| `SCAN-002` High 4xx rate (fuzzing / enumeration) | 🟡 medium | 48/55 requests were 4xx (87%); status mix 401:48 |
| `BOT-003` No static-asset fetches (headless/scanner profile) | ⚪ low | 0/55 requests were static assets (0.0%) |

**Traffic:** 55 requests over 687s · peak 10 req/min · 2 unique paths · 48 4xxs · 48 auth failures
**Identity at risk:** `svc_billing` (successful auth after failures)
**ATT&CK:** T1078 Valid Accounts, T1110.001 Password Guessing, T1593 Search Open Websites, T1595 Active Scanning, T1592 Gather Victim Host Information
**Next steps:**
1. Revoke sessions for the affected account and force a credential reset; review post-login activity.
2. Pull IdP logs for the auth endpoint and confirm no account was locked/enabled unexpectedly.
3. Confirm catch-all 404 handling is cheap and nothing sensitive returns 200.

### `185.220.101.44` — P1 · risk 85/100 · confidence 89%

185.220.101.44 made 18 requests in 939s (3 unique paths, peak 3 req/min). Deterministic detection fired on: EXPL-002 (SQL injection payload), BOT-001 (Automation / offensive-tool user agent), BOT-003 (No static-asset fetches (headless/scanner profile)). Raw evidence includes GET /search?q=1%27%20OR%20%271%27%3D%271 -> 200. The combination of critical-severity signals yields risk score 85/100 → malicious.

**False-positive check.** Plausible innocents: a monitoring/uptime probe or a sanctioned crawler. That explanation is insufficient here because hostile payloads were observed in request paths, which no monitor sends.

| Rule | Severity | Evidence |
|---|---|---|
| `BOT-001` Automation / offensive-tool user agent | 🟠 high | 9 request(s) with automation UA token 'sqlmap' |
| `EXPL-002` SQL injection payload | 🔴 critical | GET /search?q=1%27%20OR%20%271%27%3D%271 -> 200<br>GET /search?q=1%20UNION%20SELECT%20username,password%20FROM%20users-- -> 200<br>GET /product?id=1%20AND%20SLEEP(5) -> 500 |
| `BOT-003` No static-asset fetches (headless/scanner profile) | ⚪ low | 0/18 requests were static assets (0.0%) |

**Traffic:** 18 requests over 939s · peak 3 req/min · 3 unique paths · 0 4xxs · 0 auth failures
**ATT&CK:** T1190 Exploit Public-Facing Application, T1595 Active Scanning, T1592 Gather Victim Host Information
**Next steps:**
1. Verify parameterised queries on the targeted endpoint; inspect DB error/alerting for injection artefacts.

### `45.133.1.77` — P2 · risk 100/100 · confidence 95%

45.133.1.77 made 70 requests in 43s (15 unique paths, peak 70 req/min). Deterministic detection fired on: BOT-001 (Automation / offensive-tool user agent), SCAN-001 (Sensitive-path enumeration), SCAN-002 (High 4xx rate (fuzzing / enumeration)). Raw evidence includes 70 request(s) with automation UA token 'nmap'. The combination of high-severity signals yields risk score 100/100 → malicious.

**False-positive check.** Plausible innocents: a monitoring/uptime probe or a sanctioned crawler. That explanation is insufficient here because the UA/cadence pair is machine-regular and paths target sensitive locations.

| Rule | Severity | Evidence |
|---|---|---|
| `BOT-001` Automation / offensive-tool user agent | 🟠 high | 70 request(s) with automation UA token 'nmap' |
| `SCAN-001` Sensitive-path enumeration | 🟠 high | 65 request(s) to 14 sensitive path(s), e.g. /.aws/credentials, /.env, /.git/config, /actuator/env<br>93% of this IP's unique paths are scanner targets (broad sweep) |
| `SCAN-002` High 4xx rate (fuzzing / enumeration) | 🟠 high | 65/70 requests were 4xx (93%); status mix 404:65 |
| `BOT-002` Machine-regular request cadence | ⚪ low | 70 requests, median gap 1.0s with MAD 0.00s (jitter 0.0%) — faster and more regular than human clicking |
| `BOT-003` No static-asset fetches (headless/scanner profile) | ⚪ low | 0/70 requests were static assets (0.0%) |

**Traffic:** 70 requests over 43s · peak 70 req/min · 15 unique paths · 65 4xxs · 0 auth failures
**ATT&CK:** T1595 Active Scanning, T1595.002 Vulnerability Scanning, T1071 Application Layer Protocol, T1592 Gather Victim Host Information
**Next steps:**
1. Confirm WAF virtual-patch is covering the enumerated paths.
2. Confirm catch-all 404 handling is cheap and nothing sensitive returns 200.

### `103.21.244.8` — P2 · risk 58/100 · confidence 83%

103.21.244.8 made 600 requests in 120s (1 unique path, peak 305 req/min). Deterministic detection fired on: RATE-001 (Burst request rate inconsistent with humans), BOT-001 (Automation / offensive-tool user agent), BOT-002 (Machine-regular request cadence). Raw evidence includes peak 305 req/min from this IP. The combination of high-severity signals yields risk score 58/100 → suspicious.

**False-positive check.** Plausible innocents: a monitoring/uptime probe or a sanctioned crawler. That explanation is insufficient here because the UA/cadence pair is machine-regular and paths target sensitive locations.

| Rule | Severity | Evidence |
|---|---|---|
| `BOT-001` Automation / offensive-tool user agent | 🟡 medium | 600 request(s) with automation UA token 'go-http-client' |
| `RATE-001` Burst request rate inconsistent with humans | 🟠 high | peak 305 req/min from this IP |
| `BOT-002` Machine-regular request cadence | ⚪ low | 600 requests, median gap 1.0s with MAD 0.00s (jitter 0.0%) — faster and more regular than human clicking |
| `BOT-003` No static-asset fetches (headless/scanner profile) | ⚪ low | 0/600 requests were static assets (0.0%) |

**Traffic:** 600 requests over 120s · peak 305 req/min · 1 unique path · 0 4xxs · 0 auth failures
**ATT&CK:** T1498 Network DoS (potential), T1593 Search Open Websites, T1071 Application Layer Protocol, T1592 Gather Victim Host Information
**Next steps:**
1. Verify rate limiting at the edge and whether the burst degraded latency for others.

### `5.188.206.14` — P2 · risk 50/100 · confidence 75%

5.188.206.14 made 2 requests in 40s (2 unique paths, peak 2 req/min). Deterministic detection fired on: HONEY-001 (Honeypot path touched (high-confidence bot)), BOT-001 (Automation / offensive-tool user agent), SCAN-001 (Sensitive-path enumeration). Raw evidence includes GET /admin-prod-do-not-exist.php -> 404. The combination of high-severity signals yields risk score 50/100 → suspicious.

**False-positive check.** Plausible innocents: a monitoring/uptime probe or a sanctioned crawler. That explanation is insufficient here because the UA/cadence pair is machine-regular and paths target sensitive locations.

| Rule | Severity | Evidence |
|---|---|---|
| `BOT-001` Automation / offensive-tool user agent | 🟡 medium | 2 request(s) with automation UA token 'curl/' |
| `SCAN-001` Sensitive-path enumeration | ⚪ low | 1 request(s) to 1 sensitive path(s), e.g. /admin-prod-do-not-exist.php |
| `HONEY-001` Honeypot path touched (high-confidence bot) | 🟠 high | GET /admin-prod-do-not-exist.php -> 404<br>GET /honeypot/trap -> 404 |

**Traffic:** 2 requests over 40s · peak 2 req/min · 2 unique paths · 2 4xxs · 0 auth failures
**ATT&CK:** T1595 Active Scanning, T1593 Search Open Websites, T1595.002 Vulnerability Scanning
**Next steps:**
1. Honeypot hit is a high-fidelity bot indicator — safe to feed the IP into edge blocklists.
2. Confirm WAF virtual-patch is covering the enumerated paths.

### `77.88.55.20` — P3 · risk 43/100 · confidence 68%

77.88.55.20 made 120 requests in 617s (120 unique paths, peak 12 req/min). Deterministic detection fired on: SCAN-003 (Directory/content enumeration), BOT-005 (User-agent rotation from one IP), BOT-002 (Machine-regular request cadence). Raw evidence includes 120 unique paths over 120 requests (100% novel). The combination of medium-severity signals yields risk score 43/100 → suspicious.

**False-positive check.** Plausible innocents: a monitoring/uptime probe or a sanctioned crawler. That explanation is insufficient here because the request cadence and path selection match tooled enumeration rather than a curated probe.

| Rule | Severity | Evidence |
|---|---|---|
| `SCAN-003` Directory/content enumeration | 🟡 medium | 120 unique paths over 120 requests (100% novel)<br>extension spread: extensionless paths |
| `BOT-002` Machine-regular request cadence | ⚪ low | 120 requests, median gap 5.0s with MAD 0.00s (jitter 0.0%) — faster and more regular than human clicking |
| `BOT-003` No static-asset fetches (headless/scanner profile) | ⚪ low | 0/120 requests were static assets (0.0%) |
| `BOT-005` User-agent rotation from one IP | 🟡 medium | 12 distinct UAs, e.g. Mozilla/5.0 (compatible; Bot/0.9; +http://bots.example.net) \| Mozilla/5.0 (compatible; Bot/1.6; +http://bots.example.net) \| Mozilla/5.0 (compatible; B |

**Traffic:** 120 requests over 617s · peak 12 req/min · 120 unique paths · 0 4xxs · 0 auth failures
**ATT&CK:** T1083 File and Directory Discovery, T1036 Masquerading, T1071 Application Layer Protocol, T1592 Gather Victim Host Information
**Next steps:**
1. Check for content exposure behind the enumerated paths (backups, configs).
2. UA rotation suggests evasion tooling; treat any single UA as untrustworthy for this IP.

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
  - `block_ip` → 185.220.101.44 (immediate) — Risk 85/100 with BOT-001, BOT-003, EXPL-002.
  - `waf_virtual_patch` → 185.220.101.44 (immediate) — Hostile payload class observed; virtual-patch blocks the pattern fleet-wide, not just this IP.
  - `open_ticket` → SOC queue (hours) — Track containment and follow-up verification.
- `45.133.1.77` — ✅ approved
  - `block_ip` → 45.133.1.77 (immediate) — Risk 100/100 with BOT-001, BOT-002, BOT-003.
  - `rate_limit_ip` → 45.133.1.77 (immediate) — Volumetric/4xx burst — rate limit absorbs the flood cheaply.
  - `open_ticket` → SOC queue (hours) — Track containment and follow-up verification.
- `103.21.244.8` — **gated** (risk_score 58 / verdict suspicious is below the auto-action gate (needs malicious + ≥60).)
- `5.188.206.14` — **gated** (risk_score 50 / verdict suspicious is below the auto-action gate (needs malicious + ≥60).)
- `77.88.55.20` — **gated** (risk_score 43 / verdict suspicious is below the auto-action gate (needs malicious + ≥60).)

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
- `45.133.1.77` (P2): Confirm WAF virtual-patch is covering the enumerated paths.
- `103.21.244.8` (P2): Verify rate limiting at the edge and whether the burst degraded latency for others.

<details><summary>Rule hit distribution</summary>

| Rule | IPs triggering |
|---|---|
| `BOT-001` | 5 |
| `BOT-003` | 5 |
| `BOT-002` | 3 |
| `SCAN-001` | 2 |
| `SCAN-002` | 2 |
| `AUTH-001` | 1 |
| `AUTH-002` | 1 |
| `EXPL-002` | 1 |
| `RATE-001` | 1 |
| `HONEY-001` | 1 |
| `SCAN-003` | 1 |
| `BOT-005` | 1 |

</details>

---
*Generated by Sentinel · backend `local` · detection rules v1 · all containment actions are proposals until human approval.*