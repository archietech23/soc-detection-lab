# Detection: Password Spray — Single Source, Many Accounts (4625)

| | |
|---|---|
| **Detection ID** | `win-password-spray-4625` |
| **ATT&CK** | [T1110.003 — Brute Force: Password Spraying](https://attack.mitre.org/techniques/T1110/003/) |
| **Tactic** | Credential Access |
| **Data source** | Windows Security log (DC), Event 4625 — An account failed to log on |
| **Log path** | `index=wineventlog` / `sourcetype=WinEventLog:Security` |
| **Fidelity** | Medium |
| **Severity** | Medium (escalate to High if followed by a 4624 success from the same source) |
| **Status** | Production (fan-out rule) |

---

## Hypothesis

Password spraying inverts the classic brute force. Instead of many passwords
against one account (which trips lockout), the adversary tries **one common
password against many accounts** — low-and-slow, staying under per-account
lockout thresholds. The distinguishing signature is therefore **fan-out**: a
single source generating authentication failures across many *distinct* accounts
within a short window.

This detection groups failed logons (4625) by source and time window and alerts
when one source fails against a threshold number of distinct accounts. It keys on
the *shape* of the activity (one-to-many), not on any single failure — a single
4625 is normal; twenty accounts failing from one host in five minutes is not.

---

## 4625 Sub_Status reference (failure reasons)

| Sub_Status | Meaning | Relevance |
|---|---|---|
| 0xC0000064 | User name does not exist | **Enumeration**, not spray |
| **0xC000006A** | **User exists, wrong password** | **Spray signature** — valid users, one bad password |
| 0xC0000234 | Account locked out | Possible lockout storm |
| 0xC0000072 | Account disabled | Noise |
| 0xC0000071 | Password expired | Noise / post-reset |

The refined variant below filters on **0xC000006A** to isolate the true spray
signature (valid accounts, wrong password) from user-enumeration noise.

---

## Detection logic (SPL)

**Primary — source fan-out:**
```spl
index=wineventlog EventCode=4625
| eval src_ip=replace(Source_Network_Address,"^::ffff:","")
| bin _time span=5m
| stats dc(Account_Name) as distinct_accounts
        count as failed_attempts
        values(Account_Name) as targeted_accounts
        values(Sub_Status) as failure_codes
        min(_time) as firstTime max(_time) as lastTime
        by _time, src_ip, host
| where distinct_accounts >= 5
| convert ctime(firstTime) ctime(lastTime)
| sort - distinct_accounts
```

**Refined — spray signature only (0xC000006A):**
```spl
index=wineventlog EventCode=4625 Sub_Status=0xC000006A
| eval src_ip=replace(Source_Network_Address,"^::ffff:","")
| bin _time span=5m
| stats dc(Account_Name) as distinct_accounts count as failed_attempts
        values(Account_Name) as targeted_accounts
        by _time, src_ip, host
| where distinct_accounts >= 5
| sort - distinct_accounts
```

**Why each clause is here:**
- `bin _time span=5m` — buckets activity into fixed windows so "many accounts in
  a short time" is measurable. Widen the span to catch slower sprays (see gaps).
- `dc(Account_Name)` — distinct *accounts* is the fan-out metric; `count` alone
  can't tell spray from one account failing repeatedly (that's brute force).
- `where distinct_accounts >= 5` — the threshold; tune per environment.
- `replace(Source_Network_Address,"^::ffff:","")` — normalizes IPv4-mapped IPv6
  as in the Kerberoast card, keeping the source field readable and joinable.

> **Field check:** 4625's source field is `Source_Network_Address` (distinct from
> 4769's `Client_Address`). For some logon types it can be blank or `127.0.0.1`;
> if your events show an empty source, use `Workstation_Name` instead, or the
> domain-wide fallback below.

**Fallback — if source is unreliable (threshold on domain-wide distinct accounts):**
```spl
index=wineventlog EventCode=4625 Sub_Status=0xC000006A
| bin _time span=5m
| stats dc(Account_Name) as distinct_accounts values(Account_Name) as accounts by _time, host
| where distinct_accounts >= 10
```

---

## Alert configuration (savedsearches.conf — detection-as-code)

```ini
[Password Spray - Single Source Many Accounts]
search = index=wineventlog EventCode=4625 | eval src_ip=replace(Source_Network_Address,"^::ffff:","") | bin _time span=5m | stats dc(Account_Name) as distinct_accounts count as failed_attempts values(Account_Name) as targeted_accounts values(Sub_Status) as failure_codes by _time, src_ip, host | where distinct_accounts >= 5 | sort - distinct_accounts
description = Detects one source failing authentication (4625) across many distinct accounts in a short window, indicative of password spraying (T1110.003).
dispatch.earliest_time = -15m
dispatch.latest_time = now
cron_schedule = */15 * * * *
enableSched = 1
counttype = number of events
relation = greater than
quantity = 0
alert.severity = 4
alert.track = 1
```

---

## Validation

Tested against live lab telemetry:

| Field | Captured value |
|---|---|
| Method | Native `ValidateCredentials` spray (NTLM fallback) from the member server |
| Source | `10.10.15.6` (patient-zero member server) |
| Targets (`Account_Name`) | `testuser1`–`testuser8` (8 distinct accounts) |
| EventCode | `4625` (account failed to log on) |
| Sensor (`host`) | `PDC001` (domain controller) |
| Result | Fan-out across 8 distinct accounts from one source in seconds — fires ✅ |

Scenario continuity: the **same** member server (`10.10.15.6`) that performed the
Kerberoast now sprays — one compromised host, two techniques, minutes apart. That
is the spine of the Phase 5 incident report.

---

## False positives

Password-spray FPs come from **legitimate infrastructure that authenticates many
users from one source**:

- VPN concentrators, reverse proxies, load balancers, ADFS/SSO gateways.
- RDS / Citrix / jump hosts where many users log on.
- Mail servers or mobile devices with cached old passwords after a domain-wide
  password reset (mass failures across accounts).
- Vulnerability scanners / DAST tools authenticating as multiple users.

Shape tell: these have a *stable, known* source host; a spray usually comes from
an unexpected one.

## Tuning

1. Allowlist known auth-aggregating source hosts (VPN, proxy, RDS, mail gateways)
   by `src_ip`.
2. Prefer the **0xC000006A** refined variant to drop enumeration/typo noise.
3. Set the `distinct_accounts` threshold from a one-week baseline of normal
   per-source failure spread (lab: 5; production often 10+).
4. Widen `span` and lower the threshold to trade sensitivity for slow sprays.

---

## Triage workflow

1. **Source:** is `src_ip` expected auth infrastructure, or an unexpected
   internal host (like a user workstation / member server)?
2. **Breadth & code:** how many `distinct_accounts`, and are failures
   `0xC000006A` (valid users) vs `0xC0000064` (enumeration)?
3. **Success check (critical):** did the same `src_ip` produce a **4624 success**
   right after? If yes → the spray worked → escalate immediately and treat as
   account compromise.
4. **Target pattern:** are the accounts alphabetical / sequential (`testuser1-8`)
   or otherwise systematic? Systematic ordering signals automation.

## Response

- If a success followed the spray: disable/reset the compromised account, revoke
  sessions, and hunt for follow-on activity from `src_ip`.
- Contain the source host (it is authenticating for accounts it shouldn't).
- Confirm lockout policy and consider smart lockout / MFA on exposed surfaces.

---

## Coverage gaps & next

- **Low-and-slow sprays** that stay under the 5-minute window evade the primary
  rule. Add a wider-window variant (e.g. `span=1h` or `span=1d`) with a lower
  per-window threshold.
- **Distributed sprays** from many source IPs evade source-grouping. Add a
  variant that aggregates by *targeted account breadth* domain-wide regardless of
  source (the fallback query is the seed for this).
- **Highest-value next detection: spray → success correlation.** Join this 4625
  fan-out with a subsequent 4624 success from the same `src_ip` — that's the
  transition from *attempt* to *compromise* and deserves its own high-severity
  rule.

## References

- MITRE ATT&CK T1110.003 — Password Spraying
- Microsoft — Event 4625: An account failed to log on (Sub_Status codes)
- Microsoft — Event 4624: An account was successfully logged on
