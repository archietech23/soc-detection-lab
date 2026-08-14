# Password spray: single source, many accounts (4625)

| | |
|---|---|
| **Detection ID** | `win-password-spray-4625` |
| **ATT&CK** | [T1110.003: Password Spraying](https://attack.mitre.org/techniques/T1110/003/) |
| **Tactic** | Credential Access |
| **Data source** | Windows Security 4625 on the DC (account failed to log on) |
| **Search scope** | `index=wineventlog` (`sourcetype=WinEventLog`, `source=WinEventLog:Security`) |
| **Fidelity** | Medium |
| **Severity** | High (`alert.severity = 4`) |
| **Deployed as** | `[Password Spray - Single Source Many Accounts]` in [`savedsearches.conf`](../splunk-app/soc_detection_lab/default/savedsearches.conf) |

---

## Hypothesis

Password spraying inverts the classic brute force. Instead of many passwords against one account, which trips lockout, the adversary tries one common password against many accounts, staying under per-account lockout thresholds. The signature is fan-out: a single source generating authentication failures across many distinct accounts in a short window.

This detection groups failed logons (4625) by source and time window and alerts when one source fails against a threshold number of distinct accounts. It keys on the shape of the activity, one-to-many, not on any single failure. One 4625 is normal. Twenty accounts failing from one host in five minutes is not.

---

## 4625 Sub_Status reference

| Sub_Status | Meaning | Relevance |
|---|---|---|
| 0xC0000064 | User name does not exist | Enumeration, not spray |
| **0xC000006A** | **User exists, wrong password** | Spray signature: valid users, one bad password |
| 0xC0000234 | Account locked out | Possible lockout storm |
| 0xC0000072 | Account disabled | Noise |
| 0xC0000071 | Password expired | Noise, or post-reset |

The refined variant below filters on `0xC000006A` to isolate the true spray signature from user-enumeration noise.

---

## Detection logic (SPL)

Primary, source fan-out:

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

Refined, spray signature only (`0xC000006A`):

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

Why each clause is here:

- `bin _time span=5m` buckets activity into fixed windows, so "many accounts in a short time" is measurable. Widen the span to catch slower sprays (see gaps).
- `dc(Account_Name)` is the fan-out metric. `count` alone cannot tell a spray from one account failing repeatedly, which is brute force.
- `where distinct_accounts >= 5` is the threshold. Tune it per environment.
- `replace(Source_Network_Address,"^::ffff:","")` normalizes IPv4-mapped IPv6 as in the Kerberoast card, keeping the source readable and joinable.

> **Field check:** the 4625 source field is `Source_Network_Address`, not `Client_Address` as on 4769. For some logon types it can be blank or `127.0.0.1`. If your events show an empty source, use `Workstation_Name`, or the domain-wide fallback below.

> **Known counting issue:** on 4625, `Account_Name` is multivalue: the Subject account (which is `-` on a network logon) plus the targeted account. `dc(Account_Name)` therefore overcounts by one. Add `| eval Account_Name=mvfilter(Account_Name!="-")` before the `stats`. This is documented in [`incident-report.md`](../docs/incident-report.md) and is not yet in the shipped rule.

Fallback, if the source is unreliable (threshold on domain-wide distinct accounts):

```spl
index=wineventlog EventCode=4625 Sub_Status=0xC000006A
| bin _time span=5m
| stats dc(Account_Name) as distinct_accounts values(Account_Name) as accounts by _time, host
| where distinct_accounts >= 10
```

---

## Validation

Tested against live lab telemetry.

| Field | Captured value |
|---|---|
| Method | Atomic Red Team T1110.003 Test #1 (Password Spray all Domain Users) |
| Source | `10.10.15.6` (member server) |
| Targets (`Account_Name`) | `testuser1` to `testuser8`, 8 distinct accounts |
| EventCode | `4625` (account failed to log on) |
| Sensor (`host`) | `PDC001` (domain controller) |
| Result | Fan-out across 8 distinct accounts from one source, one attempt each |

The same member server (`10.10.15.6`) that performed the Kerberoast then sprays: one host, two techniques, minutes apart. That continuity is what the incident report reconstructs.

---

## False positives

Spray false positives come from legitimate infrastructure that authenticates many users from one source:

- VPN concentrators, reverse proxies, load balancers, ADFS and SSO gateways.
- RDS, Citrix, or jump hosts where many users log on.
- Mail servers or mobile devices holding cached old passwords after a domain-wide reset, which produce mass failures across accounts.
- Vulnerability scanners and DAST tools authenticating as multiple users.

The shape tell is a stable, known source host. A spray usually comes from an unexpected one.

## Tuning

1. Allowlist known auth-aggregating source hosts (VPN, proxy, RDS, mail gateways) by `src_ip`.
2. Prefer the `0xC000006A` refined variant to drop enumeration and typo noise.
3. Set the `distinct_accounts` threshold from a one-week baseline of normal per-source failure spread. The lab uses 5; production is often 10 or more.
4. Widen `span` and lower the threshold to trade sensitivity for slow sprays.
5. Consider dropping severity to Medium (`alert.severity = 3`) once VPN and proxy sources are allowlisted, given this rule's larger false-positive surface.

---

## Triage workflow

1. Source. Is `src_ip` expected auth infrastructure, or an unexpected internal host such as a user workstation or member server?
2. Breadth and code. How many `distinct_accounts`, and are failures `0xC000006A` (valid users) or `0xC0000064` (enumeration)?
3. Success check (critical). Did the same `src_ip` produce a 4624 success right after? If yes, the spray worked. Escalate and treat it as account compromise.
4. Target pattern. Are the accounts sequential (`testuser1` to `testuser8`) or otherwise systematic? Systematic ordering signals automation.

## Response

- If a success followed the spray, disable or reset the compromised account, revoke sessions, and hunt for follow-on activity from `src_ip`.
- Contain the source host, since it is authenticating for accounts it should not.
- Confirm lockout policy and consider smart lockout and MFA on exposed surfaces.

---

## Coverage gaps

- Low-and-slow sprays that stay under the five-minute window evade the primary rule. Add a wider-window variant (`span=1h` or `span=1d`) with a lower per-window threshold.
- Distributed sprays from many source IPs evade source grouping. Add a variant that aggregates by targeted-account breadth domain-wide, regardless of source. The fallback query is the seed for this.
- The highest-value next detection is spray-to-success correlation: join this 4625 fan-out with a following 4624 success from the same `src_ip`. That is the transition from attempt to compromise and deserves its own high-severity rule.

## References

- MITRE ATT&CK T1110.003, Password Spraying
- Microsoft, Event 4625: An account failed to log on (Sub_Status codes)
- Microsoft, Event 4624: An account was successfully logged on
