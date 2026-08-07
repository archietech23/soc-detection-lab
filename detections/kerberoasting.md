# Detection: Kerberoasting — RC4 Service Ticket Requested

| | |
|---|---|
| **Detection ID** | `win-kerberoast-rc4-4769` |
| **ATT&CK** | [T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting](https://attack.mitre.org/techniques/T1558/003/) |
| **Tactic** | Credential Access |
| **Data source** | Windows Security log (DC), Event 4769 — Kerberos Service Ticket Operations |
| **Log path** | `index=wineventlog` / `sourcetype=WinEventLog:Security` |
| **Fidelity** | High |
| **Severity** | Medium (escalate to High on burst — see volume note) |
| **Status** | Production (RC4 rule) · volume rule = backlog |

---

## Hypothesis

An adversary who has compromised any domain account can request Kerberos service
tickets (TGS) for accounts that have a Service Principal Name (SPN). The DC
returns the ticket encrypted with the target account's password hash. If the
ticket is issued with **RC4-HMAC (0x17)**, it can be extracted and cracked
offline (hashcat mode 13100) to recover the service account's plaintext password
— with no further interaction with the domain and no failed logons.

In a modern domain, Kerberos should negotiate **AES (0x11 / 0x12)**. A service
ticket requested with **RC4 (0x17)** to a *user* service account is therefore
anomalous and a strong Kerberoasting indicator. This detection treats the
encryption downgrade itself as the signal — high fidelity, independent of
volume, so it fires even on a single stealthy request.

---

## Encryption type reference

| Value | Encryption | Expected in a modern domain? |
|---|---|---|
| 0x1 / 0x3 | DES | No — legacy/insecure |
| 0x11 | AES128-HMAC | Yes |
| 0x12 | AES256-HMAC | Yes (preferred) |
| **0x17** | **RC4-HMAC** | **No — suspicious for user SPNs** |
| 0x18 | RC4-HMAC-EXP | No — legacy/insecure |

---

## Detection logic (SPL)

```spl
index=wineventlog EventCode=4769 Ticket_Encryption_Type=0x17
    NOT Service_Name="*$" NOT Service_Name="krbtgt"
| eval src_ip=replace(Client_Address,"^::ffff:","")
| stats count as rc4_requests
        min(_time) as firstTime max(_time) as lastTime
        values(Service_Name) as targeted_spns
        dc(Service_Name) as distinct_spns
        by Account_Name, src_ip, host
| convert ctime(firstTime) ctime(lastTime)
| sort - rc4_requests
```

**Why each clause is here:**
- `Ticket_Encryption_Type=0x17` — the core anomaly (RC4 in an AES domain).
- `NOT Service_Name="*$"` — excludes computer/machine accounts as the target;
  their 120-char random passwords aren't crackable, so they aren't roast targets
  and generate benign noise.
- `NOT Service_Name="krbtgt"` — excludes TGT-related noise.
- `replace(Client_Address,"^::ffff:","")` — normalizes the IPv4-mapped IPv6
  address (e.g. `::ffff:10.10.15.6` → `10.10.15.6`) so the source is readable and
  joinable to other data.
- Grouping by `Account_Name, src_ip, host` surfaces *who* requested, *from where*
  — and `distinct_spns` previews the burst pattern the volume rule will formalize.

---

## Alert configuration (savedsearches.conf — detection-as-code)

```ini
[Kerberoasting - RC4 Service Ticket Requested]
search = index=wineventlog EventCode=4769 Ticket_Encryption_Type=0x17 NOT Service_Name="*$" NOT Service_Name="krbtgt" | eval src_ip=replace(Client_Address,"^::ffff:","") | stats count as rc4_requests min(_time) as firstTime max(_time) as lastTime values(Service_Name) as targeted_spns dc(Service_Name) as distinct_spns by Account_Name, src_ip, host | convert ctime(firstTime) ctime(lastTime) | sort - rc4_requests
description = Detects RC4-encrypted (0x17) Kerberos service ticket requests to user SPNs on a DC, indicative of Kerberoasting (T1558.003).
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

Tested against live lab telemetry, not theory:

| Field | Captured value |
|---|---|
| Method | Atomic Red Team **T1558.003** (native ticket request) |
| Requestor (`Account_Name`) | `pam_app001@ARCHIETECH.LOCAL` (compromised member-server user) |
| Source (`Client_Address`) | `::ffff:10.10.15.6` (patient-zero member server) |
| Target (`Service_Name`) | `svc-sql` (user service account, weak password) |
| `Ticket_Encryption_Type` | `0x17` (RC4-HMAC) |
| Sensor (`host`) | `PDC001` (domain controller) |
| Result | Detection returned the event ✅ |

Scenario modeled: attacker operating from a compromised member server roasts a
weak-password service account; the DC logs the RC4 request; the detection fires.

---

## False positives

RC4 service tickets can be legitimate where a target account is still configured
for RC4 (`msDS-SupportedEncryptionTypes`). Known benign sources:

- Legacy service accounts / older third-party applications not yet on AES.
- Cross-forest or legacy trusts with down-level domain controllers.
- Historically, Azure AD Connect / directory-sync service accounts.
- Appliances or SQL/HTTP services pinned to RC4 by configuration.

Each of these is *also* a hardening finding — an account that should be moved to
AES — so a "false positive" here is still worth acting on.

## Tuning

1. Baseline for one week; export the recurring benign `Service_Name` values.
2. Maintain an allowlist lookup of known-legacy RC4 service accounts and subtract
   it (keyed on the **target** SPN, since RC4 is a property of that account):
   ```spl
   ... | lookup kerberoast_rc4_allowlist.csv Service_Name OUTPUT allowlisted
       | where isnull(allowlisted)
   ```
3. Remediate allowlisted accounts toward AES over time and shrink the list — the
   goal state is an empty allowlist and zero legitimate RC4.

---

## Triage workflow

1. **Source sanity:** is `src_ip` a normal admin/service host, or an end-user
   workstation that has no business requesting service tickets in bulk?
2. **Target sensitivity:** is `Service_Name` a privileged service account?
3. **Volume/time:** single request, or many `distinct_spns` from one
   `Account_Name` in a short window? Burst → escalate.
4. **Requestor state:** review the requesting account's recent 4624/4625/4768 for
   signs of compromise or lateral movement.
5. **Config check:** should the target account be on AES? If yes, this is both a
   possible attack and a misconfiguration.

## Response

- Reset the targeted service account's password (25+ chars, random) — assume the
  hash may be cracked.
- Investigate and, if warranted, contain the requesting account.
- Migrate the service account to a **gMSA** where feasible (AD-managed rotation,
  removes the crackable static password).
- Enforce AES and remove RC4 support on the account / domain.

---

## Coverage gaps & next

- **Volume/burst rule (backlog — capture next).** This card catches the RC4
  *encryption downgrade*. It does **not** catch roasting that requests **AES**
  tickets (e.g. tooling that doesn't force RC4, or domains where RC4 is disabled).
  The complementary behavioral detection is: **one `Account_Name` requesting many
  distinct `Service_Name` SPNs within a short window**, regardless of encryption.
  To build and validate it, add 2–3 more bait SPN accounts and run Atomic Red
  Team **T1558.003 Test #1 (Invoke-Kerberoast)** to generate a burst, then
  threshold on `dc(Service_Name)` over a `bin`-ed time window.
- Together the two rules cover both axes: **encryption-based** (high fidelity,
  low volume) and **behavioral** (catches AES roasting). Having both is the point
  — one is a static IOC, the other is behavioral analytics.

## References

- MITRE ATT&CK T1558.003 — Kerberoasting
- Microsoft — Event 4769: A Kerberos service ticket was requested
- RFC 4120 — Kerberos ticket options & encryption types
- harmj0y — "Kerberoasting without Mimikatz"
