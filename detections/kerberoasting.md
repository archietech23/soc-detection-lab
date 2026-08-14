# Kerberoasting: RC4 service ticket requested (4769)

| | |
|---|---|
| **Detection ID** | `win-kerberoast-rc4-4769` |
| **ATT&CK** | [T1558.003: Kerberoasting](https://attack.mitre.org/techniques/T1558/003/) |
| **Tactic** | Credential Access |
| **Data source** | Windows Security 4769 on the DC |
| **Search scope** | `index=wineventlog` (`sourcetype=WinEventLog`, `source=WinEventLog:Security`) |
| **Fidelity** | High |
| **Severity** | High (`alert.severity = 4`) |
| **Deployed as** | `[Kerberoasting - RC4 Service Ticket Requested]` in [`savedsearches.conf`](../splunk-app/soc_detection_lab/default/savedsearches.conf) |

---

## Hypothesis

Any domain account can request a Kerberos service ticket (TGS) for an account that has a Service Principal Name. The DC returns that ticket encrypted with the target account's password hash. If the ticket comes back as RC4-HMAC (`0x17`), it can be cracked offline (hashcat mode 13100) to recover the service account password, with no further domain interaction and no failed logons to alert on.

A modern domain negotiates AES: `0x11` (AES128) or `0x12` (AES256). An `0x17` ticket for a user service account is a downgrade, and the downgrade itself is the signal. That makes the rule volume-independent: it fires on a single stealthy request instead of waiting for a burst.

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

- `Ticket_Encryption_Type=0x17` is the core anomaly: RC4 in an AES domain.
- `NOT Service_Name="*$"` drops machine accounts. Their 120-character random passwords are not worth cracking, so they are noise rather than targets.
- `NOT Service_Name="krbtgt"` drops TGT-related noise.
- `replace(Client_Address,"^::ffff:","")` normalizes the IPv4-mapped IPv6 form, so `::ffff:10.10.15.6` becomes `10.10.15.6`. That keeps the source readable and lets it join cleanly to the password-spray rule.
- Grouping by `Account_Name, src_ip, host` answers who requested the ticket and from where. `distinct_spns` previews the burst shape the volume rule will formalize.

Schedule, dispatch window, and alert actions live in `savedsearches.conf` and are not duplicated here.

---

## Validation

Fired against live lab telemetry. Screenshot: [`docs/screenshots/4769-kerberoast-rc4-event.png`](../docs/screenshots/4769-kerberoast-rc4-event.png)

| Field | Captured value |
|---|---|
| Method | Simulated Kerberoasting: service ticket requested for the `svc-sql` SPN |
| `EventCode` | `4769` |
| `Account_Name` (requestor) | `pam_app001@ARCHIETECH.LOCAL` |
| `Client_Address` | `::ffff:10.10.15.6` |
| `Client_Port` | `63586` |
| `Service_Name` (target) | `svc-sql` |
| `Ticket_Encryption_Type` | `0x17` (RC4-HMAC) |
| `Ticket_Options` | `0x40810000` |
| `Failure_Code` / `Keywords` | `0x0` / `Audit Success` |
| `host` | `PDC001` |
| `RecordNumber` | `2352830` |

`Keywords = Audit Success` matters: the DC issued the RC4 ticket, so the requestor walked away with crackable material.

---

## False positives

RC4 tickets are legitimate wherever the target account still advertises RC4 in `msDS-SupportedEncryptionTypes`:

- Legacy service accounts and older third-party applications not yet on AES.
- Cross-forest or legacy trusts with down-level DCs.
- Appliances or SQL and HTTP services pinned to RC4 by configuration.

Each of these is also a hardening finding. A false positive here still names an account that should move to AES.

Observed in this lab: none. The domain was built AES-only apart from the deliberately weak `svc-sql` bait account, so every `0x17` seen was the simulated attack.

---

## Tuning

Not applied in this lab, and not needed here. With one bait SPN and no legacy RC4 accounts, there is no benign traffic to suppress. The steps below are what production would require.

1. Baseline for a week and export the recurring benign `Service_Name` values.
2. Subtract them with a lookup keyed on the target SPN, since RC4 is a property of the target account, not the requestor:
   `... | lookup kerberoast_rc4_allowlist.csv Service_Name OUTPUT allowlisted | where isnull(allowlisted)`
3. Migrate allowlisted accounts to AES and shrink the list. The goal state is an empty allowlist and zero legitimate RC4.

---

## Triage workflow

1. Source. Is `src_ip` a normal admin or service host, or a workstation with no reason to request service tickets?
2. Target. Is `Service_Name` a privileged account? `svc-sql` typically holds database access and sometimes local admin on database hosts.
3. Volume. One request, or many `distinct_spns` from one `Account_Name` in a short window? A burst escalates the priority.
4. Requestor. Review that account's recent 4624, 4625, and 4768 events for signs of compromise.
5. Config. Should the target be on AES? If yes, this is both a possible attack and a misconfiguration.

## Response

- Reset the targeted service account password to 25 or more random characters. Assume the hash may be cracked.
- Contain the requesting account if warranted.
- Move the service account to a gMSA where feasible, which removes the crackable static password.
- Enforce AES and drop RC4 support on the account or the domain.

---

## Coverage gaps

This card catches the RC4 downgrade. It does not catch roasting that requests AES tickets, which happens when the tooling does not force RC4 or when RC4 is already disabled domain-wide.

The complementary rule is behavioral: one `Account_Name` requesting many distinct SPNs in a short window, regardless of encryption type. Building it needs two or three more bait SPN accounts and Atomic Red Team T1558.003 Test #1 to generate a burst, then a threshold on `dc(Service_Name)` over a binned window. Tracked for v0.2.

## References

- MITRE ATT&CK T1558.003, Kerberoasting
- Microsoft, Event 4769: A Kerberos service ticket was requested
- RFC 4120, Kerberos ticket options and encryption types
- harmj0y, "Kerberoasting without Mimikatz"
