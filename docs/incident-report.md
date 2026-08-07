# Incident Report: Suspected Account Takeover on ARCHIETECH.LOCAL

**Report ID:** IR-2026-001
**Author:** Kristopher Archie Plaquia
**Date opened:** 2026-08-02
**Date closed:** 2026-08-03
**Severity:** High
**Status:** Simulated (lab environment)

> This report documents a simulated incident in a home lab. The attacks were executed with Atomic Red Team against a controlled Active Directory environment. Real detections fired against real telemetry. Names, IPs, and accounts are lab values.

## Summary

Two suspicious activities were detected on the ARCHIETECH.LOCAL domain within a two-hour window, both originating from the same internal host (`10.10.15.6`). The first was a Kerberos service ticket request for a service account (`svc-sql`) using RC4 encryption, consistent with Kerberoasting (MITRE T1558.003). The second was a burst of failed authentications against eight user accounts (`testuser1` through `testuser8`) using NTLM, consistent with a password spray (MITRE T1110.003).

Both events were triggered by the same user context (`pam_app001@ARCHIETECH.LOCAL`) from the same source host. The pattern is consistent with a single actor performing post-compromise reconnaissance and credential access after gaining a foothold on the member server.

No successful authentications on the sprayed accounts were observed during the incident window. No lateral movement was detected. The `svc-sql` account password had not yet been cracked at the time of triage.

## Timeline

| Time (UTC) | Event | Source | Detail |
|---|---|---|---|
| 2026-08-02 22:14 | Kerberos TGS request for `svc-sql` | PDC001 (4769) | RC4 (0x17), requested by `pam_app001` from `10.10.15.6` |
| 2026-08-02 22:14 | Alert fired: `Kerberoasting - RC4 TGS Request` | Splunk | Correlated to host `10.10.15.6` |
| 2026-08-02 22:37 | First failed logon for `testuser1` | PDC001 (4625) | NTLM, sub-status `0xC000006A` (bad password) |
| 2026-08-02 22:37 | Failed logons for `testuser2` through `testuser8` | PDC001 (4625) | Same source host, same window, same sub-status |
| 2026-08-02 22:38 | Alert fired: `Password Spray - NTLM Failure Burst` | Splunk | 8 distinct accounts, single source, under 60 seconds |
| 2026-08-03 08:15 | Triage started | Analyst | Two alerts pulled into one investigation |
| 2026-08-03 09:40 | Root cause identified | Analyst | Compromised host `10.10.15.6`, actor context `pam_app001` |
| 2026-08-03 10:20 | Containment recommendations issued | Analyst | See section below |

## Detection details

### Alert 1: Kerberoasting - RC4 TGS Request

Fired on Windows Event ID 4769 with `Ticket_Encryption_Type=0x17` (RC4). RC4 is the encryption type an attacker requests to enable offline cracking of the returned service ticket. Modern domain-joined services default to AES, so RC4 requests against non-machine, non-krbtgt accounts are a strong indicator.

Captured event (verbatim fields):

```
EventCode           = 4769
Service_Name        = svc-sql
Account_Name        = pam_app001@ARCHIETECH.LOCAL
Client_Address      = ::ffff:10.10.15.6
Ticket_Encryption_Type = 0x17
host                = PDC001
```

Detection logic and full SPL: [`detections/kerberoasting.md`](../detections/kerberoasting.md).

### Alert 2: Password Spray - NTLM Failure Burst

Fired on Windows Event ID 4625 where the sub-status was `0xC000006A` (valid username, wrong password) across a threshold of distinct usernames from a single source host inside a short window. Sub-status matters here: `0xC000006A` means the account exists, which is the signature of spraying a known user list rather than random enumeration (`0xC0000064` = user does not exist).

Captured pattern:

```
EventCode           = 4625
Target_User_Name    = testuser1 ... testuser8
Sub_Status          = 0xC000006A
Workstation_Name    = (attacker host name)
Source_Network_Address = 10.10.15.6
host                = PDC001
```

Detection logic and full SPL: [`detections/password-spray.md`](../detections/password-spray.md).

## Investigation

The two alerts arrived independently. In a mature SOC they would land in the same case because the correlation key (source host `10.10.15.6`) is identical, but this lab does not yet run a case-correlation layer. The analyst joined them manually.

Steps taken:

1. Pivoted on `Client_Address` and `Source_Network_Address` in Splunk. Both alerts share `10.10.15.6`.
2. Pulled all authentication events from `10.10.15.6` for the surrounding six hours. Confirmed no successful sign-ins to any of the sprayed accounts.
3. Pulled all events initiated by `pam_app001` in the same window. The account was used to request the `svc-sql` TGS and was the parent context for the spray attempts.
4. Checked whether `svc-sql` had been used to authenticate anywhere after the TGS request. It had not, which means the ticket had not yet been cracked and reused.
5. Reviewed the last known good behavior of `pam_app001`. Normal usage does not include Kerberos service ticket requests for SQL SPNs or bulk logon attempts against user accounts.

## Root cause

The host `10.10.15.6` was operating under a compromised or misused context (`pam_app001`). From that host, the actor ran two credential access techniques back to back: Kerberoasting to obtain an offline-crackable ticket for a service account, and a password spray to try known-weak passwords against a user list. The two techniques are complementary. Kerberoasting yields credentials over time (cracking is offline). Password spraying yields credentials immediately if any user has a weak password.

## Impact

No confirmed impact in this simulation. No credentials were successfully used. Had the spray landed on a valid password, or the `svc-sql` ticket been cracked offline, the actor would have had a second identity to move with. The Kerberoasting attempt targeted a SQL service account, which typically holds database access and sometimes local admin on database hosts.

## Containment and remediation

Recommended actions if this were a production incident:

1. Isolate `10.10.15.6` from the network at the switch or EDR layer.
2. Force password reset for `pam_app001` and revoke active sessions. Rotate any secrets or tokens the account had access to.
3. Force password reset for `svc-sql`. Move `svc-sql` to a Group Managed Service Account (gMSA) so the password is machine-managed and cannot be Kerberoasted usefully.
4. Reset passwords for `testuser1` through `testuser8` as a precaution and require MFA on next sign-in.
5. Review the host `10.10.15.6` for persistence: scheduled tasks, services, run keys, WMI event subscriptions. Rebuild if compromise is confirmed.
6. Enforce AES-only Kerberos encryption on service accounts where legacy compatibility is not required.

## What worked

- Both detections fired within seconds of the underlying event, with no false positives during the lab window.
- The correlation across alerts was possible because both detections preserve the source host field. This was a deliberate choice in the detection SPL.
- The `Ticket_Encryption_Type=0x17` filter kept the Kerberoasting rule quiet against normal Kerberos traffic.

## What did not work, or is not covered yet

- The two alerts did not auto-correlate into one case. The analyst had to join them manually. A correlation rule keyed on source host would close this gap.
- The lab does not yet detect a successful sign-in that follows a spray (spray-to-success correlation). This is the highest-value next rule to build.
- There is no automated containment. A SOAR playbook that isolates the host and disables the compromised account on high-confidence hits is on the v2 backlog.
- Low-and-slow spray (fewer than N attempts per hour, spread over days) would not fire the current threshold. A longer-window statistical baseline is future work.

## References

- MITRE ATT&CK T1558.003 - Kerberoasting
- MITRE ATT&CK T1110.003 - Password Spraying
- Microsoft Windows Security Event 4769 documentation
- Microsoft Windows Security Event 4625 documentation
