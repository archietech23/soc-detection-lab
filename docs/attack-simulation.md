# Attack simulation

Both attacks are reproduced with [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team), run from the member server (`10.10.15.6`) against the domain controller. The captured field values are in [`incident-report.md`](incident-report.md). This file is how to regenerate them.

Every test follows the same four steps: satisfy prerequisites, run, verify in Splunk, clean up.

## Prerequisites

- Atomic Red Team and the `Invoke-AtomicTest` harness installed on the member server (`C:\AtomicRedTeam`).
- Bait objects in AD:
  - `svc-sql`, a user account with an SPN (`MSSQLSvc/...`) and RC4 enabled. The RC4 support is what makes it Kerberoastable.
  - `testuser1` through `testuser8`, standard users with known-wrong passwords, used as the spray target list.
- Windows Security auditing forwarding 4769 and 4625 to Splunk (see [`lab-environment.md`](lab-environment.md)).

Load the harness in an elevated PowerShell on the member server:

    Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force

## 1. Kerberoasting (T1558.003)

Requests a service ticket for the `svc-sql` SPN. Because the account is RC4-enabled, the DC returns a `0x17` ticket, which is the crackable material. Set the `spn` value to match your bait account.

    Invoke-AtomicTest T1558.003 -TestNumbers 1 -GetPrereqs
    Invoke-AtomicTest T1558.003 -TestNumbers 1 -InputArgs @{ spn = "MSSQLSvc/<svc-sql-host>:1433" }

Verify in Splunk:

    index=wineventlog EventCode=4769 Ticket_Encryption_Type=0x17 Service_Name="svc-sql" earliest=-15m

Expect one 4769 with `Ticket_Encryption_Type=0x17` and `Service_Name=svc-sql`.

## 2. Password spray (T1110.003)

Tries one password against every account listed in `%temp%\users.txt` from a single source. This lab pre-populated that file with `testuser1` through `testuser8`, so the spray targeted exactly those eight accounts. `-GetPrereqs` only generates the file when it is missing; if it already exists, the prereq is reported as met and the file is left as-is.

    Invoke-AtomicTest T1110.003 -TestNumbers 1 -GetPrereqs
    Invoke-AtomicTest T1110.003 -TestNumbers 1

Verify in Splunk:

    index=wineventlog EventCode=4625 earliest=-15m
    | eval Account_Name=mvfilter(Account_Name!="-")
    | stats count dc(Account_Name) as accounts_targeted by Source_Network_Address, Sub_Status

Expect `Sub_Status=0xC000006A` (valid account, wrong password) from one source, with `accounts_targeted = 8`. The `mvfilter` is required. Without it the count reads 9, for the reason described in [`incident-report.md`](incident-report.md).

## Cleanup

    Invoke-AtomicTest T1558.003 -TestNumbers 1 -Cleanup
    Invoke-AtomicTest T1110.003 -TestNumbers 1 -Cleanup

The bait accounts (`svc-sql`, `testuserN`) are lab fixtures. Leave them in place to re-run.
