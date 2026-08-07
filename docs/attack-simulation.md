# Attack Simulation Runbook

> **Status:** Coming in v0.2. This runbook will cover reproducing both attacks using Atomic Red Team on the member server.

## What will be covered

- Prerequisites: Atomic Red Team installed at `C:\AtomicRedTeam` on `10.10.15.6`
- Running T1558.003 (Kerberoasting) — forcing RC4 to generate a 4769 event
- Running T1110.003 (Password Spray) — spraying `testuser1`–`testuser8` to generate 4625 events
- Confirming the events land in `index=wineventlog` before checking for alert fires

## In the meantime

The incident report ([`incident-report.md`](incident-report.md)) documents the captured field values from both attacks, which are the ground truth for what the SPL is matching against.
