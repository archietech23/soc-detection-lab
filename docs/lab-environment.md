# Lab Environment

This document describes the host environment the lab was built on. The hypervisor setup is out of scope for the detection engineering work in this repo. Any hypervisor will work.

## Hosts

| Role | OS | vCPU | RAM | Disk | Notes |
|---|---|---|---|---|---|
| Domain Controller | Windows Server 2022 | 2 | 4 GB | 60 GB | `PDC001` on `ARCHIETECH.LOCAL`. Splunk UF installed. |
| Member server / attack host | Windows Server 2022 | 2 | 4 GB | 60 GB | `10.10.15.6`. Atomic Red Team installed. Splunk UF installed. |
| Splunk indexer + search head | Ubuntu Server 22.04 LTS | 4 | 8 GB | 120 GB | Splunk Enterprise Trial. Listens on 9997/tcp. |

All three VMs sit on a single flat lab network. No routing to the internet is required after install.

## Hypervisor

Built on Proxmox VE. Any of these would work identically:

- Proxmox VE
- VMware ESXi or Workstation
- Microsoft Hyper-V
- KVM / libvirt

## Learning resources

Not required to read the repo. Included in case you are new to Proxmox and want to build the same environment.

- [Proxmox VE - Full home lab install and setup walkthrough](https://youtu.be/GoZaMgEgrHw)

## Software versions

- Splunk Enterprise 9.x (Trial license, 60 days, full feature set)
- Splunk Universal Forwarder 9.x on both Windows hosts
- Sysmon (SwiftOnSecurity config baseline, tuned for identity events)
- Atomic Red Team, cloned from the public repo, installed at `C:\AtomicRedTeam` on the member server

## Splunk indexes

| Index | Purpose |
|---|---|
| `wineventlog` | Windows Security and System event logs from both Windows hosts. |
| `sysmon` | Sysmon operational log from both Windows hosts. |
