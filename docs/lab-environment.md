# Lab Environment

Three VMs on one flat network. The hypervisor is out of scope for the detection work in this repo.

## Network and domain

| | |
|---|---|
| Subnet | `10.10.15.0/24` (flat, no internet routing required after install) |
| AD domain (FQDN) | `archietech.local` |
| AD domain (NetBIOS) | `ARCHIETECH` |
| Forest functional level | Windows Server 2016 <!-- TODO: confirm --> |

## Hosts

| Role | Hostname | IP | OS | vCPU / RAM / Disk |
|---|---|---|---|---|
| Domain Controller | `PDC001` | `10.10.15.<TODO>` | Windows Server 2022 | 2 / 4 GB / 60 GB |
| Member server (attack host) | `<TODO>` | `10.10.15.6` | Windows Server 2022 | 2 / 4 GB / 60 GB |
| Splunk indexer + search head | `<TODO>` | `10.10.15.<TODO>` | Ubuntu Server 22.04 LTS | 4 / 8 GB / 120 GB |

Both Windows hosts run the Splunk Universal Forwarder. The Ubuntu host receives on `9997/tcp`.

## Hypervisor

Built on Proxmox VE. These work the same way:

- Proxmox VE
- VMware ESXi or Workstation
- Microsoft Hyper-V

## Software

| Component | Version | Installed on |
|---|---|---|
| Splunk Enterprise | 10.4.2 (Trial license) | Ubuntu indexer / search head |
| Splunk Universal Forwarder | `<TODO: run splunk version>` | Both Windows hosts |
| Sysmon | SwiftOnSecurity config baseline | Both Windows hosts |
| Atomic Red Team | public repo, installed at `C:\AtomicRedTeam` | Member server |

## Indexes

| Index | Contents |
|---|---|
| `wineventlog` | Windows Security and System logs from both Windows hosts |
| `sysmon` | Sysmon operational log from both Windows hosts |

## Sourcetype note

Windows Security events land as `sourcetype=WinEventLog` with `source=WinEventLog:Security`. Detections in this repo filter on `index=wineventlog` and `EventCode`, not on sourcetype.

## Time

The Splunk UI in the captured screenshots displays UTC. The Windows hosts write local time (UTC-7) into the raw event line, so a raw event stamped `11:17:33 PM` on 08/08 appears in Splunk as `6:17:33 AM` on 08/09. Timestamps in the incident report use the Splunk display time and label it.
