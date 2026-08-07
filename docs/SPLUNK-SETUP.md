# Splunk Setup Runbook

> **Status:** Coming in v0.2. This runbook will cover installing and configuring the Splunk Universal Forwarder on the Windows hosts and Splunk Enterprise on the Linux indexer/search head.

## What will be covered

- Installing Splunk Enterprise on the Ubuntu indexer/search head
- Configuring `inputs.conf` and `outputs.conf` on the Universal Forwarders
- Setting up the `wineventlog` and `sysmon` indexes
- Confirming events are landing before running attacks

## In the meantime

The lab environment spec (hardware, software versions, indexes) is in [`lab-environment.md`](lab-environment.md).
