# Deployment Runbook

This runbook covers the two-machine workflow used to develop and deploy detections in this repo. It assumes the Splunk sensor and SIEM are already built per [`docs/SPLUNK-SETUP.md`](docs/SPLUNK-SETUP.md).

## The workflow, in one picture

```
┌────────────┐   git push    ┌────────┐   git pull    ┌──────────────┐
│  Laptop    │──────────────▶│ GitHub │──────────────▶│ Splunk host  │
│ (VS Code)  │               └────────┘               │ (Linux)      │
└────────────┘                                        └──────┬───────┘
                                                             │ make deploy
                                                             ▼
                                                     /opt/splunk/etc/apps/
                                                     soc_detection_lab/
```

You edit on the laptop. GitHub is the source of truth. The Splunk host pulls and deploys. Do not edit files directly on the Splunk host. That creates a second source of truth and breaks the model.

## One-time setup

### On the laptop

You already do this for your GitHub Pages site. Same steps:

```bash
git clone git@github.com:archietech23/soc-detection-lab.git
cd soc-detection-lab
```

Open the folder in VS Code.

### On the Splunk Linux host

Install Git if it is not already there:

```bash
sudo apt update && sudo apt install -y git
```

Clone the repo into your home directory:

```bash
cd ~
git clone https://github.com/archietech23/soc-detection-lab.git
cd soc-detection-lab
```

Confirm `SPLUNK_HOME` matches your install. The Makefile defaults to `/opt/splunk`:

```bash
grep SPLUNK_HOME Makefile
# SPLUNK_HOME ?= /opt/splunk
```

If your Splunk lives elsewhere, either export it or pass it on the command line:

```bash
export SPLUNK_HOME=/opt/splunk
# or
make deploy SPLUNK_HOME=/opt/splunk
```

## Everyday workflow

### 1. Edit and validate on the laptop

Make the change in VS Code. Then run the lint locally to catch mistakes before pushing:

```bash
make validate
```

The lint checks that every detection card has the required sections, every ATT&CK ID follows the expected format, and the Splunk `.conf` parses. It exits non-zero on failure and CI will do the same on push.

### 2. Commit and push

```bash
git add -A
git commit -m "detection: tune kerberoasting rule to allowlist svc-legacy"
git push
```

GitHub Actions will run the same lint on the push. Green build means safe to deploy.

### 3. Pull and deploy on the Splunk host

```bash
cd ~/soc-detection-lab
git pull
make deploy
```

`make deploy` copies the app from the repo into `$SPLUNK_HOME/etc/apps/soc_detection_lab/` and restarts Splunk. The restart is required for `savedsearches.conf` changes to load.

Expected output ends with a Splunk startup confirmation. If Splunk fails to start, run:

```bash
$SPLUNK_HOME/bin/splunk btool check --debug
```

to see which conf line broke parsing.

### 4. Verify in Splunk

Open the Splunk web UI:

- **Settings → Searches, reports, and alerts**: both scheduled searches should be listed, enabled, and marked "Alert."
- Trigger the attack again from the member server (see [`docs/attack-simulation.md`](docs/attack-simulation.md)).
- **Activity → Triggered alerts**: the alert should appear within one scheduling interval.

## Rollback

If a deploy breaks something, the fastest rollback is:

```bash
cd ~/soc-detection-lab
git log --oneline               # find the last good commit
git checkout <sha> -- splunk-app/
make deploy
```

Then fix the bad commit on the laptop and push a corrected version.

## Makefile targets

| Target | What it does |
|---|---|
| `make validate` | Runs the lint script against detection cards and `.conf` files. |
| `make deploy` | Copies the app into `$SPLUNK_HOME/etc/apps/` and restarts Splunk. |
| `make diff` | Shows the diff between the repo copy and the deployed copy. Useful for confirming nothing was hand-edited on the box. |
| `make restart` | Restarts Splunk without redeploying. |

## Common issues

**Splunk restart hangs.** Give it two minutes. Cold restart on a lab VM can take a while. If it still fails, check disk space (`df -h`) and inspect `/opt/splunk/var/log/splunk/splunkd.log`.

**Alert does not fire after deploy.** Confirm the search is enabled (`is_scheduled = 1`, `disabled = 0` in `savedsearches.conf`) and that the schedule window has passed. The Kerberoasting rule runs every 5 minutes by default.

**`make deploy` complains about permissions.** Run it as the user that owns the Splunk install, usually `splunk`. Do not run Splunk as root.

**Git pull says "diverged."** Someone edited files on the Splunk host. Do not do this. Reset with `git reset --hard origin/main` and make the change on the laptop instead.
