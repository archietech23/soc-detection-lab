# Deployment Runbook

This runbook covers the two-machine workflow used to develop and deploy detections in this repo. It assumes the Splunk sensor and SIEM are already built per [`docs/SPLUNK-SETUP.md`](docs/SPLUNK-SETUP.md).

## The workflow, in one picture

```
┌────────────┐   git push    ┌────────┐   git pull    ┌──────────────────┐
│  Laptop    │──────────────▶│ GitHub │──────────────▶│ Splunk host      │
│ (VS Code)  │               └────────┘               │ (service account)│
└────────────┘                                        └────────┬─────────┘
                                                               │ make deploy
                                                               ▼
                                                       /opt/splunk/etc/apps/
                                                       soc_detection_lab/
```

You edit on the laptop. GitHub is the source of truth. The Splunk host pulls and deploys. Do not edit files directly on the Splunk host. That creates a second source of truth and breaks the model.

## Identity model on the Splunk host

Splunk on this host runs under a dedicated non-login service account (`splunksvcacct`) that owns `/opt/splunk` and everything under it. Humans log in as their own admin account (`archiez`) and use `sudo -iu splunksvcacct` to get a shell as the service account when they need to work with the Splunk install.

This is the least-privilege pattern:

- The service account has no interactive password and no login shell of its own.
- Splunk runs as this account, so it cannot touch anything outside its own scope.
- Deploys happen inside a `sudo -iu splunksvcacct` shell, so ownership stays correct without any `chown` or `sudo cp` gymnastics.

Do not give the service account a password. Do not run Splunk or `make deploy` as root.

## One-time setup

### On the laptop

Same as any Git workflow:

```bash
git clone git@github.com:archietech23/soc-detection-lab.git
cd soc-detection-lab
```

Open the folder in VS Code.

### On the Splunk host

Install Git if it is not already there (as your admin user):

```bash
sudo apt update && sudo apt install -y git
```

Everything else runs as the service account. Get a shell:

```bash
sudo -iu splunksvcacct
```

You are now `splunksvcacct`. Confirm and check the home directory:

```bash
whoami                # -> splunksvcacct
echo $HOME            # note this path, it's where the repo will live
```

Clone the repo into a directory this account owns. Home is the natural place:

```bash
cd $HOME
git clone https://github.com/archietech23/soc-detection-lab.git
cd soc-detection-lab
```

Confirm `SPLUNK_HOME` matches your install (the Makefile defaults to `/opt/splunk`):

```bash
grep SPLUNK_HOME Makefile
# SPLUNK_HOME ?= /opt/splunk
```

If Splunk lives elsewhere, override on the command line:

```bash
make deploy SPLUNK_HOME=/path/to/splunk
```

Exit the service account shell when you're done setup:

```bash
exit                  # back to archiez
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

Get a service account shell first, then work inside it:

```bash
sudo -iu splunksvcacct

cd $HOME/soc-detection-lab
git pull
make deploy

exit
```

`make deploy` copies the app from the repo into `$SPLUNK_HOME/etc/apps/soc_detection_lab/` and restarts Splunk. Because the shell is running as the account that owns `/opt/splunk`, no `sudo` is needed inside the deploy step. Restart is required for `savedsearches.conf` changes to load.

Expected output ends with a Splunk startup confirmation. Restart takes 60-120 seconds on a lab VM. Do not cancel it.

If Splunk fails to start, check the config from inside the service account shell:

```bash
$SPLUNK_HOME/bin/splunk btool check --debug
```

### 4. Verify in Splunk

Open the Splunk web UI in a browser:

- **Settings → Searches, reports, and alerts**: both scheduled searches should be listed, enabled, and marked "Alert."
- Trigger the attack again from the member server (see [`docs/attack-simulation.md`](docs/attack-simulation.md)).
- **Activity → Triggered alerts**: the alert should appear within one scheduling interval.

## Rollback

If a deploy breaks something, roll back inside a service account shell:

```bash
sudo -iu splunksvcacct

cd $HOME/soc-detection-lab
git log --oneline               # find the last good commit
git checkout <sha> -- splunk-app/
make deploy

exit
```

Then fix the bad commit on the laptop and push a corrected version. When it's clean, redeploy the head of `main`.

## Running one-off commands as the service account

You do not have to open a full interactive shell every time. `sudo -iu splunksvcacct <command>` runs a single command as the service account and returns you to your own shell:

```bash
sudo -iu splunksvcacct /opt/splunk/bin/splunk status
sudo -iu splunksvcacct /opt/splunk/bin/splunk search 'index=wineventlog | stats count' -preview false
```

Use the single-command form for quick checks. Use `sudo -iu splunksvcacct` with no command when you're doing a multi-step operation like a deploy.

## Makefile targets

| Target | What it does |
|---|---|
| `make validate` | Runs the lint script against detection cards and `.conf` files. Safe to run as any user. |
| `make deploy` | Copies the app into `$SPLUNK_HOME/etc/apps/` and restarts Splunk. Must run as the service account. |
| `make diff` | Shows the diff between the repo copy and the deployed copy. Useful for confirming nothing was hand-edited on the box. |
| `make restart` | Restarts Splunk without redeploying. Must run as the service account. |

## Common issues

**Splunk restart hangs.** Give it two minutes. Cold restart on a lab VM can take a while. If it still fails, check disk space (`df -h`) and inspect `/opt/splunk/var/log/splunk/splunkd.log` from inside a service account shell.

**Alert does not fire after deploy.** Confirm the search is enabled (`is_scheduled = 1`, `disabled = 0` in `savedsearches.conf`) and that the schedule window has passed. The Kerberoasting rule runs every 5 minutes by default.

**`make deploy` errors with permission denied on `/opt/splunk/etc/apps/`.** You ran it as your own user instead of the service account. Get a service account shell first: `sudo -iu splunksvcacct`.

**Git pull says "diverged."** Someone edited files on the Splunk host. Do not do this. Reset with `git reset --hard origin/main` and make the change on the laptop instead.

**`sudo -iu splunksvcacct` prompts for password every time.** That is expected. It is prompting for your own sudo password, not the service account's. If it becomes annoying for a session, cache with `sudo -v` at the start.
