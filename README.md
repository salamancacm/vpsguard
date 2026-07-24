# vpsguard

[![CI](https://github.com/salamancacm/vpsguard/actions/workflows/ci.yml/badge.svg)](https://github.com/salamancacm/vpsguard/actions/workflows/ci.yml)
[![Latest release](https://img.shields.io/github/v/release/salamancacm/vpsguard)](https://github.com/salamancacm/vpsguard/releases/latest)
[![Go version](https://img.shields.io/github/go-mod/go-version/salamancacm/vpsguard)](go.mod)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A CLI to audit, harden, and monitor the security of a Linux VPS.

`vpsguard` checks SSH configuration, firewall, fail2ban, user accounts,
authorized SSH keys, cron, automatic updates, and listening ports; it can
automatically fix anything with a safe, well-known remediation; and it can
watch the server over time, alerting when something appears that wasn't
there before (a new user, a new SSH key, a new port, etc.).

> ⚠️ `vpsguard` modifies system configuration (`sshd_config`, firewall,
> fail2ban, file permissions). Always run `--dry-run` first and review what
> it would do before applying changes to a production server.

![vpsguard audit, harden, and monitor catching a simulated SSH key intrusion](docs/demo.gif)

## Installation

### Install script

```bash
curl -fsSL https://raw.githubusercontent.com/salamancacm/vpsguard/main/install.sh | sh
```

This detects your architecture, downloads the matching binary from the
latest release, **verifies it against the published SHA-256 checksum**
before installing (refuses to install on a mismatch), and puts it on your
`PATH` (`/usr/local/bin` if run as root, `~/.local/bin` otherwise).

Piping `curl` into `sh` is a trust-on-first-use tradeoff — you're running
code from the network. If you'd rather not, read
[`install.sh`](install.sh) first, or install from a binary by hand below.

### From a binary

Download the binary for your architecture from
[Releases](../../releases) and put it on your `PATH`:

```bash
curl -Lo vpsguard https://github.com/salamancacm/vpsguard/releases/latest/download/vpsguard-linux-amd64
chmod +x vpsguard
sudo mv vpsguard /usr/local/bin/
```

### Building from source

Requires [Go 1.22+](https://go.dev/dl/).

```bash
git clone https://github.com/salamancacm/vpsguard.git
cd vpsguard
go build -o vpsguard .
sudo mv vpsguard /usr/local/bin/
```

Cross-compiling from another platform onto a Linux VPS:

```bash
GOOS=linux GOARCH=amd64 go build -o vpsguard-linux-amd64 .
GOOS=linux GOARCH=arm64 go build -o vpsguard-linux-arm64 .
```

### go install

```bash
go install github.com/salamancacm/vpsguard@latest
```

This builds from source for whatever platform you run it on. Since
vpsguard only runs on Linux (it refuses to start otherwise — see
`requireLinux()`), running this on a non-Linux machine gets you a binary
you'd still need to cross-compile or transfer, not one you can use
locally; run it directly on the target Linux host instead, or use
`GOOS=linux GOARCH=amd64 go install ...` from elsewhere.

### Homebrew (Linux only)

```bash
brew tap salamancacm/tap
brew install vpsguard
```

Only works under Homebrew-on-Linux ("Linuxbrew") — the formula refuses to
install on macOS, since the resulting binary couldn't run there anyway.

## Usage

When run in an interactive terminal, `vpsguard` shows a small banner and
prints each check's result as it runs instead of going quiet until the
end. Piped, redirected, or `--json` output is always the same plain,
stable format regardless — safe for scripts, cron, and CI.

### Audit (read-only)

```bash
sudo vpsguard audit
```

JSON output (handy for scripting/CI):

```bash
sudo vpsguard audit --json
```

Run only some checks:

```bash
sudo vpsguard audit --check=ssh,firewall
```

Available checks: `ssh`, `firewall`, `fail2ban`, `users`, `sshkeys`,
`cron`, `updates`, `network`, `docker`, `kernel`, `cloud`.

### Hardening

See what it would do, without touching anything:

```bash
sudo vpsguard harden --dry-run
```

Apply, confirming each step:

```bash
sudo vpsguard harden
```

Apply everything without asking (for automation, use with care):

```bash
sudo vpsguard harden --yes
```

Every config file change is backed up before it's written
(`file.bak.<timestamp>`). Checks with automatic remediation: `ssh`,
`firewall`, `fail2ban`, `sshkeys`, `updates`. `users`, `cron`, `network`,
`docker`, `kernel`, and `cloud` are audit-only — they require human
judgement (`cloud` specifically requires changing an EC2 API setting from
outside the instance, which vpsguard has no way to do from inside it).

### Continuous monitoring

`monitor` saves a snapshot of server state on every run and compares it
against the previous one, reporting suspicious changes (new user, new SSH
key, new port, sudoers changes, new cron entry, new process running as
root, and a change to the SHA-256 of sshd/sudo/su/ssh or vpsguard itself).

```bash
sudo vpsguard monitor
```

Install the cron entry so it runs on its own (every 15 minutes by default):

```bash
sudo vpsguard install-cron
```

Snapshots are stored at `/var/lib/vpsguard/snapshot.json` and the cron-driven
`monitor` log goes to `/var/log/vpsguard-monitor.log`.

### Updating

```bash
vpsguard update --check   # just report whether a newer release exists
sudo vpsguard update      # download, verify, and install it
```

`update` never runs on its own — it's always an explicit command, same as
`harden` requiring `--yes`/confirmation. It checks the checksum published
alongside the release before replacing the running binary and refuses to
install on a mismatch.

### Fleet mode

Audit several hosts at once over SSH, from one place:

```bash
sudo vpsguard fleet
```

List the targets under `hosts:` in the config file:

```yaml
hosts:
  - name: web-1
    addr: 203.0.113.10
    user: root
  - name: db-1
    addr: 203.0.113.11
    user: root
    port: 2222 # optional, defaults to 22
```

`fleet` connects using your own SSH setup (keys, agent, `~/.ssh/config`) —
vpsguard never handles credentials itself — and runs `vpsguard audit
--json` on each host, in parallel (`--concurrency`, default 5). vpsguard
must already be installed on every target host. An unreachable host is
reported as an error for that host without failing the rest of the run.
`--json` gives an array of `{host, addr, findings, error}` per host.

## Configuration

An optional `/etc/vpsguard/config.yaml` (or `--config <path>` on `audit`,
`harden`, and `monitor`) tunes vpsguard's behavior. Every field is
optional — an absent file, or an absent field within it, means "use the
default," same as before this existed.

```yaml
# Skip these checks entirely in audit and harden — same as never passing
# them to --check.
disabled_checks:
  - network

# Acknowledge a specific finding going forward. It still prints (with an
# [ACK] tag) and still appears in --json with its real severity — nothing
# is silently hidden — but it's excluded from the OK/WARN/CRIT summary
# tally, so the summary reflects only what still needs a decision.
accepted_findings:
  - check: network
    message_contains: "6379 (redis)" # substring match, not exact

# Override a check's built-in thresholds. Only `kernel` has tunable
# thresholds today.
thresholds:
  kernel:
    security_update_warn: 5
    security_update_crit: 20

# Where `monitor` pushes findings when it detects a change — see below.
notify:
  webhook_url: "https://hooks.slack.com/services/..."
  email_to: "you@example.com"
  min_severity: "WARN"

# Targets for `vpsguard fleet` — see above.
hosts:
  - name: web-1
    addr: 203.0.113.10
    user: root
```

### Notifications

By default `monitor` only prints to stdout/the log file — nobody reads
that proactively, so configure `notify.webhook_url` and/or
`notify.email_to` (above) to actually get pinged when something changes.
`webhook_url` posts a Slack/Discord/Mattermost-compatible JSON payload;
`email_to` requires `sendmail` or mailutils' `mail` to already be
available. Both are optional and independent — set either, both, or
neither. A broken webhook or missing mail transport prints a warning but
never makes `monitor` itself fail.

## Audit checks

| Check | What it checks |
|---|---|
| `ssh` | `PermitRootLogin`, `PasswordAuthentication`, port, `MaxAuthTries` |
| `firewall` | ufw/nftables/iptables active with a default-deny policy |
| `fail2ban` | installed, active, sshd jail enabled |
| `users` | UID 0 accounts besides root, empty passwords, `/etc/sudoers.d` |
| `sshkeys` | permissions on `~/.ssh` and `authorized_keys`, number of trusted keys |
| `cron` | user crontabs and `/etc/cron.*` (informational) |
| `updates` | automatic security updates active |
| `network` | listening TCP/UDP ports; flags non-standard ones, and CRITs on database ports (postgres/mysql/redis/mongo/elasticsearch) bound to all interfaces |
| `docker` | Docker socket permissions, and an unauthenticated TCP daemon listener |
| `kernel` | pending reboot for a newer kernel, count of pending security package updates |
| `cloud` **(beta)** | on AWS EC2, whether the instance metadata service (IMDS) still accepts unauthenticated IMDSv1-style requests (the Capital One breach vector) — a no-op on anything that isn't AWS EC2 |

Findings tagged **`[BETA]`** in the output come from a check that's real
and tested, but hasn't been validated against the actual real-world
system it targets (e.g. `cloud` has never run against a real AWS
account — see [its tests](internal/checks/cloud_test.go) for what *has*
been verified). Not a comment on code quality, just an honest nudge to
double-check a beta finding yourself before acting on it. `--json` and
`--check`/`disabled_checks` work on beta checks exactly like any other —
nothing is hidden or excluded by default.

## Requirements

- Linux (Debian/Ubuntu or RHEL/Fedora/Rocky/AlmaLinux)
- Most commands need root

## Contributing

Issues and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md)
for how to get started. This project especially benefits from outside
review since it touches system security configuration — if you find an
incorrect check or an unsafe remediation, please open an issue.

## Security

Found a security issue? Please see [SECURITY.md](SECURITY.md) for how to
report it responsibly.

## License

[MIT](LICENSE)
