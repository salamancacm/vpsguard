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
`cron`, `updates`, `network`, `docker`, `kernel`.

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
`docker`, and `kernel` are audit-only — they require human judgement.

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
