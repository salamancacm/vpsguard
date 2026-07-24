# Contributing to vpsguard

Thanks for considering a contribution. Because this tool modifies live
server security configuration, changes here get a bit more scrutiny than a
typical CLI project — that's a feature, not a bureaucratic hurdle.

## Ground rules

- Be respectful and constructive. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
- Discuss non-trivial changes in an issue before opening a large PR, so we
  don't waste your time on an approach that won't land.
- Never report a security vulnerability as a public issue — see
  [SECURITY.md](SECURITY.md).

## Development setup

Requires [Go 1.22+](https://go.dev/dl/).

```bash
git clone https://github.com/salamancacm/vpsguard.git
cd vpsguard
go build -o vpsguard .
```

Format, vet, and test before committing:

```bash
gofmt -l .        # should print nothing
go vet ./...
go test ./...
```

## Testing changes

### Unit tests

Pure logic (parsing, threshold comparisons, string formatting — anything
that doesn't need to shell out or touch the real filesystem) should have
table-driven tests alongside it (`internal/checks/network_test.go` is a
good template). If a check's logic is entangled with a `system.Run(...)`
or `system.ReadFileLines(...)` call, prefer extracting the parsing/decision
part into its own small function that takes the raw output/lines as a
parameter — see `internal/checks/kernel.go`'s
`countDebianSecurityUpdates`/`countRHELSecurityUpdates` for the pattern.
This is what actually catches bugs: the `ss -tulnp` vs `ss -tln` column
mismatch that shipped in `docker.go`'s first version would have been
caught immediately by a test feeding it real captured `ss` output, which
is exactly what `network_test.go` and `docker_test.go` now do.

There's currently no general mocking layer for `system.Run` itself — full
check-level unit tests (as opposed to their extracted pure helpers) still
require a real container per below. A `Runner` interface to make that
mockable is a reasonable follow-up if a check's logic gets complex enough
to need it.

### Container/integration testing

vpsguard shells out to real system tools (`ufw`, `fail2ban-client`,
`systemctl`, `ss`, `crontab`, ...) and reads/writes files like
`/etc/ssh/sshd_config`. **Never run `harden` against your own machine while
developing** — use a disposable Linux container or VM instead:

```bash
docker run -d --name vpsguard-dev --privileged ubuntu:22.04 sleep infinity
docker exec vpsguard-dev bash -c "apt-get update -qq && apt-get install -y -qq \
  openssh-server ufw fail2ban unattended-upgrades cron iproute2 sudo"

GOOS=linux GOARCH=amd64 go build -o vpsguard-linux-amd64 .
docker cp vpsguard-linux-amd64 vpsguard-dev:/usr/local/bin/vpsguard
docker exec vpsguard-dev vpsguard audit
docker exec vpsguard-dev vpsguard harden --dry-run

docker rm -f vpsguard-dev   # clean up when done
```

Note: plain Docker containers don't run systemd, so `systemctl`-dependent
steps (like enabling the fail2ban service) will fail there even when the
code is correct — that's an environment limitation, not a bug. For full
end-to-end verification, use a real VM (e.g. via Vagrant or a cloud
throwaway instance).

## Adding a new audit check

1. Add `internal/checks/<name>.go` with a `func <Name>() []report.Finding`
   that returns one `report.Finding` per condition it evaluates (don't
   bundle unrelated conditions into a single Finding).
2. Register it in `internal/checks/registry.go` (`All` map and `Order`
   slice).
3. If the issue has a safe, well-understood fix, add a matching
   `internal/harden/<name>.go` with `func <Name>(dryRun bool) ([]string, error)`
   and register it in `internal/harden/registry.go`. If there's no safe
   automatic fix (it requires human judgement), leave it audit-only — see
   how `users`, `cron`, and `network` are handled.
4. Update the check table in `README.md`.

Remediations must be **idempotent** (safe to run repeatedly) and must
**back up** any file they modify via `internal/harden.BackupFile` before
writing to it.

## Cutting a release

Releases are built and published automatically by
`.github/workflows/release.yml` whenever a `v*` tag is pushed:

```bash
git tag v0.1.0
git push origin v0.1.0
```

This builds `linux/amd64` and `linux/arm64` binaries with the version baked
in (`vpsguard --version`), generates checksums, and publishes them as
GitHub release assets.

## Pull requests

- Keep PRs focused on one change.
- Explain *why* the change is needed, not just what it does.
- Make sure `gofmt -l .`, `go vet ./...`, and `go test ./...` are clean.
- If you touched a check or remediation, mention how you tested it (ideally
  against a real container/VM, per above) — unit tests cover the parsing
  logic, but they don't replace verifying the check against a real system.

### Branch naming

Fork the repo and branch off `main` using `<type>/<short-description>`,
kebab-case, no issue numbers needed:

| Type | Use for | Example |
|---|---|---|
| `feat/` | a new check, remediation, or CLI capability | `feat/nftables-firewall-check` |
| `fix/` | a bug fix | `fix/cron-empty-crontab-panic` |
| `docs/` | README/CONTRIBUTING/comments only | `docs/clarify-dry-run-flag` |
| `chore/` | tooling, CI, dependency bumps | `chore/bump-cobra` |

This isn't strictly enforced, but it makes the PR list scannable at a
glance and matches the branch prefixes used in this project's own history.

### Commit messages

Short imperative summary line (e.g. "Add nftables support to the firewall
check", not "Added" or "Adding"), blank line, then the *why* if it's not
obvious from the summary alone. Squash-merge is used for PRs, so
intermediate "wip" / "fix typo" commits within a branch are fine — the PR
title and description are what end up in `main`'s history.
