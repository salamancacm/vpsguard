# Security Policy

vpsguard modifies system security configuration (SSH, firewall, fail2ban,
file permissions) on real servers. A bug here can range from "annoying" to
"locked yourself out of your VPS" to "silently weakened a server's
security." We take reports seriously.

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

Instead, use [GitHub's private vulnerability reporting](../../security/advisories/new)
for this repository, or email the maintainer directly if that's not
available to you. Include:

- A description of the issue and its impact (e.g. "harden's ufw step can
  lock out SSH access if the port is misdetected")
- Steps to reproduce, ideally against a disposable VM or container
- Affected version/commit

We'll acknowledge reports within a few days and aim to ship a fix (and a
credit, if you'd like one) before any public disclosure.

## Scope

Examples of what's in scope:

- A `harden` remediation that could lock an operator out of their server
- An `audit` check that reports a vulnerable configuration as safe (a false
  negative), or a safe one as vulnerable in a way that leads to a harmful
  "fix" (a false positive with consequences)
- Privilege escalation, path traversal, or command injection in how
  vpsguard shells out to system tools or reads/writes files
- Insecure handling of SSH keys, passwords, or other sensitive data touched
  by the tool

Out of scope: vulnerabilities in third-party tools vpsguard shells out to
(ufw, fail2ban, sshd itself, etc.) — please report those upstream.
