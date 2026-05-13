# Security Policy

## Supported Versions

serpent-wrt is pre-1.0 software. Security fixes are applied to the current
`main` branch and included in the next tagged release when releases are
available.

## Reporting a Vulnerability

Please do not open a public issue with exploit details, private lab topology,
credentials, tokens, or packet captures.

Preferred reporting path:

1. Use GitHub private vulnerability reporting for this repository if it is
   available.
2. If private reporting is unavailable, open a minimal public issue asking for
   a security contact. Do not include sensitive details in that issue.

Useful report details include:

- Affected version or commit.
- OpenWrt target and architecture.
- Whether enforcement was enabled.
- Expected behavior and observed behavior.
- Minimal reproduction steps that avoid sharing sensitive network data.

## Scope

Security issues include vulnerabilities in detection logic, nftables enforcement,
unsafe default configuration, remote API exposure, privilege handling, and
packaging/install behavior.

Issues in third-party routers, OpenWrt itself, nftables, kernel conntrack, or
external threat feeds should also be reported to the relevant upstream project.
