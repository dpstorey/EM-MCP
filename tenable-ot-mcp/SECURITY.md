# Security Policy

## Reporting a vulnerability

If you believe you've found a security vulnerability in this project,
please **do not** open a public issue. Report it privately through GitHub:

  **<https://github.com/dpstorey/EM-MCP/security/advisories/new>**

(Repository **Security** tab, then **Report a vulnerability**.)

This policy covers the code in this repository. The original upstream
project (<https://gitlab.com/jwalley/tenable-ot-mcp>) is a separate codebase
with its own maintainers; issues in code that exists only in the upstream
should be reported there.

Please include:

- A description of the vulnerability and its impact.
- Steps to reproduce, proof-of-concept code, or affected commit/tag.
- Your suggested fix (if any).

You'll get an acknowledgment within 5 business days. We'll work with
you on a coordinated disclosure timeline appropriate to the severity.

## Scope

This project's threat model assumes:

- The Tenable OT service-account API key configured in `/data/config.enc` is
  treated as a production secret. The bearer tokens issued by the
  setup wizard are likewise sensitive.
- The container's `/data` volume is protected by the host's standard
  filesystem permissions; an attacker with shell access to the host
  is outside the threat model.
- HTTPS is on by default: the container generates a self-signed
  certificate on first start. For production, replace it with a
  CA-signed certificate, or set `MCP_TLS_DISABLE=1` and terminate TLS
  at a reverse proxy (nginx, Caddy, Traefik, or a cloud load balancer).
- Write tools are off unless enabled at setup, default to `dry_run=true`,
  and are recorded in `/data/audit.jsonl`.

## Out of scope

- Vulnerabilities in Tenable OT Security itself (report those to
  Tenable directly).
- Vulnerabilities in the consuming MCP client (report those to the
  client's vendor).
- Self-inflicted issues from disabling TLS verification, exposing the
  setup wizard publicly, or sharing bearer tokens.
