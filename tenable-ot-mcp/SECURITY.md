# Security Policy

## Reporting a vulnerability

If you believe you've found a security vulnerability in this project,
please **do not** open a public issue. Instead, email:

  **security@1clearpath.com**

Or use GitLab's confidential issue feature if you prefer the issue
tracker. Mark the issue **Confidential** before submitting.

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
- TLS termination for production deployments is provided by a reverse
  proxy in front of the container (nginx, Caddy, Traefik, or a cloud
  load balancer). The container itself listens on plain HTTP by
  default.

## Out of scope

- Vulnerabilities in Tenable OT Security itself (report those to
  Tenable directly).
- Vulnerabilities in the consuming MCP client (report those to the
  client's vendor).
- Self-inflicted issues from disabling TLS verification, exposing the
  setup wizard publicly, or sharing bearer tokens.
