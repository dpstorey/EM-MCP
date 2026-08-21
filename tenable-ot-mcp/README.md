<p align="center">
  <a href="https://1clearpath.com">
    <img src="docs/cp_logo.png" alt="OneClearPath, Incorporated" width="180" style="background-color: #0f172a; padding: 16px 24px; border-radius: 8px;">
  </a>
</p>

# Tenable OT MCP Server

> An open-source [Model Context Protocol](https://modelcontextprotocol.io)
> server that exposes [Tenable OT Security](https://www.tenable.com/products/tenable-ot)
> data to any MCP-compatible AI client.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

A [OneClearPath, Incorporated](https://1clearpath.com) project. Author: John Walley.

> ⚠️ **Pre-1.0 — open beta.** Every tool has been live-verified
> against a real Tenable OT deployment, but the surface is wide and
> field exposure has been limited so far. **Please report any bug you
> hit** — with the steps to reproduce if you can — at
> [the issue tracker](https://gitlab.com/jwalley/tenable-ot-mcp/-/issues).
> Faster fixes for everyone, and we'll credit reporters in the
> changelog.

> **Why this exists.** Every OT shop we've worked with hits the same
> wall — their Tenable OT data is trapped behind a custom integration
> for each new AI tool they want to use it with. The Model Context
> Protocol fixes that: one open standard, every client. We built this
> server for ourselves first, then realized the rest of the community
> probably needs it too. We hope you find it useful.
>
> If you're curious about the AI co-worker we built this for, see
> **[Eymbr AI](https://1clearpath.com/eymbr-overview)**.

---

## What this is

A small, stateless container that translates MCP tool calls into live
queries against your Tenable OT Security deployment (direct ICP) or
Enterprise Manager relay target (EM + machine id). AI clients
(Eymbr AI, Claude.ai, ChatGPT, Cursor, custom agents) can query OT
assets, vulnerabilities, events, detection policies, network topology,
sensor health, and active-scan definitions — and, when write tools are
enabled at setup, can hide / restore / remove assets, edit asset
properties (name, type, location, criticality, Purdue level, custom
fields) and manage the custom-field schema, maintain asset groups,
enable / disable / archive detection policies, resolve findings,
define active-scan jobs (operators run them from the Tenable OT UI),
and recalculate risk.

**Design principles:**

- **Stateless.** Tenable OT data never lands on disk inside the container.
  Every tool call is a live GraphQL query to your Tenable OT deployment.
  Data is as fresh as the question.
- **Tools expose data; the AI does the analysis.** No graph algorithms,
  no clustering, no precomputed narratives baked into the server. The
  server returns joined relational data — the consuming AI reasons
  about it.
- **Read-only by default; write access is opt-in.** A single bearer
  token is issued at setup; capabilities follow whether you checked
  "Enable write tools" in the wizard. Every write tool defaults to
  `dry_run=true` so AIs preview changes before mutating state.
- **Standards-aligned.** Streamable HTTP transport, MCP authorization
  spec, RFC 9728 protected-resource metadata. The `/.well-known/oauth-
  protected-resource` document advertises `bearer_methods_supported`
  with an empty `authorization_servers` list, signaling to compliant
  clients that the server uses a static bearer token issued by the
  setup wizard rather than an OAuth flow.

## Install

Pull and run the published image:

```bash
docker run -d \
  --name tenable-ot-mcp \
  -p 40443:40443 \
  -v tenable-ot-mcp-data:/data \
  registry.gitlab.com/jwalley/tenable-ot-mcp:latest
```

For development, air-gapped sites, or to validate the image yourself,
build from source:

```bash
git clone https://gitlab.com/jwalley/tenable-ot-mcp.git
cd tenable-ot-mcp
docker build -t tenable-ot-mcp:local .
docker run -d \
  --name tenable-ot-mcp \
  -p 40443:40443 \
  -v tenable-ot-mcp-data:/data \
  tenable-ot-mcp:local
```

The first start auto-generates a self-signed TLS certificate into
the data volume (`/data/cert.pem`, `/data/key.pem`) — HTTPS is on
by default. Verify the container is up:

```bash
curl -k https://localhost:40443/healthz
# {"status":"ok","configured":false,"version":"..."}
```

`configured: false` means setup hasn't run yet — that's the next step.

**TLS options:**

- The auto-generated cert covers `localhost`, `127.0.0.1`, and `::1`.
  If you'll reach the server by hostname or external IP, add it to
  the SAN on first run:
  `-e MCP_TLS_HOSTNAME=mcp.example.com,10.2.9.207`. Setting this
  later regenerates the cert against the new SAN list.
- To use your own CA-signed cert, drop `cert.pem` and `key.pem` into
  the data volume before starting (or set `MCP_TLS_CERT` /
  `MCP_TLS_KEY` to alternative paths inside the container).
- To run plain HTTP behind a TLS-terminating reverse proxy, set
  `MCP_TLS_DISABLE=1`.

## Run setup

The first-run wizard verifies connectivity to your Tenable OT
deployment endpoint (direct ICP or EM relay), generates the bearer
tokens MCP clients will use, and
writes the encrypted configuration to `/data/config.enc`.

1. Open `https://<host>:40443/setup` in a browser. (With the
   auto-generated self-signed cert, your browser will warn about an
   untrusted certificate — accept and proceed. Replace with a
   CA-signed cert before exposing the server beyond a trusted
   network.)

2. Fill in the form:

   - **Tenable OT / EM URL** — `https://<your-tenable-ot-or-em-host>`.
     Do not append `/graphql`; the server adds the path itself.
   - **Tenable OT API key** — a service-account key from your Tenable OT
     deployment. Use a read-only key if you don't plan to enable
     write tools; use a read-write key if you do.
   - **Verify TLS** — leave checked unless your Tenable OT presents a
     self-signed certificate.
   - **Enable write tools** — opt-in. Adds tools that hide / restore
     assets, edit asset properties (name, type, location, criticality,
     Purdue level, custom fields), manage custom-field schema slots,
     enable / disable detection policies, resolve findings, define
     active scans, and so on. Every write tool defaults to
     `dry_run=true`, and every call (preview or applied) is recorded
     in `/data/audit.jsonl`.

3. Submit. The wizard tries a real GraphQL call against your configured
  endpoint before saving. A failure here means the URL, key,
  or TLS setting is wrong — fix and resubmit.

Site-scoped reads accept `site_uuid` (machine id) or `site_name`. Collection,
search, and summary reads also accept `site_uuids` for bounded concurrent
fan-out across multiple sites. Multi-site responses keep results, errors, and
pagination state separated by site so records never lose their provenance.
Entity-detail reads remain single-site and return qualified references such as
`asset_ref`. Every write requires exactly one explicit site; write tools never
accept a site array or fall back to mutable session state. When `site_name` is
provided, the server resolves and caches its machine id via EM paired-ICP
inventory.

4. **Copy the bearer token(s) shown on the success page.** They're
   displayed once and never again. If you lose them, delete
   `/data/config.enc` and `/data/config.key` on the host volume and
   re-run setup.

5. **Restart the container.** The wizard saved config to disk, but
   the MCP endpoint comes up only after a restart so its session
   manager initializes against the saved config:

   ```bash
   docker restart tenable-ot-mcp
   ```

Confirm setup landed:

```bash
curl -k https://localhost:40443/healthz
# {"status":"ok","configured":true,"version":"..."}
```

## Connect a client

The MCP endpoint URL is:

```
https://<your-host>:40443/mcp
```

Three things matter and are easy to miss:

- **`https://`**, not `http://` (HTTPS is on by default).
- **`:40443`** — the listen port. Required unless you remapped it
  with `-p 443:40443` and accept root-on-the-host trade-offs.
- **`/mcp`** path. Without it your client will hit the server root
  and get a 404. The setup-complete page (and the matching token
  panel) shows the exact URL — copy from there.

Pass the bearer token in the `Authorization: Bearer <token>` header.
For self-signed certificates the client must skip TLS verification
(every example below shows how).

**Eymbr AI** — Admin → Integrations → MCP → Add MCP Server. Paste
the full URL including `:40443/mcp`, set Auth to "Bearer token" and
paste the bearer token, and toggle **Verify TLS certificate** off
while the cert is self-signed.

**Claude Desktop** — add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "tenable-ot": {
      "transport": "http",
      "url": "https://localhost:40443/mcp",
      "headers": { "Authorization": "Bearer <your-bearer-token>" }
    }
  }
}
```

**Python (`mcp` SDK)**:

```python
import httpx
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamablehttp_client

# Only needed while the server is using a self-signed cert. Drop the
# factory once you've installed a CA-signed cert.
def insecure_factory(headers=None, timeout=None, auth=None):
    return httpx.AsyncClient(headers=headers, timeout=timeout, auth=auth, verify=False)

async with streamablehttp_client(
    "https://localhost:40443/mcp",
    headers={"Authorization": "Bearer <your-bearer-token>"},
    httpx_client_factory=insecure_factory,
) as (read, write, _):
    async with ClientSession(read, write) as session:
        await session.initialize()
        tools = await session.list_tools()
```

Treat the bearer token like a service-account password with the
capabilities you opted into at setup — anyone holding it acts through
the server at that access level.

## Why MCP

Every AI tool used to need its own custom integration with every data
source. MCP standardizes the connection: one server, many clients. By
exposing Tenable OT through MCP, your investment in the integration carries
across every AI tool you adopt.

## Tools

114 tools across 11 categories: 48 read tools always available, 66
write tools that register only when the operator enables write
access at setup time. Full per-tool reference in
[`docs/TOOL_CATALOG.md`](docs/TOOL_CATALOG.md).

Headlines:

- **Asset domain** — `query_assets`, `get_asset`, `get_asset_vulnerabilities`,
  `list_custom_fields`; asset queries support exact CIDR filtering through
  `subnet` in addition to free-text search
- **Vulnerability domain** — `query_vulnerabilities`, `get_vulnerability`
- **Event domain** — `query_events`, `get_event`; event queries accept an
  explicit `asset_id` for asset-scoped event history
- **Detection policies** — `list_detection_policies`, `query_policy_findings`
- **Network topology** — `list_segments_and_zones`, `get_communication_paths`
- **Sensor health** — `list_sensors`
- **Correlation (relational projections, not server-side analytics)** —
  `query_attack_pathways`, `query_vulnerability_clusters`,
  `query_temporal_patterns`, `get_asset_intelligence`
- **Summary** — `summarize_environment`
- **Enterprise Manager** — `list_paired_icps` (queries EM root to list
  paired ICP sites and machine ids)
- **Active scans (define / inspect, never execute)** —
  `list_active_scans`, `get_active_scan`, `get_active_scan_executions`,
  the generic `define_active_scan` / `edit_active_scan` pair, the
  per-type pairs with typed options (`define_port_scan` /
  `edit_port_scan`, `define_snmp_scan` / `edit_snmp_scan`,
  `define_controller_discovery_scan` / `edit_controller_discovery_scan`,
  `define_asset_discovery_scan` / `edit_asset_discovery_scan`,
  `define_inactive_probing_scan` / `edit_inactive_probing_scan`,
  plus `edit_subnets_discovery_scan`), and the lifecycle
  `enable_active_scan` / `disable_active_scan` / `delete_active_scan`.
  The server deliberately does not expose any tool that runs a scan —
  that's a human-only action via the Tenable OT UI, because active
  scanning has caused operational incidents on legacy PLCs in the wild.
- **Groups** — full CRUD + paginated reads over Tenable's eight
  group concepts: asset groups (polymorphic — AssetList / IpList /
  IpRange / TypeFamily / Segment / Filter, with CIDR shorthand),
  email groups (recipient lists for policy actions), schedule groups
  (one-shot windows and weekly recurring), tag groups (PLC
  controller-tag rollups), rule groups (IDS rule SID bundles), port
  groups, protocol groups, and user / EM-user groups for permission
  management. Plus helpers like `list_eligible_tags`,
  `find_email_groups_using_smtp_server`, `set_user_groups`.
- **Writes (opt-in, dry-run-default, audit-logged)** —
  hide / restore / remove assets (single + bulk), edit asset properties
  (`update_asset`, `bulk_edit_assets`, `reset_asset_metadata`) covering
  name, type, location, description, Purdue level, criticality, and
  custom-field values keyed by their configured label, custom-field
  schema management (`create_custom_field`, `rename_custom_field`,
  `delete_custom_field`), recalculate risk, single + bulk
  detection-policy enable / disable / archive, resolve findings.

## Compatible AI clients

- **[Eymbr AI](https://1clearpath.com/eymbr-overview)** — native,
  on-premise, OT-focused AI co-worker. Air-gapped deployment, runs on
  local NVIDIA hardware, trained with the customer's own documents.
  The original consumer of this server and its reference deployment.
- claude.ai (web), Claude desktop — paste the server URL and bearer
  token in the connector settings.
- ChatGPT — via the MCP connector preview.
- Cursor / Windsurf / VS Code — via their MCP support.
- Any client built on the official MCP SDKs (Python, TypeScript).

## Configuration

State the container persists:

- `/data/cert.pem` + `/data/key.pem` — TLS keypair. Auto-generated as
  self-signed on first start (covers `localhost`, `127.0.0.1`, `::1`,
  plus anything in `MCP_TLS_HOSTNAME`). Replace with a CA-signed
  certificate before exposing the server beyond a trusted network.
- `/data/config.enc` + `/data/config.key` — encrypted (Fernet)
  configuration: Tenable OT URL, Tenable OT API key, the MCP bearer
  token, the `tls_verify` and `write_tools_enabled` flags. The key
  file is generated once on first start and never rotated by the
  server — to rotate, delete both files and re-run the setup wizard.
- `/data/audit.jsonl` — append-only audit trail. One JSON line per
  write-tool invocation: timestamp, tool name, parameters, dry-run
  flag, outcome (`ok` / `error` / `preview`), upstream Tenable OT
  status, and any error message. The server never reads this file
  back; ship it to a SIEM or rotate by truncating.

Environment variables (all optional; defaults work for typical
deployments):

| Variable | Default | Purpose |
|---|---|---|
| `MCP_BIND_HOST` | `0.0.0.0` | Listen address. |
| `MCP_BIND_PORT` | `40443` | Listen port. |
| `MCP_DATA_DIR` | `/data` | Persistent state directory. |
| `MCP_LOG_LEVEL` | `info` | Uvicorn/server log level. One of `critical`, `error`, `warning`, `info`, `debug`, `trace`. |
| `MCP_DEBUG_GRAPHQL` | (off) | Set to `1` to log Tenable GraphQL endpoint routing details (endpoint URL, root vs relay mode, and variable keys). |
| `MCP_TLS_CERT` | (auto-generated) | Path to a PEM-encoded TLS certificate. When unset, a self-signed cert is generated into the data directory on first start. |
| `MCP_TLS_KEY` | (auto-generated) | Path to the matching PEM private key. Must be set whenever `MCP_TLS_CERT` is. |
| `MCP_TLS_HOSTNAME` | (none) | Comma-separated extra hostnames or IPs to add to the auto-generated cert's Subject Alternative Name. Set this on first run if clients will reach the server by hostname or external IP. Changing the value regenerates the cert. |
| `MCP_TLS_DISABLE` | (off) | Set to `1` to fall back to plain HTTP. Only appropriate when a TLS-terminating reverse proxy sits in front of the container. |

## Security

This server holds a Tenable OT service-account API key. Treat the volume
holding `/data` and the bearer tokens it generates as you would any
production secret store.

To report a vulnerability: see [SECURITY.md](SECURITY.md).

## Changelog

Full history in [CHANGELOG.md](CHANGELOG.md).

**0.4.1** — Cursor pagination on the `query_assets`, `query_events`,
and `query_vulnerabilities` read tools. Each now accepts an `after`
cursor and returns `end_cursor` alongside `has_more`, so result sets
larger than one page can be walked in full — pass the previous
response's `end_cursor` as `after` until `has_more` is false.
`total_count` already returns the exact match count regardless of page
size, so "how many" questions never needed pagination. Also realigns
the version across `pyproject.toml`, `__init__.py`, and the changelog.

**0.3.3** — Bugfix: every `/mcp` request raised a `TypeError`
(`'NoneType' object is not callable`) in the server logs. Single
request/response clients (e.g. Claude Code) still got their answers, but
clients that hold the server-to-client SSE stream open — notably Open
WebUI — failed on tool use. The bearer-auth gate now runs as a raw ASGI
app, leaving the full streaming lifecycle to the MCP sub-app. Upgrade if
you connect a streaming MCP client.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Code of conduct in
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Partner programs

OneClearPath, Incorporated participates in the partner programs below.
The relationships do not imply endorsement or sponsorship of this
specific open-source project by either organization.

<p align="left">
  <a href="https://www.tenable.com/partners/technology" title="Tenable Assure Partner">
    <img src="https://1clearpath.com/hs-fs/hubfs/tenable-assure-logo-inverse.png?width=300&height=93&name=tenable-assure-logo-inverse.png" alt="Tenable Assure Partner" height="60">
  </a>
  &nbsp;&nbsp;&nbsp;
  <a href="https://www.nvidia.com/en-us/startups/" title="NVIDIA Inception Program">
    <img src="https://1clearpath.com/hs-fs/hubfs/nvidia-inception.png?width=150&height=56&name=nvidia-inception.png" alt="NVIDIA Inception" height="60">
  </a>
</p>

## License

Apache 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

This is an independent open-source project and is not affiliated with,
endorsed by, or sponsored by Tenable, Inc. "Tenable" and "Tenable OT
Security" are trademarks of Tenable, Inc.
