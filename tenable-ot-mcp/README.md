# Tenable OT MCP Server (Enterprise Manager edition)

> An open-source [Model Context Protocol](https://modelcontextprotocol.io)
> server that exposes [Tenable OT Security](https://www.tenable.com/products/tenable-ot)
> to MCP-compatible AI clients, with Enterprise Manager (EM) site routing,
> guarded write tools and policy-creation tools.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

Repository: <https://github.com/dpstorey/EM-MCP> (this server lives in `tenable-ot-mcp/`).
Maintained by Dom Storey. Issues and pull requests belong on this repository's tracker.

> [!NOTE]
> **Use this repository, not the original project.** This is a fork of
> [`tenable-ot-mcp` by John Walley / OneClearPath, Incorporated](https://gitlab.com/jwalley/tenable-ot-mcp)
> (Apache-2.0), who deserve the credit for the original server. It has since
> diverged: EM routing by `site_uuid`/`site_name`, the narrow policy-creation
> tools, the attackers-view tools and the agent skills in `skills/` do not exist
> upstream. **Do not pull the upstream container image
> (`registry.gitlab.com/jwalley/tenable-ot-mcp`) or clone the upstream repository
> to use with this one.** Doing so swaps in a different codebase, and the skills
> here (including the IEC 62443 onboarding skill) will break against it. Build
> the image from this repository as described below.
>
> **Status: pre-1.0.** Read tools and the policy-creation tools are live-verified
> against Tenable OT. Other write tools have had less field exposure; see
> [CHANGELOG.md](CHANGELOG.md). Please report bugs, with steps to reproduce, on
> the [issue tracker](https://github.com/dpstorey/EM-MCP/issues).

> [!TIP]
> **Branches.** `main` is the full tool set, including the attackers-view tools.
> For small local models, where shorter tool schemas and fewer registered tools
> work more reliably, use the
> [`small-model`](https://github.com/dpstorey/EM-MCP/tree/small-model) branch:
> the same server and policy-creation tools without the attackers-view tools.

---

## What this is

A small, stateless container that translates MCP tool calls into live GraphQL
queries against your Tenable OT Security deployment, either a direct ICP or an
Enterprise Manager relay (EM plus the paired site's machine id). AI clients
(Claude Desktop, Claude Code, LibreChat, Cursor, custom agents) can query
assets, vulnerabilities, events, detection policies, network topology, sensor
health and active-scan definitions. When write tools are enabled at setup they
can also maintain asset groups and other group types, create, update and
enable/disable detection policies, hide/restore/remove assets, edit asset
properties, resolve findings and define active-scan jobs. Operators run scans
from the Tenable OT UI; no tool executes one.

**Design principles:**

- **Stateless.** Tenable OT data never lands on disk inside the container.
- **Tools expose data; the AI does the analysis.** The server returns joined
  relational data and leaves the reasoning to the consuming AI.
- **Read-only by default; write access is opt-in.** Writes require "Enable
  write tools" at setup (`write_tools_enabled`). Every write tool defaults to
  `dry_run=true`, targets exactly one explicit site, and every call, preview or
  applied, is appended to `/data/audit.jsonl`.
- **Small tools for small models.** Wide forms are split into narrow tools (one
  create tool per policy type, for example) so a local model sees a short schema,
  and clients with per-tool toggles can leave unused tools off.
- **Standards-aligned.** Streamable HTTP transport, MCP authorization spec,
  RFC 9728 protected-resource metadata, static bearer token from the setup wizard.

## Enterprise Manager and sites

Site-scoped tools accept `site_uuid` (the paired ICP's machine id) or
`site_name`; `list_paired_icps` lists them. Collection, search and summary reads
also accept `site_uuids` for bounded concurrent fan-out, and responses keep
results, errors and pagination state separate per site. Detail reads are
single-site and return qualified references. **Every write requires exactly one
explicit site**; write tools never accept a site array or fall back to
remembered session state. When `site_name` is given, the server resolves and
caches its machine id from the EM paired-ICP inventory.

## Policy creation

Detection policies are created with one narrow tool per policy type, for example
`create_conversation_policy` (the "unauthorized conversation" policy),
`create_asset_policy`, `create_port_policy` and `create_intrusion_policy`.
`describe_policy_type` (no network) lists a type's parameters and enum values,
`get_policy` reads one policy and `update_policy` replaces one. Source and
destination scoping uses Tenable's conjunctive normal form (outer list AND,
inner list OR, per-member negate). `initial_state="disabled"` creates the policy
and then disables it; a failure of the second step is reported, never silent.
See [`docs/TOOL_CATALOG.md`](docs/TOOL_CATALOG.md) and [CHANGELOG.md](CHANGELOG.md).

## Agent skills

Task-level workflows that drive these tools live in [`../skills/`](../skills/).
The IEC 62443 zones-and-conduits onboarding skill is also published on its own
at <https://github.com/dpstorey/T1OTE_IEC62443>.

## Install

Build the image from this repository:

```bash
git clone https://github.com/dpstorey/EM-MCP.git
cd EM-MCP/tenable-ot-mcp
docker build -t tenable-ot-mcp:local .
docker run -d \
  --name tenable-ot-mcp \
  -p 40443:40443 \
  -v tenable-ot-mcp-data:/data \
  tenable-ot-mcp:local
```

There is no published image for this edition. If you publish one, use your own
registry and image name, never the upstream one.

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

## Tools

The full per-tool reference, with current counts, is in
[`docs/TOOL_CATALOG.md`](docs/TOOL_CATALOG.md). Read tools are always available;
write tools register only when write access was enabled at setup. Categories:

- **Assets, vulnerabilities, events** — `query_assets`, `get_asset`,
  `query_vulnerabilities`, `query_vulnerability_findings`, `query_events`,
  with cursor pagination and exact `total_count`.
- **Detection policies** — `list_detection_policies`, `query_policy_findings`,
  `get_policy`, `describe_policy_type`, the `create_*_policy` tools and
  `update_policy`.
- **Topology, sensors, summary, correlation** — `list_segments_and_zones`,
  `get_communication_paths`, `list_sensors`, `summarize_environment`, and
  relational projections such as `query_attack_pathways` (the attackers-view tools).
- **Enterprise Manager** — `list_paired_icps`.
- **Groups** — CRUD and paginated reads over asset, email, schedule, tag, rule,
  port, protocol and user groups.
- **Active scans (define and inspect, never execute)** — generic and per-type
  define/edit tools plus enable, disable and delete. No tool runs a scan:
  active scanning has caused incidents on legacy PLCs.
- **Writes (opt-in, dry-run-default, audit-logged)** — hide/restore/remove
  assets, edit asset properties and custom fields, recalculate risk,
  enable/disable/archive policies, resolve findings.

## Compatible AI clients

Claude Desktop and Claude Code, LibreChat (with per-tool enable and lazy
loading), Cursor, Windsurf, VS Code, and any client built on the official MCP
SDKs. Paste the server URL and bearer token into the client's MCP settings.

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

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Code of conduct in
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## License and credits

Apache 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

Original server: Copyright 2026 OneClearPath, Incorporated, by John Walley
(<https://gitlab.com/jwalley/tenable-ot-mcp>). Modifications in this repository
are by Dom Storey under the same license. The upstream project is a separate
codebase and is not required, and not recommended, for running this one.

This is an independent open-source project and is not affiliated with, endorsed
by, or sponsored by Tenable, Inc. "Tenable" and "Tenable OT Security" are
trademarks of Tenable, Inc.
