# SPDX-License-Identifier: Apache-2.0
"""Builds the FastMCP server and exposes it as a Streamable HTTP ASGI app.

Tool registration is split by domain (assets, vulnerabilities, events,
policies, topology, sensors, summary). Write tools register only when
the operator opted into them at setup time.
"""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

from .audit import AuditLog
from .config import Config
from .tenable_client import TenableClient
from .tools import register_read_tools, register_write_tools

SERVER_INSTRUCTIONS = """\
You are connected to a Tenable OT Security deployment via this MCP
server. Use these tools to answer questions about industrial /
operational-technology assets, vulnerabilities, events, detection
policies, network segmentation, and sensor health.

Operating principles for this data source:

1. **Asset criticality is operator-judged, not vendor-rated.** When a
   user asks "which assets are critical", surface the operator's
   `criticality` field; do not infer criticality from CVSS alone.

2. **OT events are not the same as IT alerts.** `FirmwareVersionChange`,
   `ConfigurationDownload`, `ProgrammingUpload`, and `OperatingMode`
   events represent physical or logical changes to a control device;
   treat them as high-priority for safety review even when severity is
   low. They're often legitimate maintenance — but they ALSO occur
   during attacks, so they require human confirmation.

3. **Detection policies are tunable.** When a policy fires repeatedly
   on the same assets, that's often a tuning gap, not an attack.
   Suggest reviewing the policy's threshold and asset scope before
   recommending a security action.

4. **Vulnerability data has temporal context.** A plugin's
   `vulnPubDate` is when the vulnerability was disclosed; `firstSeen`
   on an affected asset is when this deployment first observed it.
   Patch SLAs are typically measured from `vulnPubDate`, not from
   `firstSeen`.

5. **Topology shapes risk.** Assets in different network segments or
   zones have different exposure profiles. When discussing asset
   risk, surface which segments/zones the asset belongs to.

6. **No analytics are precomputed here.** This server returns joined
   relational data (assets and their links, vulns and their plugins,
   events and their policies). Attack-pathway analysis,
   vulnerability clustering, temporal correlation, and per-asset
   narratives are YOUR job — chain tool calls to walk the
   relationships.

7. **Data is live.** Every tool call queries the customer's Tenable
   OT deployment in real time. Don't cache or assume staleness.

8. **Write tools default to dry-run.** When write tools are
   available, they default to `dry_run=true`; surface the proposed
   change to the user, await confirmation, then call again with
   `dry_run=false`.

9. **Compliance frameworks map to specific data.** NERC CIP cares
   about BES Cyber Asset identification, segmentation, and patch
   management evidence. NEI 08-09 cares about Critical Digital Asset
   inventory and configuration-change detection. NIS2 cares about
   asset registers, risk evidence, and incident detection. When a
   user asks for compliance evidence, target the corresponding tools.

10. **Hide vs remove for assets — pick by intent, not by which sounds
    safer.** Both `hide_asset` and `remove_asset` exist; they're for
    different situations.

    - **Hardware physically pulled / decommissioned / never coming
      back as the same identity** → `remove_asset`. If the same
      hardware later returns to the network, Tenable OT re-discovers
      it as a fresh entry and tracking resumes cleanly.
    - **Asset is staying in the network but the analyst wants it
      filtered out of default views** (test devices, lab equipment,
      known-safe duplicates) → `hide_asset`. The row stays; it's just
      excluded from default dashboards.
    - **Wrong choice — `hide_asset` for pulled hardware** → if that
      hardware ever rejoins the network, Tenable OT matches it back
      to the same hidden row → it stays hidden → silent persistent
      visibility gap. "Hide" sounds intuitively safer than "remove"
      but is the dangerous answer for this case.

    When a user asks to "hide" an asset that's been physically
    pulled, counter-propose `remove_asset` and explain the
    re-discovery behavior.

11. **Tag terminology — do not conflate asset tags with controller
    logic tags.** This server's tag tools (`add_asset_tag`,
    asset filtering by `tags`, asset-group queries) operate on
    **asset tags** — administrative metadata for grouping or
    categorizing assets in the inventory ("safety-critical",
    "production-A", "NEI-08-09-CDA"). Tenable OT also uses the word
    "groups" interchangeably for this concept; under the hood, groups
    are tag-based. **Asset tags are NOT controller logic tags** —
    PLC program variables / datapoints like "MotorSpeed",
    "TankLevel", or "EmergencyStop" that live inside the controller's
    ladder logic or structured text. This server does not expose
    controller-internal tags. When a user says "tag" in conversation,
    confirm intent: "tag this asset" = asset tag (use `add_asset_tag`);
    "find the tags on this PLC's program" = controller logic tags,
    out of scope for this server.

12. **You may DEFINE active scans, never EXECUTE them.** Active
    scanning sends probe traffic into the operator's OT environment
    and has documented history of crashing legacy PLCs and HMIs that
    respond badly to unexpected traffic. This server therefore
    splits scanning into two halves and only exposes the safe half:
    **(a) cognitive work — yours.** Use `create_scan_job` /
    `update_scan_job` to define what to scan, how, and when (targets,
    type, schedule, parameters). Use `list_scan_jobs` /
    `get_scan_job` / `get_scan_job_results` to inspect existing jobs
    and read results. **(b) physical-world trigger — the operator's,
    not yours.** This server does NOT expose `run_scan_job` /
    `trigger_scan_job` or any equivalent. After you've defined a job,
    tell the user to review and run it from the Tenable OT UI. If
    the user says "scan asset X right now," do NOT improvise a
    workaround — explain the human-in-the-loop pattern and offer to
    create the job for them to run.
"""


def build_mcp_app(cfg: Config, audit: AuditLog) -> Any:
    """Construct the FastMCP server and return its Streamable HTTP app.

    The returned object is a Starlette ASGI application that the outer
    server can mount under /mcp. Authentication is handled by the
    outer Starlette layer; this layer trusts that all incoming
    requests have already been authenticated.
    """
    client = TenableClient(
        cfg.tenable_url,
        cfg.tenable_api_key,
        tls_verify=cfg.tls_verify,
    )

    # FastMCP auto-enables DNS-rebinding protection (HTTP 421 on
    # mismatched Host header) when its bind host defaults to a
    # loopback address. That defense targets browser-based attacks
    # where a malicious page tricks the victim's browser into hitting
    # the MCP endpoint. We don't need it: every /mcp request goes
    # through the outer Starlette bearer-token gate first, which a
    # browser-driven DNS-rebinding attack can't satisfy without the
    # operator pasting the token. Pass an explicit
    # TransportSecuritySettings to keep the protection off, regardless
    # of bind host — otherwise eymbr / Claude Desktop / any client
    # connecting by hostname or external IP gets a 421.
    mcp = FastMCP(
        name="tenable-ot-mcp",
        instructions=SERVER_INSTRUCTIONS,
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=False,
        ),
    )

    register_read_tools(mcp, client, audit)
    if cfg.write_tools_enabled:
        register_write_tools(mcp, client, audit)

    return mcp.streamable_http_app()
