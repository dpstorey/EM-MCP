# SPDX-License-Identifier: Apache-2.0
"""Attackers View: batch-generate and analyze Tenable OT's server-computed
attack vectors across a CIDR-scoped pool of assets.

Tenable OT/EM already computes a real attack vector per asset (the UI's
"Attack Vectors" tab, "Generate" action) — it walks recorded conversation
data to find a path from an entry point (or an automatically-selected one)
to the target asset, weighted by risk. That computation, its async job
handle, and its result shape are NOT exposed by any tool in this server
today: `query_attack_pathways` (correlation.py) is a *different*,
purely-relational 1-hop neighbor walk that explicitly leaves path-finding
to the calling AI. This module wraps the actual server-side algorithm.

Reverse-engineered from a captured HAR against a live deployment (not
documented publicly). Three GraphQL operations, one endpoint:

  1. `mutation generateAttackVector(dstAsset: ID!, constraints: {maxLength: Int!, srcAsset: ID})`
     -> returns a `Job` (`id`, `status: Pending`). `srcAsset` omitted
     means "select an entry point automatically" (matches the UI's
     "Select Source Automatically").
  2. `query getJob(id: ID!)` -> poll until `status` is `Success` or
     `Failure`. On `Success`, `value` is a JSON *string* holding a bare
     path (asset ids only, no names/risk-on-source) — not what we want
     to hand an LLM.
  3. `query getAssetAttackVector` (`asset(id).attackVector`) -> the
     enriched, UI-rendered shape: same steps, but each endpoint is a
     fully expanded `Asset` (name, type, criticality, risk, IPs). This
     is what gets fetched after a successful generate.

Empirically, a `Failure` with an error like "asset not accessible - no
conversations" is not a transient/flaky result — it is an accurate,
deterministic answer that this asset has no recorded communications to
build a path from *right now*. It will not change on an immediate retry;
it changes only when real traffic is later recorded for that asset. This
module therefore never retries a `Failure` automatically. Instead it
tracks a streak of consecutive `no_path_found` results across the asset
pool and stops itself early once the streak crosses `stop_on_streak`,
returning the completed work plus the untouched remainder — so the
calling AI can tell the human "N assets in a row have no conversations,
want me to keep going?" rather than silently grinding through a mostly-
dead CIDR or aborting on the first empty asset.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import time
from collections import Counter
from typing import Any

from ..audit import AuditLog
from ..tenable_client import TenableClient
from ._attack_diagram import build_attack_mermaid, is_fatality_grade
from ._enums import EXPR_BETWEEN, EXPR_EQUAL, EXPR_LIKE, expr, expr_and, expr_or
from ._shared import clamp_page_size, unwrap_nodes
from ._sites import resolve_read_site_ids, run_multi_site_read
from .assets import CustomFieldLabelCache

_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

DEFAULT_MAX_HOPS = 5
DEFAULT_MAX_ASSETS = 25
DEFAULT_STOP_ON_STREAK = 3
DEFAULT_POLL_INTERVAL_S = 1.5
DEFAULT_POLL_TIMEOUT_S = 30.0
DEFAULT_CONSECUTIVE_ERROR_LIMIT = 2
# Safety-grade lookup for diagram highlighting (RAISE "S" custom field).
FATALITY_FIELD_LABEL = "S"
_FATALITY_LOOKUP_CONCURRENCY = 5
_CUSTOM_SLOT_RE = re.compile(r"^customField(?:[1-9]|10)$")

# ----------------------------------------------------------------------
# GraphQL
# ----------------------------------------------------------------------

_ASSET_POOL_FIELDS = """
  id
  name
  type
  criticality
  risk { totalRisk }
  ips(first: 10) { nodes }
"""

_QUERY_ASSET_POOL = (
    "query Q($pageSize: Int!, $after: String, $filter: AssetExpressionsParams) { "
    "assets(first: $pageSize, after: $after, filter: $filter) { "
    "pageInfo { hasNextPage endCursor } "
    "totalCount "
    "nodes { " + _ASSET_POOL_FIELDS + " } "
    "} "
    "}"
)

_LOOKUP_ASSET_BY_NAME = (
    "query Q($filter: AssetExpressionsParams) { "
    "assets(first: 5, filter: $filter) { nodes { " + _ASSET_POOL_FIELDS + " } } "
    "}"
)

_MUTATE_GENERATE_ATTACK_VECTOR = """
mutation M($asset: ID!, $length: Int!, $source: ID) {
  generateAttackVector(dstAsset: $asset, constraints: {maxLength: $length, srcAsset: $source}) {
    id
    status
    error
  }
}
"""

_QUERY_JOB = """
query Q($id: ID!) {
  job(id: $id) {
    id
    status
    error
    value
  }
}
"""

_ATTACK_VECTOR_ASSET_FIELDS = """
    type
    name
    criticality
    risk { totalRisk unresolvedEvents }
    directIps { nodes }
"""

_QUERY_ASSET_ATTACK_VECTOR = (
    "query Q($asset: ID!) { "
    "asset(id: $asset) { "
    "id "
    "attackVector { "
    "creationTime "
    "steps { nodes { "
    "srcRisk "
    "srcAssetOrIps { id ips { nodes } ... on Asset { " + _ATTACK_VECTOR_ASSET_FIELDS + " } } "
    "dstRisk "
    "dstAssetOrIps { id ips { nodes } ... on Asset { " + _ATTACK_VECTOR_ASSET_FIELDS + " } } "
    "protocols { nodes } "
    "lastProtocolUsed "
    "lastConversationTime "
    "backplaneComm "
    "externalComm "
    "} } "
    "} "
    "} "
    "}"
)


# ----------------------------------------------------------------------
# Filter / lookup helpers
# ----------------------------------------------------------------------


def _looks_like_uuid(value: str) -> bool:
    return bool(_UUID_RE.match(value.strip()))


def _cidr_filter(cidrs: list[str]) -> dict:
    """Build an `ips Between` expression per CIDR, OR'd together, ANDed
    with `hidden: false` (matches the UI's default asset-pool scope).
    """
    parts: list[dict] = []
    for cidr in cidrs:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError as exc:
            raise ValueError(f"invalid CIDR {cidr!r}: {exc}") from exc
        parts.append(
            expr("ips", EXPR_BETWEEN, [str(network.network_address), str(network.broadcast_address)])
        )
    cidr_expr = parts[0] if len(parts) == 1 else expr_or(*parts)
    return expr_and(cidr_expr, expr("hidden", EXPR_EQUAL, [False]))


async def _resolve_asset_pool(
    client: TenableClient,
    machine_id: str,
    *,
    cidrs: list[str],
    max_assets: int,
) -> list[dict[str, Any]]:
    """Page through `assets(filter: <cidr OR-filter>)` up to `max_assets`."""
    page_size = clamp_page_size(min(max_assets, 100), default=50)
    filt = _cidr_filter(cidrs)
    pool: list[dict[str, Any]] = []
    after: str | None = None
    while len(pool) < max_assets:
        data = await client.query(
            _QUERY_ASSET_POOL,
            variables={"pageSize": page_size, "after": after, "filter": filt},
            icp_machine_id=machine_id,
        )
        block = data.get("assets") or {}
        nodes = block.get("nodes") or []
        pool.extend(nodes)
        page_info = block.get("pageInfo") or {}
        if not page_info.get("hasNextPage"):
            break
        after = page_info.get("endCursor")
        if not after:
            break
    return pool[:max_assets]


async def _resolve_entry_point(
    client: TenableClient,
    machine_id: str,
    entry_point: str | None,
) -> str | None:
    """Resolve `entry_point` to an asset id, or None for "automatic".

    Accepts a bare asset UUID directly (recommended — get one from
    `query_assets`). As a convenience, also accepts an exact asset name
    or an IP address and resolves it via a lookup; raises with guidance
    rather than guessing if nothing (or more than one asset) matches an
    IP, since silently picking the wrong entry point would misattribute
    an entire attack path.
    """
    if not entry_point:
        return None
    candidate = entry_point.strip()
    if _looks_like_uuid(candidate):
        return candidate

    if candidate.count(".") == 3 or ":" in candidate:
        try:
            ipaddress.ip_address(candidate)
            is_ip = True
        except ValueError:
            is_ip = False
    else:
        is_ip = False

    filt = expr("ips", EXPR_EQUAL, [candidate]) if is_ip else expr("name", EXPR_EQUAL, [candidate])
    data = await client.query(_LOOKUP_ASSET_BY_NAME, variables={"filter": filt}, icp_machine_id=machine_id)
    nodes = (data.get("assets") or {}).get("nodes") or []
    if not nodes:
        # Fall back to a substring match on name before giving up.
        if not is_ip:
            data = await client.query(
                _LOOKUP_ASSET_BY_NAME,
                variables={"filter": expr("name", EXPR_LIKE, [f"%{candidate}%"])},
                icp_machine_id=machine_id,
            )
            nodes = (data.get("assets") or {}).get("nodes") or []
    if not nodes:
        raise ValueError(
            f"entry_point={entry_point!r} did not resolve to any asset by exact name, "
            "substring, or IP. Do not guess or retry with a modified value — call "
            "`query_assets` to find the exact asset id and pass that instead."
        )
    if len(nodes) > 1:
        names = [f"{n.get('name')} ({n.get('id')})" for n in nodes[:5]]
        raise ValueError(
            f"entry_point={entry_point!r} matched {len(nodes)} assets: {names}. "
            "Pass the exact asset id (from `query_assets`) instead of a name/IP "
            "that could be ambiguous."
        )
    return nodes[0]["id"]


# ----------------------------------------------------------------------
# Attack-vector generation + projection
# ----------------------------------------------------------------------


def _project_endpoint(node: dict[str, Any] | None) -> dict[str, Any] | None:
    """Project one step's `srcAssetOrIps` / `dstAssetOrIps` union member.

    `None` means "outside the known asset inventory" (the UI's "External
    Network" root node — the true start of a path, since every path's
    first step has `srcAssetOrIps: null`). A resolved-but-bare IP (no
    `Asset` fragment matched) is returned with `is_asset: False`.
    """
    if node is None:
        return None
    is_asset = "type" in node or "criticality" in node
    risk = node.get("risk") or {}
    return {
        "id": node.get("id"),
        "is_asset": is_asset,
        "name": node.get("name"),
        "type": node.get("type"),
        "criticality": node.get("criticality"),
        "total_risk": risk.get("totalRisk"),
        "unresolved_events": risk.get("unresolvedEvents"),
        "ips": unwrap_nodes(node.get("ips")) or unwrap_nodes(node.get("directIps")),
    }


def _project_attack_vector(asset_attack_vector: dict[str, Any] | None) -> dict[str, Any]:
    """Flatten `asset(id).attackVector` into an ordered hop list plus
    a few derived signals that are cheap here and expensive for an LLM
    to reconstruct from the raw graph: whether the path starts at the
    external network, whether it crosses a backplane or leaves the
    network, and the riskiest hop.
    """
    if not asset_attack_vector:
        return {"creation_time": None, "hop_count": 0, "hops": [], "starts_external": None}
    steps = unwrap_nodes((asset_attack_vector.get("steps") or {}))
    hops = []
    max_risk = None
    for i, step in enumerate(steps):
        src = _project_endpoint(step.get("srcAssetOrIps"))
        dst = _project_endpoint(step.get("dstAssetOrIps"))
        dst_risk = step.get("dstRisk")
        if dst_risk is not None:
            max_risk = dst_risk if max_risk is None else max(max_risk, dst_risk)
        hops.append(
            {
                "hop": i + 1,
                "src": src,
                "dst": dst,
                "src_risk": step.get("srcRisk"),
                "dst_risk": dst_risk,
                "protocols": unwrap_nodes(step.get("protocols")),
                "last_protocol_used": step.get("lastProtocolUsed"),
                "last_conversation_time": step.get("lastConversationTime"),
                "backplane_comm": bool(step.get("backplaneComm")),
                "external_comm": bool(step.get("externalComm")),
            }
        )
    return {
        "creation_time": asset_attack_vector.get("creationTime"),
        "hop_count": len(hops),
        "hops": hops,
        "starts_external": bool(hops) and hops[0]["src"] is None,
        "crosses_backplane": any(h["backplane_comm"] for h in hops),
        "has_external_comm": any(h["external_comm"] for h in hops),
        "max_hop_risk": max_risk,
        "oldest_conversation": min(
            (h["last_conversation_time"] for h in hops if h["last_conversation_time"]),
            default=None,
        ),
    }


async def _generate_and_fetch(
    client: TenableClient,
    machine_id: str,
    asset_id: str,
    *,
    source_id: str | None,
    max_hops: int,
    poll_interval: float,
    poll_timeout: float,
) -> dict[str, Any]:
    """Run generate -> poll -> enriched-fetch for one asset.

    Returns one of:
      {"outcome": "path_found", "asset_id", "attack_vector": {...}}
      {"outcome": "no_path_found", "asset_id", "error": "<job error>"}
      {"outcome": "timeout", "asset_id", "job_id"}
      {"outcome": "error", "asset_id", "error": "<exception message>"}
    """
    try:
        gen = await client.query(
            _MUTATE_GENERATE_ATTACK_VECTOR,
            variables={"asset": asset_id, "length": max_hops, "source": source_id},
            icp_machine_id=machine_id,
        )
        job = gen.get("generateAttackVector") or {}
        job_id = job.get("id")
        if not job_id:
            return {"outcome": "error", "asset_id": asset_id, "error": job.get("error") or "no job id returned"}

        deadline = time.monotonic() + poll_timeout
        status = job.get("status")
        while status not in ("Success", "Failure"):
            if time.monotonic() >= deadline:
                return {"outcome": "timeout", "asset_id": asset_id, "job_id": job_id}
            await asyncio.sleep(poll_interval)
            poll = await client.query(_QUERY_JOB, variables={"id": job_id}, icp_machine_id=machine_id)
            job = poll.get("job") or {}
            status = job.get("status")

        if status == "Failure":
            return {
                "outcome": "no_path_found",
                "asset_id": asset_id,
                "error": job.get("error") or "generation failed with no error message",
            }

        # Success — fetch the enriched, UI-equivalent shape rather than
        # trusting the job's own bare-ids `value` payload.
        fetched = await client.query(
            _QUERY_ASSET_ATTACK_VECTOR, variables={"asset": asset_id}, icp_machine_id=machine_id
        )
        attack_vector = (fetched.get("asset") or {}).get("attackVector")
        return {
            "outcome": "path_found",
            "asset_id": asset_id,
            "attack_vector": _project_attack_vector(attack_vector),
        }
    except Exception as exc:  # noqa: BLE001 — isolate one asset's failure from the batch
        return {"outcome": "error", "asset_id": asset_id, "error": str(exc)}


# ----------------------------------------------------------------------
# Batch analysis
# ----------------------------------------------------------------------


def _analyze_batch(path_found: list[dict[str, Any]]) -> dict[str, Any]:
    """Fleet-level synthesis across every successfully generated path —
    the thing a single-asset UI view can't show: which intermediate
    assets act as chokepoints across *many* different targets' paths.
    """
    chokepoints: Counter[tuple[str, str]] = Counter()
    riskiest: list[tuple[float, str]] = []
    stalest: list[tuple[str, str]] = []
    external_exposure = 0
    backplane_crossings = 0

    for entry in path_found:
        asset_id = entry["asset_id"]
        av = entry["attack_vector"]
        hops = av.get("hops") or []
        # Count each intermediate asset once per *path*, not once per hop —
        # a linear path's intermediate node is both a hop's dst and the
        # next hop's src, so per-hop counting would double it.
        seen_in_this_path: set[tuple[str, str]] = set()
        for hop in hops:
            for endpoint in (hop.get("src"), hop.get("dst")):
                if endpoint and endpoint.get("id") and endpoint.get("id") != asset_id:
                    key = (endpoint["id"], endpoint.get("name") or endpoint["id"])
                    seen_in_this_path.add(key)
        for key in seen_in_this_path:
            chokepoints[key] += 1
        if av.get("max_hop_risk") is not None:
            riskiest.append((av["max_hop_risk"], asset_id))
        if av.get("oldest_conversation"):
            stalest.append((av["oldest_conversation"], asset_id))
        if av.get("has_external_comm"):
            external_exposure += 1
        if av.get("crosses_backplane"):
            backplane_crossings += 1

    riskiest.sort(key=lambda t: t[0], reverse=True)
    stalest.sort(key=lambda t: t[0])  # oldest (smallest ISO timestamp) first

    return {
        "chokepoints": [
            {"asset_id": aid, "name": name, "appears_in_paths": count}
            for (aid, name), count in chokepoints.most_common(10)
            if count > 1
        ],
        "riskiest_targets": [{"asset_id": aid, "max_hop_risk": risk} for risk, aid in riskiest[:10]],
        "stalest_paths": [
            {"asset_id": aid, "oldest_conversation": ts} for ts, aid in stalest[:10]
        ],
        "external_exposure_count": external_exposure,
        "backplane_crossing_count": backplane_crossings,
    }


# ----------------------------------------------------------------------
# Optional Mermaid diagram
# ----------------------------------------------------------------------


async def _fetch_fatality_ids(
    client: TenableClient, machine_id: str, asset_ids: list[str]
) -> tuple[set[str], str | None]:
    """Return (asset ids whose Safety grade is D or E, warning-or-None).

    Reads the custom field labelled `S` (the RAISE Safety grade) for each
    asset. A failed lookup never fails the batch: the caller gets a
    warning string so the diagram is never presented as "no fatalities"
    when the grades simply couldn't be read.
    """
    try:
        label_map = await CustomFieldLabelCache.get_or_fetch(client, icp_machine_id=machine_id)
    except Exception as exc:  # noqa: BLE001
        return set(), f"custom-field schema lookup failed: {exc}"
    slot = next((s for s, label in label_map.items() if label == FATALITY_FIELD_LABEL), None)
    if not slot or not _CUSTOM_SLOT_RE.match(slot):
        return set(), f"no custom field labelled {FATALITY_FIELD_LABEL!r} on this site"

    query = "query Q($asset: ID!) { asset(id: $asset) { id " + slot + " } }"
    sem = asyncio.Semaphore(_FATALITY_LOOKUP_CONCURRENCY)

    async def one(asset_id: str) -> tuple[str, Any]:
        async with sem:
            data = await client.query(query, variables={"asset": asset_id}, icp_machine_id=machine_id)
            return asset_id, (data.get("asset") or {}).get(slot)

    results = await asyncio.gather(*(one(a) for a in asset_ids), return_exceptions=True)
    fatal: set[str] = set()
    failed = 0
    for res in results:
        if isinstance(res, BaseException):
            failed += 1
            continue
        asset_id, grade = res
        if is_fatality_grade(grade):
            fatal.add(asset_id)
    warning = f"Safety-grade lookup failed for {failed} of {len(asset_ids)} assets" if failed else None
    return fatal, warning


async def _diagram_fields(
    client: TenableClient,
    machine_id: str,
    path_found: list[dict[str, Any]],
    summary: dict[str, Any],
    *,
    paused: bool,
) -> dict[str, Any]:
    """Build the optional `mermaid*` result fields. Never raises."""
    if not path_found:
        return {"mermaid": None, "mermaid_note": "No path_found results in this call, so there is nothing to draw."}
    try:
        asset_ids = sorted(
            {
                ep["id"]
                for entry in path_found
                for hop in (entry.get("attack_vector") or {}).get("hops") or []
                for ep in (hop.get("src"), hop.get("dst"))
                if ep and ep.get("is_asset") and ep.get("id")
            }
        )
        fatal, warning = await _fetch_fatality_ids(client, machine_id, asset_ids)
        mermaid = build_attack_mermaid(
            path_found,
            chokepoint_ids=[c["asset_id"] for c in summary.get("chokepoints") or []],
            fatality_ids=fatal,
        )
    except Exception as exc:  # noqa: BLE001 — a diagram problem must not lose the batch results
        return {"mermaid": None, "mermaid_note": f"Diagram generation failed: {exc}"}

    notes = ["Output `mermaid` verbatim in a ```mermaid code fence. Do not redraw or edit it."]
    if paused:
        notes.append("Run is paused: this diagram covers only the paths found so far in this call.")
    if warning:
        notes.append(f"Fatality highlighting may be incomplete: {warning}.")
    return {
        "mermaid": mermaid,
        "mermaid_fatality_asset_ids": sorted(fatal),
        "mermaid_note": " ".join(notes),
    }


# ----------------------------------------------------------------------
# Registration
# ----------------------------------------------------------------------


def register_read_tools(mcp: Any, client: TenableClient, _audit: AuditLog) -> None:
    """Register the Attackers View tool."""

    @mcp.tool(
        title="Batch-generate and analyze attack vectors (Attackers View)",
        description=(
            "Drives Tenable OT/EM's own server-side attack-vector "
            "computation (the UI's Attack Vectors tab 'Generate' action) "
            "across every asset in one or more CIDRs, then analyzes the "
            "results as a fleet rather than one asset at a time.\n\n"
            "For each asset in scope: (1) triggers "
            "`generateAttackVector` — an async job that walks recorded "
            "conversation data from an entry point (or an automatically "
            "chosen one) to that asset, weighted by risk; (2) polls the "
            "job to completion; (3) on success, fetches the enriched "
            "path (named/typed/risk-scored assets at every hop, not "
            "bare ids).\n\n"
            "A `Failure` (most commonly 'asset not accessible - no "
            "conversations') is not an error to retry — it is an "
            "accurate answer that the asset has no recorded "
            "communications to build a path from right now, and won't "
            "change until real traffic is later recorded for it. This "
            "tool never auto-retries a Failure. Instead it tracks a "
            "streak of consecutive no-path-found assets; once that "
            "streak reaches `stop_on_streak`, it stops immediately — "
            "without touching the rest of the pool — and returns "
            "`remaining_asset_ids` plus a `paused_reason`. Surface this "
            "to the user and ask whether to continue (call again with "
            "`asset_ids=remaining_asset_ids` and `force_through=true`) "
            "or stop here; do not decide silently either way. A "
            "genuine transport/API error (as opposed to a job Failure) "
            "instead stops the batch after `DEFAULT_CONSECUTIVE_ERROR_LIMIT` "
            "consecutive occurrences, since that signals a systemic "
            "problem, not per-asset data.\n\n"
            "Returns per-asset outcomes bucketed as `path_found` / "
            "`no_path_found` / `timeout` / `error`, plus a `summary` "
            "with fleet-level synthesis: `chokepoints` (intermediate "
            "assets that recur across multiple different targets' "
            "paths — the actual high-value pivot points a single-asset "
            "view can't reveal), `riskiest_targets`, `stalest_paths` "
            "(paths whose supporting conversation data is oldest — "
            "likely theoretical rather than currently live), and "
            "external-network / backplane exposure counts.\n\n"
            "By default the result also carries `mermaid`: a ready-made, "
            "syntactically valid Mermaid `flowchart LR` of every "
            "`path_found` (one node per asset, labelled edges, "
            "chokepoints and Safety-grade D/E assets highlighted). "
            "Output it verbatim; do not redraw it. Pass "
            "`include_diagram=false` when no diagram is wanted — it "
            "saves tokens and one Safety-grade lookup per asset."
        ),
    )
    async def get_attackers_view(
        cidrs: list[str] | None = None,
        asset_ids: list[str] | None = None,
        entry_point: str | None = None,
        max_hops: int = DEFAULT_MAX_HOPS,
        max_assets: int = DEFAULT_MAX_ASSETS,
        stop_on_streak: int = DEFAULT_STOP_ON_STREAK,
        force_through: bool = False,
        include_diagram: bool = True,
        site_uuid: str | None = None,
        site_name: str | None = None,
        site_uuids: list[str] | None = None,
    ) -> dict[str, Any]:
        """Batch-generate and analyze attack vectors across a CIDR-scoped
        asset pool.

        Args:
            cidrs: One or more CIDRs (e.g. '10.253.10.0/24') defining the
                target asset pool. Ignored if `asset_ids` is given.
            asset_ids: Explicit asset ids to process instead of resolving
                `cidrs` — use this to resume a paused run by passing back
                the previous response's `remaining_asset_ids`.
            entry_point: Asset id (recommended — from `query_assets`), or
                a best-effort exact name / IP, to use as the attack
                path's source. Omit to let the server select
                automatically (matches the UI's "Select Source
                Automatically").
            max_hops: Maximum path length Tenable will search (its
                `constraints.maxLength`). Default 5, matching the UI.
            max_assets: Safety cap on how many assets this call will
                process — each asset costs a mutation, one or more job
                polls, and an enriched read. Default 25.
            stop_on_streak: Stop early after this many consecutive
                `no_path_found` results, returning what's done so far
                plus `remaining_asset_ids`. 0 disables early-stop for an
                intentional full unattended sweep.
            force_through: Set true (typically when resuming with
                `asset_ids`) to disable the streak-based early-stop for
                this call.
            include_diagram: Default true. Adds `mermaid` (ready-made
                attack-path diagram, see tool description) to each
                site's result. Set false when no diagram is needed.
            site_uuid / site_name / site_uuids: Site selector(s), same
                convention as every other tool in this server.
        """
        if not asset_ids and not cidrs:
            raise ValueError("provide either `cidrs` or `asset_ids`")
        if max_assets < 1:
            raise ValueError("max_assets must be at least 1")

        site_ids = await resolve_read_site_ids(
            client, site_uuid=site_uuid, site_name=site_name, site_uuids=site_uuids
        )

        async def run_for_site(machine_id: str) -> dict[str, Any]:
            if asset_ids:
                pool = [{"id": aid} for aid in asset_ids[:max_assets]]
            else:
                pool = await _resolve_asset_pool(
                    client, machine_id, cidrs=cidrs or [], max_assets=max_assets
                )
            source_id = await _resolve_entry_point(client, machine_id, entry_point)

            path_found: list[dict[str, Any]] = []
            no_path_found: list[dict[str, Any]] = []
            timeouts: list[dict[str, Any]] = []
            errors: list[dict[str, Any]] = []

            no_path_streak = 0
            error_streak = 0
            paused_reason: str | None = None
            processed_ids: set[str] = set()

            for entry in pool:
                asset_id = entry["id"]
                result = await _generate_and_fetch(
                    client,
                    machine_id,
                    asset_id,
                    source_id=source_id,
                    max_hops=max_hops,
                    poll_interval=DEFAULT_POLL_INTERVAL_S,
                    poll_timeout=DEFAULT_POLL_TIMEOUT_S,
                )
                processed_ids.add(asset_id)
                outcome = result["outcome"]

                if outcome == "path_found":
                    path_found.append(result)
                    no_path_streak = 0
                    error_streak = 0
                elif outcome == "no_path_found":
                    no_path_found.append(result)
                    no_path_streak += 1
                    error_streak = 0
                elif outcome == "timeout":
                    timeouts.append(result)
                    no_path_streak = 0
                    error_streak = 0
                else:  # error
                    errors.append(result)
                    error_streak += 1
                    no_path_streak = 0

                if error_streak >= DEFAULT_CONSECUTIVE_ERROR_LIMIT:
                    paused_reason = (
                        f"{error_streak} consecutive transport/API errors — this looks "
                        "systemic (auth, connectivity, or a downed relay), not "
                        "per-asset data. Stopped before burning through the rest "
                        "of the pool on the same failure."
                    )
                    break
                if (
                    not force_through
                    and stop_on_streak
                    and no_path_streak >= stop_on_streak
                ):
                    paused_reason = (
                        f"{no_path_streak} consecutive assets with no recorded "
                        "conversations to build a path from. This may mean this "
                        "part of the network is quiet/dead, not that anything is "
                        "wrong. Ask the user whether to continue through the "
                        "remaining assets or stop here."
                    )
                    break

            remaining = [
                entry["id"] for entry in pool if entry["id"] not in processed_ids
            ]

            summary = _analyze_batch(path_found)
            diagram = (
                await _diagram_fields(
                    client, machine_id, path_found, summary, paused=paused_reason is not None
                )
                if include_diagram
                else {}
            )

            return {
                "site_uuid": machine_id,
                "requested_count": len(pool),
                "processed_count": len(processed_ids),
                "path_found": path_found,
                "no_path_found": no_path_found,
                "timeouts": timeouts,
                "errors": errors,
                "paused": paused_reason is not None,
                "paused_reason": paused_reason,
                "remaining_asset_ids": remaining,
                "summary": summary,
                **diagram,
            }

        if len(site_ids) == 1:
            return await run_for_site(site_ids[0])
        return await run_multi_site_read(site_ids, run_for_site)
