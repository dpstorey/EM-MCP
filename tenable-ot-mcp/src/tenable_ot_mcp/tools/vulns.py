# SPDX-License-Identifier: Apache-2.0
"""Vulnerability tools: query_vulnerabilities, get_vulnerability.

Tenable OT models vulnerabilities as Tenable plugins. Each plugin
describes one vulnerability check; an asset is "affected" when the
asset matches the plugin's triggering conditions.

Filter scope notes (verified live):

  • `severity` (PluginSeverity enum: Info / Low / Medium / High /
    Critical) — supported via Equal / In.
  • `name` Like '%CVE-2023-12345%' — works for CVE-substring matching.
  • `family`, `source`, `owner` — exact-match filters supported.
  • `source` (detection engine) values confirmed from the product UI's
    own network traffic (its `getPluginsGrouped` query, captured via
    browser devtools, not independently reintrospected against the
    `plugins` root field this module calls — `source` is a plain field
    on the same `Plugin` type either way, so this should carry over,
    but flag it if `source` filtering behaves unexpectedly on
    `plugins`): `Nessus` (active scan), `NNM` (Nessus Network Monitor,
    passive), `Tot` (Tenable OT's own native/passive detection engine).
  • Numeric filters on `cvss3Score`, `affectedAssets`, `vprScore` are
    NOT supported by this GraphQL surface (Tenable returns 500 with
    "cannot use array or slice with less than or greater than
    operators"). For score-based prioritization, fetch and sort/filter
    on the projected fields client-side.
  • `query_vulnerabilities`' `vpr_at_least` implements exactly that
    client-side pattern for `vprScore` — don't move it into
    `_build_vuln_filter`/the GraphQL `filter` argument, that reproduces
    the 500 above. A single server page can easily come back with
    fewer VPR-qualifying rows than `limit` (or zero) purely by chance,
    even with plenty more qualifying rows on later pages — and in
    practice, calling LLMs did not reliably notice `has_more` and keep
    paging to compensate (observed: a "top 20" request silently came
    back with 9). So when `vpr_at_least` is set, `query_vulnerabilities`
    fetches additional server pages itself, internally, until it has
    `limit` matches or the site truly runs out (capped at
    `_MAX_VPR_PAGES_PER_CALL` page-fetches per call, to bound worst-case
    latency when the floor is very selective) — see `query_site` below.
    `total_count`/`has_more`/`end_cursor` still describe the server's
    pagination over every *other* filter, not the VPR-narrowed subset;
    if `has_more` comes back true and fewer than `limit` matches were
    found, the safety cap was hit and a caller wanting more should still
    page again with the returned `end_cursor`.
  • `kev_only`, `exploit_available`, etc. live on `PluginDetails`,
    NOT in the top-level `PluginField` filter enum — fetch results
    and inspect the projected flags client-side.
"""

from __future__ import annotations

from typing import Any

from ..audit import AuditLog
from ..tenable_client import TenableClient
from ._enums import EXPR_EQUAL, EXPR_IN, EXPR_LIKE, expr, expr_and
from ._shared import clamp_page_size, project_vuln, unwrap_nodes
from ._sites import resolve_read_site_ids, run_multi_site_read

# ----------------------------------------------------------------------
# GraphQL fragments + queries
# ----------------------------------------------------------------------

# Field whitelist registry: natural name → (top-level field, details subfield)
_FIELD_REGISTRY: dict[str, tuple[str | None, str | None]] = {
    "plugin_id": ("id", None),
    "name": ("name", None),
    "source": ("source", None),
    "family": ("family", None),
    "severity": ("severity", None),
    "vpr_score": ("vprScore", None),
    "vpr_level": ("vprLevel", None),
    "cvss3_score": ("cvss3Score", None),
    "total_affected_assets": ("totalAffectedAssets", None),
    "total_fixed_assets": ("totalFixedAssets", None),
    "description": (None, "description"),
    "solution": (None, "solution"),
    "cves": (None, "cves"),
    "cvss_v3_base_score": (None, "cvssV3BaseScore"),
    "cvss_v3_vector": (None, "cvssV3Vector"),
    "exploit_available": (None, "exploitAvailable"),
    "exploited_by_malware": (None, "exploitedByMalware"),
    "cisa_known_exploited_dates": (None, "cisaKnownExploitedDates"),
    "threat_recency": (None, "threatRecency"),
    "threat_intensity": (None, "threatIntensity"),
    "exploit_code_maturity": (None, "exploitCodeMaturity"),
    "plugin_pub_date": (None, "pluginPubDate"),
    "vuln_pub_date": (None, "vulnPubDate"),
    "age_of_vuln": (None, "ageOfVuln"),
}

# Default lean field set for triage (no description/solution ~4KB blobs)
_LIST_DEFAULT_FIELDS = [
    "plugin_id",
    "name",
    "severity",
    "vpr_score",
    "vpr_level",
    "cvss3_score",
    "total_affected_assets",
    "family",
    "source",
    "cves",
    "exploit_available",
]


def _resolve_fields(requested: list[str] | None) -> list[str]:
    """Validate and normalize the requested field list against the whitelist.

    Returns the lean default set if requested is None/empty. Always includes
    plugin_id. Raises ValueError if unknown fields are requested.
    """
    if not requested:
        return _LIST_DEFAULT_FIELDS

    unknown = [f for f in requested if f not in _FIELD_REGISTRY]
    if unknown:
        raise ValueError(
            f"Unknown fields: {unknown}. Valid options: {sorted(_FIELD_REGISTRY.keys())}"
        )

    # Deduplicate, preserve order, ensure plugin_id is present
    seen = set()
    out = []
    for f in ["plugin_id"] + requested:
        if f not in seen:
            seen.add(f)
            out.append(f)
    return out


def _build_selection(fields: list[str]) -> str:
    """Build GraphQL selection from whitelisted field names.

    Separates top-level fields from details subfields to construct the
    proper nested shape. User input never reaches the query text directly.
    """
    top_level = []
    details_sub = []

    for natural_name in fields:
        top_field, detail_field = _FIELD_REGISTRY[natural_name]
        if top_field:
            top_level.append(top_field)
        if detail_field:
            details_sub.append(detail_field)

    parts = top_level.copy()
    if details_sub:
        parts.append("details { " + " ".join(details_sub) + " }")

    return " ".join(parts)


# Build the static query fragments from the whitelist.  The field-registry
# refactor replaced the former literal _VULN_FIELDS fragment, so both queries
# must be reconstructed before they are referenced below.
_VULN_FIELDS = _build_selection(list(_FIELD_REGISTRY))

_QUERY_VULNS = (
    "query Q($pageSize: Int!, $after: String, "
    "$filter: PluginExpressionsParams, $search: String) { "
    "plugins(first: $pageSize, after: $after, filter: $filter, search: $search) { "
    "pageInfo { hasNextPage endCursor } totalCount "
    "nodes { " + _VULN_FIELDS + " } "
    "} "
    "}"
)


_AFFECTED_ASSET_FIELDS = "id name type vendor model criticality firstSeen lastSeen"

_GET_VULN = (
    "query Q($id: ID!) { plugin(id: $id) { "
    + _VULN_FIELDS
    + " affectedAssets(first: 200) { nodes { "
    + _AFFECTED_ASSET_FIELDS
    + " } } "
    + "} }"
)


# Severity translation — natural floor → list of acceptable severities.
_SEVERITY_ORDINAL = ["info", "low", "medium", "high", "critical"]
_SEVERITY_NATURAL_TO_TENABLE = {
    "info": "Info",
    "low": "Low",
    "medium": "Medium",
    "high": "High",
    "critical": "Critical",
}
SEVERITY_VALUES = list(_SEVERITY_ORDINAL)


def _to_severity_at_least(natural: str) -> list[str]:
    v = (natural or "").strip().lower()
    if v not in _SEVERITY_NATURAL_TO_TENABLE:
        raise ValueError(f"severity must be one of {SEVERITY_VALUES}; got {natural!r}")
    idx = _SEVERITY_ORDINAL.index(v)
    return [_SEVERITY_NATURAL_TO_TENABLE[k] for k in _SEVERITY_ORDINAL[idx:]]


# VPR (Vulnerability Priority Rating) is a continuous 0.1-10.0 score Tenable
# recomputes daily from live threat intelligence — distinct from the static,
# CVSS-derived `severity` band above. Tenable's GraphQL surface 500s on
# relational operators against `vprScore` (see module docstring), so this
# threshold can't join `_build_vuln_filter`; it's applied client-side to each
# fetched page instead, in `query_vulnerabilities` below.
def _validate_vpr_at_least(value: float | int | str | None) -> float | None:
    if value is None:
        return None
    try:
        threshold = float(value)
    except (TypeError, ValueError):
        raise ValueError(f"vpr_at_least must be a number; got {value!r}") from None
    return threshold


# Safety cap on internal page-fetches per call when vpr_at_least is set (see
# module docstring) — bounds worst-case latency/cost if the floor is very
# selective against a large candidate set, at the cost of occasionally
# returning fewer than `limit` matches even though has_more is still true.
_MAX_VPR_PAGES_PER_CALL = 10


# Detection-engine source — natural vocabulary → Tenable's exact casing.
# Confirmed from the product UI's own `getPluginsGrouped` query traffic
# (see module docstring), not independent introspection.
_SOURCE_CANONICAL = {
    "NESSUS": "Nessus",
    "NNM": "NNM",
    "TOT": "Tot",
    "TENABLE_OT": "Tot",
}
SOURCE_VALUES = ["nessus", "nnm", "tot"]


def _to_source(natural: str) -> str:
    v = (natural or "").strip().upper().replace(" ", "_").replace(".", "_")
    if v not in _SOURCE_CANONICAL:
        raise ValueError(f"source must be one of {SOURCE_VALUES}; got {natural!r}")
    return _SOURCE_CANONICAL[v]


def _build_vuln_filter(
    *,
    cve: str | None,
    severity_at_least: str | None,
    family: str | None,
    source: str | None,
) -> dict | None:
    parts: list[dict] = []
    if cve:
        # Plugin names typically contain the CVE id.
        parts.append(expr("name", EXPR_LIKE, [f"%{cve}%"]))
    if severity_at_least:
        parts.append(expr("severity", EXPR_IN, _to_severity_at_least(severity_at_least)))
    if family:
        parts.append(expr("family", EXPR_EQUAL, [family]))
    if source:
        parts.append(expr("source", EXPR_EQUAL, [_to_source(source)]))
    if not parts:
        return None
    if len(parts) == 1:
        return parts[0]
    return expr_and(*parts)


def _project_affected_asset(node: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": node.get("id"),
        "name": node.get("name"),
        "type": node.get("type"),
        "vendor": node.get("vendor"),
        "model": node.get("model"),
        "criticality": node.get("criticality"),
        "first_seen": node.get("firstSeen"),
        "last_seen": node.get("lastSeen"),
    }


# ----------------------------------------------------------------------
# Registration
# ----------------------------------------------------------------------


def register_read_tools(mcp: Any, client: TenableClient, _audit: AuditLog) -> None:
    """Register read-only vulnerability tools."""

    @mcp.tool(
        title="Query OT vulnerabilities",
        description=(
            "Returns Tenable plugins (vulnerabilities) matching the "
            "filter criteria. Each result includes CVEs, CVSS v3 score "
            "and vector, exploit availability flags (CISA KEV, "
            "exploit-available, exploited-by-malware), age, public "
            "disclosure date, and the official vendor solution. Call "
            "`get_vulnerability` on a returned plugin id to see every "
            "affected asset.\n\n"
            "`total_count` is the full number of plugins matching the "
            "filter, independent of the page size — use it to answer "
            "'how many' questions directly. When the match exceeds one "
            "page the response sets `has_more: true` and returns an "
            "`end_cursor`; pass that as `after` to fetch the next page, "
            "repeating until `has_more` is false to walk the entire "
            "matched set.\n\n"
            "Filter values use natural OT vocabulary:\n"
            "  • severity_at_least: one of 'info', 'low', 'medium', "
            "'high', 'critical' — the static, CVSS-derived band\n"
            "  • vpr_at_least: a numeric VPR (Vulnerability Priority "
            "Rating) floor, e.g. 7.0 — Tenable's continuous 0.1-10.0 "
            "daily-recomputed threat-priority score, independent of "
            "severity. Applied client-side (Tenable's API doesn't "
            "support server-side VPR thresholds); this tool fetches "
            "additional pages internally as needed to try to return "
            "`limit` matches in one call. If `has_more` still comes "
            "back true alongside fewer than `limit` results, the VPR "
            "floor is unusually selective — call again with the "
            "returned `end_cursor` as `after` to keep collecting. "
            "`total_count` reflects the other filters only, not this "
            "one.\n"
            "  • cve: a CVE substring (e.g. 'CVE-2023-25619' or "
            "'CVE-2023' for a year-bucket)\n"
            "  • source: which detection engine found it — one of "
            "'nessus' (active scan), 'nnm' (Nessus Network Monitor, "
            "passive), 'tot' (Tenable OT's own native/passive "
            "detection)\n"
            "  • family: exact-match plugin metadata\n\n"
            "For KEV-only or exploit-available filtering, inspect the "
            "projected flags in the response — those live on plugin "
            "details and aren't filterable server-side."
        ),
    )
    async def query_vulnerabilities(
        site_uuid: str | None = None,
        site_name: str | None = None,
        site_uuids: list[str] | None = None,
        cve: str | None = None,
        severity_at_least: str | None = None,
        vpr_at_least: float | None = None,
        family: str | None = None,
        source: str | None = None,
        search: str | None = None,
        limit: int = 50,
        after: str | None = None,
        after_by_site: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Filter vulnerabilities and return a projected list.

        Args:
            site_uuid: Site machine-id UUID. Provide this or `site_name`.
            site_name: Site name to resolve to machine-id UUID. Provide
                this or `site_uuid`.
            cve: A CVE identifier or substring.
            severity_at_least: One of "info" / "low" / "medium" /
                "high" / "critical".
            vpr_at_least: Minimum VPR score (e.g. 7.0). Filtered
                client-side per page — see the description above for
                what that means for `total_count`/`has_more`.
            family: Plugin family (vendor-defined grouping).
            source: Detection engine — one of "nessus" / "nnm" / "tot".
            search: Single-term, case-insensitive substring across
                plugin text fields.
            limit: Maximum results per page (default 50, max 500).
            after: Opaque page cursor. Omit for the first page; to
                continue, pass the `end_cursor` value from the previous
                response. Keep paging while `has_more` is true to
                retrieve every matching vulnerability.
        """
        page_size = clamp_page_size(limit)
        vpr_threshold = _validate_vpr_at_least(vpr_at_least)
        filt = _build_vuln_filter(
            cve=cve,
            severity_at_least=severity_at_least,
            family=family,
            source=source,
        )
        variables: dict[str, Any] = {"pageSize": page_size}
        if filt is not None:
            variables["filter"] = filt
        if search:
            variables["search"] = search
        if after and after_by_site:
            raise ValueError("after cannot be combined with after_by_site")
        site_ids = await resolve_read_site_ids(
            client,
            site_uuid=site_uuid,
            site_name=site_name,
            site_uuids=site_uuids,
        )

        async def query_site(machine_id: str) -> dict[str, Any]:
            site_variables = dict(variables)
            end_cursor = after if len(site_ids) == 1 else (after_by_site or {}).get(machine_id)

            vulnerabilities: list[dict[str, Any]] = []
            total_count = None
            server_has_more = False
            pages_fetched = 0

            while True:
                if end_cursor:
                    site_variables["after"] = end_cursor
                else:
                    site_variables.pop("after", None)
                data = await client.query(
                    _QUERY_VULNS,
                    variables=site_variables,
                    icp_machine_id=machine_id,
                )
                block = data.get("plugins") or {}
                nodes = block.get("nodes") or []
                page_info = block.get("pageInfo") or {}
                total_count = block.get("totalCount")
                end_cursor = page_info.get("endCursor")
                server_has_more = bool(page_info.get("hasNextPage"))
                pages_fetched += 1

                for node in nodes:
                    vulnerability = project_vuln(node)
                    if vpr_threshold is not None:
                        vpr_score = vulnerability.get("vpr_score")
                        if vpr_score is None or float(vpr_score) < vpr_threshold:
                            continue
                    vulnerability["site_uuid"] = machine_id
                    vulnerability["vulnerability_ref"] = {
                        "site_uuid": machine_id,
                        "plugin_id": vulnerability.get("plugin_id"),
                    }
                    vulnerabilities.append(vulnerability)

                if vpr_threshold is None:
                    # No client-side filter in play — one server page per
                    # call, exactly as before this loop existed.
                    break
                if len(vulnerabilities) >= page_size:
                    break
                if not server_has_more:
                    break
                if pages_fetched >= _MAX_VPR_PAGES_PER_CALL:
                    break

            return {
                "site_uuid": machine_id,
                "count": len(vulnerabilities),
                "total_count": total_count,
                "has_more": server_has_more,
                "end_cursor": end_cursor,
                "vulnerabilities": vulnerabilities,
            }

        if len(site_ids) == 1:
            return await query_site(site_ids[0])
        return await run_multi_site_read(site_ids, query_site)

    @mcp.tool(
        title="Get one vulnerability",
        description=(
            "Returns one Tenable plugin (vulnerability) by id, plus "
            "the full list of OT assets currently affected. Use this "
            "to reason about exposure breadth ('which assets are "
            "affected by this exploited-in-the-wild vuln?'). To look "
            "up by CVE id, call `query_vulnerabilities(cve='CVE-...')` "
            "first and then fetch by the returned plugin_id."
        ),
    )
    async def get_vulnerability(
        plugin_id: str,
        site_uuid: str | None = None,
        site_name: str | None = None,
    ) -> dict[str, Any]:
        """Fetch one vulnerability and its affected-asset list.

        Args:
            plugin_id: A Tenable plugin id.
        """
        if not plugin_id:
            raise ValueError("plugin_id is required")
        machine_id = await client.resolve_site_machine_id(site_uuid=site_uuid, site_name=site_name)
        data = await client.query(
            _GET_VULN,
            variables={"id": str(plugin_id)},
            icp_machine_id=machine_id,
        )
        node = data.get("plugin")
        if not node:
            return {
                "vulnerability": None,
                "error": f"No plugin with id {plugin_id!r}.",
            }
        out = project_vuln(node)
        out["site_uuid"] = machine_id
        out["vulnerability_ref"] = {
            "site_uuid": machine_id,
            "plugin_id": str(plugin_id),
        }
        out["affected_assets"] = [
            _project_affected_asset(a) for a in unwrap_nodes(node.get("affectedAssets"))
        ]
        return {"vulnerability": out}
