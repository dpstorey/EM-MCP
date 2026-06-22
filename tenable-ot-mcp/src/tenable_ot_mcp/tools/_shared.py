# SPDX-License-Identifier: Apache-2.0
"""Cross-domain helpers used by multiple tool modules.

Projectors live here when they're consumed by more than one domain
module (e.g. `_project_vuln` is consumed by both the asset domain — for
`get_asset_vulnerabilities` — and the vulnerability domain).
"""

from __future__ import annotations

from typing import Any


def unwrap_nodes(connection: Any) -> list[Any]:
    """Tenable OT wraps array fields in `{nodes: [...]}` (Relay style).
    This collapses the wrapper safely when either the field or its
    `nodes` key is missing."""
    if not connection:
        return []
    return (connection or {}).get("nodes") or []


def project_vuln(node: dict[str, Any]) -> dict[str, Any]:
    """Plugin/vulnerability projection — flat shape with the triage
    signals a consuming AI typically asks about (CVEs, CVSSv3, KEV flag,
    exploit availability, age, public-disclosure date).
    """
    details = node.get("details") or {}
    cves = details.get("cves") or []
    return {
        "plugin_id": node.get("id"),
        "name": node.get("name"),
        "source": node.get("source"),
        "family": node.get("family"),
        "severity": node.get("severity"),
        "vpr_score": node.get("vprScore"),
        "vpr_level": node.get("vprLevel"),
        "cvss3_score": node.get("cvss3Score"),
        "cvss3_vector": details.get("cvssV3Vector"),
        "cves": cves if isinstance(cves, list) else [],
        "exploit_available": bool(details.get("exploitAvailable")),
        "exploited_by_malware": bool(details.get("exploitedByMalware")),
        "cisa_kev_dates": details.get("cisaKnownExploitedDates") or [],
        "exploit_code_maturity": details.get("exploitCodeMaturity"),
        "threat_recency": details.get("threatRecency"),
        "vuln_pub_date": details.get("vulnPubDate"),
        "plugin_pub_date": details.get("pluginPubDate"),
        "age_of_vuln_days": details.get("ageOfVuln"),
        "total_affected_assets": node.get("totalAffectedAssets"),
        "description": details.get("description"),
        "solution": details.get("solution"),
    }


def project_event(node: dict[str, Any]) -> dict[str, Any]:
    """Event projection. Returns the time, classification (eventType),
    severity, source/destination assets, the firing detection policy,
    and any related finding id. Date fields are passed through as ISO
    strings — the LLM can reason about timezones if needed.
    """
    event_type = node.get("eventType") or {}
    policy = node.get("policy") or {}
    src_assets = unwrap_nodes(node.get("srcAssets"))
    dst_assets = unwrap_nodes(node.get("dstAssets"))
    return {
        "id": node.get("id"),
        "time": node.get("time"),
        "resolved": node.get("resolved"),
        "resolved_ts": node.get("resolvedTs"),
        "resolved_user": node.get("resolvedUser"),
        "type": event_type.get("type"),
        "type_group": event_type.get("group"),
        "type_category": event_type.get("category"),
        "type_family": event_type.get("family"),
        "type_description": event_type.get("description"),
        "severity": node.get("severity"),
        "category": node.get("category"),
        "src_ip": node.get("srcIP"),
        "dst_ip": node.get("dstIP"),
        "src_mac": node.get("srcMac"),
        "dst_mac": node.get("dstMac"),
        "protocol": node.get("protocolNiceName") or node.get("protocol"),
        "port": node.get("port"),
        "src_assets": [{"id": a.get("id"), "name": a.get("name")} for a in src_assets],
        "dst_assets": [{"id": a.get("id"), "name": a.get("name")} for a in dst_assets],
        "policy": (
            {
                "id": policy.get("id"),
                "title": policy.get("title"),
                "level": policy.get("level"),
            }
            if policy
            else None
        ),
        "finding_id": node.get("findingId"),
        "comment": node.get("comment"),
        "completion": node.get("completion"),
        "continuous": node.get("continuous"),
        "payload_size": node.get("payloadSize"),
    }


def clamp_page_size(limit: int | None, default: int = 50, maximum: int = 500) -> int:
    """Sanity-clamp a tool's `limit` parameter for pagination."""
    if limit is None:
        return default
    return max(1, min(int(limit), maximum))
