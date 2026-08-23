# SPDX-License-Identifier: Apache-2.0
"""Regression tests for `query_vulnerability_findings`.

Field/filter names here (findingField enum values like `pluginId`,
`pluginSeverity`, `findingStatus`, `findingLastHit`, `assetId`, and the
`Finding` object's own fields: id/port/protocol/svcName/firstHit/
lastHit/fixedAt/status/output/asset/plugin) were confirmed live via
GraphQL introspection against a Tenable OT/EM 4.7.44 instance — not
guessed. See `tools/vuln_findings.py`'s module docstring for context.
"""

from __future__ import annotations

from typing import Any

import pytest

from tenable_ot_mcp.tools.vuln_findings import (
    _build_finding_filter,
    _project_vulnerability_finding,
    register_read_tools,
)


class FakeMCP:
    def __init__(self) -> None:
        self.tools: dict[str, Any] = {}

    def tool(self, **_kwargs: Any) -> Any:
        def decorator(fn: Any) -> Any:
            self.tools[fn.__name__] = fn
            return fn

        return decorator


class FakeClient:
    def __init__(self, responses: list[dict[str, Any]]) -> None:
        self.responses = responses
        self.query_calls: list[dict[str, Any]] = []

    async def resolve_site_machine_id(
        self,
        *,
        site_uuid: str | None,
        site_name: str | None,
    ) -> str:
        return site_uuid or f"resolved-{site_name}"

    async def query(
        self,
        query: str,
        variables: dict[str, Any] | None = None,
        *,
        icp_machine_id: str | None = None,
    ) -> dict[str, Any]:
        self.query_calls.append(
            {"query": query, "variables": variables, "icp_machine_id": icp_machine_id}
        )
        return self.responses.pop(0)


_FINDING_NODE = {
    "id": "finding-1",
    "port": 443,
    "protocol": "TCP",
    "svcName": "https",
    "firstHit": "2026-01-01T00:00:00Z",
    "lastHit": "2026-06-01T00:00:00Z",
    "fixedAt": None,
    "status": "Active",
    "output": "TLS 1.0 supported",
    "asset": {"id": "asset-1", "name": "PLC 1", "type": "Plc"},
    "plugin": {
        "id": "12345",
        "name": "SSL/TLS Weak Cipher (CVE-2024-0001)",
        "severity": "High",
        "vprScore": 7.2,
        "vprLevel": "High",
        "cvss3Score": 7.5,
        "details": {"cves": ["CVE-2024-0001"]},
    },
}


# ---- projection -------------------------------------------------------------


def test_project_vulnerability_finding_flattens_asset_and_plugin() -> None:
    projected = _project_vulnerability_finding(_FINDING_NODE)
    assert projected["id"] == "finding-1"
    assert projected["status"] == "Active"
    assert projected["port"] == 443
    assert projected["protocol"] == "TCP"
    assert projected["service_name"] == "https"
    assert projected["first_hit_time"] == "2026-01-01T00:00:00Z"
    assert projected["last_hit_time"] == "2026-06-01T00:00:00Z"
    assert projected["fixed_at"] is None
    assert projected["output"] == "TLS 1.0 supported"
    assert projected["plugin_id"] == "12345"
    assert projected["plugin_name"] == "SSL/TLS Weak Cipher (CVE-2024-0001)"
    assert projected["severity"] == "High"
    assert projected["cves"] == ["CVE-2024-0001"]
    assert projected["asset_id"] == "asset-1"
    assert projected["asset_name"] == "PLC 1"
    assert projected["asset_type"] == "Plc"


def test_project_vulnerability_finding_handles_missing_nested_objects() -> None:
    projected = _project_vulnerability_finding({"id": "finding-2", "status": "Resolved"})
    assert projected["asset_id"] is None
    assert projected["plugin_id"] is None
    assert projected["cves"] == []


# ---- filter builder ---------------------------------------------------------


def test_build_finding_filter_plugin_id_uses_equal() -> None:
    filt = _build_finding_filter(
        plugin_id="12345", cve=None, severity_at_least=None, status=None, asset_id=None, since=None
    )
    assert filt == {"field": "pluginId", "op": "Equal", "values": ["12345"]}


def test_build_finding_filter_cve_uses_like_on_plugin_name() -> None:
    filt = _build_finding_filter(
        plugin_id=None,
        cve="CVE-2024-0001",
        severity_at_least=None,
        status=None,
        asset_id=None,
        since=None,
    )
    assert filt == {"field": "pluginName", "op": "Like", "values": ["%CVE-2024-0001%"]}


def test_build_finding_filter_status_translates_natural_vocab() -> None:
    filt = _build_finding_filter(
        plugin_id=None, cve=None, severity_at_least=None, status="active", asset_id=None, since=None
    )
    assert filt == {"field": "findingStatus", "op": "Equal", "values": ["Active"]}


def test_build_finding_filter_rejects_unknown_status() -> None:
    with pytest.raises(ValueError, match="status must be one of"):
        _build_finding_filter(
            plugin_id=None,
            cve=None,
            severity_at_least=None,
            status="closed",
            asset_id=None,
            since=None,
        )


def test_build_finding_filter_combines_multiple_parts_with_and() -> None:
    filt = _build_finding_filter(
        plugin_id="12345",
        cve=None,
        severity_at_least=None,
        status="active",
        asset_id=None,
        since=None,
    )
    assert filt["op"] == "And"
    fields = [e["field"] for e in filt["expressions"]]
    assert fields == ["pluginId", "findingStatus"]


def test_build_finding_filter_returns_none_when_no_args() -> None:
    assert (
        _build_finding_filter(
            plugin_id=None,
            cve=None,
            severity_at_least=None,
            status=None,
            asset_id=None,
            since=None,
        )
        is None
    )


# ---- tool wiring -------------------------------------------------------------


async def test_query_vulnerability_findings_routes_site_and_projects() -> None:
    client = FakeClient(
        [
            {
                "findings": {
                    "nodes": [_FINDING_NODE],
                    "totalCount": 1,
                    "pageInfo": {"hasNextPage": False, "endCursor": None},
                }
            }
        ]
    )
    mcp = FakeMCP()
    register_read_tools(mcp, client, None)  # type: ignore[arg-type]

    result = await mcp.tools["query_vulnerability_findings"](
        site_uuid="site-a",
        status="active",
    )

    call = client.query_calls[0]
    assert "findings(" in call["query"]
    assert call["icp_machine_id"] == "site-a"
    assert call["variables"]["filter"] == {
        "field": "findingStatus",
        "op": "Equal",
        "values": ["Active"],
    }
    assert result["site_uuid"] == "site-a"
    assert result["total_count"] == 1
    finding = result["findings"][0]
    assert finding["id"] == "finding-1"
    assert finding["site_uuid"] == "site-a"
    assert finding["finding_ref"] == {"site_uuid": "site-a", "finding_id": "finding-1"}
    assert finding["asset_ref"] == {"site_uuid": "site-a", "asset_id": "asset-1"}
    assert finding["vulnerability_ref"] == {"site_uuid": "site-a", "plugin_id": "12345"}


async def test_query_vulnerability_findings_fans_out_across_sites() -> None:
    site_a = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    site_b = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
    empty = {
        "findings": {
            "nodes": [],
            "totalCount": 0,
            "pageInfo": {"hasNextPage": False, "endCursor": None},
        }
    }
    client = FakeClient([empty, empty])
    mcp = FakeMCP()
    register_read_tools(mcp, client, None)  # type: ignore[arg-type]

    result = await mcp.tools["query_vulnerability_findings"](site_uuids=[site_a, site_b])

    assert result["sites_requested"] == 2
    assert result["sites_succeeded"] == 2
    assert [c["icp_machine_id"] for c in client.query_calls] == [site_a, site_b]


async def test_query_vulnerability_findings_rejects_after_with_after_by_site() -> None:
    client = FakeClient([])
    mcp = FakeMCP()
    register_read_tools(mcp, client, None)  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="cannot be combined"):
        await mcp.tools["query_vulnerability_findings"](
            site_uuid="site-a", after="cursor", after_by_site={"site-a": "cursor"}
        )
