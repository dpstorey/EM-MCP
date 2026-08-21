# SPDX-License-Identifier: Apache-2.0
"""Regression tests for site-routed single-asset reads."""

from __future__ import annotations

from typing import Any

import pytest

from tenable_ot_mcp.tools.assets import CustomFieldLabelCache, register_read_tools


class FakeMCP:
    def __init__(self) -> None:
        self.tools: dict[str, Any] = {}

    def tool(self, **_kwargs: Any) -> Any:
        def decorator(fn: Any) -> Any:
            self.tools[fn.__name__] = fn
            return fn

        return decorator


class FakeClient:
    def __init__(self, responses: list[dict[str, Any] | Exception]) -> None:
        self.responses = responses
        self.resolve_calls: list[dict[str, str | None]] = []
        self.query_calls: list[dict[str, Any]] = []

    async def resolve_site_machine_id(
        self,
        *,
        site_uuid: str | None,
        site_name: str | None,
    ) -> str:
        self.resolve_calls.append({"site_uuid": site_uuid, "site_name": site_name})
        return site_uuid or f"resolved-{site_name}"

    async def query(
        self,
        query: str,
        variables: dict[str, Any] | None = None,
        *,
        icp_machine_id: str | None = None,
    ) -> dict[str, Any]:
        self.query_calls.append(
            {
                "query": query,
                "variables": variables,
                "icp_machine_id": icp_machine_id,
            }
        )
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


@pytest.fixture(autouse=True)
def clear_custom_field_cache() -> None:
    CustomFieldLabelCache.invalidate()


async def test_get_asset_vulnerabilities_routes_site_and_paginates() -> None:
    client = FakeClient(
        [
            {
                "asset": {
                    "plugins": {
                        "nodes": [],
                        "totalCount": 501,
                        "pageInfo": {"hasNextPage": True, "endCursor": "next-page"},
                    }
                }
            }
        ]
    )
    mcp = FakeMCP()
    register_read_tools(mcp, client, None)  # type: ignore[arg-type]

    result = await mcp.tools["get_asset_vulnerabilities"](
        asset_id="asset-1",
        site_uuid="site-uuid",
        limit=500,
        after="current-page",
    )

    assert client.resolve_calls == [{"site_uuid": "site-uuid", "site_name": None}]
    assert client.query_calls[0]["variables"] == {
        "id": "asset-1",
        "pageSize": 500,
        "after": "current-page",
    }
    assert client.query_calls[0]["icp_machine_id"] == "site-uuid"
    assert result["has_more"] is True
    assert result["end_cursor"] == "next-page"


async def test_get_asset_routes_site_for_asset_and_custom_fields() -> None:
    client = FakeClient(
        [
            {"asset": {"id": "asset-1", "name": "PLC 1"}},
            {"customFields": []},
        ]
    )
    mcp = FakeMCP()
    register_read_tools(mcp, client, None)  # type: ignore[arg-type]

    result = await mcp.tools["get_asset"](asset_id="asset-1", site_name="Plant A")

    assert client.resolve_calls == [{"site_uuid": None, "site_name": "Plant A"}]
    assert [call["icp_machine_id"] for call in client.query_calls] == [
        "resolved-Plant A",
        "resolved-Plant A",
    ]
    assert result["asset"]["id"] == "asset-1"
    assert result["asset"]["asset_ref"] == {
        "site_uuid": "resolved-Plant A",
        "asset_id": "asset-1",
    }


async def test_query_assets_fans_out_and_preserves_site_provenance() -> None:
    client = FakeClient(
        [
            {
                "assets": {
                    "nodes": [{"id": "asset-a", "name": "PLC A"}],
                    "totalCount": 1,
                    "pageInfo": {"hasNextPage": True, "endCursor": "cursor-a"},
                }
            },
            {"customFields": []},
            {
                "assets": {
                    "nodes": [{"id": "asset-b", "name": "PLC B"}],
                    "totalCount": 1,
                    "pageInfo": {"hasNextPage": False, "endCursor": None},
                }
            },
            {"customFields": []},
        ]
    )
    mcp = FakeMCP()
    register_read_tools(mcp, client, None)  # type: ignore[arg-type]

    result = await mcp.tools["query_assets"](
        site_uuids=["site-a", "site-b", "site-a"],
        after_by_site={"site-a": "previous-a"},
    )

    assert result["sites_requested"] == 2
    assert result["sites_succeeded"] == 2
    assert result["sites_failed"] == 0
    by_site = {entry["site_uuid"]: entry for entry in result["results"]}
    assert by_site["site-a"]["assets"][0]["asset_ref"] == {
        "site_uuid": "site-a",
        "asset_id": "asset-a",
    }
    assert by_site["site-b"]["assets"][0]["site_uuid"] == "site-b"
    asset_queries = [call for call in client.query_calls if "assets(" in call["query"]]
    assert asset_queries[0]["variables"]["after"] == "previous-a"
    assert "after" not in asset_queries[1]["variables"]


async def test_query_assets_translates_subnet_to_native_ip_range() -> None:
    client = FakeClient(
        [
            {
                "assets": {
                    "nodes": [{"id": "asset-1", "ips": {"nodes": ["10.253.10.244"]}}],
                    "totalCount": 1,
                    "pageInfo": {"hasNextPage": False, "endCursor": None},
                }
            },
            {"customFields": []},
        ]
    )
    mcp = FakeMCP()
    register_read_tools(mcp, client, None)  # type: ignore[arg-type]

    result = await mcp.tools["query_assets"](
        site_uuid="site-a",
        subnet="10.253.10.128/25",
    )

    assert client.query_calls[0]["variables"]["filter"] == {
        "field": "ips",
        "op": "Between",
        "values": ["10.253.10.128", "10.253.10.255"],
    }
    assert result["assets"][0]["ips"] == ["10.253.10.244"]


async def test_query_assets_rejects_invalid_subnet() -> None:
    client = FakeClient([])
    mcp = FakeMCP()
    register_read_tools(mcp, client, None)  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="invalid subnet CIDR"):
        await mcp.tools["query_assets"](site_uuid="site-a", subnet="10.253.10.999/25")


async def test_multi_site_read_returns_partial_failures() -> None:
    client = FakeClient(
        [
            RuntimeError("site-a unavailable"),
            {
                "assets": {
                    "nodes": [],
                    "totalCount": 0,
                    "pageInfo": {"hasNextPage": False, "endCursor": None},
                }
            },
            {"customFields": []},
        ]
    )
    mcp = FakeMCP()
    register_read_tools(mcp, client, None)  # type: ignore[arg-type]

    result = await mcp.tools["query_assets"](site_uuids=["site-a", "site-b"])

    assert result["sites_succeeded"] == 1
    assert result["sites_failed"] == 1
    assert result["errors"] == [{"site_uuid": "site-a", "error": "site-a unavailable"}]


async def test_multi_site_selector_rejects_conflicting_inputs() -> None:
    client = FakeClient([])
    mcp = FakeMCP()
    register_read_tools(mcp, client, None)  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="cannot be combined"):
        await mcp.tools["query_assets"](
            site_uuid="site-a",
            site_uuids=["site-b"],
        )


async def test_list_custom_fields_routes_across_sites() -> None:
    client = FakeClient(
        [
            {
                "customFields": [
                    {
                        "fieldId": "customField1",
                        "userDefinedName": "Plant",
                        "valueType": "PlainText",
                    }
                ]
            },
            {"customFields": []},
        ]
    )
    mcp = FakeMCP()
    register_read_tools(mcp, client, None)  # type: ignore[arg-type]

    result = await mcp.tools["list_custom_fields"](site_uuids=["site-a", "site-b"])

    assert result["sites_succeeded"] == 2
    assert [call["icp_machine_id"] for call in client.query_calls] == [
        "site-a",
        "site-b",
    ]
