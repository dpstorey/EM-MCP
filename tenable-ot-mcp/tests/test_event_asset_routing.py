# SPDX-License-Identifier: Apache-2.0
"""Regression tests for asset-scoped event queries."""

from __future__ import annotations

from typing import Any

import pytest

from tenable_ot_mcp.tools.events import register_read_tools


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


async def test_query_events_uses_asset_event_connection_and_paginates() -> None:
    client = FakeClient(
        [
            {
                "asset": {
                    "events": {
                        "nodes": [{"id": "event-1", "resolved": False}],
                        "totalCount": 145,
                        "pageInfo": {"hasNextPage": True, "endCursor": "next-events"},
                    }
                }
            }
        ]
    )
    mcp = FakeMCP()
    register_read_tools(mcp, client, None)  # type: ignore[arg-type]

    result = await mcp.tools["query_events"](
        site_uuid="site-a",
        asset_id="asset-1",
        resolved=False,
        limit=20,
        after="current-events",
    )

    call = client.query_calls[0]
    assert "asset(id: $id)" in call["query"]
    assert call["variables"]["id"] == "asset-1"
    assert call["variables"]["after"] == "current-events"
    assert call["icp_machine_id"] == "site-a"
    assert result["total_count"] == 145
    assert result["has_more"] is True
    assert result["asset_ref"] == {"site_uuid": "site-a", "asset_id": "asset-1"}
    assert result["events"][0]["event_ref"] == {
        "site_uuid": "site-a",
        "event_id": "event-1",
    }


async def test_query_events_asset_id_fans_out_with_per_site_cursors() -> None:
    empty = {
        "asset": {
            "events": {
                "nodes": [],
                "totalCount": 0,
                "pageInfo": {"hasNextPage": False, "endCursor": None},
            }
        }
    }
    client = FakeClient([empty, empty])
    mcp = FakeMCP()
    register_read_tools(mcp, client, None)  # type: ignore[arg-type]

    result = await mcp.tools["query_events"](
        site_uuids=["site-a", "site-b"],
        asset_id="asset-1",
        after_by_site={"site-b": "cursor-b"},
    )

    assert result["sites_succeeded"] == 2
    assert "after" not in client.query_calls[0]["variables"]
    assert client.query_calls[1]["variables"]["after"] == "cursor-b"


async def test_query_events_rejects_asset_id_with_free_text_search() -> None:
    client = FakeClient([])
    mcp = FakeMCP()
    register_read_tools(mcp, client, None)  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="cannot be combined"):
        await mcp.tools["query_events"](
            site_uuid="site-a",
            asset_id="asset-1",
            search="asset-1",
        )
