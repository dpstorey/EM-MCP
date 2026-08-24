# SPDX-License-Identifier: Apache-2.0
"""Regression tests for `list_detection_policies` and
`query_policy_findings` pagination.

Tenable's `policies` GraphQL query has no server-side filter argument
at all — category / enabled / paused / search are applied client-side
to each fetched page in `list_detection_policies`, the same class of
bug `vulns.py`'s `vpr_at_least` had (and the same fix): a single page
can come back with fewer matches than `limit` purely by chance, so the
tool now fetches additional pages internally until it fills `limit` or
the site's policies are exhausted (capped at
`_MAX_CLIENT_FILTER_PAGES_PER_CALL`).

`query_policy_findings` filters entirely server-side, so it needs no
such loop — these tests just confirm `after`/`after_by_site` pagination
threads through correctly, mirroring the other domain tools.
"""

from __future__ import annotations

from typing import Any

import pytest

from tenable_ot_mcp.tools.policies import (
    _MAX_CLIENT_FILTER_PAGES_PER_CALL,
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


def _policy_node(policy_id: str, *, category: str = "Anomaly", enabled: bool = True) -> dict:
    return {
        "id": policy_id,
        "title": f"Policy {policy_id}",
        "level": "High",
        "disabled": not enabled,
        "archived": False,
        "paused": False,
        "system": False,
        "continuous": True,
        "snapshot": False,
        "key": policy_id,
        "lastModifiedDate": None,
        "lastModifiedBy": None,
        "disableAfterHit": False,
        "eventTypeDetails": {
            "type": "anomaly",
            "group": "Network",
            "description": None,
            "category": category,
            "family": None,
        },
        "aggregatedEventsCount": {"last24h": 0, "last7d": 0, "last30d": 0},
    }


def _finding_node(finding_id: str) -> dict:
    return {
        "id": finding_id,
        "policyTitle": "Policy 1",
        "severity": "High",
        "status": "Open",
        "firstHitTime": None,
        "lastHitTime": None,
        "activeHits": 1,
        "resolvedHits": 0,
        "activePolicyHits": 1,
        "pluginId": None,
        "pluginName": None,
        "category": "Anomaly",
        "eventType": {"type": "anomaly", "group": None, "description": None, "category": None},
        "policy": {"id": "p1", "title": "Policy 1", "level": "High", "disabled": False},
        "srcAssets": {"nodes": []},
        "dstAssets": {"nodes": []},
    }


# ---- list_detection_policies: client-side filter pagination ----------------


async def test_list_detection_policies_filters_within_a_single_page() -> None:
    client = FakeClient(
        [
            {
                "policies": {
                    "nodes": [
                        _policy_node("1", category="Anomaly"),
                        _policy_node("2", category="ConfigurationChange"),
                    ],
                    "totalCount": 2,
                    "pageInfo": {"hasNextPage": False, "endCursor": None},
                }
            }
        ]
    )
    mcp = FakeMCP()
    register_read_tools(mcp, client, None)  # type: ignore[arg-type]

    result = await mcp.tools["list_detection_policies"](site_uuid="site-a", category="Anomaly")

    assert len(client.query_calls) == 1
    assert result["count"] == 1
    assert [p["id"] for p in result["policies"]] == ["1"]
    assert result["total_count_unfiltered"] == 2
    assert result["has_more_in_tenable"] is False


async def test_list_detection_policies_fetches_more_pages_to_fill_limit() -> None:
    # Same regression shape as query_vulnerabilities' vpr_at_least fix:
    # a "give me 2 Anomaly policies" request must not settle for 1 just
    # because the first page happened to only contain 1 match.
    client = FakeClient(
        [
            {
                "policies": {
                    "nodes": [
                        _policy_node("1", category="Anomaly"),
                        _policy_node("2", category="ConfigurationChange"),
                    ],
                    "totalCount": 4,
                    "pageInfo": {"hasNextPage": True, "endCursor": "cursor-1"},
                }
            },
            {
                "policies": {
                    "nodes": [
                        _policy_node("3", category="Anomaly"),
                        _policy_node("4", category="ConfigurationChange"),
                    ],
                    "totalCount": 4,
                    "pageInfo": {"hasNextPage": False, "endCursor": None},
                }
            },
        ]
    )
    mcp = FakeMCP()
    register_read_tools(mcp, client, None)  # type: ignore[arg-type]

    result = await mcp.tools["list_detection_policies"](
        site_uuid="site-a", category="Anomaly", limit=2
    )

    assert len(client.query_calls) == 2
    assert client.query_calls[1]["variables"]["after"] == "cursor-1"
    assert [p["id"] for p in result["policies"]] == ["1", "3"]
    assert result["count"] == 2
    assert result["has_more_in_tenable"] is False


async def test_list_detection_policies_respects_page_cap() -> None:
    responses = [
        {
            "policies": {
                "nodes": [_policy_node(str(i), category="ConfigurationChange")],
                "totalCount": 999,
                "pageInfo": {"hasNextPage": True, "endCursor": f"cursor-{i}"},
            }
        }
        for i in range(_MAX_CLIENT_FILTER_PAGES_PER_CALL)
    ]
    client = FakeClient(responses)
    mcp = FakeMCP()
    register_read_tools(mcp, client, None)  # type: ignore[arg-type]

    result = await mcp.tools["list_detection_policies"](
        site_uuid="site-a", category="Anomaly", limit=100
    )

    assert len(client.query_calls) == _MAX_CLIENT_FILTER_PAGES_PER_CALL
    assert result["count"] == 0
    assert result["has_more_in_tenable"] is True


async def test_list_detection_policies_rejects_after_with_after_by_site() -> None:
    client = FakeClient([])
    mcp = FakeMCP()
    register_read_tools(mcp, client, None)  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="cannot be combined"):
        await mcp.tools["list_detection_policies"](
            site_uuid="site-a", after="cursor", after_by_site={"site-a": "cursor"}
        )


# ---- query_policy_findings: server-side filter, pass-through pagination ----


async def test_query_policy_findings_threads_after_cursor() -> None:
    client = FakeClient(
        [
            {
                "policyFindings": {
                    "nodes": [_finding_node("f1")],
                    "totalCount": 5,
                    "pageInfo": {"hasNextPage": True, "endCursor": "cursor-1"},
                }
            }
        ]
    )
    mcp = FakeMCP()
    register_read_tools(mcp, client, None)  # type: ignore[arg-type]

    result = await mcp.tools["query_policy_findings"](site_uuid="site-a")

    assert result["count"] == 1
    assert result["total_count"] == 5
    assert result["has_more"] is True
    assert result["end_cursor"] == "cursor-1"


async def test_query_policy_findings_rejects_after_with_after_by_site() -> None:
    client = FakeClient([])
    mcp = FakeMCP()
    register_read_tools(mcp, client, None)  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="cannot be combined"):
        await mcp.tools["query_policy_findings"](
            site_uuid="site-a", after="cursor", after_by_site={"site-a": "cursor"}
        )
