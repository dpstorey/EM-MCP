# SPDX-License-Identifier: Apache-2.0
"""Regression tests for `query_vulnerabilities`'s `vpr_at_least` and
`source` filters.

Tenable's GraphQL surface 500s on relational operators (>, >=, <, <=)
against `vprScore` in the `PluginExpressionsParams` filter — confirmed
live (see `tools/vulns.py`'s module docstring) — so `vpr_at_least` is
applied client-side to each fetched page rather than pushed into the
GraphQL `filter` argument. These tests pin that behavior: the raw
GraphQL variables sent to `client.query` must never carry a vpr-related
expression, and the returned `count`/`vulnerabilities` must reflect the
post-filter set while `total_count` passes through the server's
(pre-vpr-filter) pagination state unchanged.

Client-side filtering is only trustworthy if the pages being scanned
are in a useful order: live introspection showed `plugins` has no
default ordering (two identical live runs of the same filter walked
different subsets of the same result set), so `vpr_at_least` also adds
an explicit `sort: [{field: vprScore, direction: DescNullLast}]` and
the loop stops as soon as a node fails the floor — every remaining
node, this page and every later one, is guaranteed to also fail it.
`has_more` reflects that proof: `False` once exhaustion is proven,
otherwise the server's raw signal (when `limit` was reached or the
safety cap was hit first).

`source` (detection engine) values — 'Nessus' / 'NNM' / 'Tot' — were
captured from the product UI's own `getPluginsGrouped` GraphQL traffic,
not independent introspection against the `plugins` root field this
module calls; `_to_source` translates natural lowercase vocabulary to
that exact casing.
"""

from __future__ import annotations

from typing import Any

import pytest

from tenable_ot_mcp.tools.vulns import (
    _build_vuln_filter,
    _to_source,
    _validate_vpr_at_least,
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


def _plugin_node(plugin_id: str, vpr_score: float | None) -> dict[str, Any]:
    return {
        "id": plugin_id,
        "name": f"Plugin {plugin_id}",
        "source": "Tenable",
        "family": "General",
        "severity": "High",
        "vprScore": vpr_score,
        "vprLevel": "High" if vpr_score and vpr_score >= 7 else "Medium",
        "cvss3Score": 7.5,
        "totalAffectedAssets": 1,
        "details": {
            "cves": [],
            "cvssV3Vector": None,
            "exploitAvailable": False,
            "exploitedByMalware": False,
            "cisaKnownExploitedDates": [],
            "exploitCodeMaturity": None,
            "threatRecency": None,
            "vulnPubDate": None,
            "pluginPubDate": None,
            "ageOfVuln": None,
            "description": None,
            "solution": None,
        },
    }


# ---- validation --------------------------------------------------------


def test_validate_vpr_at_least_passes_through_none() -> None:
    assert _validate_vpr_at_least(None) is None


def test_validate_vpr_at_least_coerces_numeric_types() -> None:
    assert _validate_vpr_at_least(7) == 7.0
    assert _validate_vpr_at_least("7.5") == 7.5


def test_validate_vpr_at_least_rejects_non_numeric() -> None:
    with pytest.raises(ValueError, match="vpr_at_least must be a number"):
        _validate_vpr_at_least("high")


def test_to_source_translates_natural_vocab() -> None:
    assert _to_source("nessus") == "Nessus"
    assert _to_source("nnm") == "NNM"
    assert _to_source("tot") == "Tot"


def test_to_source_is_case_and_separator_insensitive() -> None:
    assert _to_source("Nessus") == "Nessus"
    assert _to_source("NNM") == "NNM"
    assert _to_source("Tenable.OT") == "Tot"
    assert _to_source("tenable_ot") == "Tot"


def test_to_source_rejects_unknown_value() -> None:
    with pytest.raises(ValueError, match="source must be one of"):
        _to_source("lce")


def test_build_vuln_filter_sends_exact_tenable_casing_for_source() -> None:
    filt = _build_vuln_filter(cve=None, severity_at_least=None, family=None, source="nnm")
    assert filt == {"field": "source", "op": "Equal", "values": ["NNM"]}


# ---- tool behavior -------------------------------------------------------


async def test_query_vulnerabilities_vpr_filter_never_reaches_graphql_variables() -> None:
    client = FakeClient(
        [
            {
                "plugins": {
                    "nodes": [_plugin_node("1", 8.5), _plugin_node("2", 3.0)],
                    "totalCount": 2,
                    "pageInfo": {"hasNextPage": False, "endCursor": None},
                }
            }
        ]
    )
    mcp = FakeMCP()
    register_read_tools(mcp, client, None)  # type: ignore[arg-type]

    result = await mcp.tools["query_vulnerabilities"](site_uuid="site-a", vpr_at_least=7.0)

    # The GraphQL request itself must carry no vpr-related filter —
    # Tenable 500s on relational operators against vprScore.
    call = client.query_calls[0]
    assert call["variables"].get("filter") is None

    # Client-side filtering keeps only the >=7.0 plugin.
    assert result["count"] == 1
    assert [v["plugin_id"] for v in result["vulnerabilities"]] == ["1"]

    # total_count/has_more/end_cursor are the server's raw pagination
    # state — unaffected by the client-side vpr filter.
    assert result["total_count"] == 2
    assert result["has_more"] is False


async def test_query_vulnerabilities_vpr_filter_excludes_missing_scores() -> None:
    client = FakeClient(
        [
            {
                "plugins": {
                    "nodes": [_plugin_node("1", None)],
                    "totalCount": 1,
                    "pageInfo": {"hasNextPage": False, "endCursor": None},
                }
            }
        ]
    )
    mcp = FakeMCP()
    register_read_tools(mcp, client, None)  # type: ignore[arg-type]

    result = await mcp.tools["query_vulnerabilities"](site_uuid="site-a", vpr_at_least=1.0)

    assert result["count"] == 0
    assert result["vulnerabilities"] == []


async def test_query_vulnerabilities_without_vpr_at_least_returns_everything() -> None:
    client = FakeClient(
        [
            {
                "plugins": {
                    "nodes": [_plugin_node("1", 1.0), _plugin_node("2", None)],
                    "totalCount": 2,
                    "pageInfo": {"hasNextPage": False, "endCursor": None},
                }
            }
        ]
    )
    mcp = FakeMCP()
    register_read_tools(mcp, client, None)  # type: ignore[arg-type]

    result = await mcp.tools["query_vulnerabilities"](site_uuid="site-a")

    assert result["count"] == 2


async def test_query_vulnerabilities_vpr_filter_fetches_more_pages_to_fill_limit() -> None:
    # Regression for a real observed failure: a "top 20" request with
    # vpr_at_least got back only 9 results from a single server page,
    # even though has_more was true and more qualifying rows existed on
    # later pages — the calling LLM didn't reliably keep paging itself.
    # query_vulnerabilities must now do that internally. Both pages'
    # scores stay globally descending (9.0, 8.0, 7.5, 7.2) and never dip
    # below the 7.0 floor, matching what a real `sort: vprScore
    # DescNullLast` page-2 would look like — the loop fills `limit`
    # across two fetches without ever proving exhaustion.
    client = FakeClient(
        [
            {
                "plugins": {
                    "nodes": [_plugin_node("1", 9.0), _plugin_node("2", 8.0)],
                    "totalCount": 4,
                    "pageInfo": {"hasNextPage": True, "endCursor": "cursor-1"},
                }
            },
            {
                "plugins": {
                    "nodes": [_plugin_node("3", 7.5), _plugin_node("4", 7.2)],
                    "totalCount": 4,
                    "pageInfo": {"hasNextPage": False, "endCursor": None},
                }
            },
        ]
    )
    mcp = FakeMCP()
    register_read_tools(mcp, client, None)  # type: ignore[arg-type]

    result = await mcp.tools["query_vulnerabilities"](site_uuid="site-a", vpr_at_least=7.0, limit=4)

    assert len(client.query_calls) == 2
    assert client.query_calls[1]["variables"]["after"] == "cursor-1"
    assert [v["plugin_id"] for v in result["vulnerabilities"]] == ["1", "2", "3", "4"]
    assert result["count"] == 4
    assert result["total_count"] == 4
    # Reached `limit` right as the server's last page ended — has_more
    # correctly reflects the server's raw (false) signal, not a proven
    # exhaustion (no node ever dropped below the floor).
    assert result["has_more"] is False


async def test_query_vulnerabilities_vpr_filter_proves_exhaustion_before_server_pages_end() -> None:
    # The core of the fix: once a page (sorted vprScore DescNullLast)
    # yields a node below the floor, every remaining node — the rest of
    # this page, and every later page — is guaranteed to also be below
    # it, so has_more is reported False even though the server's raw
    # hasNextPage says there's more data (just none of it qualifying).
    # This is what turns "9 vs. 1 vs. who knows" into a provably
    # complete answer after a single page.
    client = FakeClient(
        [
            {
                "plugins": {
                    "nodes": [_plugin_node("1", 8.0), _plugin_node("2", 5.0)],
                    "totalCount": 500,
                    "pageInfo": {"hasNextPage": True, "endCursor": "cursor-1"},
                }
            }
        ]
    )
    mcp = FakeMCP()
    register_read_tools(mcp, client, None)  # type: ignore[arg-type]

    result = await mcp.tools["query_vulnerabilities"](
        site_uuid="site-a", vpr_at_least=7.0, limit=50
    )

    assert len(client.query_calls) == 1
    assert [v["plugin_id"] for v in result["vulnerabilities"]] == ["1"]
    assert result["count"] == 1
    assert result["has_more"] is False


async def test_query_vulnerabilities_vpr_at_least_sends_descending_vpr_sort() -> None:
    client = FakeClient(
        [
            {
                "plugins": {
                    "nodes": [_plugin_node("1", 8.0)],
                    "totalCount": 1,
                    "pageInfo": {"hasNextPage": False, "endCursor": None},
                }
            }
        ]
    )
    mcp = FakeMCP()
    register_read_tools(mcp, client, None)  # type: ignore[arg-type]

    await mcp.tools["query_vulnerabilities"](site_uuid="site-a", vpr_at_least=7.0)

    assert client.query_calls[0]["variables"]["sort"] == [
        {"field": "vprScore", "direction": "DescNullLast"}
    ]


async def test_query_vulnerabilities_without_vpr_at_least_sends_no_sort() -> None:
    # A call with no vpr_at_least shouldn't have its ordering changed —
    # the sort is only added when it's needed to make client-side VPR
    # filtering provably complete.
    client = FakeClient(
        [
            {
                "plugins": {
                    "nodes": [_plugin_node("1", 8.0)],
                    "totalCount": 1,
                    "pageInfo": {"hasNextPage": False, "endCursor": None},
                }
            }
        ]
    )
    mcp = FakeMCP()
    register_read_tools(mcp, client, None)  # type: ignore[arg-type]

    await mcp.tools["query_vulnerabilities"](site_uuid="site-a")

    assert "sort" not in client.query_calls[0]["variables"]


async def test_query_vulnerabilities_vpr_filter_respects_page_cap() -> None:
    # Every page's sole node still qualifies (9.0 >= 7.0), so the loop
    # never proves exhaustion, and the site claims far more (999) than
    # fit in `limit` (100), so it never fills `limit` either — the only
    # remaining exit is the safety cap, bounding latency for a floor low
    # enough that a huge fraction of plugins qualify. has_more stays
    # true so a caller can still page onward.
    from tenable_ot_mcp.tools.vulns import _MAX_VPR_PAGES_PER_CALL

    responses = [
        {
            "plugins": {
                "nodes": [_plugin_node(str(i), 9.0)],
                "totalCount": 999,
                "pageInfo": {"hasNextPage": True, "endCursor": f"cursor-{i}"},
            }
        }
        for i in range(_MAX_VPR_PAGES_PER_CALL)
    ]
    client = FakeClient(responses)
    mcp = FakeMCP()
    register_read_tools(mcp, client, None)  # type: ignore[arg-type]

    result = await mcp.tools["query_vulnerabilities"](
        site_uuid="site-a", vpr_at_least=7.0, limit=100
    )

    assert len(client.query_calls) == _MAX_VPR_PAGES_PER_CALL
    assert result["count"] == _MAX_VPR_PAGES_PER_CALL
    assert result["has_more"] is True


async def test_query_vulnerabilities_rejects_bad_vpr_at_least() -> None:
    client = FakeClient([])
    mcp = FakeMCP()
    register_read_tools(mcp, client, None)  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="vpr_at_least must be a number"):
        await mcp.tools["query_vulnerabilities"](site_uuid="site-a", vpr_at_least="not-a-number")
