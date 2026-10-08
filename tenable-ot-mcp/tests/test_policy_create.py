# SPDX-License-Identifier: Apache-2.0
"""Tests for the generic create_policy / update_policy / describe tools."""

from __future__ import annotations

import inspect
import re
from typing import Any

import pytest

from tenable_ot_mcp.tools import policy_create as pc

# ---- harness (same shape as test_asset_edits) ------------------------------


class FakeMcp:
    def __init__(self) -> None:
        self.tools: dict[str, Any] = {}

    def tool(self, **_kw: Any):
        def deco(fn):
            if "site_uuid" in inspect.signature(fn).parameters:

                async def with_site(*a: Any, **k: Any) -> Any:
                    k.setdefault("site_uuid", "test-site")
                    return await fn(*a, **k)

                self.tools[fn.__name__] = with_site
            else:
                self.tools[fn.__name__] = fn
            return fn

        return deco


class FakeClient:
    def __init__(self, canned: dict[str, Any] | None = None, fail: str | None = None) -> None:
        self.calls: list[tuple[str, dict[str, Any] | None]] = []
        self.canned = canned or {}
        self.fail = fail

    async def resolve_site_machine_id(self, *, site_uuid=None, site_name=None) -> str:
        if site_uuid:
            return site_uuid
        raise ValueError("site_uuid or site_name is required")

    async def query(self, query, variables=None, *, icp_machine_id=None):
        self.calls.append((query, variables))
        if self.fail and self.fail in query:
            raise RuntimeError("boom")
        for sub, resp in self.canned.items():
            if sub in query:
                return resp
        return {}


class FakeAudit:
    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []

    def record(self, **kw: Any) -> None:
        self.records.append(kw)


def _tools(canned=None, fail=None):
    mcp, client, audit = FakeMcp(), FakeClient(canned, fail), FakeAudit()
    pc.register_write_tools(mcp, client, audit)
    pc.register_read_tools(mcp, client, audit)
    return mcp, client, audit


CONV = dict(
    title="Z1 -> Z2 outside conduit",
    level="high",
    src=[["Z1"]],
    dst=[["!Z2"]],
    schedule_group_id="SCHED",
    protocol_group_id="PROTO",
)
CREATE_TOOLS = {
    "protocol": "create_conversation_policy",
    "activity": "create_activity_policy",
    "asset": "create_asset_policy",
    "port": "create_port_policy",
    "ids_src_dst": "create_ids_src_dst_policy",
    "ids_general": "create_ids_general_policy",
    "intrusion": "create_intrusion_policy",
    "spike": "create_spike_policy",
    "rediscovered_asset": "create_rediscovered_asset_policy",
    "tag_value": "create_tag_value_policy",
}

# ---- group_expr -------------------------------------------------------------


def test_group_expr_shapes():
    assert pc.group_expr("A") == [[{"id": "A"}]]
    assert pc.group_expr(["A", "B"]) == [[{"id": "A"}, {"id": "B"}]]
    assert pc.group_expr([["A", "B"], ["!C"]]) == [
        [{"id": "A"}, {"id": "B"}],
        [{"id": "C", "negate": True}],
    ]
    assert pc.group_expr([[{"id": "A", "negate": True}]]) == [[{"id": "A", "negate": True}]]


@pytest.mark.parametrize("bad", [None, [], [[]], ["A", ["B"]], 5, [""], [{"x": 1}]])
def test_group_expr_rejects(bad):
    with pytest.raises(ValueError):
        pc.group_expr(bad)


# ---- registry vs. schema ----------------------------------------------------


def test_ten_types_all_build_valid_looking_mutations():
    assert len(pc.POLICY_TYPES) == 10
    for spec in pc.POLICY_TYPES.values():
        for update in (False, True):
            m = pc.build_mutation(spec, update=update)
            name = spec.mutation_set if update else spec.mutation_new
            assert f"  {name}(" in m
            declared = re.findall(r"\$(\w+):", m)
            used = re.findall(r"(\w+): \$\1", m)
            assert declared == used and len(set(declared)) == len(declared)
            assert ("id" in declared) == update
            assert "event" in declared


def test_events_present_for_every_type():
    for spec in pc.POLICY_TYPES.values():
        assert spec.events, spec.key
    assert "Conversation" in pc.POLICY_TYPES["protocol"].events


# ---- narrow create tools ----------------------------------------------------


def test_one_narrow_tool_per_type_and_no_generic():
    mcp, _, _ = _tools()
    assert set(CREATE_TOOLS.values()) <= set(mcp.tools)
    assert "create_policy" not in mcp.tools
    assert set(CREATE_TOOLS) == set(pc.POLICY_TYPES)


def test_narrow_signatures_are_small_and_relevant():
    mcp, _, _ = _tools()
    import inspect

    conv = set(inspect.signature(mcp.tools["create_conversation_policy"]).parameters)
    assert {"event", "policy_type", "snapshot", "continuous", "disable_after_hit", "port_group_id"}.isdisjoint(conv)
    assert len(conv - {"site_uuid", "site_name"}) <= 9
    for name in CREATE_TOOLS.values():
        assert len(set(inspect.signature(mcp.tools[name]).parameters) - {"site_uuid", "site_name"}) <= 12, name


async def test_dry_run_makes_no_call_and_validates():
    mcp, client, audit = _tools()
    out = await mcp.tools["create_conversation_policy"](**CONV)
    assert out["dry_run"] is True and client.calls == []
    v = out["preview_variables"]
    assert v["event"] == "Conversation"
    assert v["srcAssetGroup"] == [[{"id": "Z1"}]]
    assert v["dstAssetGroup"] == [[{"id": "Z2", "negate": True}]]
    assert v["schedule"] == {"id": "SCHED"} and v["protocolGroup"] == {"id": "PROTO"}
    assert v["level"] == "High" and v["actions"] == []
    assert out["initial_state"] == "enabled" and out["policy_type"] == "protocol"


async def test_negated_protocol_group():
    mcp, _, _ = _tools()
    out = await mcp.tools["create_conversation_policy"](**{**CONV, "protocol_group_id": "!PG"})
    assert out["preview_variables"]["protocolGroup"] == {"id": "PG", "negate": True}


async def test_create_enabled_is_single_call():
    mcp, client, _ = _tools({"newProtocolPolicy": {"newProtocolPolicy": {"id": "P1"}}})
    out = await mcp.tools["create_conversation_policy"](**CONV, dry_run=False)
    assert len(client.calls) == 1
    assert out["policy_id"] == "P1" and out["state_applied"] == "enabled"


async def test_create_disabled_creates_then_disables():
    mcp, client, audit = _tools({"newProtocolPolicy": {"newProtocolPolicy": {"id": "P1"}}})
    out = await mcp.tools["create_conversation_policy"](**CONV, initial_state="disabled", dry_run=False)
    assert len(client.calls) == 2
    assert "disablePolicy" in client.calls[1][0] and client.calls[1][1] == {"id": "P1"}
    assert out["state_applied"] == "disabled"
    assert [r["tool_name"] for r in audit.records] == [
        "create_conversation_policy",
        "create_conversation_policy.disable",
    ]


async def test_disable_failure_is_reported_not_raised():
    mcp, client, _ = _tools({"newProtocolPolicy": {"newProtocolPolicy": {"id": "P1"}}}, fail="disablePolicy")
    out = await mcp.tools["create_conversation_policy"](**CONV, initial_state="disabled", dry_run=False)
    assert out["state_applied"] == "enabled" and "ENABLED" in out["warning"]


async def test_create_error_propagates_without_second_call():
    mcp, client, _ = _tools(fail="newProtocolPolicy")
    with pytest.raises(RuntimeError):
        await mcp.tools["create_conversation_policy"](**CONV, initial_state="disabled", dry_run=False)
    assert len(client.calls) == 1


@pytest.mark.parametrize(
    "override",
    [
        {"level": "extreme"},
        {"initial_state": "paused"},
        {"schedule_group_id": ""},
        {"protocol_group_id": ""},
        {"dst": None},
        {"title": "  "},
        {"actions": [{"aid": "1", "type": "Pager"}]},
    ],
)
async def test_validation_errors(override):
    mcp, client, _ = _tools()
    with pytest.raises(ValueError):
        await mcp.tools["create_conversation_policy"](**{**CONV, **override})
    assert client.calls == []


async def test_event_validated_on_event_tools():
    mcp, client, _ = _tools()
    with pytest.raises(ValueError):
        await mcp.tools["create_asset_policy"](title="t", level="low", event="Nope", src="G", schedule_group_id="S")
    assert client.calls == []


async def test_other_tools_shapes():
    mcp, _, _ = _tools()
    t = mcp.tools
    a = await t["create_asset_policy"](title="t", level="low", event="NewAssetDiscovered", src="G", schedule_group_id="S")
    assert "dstAssetGroup" not in a["preview_variables"]
    g = await t["create_ids_general_policy"](title="t", level="low", schedule_group_id="S")
    assert g["preview_variables"]["event"] == "IpConflict" and "srcAssetGroup" not in g["preview_variables"]
    s = await t["create_spike_policy"](title="t", level="low", event="DataSpikeDetected", schedule_group_id="S",
                                       spike_time_frame="Hour", spike_sensitivity="Low")
    assert s["preview_variables"]["params"] == {"timeFrame": "Hour", "sdCoefficient": "Low"}
    r = await t["create_rediscovered_asset_policy"](title="t", level="low", src="G", schedule_group_id="S",
                                                    inactivity_seconds=3600)
    assert r["preview_variables"]["params"] == {"inactivityInSeconds": 3600}
    tv = await t["create_tag_value_policy"](title="t", level="high", src="G", schedule_group_id="S",
                                            tag_group_id="TG", any_value=True)
    assert tv["preview_variables"]["tagGroup"] == {"id": "TG"} and tv["preview_variables"]["event"] == "UnauthorizedTagWrite"
    act = await t["create_activity_policy"](title="t", level="low", event="SimaticPlcStop", src="A", dst="B",
                                            schedule_group_id="S")
    assert act["preview_variables"]["snapshot"] is False
    p = await t["create_port_policy"](title="t", level="low", src="A", port_group_id="PG")
    assert p["preview_variables"]["portGroup"] == {"id": "PG"} and p["preview_variables"]["event"] == "OpenPort"
    i = await t["create_intrusion_policy"](title="t", level="low", src="A", dst="B", rule_group_id="R", schedule_group_id="S")
    assert i["preview_variables"]["ruleGroup"] == {"id": "R"}
    d = await t["create_ids_src_dst_policy"](title="t", level="low", event="SynScan", src="A", dst="B", schedule_group_id="S")
    assert d["preview_variables"]["event"] == "SynScan"
    with pytest.raises(ValueError):
        await t["create_rediscovered_asset_policy"](title="t", level="low", src="G", schedule_group_id="S",
                                                    inactivity_seconds=0)


# ---- update / describe / get ------------------------------------------------


async def test_update_policy_uses_set_mutation_and_id():
    mcp, client, _ = _tools({"setProtocolPolicy": {"setProtocolPolicy": {"id": "P1"}}})
    out = await mcp.tools["update_policy"](policy_id="P1", policy_type="protocol", event="Conversation", **CONV, dry_run=False)
    q, v = client.calls[0]
    assert "setProtocolPolicy(" in q and v["id"] == "P1"
    assert out["policy_type"] == "protocol"


async def test_update_tag_value_requires_value_group():
    mcp, _, _ = _tools()
    kw = dict(policy_id="P", policy_type="tag_value", title="t", level="low", event="UnauthorizedTagWrite",
              src="G", schedule_group_id="S", tag_group_id="TG")
    with pytest.raises(ValueError):
        await mcp.tools["update_policy"](**kw)
    out = await mcp.tools["update_policy"](**kw, value_group_id="VG")
    assert out["preview_variables"]["valueGroup"] == {"id": "VG"}


async def test_describe_and_get():
    mcp, client, _ = _tools({"policy(id": {"policy": {"id": "P1", "title": "x"}}})
    d = await mcp.tools["describe_policy_type"]()
    assert set(d["policy_types"]) == set(pc.POLICY_TYPES)
    one = await mcp.tools["describe_policy_type"]("protocol")
    assert one["events"] == ["Conversation", "BaselineDeviation"]
    got = await mcp.tools["get_policy"](policy_id="P1")
    assert got["policy"]["id"] == "P1"
