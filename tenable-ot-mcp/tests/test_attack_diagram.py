# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the deterministic Attackers View Mermaid renderer."""

from __future__ import annotations

from tenable_ot_mcp.tools._attack_diagram import build_attack_mermaid, is_fatality_grade


def _ep(aid, name, *, is_asset=True):
    return {"id": aid, "name": name, "is_asset": is_asset, "ips": [f"10.0.0.{len(name)}"]}


def _hop(src, dst, protocols=("HTTP (80/TCP)",)):
    return {"src": src, "dst": dst, "protocols": list(protocols), "last_protocol_used": None}


VENG = _ep("a-veng", "VENG01")
REACTOR = _ep("a-reactor", "REACTOR")
PMC = _ep("a-pmc", "pmc.barossafarm.com")

PATHS = [
    {
        "outcome": "path_found",
        "asset_id": "a-reactor",
        "attack_vector": {
            "hops": [
                _hop(None, VENG, ("HTTP (80/TCP)", "HTTPS (443/TCP)")),
                _hop(VENG, REACTOR, ("CIP (44818/TCP)",)),
            ]
        },
    },
    {
        "outcome": "path_found",
        "asset_id": "a-pmc",
        "attack_vector": {
            "hops": [
                _hop(None, VENG, ("HTTP (80/TCP)", "NTP (123/UDP)")),
                _hop(VENG, PMC, ("BACnet (47808/UDP)",)),
            ]
        },
    },
]


def test_grades():
    assert is_fatality_grade("D") and is_fatality_grade(" e ")
    assert not is_fatality_grade("C") and not is_fatality_grade(None) and not is_fatality_grade("")


def test_flowchart_lr_never_td():
    out = build_attack_mermaid(PATHS)
    assert out.splitlines()[0] == "flowchart LR"
    assert "TD" not in out and "subgraph" not in out and "style " not in out.replace("classDef", "")


def test_one_node_per_asset_and_one_shared_external_root():
    out = build_attack_mermaid(PATHS)
    assert out.count('["VENG01"]') == 1
    assert out.count("Internet / External") == 1
    # ext -> VENG01 appears once even though two paths start there
    assert sum(1 for line in out.splitlines() if line.strip().startswith("ext -->")) == 1


def test_edges_merge_protocols_without_ports():
    out = build_attack_mermaid(PATHS)
    assert '|"HTTP, HTTPS, NTP"|' in out
    assert "80/TCP" not in out


def test_edge_label_truncates_long_protocol_lists():
    hop = _hop(None, VENG, tuple(f"P{i} ({i}/TCP)" for i in range(6)))
    out = build_attack_mermaid([{"asset_id": "a-veng", "attack_vector": {"hops": [hop]}}])
    assert '"P0, P1, P2 +3"' in out


def test_chokepoint_and_fatality_classes_and_prefix():
    out = build_attack_mermaid(PATHS, chokepoint_ids=["a-veng"], fatality_ids=["a-reactor", "a-pmc"])
    assert "classDef chokepoint" in out and "classDef fatality" in out
    lines = out.splitlines()
    assert any(l.strip().startswith("class ") and l.strip().endswith(" chokepoint") for l in lines)
    fatal_line = next(l for l in lines if l.strip().endswith(" fatality") and l.strip().startswith("class "))
    assert fatal_line.count(",") == 1  # two nodes
    assert "⚠ REACTOR" in out and "⚠ pmc.barossafarm.com" in out
    assert "⚠ VENG01" not in out  # chokepoint alone is not a fatality


def test_node_can_be_both_chokepoint_and_fatality():
    out = build_attack_mermaid(PATHS, chokepoint_ids=["a-veng"], fatality_ids=["a-veng"])
    assert "⚠ VENG01" in out
    assert out.count(" chokepoint") >= 2 and out.count(" fatality") >= 2


def test_no_classes_when_nothing_flagged():
    out = build_attack_mermaid(PATHS)
    assert not any(l.strip().startswith("class ") for l in out.splitlines())


def test_empty_returns_none():
    assert build_attack_mermaid([]) is None
    assert build_attack_mermaid([{"asset_id": "x", "attack_vector": {"hops": []}}]) is None


def test_labels_are_sanitised():
    weird = _ep("a-w", 'Bad "name" <b>x</b>\nline2')
    out = build_attack_mermaid([{"asset_id": "a-w", "attack_vector": {"hops": [_hop(None, weird)]}}])
    assert '"' not in out.split('n1["', 1)[1].split('"]', 1)[0]
    assert "<" not in out and ">" not in out.replace("-->", "")


def test_bare_ip_endpoint_uses_ip_label():
    bare = {"id": "10.1.1.1", "name": None, "is_asset": False, "ips": ["10.1.1.1"]}
    out = build_attack_mermaid([{"asset_id": "x", "attack_vector": {"hops": [_hop(None, bare)]}}])
    assert '"10.1.1.1"' in out
