# SPDX-License-Identifier: Apache-2.0
"""Deterministic Mermaid rendering for Attackers View results.

Pure functions only (no I/O, no Tenable client) so the output can be
unit-tested and so small local models never have to hand-write Mermaid
from raw hop data. Attack-path topology comes straight from
`path_found[*].attack_vector.hops`; chokepoints come from the batch
`summary`; fatality ids (Safety grade D or E) are supplied by the caller.

Output rules (these are the failure modes hand-written diagrams hit):
  * always `flowchart LR`, never TD
  * one node per asset, one shared "Internet / External" root
  * one edge per distinct (src, dst) pair, labelled with protocol names
  * `classDef chokepoint` / `classDef fatality` only — no `style` lines,
    no subgraphs, no %%{init}%% block
"""

from __future__ import annotations

import re
from typing import Any, Iterable

FATALITY_GRADES = frozenset({"D", "E"})

_EXTERNAL_ID = "ext"
_EXTERNAL_LABEL = "Internet / External"
_MAX_LABEL_PROTOCOLS = 3
_PORT_SUFFIX = re.compile(r"\s*\(.*?\)\s*$")

_CLASSDEFS = (
    "    classDef chokepoint stroke:#d97706,stroke-width:3px",
    "    classDef fatality fill:#fee2e2,stroke:#dc2626,stroke-width:2px,color:#7f1d1d",
)


def is_fatality_grade(value: Any) -> bool:
    """True for a Safety (S) grade of D or E (case/space-insensitive)."""
    return isinstance(value, str) and value.strip().upper() in FATALITY_GRADES


def _clean(text: Any) -> str:
    """Make a value safe inside a double-quoted Mermaid label."""
    s = str(text)
    s = s.replace('"', "'").replace("<", "").replace(">", "")
    return re.sub(r"\s+", " ", s).strip()


def _protocol_names(hop: dict[str, Any]) -> list[str]:
    raw = hop.get("protocols") or []
    if not raw and hop.get("last_protocol_used"):
        raw = [hop["last_protocol_used"]]
    names: list[str] = []
    for proto in raw:
        name = _PORT_SUFFIX.sub("", str(proto)).strip()
        if name and name not in names:
            names.append(name)
    return names


def _edge_label(protocols: list[str]) -> str:
    if not protocols:
        return ""
    shown = protocols[:_MAX_LABEL_PROTOCOLS]
    extra = len(protocols) - len(shown)
    label = ", ".join(shown)
    if extra > 0:
        label += f" +{extra}"
    return _clean(label)


def _endpoint_key(endpoint: dict[str, Any] | None) -> tuple[str, str]:
    """(stable key, display name) for a hop endpoint; None -> external root."""
    if endpoint is None:
        return _EXTERNAL_ID, _EXTERNAL_LABEL
    key = endpoint.get("id")
    name = endpoint.get("name")
    if not name:
        ips = endpoint.get("ips") or []
        name = ips[0] if ips else (key or "unknown")
    return str(key or name), str(name)


def build_attack_mermaid(
    path_found: list[dict[str, Any]],
    *,
    chokepoint_ids: Iterable[str] = (),
    fatality_ids: Iterable[str] = (),
) -> str | None:
    """Render `path_found` as a Mermaid `flowchart LR`, or None if empty.

    `path_found` is the list of `{"outcome": "path_found", "asset_id",
    "attack_vector": {"hops": [...]}}` entries produced by
    `get_attackers_view`. Assets with `no_path_found` / timeout / error
    outcomes are never passed in, so they never appear as nodes.
    """
    chokepoints = set(chokepoint_ids)
    fatalities = set(fatality_ids)

    node_ids: dict[str, str] = {}  # endpoint key -> mermaid node id
    node_labels: dict[str, str] = {}  # mermaid node id -> display name
    node_key_by_id: dict[str, str] = {}  # mermaid node id -> endpoint key
    edges: dict[tuple[str, str], list[str]] = {}

    def node_for(endpoint: dict[str, Any] | None) -> str:
        key, name = _endpoint_key(endpoint)
        if key not in node_ids:
            nid = _EXTERNAL_ID if key == _EXTERNAL_ID else f"n{len(node_ids)}"
            node_ids[key] = nid
            node_labels[nid] = name
            node_key_by_id[nid] = key
        return node_ids[key]

    for entry in path_found:
        hops = (entry.get("attack_vector") or {}).get("hops") or []
        for hop in hops:
            src = node_for(hop.get("src"))
            dst = node_for(hop.get("dst"))
            if src == dst:
                continue
            protos = edges.setdefault((src, dst), [])
            for name in _protocol_names(hop):
                if name not in protos:
                    protos.append(name)

    if not edges:
        return None

    lines = ["flowchart LR"]
    # Declare nodes first (external root first, then in first-seen order).
    ordered = sorted(node_labels, key=lambda n: (n != _EXTERNAL_ID, len(n), n))
    for nid in ordered:
        label = _clean(node_labels[nid])
        if node_key_by_id[nid] in fatalities:
            label = f"⚠ {label}"
        if nid == _EXTERNAL_ID:
            lines.append(f'    {nid}(["{label}"])')
        else:
            lines.append(f'    {nid}["{label}"]')
    for (src, dst), protos in edges.items():
        label = _edge_label(protos)
        arrow = f'-->|"{label}"|' if label else "-->"
        lines.append(f"    {src} {arrow} {dst}")

    lines.extend(_CLASSDEFS)
    choke_nodes = [n for n in ordered if node_key_by_id[n] in chokepoints]
    fatal_nodes = [n for n in ordered if node_key_by_id[n] in fatalities]
    if choke_nodes:
        lines.append(f"    class {','.join(choke_nodes)} chokepoint")
    if fatal_nodes:
        lines.append(f"    class {','.join(fatal_nodes)} fatality")
    return "\n".join(lines)
