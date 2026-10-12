# SPDX-License-Identifier: Apache-2.0
"""Detection-policy creation — one narrow tool per policy type over a shared registry.

Narrow tools keep each schema small and every argument relevant (better for small
local models); LibreChat-style clients can untick the ones not needed.

Tenable OT exposes ten ``new*Policy`` mutations (Activity, Asset, Protocol,
Port, IDSSrcDst, IDSGeneral, Intrusion, Spike, RediscoveredAsset,
TagValue) with overlapping but different argument lists, plus matching
``set*Policy`` full-replace mutations. This module wraps them behind:

* ``create_<type>_policy``— ten narrow create tools (conversation, activity, asset, port,
                           ids_src_dst, ids_general, intrusion, spike, rediscovered_asset,
                           tag_value), each with only its own arguments and ``initial_state``
* ``update_policy``       — full replace of an existing policy (``set*``)
* ``describe_policy_type``— list types / args / valid events (no network)
* ``get_policy``          — read one policy (read tool)

Why ``initial_state``: Tenable creates every new policy **enabled** and the
mutations have no create-time flag. ``initial_state="disabled"`` is
implemented as create followed by ``disablePolicy``. The window between the
two calls is milliseconds, but it is two calls, not one atomic operation; if
the second fails the policy exists and is enabled, and the result says so.

Source/destination scoping uses Tenable's conjunctive normal form:
``[[Group]]`` — the outer list is AND, each inner list is OR, and every
member may be negated. ``group_expr()`` normalises friendlier inputs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..audit import AuditLog
from ..tenable_client import TenableClient
from ._enums import to_policy_level
from ._policy_events import POLICY_EVENTS
from ._sites import SiteScopedWriteMCP, run_site_read

# ---------------------------------------------------------------------------
# Group-expression normalisation
# ---------------------------------------------------------------------------

def _group_member(item: Any) -> dict[str, Any]:
    """One group reference → ``{"id": ..., "negate": bool}`` (negate omitted if False)."""
    if isinstance(item, dict):
        gid = item.get("id")
        if not gid:
            raise ValueError(f"group reference {item!r} has no 'id'")
        member: dict[str, Any] = {"id": str(gid)}
        if item.get("negate"):
            member["negate"] = True
        return member
    if isinstance(item, str):
        text = item.strip()
        negate = False
        if text.startswith("!") or text.startswith("~"):
            negate, text = True, text[1:].strip()
        if not text:
            raise ValueError("empty group id")
        member = {"id": text}
        if negate:
            member["negate"] = True
        return member
    raise ValueError(f"group reference must be a string or {{id, negate}} object; got {item!r}")


def group_expr(value: Any, *, field_name: str = "group expression") -> list[list[dict[str, Any]]]:
    """Normalise to Tenable's ``[[Group!]!]!``.

    Accepted shapes:

    * ``"A"``                       → ``[[A]]``
    * ``["A", "B"]`` (flat)         → ``[[A, B]]``  (ONE clause: A OR B)
    * ``[["A","B"], ["C"]]``        → as given      (clause1 AND clause2)
    * members may be ``"!id"`` or ``{"id": "...", "negate": true}``

    Semantics are ``(A OR B) AND C``. To say "not in zone Z" for a zone
    made of several groups, use one negated clause per group:
    ``[["!Z1"], ["!Z2"]]``.
    """
    if value is None:
        raise ValueError(f"{field_name} is required")
    if isinstance(value, (str, dict)):
        return [[_group_member(value)]]
    if not isinstance(value, (list, tuple)):
        raise ValueError(f"{field_name} must be a string, object or list")
    if not value:
        raise ValueError(
            f"{field_name} is empty. Pass an explicit group (e.g. an 'All Assets'-style "
            "group) — empty expressions are not accepted by this tool."
        )
    if all(isinstance(x, (list, tuple)) for x in value):
        clauses = []
        for clause in value:
            if not clause:
                raise ValueError(f"{field_name} contains an empty clause")
            clauses.append([_group_member(m) for m in clause])
        return clauses
    if any(isinstance(x, (list, tuple)) for x in value):
        raise ValueError(f"{field_name} mixes flat members and clauses; use all-flat or all-nested")
    return [[_group_member(m) for m in value]]


def _group_arg(value: Any, name: str, *, allow_negate: bool = False) -> dict[str, Any]:
    """Single required ``Group!`` (schedule, protocol group, ...)."""
    member = _group_member(value)
    if member.get("negate") and not allow_negate:
        raise ValueError(f"{name} cannot be negated")
    return member


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

# Variable type declarations for the shared leading arguments.
_COMMON_DECLS = {
    "title": "String!",
    "level": "PolicyLevel!",
    "disableAfterHit": "Boolean",
    "continuous": "Boolean",
    "actions": "[ActionParams!]!",
}


@dataclass(frozen=True)
class PolicyTypeSpec:
    key: str  # user-facing key, e.g. "protocol"
    mutation_new: str
    mutation_set: str
    event_enum: str
    summary: str
    # variable name -> GraphQL type, in addition to the common ones + event.
    extra: dict[str, str] = field(default_factory=dict)
    # Additional required-on-set-only variables.
    set_only: dict[str, str] = field(default_factory=dict)
    notes: str = ""

    @property
    def events(self) -> tuple[str, ...]:
        return POLICY_EVENTS[self.event_enum]


_SRC = {"srcAssetGroup": "[[Group!]!]!"}
_DST = {"dstAssetGroup": "[[Group!]!]!"}
_SCHED = {"schedule": "Group!"}

POLICY_TYPES: dict[str, PolicyTypeSpec] = {
    "activity": PolicyTypeSpec(
        "activity",
        "newActivityPolicy",
        "setActivityPolicy",
        "ActivityPolicyEvent",
        "Engineering activity between a source and destination (downloads, uploads, "
        "start/stop, firmware...).",
        {**_SRC, **_DST, **_SCHED, "snapshot": "Boolean!"},
    ),
    "asset": PolicyTypeSpec(
        "asset",
        "newAssetPolicy",
        "setAssetPolicy",
        "AssetPolicyEvent",
        "Asset change events (new asset, inactive, firmware change...).",
        {**_SRC, **_SCHED},
    ),
    "protocol": PolicyTypeSpec(
        "protocol",
        "newProtocolPolicy",
        "setProtocolPolicy",
        "ProtocolPolicyEvent",
        "Network conversations: Conversation = any traffic matching the scope and "
        "protocol group; BaselineDeviation = traffic not in the learned baseline. "
        "Direction-sensitive (src -> dst).",
        {**_SRC, **_DST, **_SCHED, "protocolGroup": "Group!", "snapshot": "Boolean"},
    ),
    "port": PolicyTypeSpec(
        "port",
        "newPortPolicy",
        "setPortPolicy",
        "PortPolicyEvent",
        "Open-port detection on source assets against a port group.",
        {**_SRC, "portGroup": "Group!"},
    ),
    "ids_src_dst": PolicyTypeSpec(
        "ids_src_dst",
        "newIDSSrcDstPolicy",
        "setIDSSrcDstPolicy",
        "IDSSrcDstEvent",
        "IDS-style events between a source and destination (scans, RDP, DNP3...).",
        {**_SRC, **_DST, **_SCHED},
    ),
    "ids_general": PolicyTypeSpec(
        "ids_general",
        "newIDSGeneralPolicy",
        "setIDSGeneralPolicy",
        "IDSGeneralNewEvent",
        "General IDS events with no src/dst scope (IP conflict).",
        {**_SCHED},
    ),
    "intrusion": PolicyTypeSpec(
        "intrusion",
        "newIntrusionPolicy",
        "setIntrusionPolicy",
        "IntrusionPolicyEvent",
        "Intrusion-rule hits between a source and destination, from a rule group.",
        {**_SRC, **_DST, "ruleGroup": "Group!", **_SCHED},
    ),
    "spike": PolicyTypeSpec(
        "spike",
        "newSpikePolicy",
        "setSpikePolicy",
        "SpikeEvent",
        "Data-volume or conversation-count spikes (statistical).",
        {**_SCHED, "params": "SpikeDefParam!"},
    ),
    "rediscovered_asset": PolicyTypeSpec(
        "rediscovered_asset",
        "newRediscoveredAssetPolicy",
        "setRediscoveredAssetPolicy",
        "RediscoveredAssetEvent",
        "Asset reappearing after N seconds of inactivity.",
        {**_SCHED, **_SRC, "params": "RediscoveredAssetParams!"},
    ),
    "tag_value": PolicyTypeSpec(
        "tag_value",
        "newTagValuePolicy",
        "setTagValuePolicy",
        "TagPolicyEvent",
        "Controller tag written with a value outside the allowed value group/range.",
        {**_SRC, **_SCHED, "tagGroup": "Group!", "min": "String", "max": "String", "any": "Boolean"},
        set_only={"valueGroup": "Group!"},
        notes="update requires value_group_id (Tenable's setTagValuePolicy takes valueGroup).",
    ),
}

_ALIASES = {
    "idssrcdst": "ids_src_dst",
    "ids_srcdst": "ids_src_dst",
    "idsgeneral": "ids_general",
    "rediscoveredasset": "rediscovered_asset",
    "rediscovered": "rediscovered_asset",
    "tagvalue": "tag_value",
    "tag": "tag_value",
}

_RETURN_FIELDS = "id title level disabled"

# Policy types whose event enum has a single value (or, for protocol, the one
# the narrow tool exposes). Narrow create tools omit the `event` argument.
FIXED_EVENTS: dict[str, str] = {
    "protocol": "Conversation",
    "port": "OpenPort",
    "ids_general": "IpConflict",
    "intrusion": "IntrusionDetected",
    "rediscovered_asset": "RediscoveredAsset",
    "tag_value": "UnauthorizedTagWrite",
}


def resolve_type(policy_type: str) -> PolicyTypeSpec:
    key = (policy_type or "").strip().lower().replace("-", "_").replace(" ", "_")
    key = _ALIASES.get(key, key)
    spec = POLICY_TYPES.get(key)
    if spec is None:
        raise ValueError(
            f"unknown policy_type {policy_type!r}; valid: {sorted(POLICY_TYPES)}. "
            "Use describe_policy_type to see arguments and events."
        )
    return spec


def build_mutation(spec: PolicyTypeSpec, *, update: bool) -> str:
    """Render the GraphQL document for one policy type (create or update)."""
    decls: dict[str, str] = {}
    if update:
        decls["id"] = "ID!"
        decls.update(spec.set_only)
    decls.update(_COMMON_DECLS)
    decls["event"] = f"{spec.event_enum}!"
    decls.update(spec.extra)
    name = spec.mutation_set if update else spec.mutation_new
    var_block = ",\n  ".join(f"${k}: {t}" for k, t in decls.items())
    arg_block = ",\n    ".join(f"{k}: ${k}" for k in decls)
    return f"mutation M(\n  {var_block}\n) {{\n  {name}(\n    {arg_block}\n  ) {{ {_RETURN_FIELDS} }}\n}}\n"


_M_DISABLE_POLICY = "mutation M($id: ID!) { disablePolicy(id: $id) { id title disabled } }"


def _ew():
    from .writes import _execute_write

    return _execute_write


# ---------------------------------------------------------------------------
# Variable assembly
# ---------------------------------------------------------------------------


def _norm_actions(actions: list[dict[str, Any]] | None) -> list[dict[str, str]]:
    out = []
    for a in actions or []:
        aid, typ = a.get("aid"), a.get("type")
        if not aid or typ not in ("Email", "Syslog", "FortiGate"):
            raise ValueError(
                f"each action needs 'aid' and 'type' in Email|Syslog|FortiGate; got {a!r}"
            )
        out.append({"aid": str(aid), "type": typ})
    return out


def build_variables(
    spec: PolicyTypeSpec,
    *,
    title: str,
    level: str,
    event: str,
    src: Any = None,
    dst: Any = None,
    schedule_group_id: str | None = None,
    protocol_group_id: str | None = None,
    port_group_id: str | None = None,
    rule_group_id: str | None = None,
    tag_group_id: str | None = None,
    value_group_id: str | None = None,
    actions: list[dict[str, Any]] | None = None,
    disable_after_hit: bool = False,
    continuous: bool = False,
    snapshot: bool | None = None,
    min_value: str | None = None,
    max_value: str | None = None,
    any_value: bool | None = None,
    spike_time_frame: str | None = None,
    spike_sensitivity: str | None = None,
    inactivity_seconds: int | None = None,
    policy_id: str | None = None,
) -> dict[str, Any]:
    if not title or not title.strip():
        raise ValueError("title is required")
    if event not in spec.events:
        raise ValueError(
            f"event {event!r} is not valid for policy_type {spec.key!r} "
            f"({spec.event_enum}). Valid ({len(spec.events)}): {list(spec.events)[:25]}"
            f"{'...' if len(spec.events) > 25 else ''}"
        )
    v: dict[str, Any] = {
        "title": title.strip(),
        "level": to_policy_level(level),
        "event": event,
        "disableAfterHit": bool(disable_after_hit),
        "continuous": bool(continuous),
        "actions": _norm_actions(actions),
    }
    if policy_id is not None:
        v["id"] = policy_id
    wanted = set(spec.extra) | (set(spec.set_only) if policy_id is not None else set())

    def need(name: str, value: Any, label: str) -> None:
        if value in (None, ""):
            raise ValueError(f"{label} is required for policy_type {spec.key!r}")

    if "srcAssetGroup" in wanted:
        v["srcAssetGroup"] = group_expr(src, field_name="src")
    if "dstAssetGroup" in wanted:
        v["dstAssetGroup"] = group_expr(dst, field_name="dst")
    if "schedule" in wanted:
        need("schedule", schedule_group_id, "schedule_group_id")
        v["schedule"] = _group_arg(schedule_group_id, "schedule_group_id")
    if "protocolGroup" in wanted:
        need("protocolGroup", protocol_group_id, "protocol_group_id")
        v["protocolGroup"] = _group_arg(protocol_group_id, "protocol_group_id", allow_negate=True)
    if "portGroup" in wanted:
        need("portGroup", port_group_id, "port_group_id")
        v["portGroup"] = _group_arg(port_group_id, "port_group_id", allow_negate=True)
    if "ruleGroup" in wanted:
        need("ruleGroup", rule_group_id, "rule_group_id")
        v["ruleGroup"] = _group_arg(rule_group_id, "rule_group_id")
    if "tagGroup" in wanted:
        need("tagGroup", tag_group_id, "tag_group_id")
        v["tagGroup"] = _group_arg(tag_group_id, "tag_group_id")
    if "valueGroup" in wanted:
        need("valueGroup", value_group_id, "value_group_id")
        v["valueGroup"] = _group_arg(value_group_id, "value_group_id")
    if "snapshot" in wanted:
        if spec.extra["snapshot"].endswith("!") and snapshot is None:
            snapshot = False
        v["snapshot"] = snapshot
    if spec.key == "tag_value":
        v["min"], v["max"], v["any"] = min_value, max_value, any_value
    if spec.key == "spike":
        need("params", spike_time_frame, "spike_time_frame")
        need("params", spike_sensitivity, "spike_sensitivity")
        v["params"] = {"timeFrame": spike_time_frame, "sdCoefficient": spike_sensitivity}
    if spec.key == "rediscovered_asset":
        if not inactivity_seconds or inactivity_seconds <= 0:
            raise ValueError("inactivity_seconds (> 0) is required for rediscovered_asset")
        v["params"] = {"inactivityInSeconds": int(inactivity_seconds)}
    return v


def describe(policy_type: str | None = None) -> dict[str, Any]:
    if policy_type is None:
        return {
            "policy_types": {
                k: {
                    "summary": s.summary,
                    "mutation": s.mutation_new,
                    "event_count": len(s.events),
                    "required_args": sorted(_user_args(s)),
                }
                for k, s in POLICY_TYPES.items()
            },
            "scoping": group_expr.__doc__,
        }
    spec = resolve_type(policy_type)
    return {
        "policy_type": spec.key,
        "summary": spec.summary,
        "create_mutation": spec.mutation_new,
        "update_mutation": spec.mutation_set,
        "event_enum": spec.event_enum,
        "events": list(spec.events),
        "required_args": sorted(_user_args(spec)),
        "notes": spec.notes,
        "graphql_variables": {**_COMMON_DECLS, "event": spec.event_enum + "!", **spec.extra},
    }


_VAR_TO_ARG = {
    "srcAssetGroup": "src",
    "dstAssetGroup": "dst",
    "schedule": "schedule_group_id",
    "protocolGroup": "protocol_group_id",
    "portGroup": "port_group_id",
    "ruleGroup": "rule_group_id",
    "tagGroup": "tag_group_id",
    "snapshot": None,
    "min": None,
    "max": None,
    "any": None,
}


def _user_args(spec: PolicyTypeSpec) -> set[str]:
    args = {"title", "level", "event"}
    for var, typ in spec.extra.items():
        if var in _VAR_TO_ARG and _VAR_TO_ARG[var]:
            args.add(_VAR_TO_ARG[var])
    if spec.key == "spike":
        args |= {"spike_time_frame", "spike_sensitivity"}
    if spec.key == "rediscovered_asset":
        args.add("inactivity_seconds")
    return args


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

_Q_GET_POLICY = (
    "query Q($id: ID!) { policy(id: $id) { "
    "id title level disabled archived paused system continuous snapshot key "
    "lastModifiedDate lastModifiedBy disableAfterHit "
    "eventTypeDetails { type group description category family } "
    "} }"
)


def register_read_tools(mcp: Any, client: TenableClient, _audit: AuditLog) -> None:
    @mcp.tool(
        title="Describe detection-policy types",
        description=(
            "List the detection-policy types the create_*_policy tools cover, or give the "
            "arguments and valid `event` values for one type. No network call. Call "
            "this to find the valid `event` values for a type (activity and ids_src_dst have many)."
        ),
    )
    async def describe_policy_type(policy_type: str | None = None) -> dict[str, Any]:
        return describe(policy_type)

    @mcp.tool(
        title="Get one detection policy",
        description=(
            "Fetch a single detection policy by id (title, level, disabled, event "
            "details). Use after a create_*_policy call to confirm state."
        ),
    )
    async def get_policy(
        policy_id: str,
        site_uuid: str | None = None,
        site_name: str | None = None,
    ) -> dict[str, Any]:
        if not policy_id:
            raise ValueError("policy_id is required")

        async def query_site(machine_id: str) -> dict[str, Any]:
            data = await client.query(
                _Q_GET_POLICY, variables={"id": policy_id}, icp_machine_id=machine_id
            )
            return {"site_uuid": machine_id, "policy": data.get("policy")}

        return await run_site_read(
            client,
            site_uuid=site_uuid,
            site_name=site_name,
            site_uuids=None,
            worker=query_site,
        )


def register_write_tools(mcp: Any, client: TenableClient, audit: AuditLog) -> None:
    mcp = SiteScopedWriteMCP(mcp, client)
    execute_write = _ew()

    _common_doc = (
        "Scope args `src`/`dst` use conjunctive normal form: a flat list is ONE "
        "OR-clause (['A','B'] = A or B); a list of lists is AND of OR-clauses; "
        "prefix an id with '!' (or pass {id, negate:true}) to negate. "
        "Group ids (schedule, protocol, port, rule, tag) must exist on the target "
        "site — resolve them with the list_*_groups tools first."
    )

    _state_doc = (
        "`initial_state`: 'enabled' (Tenable's native behaviour) or 'disabled'. Tenable always "
        "creates policies enabled; 'disabled' is create + disablePolicy (two calls, not atomic; "
        "the result reports `state_applied` and any `warning`). `actions` may be empty. "
        "WRITE. Defaults to dry_run."
    )
    _scope_doc = (
        "`src`/`dst`: a group id, a flat list (['A','B'] = A OR B) or a list of lists "
        "(AND of OR-clauses); prefix an id with '!' to negate. Group ids must exist on the site "
        "(find them with the list_*_groups tools)."
    )

    async def _create(
        tool: str,
        ptype: str,
        *,
        initial_state: str,
        dry_run: bool,
        event: str | None = None,
        **kw: Any,
    ) -> dict[str, Any]:
        spec = resolve_type(ptype)
        state = (initial_state or "").strip().lower()
        if state not in ("enabled", "disabled"):
            raise ValueError("initial_state must be 'enabled' or 'disabled'")
        ev = event or FIXED_EVENTS.get(spec.key)
        if not ev:
            raise ValueError(f"event is required for {spec.key} policies; see describe_policy_type")
        variables = build_variables(spec, event=ev, **kw)
        out = await execute_write(
            client, audit, tool, build_mutation(spec, update=False), variables, dry_run
        )
        out["policy_type"] = spec.key
        out["initial_state"] = state
        if dry_run:
            out["note"] = "On apply, the policy is created enabled" + (
                " and then immediately disabled." if state == "disabled" else "."
            )
            return out
        created = (out.get("result") or {}).get(spec.mutation_new) or {}
        policy_id = created.get("id")
        out["policy_id"] = policy_id
        out["state_applied"] = "enabled"
        if state == "disabled":
            if not policy_id:
                out["warning"] = "created, but no id returned; policy left ENABLED"
                return out
            try:
                await execute_write(
                    client, audit, f"{tool}.disable", _M_DISABLE_POLICY, {"id": policy_id}, False
                )
                out["state_applied"] = "disabled"
            except Exception as exc:  # noqa: BLE001
                out["warning"] = (
                    f"policy {policy_id} was created but disabling failed ({exc}); "
                    "it is currently ENABLED - call disable_detection_policy to fix."
                )
        return out

    @mcp.tool(
        title="Create an unauthorized-conversation policy",
        description=(
            "Create a protocol policy that alerts on a CONVERSATION from `src` to `dst` "
            "(direction matters: src initiates) using the protocols in `protocol_group_id`. "
            "Prefix the protocol group id with '!' to alert on any protocol NOT in the group; "
            "use the 'Any protocol' group to alert on any conversation. `schedule_group_id` is "
            "usually the 'Any Time' group. `level`: none|low|medium|high.\n\n"
            + _scope_doc
            + "\n\n"
            + _state_doc
        ),
    )
    async def create_conversation_policy(
        title: str,
        level: str,
        src: Any,
        dst: Any,
        schedule_group_id: str,
        protocol_group_id: str,
        actions: list[dict[str, Any]] | None = None,
        initial_state: str = "enabled",
        dry_run: bool = True,
    ) -> dict[str, Any]:
        return await _create(
            "create_conversation_policy", "protocol", initial_state=initial_state, dry_run=dry_run,
            title=title, level=level, src=src, dst=dst, schedule_group_id=schedule_group_id,
            protocol_group_id=protocol_group_id, actions=actions,
        )  # fmt: skip

    @mcp.tool(
        title="Create an engineering-activity policy",
        description=(
            "Create a policy for engineering activity (downloads, uploads, start/stop, firmware...) "
            "from `src` to `dst`. `event` is a Tenable ActivityPolicyEvent value; list them with "
            "describe_policy_type('activity'). `level`: none|low|medium|high.\n\n"
            + _scope_doc
            + "\n\n"
            + _state_doc
        ),
    )
    async def create_activity_policy(
        title: str,
        level: str,
        event: str,
        src: Any,
        dst: Any,
        schedule_group_id: str,
        actions: list[dict[str, Any]] | None = None,
        snapshot: bool = False,
        initial_state: str = "enabled",
        dry_run: bool = True,
    ) -> dict[str, Any]:
        return await _create(
            "create_activity_policy", "activity", initial_state=initial_state, dry_run=dry_run,
            event=event, title=title, level=level, src=src, dst=dst,
            schedule_group_id=schedule_group_id, snapshot=snapshot, actions=actions,
        )  # fmt: skip

    @mcp.tool(
        title="Create an asset-change policy",
        description=(
            "Create a policy for asset changes on assets in `src` (new asset discovered, inactive, "
            "firmware change, ...). `event` is an AssetPolicyEvent value; see "
            "describe_policy_type('asset'). `level`: none|low|medium|high.\n\n"
            + _scope_doc
            + "\n\n"
            + _state_doc
        ),
    )
    async def create_asset_policy(
        title: str,
        level: str,
        event: str,
        src: Any,
        schedule_group_id: str,
        actions: list[dict[str, Any]] | None = None,
        initial_state: str = "enabled",
        dry_run: bool = True,
    ) -> dict[str, Any]:
        return await _create(
            "create_asset_policy", "asset", initial_state=initial_state, dry_run=dry_run,
            event=event, title=title, level=level, src=src,
            schedule_group_id=schedule_group_id, actions=actions,
        )  # fmt: skip

    @mcp.tool(
        title="Create an open-port policy",
        description=(
            "Create a policy that alerts when assets in `src` expose an open port in `port_group_id` "
            "(event OpenPort). `level`: none|low|medium|high.\n\n"
            + _scope_doc
            + "\n\n"
            + _state_doc
        ),
    )
    async def create_port_policy(
        title: str,
        level: str,
        src: Any,
        port_group_id: str,
        actions: list[dict[str, Any]] | None = None,
        initial_state: str = "enabled",
        dry_run: bool = True,
    ) -> dict[str, Any]:
        return await _create(
            "create_port_policy", "port", initial_state=initial_state, dry_run=dry_run,
            title=title, level=level, src=src, port_group_id=port_group_id, actions=actions,
        )  # fmt: skip

    @mcp.tool(
        title="Create an IDS source/destination policy",
        description=(
            "Create an IDS-style policy for events between `src` and `dst` (scans, RDP, DNP3 "
            "function codes, ...). `event` is an IDSSrcDstEvent value; see "
            "describe_policy_type('ids_src_dst'). `level`: none|low|medium|high.\n\n"
            + _scope_doc
            + "\n\n"
            + _state_doc
        ),
    )
    async def create_ids_src_dst_policy(
        title: str,
        level: str,
        event: str,
        src: Any,
        dst: Any,
        schedule_group_id: str,
        actions: list[dict[str, Any]] | None = None,
        initial_state: str = "enabled",
        dry_run: bool = True,
    ) -> dict[str, Any]:
        return await _create(
            "create_ids_src_dst_policy", "ids_src_dst", initial_state=initial_state, dry_run=dry_run,
            event=event, title=title, level=level, src=src, dst=dst,
            schedule_group_id=schedule_group_id, actions=actions,
        )  # fmt: skip

    @mcp.tool(
        title="Create an IP-conflict policy",
        description=(
            "Create a general IDS policy that alerts on IP address conflicts (event IpConflict). "
            "`level`: none|low|medium|high.\n\n" + _state_doc
        ),
    )
    async def create_ids_general_policy(
        title: str,
        level: str,
        schedule_group_id: str,
        actions: list[dict[str, Any]] | None = None,
        initial_state: str = "enabled",
        dry_run: bool = True,
    ) -> dict[str, Any]:
        return await _create(
            "create_ids_general_policy", "ids_general", initial_state=initial_state, dry_run=dry_run,
            title=title, level=level, schedule_group_id=schedule_group_id, actions=actions,
        )  # fmt: skip

    @mcp.tool(
        title="Create an intrusion-rule policy",
        description=(
            "Create a policy that alerts when intrusion rules in `rule_group_id` hit between `src` "
            "and `dst` (event IntrusionDetected). `level`: none|low|medium|high.\n\n"
            + _scope_doc
            + "\n\n"
            + _state_doc
        ),
    )
    async def create_intrusion_policy(
        title: str,
        level: str,
        src: Any,
        dst: Any,
        rule_group_id: str,
        schedule_group_id: str,
        actions: list[dict[str, Any]] | None = None,
        initial_state: str = "enabled",
        dry_run: bool = True,
    ) -> dict[str, Any]:
        return await _create(
            "create_intrusion_policy", "intrusion", initial_state=initial_state, dry_run=dry_run,
            title=title, level=level, src=src, dst=dst, rule_group_id=rule_group_id,
            schedule_group_id=schedule_group_id, actions=actions,
        )  # fmt: skip

    @mcp.tool(
        title="Create a traffic-spike policy",
        description=(
            "Create a statistical spike policy. `event`: DataSpikeDetected or "
            "ConversationCountSpikeDetected. `spike_time_frame` (Tenable SpikeTimeFrame) and "
            "`spike_sensitivity` (Tenable Sensitivity) are passed through as given; the server "
            "rejects invalid values. `level`: none|low|medium|high.\n\n"
            + _state_doc
        ),
    )
    async def create_spike_policy(
        title: str,
        level: str,
        event: str,
        schedule_group_id: str,
        spike_time_frame: str,
        spike_sensitivity: str,
        actions: list[dict[str, Any]] | None = None,
        initial_state: str = "enabled",
        dry_run: bool = True,
    ) -> dict[str, Any]:
        return await _create(
            "create_spike_policy", "spike", initial_state=initial_state, dry_run=dry_run,
            event=event, title=title, level=level, schedule_group_id=schedule_group_id,
            spike_time_frame=spike_time_frame, spike_sensitivity=spike_sensitivity, actions=actions,
        )  # fmt: skip

    @mcp.tool(
        title="Create a rediscovered-asset policy",
        description=(
            "Create a policy that alerts when an asset in `src` reappears after "
            "`inactivity_seconds` of silence (event RediscoveredAsset). "
            "`level`: none|low|medium|high.\n\n"
            + _scope_doc
            + "\n\n"
            + _state_doc
        ),
    )
    async def create_rediscovered_asset_policy(
        title: str,
        level: str,
        src: Any,
        schedule_group_id: str,
        inactivity_seconds: int,
        actions: list[dict[str, Any]] | None = None,
        initial_state: str = "enabled",
        dry_run: bool = True,
    ) -> dict[str, Any]:
        return await _create(
            "create_rediscovered_asset_policy", "rediscovered_asset", initial_state=initial_state,
            dry_run=dry_run, title=title, level=level, src=src, schedule_group_id=schedule_group_id,
            inactivity_seconds=inactivity_seconds, actions=actions,
        )  # fmt: skip

    @mcp.tool(
        title="Create a controller tag-value policy",
        description=(
            "Create a policy that alerts on an unauthorized write (event UnauthorizedTagWrite) to "
            "controller tags in `tag_group_id` on assets in `src`; `min_value`/`max_value` give the "
            "allowed range, or set `any_value`. `level`: none|low|medium|high.\n\n"
            + _scope_doc
            + "\n\n"
            + _state_doc
        ),
    )
    async def create_tag_value_policy(
        title: str,
        level: str,
        src: Any,
        schedule_group_id: str,
        tag_group_id: str,
        min_value: str | None = None,
        max_value: str | None = None,
        any_value: bool | None = None,
        actions: list[dict[str, Any]] | None = None,
        initial_state: str = "enabled",
        dry_run: bool = True,
    ) -> dict[str, Any]:
        return await _create(
            "create_tag_value_policy", "tag_value", initial_state=initial_state, dry_run=dry_run,
            title=title, level=level, src=src, schedule_group_id=schedule_group_id,
            tag_group_id=tag_group_id, min_value=min_value, max_value=max_value,
            any_value=any_value, actions=actions,
        )  # fmt: skip

    @mcp.tool(
        title="Update a detection policy (full replace)",
        description=(
            "Replace an existing detection policy's configuration via the matching "
            "set*Policy mutation. This is a FULL REPLACE: every field is overwritten "
            "from the arguments, so pass the complete desired definition (read the "
            "current one first with get_policy). Does not change enabled/disabled "
            "state — use enable_detection_policy / disable_detection_policy.\n\n"
            + _common_doc
            + "\n\nWRITE. Defaults to dry_run."
        ),
    )
    async def update_policy(
        policy_id: str,
        policy_type: str,
        title: str,
        level: str,
        event: str,
        src: Any = None,
        dst: Any = None,
        schedule_group_id: str | None = None,
        protocol_group_id: str | None = None,
        port_group_id: str | None = None,
        rule_group_id: str | None = None,
        tag_group_id: str | None = None,
        value_group_id: str | None = None,
        actions: list[dict[str, Any]] | None = None,
        disable_after_hit: bool = False,
        continuous: bool = False,
        snapshot: bool | None = None,
        min_value: str | None = None,
        max_value: str | None = None,
        any_value: bool | None = None,
        spike_time_frame: str | None = None,
        spike_sensitivity: str | None = None,
        inactivity_seconds: int | None = None,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        if not policy_id:
            raise ValueError("policy_id is required")
        spec = resolve_type(policy_type)
        variables = build_variables(
            spec,
            title=title,
            level=level,
            event=event,
            src=src,
            dst=dst,
            schedule_group_id=schedule_group_id,
            protocol_group_id=protocol_group_id,
            port_group_id=port_group_id,
            rule_group_id=rule_group_id,
            tag_group_id=tag_group_id,
            value_group_id=value_group_id,
            actions=actions,
            disable_after_hit=disable_after_hit,
            continuous=continuous,
            snapshot=snapshot,
            min_value=min_value,
            max_value=max_value,
            any_value=any_value,
            spike_time_frame=spike_time_frame,
            spike_sensitivity=spike_sensitivity,
            inactivity_seconds=inactivity_seconds,
            policy_id=policy_id,
        )
        out = await execute_write(
            client, audit, "update_policy", build_mutation(spec, update=True), variables, dry_run
        )
        out["policy_type"] = spec.key
        return out
