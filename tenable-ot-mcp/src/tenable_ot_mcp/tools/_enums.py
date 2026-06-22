# SPDX-License-Identifier: Apache-2.0
"""Natural-vocabulary ↔ Tenable OT enum translation.

This module is the *only* place Tenable OT's internal enum spellings
appear. Everywhere else in the codebase — tool argument types, tool
descriptions, the README, the tool catalog — uses natural OT
vocabulary ("high", "plc", "controller", "level1") and lets this
module translate before the GraphQL goes out the door.

The benefit: a Tenable OT enum rename never breaks the MCP tool
surface; consuming AIs (Eymbr AI especially) reason about familiar
words instead of vendor-specific PascalCase. See
`project_mcp_tool_surface_owns_its_vocabulary` memory.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Filter operators (Tenable's `ExprOp` enum)
# ---------------------------------------------------------------------------

# Tenable's ExprOp values, exposed by canonical name. Tools do not pass
# these directly — they're used internally when constructing filters.
EXPR_EQUAL = "Equal"
EXPR_NOT_EQUAL = "NotEqual"
EXPR_GREATER = "Greater"
EXPR_LESS = "Less"
EXPR_GREATER_EQUAL = "GreaterEqual"
EXPR_LESS_EQUAL = "LessEqual"
EXPR_IN = "In"
EXPR_NOT_IN = "NotIn"
EXPR_BETWEEN = "Between"
EXPR_AND = "And"
EXPR_OR = "Or"
EXPR_CONTAINS = "Contains"
EXPR_LIKE = "Like"


# ---------------------------------------------------------------------------
# Criticality — operator-judged risk level
# ---------------------------------------------------------------------------

_CRITICALITY = {
    "none": "NoneCriticality",
    "low": "LowCriticality",
    "medium": "MediumCriticality",
    "high": "HighCriticality",
}

CRITICALITY_VALUES = list(_CRITICALITY)


def to_criticality(natural: str) -> str:
    """Translate "low" / "medium" / "high" / "none" to Tenable's enum."""
    v = (natural or "").strip().lower()
    if v not in _CRITICALITY:
        raise ValueError(f"criticality must be one of {CRITICALITY_VALUES}; got {natural!r}")
    return _CRITICALITY[v]


# Tenable's `criticality` field doesn't accept `GreaterEqual` against the
# enum, so "at least Medium" can't be expressed as a single comparison.
# Instead we translate to an `In` filter with the explicit set of
# acceptable values. The order below is the natural ordinal of OT
# criticality (None < Low < Medium < High).
_CRITICALITY_ORDINAL = ["none", "low", "medium", "high"]


def to_criticality_at_least(natural: str) -> list[str]:
    """Translate "at least medium" → list of Tenable criticality values
    matching that floor (e.g. ["MediumCriticality", "HighCriticality"]).
    For use with the `In` filter operator since `GreaterEqual` is not
    supported on this field."""
    v = (natural or "").strip().lower()
    if v not in _CRITICALITY:
        raise ValueError(f"criticality must be one of {CRITICALITY_VALUES}; got {natural!r}")
    idx = _CRITICALITY_ORDINAL.index(v)
    return [_CRITICALITY[k] for k in _CRITICALITY_ORDINAL[idx:]]


# ---------------------------------------------------------------------------
# Policy level — severity of a detection policy
# ---------------------------------------------------------------------------

_POLICY_LEVEL = {
    "none": "None",
    "low": "Low",
    "medium": "Medium",
    "high": "High",
}

POLICY_LEVEL_VALUES = list(_POLICY_LEVEL)


def to_policy_level(natural: str) -> str:
    """Translate "low" / "medium" / "high" / "none" to Tenable's PolicyLevel."""
    v = (natural or "").strip().lower()
    if v not in _POLICY_LEVEL:
        raise ValueError(f"policy level must be one of {POLICY_LEVEL_VALUES}; got {natural!r}")
    return _POLICY_LEVEL[v]


# ---------------------------------------------------------------------------
# Asset category — the high-level grouping ("controller" / "network" / "iot")
# ---------------------------------------------------------------------------

_ASSET_CATEGORY = {
    "controller": "ControllersCategory",
    "network": "NetworkAssetsCategory",
    "iot": "IotCategory",
}

ASSET_CATEGORY_VALUES = list(_ASSET_CATEGORY)


def to_asset_category(natural: str) -> str:
    """Translate "controller" / "network" / "iot" to Tenable's AssetCategory."""
    v = (natural or "").strip().lower()
    if v not in _ASSET_CATEGORY:
        raise ValueError(f"asset category must be one of {ASSET_CATEGORY_VALUES}; got {natural!r}")
    return _ASSET_CATEGORY[v]


# ---------------------------------------------------------------------------
# Asset type kind — natural OT category that may map to several specific values
# ---------------------------------------------------------------------------

# Each natural kind maps to one or more Tenable AssetType enum values,
# combined via the `In` operator at filter time. "controller" matches
# both `OtDevice` (PLCs / RTUs) and the industrial-flavored types that
# operators commonly think of as controllers.
_ASSET_KIND: dict[str, list[str]] = {
    # Controllers and OT compute. PLCs and IEDs are explicit asset types
    # in Tenable's enum; OtDevice is the generic OT-control bucket;
    # OtServer / OtWorkstation are HMI-adjacent hosts.
    "plc": ["Plc"],
    "rtu": ["Rtu"],
    "ied": ["Ied"],
    "hmi": ["Hmi"],
    "controller": ["Plc", "Rtu", "Ied", "OtDevice"],
    "ot_compute": ["OtDevice", "OtServer", "OtWorkstation"],
    # Network gear.
    "switch": ["Switch", "IndustrialSwitch"],
    "router": ["Router", "IndustrialRouter"],
    "firewall": ["Firewall"],
    "gateway": ["Gateway", "IndustrialGateway", "SerialEthernetBridge"],
    "access_point": ["AccessPoint"],
    # IoT / IT compute.
    "iot": ["Iot", "SmartSensor", "SmartHub", "Camera"],
    "server": ["Server", "FileServer", "WebServer", "VirtualServer", "DomainController"],
    "workstation": ["OtWorkstation"],
    "field_device": ["FieldDevice", "Actuator"],
    "tenable_appliance": ["TenableIcp", "TenableEm", "TenableSensor"],
    "printer": ["Printer", "IndustrialPrinter", "ThreeDPrinter"],
    "camera": ["Camera"],
    "ups": ["Ups"],
    "mobile": ["Mobile", "Tablet"],
    "medical": ["MedicalDevice"],
    "panel": ["Panel"],
    "storage": ["StorageDevice"],
}

ASSET_KIND_VALUES = list(_ASSET_KIND)


def to_asset_types(natural_kind: str) -> list[str]:
    """Translate a natural asset kind to a list of Tenable AssetType values
    for use with the `In` filter operator."""
    v = (natural_kind or "").strip().lower()
    if v not in _ASSET_KIND:
        raise ValueError(f"asset kind must be one of {ASSET_KIND_VALUES}; got {natural_kind!r}")
    return _ASSET_KIND[v]


# ---------------------------------------------------------------------------
# Purdue level — ICS hierarchy (0=process, 1=basic control, 2=area
# supervisory, 3=site ops, 3.5=DMZ, 4=enterprise)
# ---------------------------------------------------------------------------

_PURDUE = {
    "unknown": "UnknownLevel",
    "level0": "Level0",
    "level1": "Level1",
    "level2": "Level2",
    "level3": "Level3",
    "level3.5": "Level3_5",
    "level4": "Level4",
    "level5": "Level5",
}

PURDUE_VALUES = list(_PURDUE)


def to_purdue(natural: str) -> str:
    """Translate "level0" / "level3.5" / etc. to Tenable's PurdueLevel."""
    v = (natural or "").strip().lower().replace(" ", "")
    if v not in _PURDUE:
        raise ValueError(f"purdue level must be one of {PURDUE_VALUES}; got {natural!r}")
    return _PURDUE[v]


# ---------------------------------------------------------------------------
# User-definable enums — for asset-edit mutations
#
# Tenable distinguishes "filter" enums from "user-definable" enums. The
# user-definable variants are a subset of the filter enums plus a
# `_RemoveUserDefinedValue` sentinel that callers pass to clear an
# operator override and revert the asset to "as Tenable discovered".
# `UserDefinedAssetType` exposes the full asset-type vocabulary (~70
# values) — far broader than the filter "kind" surface. `UserDefinedPurdueLevel`
# drops Level3_5 and Level5. `UserDefinedCriticality` matches `Criticality`.
# ---------------------------------------------------------------------------

REMOVE_USER_DEFINED = "_RemoveUserDefinedValue"


# UserDefinedAssetType enum — the full editable asset-type surface
_USER_DEFINED_ASSET_TYPES: list[str] = [
    "Unknown",
    "NetworkDevice",
    "Radio",
    "Repeater",
    "Converter",
    "Firewall",
    "AccessPoint",
    "Hub",
    "Gateway",
    "SerialEthernetBridge",
    "Switch",
    "Router",
    "OtDevice",
    "IndustrialPrinter",
    "IndustrialNetworkDevice",
    "IndustrialGateway",
    "IndustrialSwitch",
    "IndustrialRouter",
    "Iot",
    "Projector",
    "Panel",
    "StorageDevice",
    "VoipDevice",
    "Mobile",
    "MedicalDevice",
    "Tablet",
    "SmartTv",
    "SmartHub",
    "LightingControl",
    "HvacModule",
    "AccessControlSystem",
    "BarcodeScanner",
    "SmartSensor",
    "ThreeDPrinter",
    "Printer",
    "Ups",
    "Camera",
    "Server",
    "FileServer",
    "WebServer",
    "VirtualServer",
    "VideoManagementSystem",
    "SecurityAppliance",
    "TenableIcp",
    "TenableEm",
    "TenableSensor",
    "DomainController",
    "FieldDevice",
    "Actuator",
    "Drive",
    "IndustrialSensor",
    "Inverter",
    "Relay",
    "RemoteIo",
    "PowerMeter",
    "OtServer",
    "Historian",
    "DataLogger",
    "Hmi",
    "Workstation",
    "VirtualWorkstation",
    "OtWorkstation",
    "Eng",
    "Controller",
    "BackplaneModule",
    "PowerSupply",
    "Io",
    "Cp",
    "Cnc",
    "Robot",
    "Bms",
    "Rtu",
    "Ied",
    "Dcs",
    "Plc",
]

# Aliases for natural variants users might type. The enum values themselves
# are also accepted (case- and separator-insensitive) via _normalize_setter_key.
_USER_DEFINED_ASSET_TYPE_ALIASES: dict[str, str] = {
    "engineering_workstation": "Eng",
    "engineering": "Eng",
    "data_logger": "DataLogger",
    "control_panel": "Panel",
    "video_management": "VideoManagementSystem",
    "vms": "VideoManagementSystem",
    "3d_printer": "ThreeDPrinter",
    "remote_io": "RemoteIo",
    "io_module": "Io",
    "power_supply": "PowerSupply",
    "power_meter": "PowerMeter",
    "smart_sensor": "SmartSensor",
    "industrial_sensor": "IndustrialSensor",
}

USER_DEFINED_ASSET_TYPE_VALUES = list(_USER_DEFINED_ASSET_TYPES)


def _normalize_setter_key(s: str) -> str:
    return s.strip().lower().replace(" ", "").replace("_", "").replace("-", "")


_NORMALIZED_ASSET_TYPE_MAP: dict[str, str] = {
    _normalize_setter_key(v): v for v in _USER_DEFINED_ASSET_TYPES
}
for _alias, _target in _USER_DEFINED_ASSET_TYPE_ALIASES.items():
    _NORMALIZED_ASSET_TYPE_MAP[_normalize_setter_key(_alias)] = _target


def to_asset_type_setter(natural: str) -> str:
    """Translate natural OT vocab to a single UserDefinedAssetType enum value.

    For use with `updateAssetWithRemove` / `bulkEditAssetsWithRemove`. Accepts
    enum values directly (e.g. "Plc", "OtWorkstation") as well as natural
    variants ("plc", "ot_workstation", "data_logger", "3d_printer"). Different
    from `to_asset_types` which returns a LIST for filter `In` operators.
    """
    if not natural:
        raise ValueError("asset type must be a non-empty string")
    key = _normalize_setter_key(natural)
    if key not in _NORMALIZED_ASSET_TYPE_MAP:
        raise ValueError(
            f"unknown asset type {natural!r}; must match one of "
            f"{USER_DEFINED_ASSET_TYPE_VALUES} (case- and separator-insensitive)"
        )
    return _NORMALIZED_ASSET_TYPE_MAP[key]


# UserDefinedPurdueLevel — narrower than the filter PurdueLevel (no Level3_5 / Level5)
_USER_DEFINED_PURDUE = {
    "unknown": "UnknownLevel",
    "level0": "Level0",
    "level1": "Level1",
    "level2": "Level2",
    "level3": "Level3",
    "level4": "Level4",
}

USER_DEFINED_PURDUE_VALUES = list(_USER_DEFINED_PURDUE)


def to_purdue_setter(natural: str) -> str:
    """Translate natural Purdue level to UserDefinedPurdueLevel for setting.

    Setter enum is narrower than the filter `to_purdue`: no Level3.5 / Level5.
    """
    v = (natural or "").strip().lower().replace(" ", "")
    if v not in _USER_DEFINED_PURDUE:
        raise ValueError(
            f"purdue level for setting must be one of {USER_DEFINED_PURDUE_VALUES}; got {natural!r}"
        )
    return _USER_DEFINED_PURDUE[v]


# CustomFieldValueType — only two options in Tenable's schema
_VALUE_TYPE = {
    "plaintext": "PlainText",
    "plain_text": "PlainText",
    "text": "PlainText",
    "string": "PlainText",
    "hyperlink": "HyperLink",
    "link": "HyperLink",
    "url": "HyperLink",
}

VALUE_TYPE_VALUES = ["PlainText", "HyperLink"]


def to_value_type(natural: str) -> str:
    """Translate natural label to CustomFieldValueType ("PlainText" or "HyperLink")."""
    v = (natural or "").strip().lower().replace(" ", "").replace("-", "")
    if v not in _VALUE_TYPE:
        raise ValueError(f"value_type must be one of {VALUE_TYPE_VALUES}; got {natural!r}")
    return _VALUE_TYPE[v]


# ---------------------------------------------------------------------------
# Filter expression builders
# ---------------------------------------------------------------------------


# Ordinal comparison ops require `values` as a SCALAR, not an array —
# Tenable's backend errors with "cannot use array or slice with less
# than or greater than operators" if a list is passed. Equality and
# membership ops keep the array shape.
_ORDINAL_OPS = {EXPR_GREATER, EXPR_GREATER_EQUAL, EXPR_LESS, EXPR_LESS_EQUAL}


def expr(field: str, op: str, values: list | None = None) -> dict:
    """Build a single filter expression.

    Tenable accepts `values` as a JSON scalar OR array depending on
    the operator. Callers always pass a list for shape uniformity;
    this helper unwraps to a single scalar for ordinal ops where
    Tenable rejects the array form.
    """
    out: dict = {"field": field, "op": op}
    if values is not None:
        if op in _ORDINAL_OPS and isinstance(values, list):
            if len(values) != 1:
                raise ValueError(f"ordinal op {op!r} requires exactly one value; got {len(values)}")
            out["values"] = values[0]
        else:
            out["values"] = values
    return out


def expr_and(*expressions: dict) -> dict:
    """Combine multiple expressions via AND."""
    return {"op": EXPR_AND, "expressions": list(expressions)}


def expr_or(*expressions: dict) -> dict:
    """Combine multiple expressions via OR."""
    return {"op": EXPR_OR, "expressions": list(expressions)}
