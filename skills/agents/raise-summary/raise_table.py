#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build the RAISE Asset Summary table from `query_assets` output.

Deterministic, no network. Lives with the agent's Code Environment, NOT in the
MCP server, so the MCP stays neutral about grading schemes. Change
RAISE_FIELDS / FATAL_FIELD / FATAL_VALUES below for a site that uses a
different scale.

Normal use is one `run_tools_with_bash` call (the sandbox exposes tools as bash
functions; tool_manifest must list the exact registered name of query_assets):

    eval "$(python3 /PATH/TO/raise_table.py --bash-init)"; raise_table "London" "10.253.0.0/20"

`--bash-init` prints a small bash function, `raise_table`, which finds the
query_assets function, pages through every result into JSON files, then runs:

    python3 /mnt/data/raise_table.py SITE page1.json [page2.json ...]

Each page file is one `query_assets` result (`assets`, `total_count`,
`has_more`, `end_cursor`). Pages are merged, then the table is printed.
`build_table(result, site_name)` is the importable core.
"""
from __future__ import annotations

import json
import sys
from typing import Any

__version__ = "1.4.1"  # 1.4.1: --bash-init uses the script's own path (works from /pkgs or /mnt/data). 1.4: single file

RAISE_FIELDS = ("R", "A", "I", "S", "E")  # custom-field labels, in column order
FATAL_FIELD = "S"                         # which grade triggers the flag
FATAL_VALUES = frozenset({"D", "E"})
FLAG_PREFIX = "⚠️ FATALITY RISK — "
TYPE_MAP = {"Plc": "PLC", "Io": "I/O", "Hmi": "HMI"}
DESC_MAX = 40

HEADER = ("Site", "Asset", "IP Address", "Asset Type", "Numerical Risk Score", "Description",
          "R", "A", "I", "S", "E")
SEPARATOR = "|:---|:---|:---|:---|---:|:---|:---:|:---:|:---:|:---:|:---:|"


def _cell(text: Any) -> str:
    """Make text safe for a Markdown table cell."""
    return str(text).replace("|", "/").replace("\n", " ").strip()


def _grade(cf: dict[str, Any], label: str) -> str:
    v = cf.get(label)
    return v.strip() if isinstance(v, str) and v.strip() else "-"


def _desc(text: Any) -> str:
    if not isinstance(text, str) or not text.strip():
        return "-"
    t = " ".join(text.split())
    return t if len(t) <= DESC_MAX else t[:DESC_MAX].rstrip() + "…"


def _score(asset: dict[str, Any]) -> float | None:
    v = (asset.get("risk") or {}).get("total_risk")
    return float(v) if isinstance(v, (int, float)) else None


def build_table(result: Any, site_name: str) -> str:
    assets = result.get("assets", []) if isinstance(result, dict) else list(result)
    total = result.get("total_count") if isinstance(result, dict) else None

    rows = sorted(assets, key=lambda a: (-(_score(a) if _score(a) is not None else -1.0),
                                         str(a.get("name") or "")))
    lines = ["| " + " | ".join(HEADER) + " |", SEPARATOR]
    fatal_names = []
    for a in rows:
        cf = a.get("custom_fields") or {}
        name = str(a.get("name") or a.get("id") or "unknown")
        fatal = str(cf.get(FATAL_FIELD) or "").strip().upper() in FATAL_VALUES
        if fatal:
            fatal_names.append(name)
        ips = a.get("ips") or []
        typ = str(a.get("type") or "-")
        sc = _score(a)
        cells = [
            site_name,
            (FLAG_PREFIX if fatal else "") + name,
            ips[0] if ips else "-",
            TYPE_MAP.get(typ, typ),
            f"{sc:.1f}" if sc is not None else "-",
            _desc(a.get("description")),
            *[_grade(cf, f) for f in RAISE_FIELDS],
        ]
        lines.append("| " + " | ".join(_cell(c) for c in cells) + " |")

    check = f"Rows: {len(rows)}"
    if total is not None:
        check += f" of total_count {total}" + ("" if total == len(rows) else " (MISMATCH: assets missing, do not present as complete)")
    fatal_line = ("Fatality-flagged (S=D or S=E): " + ", ".join(fatal_names)) if fatal_names else "Fatality-flagged (S=D or S=E): none"
    return "\n".join(lines) + "\n\n" + check + "\n" + fatal_line + "\n"


BASH_INIT = r'''
raise_table() {
  local site="$1" subnet="$2" fn="" after="" n=0 args raw dir
  local -a files=()
  if [ -z "$site" ] || [ -z "$subnet" ]; then
    echo "ERROR: usage: raise_table SITE_NAME CIDR"
    return 2
  fi
  fn=$(declare -F | awk '{print $3}' | grep -E '^query_assets' | head -n 1)
  if [ -z "$fn" ]; then
    echo "ERROR: no query_assets function is defined in this shell. Put the exact registered tool name in tool_manifest."
    echo "Functions seen: $(declare -F | awk '{print $3}' | grep -v '^_' | tr '\n' ' ')"
    return 1
  fi
  dir=$(mktemp -d)
  while [ "$n" -lt 200 ]; do
    n=$((n + 1))
    args=$(jq -nc --arg s "$site" --arg c "$subnet" --arg a "$after" \
      '{site_name: $s, subnet: $c, limit: 500} + (if $a != "" then {after: $a} else {} end)')
    raw=$("$fn" "$args")
    printf '%s\n' "$raw" > "$dir/p$n.json"
    files+=("$dir/p$n.json")
    if ! jq -e 'type == "object" and has("assets")' "$dir/p$n.json" > /dev/null 2>&1; then
      echo "ERROR: $fn did not return an asset list. First 300 characters: $(head -c 300 "$dir/p$n.json")"
      return 1
    fi
    [ "$(jq -r '.has_more // false' "$dir/p$n.json")" = "true" ] || break
    after=$(jq -r '.end_cursor // ""' "$dir/p$n.json")
    [ -n "$after" ] || break
  done
  python3 "__RAISE_PY__" "$site" "${files[@]}"
}
'''


def _load_page(path: str) -> dict[str, Any]:
    data = json.load(open(path, encoding="utf-8"))
    if isinstance(data, str):  # tool stdout sometimes arrives as a JSON string
        data = json.loads(data)
    if not isinstance(data, dict) or "assets" not in data:
        raise SystemExit(f"ERROR: {path} is not a query_assets result: {str(data)[:200]}")
    return data


def main(argv: list[str]) -> int:
    if len(argv) == 2 and argv[1] == "--bash-init":
        import os
        print(BASH_INIT.replace("__RAISE_PY__", os.path.abspath(__file__)).strip("\n"))
        return 0
    if len(argv) < 3:
        print("usage: raise_table.py SITE page1.json [page2.json ...]", file=sys.stderr)
        return 2
    site, pages = argv[1], [_load_page(p) for p in argv[2:]]
    assets: list[dict[str, Any]] = []
    for p in pages:
        assets += p.get("assets", [])
    total = pages[0].get("total_count")
    print(build_table({"assets": assets, "total_count": total}, site))
    print(f"\nraise_table v{__version__}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
