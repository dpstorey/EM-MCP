# SPDX-License-Identifier: Apache-2.0
"""Print the Backplane-related GraphQL types and the Asset fields that reach them.

Usage:
    TENABLE_URL=https://ot.example TENABLE_API_KEY=... [ICP_MACHINE_ID=...] \
        python scripts/introspect_backplane.py [--insecure] [--all]

Use the output to confirm/adjust `_GET_ASSET_BACKPLANE` and `_project_backplane`
in src/tenable_ot_mcp/tools/assets.py.
"""
import json
import os
import sys

import httpx

TYPES = ["Backplane", "AssetConnection", "AssetEdge", "HardwareState", "AssetDetailsLayout", "OS", "NetworkInterface", "Asset"]
KEYWORDS = ("backplane", "slot", "module", "position", "rack", "chassis")
Q = """query($n:String!){__type(name:$n){name kind enumValues{name} fields{name args{name type{...T}} type{...T}}}}
fragment T on __Type{kind name ofType{kind name ofType{kind name ofType{kind name}}}}"""


def tname(t):
    if not t:
        return ""
    if t["kind"] == "NON_NULL":
        return tname(t["ofType"]) + "!"
    if t["kind"] == "LIST":
        return "[" + tname(t["ofType"]) + "]"
    return t["name"]


def main() -> None:
    base = os.environ["TENABLE_URL"].rstrip("/")
    icp = os.environ.get("ICP_MACHINE_ID", "").strip("/")
    url = f"{base}/{icp}/graphql" if icp else f"{base}/graphql"
    hdr = {"X-APIKeys": f"key={os.environ['TENABLE_API_KEY']}", "Content-Type": "application/json"}
    with httpx.Client(verify="--insecure" not in sys.argv, timeout=30) as c:
        for name in TYPES:
            r = c.post(url, headers=hdr, json={"query": Q, "variables": {"n": name}})
            t = (r.json().get("data") or {}).get("__type")
            if not t:
                print(f"\n## {name}: not found\n{json.dumps(r.json())[:300]}")
                continue
            print(f"\n## {name} ({t['kind']})")
            for v in t.get("enumValues") or []:
                print(f"  = {v['name']}")
            for f in t["fields"] or []:
                if name == "Asset" and "--all" not in sys.argv and not any(k in f["name"].lower() for k in KEYWORDS):
                    continue
                args = ", ".join(f"{a['name']}: {tname(a['type'])}" for a in f["args"])
                print(f"  {f['name']}({args}): {tname(f['type'])}")


if __name__ == "__main__":
    main()
