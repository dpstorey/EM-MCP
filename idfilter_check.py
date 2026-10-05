"""Check whether the Tenable OT `assets` GraphQL filter accepts asset ids.

Read-only: sends a few small `assets` queries, prints status + counts.
Run INSIDE the tenable-ot MCP container (it reads the encrypted config the
server itself uses; nothing secret is printed):

    docker cp idfilter_check.py <container>:/tmp/idfilter_check.py
    docker exec -it <container> python /tmp/idfilter_check.py

Optional env: MCP_DATA_DIR (default /data).
"""
import asyncio
import json
import os
from pathlib import Path

from tenable_ot_mcp.config import ConfigStore
from tenable_ot_mcp.tenable_client import TenableClient

SITE = "9b06f7ce-20ca-44d2-8927-4be796cc0c2d"  # London machine_id
IDS = [
    "08bda440-1b9d-49e5-b2a8-b2f04a55635c",  # router.barossafarm.com
    "c4c1c7d4-08e4-4d24-a9dc-1d2234d4bc0c",  # SRV_M
]
CIDR = ("10.253.0.0", "10.253.15.255")

QUERY = (
    "query Q($pageSize: Int!, $filter: AssetExpressionsParams) { "
    "assets(first: $pageSize, filter: $filter) { totalCount nodes { id name } } }"
)


def eq(field, v):
    return {"field": field, "op": "Equal", "values": [v]}


CASES = [
    ("control: ips Between /20", {"field": "ips", "op": "Between", "values": list(CIDR)}),
    ("id In [2 ids]", {"field": "id", "op": "In", "values": IDS}),
    ("assetId In [2 ids]", {"field": "assetId", "op": "In", "values": IDS}),
    ("id Equal [1 id]", eq("id", IDS[0])),
    ("Or(id Equal, id Equal)", {"op": "Or", "expressions": [eq("id", IDS[0]), eq("id", IDS[1])]}),
]


async def main() -> None:
    cfg = ConfigStore(Path(os.environ.get("MCP_DATA_DIR", "/data"))).load()
    client = TenableClient(
        base_url=cfg.tenable_url,
        api_key=cfg.tenable_api_key,
        icp_machine_id=cfg.icp_machine_id,
        tls_verify=cfg.tls_verify,
    )
    for label, flt in CASES:
        try:
            data = await client.query(
                QUERY, {"pageSize": 50, "filter": flt}, icp_machine_id=SITE
            )
            conn = data.get("assets") or {}
            names = [n.get("name") for n in conn.get("nodes") or []]
            print(f"OK    {label}: totalCount={conn.get('totalCount')} "
                  f"returned={len(names)} names={names[:4]}")
        except Exception as e:  # report the server's message, keep going
            print(f"FAIL  {label}: {type(e).__name__}: {str(e)[:300]}")


asyncio.run(main())
