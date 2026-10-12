# Tenable OT MCP, Enterprise Manager edition

An MCP server that exposes [Tenable OT Security](https://www.tenable.com/products/tenable-ot)
to AI clients through Enterprise Manager (EM), with site routing, guarded write
tools and policy-creation tools. The server lives in [`tenable-ot-mcp/`](tenable-ot-mcp/);
start with its [README](tenable-ot-mcp/README.md) for install, setup and the tool reference.

> [!NOTE]
> **Use this repository, not the original project.** This is a fork of
> [`tenable-ot-mcp` by John Walley / OneClearPath, Incorporated](https://gitlab.com/jwalley/tenable-ot-mcp)
> (Apache-2.0), who deserve the credit for the original server. It has diverged,
> and the skills here depend on features that do not exist upstream. **Do not pull
> the upstream container image or clone the upstream repository to use with this
> one.** Build from this repository.

## Branches

| Branch | Use it for |
|:---:|:---|
| [`main`](https://github.com/dpstorey/EM-MCP/tree/main) | The full tool set, including the attackers-view tools. |
| [`small-model`](https://github.com/dpstorey/EM-MCP/tree/small-model) | A lighter build for small local models, where shorter tool schemas and fewer registered tools work more reliably. Same server and policy-creation tools, without the attackers-view tools. |

Both branches run the same CI (pytest on Python 3.12 and 3.13).

## EM-specific features

- **Site routing:** site-scoped tools accept `site_uuid` / `site_name` for EM relay;
  writes require exactly one explicit site.
- **Machine ID caching:** site names resolve to machine ids automatically and are cached.
- **EM root queries:** `list_paired_icps` queries EM directly.
- **Subnet queries:** assets can be queried by subnet, for example `10.253.10.128/25`.
- **Findings:** vulnerability and policy findings can be queried.
- **Policy creation:** narrow `create_*_policy` tools, one per policy type, so small models see short schemas.
- **Short tool descriptions** for faster tool loading.

## Quick start

```bash
docker compose up -d --build --force-recreate tenable-ot
docker compose ps tenable-ot
docker compose logs --tail=100 tenable-ot
```

Then follow the setup steps in [`tenable-ot-mcp/README.md`](tenable-ot-mcp/README.md).
Suggested agent prompts are in `prompt/`; some smaller MoE models need more reinforcement.

## More

- **Tool list:** [`tot-mcp-tool-list.md`](tot-mcp-tool-list.md) and [`tenable-ot-mcp/docs/TOOL_CATALOG.md`](tenable-ot-mcp/docs/TOOL_CATALOG.md).
- **Example session:** [`EXAMPLE_SESSION.md`](EXAMPLE_SESSION.md), a transcript against demonstration data with a locally run LLM (HCompany Holo-35B-A3B on two Nvidia A6000s).
- **Skills:** task workflows in [`skills/`](skills/). The IEC 62443 zones-and-conduits skill is also published at [T1OTE_IEC62443](https://github.com/dpstorey/T1OTE_IEC62443).
- **Changes:** [`tenable-ot-mcp/CHANGELOG.md`](tenable-ot-mcp/CHANGELOG.md).
- **Security and contributing:** [`SECURITY.md`](tenable-ot-mcp/SECURITY.md), [`CONTRIBUTING.md`](tenable-ot-mcp/CONTRIBUTING.md).

## License

Apache 2.0. See [`LICENSE`](LICENSE) and [`tenable-ot-mcp/NOTICE`](tenable-ot-mcp/NOTICE).
Independent project, not affiliated with, endorsed by, or sponsored by Tenable, Inc.
