# RAISE table helper: setup (v1.4.1)

The primary agent builds the RAISE Asset Summary table by running one
`run_tools_with_bash` call. No subagent is needed. The assets are fetched
inside the sandbox by the `query_assets` bash function, so they never pass
through the model.

## File (upload to the agent's Code Environment)

- `raise_table.py`: one file. It builds the table (RAISE fields, fatality
  rule, trimming) and, with `--bash-init`, prints the small bash function that
  pages through `query_assets`.

The last line of the output reads `raise_table v1.4.1`. If a transcript shows
another version, the Code Environment holds a stale copy: delete it and upload
again. `raise_table.sh` from v1.3.0 is obsolete and can be deleted.

## LibreChat requirements

1. `endpoints.agents.capabilities` in `librechat.yaml` includes
   `programmatic_tools` (and the defaults), then restart the `api` container.
2. On the agent: Run Code enabled, and `query_assets` marked Programmatic.
   The tool `run_tools_with_bash` should then appear in the tool list.
3. The sandbox's configured timeout cap is 15 seconds; one 500-asset page of
   `query_assets` takes about a second.
4. `.py` uploads are allowed by default, so no `fileConfig` change is needed.

## The call (as the t1ote-raise-fatality-flag skill specifies)

- `code`: `eval "$(python3 /mnt/data/raise_table.py --bash-init)"; raise_table "London" "10.253.0.0/20"`
- `tool_manifest`: `["query_assets_mcp_tenable-ot-em"]` (exact registered name)

## Troubleshooting

If `python3: can't open file '/mnt/data/raise_table.py'` appears, the
code-interpreter stack is not mounting agent files into programmatic runs.
Rebuild and restart the code-interpreter services (api, service-worker,
sandbox-runner), then delete and re-upload the file on the agent. Confirm with
a `run_tools_with_bash` call of `ls -la /mnt/data` and an empty `tool_manifest`.

## Customising

`RAISE_FIELDS`, `FATAL_FIELD`, `FATAL_VALUES`, `FLAG_PREFIX` and `DESC_MAX`
are constants at the top of `raise_table.py`. Nothing RAISE-specific lives in
the MCP server.
