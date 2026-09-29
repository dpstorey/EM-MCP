# Local Model Hardening — Qwen3.8 (27B / Flash-Next) and Mistral Small, via LibreChat

This library was written and tested against self-hosted models, not frontier
hosted models (Claude, GPT, Gemini). Adapted from the hexa library's own
`local-model-hardening.md` pattern, using failures actually observed running
these three T1OTE skills against Qwen-3.8-27B, Qwen3.8-Flash-Next, and
Mistral Small — not a generic local-model checklist.

Two things are specific to this stack and worth knowing before you rely on
the output:

- **At least one of these models (Mistral) shows no visible reasoning/
  chain-of-thought before its answer** — straight from tool result to final
  output, with no visible self-check step. Both Qwen models do show a
  visible `<details><summary>Thinking` block and visibly self-correct
  within it. A MANDATORY rule stated once in a skill body is *recited* by
  a model without visible reasoning, not necessarily *performed* — treat
  the rest of this file as compensating for that difference in kind, not
  degree.
- **A rule can be correct, present, and still not applied.** We watched a
  model state "Check every row's S column for fatality-level safety risks"
  as narration *after* already emitting a table that failed exactly that
  check, on the same asset, in the same reply. More or stronger wording in
  the rule itself did not fix this — it needed the check made structurally
  unavoidable (see §1) rather than more emphatic.

## 1. Make every MANDATORY check load-bearing, not decorative

Before rendering any table, profile, or diagram that a raise-fatality-flag
or attackers-view-diagram MANDATORY check applies to:

- List, for your own working, every asset's S grade and whether it
  triggers fatality — one line per asset, before writing the table.
- If a value in the output can't be traced to a specific field on a
  specific tool response, it is `-` (per the RAISE rules) or "Data Not
  Available" — never invented, and never silently dropped.
- The same check applies twice when both a table and a diagram are
  produced from the same data (see attackers-view-diagram) — do the trace
  once, then apply it consistently to both outputs, rather than
  re-deriving it twice and risking a mismatch between them.

## 2. Require a visible tool-call plan before executing more than one call

Before making a sequence of tool calls — and always before any write tool
(`submit_report_job`, `purge_reports`, `create_activity_exclusion`) —
state in a short numbered list which calls you intend to make and why.
This is what catches, before it happens rather than after: scope creep
from a site-selection instruction into an unrequested report or attackers
view; a jump straight to output generation before the data is actually in
hand.

**Never resubmit an identical tool call after it fails validation.** A
repeated identical error is a stop signal, not a retry signal — fix the
specific parameter or report the error and stop. We watched a model
resubmit the same malformed `submit_report_job` call nine times in a row
against the same "asset_id is required" error, from a single scope-setting
instruction that never asked for a report at all.

## 3. Known syntax failure modes — fix these in the skill, not the model

Validated against this stack's actual output, not hypothetical:

- Dropping the `:---:` alignment markers on a markdown table's separator
  row (falling back to plain `---`) has been observed to cause a silent
  cell-count mismatch — one more separator cell than header cell — that
  breaks table rendering. Tables that kept the alignment markers counted
  correctly; the ones that dropped them didn't. Keep the markers.
- An unrequested `%%{init: ...}%%` Mermaid theme/color override, and a
  `class` statement referencing an undeclared node ID, can each silently
  blank out or wash out a rendered diagram. Neither is a "try harder"
  problem — they're syntax the skill should simply forbid, which is why
  both are called out explicitly in attackers-view-diagram.

Treat any of the three above as a skill-content bug to fix, not a
model-capability gap to work around by asking more forcefully.

## 4. Consider splitting data-gathering from final rendering

For a skill producing a large table plus a diagram from a multi-call
sequence (attackers-view-diagram in particular): if a skill's output
keeps showing untraceable or dropped values, try asking for the retrieved
data as a plain table first, confirm it against the raw tool results, then
ask for the diagram/final formatting as a second step. This costs an extra
turn — don't default to it — but it isolates whether a fidelity problem is
happening during retrieval or during final rendering.

## 5. If something drifts

A missed MANDATORY check, an invented value, or a malformed table/diagram
is a rule-adherence or syntax-validation failure, not a "the model needs a
bigger prompt" problem. Add scaffolding from §1–2 above, or fix the
specific syntax rule per §3, before making the skill's instructions longer
or more repetitive — repetition alone did not fix the fatality-flag miss
this file describes; a structural trace requirement is what's being tried
instead.
