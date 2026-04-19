# UC-15: LLM Investigation Guide Generation — Example

A working example of generating structured investigation guides from detection rules. This is the **recommended starting use case** for any team building their first AI-for-DE artifact: bounded scope, low blast radius, immediately useful.

## What This Example Demonstrates

- **Schema-constrained output**: the model produces a fixed JSON structure for downstream consumption (rule PR comment, runbook DB)
- **Cite-and-verify**: every step in the generated guide must reference a specific element of the source rule
- **Field-grounded validation**: post-processing rejects guides that reference fields the source rule doesn't actually use
- **Bulk + incremental modes**: the same prompt works for backfilling 1,500 rules in batch and for generating a guide on every new PR

## Use Case Reference

[UC-15: LLM Investigation Guide Generation](../../use-cases/rule-content-engineering/15-llm-investigation-guide-generation.md)

## Engineering Patterns Used

- [x] Cite-and-verify
- [x] Schema-constrained outputs
- [x] Prompt caching (system prompt is large and stable)
- [ ] Two-pass extract → reason (not needed at this complexity)
- [ ] Confidence-banded routing (not applicable; output is content, not decision)
- [ ] Tool-use with allow-list (no tools)

## Model Choice

Default: **Claude Sonnet 4.6**.

Why: Investigation guide generation requires reasoning about detection logic and producing structured prose. Haiku occasionally misses subtle query nuances; Opus is overkill for a per-rule task with bounded context. Sonnet hits the right quality/cost balance.

## Cost Estimate

Per rule:
- Input tokens (cached system + few-shot): ~5K cached
- Input tokens (rule body): ~3K fresh
- Output tokens: ~3K
- Estimated cost: ~$0.05 per rule

Backfill of 1,500 rules: ~$75 one-time.
Incremental on new/changed rules: ~$30/month at typical change rate.

## How to Run

1. Load `prompt.md` as system + user templates
2. Load `golden-set.yaml` 
3. For each entry, render prompt with rule content, call Claude Sonnet 4.6
4. Parse JSON response, validate against schema
5. Run scorers per `eval-runner.md`
6. Compare against gates: `schema_valid >= 99%`, `field_grounding_pass >= 95%`, `hallucination = 0%`

## Known Limitations

- Does not call out to external context (no tool use)
- Assumes the rule body is in Sigma YAML or Elastic TOML; KQL/SPL works but with reduced quality
- Does not generate platform-specific pivot queries; produces generic investigation steps that the analyst translates to their console
- Does not validate generated steps against actual telemetry availability — that requires data-source health input not modeled here

## What This Example Does Not Cover

The full UC-15 production system would also:
- Cache previous guides and re-generate only on rule change (diff-based incremental)
- Auto-comment generated guide on the rule's PR
- Integrate with a runbook DB for analyst console linking
- Track guide acceptance rate per rule family for prompt iteration

These are engineering integrations, not prompt design. Build them on top.
