# UC-01: Detection Performance Analytics — Example

A working example of generating prioritized portfolio-level narratives from deterministic per-rule metrics. The most-shipped use case in any AI-for-DE program.

## What This Example Demonstrates

- **Batched processing** — analyze 50 rules per LLM call to amortize fixed overhead
- **Prompt caching** — system prompt + portfolio context are reused across batches; only per-rule metrics vary
- **Cite-and-verify** — every prioritized recommendation references specific input metrics
- **Two-pass pattern** — first pass extracts per-rule observations; second pass produces portfolio-level priorities

## Use Case Reference

[UC-01: Detection Performance Analytics](../../use-cases/alert-analysis/01-detection-performance-analytics.md)

## Engineering Patterns Used

- [x] Cite-and-verify
- [x] Two-pass extract → reason
- [x] Schema-constrained outputs
- [x] Prompt caching (large stable system prompt)
- [ ] Confidence-banded routing (not applicable; output informs humans)
- [ ] Tool-use (no tools)

## Model Choice

Default: **Claude Sonnet 4.6**.

Why: Synthesis over structured numerical data with narrative output; Sonnet handles this reliably. Haiku occasionally misses cross-rule patterns; Opus is overkill for the per-rule extraction step. Two-pass design uses Sonnet for both passes for consistency.

## Cost Estimate

Per weekly portfolio scan of 1,500 rules:
- Batches: 30 (50 rules per batch)
- Per-batch input (cached system + portfolio context): ~50K cached
- Per-batch input (rule metrics): ~10K fresh
- Per-batch output: ~2K
- Per-batch cost: ~$0.18
- Total per weekly scan: ~$5.50
- Monthly: ~$25–60 depending on scan frequency

Plus ~$5 for the second-pass portfolio synthesis (consumes per-batch outputs as input).

## How to Run

1. Pull deterministic metrics for each rule (volume, entity cardinality, top-N concentration, trend, periodicity, co-occurrence, silence flag) from your SIEM
2. Group rules into batches of 50; render `prompt-pass1.md` per batch
3. Collect per-rule observations from pass 1
4. Feed the observation set into `prompt-pass2.md` for portfolio synthesis
5. Score against `golden-set.yaml` per `eval-runner.md`
6. Compare to gates: `schema_valid >= 99%`, `metric_grounding >= 95%`, `hallucinated_rule_id = 0`

## Known Limitations

- Metric computation is **out of scope** — this example assumes the SIEM has produced the metric payload; the AI does not query the SIEM directly
- No auto-tuning loop — recommendations are presented to a DE for triage; coupling to UC-03 (auto-tuning) is a separate workflow
- Portfolio synthesis (pass 2) assumes ≤300 rule observations fit in context; larger portfolios need hierarchical batching

## What This Example Does Not Cover

- Producing the deterministic metrics in the first place (a SIEM query problem; see [UC-01](../../use-cases/alert-analysis/01-detection-performance-analytics.md) Prerequisites)
- Routing recommendations into a ticketing system
- Tracking recommendation acceptance rate (a feedback loop a production system would close)

## Note on Two-Pass Design

The two-pass pattern (extract observations per batch → synthesize across batches) is here for two reasons:

1. **Token economics**: a single 1,500-rule prompt would use ~150K tokens of input; batching into 50-rule chunks with prompt caching cuts cost ~5×
2. **Anchoring control**: pass 1 produces structured observations independent of rule order; pass 2 reasons over the observation set without being biased by the first batch's framing
