# UC-11: LLM Triage Verdicts — Example

A working example of producing structured triage verdicts on enriched alerts. The highest-stakes use case in this repository — calibration matters, hallucination matters, adversarial input matters.

## What This Example Demonstrates

- **Schema-constrained verdicts** with enum-bounded confidence bands → drives confidence-banded routing
- **Cite-and-verify with explicit grounding** — every verdict requires citation chain back to enrichment data
- **Untrusted-content delimiting** — alert payload is wrapped to defend against prompt injection
- **Tiered model use** — Haiku-class for the routing pass, Sonnet for borderline cases (cost savings ~3×)
- **Calibration measurement** — eval runner computes Expected Calibration Error per confidence band
- **Adversarial test cases** — golden set includes prompt-injection attempts the model must refuse

## Use Case Reference

[UC-11: LLM Triage Verdicts](../../use-cases/ai-assisted-triage/11-llm-triage-verdicts.md)

## Engineering Patterns Used

- [x] Cite-and-verify
- [x] Schema-constrained outputs
- [x] Confidence-banded routing
- [x] Prompt caching
- [x] Untrusted-content delimiting
- [x] Two-pass extract → reason (for borderline cases)
- [ ] Tool-use with allow-list (deferred to UC-14)

## Model Choice

**Two-tier**:
- **Pass 1 (routing)**: Claude Haiku 4.5 — fast, cheap classification with confidence band
- **Pass 2 (escalation)**: Claude Sonnet 4.6 — invoked only when Pass 1 returns confidence band of `medium` or below

This pattern saves ~3× cost vs. all-Sonnet without sacrificing quality on the cases that matter (high-confidence verdicts route directly without escalation; ambiguous cases get the better model).

## Cost Estimate

Per 10,000 alerts/month:
- Pass 1: 10,000 × Haiku at ~4K in / 1K out = ~$90
- Pass 2 (~20% of alerts escalated): 2,000 × Sonnet at ~6K in / 2K out = ~$135
- **Total: ~$225/month**

All-Sonnet alternative: ~$600/month for the same volume.

Scale linearly with volume. At 50K alerts/month tiered cost is ~$1,100; that's the threshold to evaluate on-prem inference (see [cost-models.md](../../docs/cost-models.md)).

## How to Run

1. For each enriched alert (after deterministic SOAR enrichment), render `prompt-pass1-routing.md`
2. Call Haiku 4.5 with structured output enforced
3. If the verdict's `confidence_band` is `high`, route per the verdict
4. If `confidence_band` is `medium` or `low`, render `prompt-pass2-reasoning.md` and call Sonnet 4.6
5. Score against `golden-set.yaml` per `eval-runner.md`
6. Compare against gates: `accuracy >= 85%`, `false_negative_rate <= 2%`, `ECE <= 0.10`, `injection_resistance = 100%`

## Known Limitations

- This example produces verdicts; the **routing decision** (auto-close, queue for analyst, escalate) is downstream policy
- The pass-2 escalation prompt does not invoke tools — that's UC-14's territory
- Adversarial test coverage is starter-level; production deployments need ongoing red-team testing
- Calibration measurement requires ≥100 examples per confidence band — the starter golden set has 8; production needs 100+

## What This Example Does Not Cover

- Enrichment pipeline (deterministic SOAR work — Pillar 4 prerequisite)
- Confidence-band → action policy (your governance decision)
- Override capture and feedback ingest (separate workflow; see [adversarial-ai-considerations.md](../../concepts/adversarial-ai-considerations.md) on feedback poisoning)
- Per-rule-family verdict tuning

## Critical Production Considerations

This use case has the highest blast radius of the three exemplified examples. Before deploying:

1. **Run the [validation harness](../../concepts/validation-harness.md) regression gates** — non-negotiable
2. **Implement the controls from [adversarial-ai-considerations.md](../../concepts/adversarial-ai-considerations.md)** Attacks 1, 3, 4
3. **Apply redaction per [privacy-and-data-handling.md](../../docs/privacy-and-data-handling.md)** — alert payloads are the most PII-dense input in the catalog
4. **Document the use case per [governance-mapping.md](../../docs/governance-mapping.md)**
5. **Stay in shadow mode for ≥60 days** before any auto-close

This is the use case where shortcuts break things in production.
