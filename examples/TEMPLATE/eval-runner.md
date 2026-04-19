# Eval Runner — UC-XX

Pseudocode for evaluating model output against the golden set. Adapt to your eval framework (`promptfoo`, `LangSmith`, `Inspect AI`, custom).

## Loop

```
for example in load_golden_set():
    prompt    = render(prompt_template, example.input)
    response  = call_model(model="claude-sonnet-4-6", system=prompt.system, user=prompt.user)
    parsed    = parse_json(response)
    scores    = score(parsed, example.expected, example.input)
    record(example.id, scores)

report(aggregate_scores)
gate_pass = aggregate_scores.meets(production_gates)
exit(0 if gate_pass else 1)
```

## Scoring Logic

Per example, the runner produces a record like:

```yaml
example_id: ucXX-golden-001
schema_valid:    true | false        # JSON parses, all required fields present
field_match:    true | false         # output.field1 == expected.field1
citation_pass:  N of M               # how many `must_cite` items appear in output.evidence
hallucination:  count                # how many `must_not_invent` items appear in output
overall_pass:   true | false         # schema_valid AND field_match AND citation_pass==M AND hallucination==0
```

## Aggregate Metrics

```
schema_valid_rate    = #(schema_valid=true) / total
field_accuracy       = #(field_match=true) / total
citation_pass_rate   = mean(citation_pass / M) per example
hallucination_rate   = #(hallucination > 0) / total
overall_pass_rate    = #(overall_pass=true) / total
```

## Production Gates (example values — set per use case)

```
schema_valid_rate     >= 0.99
field_accuracy        >= 0.85
citation_pass_rate    >= 0.95
hallucination_rate    <= 0.01
overall_pass_rate     >= 0.80
```

If any gate fails, the eval run fails. Block PR merge or production deployment until fixed.

## Calibration (for use cases emitting confidence)

If the use case emits a confidence score, additionally:

1. Bin examples by stated confidence (e.g., 0–10%, 10–20%, ..., 90–100%)
2. For each bin, compute actual accuracy
3. Compute Expected Calibration Error: `ECE = sum_bins (|stated - actual| * bin_weight)`
4. Plot reliability diagram

Gate: `ECE <= 0.10`.

## Continuous Integration

Wire this runner into:
- **Pre-merge**: every PR touching `prompt.md` or post-processing logic
- **Nightly**: against pinned production model version, alert on regression
- **Weekly**: against a sampled production input distribution (with redaction per privacy doc)
- **On model version changes**: parallel-run new vs. old, gate the upgrade

See [validation-harness.md](../../concepts/validation-harness.md) § Continuous Production Monitoring for production telemetry beyond eval.
