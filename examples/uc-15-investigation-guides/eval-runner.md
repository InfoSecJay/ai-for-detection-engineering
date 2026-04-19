# UC-15 Eval Runner

Pseudocode for evaluating UC-15 generated guides against `golden-set.yaml`.

## Per-Example Scoring

```
def score(model_output, expected, input):
    parsed = parse_json(model_output)  # raises if not valid JSON
    if not parsed:
        return record(schema_valid=False, all_else_zero=True)

    # 1. Schema validity
    schema_valid = all(field in parsed for field in expected.schema_required_fields)

    # 2. Citation: every must_cite string appears somewhere in the output prose
    output_prose = concat(parsed.what_this_detects, parsed.first_actions[*].rationale,
                          parsed.true_positive_indicators, parsed.false_positive_indicators)
    citation_hits = sum(1 for c in expected.must_cite if c in output_prose)
    citation_rate = citation_hits / len(expected.must_cite)

    # 3. Hallucination: must_not_invent items must NOT appear anywhere in output
    full_output = json_to_string(parsed)
    hallucinations = sum(1 for h in expected.must_not_invent if h in full_output)

    # 4. Field grounding: every pivot field must appear in the input rule
    input_text = input.rule_content
    pivot_grounding = all(field in input_text for field in parsed.expected_pivot_fields)

    # 5. MITRE grounding (if expected specifies)
    if 'mitre_techniques_must_be_subset_of_input' in expected:
        output_techniques = extract_techniques_from_output(parsed)
        techniques_grounded = output_techniques.issubset(set(expected.mitre_techniques_must_be_subset_of_input))
    else:
        techniques_grounded = True

    # 6. Optional: what_this_detects content check
    what_pass = True
    if 'what_this_detects_must_describe' in expected:
        what_pass = all(t.lower() in parsed.what_this_detects.lower()
                        for t in expected.what_this_detects_must_describe)

    overall_pass = (
        schema_valid and
        citation_rate >= 0.9 and
        hallucinations == 0 and
        pivot_grounding and
        techniques_grounded and
        what_pass
    )

    return record(
        schema_valid=schema_valid,
        citation_rate=citation_rate,
        hallucinations=hallucinations,
        pivot_grounding=pivot_grounding,
        techniques_grounded=techniques_grounded,
        what_pass=what_pass,
        overall_pass=overall_pass,
    )
```

## Aggregate Metrics

```
schema_valid_rate    = mean(schema_valid)
citation_rate_avg    = mean(citation_rate)
hallucination_rate   = #(hallucinations > 0) / total
pivot_grounding_rate = mean(pivot_grounding)
overall_pass_rate    = mean(overall_pass)
```

## Production Gates

| Metric | Pilot Exit | Production | Continuous Floor |
|---|---|---|---|
| `schema_valid_rate` | ≥ 0.99 | 1.00 | ≥ 0.99 |
| `citation_rate_avg` | ≥ 0.85 | ≥ 0.95 | ≥ 0.90 |
| `hallucination_rate` | ≤ 0.05 | 0.00 | 0.00 |
| `pivot_grounding_rate` | ≥ 0.95 | 1.00 | ≥ 0.98 |
| `overall_pass_rate` | ≥ 0.70 | ≥ 0.85 | ≥ 0.80 |

`hallucination_rate = 0` is a hard gate — any guide referencing a field or technique not in the source rule must block deployment.

## Run Cadence

- **Per PR** that touches `prompt.md` or `eval-runner.md`
- **Nightly** against pinned production model version
- **On model version change** — parallel-run new vs. old, gate the upgrade

See [validation-harness.md](../../concepts/validation-harness.md) for the framework around these.

## Failure Triage

When the eval fails:

1. **Schema failures**: usually a model output formatting drift; check for prose around the JSON block
2. **Citation failures**: prompt may need stronger few-shot grounding
3. **Hallucinations**: most common after model version change; add the specific hallucinated item to the prompt's "DO NOT" list
4. **Pivot grounding failures**: prompt is allowing the model to over-extrapolate from rule metadata; tighten the field-derivation instruction
