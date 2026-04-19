# UC-01 Eval Runner

Two-pass scoring for the two-pass prompt design.

## Pass 1 Scoring

```
def score_pass1(model_output, expected, input):
    parsed = parse_json(model_output)
    if not parsed or 'observations' not in parsed:
        return record(schema_valid=False)

    observations = parsed['observations']
    input_rule_ids = {r['rule_id'] for r in input['rules']}
    output_rule_ids = {o['rule_id'] for o in observations}

    # 1. Coverage: every input rule has an observation
    coverage = output_rule_ids == input_rule_ids

    # 2. Schema validity: each observation has required fields
    required = ['rule_id', 'rule_name', 'health_state', 'priority_signals']
    schema_valid = all(all(f in o for f in required) for o in observations)

    # 3. Hallucination: no rule_id outside input
    hallucinated_rules = output_rule_ids - input_rule_ids

    # 4. Per-rule assertions
    per_rule_results = []
    for assertion in expected.per_rule_assertions:
        obs = next((o for o in observations if o['rule_id'] == assertion['rule_id']), None)
        if not obs:
            per_rule_results.append({'rule': assertion['rule_id'], 'pass': False, 'reason': 'observation missing'})
            continue
        checks = []
        if 'must_have_health_state_in' in assertion:
            checks.append(obs['health_state'] in assertion['must_have_health_state_in'])
        if 'must_cite_metrics_containing' in assertion:
            cited_text = json_to_string(obs.get('key_metrics_cited', []))
            checks.append(all(s in cited_text for s in assertion['must_cite_metrics_containing']))
        if 'must_have_priority_signals' in assertion:
            for sig, expected_value in assertion['must_have_priority_signals'].items():
                checks.append(obs['priority_signals'].get(sig) == expected_value)
        per_rule_results.append({'rule': assertion['rule_id'], 'pass': all(checks)})

    # 5. Hallucinated content (must_not_invent)
    full_output = json_to_string(parsed)
    invented_count = sum(1 for s in expected.must_not_invent if s in full_output)

    overall_pass = (
        schema_valid and coverage and
        len(hallucinated_rules) == 0 and
        invented_count == 0 and
        all(r['pass'] for r in per_rule_results)
    )

    return record(
        schema_valid=schema_valid,
        coverage=coverage,
        hallucinated_rules=len(hallucinated_rules),
        per_rule_pass_rate=mean(r['pass'] for r in per_rule_results),
        invented_count=invented_count,
        overall_pass=overall_pass,
    )
```

## Pass 2 Scoring

```
def score_pass2(model_output, expected, input):
    parsed = parse_json(model_output)
    if not parsed:
        return record(schema_valid=False)

    # 1. Schema validity
    required = ['executive_summary', 'top_attention_items', 'portfolio_patterns', 'portfolio_metrics']
    schema_valid = all(f in parsed for f in required)

    input_rule_ids = {o['rule_id'] for o in input['observations']}

    # 2. Hallucinated rule references
    output_rules_referenced = set()
    for item in parsed.get('top_attention_items', []):
        output_rules_referenced.add(item['rule_id'])
    for pattern in parsed.get('portfolio_patterns', []):
        output_rules_referenced.update(pattern.get('affected_rule_ids', []))
    hallucinated_rules = output_rules_referenced - input_rule_ids

    # 3. Top attention items must include expected rules
    attention_rule_ids = {item['rule_id'] for item in parsed.get('top_attention_items', [])}
    must_include = set(expected.top_attention_items_must_include_rule_ids)
    attention_pass = must_include.issubset(attention_rule_ids)

    # 4. Portfolio patterns must identify expected groupings
    pattern_pass = True
    for expected_pattern in expected.portfolio_patterns_must_identify:
        match = any(
            set(expected_pattern['must_reference_rules']).issubset(set(p.get('affected_rule_ids', [])))
            and expected_pattern['pattern_about'] in p['pattern_description'].lower()
            for p in parsed.get('portfolio_patterns', [])
        )
        if not match:
            pattern_pass = False

    # 5. Portfolio metrics arithmetic
    metrics = parsed.get('portfolio_metrics', {})
    arithmetic_pass = (
        metrics.get('healthy_count', 0) +
        metrics.get('noisy_count', 0) +
        metrics.get('degraded_count', 0) +
        metrics.get('abandoned_count', 0) +
        metrics.get('silent_count', 0)
    ) == metrics.get('total_rules_reviewed', 0)

    # 6. Hallucinated content
    full_output = json_to_string(parsed)
    invented_count = sum(1 for s in expected.must_not_invent if s in full_output)

    overall_pass = (
        schema_valid and
        len(hallucinated_rules) == 0 and
        attention_pass and
        pattern_pass and
        arithmetic_pass and
        invented_count == 0
    )

    return record(
        schema_valid=schema_valid,
        hallucinated_rules=len(hallucinated_rules),
        attention_pass=attention_pass,
        pattern_pass=pattern_pass,
        arithmetic_pass=arithmetic_pass,
        invented_count=invented_count,
        overall_pass=overall_pass,
    )
```

## Production Gates

| Metric | Pass 1 Pilot | Pass 1 Production | Pass 2 Pilot | Pass 2 Production |
|---|---|---|---|---|
| `schema_valid_rate` | ≥ 0.99 | 1.00 | ≥ 0.99 | 1.00 |
| `hallucinated_rules_per_run` | 0 | 0 | 0 | 0 |
| `coverage_rate` (pass 1) | 1.00 | 1.00 | n/a | n/a |
| `per_rule_pass_rate` (pass 1) | ≥ 0.85 | ≥ 0.95 | n/a | n/a |
| `attention_pass_rate` (pass 2) | n/a | n/a | ≥ 0.85 | ≥ 0.95 |
| `pattern_pass_rate` (pass 2) | n/a | n/a | ≥ 0.80 | ≥ 0.90 |
| `arithmetic_pass_rate` (pass 2) | n/a | n/a | 1.00 | 1.00 |
| `overall_pass_rate` | ≥ 0.75 | ≥ 0.85 | ≥ 0.70 | ≥ 0.85 |

## Run Cadence

- Pass 1 + Pass 2 evals run together on every PR touching either prompt
- Nightly run with pinned model version
- Weekly run sampling from real production batches (with privacy controls applied)

## Failure Triage

| Failure Mode | Likely Cause | Fix |
|---|---|---|
| Pass 1 hallucinated rule_id | Model conflated similar rule names | Stronger few-shot with rule_id emphasis |
| Pass 1 wrong health_state | Model over-weighting a single signal | Add health_state decision rubric to prompt |
| Pass 2 missing attention item | Pass 1 observation didn't surface the priority signal | Fix pass 1 first |
| Pass 2 missing pattern grouping | Model treated cluster as separate items | Stronger pattern-detection instruction; add few-shot |
| Arithmetic failure | Counting issue | Add explicit "verify counts sum" instruction |
