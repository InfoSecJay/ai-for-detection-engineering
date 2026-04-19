# Validation Harness

A specification for how to evaluate, regression-test, and continuously monitor every AI use case in this repository. Without this layer, every claim about AI quality is anecdote. With it, you have evidence — and the ability to detect degradation before users do.

This is the framework that turns the per-use-case "promotion criteria" in the [deployment roadmap](../docs/deployment-roadmap.md) from aspiration into measurement.

---

## What a Validation Harness Is

Three components, deployed together:

1. **A golden set** — versioned, hand-curated input/expected-output pairs that represent the cases the use case must handle correctly
2. **An eval runner** — code that feeds the golden set through the use case's prompt + model + post-processing, scores outputs against expectations, and produces metrics
3. **A regression gate** — a quality threshold below which the use case cannot be promoted, deployed, or updated

Without all three, you don't have a harness — you have a wish.

---

## Golden Set Construction

A golden set is the most valuable artifact in your AI-for-DE program. Treat it accordingly.

### Sourcing

| Use Case Family | Where Golden Inputs Come From | Where Golden Outputs Come From |
|---|---|---|
| Alert Analysis (UC-01–05) | Real historical metric snapshots from your SIEM | Senior DE writes expected narrative or fact list |
| Posture Assessment (UC-06–10) | Real rule portfolio + scoring inputs | Senior DE produces expected per-technique narrative + priority |
| Triage (UC-11–14) | Anonymized historical alerts with known TP/FP outcome | The actual analyst verdict (or independent re-grading) |
| Rule Content (UC-15–19, 23) | Real rule files + sample telemetry | Senior DE writes expected guide / extraction / quality finding / generated rule |
| Strategic (UC-20–22) | Real triage telemetry / CTI reports | Senior DE produces expected synthesis |

**Golden inputs must come from your environment.** A golden set built on synthetic or generic alerts won't catch your real failure modes.

### Size

Per use case:

| Use Case Type | Minimum Golden Set Size | Why |
|---|---|---|
| Narrow extraction (UC-16) | 30 examples | Coverage of major query-syntax variants |
| Narrative generation (UC-01, UC-12, UC-22) | 50 examples | Diverse rule and entity contexts |
| Triage classification (UC-11) | 100–200 examples | Stratified by TP/FP, severity, rule family — needed for calibration metrics |
| Agentic (UC-14) | 30 historical investigations with full evidence trails | High effort to curate; lower count justified by depth |
| Quality assessment (UC-18) | 50 known-good + 50 known-bad rules | Need both classes |
| Rule generation (UC-19) | 30 (TTP description, expected rule pattern) pairs | High curation cost |

These are floors, not targets. Bigger is better up to the point where curation cost exceeds value.

### Structure

Every golden example is a record:

```yaml
id: uc11-golden-042
use_case: UC-11
created: 2026-04-15
created_by: senior_de_alice
last_reviewed: 2026-04-15
input:
  alert_payload: { ... }   # full input as it would arrive
  enrichment: { ... }
expected:
  verdict: true_positive
  confidence_band: high
  reasoning_must_cite:
    - "process.command_line containing -enc"
    - "user.is_privileged: true"
  reasoning_must_not_invent:
    - any field not in input
metadata:
  difficulty: medium
  rule_family: powershell-execution
  notes: "Borderline — analyst overruled on first pass; second analyst confirmed TP"
```

The `expected` block is the contract. The `reasoning_must_cite` and `reasoning_must_not_invent` lists encode the cite-and-verify pattern from [where-ai-fails.md](where-ai-fails.md).

### Maintenance

- **Versioned in git** alongside the use case definition
- **Reviewed quarterly** — examples that no longer reflect production reality are retired, not modified in place
- **Independent of production feedback** — analyst overrides do not silently update the golden set; updates are explicit code changes with review
- **Owner per use case** — usually the senior DE who built the use case; this is real ongoing work, not a one-time setup

---

## Metrics by Use Case Type

Different use cases need different scoring. One metric does not fit all.

### Classification (UC-11 verdicts, UC-16 observable type, UC-18 quality category)

- **Accuracy** overall
- **Precision and recall per class** — for UC-11, false negatives (missed TP) cost more than false positives, weight accordingly
- **Expected Calibration Error (ECE)** — bin predictions by stated confidence, compute |stated confidence − actual accuracy| per bin, weight by bin size; for UC-11 this is critical
- **Brier score** — alternative calibration metric; rewards both accuracy and well-calibrated confidence

### Extraction (UC-16 observables, UC-21 TTPs)

- **Field-level F1** — for each extracted field, precision and recall against expected
- **Hallucination rate** — % of extracted items not present in input (must be zero or near-zero)
- **Coverage** — % of expected items the model extracted

### Generation (UC-01 narratives, UC-15 guides, UC-19 rules, UC-22 reports)

These are the hardest to score. Use a combination:

- **Citation faithfulness** — every claim in the output ties to a verifiable input span (deterministic checker; binary pass/fail per claim)
- **Required-element coverage** — does the output mention each item the golden set says it must mention? (deterministic; F1)
- **Forbidden-element avoidance** — does the output avoid items it must not invent? (deterministic; binary)
- **LLM-as-judge for prose quality** — a separate, more capable model scores readability/clarity against a rubric; use sparingly because it's expensive and itself imperfect
- **Human spot-check** — DE reviews ~10% sample monthly; tracks "would I send this?" pass rate

For UC-19 (rule generation):
- **Syntax validity** — does the generated rule parse?
- **Schema validity** — do referenced fields exist in the target data source?
- **Test-data behavior** — does the generated rule fire on synthetic positive cases (UC-23) and not fire on negative cases?

### Agentic (UC-14)

- **Conclusion accuracy** — does the agent's verdict match the historical outcome on the golden investigation?
- **Citation chain completeness** — does the agent's reasoning trace back to specific evidence?
- **Tool-call efficiency** — # of tool calls per investigation; cap and median should be measured
- **Safety violations** — any tool call outside allow-list, any unauthorized scope expansion, any suspected prompt injection followed
- **Cost per investigation** — dollar figure; should track to [cost-models.md](../docs/cost-models.md) projections

### Calibration (cross-cutting)

For any use case that emits a confidence score, plot reliability diagrams quarterly:

- X-axis: stated confidence buckets (e.g., 0–10%, 10–20%, … 90–100%)
- Y-axis: actual accuracy in each bucket
- A perfectly calibrated model lies on the diagonal

Drift away from the diagonal is the most important signal for triage use cases. A use case where "90% confident" verdicts are right only 60% of the time is dangerous regardless of overall accuracy.

---

## Regression Gates

Per use case, define explicit thresholds that must be met to:

- **Promote from pilot to production**: highest bar
- **Deploy a prompt change**: lower than pilot bar but binding
- **Deploy a model change**: same as prompt change
- **Continue running in production**: a continuous floor; falling below triggers rollback

Example gates for UC-11:

| Stage | Metric | Threshold |
|---|---|---|
| Pilot exit | Accuracy on golden set | ≥85% overall |
| Pilot exit | False negative rate (missed TP) | ≤2% |
| Pilot exit | ECE | ≤0.10 |
| Production gate (per change) | Accuracy on golden set | ≥85% |
| Production gate | No new hallucinated entities in any sampled output | 100% pass |
| Continuous floor | Rolling 7-day accuracy on production sample | ≥80% |
| Rollback trigger | Rolling 24-hour false negative rate | >5% |

These numbers are illustrative. Calibrate to your environment's risk tolerance and the use case's blast radius.

---

## Eval Runner Architecture

Conceptually simple. Mechanically the part most teams skip.

```
                   ┌─────────────┐
                   │ Golden Set  │
                   │  (in git)   │
                   └──────┬──────┘
                          │
                          ▼
            ┌──────────────────────────┐
            │     Eval Runner          │
            │  - load golden examples  │
            │  - render prompt         │
            │  - call model            │
            │  - run scorers           │
            │  - emit metrics          │
            └──────────┬───────────────┘
                       │
        ┌──────────────┼──────────────┐
        ▼              ▼              ▼
  ┌──────────┐   ┌──────────┐   ┌──────────┐
  │ Reports  │   │ CI Gate  │   │ Telemetry│
  │ (HTML/MD)│   │ (PR check│   │ (Grafana,│
  │          │   │  pass/   │   │ etc.)    │
  │          │   │  fail)   │   │          │
  └──────────┘   └──────────┘   └──────────┘
```

Run frequencies:

- **On every PR** that touches a use case's prompt, model, or post-processing — block the merge if regression gates fail
- **Nightly** against production model versions — catches vendor-side model changes
- **Weekly** against production input distribution — samples real inputs (with privacy controls per [privacy-and-data-handling.md](../docs/privacy-and-data-handling.md)) to detect input-distribution drift
- **Quarterly** full re-grading — senior DE reviews a stratified sample, refreshes golden set as needed

Open-source frameworks worth evaluating: `promptfoo`, `LangSmith`, `Braintrust`, `OpenAI Evals`, `Inspect AI`. Most teams end up with a thin custom wrapper around one of these — that's fine.

---

## Continuous Production Monitoring

The golden set tells you about known cases. Production telemetry tells you about reality. You need both.

Per use case, instrument:

| Metric | Why | Alert Threshold |
|---|---|---|
| Invocation count per hour | Capacity, anomaly detection | >2× baseline |
| Latency p50 / p95 / p99 | User experience, cost | p95 >2× baseline |
| Token spend per day | Cost control | >1.5× modelled |
| Output schema violation rate | Hallucination, model drift | >1% |
| Confidence distribution | Calibration drift | major shift in distribution shape |
| Tool-call count per invocation (UC-14) | Cost, runaway loops | p95 >2× baseline |
| Analyst override rate (UC-11) | Disagreement signal | >10% week-over-week increase |
| Field-population rate of input | Upstream data drift | drop >5% from baseline |

These belong in your existing monitoring (Grafana, Datadog, Splunk dashboards), not in a separate AI-monitoring product. Treat AI use cases like any other production system.

---

## Connecting Validation Back to the Roadmap

The [deployment roadmap](../docs/deployment-roadmap.md) lists pilot-exit and production-promotion criteria per use case. Those criteria are met by demonstrating performance against the validation harness. Specifically:

| Roadmap Statement | Validation Harness Equivalent |
|---|---|
| "Shadow-mode agreement ≥85%" | Accuracy ≥85% on golden set + production sample |
| "Documented escalation criteria" | Confidence-band thresholds enforced and tested |
| "≥80% accepted by DE" | Acceptance rate tracked per use case; regression gate |
| "Drift caught within 7 days of source change" | Input field-population canary + scheduled eval run |
| "Tool-call cap" (UC-14) | Tool-call count metric with hard ceiling enforced |

The roadmap criteria without a corresponding harness measurement are not actually criteria — they are vibes. Wire the harness up first, then enforce the gates.

---

## What Validation Cannot Do

Honest limits:

- **Cannot certify safety** — passing your golden set means handling cases similar to the golden set; novel adversarial input remains a risk (see [adversarial-ai-considerations.md](adversarial-ai-considerations.md))
- **Cannot replace human review** for high-stakes decisions — the harness justifies *running* a use case, not *trusting it unreviewed*
- **Cannot prove generalization** — the harness samples your environment's distribution; it does not predict behavior on new rule families or data sources you haven't tested
- **Cannot stop vendor model changes from causing regressions** — but it will *detect* them quickly

The harness is a tripwire and a gate. It is not a substitute for the controls in the rest of this repository.

---

## Minimum Viable Implementation

A team starting from zero can have a useful harness in two weeks:

**Week 1**:
- Pick one use case (recommend UC-15 or UC-18 — bounded scope, low blast radius)
- Curate 30 golden examples from your existing rule corpus
- Write a simple eval runner: load examples, call API, run a scorer, print metrics
- Commit it all to the repo

**Week 2**:
- Add a CI workflow that runs the harness on PRs touching the use case
- Add nightly run with a single Slack/Teams alert on regression
- Document the gates

That's the minimum. Expand from there. Most failures in AI-for-DE programs trace back to skipping this step "until the use case is more mature." Build the harness first, then mature the use case against it.

---

## Public Benchmarks (2026)

Benchmark methodology to inform — and benchmark *against*, where applicable — your internal validation harness. None of these replace your environment-specific golden set; they complement it.

| Benchmark | Scope | Source | When to Use |
|---|---|---|---|
| **CTI-REALM** (Microsoft, Mar 2026) | End-to-end AI-driven detection rule generation: read CTI → identify techniques → explore telemetry → iterate KQL → emit Sigma + KQL. 37 reports across Linux/AKS/Azure. | [Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/03/20/cti-realm-a-new-benchmark-for-end-to-end-detection-rule-generation-with-ai-agents/) | Reference methodology for [UC-19 (Detection Rule Generation)](../use-cases/rule-content-engineering/19-detection-rule-generation.md) and [UC-21 (CTI Synthesis)](../use-cases/strategic/21-threat-intelligence-synthesis.md) golden-set design |
| **CyberSOCEval** (arXiv 2509.20166) | Open benchmark for malware analysis and threat-intel reasoning, hyperscaler-practitioner-designed | [arXiv](https://arxiv.org/html/2509.20166v2) | Reference for evaluating LLM capability on security-domain reasoning tasks |
| **AIDR / Information-Dense Reasoning** (arXiv 2512.08169) | SOC alert triage reasoning with auditability and 40.6% latency reduction vs. CoT | [arXiv](https://arxiv.org/html/2512.08169) | Methodology reference for [UC-11 (Triage Verdicts)](../use-cases/ai-assisted-triage/11-llm-triage-verdicts.md) |
| **Decision-Aware Trust Signal Alignment** (arXiv 2601.04486) | Calibration / trust scoring for LLM triage outputs | [arXiv](https://arxiv.org/abs/2601.04486) | Calibration measurement methodology for any verdict-emitting use case |
| **CORTEX** (arXiv 2510.00311) | Multi-agent LLM architecture for high-stakes alert triage | [arXiv](https://arxiv.org/html/2510.00311v1) | Architecture reference for [UC-14 (Agentic Investigation)](../use-cases/ai-assisted-triage/14-agentic-investigation-execution.md) |
| **Simbian AI in the SOC LLM Benchmark** (2026) | Vendor-published comparative benchmark across LLMs on SOC tasks | [Simbian](https://simbian.ai/blog/the-first-ai-soc-llm-benchmark) | Vendor perspective; useful for model-selection conversations |

**How to consume public benchmarks**:

1. **Methodology**: Adopt the eval structure (input format, scoring rubric, calibration metrics) for your internal harness. Don't reinvent.
2. **Floor reference**: A model that fails CTI-REALM dramatically should not be deployed in your UC-19 pipeline regardless of what your internal eval says. Public benchmarks set a floor.
3. **Model selection**: When evaluating a new model for an existing use case, compare its public benchmark scores alongside your internal eval delta. Both signals matter.
4. **Calibration cross-validation**: If your internal eval shows a model passing while a comparable public benchmark shows it failing, investigate. Either your golden set is too easy or there's a calibration issue.

**What public benchmarks cannot do**:

- Reflect your environment's actual rule families, data sources, or attack surface
- Substitute for the per-use-case promotion criteria in [deployment-roadmap.md](../docs/deployment-roadmap.md)
- Validate that the *production system* (prompt + post-processing + adversarial controls) works — they only validate the model's raw capability

The internal harness remains primary. Public benchmarks are evidence of model maturity, not of system maturity.
