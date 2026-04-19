# Cost Models

Token economics and ROI estimation for the use cases in this repository. All numbers below are **planning estimates**, not commitments. Real costs swing 2–5× based on prompt design, batching, and the chattiness of your environment. Validate against the [validation harness](../concepts/validation-harness.md) on representative data before signing a budget.

---

## Pricing Reference (as of 2026-04)

Public list pricing for the most common production models. Vendor and reseller discounts vary; enterprise customers typically realize 20–40% off list. Cached input pricing (where supported) is materially lower for repeated system prompts.

| Model | Input ($/MTok) | Output ($/MTok) | Cached Input ($/MTok) | Notes |
|---|---|---|---|---|
| Claude Opus 4.7 | $15.00 | $75.00 | $1.50 | Frontier reasoning; reserve for hard triage and rule generation |
| Claude Sonnet 4.6 | $3.00 | $15.00 | $0.30 | Default workhorse for most use cases |
| Claude Haiku 4.5 | $1.00 | $5.00 | $0.10 | Triage classification, extraction, routing |
| GPT-4.x equivalent tier | $5–10 | $15–30 | varies | Comparable; check current vendor pricing |
| Local (Llama 3.1 70B / Qwen 2.5) | infrastructure-only | — | — | $0.50–$2.00/MTok effective on dedicated GPUs at sustained load |

**Prompt caching is the single largest cost lever**. For UC-01 batch analysis, UC-15 guide generation, UC-19 rule generation — anywhere the system prompt is large and stable — caching cuts input cost ~10×.

---

## Cost Drivers

Five variables dominate per-use-case spend:

1. **Volume**: alerts/day, rules/portfolio, reports/quarter
2. **Token width**: how much context per invocation (alert payload size, rule body length, batch size)
3. **Output length**: a one-line verdict vs. a paragraph narrative
4. **Model tier**: Haiku → Sonnet → Opus
5. **Cache hit rate**: stable system prompts at >70% hit rate change the math

Always compute cost as: `(input_tokens × in_price + output_tokens × out_price) × invocations_per_period`. Apply cache discount to the cached portion of input.

---

## Per-Use-Case Cost Estimates

Estimates use a **medium SOC** baseline (1,500 rules, 10,000 alerts/day, 50 active analysts/DEs). Scale linearly for your size. All numbers are USD/month at default models with reasonable caching.

### Alert Analysis

| UC | Model | Invocations/Month | Tokens In/Invocation | Tokens Out/Invocation | Est. Cost/Month | Notes |
|---|---|---|---|---|---|---|
| UC-01 Detection Performance Analytics | Sonnet 4.6 | 4 batches × 30 (weekly portfolio scan) = 120 | 60K (cached: 50K, fresh: 10K) | 2K | $30–60 | Cache the system prompt and rule-metadata block; vary the metric payload per call |
| UC-02 Entity Cardinality Noise | Sonnet 4.6 | 200 (per-rule deep-dives) | 8K | 1.5K | $15–30 | Triggered on demand from UC-01 priorities |
| UC-03 Automated Rule Tuning | Sonnet 4.6 | 100 (per tuning candidate) | 12K | 2K | $15–25 | Output includes proposed exclusion + safety analysis |
| UC-04 Detection Drift Monitoring | Sonnet 4.6 | 60 (drift events/month) | 15K | 1K | $10–20 | Largely deterministic; LLM only on diagnostic step |
| UC-05 Temporal Pattern Detection | Sonnet 4.6 | 30 | 20K | 1.5K | $10–15 | Most work happens in statsmodels/scipy upstream |

**Subtotal: $80–150/month for the entire Alert Analysis block.**

### Posture Assessment

| UC | Model | Invocations/Month | Tokens In/Invocation | Tokens Out/Invocation | Est. Cost/Month | Notes |
|---|---|---|---|---|---|---|
| UC-06 ATT&CK Posture Scoring (narrative pass) | Sonnet 4.6 | 600 techniques × 1 (monthly) | 12K (cached: 8K) | 1.5K | $30–50 | Scoring math is deterministic; LLM only narrates |
| UC-07 Threat-Informed Gap Prioritization | Sonnet 4.6 | 8 CTI reports/month | 25K | 4K | $5–10 | Cost dominated by report length |
| UC-08 Kill Chain Completeness | Sonnet 4.6 | 4 (quarterly per actor profile, 3 active actors) | 20K | 3K | $2–5 | Low frequency; high value |
| UC-09 Cross-Domain Coverage | Sonnet 4.6 | 4 (quarterly) | 30K | 4K | $3–7 | Long input; mostly cached |
| UC-10 Executive Posture Reporting | Sonnet 4.6 | 1 (monthly) | 30K | 6K | $1–3 | One-shot per cycle; low cost |

**Subtotal: $40–75/month for the entire Posture block.**

### AI-Assisted Triage

This is where costs scale with alert volume and where most budget surprises live.

| UC | Model | Invocations/Month | Tokens In/Invocation | Tokens Out/Invocation | Est. Cost/Month | Notes |
|---|---|---|---|---|---|---|
| UC-11 LLM Triage Verdicts | Haiku 4.5 (triage) → Sonnet (escalation) | 300K alerts × 80% Haiku, 20% Sonnet | 4K (cached: 3K) | 1K | $250–500 | Tiered model use is critical; otherwise cost 3–5× |
| UC-12 Alert Cluster Narrative | Sonnet 4.6 | 2K clusters/month | 15K (cached: 10K) | 2K | $80–150 | Cluster size dominates token width |
| UC-13 NL Alert Query | Haiku 4.5 (intent + query gen) | 5K queries/month | 6K | 1K | $30–60 | Add SIEM query execution cost separately |
| UC-14 Agentic Investigation | Sonnet 4.6 + Opus on hard cases | 1.5K investigations × 15 tool calls avg | 8K per call (cached system: 6K) | 1.5K per call | $1,500–3,500 | Highest cost; biggest variance; cap tool calls per investigation |

**Subtotal: $1,860–4,210/month for the AI-Assisted Triage block.** UC-14 dominates; if not yet deployed, subtotal is ~$360–710.

### Rule Content Engineering

| UC | Model | Invocations/Month | Tokens In/Invocation | Tokens Out/Invocation | Est. Cost/Month | Notes |
|---|---|---|---|---|---|---|
| UC-15 LLM Investigation Guide Generation | Sonnet 4.6 | 200 (new + modified rules) | 8K (cached: 5K) | 3K | $30–60 | Bulk first-time backfill is one-time large cost (~$500 for 1,500 rules) |
| UC-16 Observable Artifact Extraction | Haiku 4.5 | 200 | 4K | 1K | $5–10 | Lightweight |
| UC-17 Rule Comparison & Gap Analysis | Sonnet 4.6 | 50 paired comparisons | 20K | 3K | $15–30 | Cost scales with rule pairs analyzed |
| UC-18 Rule Quality Assessment | Sonnet 4.6 | 200 | 10K | 2K | $20–40 | Run on PR + nightly drift |
| UC-19 Detection Rule Generation | Opus 4.7 (hard) + Sonnet (drafting) | 30 generation attempts | 25K | 5K | $40–80 | Quality > quantity; budget for regeneration loops |
| UC-23 Synthetic Detection Test Data | Sonnet 4.6 | 100 (per rule under test) | 10K | 4K | $25–50 | Diverse procedure variants per rule |

**Subtotal: $135–270/month, plus ~$500 one-time backfill for UC-15.**

### Strategic

| UC | Model | Invocations/Month | Tokens In/Invocation | Tokens Out/Invocation | Est. Cost/Month | Notes |
|---|---|---|---|---|---|---|
| UC-20 Analyst Workflow Optimization | Sonnet 4.6 | 4 (weekly snapshot) | 40K | 5K | $5–10 | Batch processing |
| UC-21 CTI Synthesis | Sonnet 4.6 | 8 reports/month | 25K | 5K | $5–15 | Scales with TI feed volume |
| UC-22 Detection Program Health Reporting | Sonnet 4.6 | 1 monthly + 1 quarterly | 50K | 10K | $5–10 | Largely synthesis of metrics produced elsewhere |

**Subtotal: $15–35/month.**

---

## Total Cost Envelope (Medium SOC)

| Block | Lower bound | Upper bound | Notes |
|---|---|---|---|
| Alert Analysis | $80 | $150 | Stable, predictable |
| Posture Assessment | $40 | $75 | Low frequency |
| AI-Assisted Triage (without UC-14) | $360 | $710 | Scales with alert volume |
| AI-Assisted Triage (with UC-14) | $1,860 | $4,210 | UC-14 dominates |
| Rule Content Engineering | $135 | $270 | + ~$500 one-time UC-15 backfill |
| Strategic | $15 | $35 | Negligible |
| **Total without UC-14** | **$630** | **$1,240** | Most teams operate here for 18+ months |
| **Total with UC-14** | **$2,130** | **$4,740** | After UC-11 maturity gate |

For a small SOC, divide by 3–5. For a large SOC, multiply by 4–8 — at very large scale, UC-11/UC-14 alone can exceed $30K/month and warrant on-prem inference (see below).

---

## ROI Framing

A reasonable analyst FTE in North America loaded cost is ~$150K–$200K/year, ~$12K–$17K/month. **One FTE equivalent of saved time pays for the entire AI program at a medium SOC, even at the upper bound.** ROI flips negative if:

- Time savings are not measured (Pillar 5 failure)
- AI-generated false negatives create incidents (cost: incident-handling + reputational)
- Engineering build cost exceeds run cost by an unrecovered margin

**Plan for 18-month payback** on the engineering investment. Use cases that don't pencil out at that horizon should be deprioritized regardless of how interesting they are.

---

## Cost Levers

When the bill comes in higher than modelled, pull these in order:

1. **Cache the system prompt** (10× input cost reduction on the cached portion). This alone is the difference between affordable and not affordable for UC-01, UC-15, UC-19, UC-22.
2. **Tier the model**: Haiku for classification/extraction, Sonnet for reasoning, Opus only for hard cases UC-11/UC-19. UC-11 with all-Sonnet is ~3× the bill of tiered.
3. **Trim context width**: send only the fields the use case actually reads. Most alert payloads carry 10–20 KB of fields the LLM doesn't need.
4. **Batch where latency-tolerant**: UC-01, UC-06, UC-22 batch well. UC-11, UC-13 do not.
5. **Async + offline**: Posture scoring and program reporting do not need real-time inference. Run on cheaper compute / nightly windows.
6. **Cap agentic loops**: UC-14 should have hard tool-call ceilings (e.g., 25 tool calls). Without caps, runaway loops are the #1 cost surprise.
7. **Sample, don't enumerate**: UC-18 quality assessment over 4,000 rules every night is expensive. Quality assessment on changed rules + a 5% rolling sample is ~95% as useful at <10% the cost.

---

## When to Consider On-Prem / Open-Weight Models

External-API costs become structural at:

- UC-11 verdicts on >5,000 alerts/day sustained
- UC-14 with >100 investigations/day sustained
- Heavily regulated environments where data egress to a hosted API is itself the blocker (see [privacy-and-data-handling.md](privacy-and-data-handling.md))

Approximate breakeven: ~$8K–$15K/month of API spend equates to operating a single 4×H100 node hosting a 70B-parameter model at moderate utilization. Below that, hosted APIs are cheaper. Above it, the math depends on whether you have GPU-ops capability in-house.

Open-weight models (Llama, Qwen, Mistral) at 70B+ parameters are sufficient for most use cases in this repo *except* UC-19 (rule generation) and UC-14 (complex agentic reasoning), where frontier model quality still matters. A hybrid posture — open-weight for high-volume triage classification, hosted frontier for hard cases — is the most cost-efficient configuration above the breakeven threshold.

---

## Budget Template

A starter template you can hand to finance:

```
AI-for-Detection program — annual budget request

Inference (hosted API, list pricing, no negotiated discount):
  Alert Analysis block               $1,500
  Posture Assessment block             $750
  Triage block (without UC-14)       $7,000
  Rule Content block                 $2,500 + $500 one-time
  Strategic block                      $300
  Subtotal                          $12,050 + $500
  Add 30% headroom for spikes        $3,615
  TOTAL inference                   $16,165

Engineering (build):
  Year 1: 1.0 FTE detection-eng-AI specialist  $200,000
  Year 2: 0.5 FTE sustained                     $100,000

Validation harness + governance:
  Tooling + golden-set maintenance              $25,000

Total Year 1                                   $241,165
Expected savings (1.0 analyst FTE equivalent)  $180,000
Net Year 1                                     -$61,165
Net Year 2                                     +$80,000  (positive once build cost amortizes)
```

If the math doesn't work in your environment, the right move is to scope down, not to skip the financial modelling. A program that delivers 60% of the catalog at break-even is a better outcome than 100% of the catalog at a loss.
