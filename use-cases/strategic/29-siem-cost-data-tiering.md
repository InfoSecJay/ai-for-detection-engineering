# UC-29: SIEM Cost & Data Tiering Optimization

## Category

Strategic

## Summary

Analyzes per-data-source cost vs. detection coverage value, recommends tiering decisions across the modern data-architecture (hot SIEM index ↔ warm searchable lake ↔ cold archive ↔ drop entirely), models the detection-coverage impact of proposed changes, and identifies expensive low-value telemetry that can be filtered, sampled, or rerouted. Pairs deterministic cost data with AI reasoning over coverage trade-offs. Existed as a finance/SIEM-admin concern for years but became operationally tractable in 2026 with the emergence of cheap data-lake tiers (Sentinel data lake, Splunk Federated Search, Databricks Lakewatch, Elastic Frozen tier) and AI-assisted ingest pipelines.

## Problem Statement

SIEM cost is the second-largest line item in most SOC budgets after headcount, and frequently approaches or exceeds it. The 2026 reality:

- Median enterprise SIEM ingest: 500 GB/day to 5+ TB/day
- Pricing: $1,500–$10,000+ per GB/day annually depending on platform and tier
- Total annual SIEM cost: often $1M–$20M+ for mid-to-large enterprises
- Detection coverage value of telemetry: highly uneven — some sources drive 10× their cost in detections; others drive ~zero

Most SIEM cost decisions historically followed one of two failure modes:

1. **Ingest everything, drop nothing** — driven by "we might need it for IR." Outcome: catastrophic cost growth, and the data is only consulted when an incident already happened.
2. **Across-the-board cost cuts** — finance demands 30% reduction, the team picks data sources to drop without coverage analysis. Outcome: silent detection regressions; an incident hits a blind spot months later.

The 2026 architecture enables a third option: tiered ingestion where data lands in different storage layers at different costs with different query speeds. ReliaQuest customer cited 860 GB/day reduction with 43% cost cut. Databricks Lakewatch claims 80% TCO reduction. Sentinel data lake (GA 2026) and Splunk Federated Search make this architecture mainstream.

The deterministic part — *measuring* per-source cost, *measuring* per-source ingest volume, *enumerating* which rules depend on which sources — is finance + SIEM-admin work. The AI-shaped parts are: (a) *reasoning* about which data sources are detection-load-bearing vs. observability-only, (b) *modeling* the detection coverage impact of moving a source to a cheaper tier or filtering it at ingest, (c) *generating* tiering proposals with explicit coverage trade-offs, and (d) *explaining* the decisions in language that detection engineering, finance, and audit can all read.

## Prerequisites (What Your SIEM/SOAR Should Already Handle)

- **Per-source ingest volume metrics.** GB/day per data source, ideally per dataset within source. Standard SIEM telemetry (Splunk's `_internal` index; Elastic monitoring; Sentinel's Usage table; Chronicle ingestion metrics).
- **Per-source cost attribution.** Either explicit (Sentinel commitment tier billing) or modeled (GB/day × $/GB-tier rate). Required for any cost-vs-value analysis.
- **Detection rule dependency map.** Which rules depend on which fields from which sources? Maintained as part of the [UC-27](../rule-content-engineering/27-log-source-onboarding.md) workflow.
- **Tiered storage architecture.** Hot SIEM index, warm searchable lake (Sentinel data lake / Snowflake / Databricks / S3 + Iceberg / Splunk Federated Search target), cold archive (S3 Glacier / Azure Archive). Without tiers, this use case has no levers.
- **Filter/transform capability at ingest.** Cribl Stream, Edge Delta, Axoflow, Sentinel transformation rules, Splunk ingest actions — pipeline-level capability to filter, sample, or reroute data before SIEM ingest.
- **Per-rule operating effectiveness data.** Signal quality scores ([UC-06](../posture-assessment/06-mitre-attack-posture-scoring.md)) and validation status ([UC-26](../rule-content-engineering/26-continuous-detection-validation.md)). A rule that fails validation provides no detection value, so its data dependencies have no detection value either.

## Where AI Adds Value

### 1. Source Value Classification

Each data source is classified by detection load: load-bearing (multiple high-signal rules depend on it), supplementary (some rules use it but alternatives exist), incident-response-only (no rules use it but valuable for IR), observability-only (operational telemetry that snuck into the SIEM with no security purpose). The AI reads the rule dependency map plus rule descriptions plus signal quality scores and produces structured classifications with reasoning.

### 2. Tiering Proposal Generation

For each data source, the AI proposes tier-placement options with coverage impact:

- **Hot tier (current)**: $X/year, all rules retain instant queryability
- **Warm tier (data lake / federated)**: $0.4X/year, rules requiring sub-second query latency move to hot, others can run from warm with seconds-to-minutes latency
- **Cold tier (archive)**: $0.1X/year, no real-time detection but available for IR within hours
- **Drop entirely**: $0/year, lose detection capability X, gain no IR fallback
- **Filter at ingest**: keep field subset, drop noise — saves $Y while retaining detection capability

Each proposal includes specific impact: "Moving Windows DNS logs to warm tier breaks 4 rules that require sub-second triage latency. The other 14 rules using Windows DNS continue to function with 30-second query latency on the warm tier."

### 3. Counterfactual Modeling

Before approving a tiering change, the AI models the counterfactual: "If you had made this change 90 days ago, here's what would have happened." It cross-references the change against the alert history of dependent rules and reports: alerts that would have been delayed (warm-tier latency), alerts that would have been missed (data dropped), incidents whose investigation would have been hampered. Counterfactual modeling against historical data is the strongest evidence for or against a proposed change.

### 4. Cross-Cutting Optimization

Many sources have multiple high-volume datasets. Often the cheapest win is field-level filtering (drop verbose fields like `process.executable.full` if `process.name` and `process.executable.path` are sufficient) rather than tier-shifting the whole source. The AI identifies these field-level opportunities by analyzing which fields are actually referenced by detection rules vs. ingested but unused.

### 5. Cost-Attribution Narrative for Stakeholders

Finance asks "why does the SIEM cost so much?" The AI produces a narrative: "70% of SIEM cost ($4.2M of $6M) goes to four data sources — Windows DNS (44%), Palo Alto traffic logs (18%), AWS CloudTrail data events (5%), and Cisco firewall logs (3%). Of these, Windows DNS provides 14 detection rules with average signal quality 67 (Functional). Palo Alto traffic logs provide 8 detection rules averaging 51 (Degraded). The Palo Alto traffic-log spend is the strongest candidate for tiering — moving to warm tier saves $810K/year with measurable detection impact: 2 rules (TPS-time-sensitive) lose function; 6 rules retain coverage."

## AI Approach

**Hybrid: deterministic cost + dependency analysis + LLM reasoning.**

1. **Cost + volume aggregation (deterministic)** — Per source, per dataset, per field: ingest GB, cost, retention period.

2. **Dependency analysis (deterministic)** — Per source, list of dependent rules; per rule, signal quality + validation status.

3. **Source classification (LLM)** — For each source, produce structured classification (load-bearing / supplementary / IR-only / observability-only) with reasoning.

4. **Tiering proposal generation (LLM)** — Per source, generate 2–4 tier-placement proposals with coverage impact.

5. **Counterfactual modeling (deterministic + LLM)** — For each proposal, replay against historical alert and incident data; LLM narrates the counterfactual.

6. **Field-level optimization (LLM)** — Per source, identify ingested-but-unused fields. Propose filter rules.

7. **Stakeholder narrative (LLM)** — Translate the analysis into language for finance and leadership.

## Data Requirements

### Inputs

| Input | Format | Key Fields Used |
|---|---|---|
| Per-source ingest volume | Time series (GB/day) | source, dataset, GB_per_day, days |
| Per-source cost | Cost calculation or invoice attribution | source → $/year |
| SIEM tier pricing | Pricing reference | hot/warm/cold per-GB rates |
| Detection rule dependency map | YAML/JSON (UC-27 output) | rule_id → [data_sources, fields_used] |
| Signal quality scores | UC-06 output | rule_id → SQS, confidence_tier |
| Validation status | UC-26 output | rule_id → validation_pass, last_validated |
| Historical alert volumes per rule | Time series | rule_id → daily alert counts |
| Historical incident records | IR ticket system | incident_id → data_sources_consulted |
| Tier latency budgets | Per detection use case | rule_id → max_latency_seconds_acceptable |
| Available tiers | Architecture inventory | hot, warm, cold, drop, filter options |

### Outputs

**Per-source tiering analysis:**

```json
{
  "data_source": "windows_dns",
  "current_state": {
    "tier": "hot",
    "ingest_gb_per_day": 412,
    "cost_per_year": 2470000,
    "fields_ingested": 47,
    "fields_referenced_by_rules": 12,
    "fields_unreferenced": 35
  },
  "source_classification": "load_bearing",
  "classification_reasoning": "Windows DNS supports 18 detection rules across DNS tunneling, C2 beaconing, suspicious domain queries, DGA, and beaconing tactics. 14 of 18 rules have Functional or Strong signal quality. The source is genuinely detection-load-bearing.",
  "rule_dependencies": {
    "total_rules": 18,
    "by_quality_tier": {"strong": 6, "functional": 8, "degraded": 3, "abandoned": 1},
    "validation_pass_rate": 0.89
  },
  "tiering_proposals": [
    {
      "proposal_id": "TP-A",
      "name": "Field filter at ingest (recommended)",
      "description": "Drop 35 unreferenced fields at the Cribl ingest layer. Retain the 12 fields actually used by detection rules.",
      "estimated_savings_per_year": 1820000,
      "savings_pct": 73.7,
      "coverage_impact": {
        "rules_affected": 0,
        "rules_broken": 0,
        "alerts_impact": "none — only unused fields removed"
      },
      "risk_level": "LOW",
      "implementation_effort": "1 day Cribl pipeline change + monitoring"
    },
    {
      "proposal_id": "TP-B",
      "name": "Tier 70% to warm (sample-based)",
      "description": "Sample-based ingest: 100% of DNS queries with non-corporate destination domains stay hot; 30% of queries to corporate-domain destinations go to warm tier (data lake).",
      "estimated_savings_per_year": 1450000,
      "savings_pct": 58.7,
      "coverage_impact": {
        "rules_affected": 4,
        "rules_with_degraded_latency": 2,
        "rules_broken": 0,
        "alerts_impact": "DNS-tunneling rule loses 30% of corporate-traffic visibility (acceptable per security architect review); 1 internal-DGA rule may need to query warm tier (5-30 sec latency vs current sub-second)"
      },
      "risk_level": "MEDIUM",
      "implementation_effort": "5 days — Cribl rules + warm-tier query rewrite"
    },
    {
      "proposal_id": "TP-C",
      "name": "Drop entirely",
      "description": "Stop ingesting Windows DNS.",
      "estimated_savings_per_year": 2470000,
      "savings_pct": 100,
      "coverage_impact": {
        "rules_affected": 18,
        "rules_broken": 18,
        "alerts_impact": "Loses all 18 DNS-dependent detections including the DNS tunneling, C2 beaconing, and DGA rules."
      },
      "risk_level": "HIGH",
      "implementation_effort": "trivial",
      "recommended": false,
      "rejection_reasoning": "DNS telemetry is detection-load-bearing. Dropping breaks 18 rules including 6 Strong-tier and 8 Functional-tier rules. Counterfactual: in the past 90 days, 47 alerts on these rules were investigated, 12 of which were true positives. Losing this detection capability has higher cost than the $2.47M saved."
    }
  ],
  "recommended": "TP-A",
  "recommendation_rationale": "Field filtering captures 74% of the savings with zero detection impact and minimal effort. Combined with TP-B's sample-based tiering as a follow-up project (after TP-A operating successfully for 60 days), would achieve $3.27M total savings."
}
```

**Stakeholder summary:**

```
=============================================================================
SIEM COST OPTIMIZATION — Q2 2026 PROPOSAL
Generated: 2026-04-18
=============================================================================

Current annual SIEM cost: $6,200,000
Proposed annual SIEM cost (Phase 1): $4,380,000
Savings (Phase 1): $1,820,000 (29.4%)

Detection capability impact: NONE — Phase 1 is field-level filtering only.

Cost driver breakdown (current):
  Windows DNS:               $2,470,000  (39.8%)  [load-bearing — keep]
  Palo Alto traffic:         $1,118,000  (18.0%)  [supplementary — tier candidate]
  AWS CloudTrail data evts:    $310,000  ( 5.0%)  [load-bearing — filter candidate]
  Cisco firewall:              $186,000  ( 3.0%)  [observability-only — drop candidate]
  All other sources:         $2,116,000  (34.2%)

Phase 1 (no detection impact): Field-level filtering on Windows DNS
  Estimated savings:          $1,820,000

Phase 2 (acceptable detection impact, 60-day hold):
  Tier Palo Alto traffic to warm: estimated $670,000
  Drop Cisco firewall:            estimated $186,000
  Total Phase 2:                  $856,000

Combined (Phase 1 + Phase 2 after validation): $2,676,000 annual savings (43.2%)
```

## Implementation Notes

- **Field filtering before tier shifting.** Most environments have 30–60% of ingested data in fields no rule references. Filtering at ingest delivers savings with zero detection impact and should always be Phase 1.
- **Counterfactual modeling against historical incidents is the killer feature.** Finance hears "we might lose visibility." Showing that "in the past 90 days, this proposed change would have blocked 0 incidents and delayed 2 by an average of 4 minutes" turns the conversation.
- **Latency budgets matter.** A correlation rule with a 5-minute window doesn't care if data arrives in 30 seconds vs. 5 minutes. A real-time response rule does. Tier decisions must be informed by per-rule latency budgets, not blanket assumptions.
- **Watch out for retention requirements.** Compliance frameworks (PCI requires 12 months minimum for some logs; HIPAA requires 6 years for audit logs; sector regulators vary) constrain how cheap "cold" can go. Combine with [UC-28](../posture-assessment/28-compliance-detection-mapping.md).
- **Don't model purely on cost.** Some data sources are cheap-to-ingest but operationally critical (e.g., a small-volume identity log that drives 30 detections). Conversely, some are expensive but low-value. Use the source classification to drive priority.
- **Sample-based tiering is risky for low-volume data.** A 1% sample of 1M events is 10K events. A 1% sample of 100 events is 1 event. Sampling works for high-volume noise sources, not for low-volume strategic telemetry.
- **Track cost-attribution drift.** A new connector deployment can quietly add 200 GB/day to a previously-modest source. Continuous monitoring of per-source cost catches surprises.
- **Vendor capabilities exist.** Cribl Stream, Edge Delta, Axoflow, and Observo AI all do AI-classified ingest filtering. Sentinel data lake + Splunk Federated Search + Databricks Lakewatch are tiered-storage substrates. ReliaQuest publishes case studies. For most environments, vendor-native tooling is the right path; this use case applies for cross-vendor analysis or for environments wanting custom optimization logic.

## Dependencies

- **Prerequisite — Pillar 1 (Data Foundations)**: Per-source cost and volume metrics must be reliably available.
- **Prerequisite — Pillar 5 (Metrics & Feedback)**: Per-rule signal quality (UC-06) and validation (UC-26) underpin source value classification.
- [UC-27: AI-Driven Log Source Onboarding & Parser Generation](../rule-content-engineering/27-log-source-onboarding.md) — Maintains the rule dependency map this use case consumes.
- [UC-06: MITRE ATT&CK Posture Scoring](../posture-assessment/06-mitre-attack-posture-scoring.md) — Per-rule signal quality scores.
- [UC-26: Continuous Detection Validation](../rule-content-engineering/26-continuous-detection-validation.md) — Validation status determines whether a rule's data dependencies are providing real value.
- [UC-28: Detection Coverage Mapping for Compliance](../posture-assessment/28-compliance-detection-mapping.md) — Compliance retention requirements constrain tier decisions.

## Complexity Assessment

| Dimension | Rating | Notes |
|---|---|---|
| Data engineering | Medium | Cost + volume + dependency map are SIEM-admin standard data. Counterfactual modeling against historical alerts requires more work. |
| AI/ML complexity | Medium | LLM reasoning over structured cost/coverage data. Source classification and proposal generation are templated. |
| Integration effort | Medium | Touches SIEM cost data, ingest pipeline configuration (Cribl/Edge Delta/etc.), data lake architecture, finance reporting. Multi-team. |
| Overall | **Medium** | One of the highest-ROI use cases when prerequisites exist. SIEM cost reduction is directly measurable in dollars. |

## Real-World Considerations

- **The cost conversation is ultimately political.** Finance wants cuts. Detection engineering wants coverage. Compliance wants retention. Security architecture wants flexibility. The AI-generated proposals are *evidence*, not decisions — they make the trade-offs explicit so the decision can be made informed.
- **Vendor lock-in via tiering.** The "warm tier" of choice (Sentinel data lake, Splunk Federated, Databricks Lakewatch, custom S3 + Iceberg) creates new vendor relationships and migration cost. Factor in the architectural lock-in alongside the cost savings.
- **Detection coverage decay can be invisible.** Cost cuts are immediate and measurable. Detection regressions surface only when an attacker exploits the gap. Use [UC-26](../rule-content-engineering/26-continuous-detection-validation.md) to surface coverage degradation continuously, not at-incident.
- **Compliance retention can override cost optimization.** PCI DSS 4.0 minimum log retention, HIPAA Security Rule 6-year requirement, sector-specific mandates are non-negotiable. Don't propose tier-down changes that would violate these without a clear compliance signoff.
- **The 80% TCO claims are aspirational.** Vendor reductions of 50–80% are real for specific environments but assume a baseline of "everything in expensive hot tier." A SOC that already runs a tiered architecture realizes more modest savings (10–30%). Set expectations realistically.
- **Data-lake search latency is uneven.** Sub-second on hot SIEM tier becomes 5–60 seconds on warm tier with cached indexes, and can be minutes-to-hours on cold tier or full-table scans. Test latency against actual rule queries, not against theoretical SLAs.

## Related Use Cases

- [UC-27: AI-Driven Log Source Onboarding & Parser Generation](../rule-content-engineering/27-log-source-onboarding.md) — Onboarding decisions are tiering decisions
- [UC-06: MITRE ATT&CK Posture Scoring](../posture-assessment/06-mitre-attack-posture-scoring.md) — Source classification depends on per-rule scoring
- [UC-26: Continuous Detection Validation](../rule-content-engineering/26-continuous-detection-validation.md) — Validation status confirms whether a source's dependent rules are functional
- [UC-28: Detection Coverage Mapping for Compliance](../posture-assessment/28-compliance-detection-mapping.md) — Retention requirements constrain tiering
- [UC-01: Detection Performance Analytics](../alert-analysis/01-detection-performance-analytics.md) — Source-level cost analysis pairs with rule-level performance analysis

## References

- Cribl, [Cribl Stream Documentation](https://docs.cribl.io/) — Vendor-side ingest filtering and routing
- Edge Delta, [Observability Pipelines](https://edgedelta.com/) — Vendor-side filtering reference
- Axoflow, [How Axoflow Really Uses AI](https://axoflow.com/how-axoflow-really-uses-ai) — AI-classified ingest pipeline
- SentinelOne, [Singularity AI SIEM (Observo AI integration)](https://www.sentinelone.com/press/sentinelone-unveils-new-ai-security-offerings/) — In-pipe enrichment + tiering
- Microsoft, [Sentinel Data Lake (GA 2026)](https://techcommunity.microsoft.com/blog/microsoftsentinelblog/what%E2%80%99s-new-in-microsoft-sentinel-rsac-2026/4503971) — Tiered SIEM architecture
- Splunk, [Federated Search](https://www.splunk.com/en_us/blog/security/from-reactive-to-agentic-with-enterprise-security-at-rsac-2026.html) — Cold-tier search across S3 + Iceberg
- Databricks, [Lakewatch — Open Agentic SIEM](https://www.databricks.com/company/newsroom/press-releases/databricks-enters-security-market-launch-lakewatch-new-open-agentic) — 80% TCO claim
- ReliaQuest, [Is SIEM Still Worth the Cost in 2026?](https://reliaquest.com/digital-guide/is-siem-still-worth-the-cost) — 860 GB/day, 43% cost reduction case study
- CISO Expert, [The SIEM Cost Trap (April 2026)](https://cisoexpert.com/blog/2026-04-01-siem-cost-trap-data-lake-ai-agents/) — Industry analysis
- Elastic, [Frozen Tier and Searchable Snapshots](https://www.elastic.co/guide/en/elasticsearch/reference/current/data-tiers.html)
