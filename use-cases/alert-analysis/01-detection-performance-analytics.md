# UC-01: Detection Performance Analytics

## Category

Alert Analysis

## Summary

Use an LLM to synthesize deterministic performance metrics across a large detection rule portfolio into prioritized, actionable narratives. The SIEM computes every metric — volume, entity cardinality, trends, spikes, periodicity, co-occurrence. The AI reads the full picture across thousands of rules and tells you where to focus, why, and what the metrics mean in combination.

## Problem Statement

An environment with 4,000+ detection rules across 50+ data source domains produces an enormous surface area of performance data. Any individual metric — alert volume, entity counts, trend direction — is trivially queryable in a SIEM. The problem is not computation; it is comprehension at scale.

No single analyst can review performance dashboards for thousands of rules on a recurring basis and synthesize meaningful insights. The questions that matter are cross-cutting: Which rules are degrading? Which share a common noise source? Which cluster of rules all spiked on the same day, and does that correlate with an infrastructure change or a real campaign? Which rules have been silently producing zero alerts for weeks while their data source is still active?

Without synthesis, detection engineering teams operate reactively — they tune the rule that generated the most recent complaint, not the rule that has been quietly accumulating technical debt for months.

## Prerequisites (What Your SIEM/SOAR Should Already Handle)

These are table-stakes SIEM capabilities. If your platform cannot do these, solve that problem first before introducing AI.

- **Alert volume aggregation**: Total alert count per rule over configurable time windows (7d, 30d, 90d). This is a simple `count()` aggregation grouped by `rule.name` or `rule.id`.
- **Daily average calculation**: Volume divided by days in window. Basic arithmetic.
- **Trend computation**: Compare current window volume to prior window. Percentage change. A scheduled search or detection-as-code pipeline can compute this on any cadence.
- **Spike detection**: Standard deviation from rolling baseline, or simpler threshold-based approaches (e.g., daily volume > 3x 30-day average). Elastic ML, Splunk `anomalydetection`, or Sentinel anomaly rules can automate this, but even a scheduled query with a static multiplier works.
- **Entity cardinality per field**: `cardinality()` (Elastic), `dc()` (Splunk), `dcount()` (Sentinel/KQL) on domain-appropriate fields — `user.name`, `host.name`, `source.ip`, `process.name`, `destination.ip`, etc.
- **Alert-to-entity ratio**: Volume divided by unique entity count. Computed per entity field. A ratio of 10,000 alerts to 3 unique users tells a very different story than 10,000 alerts across 8,000 unique users.
- **Top-N entity concentration**: Terms aggregation showing the top 5-10 entities by alert count, plus their percentage of total volume. If one service account drives 94% of a rule's volume, that is a tuning opportunity.
- **Periodicity detection**: Date histogram aggregation (hourly, daily) to identify recurring patterns. Business-hours-only firing, weekly batch-job spikes, etc.
- **Co-occurrence rate**: Rules that fire on the same entity within the same time window. This is a join or correlation search — group alerts by entity + time bucket, then count distinct rules per group.
- **Silence detection**: Rules with zero alerts over a defined window where the underlying data source index is still receiving events.

All of these are deterministic. They produce numbers. The SIEM is the right tool.

## Where AI Adds Value

AI does not compute metrics. AI reads metrics and produces judgment.

Given the structured output of all metrics above for hundreds or thousands of rules, an LLM can:

1. **Generate per-rule health narratives**: Instead of a dashboard row with 12 columns of numbers, produce a paragraph that says what the numbers mean together. "This rule has fired 47,000 times in 30 days, but 98% of volume comes from 2 service accounts running scheduled tasks. Entity cardinality across users is 2; across hosts is 1. Alert-to-entity ratio is extreme. This rule is functioning as a service-account activity log, not a detection."

2. **Identify portfolio-level patterns**: "14 rules targeting Windows process creation all spiked 300%+ on Feb 3rd. All share `process.command_line` as a key field. This correlates with a software deployment event reported in the change log." No single-rule dashboard surfaces this.

3. **Produce a prioritized attention list**: Rank rules by combined signal — high volume + low cardinality + increasing trend + no recent tuning = high priority. The ranking heuristic can be deterministic, but the explanation of *why* a rule is prioritized and *what to do about it* benefits from natural language generation.

4. **Cross-reference rule intent with observed behavior**: If a rule's description says it detects lateral movement, but its entity profile shows it fires exclusively on a single monitoring tool's service account, the AI can flag the mismatch between intent and observed reality.

5. **Surface non-obvious correlations**: Rules that individually look fine but share a noise source. A noisy DHCP server causing low-severity alerts across 8 different network rules, none of which individually crosses a volume threshold.

## AI Approach

**Method**: LLM prompting with structured metric data.

No fine-tuning required. No embeddings. No RAG. This is a structured-data-to-narrative task.

### Prompt Architecture

1. **System prompt**: Establishes the role (detection engineering analyst), the environment (rule count, data source domains, no analyst disposition data available), and the output format (structured narrative with priority rankings).

2. **Metric payload**: A structured object (JSON or markdown table) per rule containing all computed metrics. For a portfolio-wide analysis, batch rules into groups of 50-100 per prompt to stay within context limits.

```json
{
  "rule_id": "siem-rule-00421",
  "rule_name": "Suspicious PowerShell Encoded Command",
  "rule_description": "Detects use of -EncodedCommand or -enc flags in PowerShell execution",
  "data_source_domain": "endpoint.process",
  "severity": "medium",
  "metrics": {
    "volume_30d": 12847,
    "daily_avg_30d": 428.2,
    "volume_prior_30d": 3210,
    "trend_pct_change": 300.2,
    "spike_days": ["2026-01-18", "2026-01-19", "2026-01-20"],
    "entity_cardinality": {
      "user.name": 4,
      "host.name": 3,
      "process.parent.name": 2,
      "process.command_line": 87
    },
    "alert_to_entity_ratio": {
      "user.name": 3211.75,
      "host.name": 4282.33
    },
    "top_entities": {
      "user.name": [
        {"entity": "svc_sccm", "count": 11200, "pct": 87.2},
        {"entity": "svc_intune", "count": 1400, "pct": 10.9},
        {"entity": "jsmith", "count": 150, "pct": 1.2},
        {"entity": "admin_klee", "count": 97, "pct": 0.8}
      ]
    },
    "periodicity": "business_hours_weekdays",
    "co_occurring_rules": ["siem-rule-00089", "siem-rule-00415"],
    "silent_days_last_90d": 0
  }
}
```

3. **Task instruction**: "For each rule, produce a health assessment narrative. Then produce a portfolio summary identifying cross-cutting patterns. Finally, produce a prioritized attention list ranked by urgency."

### Output Parsing

The LLM output should be structured (e.g., JSON with designated fields for narrative, priority_score, recommended_action, and reasoning). Use output schemas or structured output modes where available to enforce consistency.

## Data Requirements

### Inputs

| Data Element | Source | Computation | Notes |
|---|---|---|---|
| Alert volume (current window) | SIEM alert index | `count()` grouped by `rule.id` | Window configurable: 7d, 30d, 90d |
| Alert volume (prior window) | SIEM alert index | Same query, shifted time range | For trend calculation |
| Daily average | Derived | Volume / days in window | Simple arithmetic |
| Trend (% change) | Derived | `(current - prior) / prior * 100` | Flag if abs(change) > threshold |
| Spike days | SIEM alert index | Date histogram, flag days > 3x daily avg | Threshold configurable |
| Entity cardinality per field | SIEM alert index | `cardinality()` on domain-appropriate fields | Fields vary by data source domain |
| Alert-to-entity ratio | Derived | Volume / cardinality per field | High ratio = low diversity = potential noise |
| Top-N entities | SIEM alert index | `terms` aggregation, top 10 by count | Include count and % of total |
| Periodicity signal | SIEM alert index | Date histogram (hourly buckets), analyze distribution | Business hours, daily, weekly patterns |
| Co-occurrence rate | SIEM alert index | Group by entity + time bucket, count distinct rules | Requires join/correlation query |
| Rule metadata | Rule repository / SIEM API | Rule name, description, severity, data source, MITRE mapping | Enriches AI context |
| Data source health | SIEM index stats | Event count per index/data source over same window | Needed for silence interpretation |

### Outputs

The AI produces three tiers of output:

**Tier 1: Per-Rule Health Narrative**

```
## Rule: Suspicious PowerShell Encoded Command (siem-rule-00421)
**Priority: HIGH | Trend: +300% | 30d Volume: 12,847**

This rule has experienced a 4x volume increase compared to the prior 30-day period,
concentrated on Jan 18-20. Despite the high volume, entity diversity is extremely low:
only 4 unique users and 3 unique hosts. Two service accounts (svc_sccm at 87.2% and
svc_intune at 10.9%) account for 98.1% of all alerts. The remaining 1.9% (247 alerts)
comes from 2 interactive user accounts.

The alert-to-entity ratio for user.name is 3,212:1, indicating this rule is
overwhelmingly driven by repetitive automated activity. The periodicity pattern
(business hours, weekdays only) aligns with scheduled management tool operations.

The spike on Jan 18-20 likely correlates with a deployment or configuration push
via SCCM/Intune — check change management records for that window.

**Recommended action**: Exclude svc_sccm and svc_intune after validating they are
legitimate service accounts. Projected volume reduction: ~98%. Residual signal
(247 alerts from interactive users) retains detection value for actual suspicious
encoded PowerShell usage.

**Co-occurrence note**: This rule co-fires with siem-rule-00089 (PowerShell Download
Cradle) and siem-rule-00415 (Encoded PowerShell via WMI). Review as a group — the
same exclusion may apply across all three.
```

**Tier 2: Portfolio-Level Insights**

```
## Portfolio Summary — 30-Day Review (4,127 active rules)

### Key Findings

1. **Shared noise source identified**: 14 endpoint.process rules (listed below) share
   a common noise driver — svc_sccm executing encoded PowerShell commands during
   software deployments. Combined volume from this single source: 89,400 alerts/30d.
   A single service account exclusion across these rules would reduce total portfolio
   volume by approximately 6%.

2. **Silent rule cluster**: 23 rules targeting network.dns data source have produced
   zero alerts in the past 30 days. The dns index is healthy (42M events/30d).
   Likely cause: DNS logging format change deployed Jan 5 altered field names.
   Recommend immediate investigation — these rules are blind.

3. **Emerging volume trend**: Rules in the cloud.azure_ad domain have collectively
   increased 45% over 30 days. No single rule spiked — this is a gradual, distributed
   increase. Correlates with Azure AD tenant expansion (12 new application
   registrations in the past month). Not necessarily noise — may reflect expanded
   attack surface requiring proportionally more alerts.
```

**Tier 3: Prioritized Attention List**

```
## Prioritized Attention List

| Rank | Rule ID | Rule Name | Priority | Primary Issue | Est. Effort |
|------|---------|-----------|----------|---------------|-------------|
| 1 | siem-rule-00421 | Suspicious PowerShell Encoded Command | HIGH | 98% single-source noise, +300% trend | 30 min |
| 2 | (23 rules) | DNS detection cluster | HIGH | Silent 30+ days, data source field change | 2-4 hrs |
| 3 | siem-rule-00089 | PowerShell Download Cradle | HIGH | Co-occurs with #1, same noise source | 15 min (if #1 done) |
| 4 | siem-rule-01102 | Multiple Failed Logins | MEDIUM | 12,000/30d but 6,200 unique users — may be legitimate signal | 1 hr investigation |
| 5 | siem-rule-00673 | Rare Scheduled Task Created | MEDIUM | Volume doubled but cardinality also doubled — scaling, not noise | Monitor |
```

## Implementation Notes

- **Batching strategy**: With 4,000+ rules, you cannot send all metric data in a single prompt. Batch by data source domain (e.g., all `endpoint.process` rules together, all `network.firewall` rules together). This gives the LLM domain context for its assessments. A second pass can synthesize across domains for portfolio-level insights.

- **Metric computation cadence**: Run the SIEM aggregation queries on a scheduled basis (daily or weekly). Store results in a metrics index or flat file. The AI analysis then reads from this pre-computed dataset — it should never query the SIEM directly.

- **Prompt token management**: A batch of 100 rules with full metrics is roughly 50-80K tokens of input depending on entity detail. Use a model with a large context window (128K+). If needed, reduce top-N entity lists or omit low-volume rules from AI analysis entirely.

- **Deterministic vs. AI boundary**: The priority ranking heuristic (which combines volume, trend, cardinality, and ratio thresholds) can be implemented deterministically. The AI's value is in the narrative explanation and cross-rule correlation — not in the ranking formula itself. Consider computing a deterministic priority score and having the AI explain and adjust it.

- **No analyst disposition data**: Since analyst feedback (true positive, false positive, benign true positive) is not available, entity cardinality is the primary proxy for signal quality. A rule with high volume and low entity cardinality is almost certainly noisy. A rule with high volume and high entity cardinality may be correctly detecting a widespread condition. The AI should reason about this distinction explicitly.

- **Automation pipeline**: This use case is well-suited to a scheduled pipeline: (1) SIEM queries compute metrics nightly, (2) metrics are formatted into batched prompts, (3) LLM generates narratives, (4) output is written to a report index or wiki page, (5) detection engineering team reviews weekly.

## Dependencies

- SIEM platform with scheduled query capability and alert index access
- Rule metadata repository (rule names, descriptions, severity, data source mappings, MITRE tags)
- LLM API access with sufficient context window (128K+ tokens recommended)
- Pre-computed metrics pipeline (scheduled queries writing to a metrics store)
- Data source health monitoring (event counts per index to contextualize silence)

## Complexity Assessment

| Dimension | Rating | Notes |
|---|---|---|
| Overall | Medium | No model training. No embeddings. Structured data in, narrative out. |
| Data pipeline | Medium | Requires scheduled aggregation queries across the full rule portfolio. Query design is straightforward but operationalizing across 4,000+ rules requires automation. |
| Prompt engineering | Medium | Prompt must convey metric semantics, domain context, and output format. Iterative refinement needed to get consistent, useful narratives. |
| AI integration | Low | Single LLM API call per batch. No chaining, no tool use, no retrieval. |
| Output validation | Medium | AI narratives should be spot-checked against raw metrics. Projected volume reductions are deterministic and verifiable. Safety assessments require human review. |
| Maintenance | Low | Metrics schema changes infrequently. Prompt updates needed when new metric types are added or output format requirements change. |

## Real-World Considerations

- **The 80/20 reality**: In most environments, 10-15% of rules generate 80%+ of alert volume. The AI analysis will likely converge on a short list of high-impact tuning targets quickly. The long tail of low-volume rules may not warrant AI analysis at all — a simple deterministic filter (e.g., "show me rules with < 5 alerts in 30 days that are not on silent data sources") handles that tier.

- **Narrative fatigue**: If the AI generates 4,000 per-rule narratives, nobody will read them. The portfolio summary and prioritized attention list are the high-value outputs. Per-rule narratives are useful on-demand (i.e., when an engineer is actively working on a specific rule), not as a bulk report.

- **Metric stability**: Some metrics are noisy by nature. A rule that fires 5 times in 30 days has unstable trend percentages (going from 2 to 5 is a +150% trend, but it is meaningless). The AI should be instructed to discount trend signals for low-volume rules, or a minimum volume threshold should be applied before trend is computed.

- **Change correlation is manual today**: The AI can hypothesize that a spike correlates with an infrastructure change, but it does not have access to the change management system. Integrating change logs (even as a text summary in the prompt) would significantly improve diagnostic accuracy. This is a future enhancement, not a prerequisite.

- **Cost**: At ~$15/MTok input for frontier models, analyzing 4,000 rules in batches of 100 at ~60K tokens each = ~40 batches = ~2.4M input tokens = ~$36 per full portfolio analysis. Weekly cadence = ~$150/month. This is negligible compared to the analyst time saved.

## Related Use Cases

- **UC-02 (Entity Cardinality Noise Analysis)**: Deep-dives into the entity cardinality metrics that UC-01 surfaces at a high level.
- **UC-03 (Automated Rule Tuning Recommendations)**: Takes UC-01's prioritized attention list and generates specific, implementable tuning proposals.
- **UC-04 (Detection Drift Monitoring)**: Focuses specifically on the silence detection and trend deviation aspects of UC-01, with deeper diagnostic capability.
- **UC-05 (Temporal Pattern Detection)**: Expands on the periodicity signals surfaced in UC-01 with more sophisticated pattern analysis.

## References

- Elastic: [Aggregations documentation](https://www.elastic.co/guide/en/elasticsearch/reference/current/search-aggregations.html) — `cardinality`, `terms`, `date_histogram`, `avg_bucket`
- Splunk: [Stats and charting commands](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/CommonStatsFunctions) — `dc()`, `count`, `timechart`, `anomalydetection`
- Sentinel/KQL: [Summarize operator](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/summarizeoperator) — `dcount()`, `count()`, `make_set()`, `bin()`
- MITRE ATT&CK: Detection analytics quality dimensions — coverage, fidelity, robustness
- Palantir: [Alerting and Detection Strategy Framework](https://github.com/palantir/alerting-detection-strategy-framework) — structured approach to detection quality assessment
