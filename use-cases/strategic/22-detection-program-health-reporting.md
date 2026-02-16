# UC-22: Detection Program Health Reporting

## Category

Strategic

## Summary

Synthesizes all quantitative detection program metrics — posture scores, tuning progress, coverage trends, alert volumes, triage velocity, rule inventory health — into a narrative program health report for leadership. The LLM transforms tables and time-series data into quarter-over-quarter trend analysis, progress against goals, risk area identification, and investment recommendations. This is the capstone use case: it consumes outputs from most other use cases and produces the artifact that a detection engineering lead presents to a CISO or VP of Security.

## Problem Statement

Detection engineering programs generate large volumes of quantitative data: MITRE ATT&CK posture scores across hundreds of techniques, alert volumes per rule, tuning backlog status, rule inventory growth, false positive rates, mean time to triage, analyst throughput metrics, and coverage gap lists. This data exists in dashboards, spreadsheets, and SIEM indices. What does not exist is the *narrative* — the coherent story that explains what the numbers mean, whether the program is on track, where the risks are, and what investments would move the needle.

A detection engineering lead preparing a quarterly program review for leadership currently spends 4-8 hours manually pulling metrics from multiple systems, computing quarter-over-quarter deltas, identifying trends, and writing the narrative. Most of the time is spent on mechanical data assembly and formatting, not on the analytical judgment that actually matters.

Deterministic tooling can compute the metrics, generate charts, and flag threshold breaches. It cannot write a paragraph explaining why the credential access posture score dropped 12 points this quarter, that the drop correlates with a Sysmon configuration change that degraded three rules, and that the fix is a 2-day engineering task that should be prioritized over new rule development.

## Prerequisites (What Your SIEM/SOAR Should Already Handle)

- **Detection posture scores (UC-06).** Per-technique and per-tactic MITRE ATT&CK confidence scores must be computed and trended over time. These are the primary health indicators.
- **Alert volume metrics (UC-01).** Per-rule alert volumes, entity cardinality, and performance scores must be available as time-series data.
- **Tuning backlog tracking.** The status of rule tuning recommendations (open, in-progress, completed, deferred) must be tracked in a structured system — Jira, GitHub Issues, or equivalent.
- **Rule inventory metadata.** Total rule count, rules by category, rules by data source, rules enabled/disabled, rules added/removed per period — all available from the detection-as-code repository via Git history.
- **Triage metrics.** Mean time to triage, analyst throughput, verdict distribution (TP/FP/BTP), escalation rate — available from case management or SOAR execution data.
- **Dashboards and aggregation queries.** All of the above metrics should already be computed by deterministic tooling (SIEM dashboards, scripts, or data pipelines). The AI does not compute the metrics — it synthesizes them into narrative.

## Where AI Adds Value

The AI contribution is entirely in synthesis and generation. Every input is a pre-computed metric. The LLM's job is to:

1. **Narrative generation from quantitative data.** Transform tables of posture scores, alert volumes, and trend data into human-readable paragraphs that explain what the numbers mean in operational context. Not "T1059.001 score: 91, delta: +4" but "PowerShell detection remains strong at 91, up 4 points from last quarter after the team added encoded command-line analysis to two existing rules."

2. **Trend identification and explanation.** Identify meaningful quarter-over-quarter trends and hypothesize causes. "Lateral movement posture declined 8 points this quarter. The decline traces to three WMI-based rules that became noisy after the infrastructure team deployed a new management tool. Two of the three rules have open tuning tickets."

3. **Risk area prioritization.** Synthesize multiple data points into a prioritized risk list for leadership. Not just "these techniques have low scores" but reasoning about which low scores matter most given recent threat intelligence, organizational context, and attack chain position.

4. **Investment recommendation generation.** Based on the full program picture, generate specific recommendations: "Investing 2 FTE-weeks in re-tuning the 5 noisiest credential access rules would improve the credential access posture score from Degraded (44) to Functional (65), closing the gap identified in 3 of the last 4 CTI reports targeting our sector."

5. **Audience-appropriate language.** Adjust technical depth based on the audience: CISO-level summary (business risk, investment asks), security leadership (tactical priorities, resource allocation), and detection engineering team (technical details, specific rules and techniques).

## AI Approach

- **LLM prompting with structured data injection.** The primary technique is feeding pre-computed metrics in structured format (JSON or tabular) into an LLM with a prompt that specifies the report structure, audience, and narrative tone.
- **Multi-section generation.** Generate each report section independently (executive summary, posture trends, triage metrics, risk areas, recommendations) and assemble. This keeps each LLM call focused and reduces hallucination risk.
- **Templated prompting with few-shot examples.** Provide 2-3 examples of well-written report sections as few-shot examples in the prompt. This ensures consistent tone, structure, and level of specificity across quarterly reports.
- **Comparative prompting.** For trend analysis, provide both current-quarter and previous-quarter data in the prompt so the LLM can compute deltas and generate comparative narrative directly.

## Data Requirements

### Inputs

| Input | Format | Key Fields Used |
|---|---|---|
| MITRE ATT&CK posture scores | Structured (JSON from UC-06) | `technique_id`, `confidence_score`, `confidence_tier`, `delta_vs_prior_quarter`, `contributing_rules[]`, `tactic` |
| Rule performance metrics | Structured (JSON from UC-01) | `rule_id`, `rule_name`, `alert_volume`, `entity_cardinality`, `fp_proxy_score`, `trend` (increasing/stable/decreasing/silent) |
| Tuning backlog status | Structured (JSON/CSV from issue tracker) | `rule_id`, `tuning_recommendation`, `status` (open/in-progress/completed/deferred), `date_opened`, `date_closed`, `projected_volume_reduction` |
| Rule inventory summary | Structured (JSON from detection-as-code repo) | `total_rules`, `rules_by_category`, `rules_by_data_source`, `rules_added_this_quarter`, `rules_retired_this_quarter`, `rules_disabled` |
| Triage metrics | Structured (JSON/CSV from case management) | `mean_time_to_triage`, `median_time_to_triage`, `verdicts_by_category` (TP/FP/BTP counts), `escalation_rate`, `alerts_per_analyst_per_shift` |
| CTI synthesis findings (optional) | Structured (JSON from UC-21) | `reports_processed`, `gaps_identified[]`, `work_orders_generated[]`, `work_orders_completed[]` |
| Prior quarter report (optional) | Markdown or text | Previous report for stylistic consistency and comparative framing |
| Organizational goals | Text or structured | Quarterly detection engineering OKRs or goals for progress tracking |

> **Note:** Alert data follows the SIEM's standard alert schema with normalized source event fields. Rule files follow their format's defined schema (Elastic TOML, Sigma YAML, Splunk YAML, etc.). These are structured, documented formats — see [data-requirements/](../../data-requirements/) for platform-specific field references.

### Outputs

**Primary output: Quarterly Detection Program Health Report**

```
# Detection Program Health Report — Q4 2025

## Executive Summary (CISO Audience)

The detection engineering program ended Q4 2025 with 4,247 active detection rules
covering 189 of 201 ATT&CK techniques relevant to our threat profile. Overall
posture score improved from 61 to 64 (Functional tier), driven by focused tuning
work on credential access and execution technique categories.

**Key wins this quarter:**
- Credential access posture improved from Degraded (44) to Functional (62) after
  retuning 5 high-noise rules and deploying 3 new technique-generic detections.
- Mean time to triage decreased 18% (from 11.2 min to 9.2 min) following deployment
  of AI-assisted triage verdicts for 12 high-volume rule categories.
- 94 tuning recommendations completed out of 127 generated (74% completion rate,
  up from 58% in Q3).

**Key risks requiring attention:**
- Lateral movement posture declined from 58 to 47 (now Degraded). Root cause:
  infrastructure team deployed a new WMI-based management tool in October that
  generates false positives on 3 critical lateral movement rules. Tuning tickets
  are open but deprioritized behind new rule development work.
- Exfiltration remains the weakest tactic (average score: 23, Abandoned tier).
  4 of the last 6 CTI reports targeting our sector describe exfiltration techniques
  for which we have no effective detection. This is a structural gap driven by
  limited DLP and TLS inspection telemetry.

**Investment recommendation:**
Allocating 2 FTE-weeks to retune the 3 degraded lateral movement rules would
restore posture to Functional (projected score: 61). Separately, the exfiltration
gap requires a data source investment — TLS inspection coverage for egress traffic
— estimated at $XX and 4 weeks of engineering time. Recommend including in Q1 2026
planning.

---

## Posture Trends by Tactic

| Tactic | Q3 Score | Q4 Score | Delta | Tier | Trend |
|--------|----------|----------|-------|------|-------|
| Initial Access | 72 | 74 | +2 | Functional | Stable improvement |
| Execution | 78 | 82 | +4 | Strong | New encoded PowerShell rules |
| Persistence | 65 | 67 | +2 | Functional | Steady |
| Privilege Escalation | 58 | 60 | +2 | Functional | Crossed into Functional tier |
| Defense Evasion | 52 | 54 | +2 | Degraded | Slow improvement, high technique count |
| Credential Access | 44 | 62 | +18 | Functional | Major improvement from focused tuning sprint |
| Discovery | 41 | 43 | +2 | Degraded | Low priority, minimal change |
| Lateral Movement | 58 | 47 | -11 | Degraded | Regression — WMI management tool noise |
| Collection | 38 | 40 | +2 | Abandoned | Limited telemetry for most techniques |
| Exfiltration | 21 | 23 | +2 | Abandoned | Structural gap — requires data source investment |
| Command and Control | 66 | 68 | +2 | Functional | Stable |
| Impact | 55 | 57 | +2 | Degraded | Incremental improvement |

### Analysis

The credential access improvement (+18 points) is the standout result this quarter.
The team executed a focused 3-week sprint addressing the 5 noisiest credential access
rules, which were generating 62% of all false positives in that tactic category.
Post-tuning, those rules now have entity cardinality ratios in the healthy range
(>0.3) and the tactic crossed from Degraded to Functional for the first time.

The lateral movement regression (-11 points) is the most urgent issue. The decline
is attributable to a single root cause: a new IT management tool (ManageEngine
ServiceDesk agent) deployed to 1,200 servers in October generates WMI process
creation events that trigger 3 lateral movement rules. The fix is well-understood
(exclude the tool's service account and process path) but the tuning tickets have
been in the backlog for 6 weeks.

---

## Rule Inventory Health

| Metric | Q3 | Q4 | Delta |
|--------|-----|-----|-------|
| Total active rules | 4,102 | 4,247 | +145 |
| Rules added | 168 | 178 | +10 |
| Rules retired | 31 | 33 | +2 |
| Rules disabled (pending tuning) | 24 | 19 | -5 |
| Data source domains covered | 48 | 51 | +3 (added GitHub Audit, Zscaler ZIA, CrowdStrike Identity) |

### Notable Changes
- 3 new data source domains onboarded (GitHub Audit, Zscaler ZIA, CrowdStrike Identity),
  adding 34 new rules across defense evasion, initial access, and credential access.
- 5 previously disabled rules re-enabled after successful tuning, contributing to the
  credential access improvement.
- Rule retirement rate remains healthy — removing rules that duplicate coverage or
  detect deprecated attacker tooling.

---

## Triage Performance

| Metric | Q3 | Q4 | Delta |
|--------|-----|-----|-------|
| Total alerts triaged | 42,318 | 39,847 | -5.8% (volume decrease from tuning) |
| Mean time to triage | 11.2 min | 9.2 min | -18% |
| Median time to triage | 7.4 min | 6.1 min | -18% |
| True positive rate | 12.3% | 14.8% | +2.5pp (better signal-to-noise from tuning) |
| Escalation rate | 3.1% | 3.4% | +0.3pp (within normal range) |
| AI-assisted triage coverage | 0% | 31% | +31pp (12 rule categories onboarded) |

### Analysis
Alert volume decreased 5.8% despite adding 145 new rules — a direct result of the
tuning work. The true positive rate improvement from 12.3% to 14.8% means analysts
are spending more time on real threats and less time on noise. This is the most
important SOC efficiency metric and it moved in the right direction.

AI-assisted triage verdicts were deployed for 12 high-volume rule categories in
November. Early results show a 94% agreement rate with analyst verdicts on those
categories. The 6% disagreement cases are under review — approximately half appear
to be AI correct / analyst incorrect (analyst missed context that the AI surfaced),
and half are genuine AI errors requiring prompt tuning.

---

## Recommendations for Q1 2026

1. **Immediate (Week 1-2):** Close the 3 lateral movement tuning tickets to restore
   posture from Degraded to Functional. Estimated effort: 2-3 days.

2. **Short-term (Month 1):** Expand AI-assisted triage coverage from 12 to 25 rule
   categories. Prioritize categories with highest volume and clearest TP/FP signal.
   Projected impact: reduce mean time to triage to ~7 minutes.

3. **Medium-term (Quarter):** Initiate exfiltration telemetry project. Current
   Abandoned-tier posture is a structural gap. Requires TLS inspection deployment
   for egress traffic and DLP integration. This is a capital investment, not a
   detection engineering task.

4. **Ongoing:** Maintain tuning cadence of 25+ recommendations completed per month.
   Q4 demonstrated that focused tuning sprints produce measurable posture improvement.
```

## Implementation Notes

- **Data pipeline, not real-time.** This is a batch process run monthly or quarterly. Build a data pipeline that pulls metrics from all source systems into a staging area (JSON files, database, or data warehouse) before LLM processing.
- **Metric computation is deterministic.** The LLM does not compute posture scores, alert volumes, or triage statistics. All quantitative data is pre-computed by the upstream use cases and tooling. The LLM's only job is narrative synthesis.
- **Version the reports.** Store generated reports in the detection-as-code repository alongside the metrics snapshots that produced them. This creates an audit trail and enables quarter-over-quarter comparison.
- **Human editing is expected.** The LLM produces a first draft. The detection engineering lead reviews, corrects any misinterpretations, adjusts recommendations based on context the LLM does not have (budget constraints, organizational politics, upcoming projects), and finalizes. Expect 30-60 minutes of editing on a draft that would have taken 4-8 hours to write from scratch.
- **Prompt stability across quarters.** Use the same prompt template each quarter to ensure stylistic consistency. Include the prior quarter's report as a few-shot example so the LLM maintains continuity in framing and language.
- **Multiple audience versions.** Consider generating two versions: a CISO-level executive summary (1 page, business risk framing, investment asks) and a technical deep-dive for the detection engineering team (full metrics, specific rules, detailed analysis). Both derive from the same data but use different prompt instructions for tone and depth.

## Dependencies

- [UC-01: Detection Performance Analytics](../alert-analysis/01-detection-performance-analytics.md) — Per-rule performance metrics and health narratives.
- [UC-06: MITRE ATT&CK Posture Scoring](../posture-assessment/06-mitre-attack-posture-scoring.md) — Per-technique and per-tactic posture scores. This is the primary health indicator.
- [UC-10: Executive Posture Reporting](../posture-assessment/10-executive-posture-reporting.md) — Closely related. UC-10 focuses on posture-specific executive reporting; UC-22 is the broader program health report that incorporates posture plus triage, tuning, inventory, and operational metrics.
- [UC-20: Analyst Workflow Optimization](../strategic/20-analyst-workflow-optimization.md) — Analyst effectiveness findings contribute to the triage performance section.
- [UC-21: Threat Intelligence Synthesis](../strategic/21-threat-intelligence-synthesis.md) — CTI-derived gap findings contribute to the risk areas and recommendations sections.
- [Prerequisites: Metrics & Feedback](../../prerequisites/05-metrics-and-feedback.md) — Baseline metrics must exist before trend analysis is possible.

## Complexity Assessment

| Dimension | Rating | Notes |
|---|---|---|
| Data engineering | Medium | Requires pulling pre-computed metrics from 4-6 source systems into a unified input format. Each source has its own API or export mechanism. |
| AI/ML complexity | Low | Straightforward LLM prompting. The inputs are structured metrics; the output is narrative text. No classification, clustering, or RAG required. |
| Integration effort | Medium | Read access to posture scores, alert metrics, tuning backlog, rule inventory, and triage statistics. The integration challenge is breadth (many sources) rather than depth. |
| Overall | Medium | The AI component is simple. The value depends on having mature upstream use cases (UC-01, UC-06) producing reliable metrics. Without good input data, the narrative will be hollow. |

## Real-World Considerations

- **Garbage in, garbage out — at leadership scale.** If posture scores are unreliable or triage metrics are poorly categorized, the LLM will generate a confident-sounding narrative about bad data. This is worse than a spreadsheet with bad data because narrative text feels more authoritative. Validate input quality aggressively.
- **LLM hallucination in causal reasoning.** When the LLM writes "the decline correlates with the Sysmon configuration change," it is generating a plausible hypothesis, not performing a causal analysis. The detection engineering lead must verify causal claims before presenting them to leadership.
- **Metric gaming.** If the program health report drives resource allocation decisions, there is a risk of optimizing for the metrics rather than for actual security outcomes. The report should include qualitative assessments alongside quantitative scores.
- **Consistency across quarters.** Leadership expects quarter-over-quarter comparability. Changing the metrics methodology, scoring formula, or report structure mid-stream undermines credibility. Lock in the methodology before the first report and change it only with explicit version notes.
- **Sensitive content.** Program health reports may contain information about detection gaps that is sensitive from a security perspective. Treat the report as confidential and restrict distribution.
- **Report fatigue.** Leadership reads many reports. Keep the executive summary to one page. Put the detail in appendix sections for those who want it. The LLM can generate both levels from the same data.

## Related Use Cases

- [UC-01: Detection Performance Analytics](../alert-analysis/01-detection-performance-analytics.md) — Primary data source for per-rule health metrics.
- [UC-03: Automated Rule Tuning Recommendations](../alert-analysis/03-automated-rule-tuning-recommendations.md) — Tuning backlog status is a key program health indicator.
- [UC-06: MITRE ATT&CK Posture Scoring](../posture-assessment/06-mitre-attack-posture-scoring.md) — Primary data source for posture trends.
- [UC-10: Executive Posture Reporting](../posture-assessment/10-executive-posture-reporting.md) — Complementary use case focused specifically on posture narrative.
- [UC-20: Analyst Workflow Optimization](../strategic/20-analyst-workflow-optimization.md) — Workflow findings feed into the triage performance section.
- [UC-21: Threat Intelligence Synthesis](../strategic/21-threat-intelligence-synthesis.md) — CTI gap findings feed into the risk areas section.

## References

- Anton Chuvakin, ["Simple to Ask: Is Your SOC AI Ready? Not Simple to Answer!"](https://medium.com/anton-on-security/simple-to-ask-is-your-soc-ai-ready-not-simple-to-answer) (October 2025) — Pillar 5 (Metrics & Feedback) directly supports this use case.
- Anton Chuvakin, ["Beyond 'Is Your SOC AI Ready?' Plan the Journey!"](https://medium.com/anton-on-security/beyond-is-your-soc-ai-ready-plan-the-journey) (January 2026) — Framework for measuring AI-driven improvement.
- Gartner, "Hype Cycle for Security Operations, 2025" — Context for positioning detection program maturity metrics.
