# UC-20: Analyst Workflow Optimization

## Category

Strategic

## Summary

Analyzes SOC analyst investigation patterns to identify which analysts perform best on which alert types, where investigation guides fail to match actual analyst behavior, and what common investigation paths are ripe for automation. The LLM synthesizes workflow telemetry into coaching recommendations and process improvement proposals that a detection engineering lead can act on.

## Problem Statement

SOC managers have basic ticket-system metrics: alerts closed per analyst, average time to triage, closure rates by shift. These numbers tell you *what* happened but not *why*. They cannot answer questions like: Why does Analyst A resolve credential-access alerts in 4 minutes while Analyst B takes 22? Is it skill, tooling, or a broken investigation guide? When 60% of analysts skip Step 3 in a triage procedure, is Step 3 wrong or are the analysts cutting corners? Which recurring investigation sequences are identical enough to automate without losing analytical quality?

These are synthesis and reasoning problems. The raw data exists in ticket systems, SOAR execution logs, and SIEM audit trails, but extracting actionable insight requires correlating multiple structured and semi-structured data sources and reasoning about patterns that simple aggregations cannot surface.

## Prerequisites (What Your SIEM/SOAR Should Already Handle)

Before AI adds value here, the following must be in place:

- **Structured case management data.** Ticket/case records must use standardized fields: alert type, MITRE technique, resolution category (true positive, false positive, benign true positive), time-to-close, assigned analyst, shift. If analysts close tickets with "resolved" or "done" in a freeform text field, the data is useless.
- **SOAR execution logs.** If analysts use SOAR playbooks during triage, the execution history (which steps ran, which were skipped, what the analyst queried manually outside the playbook) must be logged and queryable.
- **SIEM audit trails.** Query history per analyst session — what queries they ran, what indices they searched, how many pivots they performed — available via SIEM audit logging (e.g., Elasticsearch slow logs, Splunk search audit, Sentinel activity logs).
- **Investigation guides.** Documented triage procedures per rule or rule category (see [UC-15](../rule-content-engineering/15-llm-investigation-guide-generation.md)). Without these, there is no baseline to measure deviation against.
- **Basic metrics dashboards.** Alerts per analyst, mean time to triage, closure rate by category — these are ticket-system queries and SIEM dashboard problems, not AI problems. Build these first.

## Where AI Adds Value

The AI contribution is in three areas, all requiring reasoning over heterogeneous data that simple queries and dashboards cannot provide:

1. **Analyst-alert affinity analysis.** The LLM examines resolution quality and speed across analyst-alert type pairs and identifies statistically meaningful patterns. Not just "Analyst A is fast on credential alerts" but reasoning about *why* — correlating with the analyst's query patterns, the enrichment sources they use, and the investigation paths they follow.

2. **Investigation guide gap detection.** By comparing documented investigation procedures against actual analyst behavior (derived from SOAR logs and query audit trails), the LLM identifies where guides are consistently ignored, where analysts add undocumented steps that improve outcomes, and where procedural gaps correlate with slower resolution or incorrect verdicts.

3. **Automation candidate identification.** The LLM identifies investigation sequences that are performed identically (or near-identically) across multiple analysts and alert types — patterns that could be encoded as SOAR playbook steps or automated enrichment workflows without losing analytical quality.

## AI Approach

- **LLM prompting with structured data synthesis.** The primary technique is feeding structured workflow data (analyst metrics, SOAR execution traces, query audit logs, investigation guide documents) into an LLM with prompts designed to extract patterns and generate recommendations.
- **Clustering** (optional, enhances quality). Use embedding-based clustering on analyst query sequences to group similar investigation patterns before LLM synthesis. This reduces the volume of data the LLM must process and surfaces groupings that improve recommendation quality.
- **RAG over investigation guides.** Retrieve the relevant investigation guide for each alert type so the LLM can compare documented procedure against observed behavior.

## Data Requirements

### Inputs

| Input | Format | Key Fields Used |
|---|---|---|
| Case/ticket records | Structured (JSON, CSV export from case management) | `analyst_id`, `alert_type`, `rule_id`, `mitre_technique`, `resolution_category` (TP/FP/BTP), `time_to_triage`, `time_to_close`, `shift`, `escalated` (bool) |
| SOAR execution logs | Structured (JSON from SOAR API) | `playbook_name`, `steps_executed[]`, `steps_skipped[]`, `manual_actions[]`, `analyst_id`, `alert_id`, `execution_time_per_step` |
| SIEM query audit trail | Structured (audit index or API) | `analyst_id`, `query_text`, `index_searched`, `timestamp`, `results_count`, `session_id` |
| Investigation guides | Markdown or structured text | Per-rule or per-category triage procedures with numbered steps |
| Analyst roster | Structured (CSV/JSON) | `analyst_id`, `experience_level`, `shift`, `specializations` |

> **Note:** Alert data follows the SIEM's standard alert schema with normalized source event fields. Rule files follow their format's defined schema (Elastic TOML, Sigma YAML, Splunk YAML, etc.). These are structured, documented formats — see [data-requirements/](../../data-requirements/) for platform-specific field references.

### Outputs

The system produces three output types:

**1. Analyst-Alert Affinity Report**

```
## Analyst Effectiveness Matrix — Q4 2025

### Top Findings

- Analyst M. Torres resolves credential access alerts (T1003, T1558) 62% faster
  than team average with a 94% correct verdict rate. Primary differentiator:
  Torres consistently queries AD group membership and recent password changes
  as the first investigation step — a pattern not documented in the current
  investigation guide for these alert types.

- Analysts on the overnight shift (00:00–08:00) have a 31% higher false
  negative rate on lateral movement alerts (T1021) compared to day shift.
  Correlation: overnight analysts skip the "check for concurrent sessions
  on target host" step 78% of the time. Likely cause: the step requires
  querying a secondary index (authentication logs) that is not linked from
  the triage playbook.

### Recommended Actions

1. Update credential access investigation guide to include AD group membership
   check as Step 1 (based on Torres pattern).
2. Add direct link to authentication log query in lateral movement playbook
   to reduce overnight skip rate.
3. Consider routing credential access alerts preferentially to Torres and
   Kim during peak volume periods.
```

**2. Investigation Guide Gap Analysis**

```
## Guide Deviation Report — December 2025

### Rules with Highest Guide Deviation

| Rule Name | Guide Steps | Avg Steps Followed | Deviation Rate | Outcome Impact |
|---|---|---|---|---|
| Suspicious PowerShell Execution | 6 | 3.2 | 47% | No measurable impact on verdict accuracy |
| LSASS Memory Access | 5 | 5.0 + 2.1 extra | 42% (additions) | Analysts adding EDR timeline check — improves accuracy by 18% |
| Okta MFA Bypass Attempt | 4 | 2.8 | 30% | Skipping Step 3 correlates with 2.4x higher false negative rate |

### Key Insight

For "LSASS Memory Access," 84% of analysts independently add an EDR process
timeline check that is not in the current guide. This step reduces false
positive rate by 18%. Recommend adding this as an official guide step.

For "Okta MFA Bypass Attempt," Step 3 ("verify user's recent travel via
HR system") is skipped by 70% of analysts. Those who skip it have a 2.4x
higher false negative rate. The step is critical but the current guide does
not explain why — add context about why travel verification matters for this
alert type.
```

**3. Automation Candidate List**

```
## Automation Opportunities — Q4 2025

### High-Confidence Automation Candidates

1. **IP reputation + geo check sequence** (identified in 14 rule types)
   - 92% of analysts perform the same 3-step sequence: VirusTotal lookup,
     AbuseIPDB check, geo-IP verification.
   - Sequence is identical across analysts and alert types.
   - Recommendation: Encode as SOAR playbook enrichment step. Estimated
     savings: 2.1 minutes per alert, ~340 analyst-hours/quarter.

2. **User account status verification** (identified in 9 rule types)
   - 88% of analysts query AD for account status, last logon, group
     membership as first triage step for identity-related alerts.
   - Recommendation: Auto-enrich all identity alerts with AD context at
     alert creation time. Estimated savings: 1.8 minutes per alert.

### Lower-Confidence Candidates (Require Human Judgment)

3. **EDR process tree analysis** (identified in 7 rule types)
   - Analysts consistently pull the process tree, but the *interpretation*
     varies significantly by analyst and context. Not suitable for full
     automation — consider auto-fetching the tree and presenting it to
     the analyst rather than auto-interpreting.
```

## Implementation Notes

- **Data collection is the hard part.** Most SOCs do not have clean, queryable SOAR execution logs or SIEM audit trails. Expect to spend significant effort on data engineering before the AI component is useful.
- **Privacy considerations.** Analyst performance data is sensitive. Work with HR and management to establish how the data will be used. Framing matters: "coaching tool to improve guides and tooling" is different from "analyst performance surveillance."
- **Start with investigation guide gap analysis.** This is the highest-value, lowest-risk output. Comparing documented procedures against observed behavior is less sensitive than ranking analyst performance.
- **Batch processing, not real-time.** This is a weekly or monthly reporting use case, not a real-time system. Run analysis on accumulated data and produce reports for the detection engineering lead and SOC manager.
- **LLM context window management.** For a large SOC, the raw data volume may exceed LLM context limits. Pre-aggregate metrics per analyst-alert pair and per investigation step before passing to the LLM. The LLM synthesizes pre-computed statistics, not raw logs.

## Dependencies

- [UC-15: LLM Investigation Guide Generation](../rule-content-engineering/15-llm-investigation-guide-generation.md) — Investigation guides must exist as a baseline for deviation analysis.
- [Prerequisites: Process Maturity](../../prerequisites/02-process-maturity.md) — Structured case management and documented workflows are foundational.
- [Prerequisites: Metrics & Feedback](../../prerequisites/05-metrics-and-feedback.md) — Baseline SOC metrics must be established before optimization analysis is meaningful.

## Complexity Assessment

| Dimension | Rating | Notes |
|---|---|---|
| Data engineering | Medium | Collecting and normalizing SOAR execution logs and SIEM audit trails requires integration work. Most of the data exists but is not pre-joined. |
| AI/ML complexity | Low-Medium | Straightforward LLM prompting with structured data. Optional clustering for investigation pattern grouping. |
| Integration effort | Medium | Requires read access to case management, SOAR logs, and SIEM audit indices. No write-back required. |
| Overall | Medium | The data engineering and organizational adoption are harder than the AI component. |

## Real-World Considerations

- **Organizational resistance.** Analyst workflow analysis can feel like surveillance. Secure management buy-in and frame outputs as process improvement, not individual evaluation. Share findings with the team, not just leadership.
- **Sparse data for small teams.** A 5-analyst SOC may not generate enough data for statistically meaningful patterns. This use case works best with 10+ analysts and 3+ months of data.
- **Investigation guide quality varies.** If existing guides are outdated or incomplete, deviation analysis may simply confirm that analysts have already adapted to better practices informally. This is still valuable — it identifies which informal practices should become official.
- **Alert type distribution is uneven.** Some alert types fire thousands of times per month; others fire twice. Patterns in high-volume alert types are statistically reliable; patterns in low-volume types may be noise.
- **Seasonal and shift effects.** Analyst behavior changes during incident surges, holiday periods, and shift changes. Normalize for these factors before drawing conclusions.

## Related Use Cases

- [UC-01: Detection Performance Analytics](../alert-analysis/01-detection-performance-analytics.md) — Provides the rule-level performance data that feeds into workflow analysis.
- [UC-03: Automated Rule Tuning Recommendations](../alert-analysis/03-automated-rule-tuning-recommendations.md) — Tuning recommendations reduce noise, which changes analyst workload patterns.
- [UC-11: LLM Triage Verdicts](../ai-assisted-triage/11-llm-triage-verdicts.md) — AI triage verdicts can be compared against analyst verdicts to identify where AI and humans diverge.
- [UC-14: Agentic Investigation Execution](../ai-assisted-triage/14-agentic-investigation-execution.md) — Automation candidates identified here feed into agentic investigation design.
- [UC-15: LLM Investigation Guide Generation](../rule-content-engineering/15-llm-investigation-guide-generation.md) — Investigation guides are both an input to this use case and improved by its output.
- [UC-22: Detection Program Health Reporting](../strategic/22-detection-program-health-reporting.md) — Workflow optimization findings contribute to overall program health narrative.

## References

- Anton Chuvakin, ["Simple to Ask: Is Your SOC AI Ready? Not Simple to Answer!"](https://medium.com/anton-on-security/simple-to-ask-is-your-soc-ai-ready-not-simple-to-answer) (October 2025) — Pillar 2 (Process Maturity) directly applies to this use case.
- Anton Chuvakin, ["Beyond 'Is Your SOC AI Ready?' Plan the Journey!"](https://medium.com/anton-on-security/beyond-is-your-soc-ai-ready-plan-the-journey) (January 2026) — Framework for planning process maturity improvements.
- OWASP Agentic AI Security Initiative — Considerations for AI agents operating on sensitive workforce data.
