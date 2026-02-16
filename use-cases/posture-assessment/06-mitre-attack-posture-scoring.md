# UC-06: MITRE ATT&CK Posture Scoring

## Category

Posture Assessment

## Summary

Scores your detection posture against the MITRE ATT&CK framework using a two-level quantitative model: a Signal Quality Score per detection rule (0-100), rolled up into a Detection Confidence Score per ATT&CK technique (0-100). Deterministic tooling computes all scores. AI adds value in three specific places: generating per-technique health narratives, assessing whether rules covering the same technique detect genuinely different observables, and synthesizing the full posture into executive-consumable summaries.

## Problem Statement

Most organizations can produce a MITRE ATT&CK heatmap showing which techniques have detection rules mapped to them. This is a binary view — covered or not covered — and it is dangerously misleading. A technique "covered" by six rules where four are broken by noise and one has lost telemetry is not meaningfully covered. The operational question is not "do we have a rule?" but "if an attacker uses this technique in our environment, will we actually detect it?"

Answering that question requires scoring the health of every individual rule, rolling those scores up per technique, and then communicating the results in a way that both detection engineers and executives can act on. The scoring math is deterministic. But interpreting what the scores mean for each technique, assessing whether multiple rules provide genuine detection diversity or just repeat the same narrow pattern, and translating the full posture into actionable narratives — these require reasoning and synthesis that deterministic tooling cannot produce.

## Prerequisites (What Your SIEM/SOAR Should Already Handle)

Before this use case delivers value, the following must be operational:

- **Structured alert data with consistent fields.** Alert logs must be in a normalized schema (ECS, CIM, ASIM) with reliable field population for entity fields — hostname, username, process fields, network tuples, cloud API actions. If your fields are missing or inconsistent, fix the ingest pipeline. This is a data engineering problem.
- **Detection rules with MITRE ATT&CK metadata.** Every rule must have technique and tactic mappings in structured, parseable metadata. In Elastic, this is the `[[rule.threat]]` TOML block. In Sigma, the `tags` field with `attack.tXXXX` values. In Splunk Security Content, the `tags.mitre_attack` YAML field. If your rules lack MITRE mappings, that is a rule content gap — not an AI problem.
- **Alert volume history.** At least 30 days (ideally 90) of alert data to compute meaningful signal quality metrics. Short windows produce unreliable scores.
- **Entity field availability per data source domain.** You must know which entity fields are meaningful for each data source domain (see [Domain-Aware Entity Framework](../../concepts/domain-aware-entity-framework.md)). Endpoint rules are scored on host/user/process diversity; network rules on source/destination/port diversity; identity rules on user/application/action diversity.
- **Rule inventory accessible programmatically.** Rules must be queryable via API or parseable from version control. In Elastic, the Detection Rules API. In Sigma, the YAML files in your Git repo. In Splunk, the REST API or the `security_content` repo.

## Where AI Adds Value

AI contributes in three specific, bounded areas — everything else is deterministic computation:

### 1. Per-Technique Health Narrative Generation

After deterministic scoring produces a Signal Quality Score for every rule and a Detection Confidence Score for every technique, an LLM generates human-readable health assessments that explain *what the numbers mean operationally*. A score of 42 for T1059.001 tells you it is "Degraded." The narrative tells you *why* and *what to do about it*.

Example narrative:

> **T1059.001 — PowerShell (Confidence: 42 — Degraded)**
>
> Covered by 6 rules across 2 domains (Windows Endpoint, EDR). Two rules are healthy: "Suspicious PowerShell Encoded Command" (SQ: 87) shows strong entity diversity across 340 unique hosts with no single entity exceeding 4% of volume. "PowerShell Download Cradle Detected" (SQ: 78) fires rarely but against diverse targets. Two rules are degraded by noise: "PowerShell Script Block Logging — Suspicious Content" (SQ: 38) is dominated by SVC-DEPLOY on BUILD-SVR-01 through BUILD-SVR-08 (72% of volume) — legitimate build automation. "Encoded PowerShell Process" (SQ: 34) shows similar build server concentration. One rule is effectively abandoned: "PowerShell Execution via WMI" (SQ: 14) has fired 3 times in 90 days, all from the same host, suggesting the telemetry feeding it has degraded. One rule appears to have lost telemetry entirely: "PowerShell Remoting Inbound Connection" (SQ: 0) has been silent for 47 days despite peer rules on the same data source remaining active.
>
> **Recommendation:** Tune the two degraded rules to exclude build server infrastructure (projected volume reduction: 68%). Investigate telemetry loss on "PowerShell Remoting Inbound Connection" — likely a Sysmon configuration regression. After tuning, projected confidence rises to 71 (Functional).

This narrative requires reasoning about what each rule does, why specific entity patterns indicate noise vs. signal degradation, and what targeted actions would improve the score. A deterministic system cannot generate this.

### 2. Observable Diversity Assessment

Multiple rules mapped to the same ATT&CK technique may all detect the same narrow artifact. If all six PowerShell rules look for `powershell.exe` in the process name field, the technique appears well-covered but is trivially evaded by renaming the binary or using `pwsh.exe`.

An LLM reads each rule's query logic and assesses whether the rules detect genuinely different observables:

> **Observable Diversity Assessment for T1059.001:**
>
> - **Process execution patterns:** 3 rules (detect process name, parent-child relationships, command line content)
> - **Script block content:** 1 rule (detects suspicious strings within PowerShell script blocks — deeper visibility than process-level)
> - **Network behavior:** 1 rule (detects PowerShell initiating outbound connections — behavioral, not artifact-based)
> - **WMI-based execution:** 1 rule (detects PowerShell launched via WMI — lateral movement vector)
>
> **Assessment:** Good observable diversity. Rules cover process-level, script-level, network-level, and lateral execution vectors. An attacker would need to evade multiple detection layers. However, 3 of 6 rules rely on `process.name: powershell.exe` as a primary condition — consider adding rules that detect PowerShell behavior by script block content alone, independent of process name.

This requires semantic understanding of query logic — what each rule actually looks for, not just what fields it references. A deterministic parser can extract field names from queries; it cannot reason about whether two different query patterns detect the same attacker behavior.

### 3. Executive Summary Synthesis

Aggregating the full posture into a narrative for CISO-level consumption:

> **MITRE ATT&CK Detection Posture — Q1 2026 Executive Summary**
>
> Your detection program covers 187 of 201 ATT&CK techniques applicable to your environment. Of the 187 covered techniques, 68 are rated Strong or Functional, 71 are Degraded, 34 are Abandoned, and 14 have some rule coverage but are effectively Blind due to telemetry or noise issues.
>
> **Strongest areas:** Initial Access (82% of techniques at Functional or above), Credential Access (76%). Your phishing and credential theft detection capabilities are mature.
>
> **Critical gaps:** Lateral Movement (only 31% Functional or above — 5 of 16 techniques). This means you reliably detect how attackers get in and what they steal, but lose visibility once they move off the initial foothold. Defense Evasion coverage is broad (22 techniques) but shallow — 15 of 22 are Degraded, primarily due to noisy rules that analysts ignore.
>
> **Top 3 investments for Q2:**
> 1. Tune 12 high-volume Degraded rules in Defense Evasion — projected to elevate 9 techniques to Functional with estimated 40 hours of engineering effort.
> 2. Deploy lateral movement telemetry (SMB, WMI, RDP session logging) to address the 5 Blind techniques in that tactic.
> 3. Investigate the 34 Abandoned rules — 11 appear to have lost telemetry silently and may indicate data source regressions.

## AI Approach

**Hybrid deterministic + LLM pipeline:**

1. **Deterministic scoring engine** computes all metrics and scores. No AI involved in the math.
2. **LLM narrative generation** via structured prompting with few-shot examples. The LLM receives the scored data as structured input (JSON) and generates narratives following a defined template.
3. **LLM observable diversity assessment** via semantic analysis of rule query logic. The LLM receives rule queries and assesses detection overlap.
4. **LLM executive synthesis** via summarization prompting with posture data and historical trend context.

Prompt architecture:
- System prompt establishes the role (detection engineering analyst) and output format requirements.
- Structured data injection: per-rule scores, per-technique rollups, historical trends as JSON.
- Few-shot examples: 2-3 example narratives per output type to establish tone and specificity.
- Output format enforcement: structured sections with headers, specific recommendations, projected impacts.

## Data Requirements

### Inputs

| Input | Format | Key Fields Used |
|---|---|---|
| SIEM alert logs (30-90 days) | Platform alert schema (ECS, CIM, ASIM) | `rule.id`, `rule.name`, `host.name`, `user.name`, `process.name`, `process.command_line`, `source.ip`, `destination.ip`, `event.action`, `@timestamp` |
| Detection rule files | Elastic TOML / Sigma YAML / Splunk YAML | Rule ID, name, query/search, `threat` mappings (technique ID, tactic), `severity`, data source declarations |
| MITRE ATT&CK framework | STIX 2.1 JSON (from ATT&CK TAXII or static export) | Technique IDs, tactic mappings, technique descriptions, data source mappings |
| Domain entity configuration | YAML configuration (custom) | Per-domain entity field definitions, weight configurations, tier assignments (primary/secondary/supporting) |
| Historical posture scores (optional) | JSON/CSV from previous scoring runs | Prior period technique scores for trend analysis |

> **Note:** Alert data follows the SIEM's standard alert schema with normalized source event fields. Rule files follow their format's defined schema (Elastic TOML, Sigma YAML, Splunk YAML, etc.). These are structured, documented formats — see [data-requirements/](../../data-requirements/) for platform-specific field references.

### Outputs

Three output tiers, each with concrete examples:

**Tier 1: Per-Rule Signal Quality Report Card**

```
Rule: "Suspicious PowerShell Encoded Command"
Rule ID: endpoint-rule-0047
Technique: T1059.001 (PowerShell)
Domain: Windows Endpoint
Period: 2025-12-01 to 2026-02-14

Signal Quality Score: 87 / 100

Dimension Breakdown:
  Entity Diversity (host.name):     92  | 340 unique hosts, no single host > 4%
  Entity Diversity (user.name):     85  | 128 unique users, top user at 7%
  Entity Diversity (process.parent): 78  | 42 unique parent processes
  Concentration (top-10):           88  | Top 10 entities = 18% of volume (healthy)
  Entropy (host.name):              90  | 7.2 bits (near-uniform distribution)
  Volume Stability:                 82  | 12.4 alerts/day avg, CV = 0.31
  Periodicity:                      95  | No significant periodic pattern detected
  Co-occurrence:                    84  | 34% of alerts co-occur with other rules on same entity
  Cross-Domain Correlation:         78  | 12% of triggering entities also appear in network domain alerts
  Data Source Health:               94  | Source log volume stable, no gaps detected

Tier: Strong
Trend: Stable (was 84 last period)
```

**Tier 2: Per-Technique Detection Confidence Summary**

```
Technique: T1059.001 — Command and Scripting Interpreter: PowerShell
Tactic: Execution
Detection Confidence Score: 42 / 100
Tier: Degraded

Contributing Rules:
  Rule                                          | SQ Score | Status
  ----------------------------------------------|----------|----------
  Suspicious PowerShell Encoded Command          |    87    | Healthy
  PowerShell Download Cradle Detected            |    78    | Healthy
  PowerShell Script Block — Suspicious Content   |    38    | Degraded (noise)
  Encoded PowerShell Process                     |    34    | Degraded (noise)
  PowerShell Execution via WMI                   |    14    | Abandoned
  PowerShell Remoting Inbound Connection         |     0    | Blind (silent 47d)

Observable Diversity: 0.72 (Good — 4 distinct detection angles)
Domain Breadth: 1.0 (Single domain — Windows Endpoint only)
Silence Penalty: Applied (1 rule silent > 30 days)

Weighted Confidence Calculation:
  Base (weighted avg of healthy rules):  61
  Observable diversity multiplier:       x1.15
  Domain breadth multiplier:             x1.0 (single domain, no bonus)
  Silence penalty:                       -8
  Abandoned rule drag:                   -12
  Noise-degraded rule drag:              -9
  Final Score:                           42

[AI-generated narrative appears here — see example in "Where AI Adds Value" section]
```

**Tier 3: Executive Posture Narrative**

See the executive summary example in the "Where AI Adds Value" section above. This is a full-page narrative synthesizing posture across all tactics, identifying strongest and weakest areas, and providing prioritized investment recommendations with projected impact.

## Implementation Notes

### Scoring Architecture

The scoring engine is entirely deterministic. No AI/ML is used in score computation.

**Signal Quality Score (per rule, 0-100):**

Each dimension is normalized to 0-100 and weighted by domain. Weights vary because what constitutes "healthy" signal differs by data source:

| Dimension | Endpoint Weight | Network Weight | Identity Weight | Cloud Weight |
|---|---|---|---|---|
| Entity Diversity (primary field) | 0.20 | 0.20 | 0.25 | 0.20 |
| Entity Diversity (secondary field) | 0.10 | 0.15 | 0.15 | 0.15 |
| Concentration (top-10) | 0.15 | 0.15 | 0.15 | 0.15 |
| Entropy | 0.10 | 0.10 | 0.10 | 0.10 |
| Volume Stability | 0.10 | 0.10 | 0.10 | 0.10 |
| Periodicity | 0.10 | 0.05 | 0.05 | 0.05 |
| Co-occurrence | 0.10 | 0.10 | 0.10 | 0.10 |
| Cross-Domain Correlation | 0.05 | 0.05 | 0.05 | 0.05 |
| Data Source Health | 0.10 | 0.10 | 0.05 | 0.10 |

**Detection Confidence Score (per technique, 0-100):**

1. Compute weighted average of Signal Quality Scores for all rules mapped to the technique. Weight by rule health tier (Strong rules weighted more heavily than Degraded).
2. Apply Observable Diversity Multiplier (1.0-1.3): bonus for rules that detect different artifacts of the same technique. Computed by LLM assessment, cached per technique.
3. Apply Domain Breadth Multiplier (1.0-1.2): bonus for rules spanning multiple data source domains.
4. Apply Silence Penalty: deduction for rules silent beyond expected threshold.
5. Apply Abandoned/Blind Drag: deduction proportional to the fraction of rules in low tiers.
6. Clamp to 0-100.

**Confidence Tiers:**

| Tier | Score Range | Meaning |
|---|---|---|
| Strong | 80-100 | Reliable, diverse detection. High confidence of catching this technique. |
| Functional | 60-79 | Working detection with room for improvement. Adequate for most scenarios. |
| Degraded | 40-59 | Detection exists but is compromised by noise, low diversity, or partial telemetry loss. May miss attacks. |
| Abandoned | 20-39 | Rules exist but produce minimal useful signal. Detection is nominal, not operational. |
| Blind | 0-19 | No meaningful detection capability. Rules may be mapped but are silent or broken. |

### LLM Integration Points

- **Narrative generation** runs as a batch process after scoring completes. Not real-time.
- **Observable diversity assessment** can be cached — it only changes when rules are modified. Run on rule change events or weekly.
- **Executive summaries** are generated on-demand or on a scheduled cadence (monthly/quarterly).
- Use structured output parsing (JSON mode or function calling) to enforce consistent narrative format.
- Temperature 0.2-0.3 for consistency across runs. Higher temperature produces more varied phrasing but less predictable structure.

### Technical Stack

- **Scoring engine:** Python (Pandas, NumPy, SciPy for entropy calculations). No ML libraries needed for scoring.
- **SIEM queries:** Elasticsearch aggregations API, Splunk REST API, or Sentinel KQL API for alert metric extraction.
- **Rule parsing:** Platform-specific parsers (TOML for Elastic, YAML for Sigma/Splunk). pySigma for Sigma rule parsing.
- **LLM integration:** Anthropic API (Claude) or equivalent. Structured prompting with JSON input/output.
- **ATT&CK data:** `mitreattack-python` library or direct STIX 2.1 parsing.
- **Output:** Markdown reports, JSON for programmatic consumption, optional ATT&CK Navigator layer export.

## Dependencies

- [Signal Quality Scoring](../../concepts/signal-quality-scoring.md) — full methodology for per-rule scoring dimensions and normalization.
- [Detection Confidence Scoring](../../concepts/detection-confidence-scoring.md) — rollup methodology from rule-level to technique-level.
- [Domain-Aware Entity Framework](../../concepts/domain-aware-entity-framework.md) — defines which entity fields are scored per data source domain.
- [Entity Cardinality as FP Proxy](../../concepts/entity-cardinality-as-fp-proxy.md) — theoretical foundation for using entity diversity as a signal quality indicator.
- UC-01 (Detection Performance Analytics) — produces the per-rule alert metrics that feed into Signal Quality scoring.
- UC-02 (Entity Cardinality Noise Analysis) — provides the entity distribution analysis used in scoring dimensions.

## Complexity Assessment

| Dimension | Rating | Notes |
|---|---|---|
| Data engineering | High | Requires aggregation queries across all rules and all entity fields, per domain. At 4,000+ rules, this is a significant data pipeline. Must handle missing fields, sparse data, and cross-domain normalization. |
| AI/ML complexity | Medium | LLM prompting with structured input — no model training. Complexity is in prompt engineering for consistent, accurate narratives across thousands of technique assessments. Observable diversity assessment is the hardest LLM task — requires genuine understanding of query semantics. |
| Integration effort | High | Requires API access to SIEM (alert data), rule repository (rule metadata and queries), and ATT&CK framework data. Output integration into reporting tools, dashboards, or ATT&CK Navigator. |
| Overall | **High** | This is the most data-intensive use case in the posture assessment category. The scoring engine alone is a significant engineering effort. The AI layer adds narrative quality but depends entirely on the deterministic foundation being solid. |

## Real-World Considerations

**Score calibration takes iteration.** The first scoring run will produce results that feel wrong — rules you know are healthy will score low because of unexpected entity patterns, and rules you know are noisy will score medium because they happen to fire against diverse entities. Expect 3-5 calibration cycles adjusting dimension weights per domain before scores align with practitioner intuition. This is normal and necessary.

**Observable diversity assessment is the hardest LLM task.** Getting an LLM to accurately assess whether two KQL queries detect the same attacker behavior requires careful prompting with query language context. Expect ~80% accuracy initially. Build in human review for the observable diversity assessment — let detection engineers correct the LLM's understanding and use those corrections to improve prompts.

**Silence is not always failure.** A rule that fires zero times in 90 days might be perfectly healthy — it detects rare attacker behavior that simply did not occur. The scoring model penalizes silence, which creates false negatives for legitimately rare detections. Mitigation: tag rules as "expected low volume" in rule metadata and suppress the silence penalty for those rules.

**Scale matters.** At 4,000+ rules across 200+ techniques, the narrative generation pass produces substantial LLM token volume. Budget for it. Batch processing with caching (regenerate narratives only for techniques whose scores changed) keeps costs manageable.

**Organizational adoption requires trust.** Engineers will distrust scores that contradict their intuition. Start with a small set of well-understood rules, validate that scores match reality, and expand. Publishing scores that engineers immediately dispute destroys credibility and is hard to recover from.

**Beware the "green heatmap" trap.** Executives love green heatmaps. If your scoring model is too generous, every technique lights up green and the posture report becomes meaningless. Calibrate thresholds to ensure the Degraded and Abandoned tiers are populated — a posture report that shows 90% Strong is either wrong or your detection program is genuinely exceptional (it probably is not).

## Related Use Cases

- [UC-01: Detection Performance Analytics](../alert-analysis/01-detection-performance-analytics.md) — produces the per-rule metrics that feed Signal Quality scoring.
- [UC-02: Entity Cardinality Noise Analysis](../alert-analysis/02-entity-cardinality-noise-analysis.md) — detailed entity distribution analysis used in scoring dimensions.
- [UC-04: Detection Drift Monitoring](../alert-analysis/04-detection-drift-monitoring.md) — detects the telemetry loss and rule silence that degrades posture scores.
- [UC-07: Threat-Informed Gap Prioritization](07-threat-informed-gap-prioritization.md) — uses posture scores to prioritize gaps against specific threat actors.
- [UC-08: Kill Chain Completeness Analysis](08-kill-chain-completeness-analysis.md) — uses posture scores to assess detection across attack stages.
- [UC-09: Cross-Domain Detection Coverage](09-cross-domain-detection-coverage.md) — uses posture scores to evaluate multi-domain detection quality.
- [UC-10: Executive Posture Reporting](10-executive-posture-reporting.md) — consumes posture scores and narratives for leadership reporting.
- [UC-22: Detection Program Health Reporting](../strategic/22-detection-program-health-reporting.md) — incorporates posture scoring into program-level health metrics.

## References

- [MITRE ATT&CK Framework](https://attack.mitre.org/) — technique and tactic definitions.
- [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) — visualization tool for ATT&CK coverage layers.
- [DeTT&CT](https://github.com/rabobank-cdc/DeTTECT) — framework for scoring detection and visibility against ATT&CK. Inspiration for the scoring model, though DeTT&CT uses manual assessment rather than automated signal quality metrics.
- [Elastic Detection Rules](https://github.com/elastic/detection-rules) — example of structured rule repository with MITRE mappings in TOML format.
- [SigmaHQ](https://github.com/SigmaHQ/sigma) — community detection rules with ATT&CK tags.
- [Splunk Security Content](https://github.com/splunk/security_content) — Splunk detection rules with MITRE mappings.
- [mitreattack-python](https://github.com/mitre-attack/mitreattack-python) — Python library for working with ATT&CK STIX data.
- [Signal Quality Scoring](../../concepts/signal-quality-scoring.md) — detailed scoring methodology referenced in this use case.
- [Detection Confidence Scoring](../../concepts/detection-confidence-scoring.md) — rollup methodology from rule-level to technique-level scoring.
