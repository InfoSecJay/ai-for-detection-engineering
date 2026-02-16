# UC-10: Executive Posture Reporting

## Category

Posture Assessment

## Summary

Transforms scored detection posture data into leadership-consumable narratives — quarterly trend reports, business-risk-framed gap summaries, industry benchmark comparisons, and investment recommendations. This is almost entirely an LLM use case. The technical metrics are computed deterministically by UC-06 through UC-09. The AI generates the narrative layer that makes those metrics actionable for CISOs, VPs, and board-level audiences who do not read ATT&CK heatmaps or Signal Quality Score breakdowns.

## Problem Statement

Detection engineering teams produce excellent technical data — posture scores, coverage percentages, gap analyses, drift reports. Almost none of this data reaches leadership in a form they can act on. The CISO asks "how is our detection posture?" and gets either a green heatmap that obscures real problems or a spreadsheet of technique scores that requires a detection engineering degree to interpret.

The translation gap is not a data problem — the data exists. It is a communication problem. Technical metrics must be reframed in terms leadership understands: business risk, investment ROI, competitive benchmarking, regulatory compliance, and trend direction. A Detection Confidence Score of 31 for Lateral Movement means nothing to a CISO. "An attacker who compromises one of our endpoints can move freely across the network because our lateral movement detection is functionally broken — and this is the primary operational technique used by the adversary group targeting Canadian telecom" is a statement that drives budget decisions.

This translation requires synthesizing quantitative metrics with business context, regulatory landscape, threat intelligence, and organizational priorities. It requires generating prose that is accurate, appropriately caveated, and calibrated to the audience's technical depth. This is a natural language generation task that deterministic tooling cannot perform.

## Prerequisites (What Your SIEM/SOAR Should Already Handle)

- **Scored posture data from UC-06.** Detection Confidence Scores per technique, confidence tiers, Signal Quality breakdowns, observable diversity ratings. This is the quantitative foundation. Without it, the executive report has nothing to synthesize.
- **Threat-informed gap analysis from UC-07.** Prioritized gap lists with adversary relevance and remediation recommendations. This provides the "so what?" context that transforms a score sheet into a risk narrative.
- **Kill chain analysis from UC-08.** Detection breakpoint identification and chain integrity assessments. This provides the operational impact framing that resonates with leadership.
- **Cross-domain coverage analysis from UC-09.** Domain dependency data and single-point-of-failure identification. This provides the resilience framing.
- **Historical posture data.** At least one prior period's posture scores for trend analysis. Quarterly cadence is standard — the report shows Q-over-Q changes and progress toward goals.
- **Organizational context.** Business priorities, regulatory requirements, risk appetite, recent incidents, budget cycle timing, industry vertical. This context is manually maintained and updated — it is what transforms generic posture reporting into organization-specific executive communication.

None of the above prerequisites involve AI. They are all outputs of deterministic scoring (UC-06) or structured analysis (UC-07, UC-08, UC-09), plus organizational knowledge that the detection engineering team maintains.

## Where AI Adds Value

This use case is almost entirely an LLM generation task. The AI takes structured quantitative data and organizational context and produces four categories of executive output:

### 1. Quarterly Trend Narratives

> **Detection Posture Trend — Q4 2025 to Q1 2026**
>
> Overall detection confidence improved from 47.2 to 53.8 across 187 covered techniques, driven primarily by targeted rule tuning in the Execution and Defense Evasion tactics. This is the largest quarter-over-quarter improvement since posture scoring was implemented in Q2 2025.
>
> **What improved:**
> - 14 techniques moved from Degraded to Functional tier, primarily through exclusion tuning that removed build server noise from endpoint detection rules. This was the single highest-ROI activity of the quarter — 40 hours of engineering effort elevated 14 techniques.
> - Credential Access coverage improved from 44 to 58 (Degraded to nearly Functional) after deploying behavioral LSASS access detection rules that are tool-agnostic rather than signature-based.
> - Identity domain coverage expanded from 38 to 46 techniques with new Okta detection rules for session hijacking and MFA bypass.
>
> **What did not improve:**
> - Lateral Movement remains at 31 (Abandoned tier) — the most critical gap in our posture. Remediation was deprioritized due to competing project commitments. This remains the #1 recommended investment for Q2.
> - 7 techniques regressed from Functional to Degraded due to a Sysmon configuration change that reduced process command-line logging fidelity on 1,200 servers. This was identified by drift monitoring (UC-04) but remediation is pending infrastructure team action.
>
> **Net assessment:** Positive trajectory. The detection program is measurably improving. However, the Lateral Movement gap represents a structural risk that is not being addressed at the pace the threat landscape requires. Recommend elevating this to a Q2 priority with dedicated engineering allocation.

### 2. Business-Risk-Framed Gap Summaries

> **Detection Gaps Framed by Business Risk**
>
> **Risk 1: Post-Compromise Blindness (Lateral Movement — Confidence: 31)**
> *Business impact:* If an attacker breaches a single endpoint, our current detection will identify the initial compromise but will not track the attacker as they move to additional systems. Mean time from initial compromise to lateral movement for targeted attacks is typically 1-4 hours. Our current triage SLA for endpoint alerts is 2 hours. This means the attacker reaches additional systems before we investigate the first alert.
> *Financial exposure:* Based on industry data for breaches involving undetected lateral movement in organizations of our size and sector, estimated incident cost ranges from $2.4M to $8.1M (including investigation, remediation, regulatory notification, and business disruption).
> *Remediation cost:* Approximately $45K in engineering effort (120 hours) plus $12K in additional telemetry licensing for SMB and RDP session monitoring.
> *Risk-to-remediation ratio:* Extremely favorable. $57K investment against $2.4M+ potential exposure.
>
> **Risk 2: Credential Theft Detection Is Tool-Specific (Credential Access — Confidence: 44)**
> *Business impact:* Our credential access detection catches known tools (Mimikatz, LaZagne) but misses the same techniques executed with custom tooling. Targeted adversaries — including the APT group profiled in our Q1 threat assessment — predominantly use custom tools. Our detection creates a false sense of security: we detect commodity attacks but miss targeted ones.
> *Remediation cost:* Approximately $20K in engineering effort (50 hours) to deploy behavioral detection rules based on API call patterns rather than tool signatures.
>
> **Risk 3: Single-Domain Dependency for 55% of Techniques**
> *Business impact:* 104 of our 187 covered techniques rely on detection from a single data source domain (primarily Windows Endpoint via SentinelOne). An outage, misconfiguration, or adversary evasion of this single telemetry source would eliminate detection for over half our coverage. This concentration risk is analogous to having all backup systems in one data center.
> *Remediation cost:* Long-term investment — estimated 200 engineering hours over 2 quarters to expand cross-domain coverage for the 30 highest-priority single-domain techniques.

### 3. Industry Benchmark Comparisons

> **Detection Posture vs. Industry Benchmarks**
>
> *Note: Industry benchmarks are derived from published data (MITRE Engenuity evaluations, vendor reports, and peer community sharing). Exact comparisons are approximate — no two organizations score detection posture the same way. These benchmarks provide directional context, not precise rankings.*
>
> | Metric | Our Posture | Industry Median (Telecom) | Top Quartile |
> |---|---|---|---|
> | Techniques covered | 187 / 201 (93%) | ~160 / 201 (80%) | ~185 / 201 (92%) |
> | Techniques at Functional+ | 68 (36%) | ~55 (34%) | ~90 (49%) |
> | Average confidence score | 53.8 | ~48 | ~62 |
> | Lateral Movement confidence | 31 (Abandoned) | ~40 (Degraded) | ~65 (Functional) |
> | Cross-domain coverage (2+ domains) | 44% | ~35% | ~55% |
>
> **Interpretation:** Our coverage breadth (93% of techniques) is above median and at the top quartile threshold. However, our coverage depth (36% at Functional or above) is near median and significantly below top quartile. We have broad but shallow detection — many rules exist but too many are degraded by noise or abandoned. The industry top quartile achieves nearly 50% Functional or above, suggesting that organizations investing in rule quality (not just rule quantity) gain significant advantage.
>
> **Lateral Movement is below median.** At 31, our lateral movement detection is below the telecom industry median of 40. This is notable because lateral movement is the tactic most strongly correlated with breach severity in the telecom sector. Peer organizations at the top quartile achieve Functional-tier lateral movement detection.

### 4. Investment Recommendations

> **Q2 2026 Detection Engineering Investment Recommendations**
>
> Ranked by risk-adjusted ROI:
>
> | Priority | Investment | Effort | Cost Est. | Projected Impact | Risk Addressed |
> |---|---|---|---|---|---|
> | 1 | Lateral movement rule tuning + telemetry deployment | 120 hrs | $57K | Blind (31) to Degraded (48) | Post-compromise blindness |
> | 2 | Behavioral credential access detection | 50 hrs | $20K | Degraded (44) to Functional (62) | Tool-specific detection gap |
> | 3 | Cross-domain expansion (top 15 single-domain techniques) | 80 hrs | $32K | 15 techniques gain multi-domain coverage | Single-domain dependency |
> | 4 | Noise tuning sprint (Defense Evasion) | 40 hrs | $16K | 9 techniques Degraded to Functional | Alert fatigue in evasion detection |
> | 5 | Sysmon configuration remediation (cross-team) | 20 hrs | $8K | Recover 7 regressed techniques | Telemetry regression |
>
> **Total Q2 investment:** 310 engineering hours, ~$133K
> **Projected Q2 posture:** Overall confidence from 53.8 to ~64.2 (+19.3%), Functional+ techniques from 68 to ~97 (+42.6%)
>
> **If budget is constrained to one initiative:** Prioritize #1 (lateral movement). It addresses the highest business risk, has the most favorable cost-to-exposure ratio, and directly mitigates the primary attack vector used by the adversary group targeting our sector.

## AI Approach

**LLM narrative generation from structured data:**

This use case is a straightforward — but non-trivial — natural language generation task. The LLM receives:

1. **Structured posture data** (JSON): per-technique scores, tier distributions, domain coverage, trend data, gap prioritization.
2. **Organizational context** (structured profile): industry, regulatory requirements, budget cycle, risk appetite, recent incidents, leadership priorities.
3. **Report template** (prompt): output format, section structure, tone calibration, audience specification.
4. **Few-shot examples**: 2-3 example report sections that establish the desired level of specificity, appropriate use of caveats, and business-risk framing.

**Prompt engineering considerations:**

- **Audience calibration:** The prompt specifies the target audience (CISO, VP Security, Board). CISO reports can reference ATT&CK tactics by name. Board reports should not — translate to business language ("attackers who break in can move freely across our network" rather than "Lateral Movement tactic coverage is Abandoned tier").
- **Appropriate caveats:** The LLM must include appropriate uncertainty language. "Industry benchmarks are approximate" not "we are ranked #3 in telecom." "Estimated financial exposure based on industry data" not "this will cost $5M."
- **Actionable specificity:** Every finding must include a recommendation. "Lateral Movement is weak" is an observation. "Invest 120 engineering hours in lateral movement tuning and telemetry deployment to elevate from Blind to Degraded" is actionable.
- **Intellectual honesty:** The LLM must not generate flattering narratives that obscure real problems. If posture is weak, the report says so clearly. Prompt: "Do not soften findings. Leadership needs accurate assessments to make informed investment decisions. A report that hides problems is worse than no report."

**Multi-pass generation for quality:**

1. **First pass:** Generate raw narrative from structured data.
2. **Validation pass:** Check all numbers in the narrative against the source data. LLMs sometimes hallucinate statistics — validate every number cited.
3. **Tone calibration pass:** Adjust language for target audience.
4. **Final review:** Human detection engineer reviews for accuracy and appropriate framing before distribution.

## Data Requirements

### Inputs

| Input | Format | Key Fields Used |
|---|---|---|
| Detection Confidence Scores (from UC-06) | JSON | Technique ID, tactic, confidence score, tier, contributing rule count, observable diversity rating |
| Signal Quality Scores (from UC-06) | JSON | Rule ID, SQ score, tier, dimension breakdowns |
| Threat-informed gap analysis (from UC-07) | JSON/Markdown | Prioritized gap list, adversary profiles, remediation recommendations, effort estimates |
| Kill chain analysis (from UC-08) | JSON/Markdown | Detection breakpoints, chain integrity scores, adversary path analyses |
| Cross-domain coverage (from UC-09) | JSON/Markdown | Domain distribution, single-domain technique list, complementarity assessments |
| Historical posture data | JSON | Prior period scores for trend computation |
| Organizational context profile | YAML/JSON | Industry, geography, regulatory frameworks, risk appetite, budget constraints, leadership priorities, recent incidents |
| Industry benchmark data (optional) | JSON/CSV | Peer organization posture metrics (from vendor reports, community sharing, MITRE Engenuity evaluations) |

> **Note:** Alert data follows the SIEM's standard alert schema with normalized source event fields. Rule files follow their format's defined schema (Elastic TOML, Sigma YAML, Splunk YAML, etc.). These are structured, documented formats — see [data-requirements/](../../data-requirements/) for platform-specific field references.

### Outputs

Four output document types, all generated as Markdown or PDF:

**1. Quarterly Posture Trend Report** (2-4 pages)
- Overall score trend with Q-over-Q delta.
- Top improvements and regressions with root cause explanations.
- Progress against prior quarter's goals.
- Net assessment and outlook.

**2. Business Risk Gap Summary** (2-3 pages)
- Top 5 detection gaps framed as business risks.
- Financial exposure estimates where applicable.
- Remediation cost and risk-to-remediation ratio.
- Compensating controls and residual risk.

**3. Industry Benchmark Comparison** (1-2 pages)
- Posture metrics compared to industry medians and top quartile.
- Directional positioning with appropriate caveats.
- Areas above and below benchmark.

**4. Investment Recommendation Brief** (1-2 pages)
- Prioritized investment table with effort, cost, projected impact.
- Constrained-budget recommendation (if only one initiative).
- Projected posture improvement with visualization guidance.

**Combined output: Executive Posture Package** — all four documents assembled into a single presentation-ready package with consistent formatting and cross-references.

Example combined executive summary (first page):

```
DETECTION POSTURE — EXECUTIVE SUMMARY — Q1 2026

Overall Confidence: 53.8 / 100  (up from 47.2 in Q4 — +14.0%)
Techniques Covered: 187 / 201  (93%)
Functional or Above: 68 / 187  (36%, up from 54 / 187 in Q4)

Strongest: Initial Access (82%), Credential Access (76% — improved from 58%)
Weakest: Lateral Movement (31% — unchanged, #1 recommended investment)

Key Metric:   If an attacker gets past initial access, we have a 69%
              probability of losing them before they reach their objective.
              (Based on kill chain integrity analysis across 4 relevant
              adversary profiles.)

Q2 Recommended Investment: $133K / 310 engineering hours
Projected Q2 Posture: 64.2 / 100 (+19.3%)

Top Risk: Post-compromise lateral movement blindness.
          Estimated financial exposure: $2.4M-$8.1M.
          Remediation cost: $57K. Risk-to-remediation ratio: 42:1 to 142:1.
```

## Implementation Notes

**Report cadence and triggering.** Executive posture reports are generated on a fixed cadence — monthly for operational summaries, quarterly for comprehensive trend reports, annually for board-level assessments. Ad hoc generation is triggered by: major posture score changes (>10 point swing in any tactic), new threat intelligence about relevant adversaries, or leadership requests.

**Number validation is non-negotiable.** LLMs hallucinate statistics. Every number in the executive report — scores, percentages, technique counts, financial estimates, effort projections — must be validated against the source data programmatically before the report is finalized. Implement a validation pass that extracts all numbers from the generated narrative and cross-references them against the input data. Flag discrepancies for human review.

**Financial exposure estimates require careful sourcing.** Business-risk framing often includes financial exposure estimates. These should be sourced from published industry data (Ponemon/IBM Cost of a Data Breach, Verizon DBIR, sector-specific regulatory penalty schedules) and explicitly cited. Do not let the LLM generate financial estimates from thin air. Provide reference data as input and require the LLM to cite its source for every financial figure.

**Audience-specific variants.** The same underlying posture data may need three different report variants:
- **CISO report:** Technical depth, specific ATT&CK references, engineering recommendations.
- **VP/Executive report:** Business-risk framing, financial exposure, investment ROI.
- **Board report:** Strategic positioning, trend direction, industry comparison, yes/no risk questions ("Can an attacker move freely through our network?").

Generate all variants from the same data by adjusting the prompt's audience specification. Do not maintain three separate pipelines.

**Template evolution.** The report format will evolve as leadership provides feedback on what is useful vs. what is ignored. Build the generation pipeline to support template changes without re-engineering — the prompt template is the primary configuration point, not code logic.

**Integration with existing reporting workflows.** Most CISOs have an established reporting cadence and format. The executive posture report should integrate into existing board packages and security committee presentations rather than creating a parallel reporting stream. Output in formats compatible with the organization's presentation tools (Markdown for conversion to PDF, structured data for PowerPoint slide generation, etc.).

## Dependencies

- [UC-06: MITRE ATT&CK Posture Scoring](06-mitre-attack-posture-scoring.md) — provides all quantitative posture data. Hard dependency. Without UC-06, there is nothing to report on.
- [UC-07: Threat-Informed Gap Prioritization](07-threat-informed-gap-prioritization.md) — provides adversary-contextualized gap analysis. Strongly recommended. Without it, gap summaries lack threat relevance.
- [UC-08: Kill Chain Completeness Analysis](08-kill-chain-completeness-analysis.md) — provides kill chain integrity and detection breakpoint analysis. Strongly recommended. Produces the most impactful executive-level finding ("69% probability of losing the attacker").
- [UC-09: Cross-Domain Detection Coverage](09-cross-domain-detection-coverage.md) — provides domain dependency and resilience analysis. Recommended. Adds the single-point-of-failure narrative.
- [UC-22: Detection Program Health Reporting](../strategic/22-detection-program-health-reporting.md) — overlaps in scope. UC-10 focuses specifically on posture metrics for executive audiences. UC-22 encompasses broader program health including operational metrics (triage velocity, engineering throughput). They should be co-designed to avoid duplication.

## Complexity Assessment

| Dimension | Rating | Notes |
|---|---|---|
| Data engineering | Low | This use case consumes pre-computed outputs from UC-06 through UC-09. No new data engineering required — the complexity is in the upstream use cases. Maintaining the organizational context profile and benchmark data requires manual curation but is not technically complex. |
| AI/ML complexity | Medium | LLM narrative generation is conceptually straightforward but requires careful prompt engineering for: audience calibration, appropriate caveats, intellectual honesty, actionable specificity, and consistent quality across report sections. Number validation and fact-checking against source data adds implementation complexity. Multi-pass generation (generate, validate, refine) is necessary for production quality. |
| Integration effort | Low-Medium | Output is document generation — Markdown, PDF, or structured data for presentation tools. No SIEM or API integration needed. Integration with existing reporting workflows (SharePoint, Confluence, email distribution) may require format adaptation. |
| Overall | **Medium** | The technical complexity is moderate — primarily prompt engineering and validation pipelines. The organizational complexity is higher: getting the report format, tone, and content right for your specific leadership audience takes iteration and feedback cycles. The first version will not be perfect. Plan for 3-4 revision cycles with leadership feedback before the report stabilizes. |

## Real-World Considerations

**The first report will be wrong in tone, not in data.** The numbers will be accurate (assuming UC-06 is calibrated). But the framing will be off — too technical, too alarmist, too soft, wrong level of detail for the audience. Plan for the first 2-3 reports to be iterative drafts that incorporate leadership feedback. The LLM generates the draft; the detection engineering lead reviews and adjusts; leadership provides feedback; the prompt template is refined. This is normal.

**Avoid the "AI wrote this" credibility trap.** If leadership knows the report is AI-generated and encounters any error, credibility collapses. Two mitigations: (1) Always have a detection engineer review and approve the report before distribution. The engineer is the author; the LLM is the drafting tool. (2) Validate every number. A single wrong statistic in a board report will permanently damage the program's credibility.

**Benchmark data is hard to get and easy to misuse.** Industry benchmarks for detection posture are sparse, inconsistent, and based on different scoring methodologies. MITRE Engenuity evaluations test specific vendors against specific adversary emulations — they are not posture benchmarks. Vendor reports have selection bias. Peer community sharing (ISACs, vendor user groups) is the best source but varies in quality. Always caveat benchmark comparisons heavily. "Directional context" is honest; "we are ranked #3 in telecom" is not.

**Positive trends matter more than absolute scores.** A posture score of 54 means little in isolation — is that good? Bad? Depends on the starting point, the industry, the threat landscape. A posture score that went from 47 to 54 in one quarter tells a clear story: the detection program is improving at a measurable rate, and at this trajectory, the Q4 target of 65 is achievable. Frame reports around trends and progress, not absolute values.

**Budget cycle alignment is critical for investment recommendations.** A report that recommends $133K in Q2 investment needs to arrive before Q2 budget decisions are finalized. If it arrives after, the recommendations are dead on arrival. Align the report cadence with the organization's budget planning cycle. For most organizations, this means the annual posture report with investment recommendations must be ready 2-3 months before the fiscal year starts.

**Resist the urge to generate dashboards.** Executive reports and real-time dashboards serve different purposes. The quarterly narrative report provides strategic context and investment guidance. A dashboard provides operational visibility. The LLM generates narratives, not dashboards. Dashboard design and implementation is a BI/data engineering task that consumes the same underlying data but presents it differently.

## Related Use Cases

- [UC-06: MITRE ATT&CK Posture Scoring](06-mitre-attack-posture-scoring.md) — provides all quantitative posture data that this use case synthesizes into executive narratives.
- [UC-07: Threat-Informed Gap Prioritization](07-threat-informed-gap-prioritization.md) — provides adversary-contextualized gap analysis for risk framing.
- [UC-08: Kill Chain Completeness Analysis](08-kill-chain-completeness-analysis.md) — provides detection breakpoint analysis for operational impact framing.
- [UC-09: Cross-Domain Detection Coverage](09-cross-domain-detection-coverage.md) — provides domain dependency analysis for resilience framing.
- [UC-22: Detection Program Health Reporting](../strategic/22-detection-program-health-reporting.md) — broader program health reporting that incorporates posture metrics alongside operational metrics.
- [UC-01: Detection Performance Analytics](../alert-analysis/01-detection-performance-analytics.md) — produces the per-rule metrics that underpin the posture scoring consumed by this use case.

## References

- [MITRE ATT&CK](https://attack.mitre.org/) — framework referenced throughout posture reporting.
- [MITRE Engenuity ATT&CK Evaluations](https://attackevals.mitre-engenuity.org/) — vendor evaluations against adversary emulations. Useful as directional benchmark data with appropriate caveats.
- [IBM/Ponemon Cost of a Data Breach Report](https://www.ibm.com/security/data-breach) — source data for financial exposure estimates in business-risk framing.
- [Verizon Data Breach Investigations Report (DBIR)](https://www.verizon.com/business/resources/reports/dbir/) — source data for breach patterns and industry-specific risk context.
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework) — detection function mapping. Useful for organizations that report posture in NIST CSF terms rather than ATT&CK.
- Anton Chuvakin, ["Simple to Ask: Is Your SOC AI Ready? Not Simple to Answer!"](https://medium.com/anton-on-security) — foundational work on SOC metrics and AI readiness that informs the measurement approach.
- [Detection Confidence Scoring](../../concepts/detection-confidence-scoring.md) — the scoring methodology whose outputs are synthesized by this use case.
