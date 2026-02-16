# UC-08: Kill Chain Completeness Analysis

## Category

Posture Assessment

## Summary

Analyzes detection coverage across sequential ATT&CK tactics to identify where in an attacker's operational chain your detection breaks down. Deterministic tooling maps rules to tactics in sequence and overlays posture scores. AI adds value by assessing whether detection at each stage is operationally meaningful given real-world posture health, identifying the specific points where an attacker would evade detection, and generating narrative path analyses that map adversary behavior to your detection reality.

## Problem Statement

ATT&CK coverage is typically viewed per technique — do you have rules for T1059.001, T1003.001, T1021.002? But attackers do not execute techniques in isolation. They execute chains: initial access leads to execution, which leads to credential access, which enables lateral movement, which reaches the objective. The operational question is not "do you detect this technique?" but "if an attacker follows this path, at which point do you lose them?"

A SOC might have Strong detection for initial access (spearphishing) and execution (PowerShell) but go Blind at lateral movement. In practice, this means analysts detect the entry and the first payload, then lose the attacker as they move through the network. The alerts fire, the analyst investigates the initial host, finds PowerShell execution, maybe even credential dumping — but the attacker has already moved to three other hosts where no alerts fire. The investigation closes on the initial host while the breach continues.

Identifying these "blind spots in the chain" requires more than listing per-technique scores by tactic. It requires reasoning about how posture health at each stage affects the operational outcome — a Degraded detection at lateral movement is far more dangerous than a Degraded detection at initial access (where multiple overlapping controls often exist). This reasoning about operational impact and attacker decision-making is where deterministic tooling reaches its limits and LLM synthesis adds value.

## Prerequisites (What Your SIEM/SOAR Should Already Handle)

- **Rules mapped to ATT&CK tactics and techniques.** Every rule must have tactic-level mapping (not just technique). In Elastic TOML, this is the `tactic` field within `[[rule.threat]]`. In Sigma, the `attack.` tags include both technique and tactic. Without tactic mappings, you cannot sequence rules along the kill chain.
- **Detection Confidence Scores from UC-06.** This use case layers kill chain analysis on top of scored posture data. Without scores, you can only identify binary presence/absence at each tactic stage — which misses the critical insight that "you have rules for lateral movement but they are all Degraded by noise."
- **Threat actor TTP sequences (from UC-07 or CTI).** Kill chain analysis is most valuable when applied to specific adversary profiles. The sequenced TTPs come from CTI report synthesis (UC-07) or from MITRE ATT&CK Group data.
- **The tactic-to-rule mapping is a deterministic data join.** Grouping rules by tactic, ordering tactics in the ATT&CK sequence (Reconnaissance through Impact), and overlaying scores per tactic — all of this is structured data manipulation. The SIEM or a simple script handles it.

## Where AI Adds Value

### 1. Operational Meaningfulness Assessment

A deterministic system can tell you that Lateral Movement has an average Detection Confidence Score of 31. An LLM assesses what that means operationally:

> **Lateral Movement — Average Confidence: 31 (Abandoned)**
>
> This is your most critical detection gap in the chain. You have 8 rules mapped to lateral movement techniques, but 5 are effectively Abandoned: 3 detect only specific tools (PsExec, Cobalt Strike lateral movement modules) and score low because those tools are rarely used against your environment; 2 are drowned in legitimate SMB traffic noise from file share access by IT operations (entity concentration > 85% from service accounts).
>
> The remaining 3 rules are Degraded: "Remote Service Session Creation" (SQ: 44) detects RDP sessions but fires frequently for legitimate remote administration; "WMI Remote Process Creation" (SQ: 41) shows reasonable entity diversity but low volume suggesting incomplete telemetry coverage; "DCOM Lateral Movement" (SQ: 37) fires exclusively on a monitoring tool.
>
> **Operational impact:** An attacker who achieves credential access on the initial foothold can move laterally with high confidence of evading detection. Your strong Initial Access and Execution detection means you will see them arrive and execute — but the investigation will be confined to the initial host while the attacker operates freely across the network.

### 2. Attack Path Evasion Analysis

The LLM traces an adversary's typical operational sequence through your detection layers and identifies where they would break free:

> **Attack Path Analysis: APT-X Intrusion Pattern**
>
> ```
> Stage 1: Initial Access (Spearphishing) -----> STRONG (86)
>   You detect this. Email rules and endpoint rules both fire.
>   Analyst sees: phishing email alert + suspicious attachment execution.
>
> Stage 2: Execution (PowerShell)  --------------> DEGRADED (42)
>   Partial detection. Encoded command rules fire but are noisy.
>   Analyst sees: PowerShell alert, but it may be lost in build server noise.
>   Risk: Alert fatigue causes analyst to deprioritize or miss.
>
> Stage 3: Credential Access (LSASS) ------------> DEGRADED (44)
>   Partial detection. Mimikatz-specific rules fire but custom tools evade.
>   Analyst sees: credential alert IF attacker uses known tools.
>   Risk: Custom credential harvesting goes undetected.
>
> Stage 4: Lateral Movement (SMB/RDP) -----------> BLIND (8)
>   *** DETECTION BREAKPOINT ***
>   Attacker moves to additional hosts. No actionable alerts fire.
>   Analyst sees: nothing. Investigation stays on initial host.
>
> Stage 5: Collection (Data Staging) ------------> ABANDONED (22)
>   Rules exist but are not operationally useful.
>   Analyst sees: nothing actionable.
>
> Stage 6: Exfiltration --------------------------> FUNCTIONAL (64)
>   DLP and network rules detect large data transfers.
>   Analyst sees: exfiltration alert — but by this point, data is leaving.
> ```
>
> **Critical finding:** Your detection creates a "donut hole" — you see the entry (stages 1-2) and the exit (stage 6), but stages 3-5 are Degraded or worse. An attacker who reaches stage 4 operates with near-impunity until data exfiltration triggers a late-stage alert. The mean time between initial compromise and exfiltration detection could be days or weeks.
>
> **Recommendation:** Close the lateral movement gap first. Even elevating lateral movement from Blind (8) to Degraded (40) would give analysts a signal to follow the attacker beyond the initial foothold.

### 3. Comparative Path Analysis

When multiple adversary profiles are analyzed, the LLM identifies patterns across paths:

> **Cross-Adversary Path Comparison:**
>
> Analyzed 4 adversary profiles relevant to your environment. Lateral movement is the detection breakpoint in 3 of 4 profiles. Defense evasion is the breakpoint in 1 of 4 (APT-Y, which relies heavily on process injection techniques where your coverage is Blind).
>
> **Common weakness:** Regardless of adversary, your detection chain consistently breaks at the transition from "attacker on one host" to "attacker on multiple hosts." This is a structural gap, not an adversary-specific one.

## AI Approach

**Deterministic sequencing + LLM narrative analysis:**

1. **Deterministic tactic ordering:** Map all rules to their tactic positions in the ATT&CK framework sequence. Compute average and weighted Detection Confidence Scores per tactic. This produces a structured "detection health by tactic" table.

2. **Deterministic path construction:** For a given adversary profile, extract the sequence of techniques used and map them to the tactic chain. Overlay per-technique confidence scores from UC-06. This produces a structured "adversary path with detection overlay" table.

3. **LLM operational assessment:** The structured data from steps 1-2 is provided to the LLM with the rule details (which rules contribute to each stage, why they score as they do). The LLM generates:
   - Per-tactic health narrative with operational impact assessment.
   - Attack path trace with detection breakpoint identification.
   - Comparative analysis across multiple adversary paths.
   - Prioritized remediation recommendations focused on the weakest chain links.

4. **LLM visualization guidance:** The LLM generates descriptions suitable for visual representation — color-coded kill chain diagrams, heatmap annotations, and ATT&CK Navigator layer configurations that highlight the path analysis results.

**Prompt design:** The LLM is prompted as a red team analyst assessing detection evasion opportunities. This framing produces more operationally relevant analysis than a defensive framing, because it focuses on where the attacker succeeds rather than where the defender succeeds.

## Data Requirements

### Inputs

| Input | Format | Key Fields Used |
|---|---|---|
| Detection Confidence Scores (from UC-06) | JSON | Technique ID, tactic, confidence score, tier, contributing rules with individual Signal Quality Scores |
| Rule inventory | Elastic TOML / Sigma YAML / Splunk YAML | Rule ID, technique/tactic mappings, query logic, data source, Signal Quality Score |
| MITRE ATT&CK framework | STIX 2.1 JSON | Tactic ordering, technique-to-tactic mappings, technique descriptions |
| Adversary TTP sequences (from UC-07 or CTI) | JSON / structured extraction | Adversary ID, ordered technique list with tactic mapping, campaign context |
| Environmental context | Structured profile (YAML/JSON) | Network architecture (segmentation, trust boundaries), crown jewel asset locations, compensating controls (NDR, DLP) |

> **Note:** Alert data follows the SIEM's standard alert schema with normalized source event fields. Rule files follow their format's defined schema (Elastic TOML, Sigma YAML, Splunk YAML, etc.). These are structured, documented formats — see [data-requirements/](../../data-requirements/) for platform-specific field references.

### Outputs

**Primary output: Kill Chain Analysis Report**

Per adversary profile:

```
Kill Chain Analysis: APT-X (Operation Northern Reach)
Analysis Date: 2026-02-14
Environment: Canadian Telecom, 15,000 endpoints

Tactic Sequence Coverage:
  Tactic                  | Confidence | Tier       | Rules | Breakpoint?
  ------------------------|------------|------------|-------|------------
  Initial Access          |     86     | Strong     |   12  | No
  Execution               |     42     | Degraded   |   24  | No (detected but noisy)
  Persistence             |     55     | Degraded   |   18  | No (partial)
  Privilege Escalation    |     61     | Functional |    9  | No
  Defense Evasion         |     38     | Degraded   |   22  | Possible (many noisy rules)
  Credential Access       |     44     | Degraded   |   11  | Possible
  Discovery               |     29     | Abandoned  |    7  | No (low impact stage)
  Lateral Movement        |     08     | Blind      |    8  | YES — PRIMARY BREAKPOINT
  Collection              |     22     | Abandoned  |    5  | Yes
  Exfiltration            |     64     | Functional |    6  | No (late-stage detection)

Detection Breakpoint: Lateral Movement (Stage 8 of 10)
Chain Integrity: 30% — detection chain breaks before adversary reaches objective
Mean Detection Depth: Stage 2.5 (attacker detected at Execution, lost by Lateral Movement)

[AI-generated narrative path analysis follows — see examples above]

Remediation Priority:
  1. Lateral Movement — elevate from Blind to Degraded (minimum) or Functional (target)
  2. Defense Evasion — tune noisy rules to recover 9 techniques from Degraded to Functional
  3. Collection — deploy data staging detection (new telemetry required)
```

**Secondary output: ATT&CK Navigator layer** with color coding by confidence tier, annotated with breakpoint markers.

**Tertiary output: Cross-adversary comparison matrix** showing breakpoint patterns across analyzed threat actors.

## Implementation Notes

**Tactic ordering is not linear in practice.** The ATT&CK tactic chain (Reconnaissance through Impact) represents a general progression, but real attacks skip stages, revisit stages, and operate across multiple stages simultaneously. The kill chain analysis should account for this by analyzing both the canonical sequence and the adversary-specific sequence extracted from CTI. The LLM should note when an adversary's actual operational pattern deviates from the canonical chain.

**Not every tactic gap is equally dangerous.** Discovery (T1087, T1082, etc.) going undetected is far less operationally damaging than Lateral Movement going undetected. The LLM should weight tactic importance by operational impact — losing visibility at lateral movement is catastrophic; losing visibility at discovery is acceptable if adjacent stages are well-covered. This impact weighting is a judgment call, not a formula, which is exactly why LLM reasoning is appropriate here.

**Compensating controls matter.** Network segmentation, DLP, NDR, and other controls outside the SIEM detection layer may compensate for detection gaps. The environmental context should include these compensating controls so the LLM can factor them into the path analysis. A lateral movement detection gap is less critical if the network is heavily segmented and NDR provides independent visibility.

**Path analysis is only as good as the threat model.** If you analyze kill chains for adversaries that do not target your environment, the results are academically interesting but operationally useless. Focus on the 3-5 adversary profiles most relevant to your industry and geography. UC-07 (Threat-Informed Gap Prioritization) should drive which adversary profiles are analyzed here.

**Visualization enhances adoption.** A text-based kill chain report with a color-coded attack path diagram is far more impactful in a leadership briefing than a table of scores. Generate ATT&CK Navigator layers programmatically and include them in the report. Color coding: green (Strong/Functional), yellow (Degraded), red (Abandoned/Blind), black border (detection breakpoint).

## Dependencies

- [UC-06: MITRE ATT&CK Posture Scoring](06-mitre-attack-posture-scoring.md) — provides the Detection Confidence Scores that are the foundation of kill chain assessment. This is a hard dependency — without scored posture, kill chain analysis reduces to binary coverage mapping.
- [UC-07: Threat-Informed Gap Prioritization](07-threat-informed-gap-prioritization.md) — provides adversary TTP sequences and environmental context that drive which kill chains to analyze.
- [Domain-Aware Entity Framework](../../concepts/domain-aware-entity-framework.md) — understanding domain coverage helps assess whether detection at a given stage covers the right telemetry.

## Complexity Assessment

| Dimension | Rating | Notes |
|---|---|---|
| Data engineering | Low-Medium | Tactic sequencing is a straightforward data join. The main data engineering work is in UC-06 (posture scoring). This use case primarily consumes pre-computed scores. |
| AI/ML complexity | Medium | LLM must reason about operational impact of detection gaps at each chain stage and generate attack path narratives. Requires understanding of attacker behavior and detection operations. Prompt engineering for the "red team analyst" framing requires iteration. |
| Integration effort | Low-Medium | Consumes UC-06 output and adversary profiles from UC-07. Output is primarily documentation (reports, Navigator layers). No real-time SIEM integration required. |
| Overall | **Medium** | Moderate complexity. The value is in the LLM's ability to reason about operational impact and generate clear path narratives — not in data engineering. Depends heavily on UC-06 being operational. |

## Real-World Considerations

**Tactic-level aggregation hides technique-level variance.** A tactic with an average confidence of 55 (Degraded) might contain 3 Strong techniques and 4 Blind techniques. The average is misleading. The LLM narrative should explicitly call out this variance: "Credential Access averages 44 (Degraded), but this masks a split — LSASS-based techniques are Functional while Kerberoasting and AS-REP Roasting are Blind."

**Chain integrity is a more useful metric than coverage percentage.** Telling leadership "we cover 85% of ATT&CK techniques" sounds good. Telling them "our detection chain breaks at lateral movement for 3 of 4 relevant adversaries" is more honest and more actionable. The kill chain analysis should emphasize chain integrity over coverage breadth.

**The "last mile" problem.** Even with Strong detection at every stage, the kill chain only works if alerts are triaged quickly enough to disrupt the attacker before they advance. A Strong detection at Execution that takes 4 hours to triage is operationally equivalent to Degraded detection if the attacker reaches Lateral Movement within 30 minutes. Consider incorporating mean triage time per tactic into the analysis.

**Seasonal and operational variation.** Detection posture is not static. Build server noise increases during release cycles, degrading Execution and Defense Evasion detection. IT operations generate legitimate lateral movement traffic during maintenance windows, increasing noise on Lateral Movement rules. The kill chain analysis should be run regularly (monthly) and should note when detection confidence at specific stages varies due to known operational patterns.

## Related Use Cases

- [UC-06: MITRE ATT&CK Posture Scoring](06-mitre-attack-posture-scoring.md) — provides the confidence scores consumed by this use case.
- [UC-07: Threat-Informed Gap Prioritization](07-threat-informed-gap-prioritization.md) — provides adversary TTP sequences and environmental context.
- [UC-09: Cross-Domain Detection Coverage](09-cross-domain-detection-coverage.md) — assesses whether detection at each stage spans multiple telemetry domains (endpoint + network + cloud), which affects chain resilience.
- [UC-10: Executive Posture Reporting](10-executive-posture-reporting.md) — incorporates kill chain analysis into executive narratives.
- [UC-04: Detection Drift Monitoring](../alert-analysis/04-detection-drift-monitoring.md) — detects when telemetry loss at a specific stage silently breaks the detection chain.
- [UC-12: Alert Cluster Narrative Synthesis](../ai-assisted-triage/12-alert-cluster-narrative-synthesis.md) — when alerts do fire across multiple chain stages, UC-12 synthesizes them into a coherent attack narrative.

## References

- [MITRE ATT&CK Tactics](https://attack.mitre.org/tactics/enterprise/) — tactic definitions and ordering.
- [Lockheed Martin Cyber Kill Chain](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html) — the original kill chain model. ATT&CK tactics provide a more granular and industry-standard framework, but the kill chain concept of sequential detection opportunities originates here.
- [DeTT&CT](https://github.com/rabobank-cdc/DeTTECT) — includes visibility scoring per technique that supports kill chain analysis.
- [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) — layer visualization for color-coded kill chain overlays.
- [MITRE ATT&CK Flow](https://center-for-threat-informed-defense.github.io/attack-flow/) — framework for describing sequences of adversary behaviors as attack flows, directly applicable to kill chain modeling.
