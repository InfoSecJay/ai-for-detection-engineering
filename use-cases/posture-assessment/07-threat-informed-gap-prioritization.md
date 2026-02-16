# UC-07: Threat-Informed Gap Prioritization

## Category

Posture Assessment

## Summary

Prioritizes detection coverage gaps by mapping threat intelligence about relevant adversaries to your scored detection posture. Deterministic tooling handles the TTP-to-rule-inventory join. AI adds value by synthesizing natural language CTI reports into structured technique lists, reasoning about which gaps matter most given your specific environment context, and producing risk-ranked remediation recommendations that account for both threat relevance and operational feasibility.

## Problem Statement

Detection engineering teams always have more gaps than engineering hours. A raw list of "techniques you don't cover" is not actionable — it doesn't tell you which gaps matter, which ones are exploitable given your environment, or where a single tuning fix might elevate a Degraded technique to Functional.

The naive approach is to map threat actor TTPs to your rule inventory and flag missing techniques. This is a data join — deterministic and straightforward. But the result is an unprioritized list that treats every gap equally. In practice, a gap in lateral movement detection matters far more if the adversary targeting your sector relies heavily on lateral movement, and a Degraded technique that could be rescued by tuning one noisy rule is a better investment than a Blind technique requiring new telemetry deployment.

The prioritization requires reasoning across three data domains simultaneously: what adversaries do (CTI), how well your detections work (posture scores), and what your environment looks like (infrastructure, industry, risk profile). This cross-domain synthesis is where deterministic tooling falls short and where an LLM adds genuine value.

## Prerequisites (What Your SIEM/SOAR Should Already Handle)

- **Detection rules with MITRE ATT&CK technique mappings.** The join between threat actor TTPs and your rule inventory depends entirely on accurate technique tags in your rule metadata. If your MITRE mappings are incomplete or inaccurate, the gap analysis will be wrong. Validate mappings before running this use case — UC-18 (Rule Quality Assessment) can help identify mapping errors.
- **Posture scores from UC-06.** This use case consumes Detection Confidence Scores per technique. Without scored posture data, you can only identify binary gaps (covered/not covered), which misses the critical distinction between Functional and Degraded coverage.
- **Structured threat intelligence feeds.** STIX/TAXII feeds with technique mappings (e.g., MITRE ATT&CK Groups data, vendor threat profiles) provide the deterministic TTP mappings. These are structured data joins — no AI required for the mapping itself.
- **CTI report repository.** Your organization's threat intelligence reports, vendor advisories, and sector-specific threat briefings stored in an accessible format. These are the natural language documents that require AI to process.
- **Environmental context documentation.** Industry vertical, geographic presence, technology stack, crown jewel assets, regulatory requirements. This context is what transforms a generic gap list into a prioritized, environment-specific remediation plan.

## Where AI Adds Value

### 1. CTI Report Synthesis (Natural Language to Structured Techniques)

Threat intelligence reports are written in natural language. They describe adversary behavior in prose: "The group typically gains initial access through spearphishing attachments containing macro-enabled documents, then establishes persistence via scheduled tasks and registry run keys." Extracting a precise, deduplicated list of ATT&CK techniques from this prose requires understanding security concepts, recognizing that "macro-enabled documents" maps to T1204.002 (User Execution: Malicious File) and T1059.005 (Visual Basic), and handling ambiguity when reports describe behavior that maps to multiple techniques.

Deterministic keyword matching catches obvious mentions ("uses Mimikatz" maps to T1003.001) but misses behavioral descriptions that don't name specific tools. An LLM reads the full report, understands the described behavior, and produces a structured technique list with confidence levels:

> **CTI Report: "Operation Northern Reach — APT-X Campaign Targeting Canadian Telecom"**
>
> Extracted Techniques:
> | Technique | Confidence | Evidence from Report |
> |---|---|---|
> | T1566.001 — Spearphishing Attachment | High | "targeted emails with macro-enabled Word documents sent to engineering staff" |
> | T1204.002 — User Execution: Malicious File | High | Implied by spearphishing attachment delivery |
> | T1059.005 — Visual Basic | High | "macro-enabled documents" implies VBA execution |
> | T1053.005 — Scheduled Task | High | "persistence established via scheduled tasks on compromised hosts" |
> | T1547.001 — Registry Run Keys | High | "additional persistence through registry modifications in HKCU\Software\Microsoft\Windows\CurrentVersion\Run" |
> | T1021.002 — SMB/Windows Admin Shares | Medium | "moved laterally using administrative shares" — could be T1021.002 or T1080 |
> | T1003.001 — LSASS Memory | Medium | "harvested credentials from memory" — likely LSASS but report does not specify |
> | T1048.003 — Exfiltration Over Unencrypted Non-C2 Protocol | Low | "data staged and exfiltrated" — limited detail on exfil method |

### 2. Environment-Contextual Gap Reasoning

After the deterministic join identifies which extracted techniques lack detection, an LLM reasons about which gaps matter most *for your specific environment*:

> **Gap Prioritization for Operation Northern Reach:**
>
> **Critical Gap: T1021.002 — SMB/Windows Admin Shares (Confidence: Blind — 8)**
> This is the highest-priority gap. The report describes lateral movement as a primary operational phase, and your lateral movement detection is your weakest tactic area (31% Functional per UC-06 scoring). APT-X targeting Canadian telecom specifically elevates this risk — your environment matches the victim profile exactly. Your current SMB detection rules exist but score Blind due to overwhelming noise from legitimate file share access by IT operations. Tuning these rules to exclude known IT automation accounts would be the highest-ROI remediation action.
>
> **High Gap: T1003.001 — LSASS Memory (Confidence: Degraded — 44)**
> You have coverage but it is degraded. Four rules cover this technique; two are healthy but detect only Mimikatz-specific artifacts. The report suggests APT-X may use custom tooling for credential harvesting. Your detection would catch Mimikatz but miss custom LSASS access tools. Recommend adding a rule based on LSASS access patterns (process handle requests to lsass.exe) rather than tool-specific signatures.
>
> **Low Priority: T1566.001 — Spearphishing Attachment (Confidence: Strong — 86)**
> Your initial access detection for this technique is strong across both email and endpoint domains. No immediate action needed.

### 3. Risk-Ranked Remediation Recommendations

The LLM synthesizes gap analysis into actionable, prioritized work orders:

> **Remediation Plan — Ranked by Risk-Adjusted Priority:**
>
> 1. **Tune SMB lateral movement rules** (T1021.002) — Exclude IT automation service accounts from 3 existing rules. Estimated effort: 4 hours. Projected score improvement: Blind (8) to Degraded (48). *Why first: highest threat relevance, lowest remediation effort, addresses your weakest tactic area.*
>
> 2. **Add behavioral LSASS access detection** (T1003.001) — Write rule detecting process handle requests to lsass.exe regardless of source process name. Estimated effort: 8 hours including testing. Projected score improvement: Degraded (44) to Functional (62). *Why second: addresses tool-agnostic evasion risk identified in CTI.*
>
> 3. **Deploy scheduled task monitoring telemetry** (T1053.005) — Current rules depend on Windows Security Event 4698, which is not enabled on 40% of your server fleet. Enable auditing via GPO, then validate existing rules. Estimated effort: 16 hours (cross-team coordination). *Why third: requires infrastructure change, longer timeline.*

## AI Approach

**LLM-driven synthesis pipeline with deterministic data joins:**

1. **CTI report ingestion:** LLM processes natural language threat reports and extracts structured technique lists with confidence ratings. Uses few-shot prompting with examples of report-to-technique extraction. For lengthy reports, chunk into sections and process iteratively, then deduplicate.

2. **Deterministic TTP-to-posture join:** Extracted techniques are joined against the Detection Confidence Score table from UC-06. This is a simple data operation — no AI needed. Output: per-technique record with threat relevance, current confidence score, and tier.

3. **LLM gap reasoning:** The joined data plus environmental context (industry, geography, technology stack, known risk areas) is provided to the LLM for prioritized gap analysis. The LLM reasons about which gaps represent the highest operational risk and produces ranked recommendations.

4. **LLM remediation planning:** For each prioritized gap, the LLM generates specific remediation actions — tuning existing rules, writing new rules, deploying telemetry — with estimated effort and projected impact on confidence scores.

**RAG pattern for CTI context:** If the organization maintains a CTI knowledge base, use retrieval-augmented generation to pull relevant prior reports, adversary profiles, and historical incident data to enrich the gap reasoning step.

## Data Requirements

### Inputs

| Input | Format | Key Fields Used |
|---|---|---|
| CTI reports | Natural language (PDF, HTML, Markdown) | Adversary name, described TTPs, victim profile, campaign timeline |
| MITRE ATT&CK Groups data | STIX 2.1 JSON | Group ID, associated techniques, target sectors |
| Detection Confidence Scores (from UC-06) | JSON | Technique ID, confidence score, tier, contributing rule count, observable diversity rating |
| Rule inventory | Elastic TOML / Sigma YAML / Splunk YAML | Rule ID, technique mappings, data source, current health status |
| Environmental context | Structured profile (YAML/JSON) | Industry vertical, geography, technology stack, crown jewel assets, regulatory frameworks |
| Historical gap analysis results (optional) | JSON from prior runs | Previous prioritization for trend tracking and progress measurement |

> **Note:** Alert data follows the SIEM's standard alert schema with normalized source event fields. Rule files follow their format's defined schema (Elastic TOML, Sigma YAML, Splunk YAML, etc.). These are structured, documented formats — see [data-requirements/](../../data-requirements/) for platform-specific field references.

### Outputs

**Primary output: Threat-Informed Gap Report**

A structured document per CTI input containing:

1. **Extracted technique list** with confidence ratings and evidence citations from the source report.
2. **Coverage overlay** showing each technique's current Detection Confidence Score and tier.
3. **Prioritized gap list** ranked by risk-adjusted priority, with reasoning for each ranking.
4. **Remediation plan** with specific actions, estimated effort, projected score improvement, and sequencing recommendations.
5. **Residual risk summary** — what gaps remain even after remediation, and what compensating controls exist.

Example output snippet:

```
Threat Actor: APT-X (Operation Northern Reach)
Report Date: 2026-01-15
Sector Relevance: Canadian Telecom (exact match)

Techniques Extracted: 8
  Coverage Breakdown:
    Strong/Functional:  3 (T1566.001, T1059.005, T1547.001)
    Degraded:           2 (T1003.001, T1204.002)
    Abandoned:          1 (T1053.005)
    Blind:              1 (T1021.002)
    No Coverage:        1 (T1048.003)

Overall Threat Coverage: 37.5% at Functional or above
Risk Rating: HIGH — critical gaps in lateral movement and persistence
  align with adversary's primary operational phases

Remediation Effort Estimate: 28 engineering hours across 3 work orders
Projected Post-Remediation Coverage: 62.5% at Functional or above
```

## Implementation Notes

**CTI report parsing requires preprocessing.** Reports arrive in varied formats — PDF, HTML, email, threat platform exports. Build a preprocessing pipeline that extracts clean text before LLM processing. For PDFs, use a text extraction library (PyMuPDF, pdfplumber). For structured threat platform exports (STIX bundles from MISP, Recorded Future, Mandiant), extract technique mappings deterministically first and use the LLM only for the natural language portions.

**Confidence calibration for technique extraction.** The LLM will sometimes hallucinate technique mappings that are not supported by the report text. Require the LLM to cite specific passages for each extraction and implement a validation step that checks citations against the source. Techniques extracted with Low confidence should be flagged for human review rather than automatically included in the gap analysis.

**Environmental context is the differentiator.** The same gap list prioritized for a Canadian telecom looks very different from one prioritized for a US healthcare provider. The environmental context profile should be maintained as a living document and updated quarterly. Include: industry vertical, geographic presence, technology stack (which OS, cloud providers, identity providers), known high-value assets, regulatory requirements (PCI, HIPAA, SOX), and historical incident patterns.

**Batch vs. on-demand processing.** Two operational modes: (1) Scheduled batch — run monthly against your top 5 tracked threat actor profiles to generate a standing prioritized gap list. (2) On-demand — when a new CTI report drops about a relevant adversary, run the pipeline immediately to assess exposure and generate urgent remediation recommendations. Both modes use the same pipeline; the trigger differs.

**Integration with detection engineering workflow.** Gap remediation recommendations should feed directly into your detection engineering backlog (Jira, GitHub Issues, Azure DevOps). Automate the creation of work items from the remediation plan so that prioritized gaps become tracked engineering tasks, not just a report that gets filed.

## Dependencies

- [UC-06: MITRE ATT&CK Posture Scoring](06-mitre-attack-posture-scoring.md) — provides the Detection Confidence Scores that determine whether a technique is Strong, Degraded, or Blind. Without scored posture data, this use case degrades to a binary covered/not-covered gap analysis.
- [UC-17: Rule Comparison & Gap Analysis](../rule-content-engineering/17-rule-comparison-and-gap-analysis.md) — can analyze whether existing rules actually detect the behaviors described in a CTI report or just superficially match technique IDs.
- [UC-21: Threat Intelligence Synthesis](../strategic/21-threat-intelligence-synthesis.md) — overlaps in CTI report processing. UC-21 focuses on broader TI synthesis; UC-07 focuses specifically on posture gap prioritization.
- [Domain-Aware Entity Framework](../../concepts/domain-aware-entity-framework.md) — understanding which domains provide coverage influences gap prioritization.

## Complexity Assessment

| Dimension | Rating | Notes |
|---|---|---|
| Data engineering | Medium | CTI report preprocessing (PDF/HTML extraction) is the main data engineering challenge. The TTP-to-posture join is trivial once both datasets are structured. Environmental context requires manual curation. |
| AI/ML complexity | Medium-High | CTI report synthesis requires the LLM to understand security concepts and map behavioral descriptions to ATT&CK techniques accurately. Gap reasoning requires multi-factor prioritization across threat, posture, and environment domains. Prompt engineering is non-trivial. |
| Integration effort | Medium | Requires access to CTI report repository, UC-06 posture scores, and ideally the detection engineering backlog system for work item creation. No real-time SIEM integration needed. |
| Overall | **Medium-High** | The core challenge is LLM accuracy in CTI synthesis and gap reasoning. The data pipeline is straightforward. The value depends heavily on the quality of environmental context provided and the accuracy of UC-06 posture scores. |

## Real-World Considerations

**CTI report quality varies wildly.** A Mandiant APT report with detailed TTP descriptions produces excellent technique extractions. A one-paragraph threat advisory produces vague, low-confidence extractions. Build your pipeline to handle the quality spectrum gracefully — output confidence ratings that reflect input quality, and flag low-quality inputs for human review rather than generating false precision.

**The "everything is critical" trap.** If your environmental context is too broad ("we use Windows and cloud and have users"), every gap will be prioritized as critical because every technique is potentially relevant. Specificity in the environmental profile directly determines the usefulness of prioritization. "We are a Canadian telecom with 15,000 endpoints running Windows 10/11, AWS for cloud workloads, Okta for identity, and PCI compliance requirements" produces meaningful prioritization. "We are a company" does not.

**Adversary technique overlap means diminishing returns.** After analyzing 5-10 relevant threat actor profiles, the extracted technique lists start converging heavily. The first analysis is revelatory; the tenth adds marginal new gaps. Track cumulative technique coverage across analyzed adversaries and focus new analyses on adversaries with novel TTPs.

**Political sensitivity of gap reports.** A report that says "you are Blind to the primary lateral movement technique used by the adversary targeting your sector" is a powerful statement. Ensure leadership understands that gap identification is a feature, not a failure. Frame reports as "detection engineering investment guidance" rather than "security failure documentation."

**Progress tracking matters.** Run this analysis quarterly against the same adversary profiles and track score changes over time. Showing "Q4 coverage of APT-X TTPs was 37.5% Functional; after targeted tuning, Q1 coverage is 62.5% Functional" is a concrete, defensible metric for the value of detection engineering investment.

## Related Use Cases

- [UC-06: MITRE ATT&CK Posture Scoring](06-mitre-attack-posture-scoring.md) — provides the posture scores consumed by this use case.
- [UC-08: Kill Chain Completeness Analysis](08-kill-chain-completeness-analysis.md) — complements gap prioritization with attack-path-aware analysis.
- [UC-10: Executive Posture Reporting](10-executive-posture-reporting.md) — incorporates threat-informed gap analysis into executive narratives.
- [UC-17: Rule Comparison & Gap Analysis](../rule-content-engineering/17-rule-comparison-and-gap-analysis.md) — semantic comparison of existing rules against CTI-described behaviors.
- [UC-19: Detection Rule Generation](../rule-content-engineering/19-detection-rule-generation.md) — generates candidate rules for gaps identified by this use case.
- [UC-21: Threat Intelligence Synthesis](../strategic/21-threat-intelligence-synthesis.md) — broader CTI synthesis that feeds into this use case.

## References

- [MITRE ATT&CK Groups](https://attack.mitre.org/groups/) — adversary profiles with associated techniques.
- [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) — layer visualization for threat actor coverage overlays.
- [DeTT&CT](https://github.com/rabobank-cdc/DeTTECT) — framework for mapping threat actor TTPs to detection and visibility.
- [Threat Detection Explorer](https://github.com/InfoSecJay/threat-detection-explorer) — tool for exploring detection coverage against threat profiles.
- [MISP](https://www.misp-project.org/) — open source threat intelligence platform with STIX/TAXII support.
- [ATT&CK Workbench](https://github.com/center-for-threat-informed-defense/attack-workbench-frontend) — tool for extending and customizing ATT&CK data.
- Center for Threat-Informed Defense — [Top ATT&CK Techniques](https://top-attack-techniques.mitre-engenuity.org/) — methodology for prioritizing techniques by prevalence and impact.
