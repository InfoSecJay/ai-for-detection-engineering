# UC-21: Threat Intelligence Synthesis

## Category

Strategic

## Summary

Reads natural-language cyber threat intelligence (CTI) reports, extracts the tactics, techniques, and procedures (TTPs) described, maps them to MITRE ATT&CK, compares the extracted techniques against the organization's current detection posture, and generates an actionable brief with prioritized detection engineering work orders for coverage gaps. This is one of the highest-value LLM applications in detection engineering because the input (prose reports) and the output (prioritized action items) both require natural language reasoning that deterministic tooling cannot perform.

## Problem Statement

Threat intelligence teams publish reports in natural language. A single report from Mandiant, CrowdStrike, or an ISAC partner may describe an intrusion campaign spanning 15 ATT&CK techniques across 8 tactics, with tool-specific indicators, behavioral TTPs, and contextual details about targeting and infrastructure. A detection engineer reading this report needs to:

1. Extract every technique described (not just the ones explicitly tagged with ATT&CK IDs).
2. Determine which of those techniques the organization can currently detect.
3. Assess detection quality — not just "we have a rule" but "the rule is healthy and firing correctly."
4. Prioritize the gaps by attack chain position, exploitability, and environmental relevance.
5. Generate specific detection engineering work orders for each gap.

Today, this process takes a senior detection engineer 2-4 hours per report. Much of that time is spent on the mechanical work of cross-referencing TTPs against the rule inventory, checking posture scores, and drafting work orders. The analytical judgment required — "this gap matters more than that one because it breaks our visibility at the lateral movement stage" — is genuinely hard, but it is buried under hours of lookup work.

Deterministic tooling can match explicitly tagged ATT&CK IDs against a rule inventory. It cannot read a paragraph describing "the actor used a scheduled task with a Base64-encoded PowerShell payload to establish persistence" and recognize that this describes T1053.005 (Scheduled Task) + T1059.001 (PowerShell) + T1027 (Obfuscated Files or Information) without explicit tagging.

## Prerequisites (What Your SIEM/SOAR Should Already Handle)

- **Detection rule inventory with MITRE mappings.** Rules must be tagged with ATT&CK technique IDs in their metadata. If your rules lack MITRE tags, fix that first — it is a metadata hygiene problem, not an AI problem.
- **Detection posture scores.** Per-technique detection confidence scores (see [UC-06](../posture-assessment/06-mitre-attack-posture-scoring.md)) should be computed and available. Without posture scores, the system can only tell you "you have rules" vs. "you don't have rules" — it cannot assess detection quality.
- **ATT&CK technique reference data.** The full ATT&CK matrix with technique definitions, sub-techniques, and tactic mappings must be available as structured data (STIX/TAXII feed or ATT&CK STIX data).
- **CTI report ingestion pipeline.** Reports must be accessible in a machine-readable format (PDF-to-text extraction, structured feed, or API). If your threat intel arrives as email attachments that get saved to a shared drive, build the ingestion pipeline first.

## Where AI Adds Value

The AI contribution spans the full pipeline from report intake to actionable output:

1. **TTP extraction from natural language.** The LLM reads the report and identifies every technique described, including those implied by behavioral descriptions rather than explicitly tagged. A paragraph describing "lateral movement via WMI to deploy Cobalt Strike beacons" maps to T1047 (Windows Management Instrumentation), T1570 (Lateral Tool Transfer), and potentially T1059.001 (PowerShell) depending on beacon delivery — even if the report never mentions ATT&CK IDs.

2. **Technique-to-posture comparison with quality assessment.** The LLM does not just check "rule exists / rule doesn't exist." It incorporates posture scores to assess whether existing detection is healthy, degraded, or effectively blind. A technique with three rules that are all abandoned (posture score <20) is functionally the same as having no coverage.

3. **Gap prioritization with attack chain reasoning.** The LLM reasons about which gaps matter most based on the attack chain described in the report. A gap at the initial access stage is different from a gap at the data exfiltration stage. The LLM considers: position in the kill chain, whether adjacent techniques provide compensating visibility, and the organization's environmental exposure to the described targeting.

4. **Work order generation.** For each prioritized gap, the LLM generates a specific detection engineering work order: what technique to cover, what data source to use, what observable to detect, suggested rule logic starting points, and expected effort level.

## AI Approach

- **LLM prompting with structured context injection.** The core technique is prompting an LLM with the full report text plus structured context: the ATT&CK matrix for technique validation, the organization's rule inventory with MITRE tags, and per-technique posture scores. The prompt instructs the LLM to extract TTPs, map to ATT&CK, compare against posture, and generate the actionable brief.
- **RAG over ATT&CK knowledge base.** Use retrieval-augmented generation to provide the LLM with ATT&CK technique definitions during TTP extraction. This improves mapping accuracy by grounding the LLM's technique identification in the official ATT&CK corpus rather than relying solely on the model's training data.
- **Multi-step prompting.** Break the pipeline into stages: (1) TTP extraction and ATT&CK mapping, (2) posture comparison, (3) gap prioritization, (4) work order generation. Each stage's output feeds the next. This improves accuracy over a single monolithic prompt.
- **Optional: embedding-based similarity for fuzzy technique matching.** When the LLM extracts a behavioral description that does not cleanly map to a single technique, use embedding similarity against ATT&CK technique descriptions to identify the closest matches and present them for human review.

## Data Requirements

### Inputs

| Input | Format | Key Fields Used |
|---|---|---|
| CTI report | PDF, HTML, or plain text (natural language) | Full report text, threat actor name, targeted sectors/regions, described TTPs |
| ATT&CK matrix | STIX 2.1 JSON (from MITRE CTI repository) | `technique_id`, `technique_name`, `tactic`, `description`, `sub-techniques[]` |
| Detection rule inventory | Structured (JSON/YAML from detection-as-code repo) | `rule_id`, `rule_name`, `mitre_technique_ids[]`, `data_source`, `enabled` (bool) |
| Detection posture scores | Structured (JSON from UC-06 output) | `technique_id`, `confidence_score` (0-100), `confidence_tier` (Strong/Functional/Degraded/Abandoned/Blind), `contributing_rules[]` |
| Organizational context (optional) | Structured (JSON/text) | Industry sector, geographic region, critical asset types, known threat actor targeting |

> **Note:** Alert data follows the SIEM's standard alert schema with normalized source event fields. Rule files follow their format's defined schema (Elastic TOML, Sigma YAML, Splunk YAML, etc.). These are structured, documented formats — see [data-requirements/](../../data-requirements/) for platform-specific field references.

### Outputs

**Primary output: Actionable threat intelligence brief**

```
## Threat Intelligence Assessment: UNC4736 Campaign Targeting Canadian Financial Sector
### Source: Mandiant Report M-TR-2025-1142 (Published 2025-11-18)

### Executive Summary

This report describes a multi-stage intrusion campaign by UNC4736 targeting
Canadian financial services organizations. The campaign uses spearphishing
with ISO file attachments for initial access, progresses through scheduled
task persistence, credential harvesting via LSASS dump, lateral movement
using WMI and RDP, and culminates in data staging and exfiltration over
encrypted channels.

**8 ATT&CK techniques identified in this report.**
- Strong detection (score 80+): 3 techniques
- Degraded detection (score 40-59): 2 techniques
- No effective coverage (score <20 or no rules): 3 techniques

### Technique Mapping and Posture Comparison

| # | Technique | Tactic | Your Posture | Score | Assessment |
|---|-----------|--------|-------------|-------|------------|
| 1 | T1566.001 — Spearphishing Attachment | Initial Access | Strong | 87 | 4 healthy rules across email and endpoint domains |
| 2 | T1553.005 — Mark-of-the-Web Bypass (ISO) | Defense Evasion | Blind | 0 | No rules. ISO-based MotW bypass is a known gap. |
| 3 | T1053.005 — Scheduled Task/Job | Persistence | Functional | 68 | 2 rules, but both are Windows-only. Report describes Linux cron variant. |
| 4 | T1059.001 — PowerShell | Execution | Strong | 91 | 6 rules with high diversity of observables |
| 5 | T1003.001 — LSASS Memory | Credential Access | Degraded | 44 | 3 rules, but 2 are tool-specific (mimikatz.exe). Report describes custom tooling. |
| 6 | T1047 — Windows Management Instrumentation | Lateral Movement | Degraded | 38 | 1 rule, high FP rate from admin scripts. Effectively abandoned. |
| 7 | T1021.001 — Remote Desktop Protocol | Lateral Movement | Strong | 82 | Good coverage with anomaly-based detection |
| 8 | T1041 — Exfiltration Over C2 Channel | Exfiltration | Blind | 12 | 1 rule but dependent on TLS inspection data that is not reliably available |

### Critical Gaps (Prioritized)

**Priority 1: T1553.005 — Mark-of-the-Web Bypass (ISO)**
- **Why critical:** This is the initial access delivery mechanism. Without detection
  here, the entire attack chain proceeds undetected until execution stage.
- **Compensating control:** T1566.001 (email detection) provides partial coverage,
  but only if ISO is delivered via email — report notes USB delivery as alternate vector.
- **Risk:** High. Zero detection on the primary delivery technique.

**Priority 2: T1047 — WMI Lateral Movement**
- **Why critical:** After credential harvesting, WMI is the primary lateral movement
  method described. Your only rule is effectively abandoned due to noise. This creates
  a blind spot between credential access and objective completion.
- **Compensating control:** T1021.001 (RDP) detection is strong, but report describes
  WMI as primary and RDP as fallback. Relying on the fallback technique for detection
  is fragile.
- **Risk:** High. Detection exists but is non-functional.

**Priority 3: T1003.001 — LSASS Memory (technique-specific gap)**
- **Why critical:** Current rules detect mimikatz.exe by process name. Report describes
  custom tooling using direct syscalls to access LSASS memory. Your detection is
  tool-specific, not technique-specific.
- **Compensating control:** None for custom tooling variants.
- **Risk:** Medium-high. Detection exists but is trivially evadable.

### Detection Engineering Work Orders

**WO-001: Create ISO/IMG mount detection rule**
- Technique: T1553.005
- Data source: Sysmon Event ID 12/13 (registry) or Windows Security Event 4663 (object access)
- Observable: Virtual disk mount events for .iso/.img/.vhd files, especially
  from user-writable directories (Downloads, Temp)
- Suggested approach: Process creation from mounted ISO path + no MotW on child process
- Estimated effort: 2-3 days (rule development + testing)
- Reference: Elastic rule "Execution from Unusual Directory" as starting template

**WO-002: Retune or replace WMI lateral movement rule**
- Technique: T1047
- Current rule: "WMI Remote Execution" — FP rate too high, investigate root cause
- Option A: Tune existing rule to exclude known admin WMI patterns (asset-tagged management servers)
- Option B: Replace with WMI process creation correlation — WMI provider host spawning
  unexpected child processes on remote systems
- Data source: Sysmon Event ID 1 (process creation) with parent process WmiPrvSE.exe
- Estimated effort: 1-2 days (tune) or 3-4 days (new rule)

**WO-003: Add technique-generic LSASS access detection**
- Technique: T1003.001
- Current gap: Rules are tool-name-specific (mimikatz.exe)
- Recommended: Add Sysmon Event ID 10 (ProcessAccess) rule for any process
  accessing lsass.exe with PROCESS_VM_READ rights, excluding known legitimate
  accessors (csrss.exe, MsMpEng.exe, etc.)
- Data source: Sysmon Event ID 10
- Estimated effort: 3-5 days (rule development + tuning expected FPs from security tools)
```

## Implementation Notes

- **Report length and context windows.** CTI reports vary from 2-page advisories to 60-page campaign analyses. For long reports, chunk the text and extract TTPs per section before consolidating. Use the LLM to deduplicate techniques across sections.
- **ATT&CK version alignment.** Ensure the ATT&CK version used for mapping matches the version your rule inventory is tagged against. Technique IDs and sub-technique structures change between ATT&CK versions.
- **Hallucination risk on technique mapping.** LLMs may map behavioral descriptions to incorrect techniques, especially for similar sub-techniques. Mitigate with RAG over ATT&CK definitions and include confidence levels in the mapping output. Flag low-confidence mappings for human review.
- **Posture score freshness.** Posture scores should be refreshed before running the synthesis. A score computed 60 days ago may not reflect recent tuning work or rule deployments.
- **Multi-report synthesis.** For maximum value, run this across multiple recent reports targeting your sector. The system can then identify recurring gaps — "T1047 WMI lateral movement has appeared in 4 of the last 6 reports targeting your sector and remains a blind spot."
- **Human review is mandatory.** The output is a draft brief and draft work orders. A senior detection engineer must validate the TTP extraction, confirm the posture assessment, and approve the work orders before they enter the backlog.

## Dependencies

- [UC-06: MITRE ATT&CK Posture Scoring](../posture-assessment/06-mitre-attack-posture-scoring.md) — Provides the per-technique posture scores that make the comparison meaningful. Without these, the system degrades to a binary "rule exists / rule doesn't" check.
- [UC-07: Threat-Informed Gap Prioritization](../posture-assessment/07-threat-informed-gap-prioritization.md) — Closely related. UC-07 focuses on gap prioritization from the posture side; UC-21 starts from the intelligence report side. They share the same posture data.
- [UC-19: Detection Rule Generation](../rule-content-engineering/19-detection-rule-generation.md) — Work orders generated by UC-21 can feed into UC-19 for AI-assisted rule drafting.
- [Prerequisites: Data Foundations](../../prerequisites/01-data-foundations.md) — CTI reports must be ingested in machine-readable format.

## Complexity Assessment

| Dimension | Rating | Notes |
|---|---|---|
| Data engineering | Medium | CTI report ingestion (PDF-to-text), posture score availability, and rule inventory access all require integration. The data is structured but distributed across systems. |
| AI/ML complexity | Medium | Multi-step LLM prompting with structured context injection. RAG over ATT&CK improves accuracy. No custom model training required. |
| Integration effort | Medium | Requires read access to CTI platform, detection-as-code repository, and posture scoring outputs. No write-back to production systems. |
| Overall | Medium | The core LLM pipeline is straightforward. Quality depends on posture score maturity (UC-06) and CTI ingestion reliability. |

## Real-World Considerations

- **Report quality varies enormously.** A Mandiant APT report with explicit ATT&CK mappings is easy to process. An ISAC advisory that describes behavior without ATT&CK references requires more LLM reasoning and produces less reliable mappings. Build confidence scoring into the output.
- **Not every report is relevant.** Before running the full synthesis pipeline, a quick relevance filter (sector, geography, technology stack) saves compute. An LLM can perform this relevance check with a lightweight prompt.
- **Work order realism.** LLM-generated work orders may suggest detections for data sources that your environment doesn't collect. Include data source availability as an input so the system can flag "this detection requires Sysmon Event ID 10, which is not currently collected in your environment" rather than generating an infeasible work order.
- **Organizational workflow integration.** The output is most useful when it integrates directly into the detection engineering backlog (Jira, GitHub Issues, etc.). Consider templating the work orders in your ticket system's format.
- **Volume management.** A busy threat intel team may process 10-20 reports per week. Not every report warrants full synthesis. Establish criteria for which reports trigger the full pipeline vs. a lightweight TTP extraction only.

## Related Use Cases

- [UC-06: MITRE ATT&CK Posture Scoring](../posture-assessment/06-mitre-attack-posture-scoring.md) — Provides the posture data that makes gap assessment meaningful.
- [UC-07: Threat-Informed Gap Prioritization](../posture-assessment/07-threat-informed-gap-prioritization.md) — Complementary approach starting from posture rather than individual reports.
- [UC-08: Kill Chain Completeness Analysis](../posture-assessment/08-kill-chain-completeness-analysis.md) — Kill chain reasoning used in gap prioritization.
- [UC-17: Rule Comparison & Gap Analysis](../rule-content-engineering/17-rule-comparison-and-gap-analysis.md) — Semantic rule comparison can validate whether existing rules truly cover described TTPs.
- [UC-19: Detection Rule Generation](../rule-content-engineering/19-detection-rule-generation.md) — Downstream consumer of work orders generated here.
- [UC-22: Detection Program Health Reporting](../strategic/22-detection-program-health-reporting.md) — CTI synthesis findings feed into program health narrative.

## References

- [MITRE ATT&CK](https://attack.mitre.org/) — Authoritative technique reference. STIX data available via the [MITRE CTI GitHub repository](https://github.com/mitre/cti).
- [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) — Visualization tool for posture overlays.
- [sigma-llm-doc](https://github.com/InfoSecJay/sigma-llm-doc) — Related project using LLMs with Sigma detection rules.
- [DeTT&CT](https://github.com/rabobank-cdc/DeTTECT) — Tool for scoring detection and visibility coverage against ATT&CK.
- Anton Chuvakin, ["Simple to Ask: Is Your SOC AI Ready? Not Simple to Answer!"](https://medium.com/anton-on-security/simple-to-ask-is-your-soc-ai-ready-not-simple-to-answer) (October 2025) — Pillar 1 (Data Foundations) applies to CTI report ingestion requirements.
