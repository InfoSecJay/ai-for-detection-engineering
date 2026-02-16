# UC-17: Rule Comparison and Gap Analysis

## Category

Rule Content Engineering

## Summary

Uses an LLM to perform semantic comparison of detection rules -- across different formats, query languages, and rule repositories -- to identify coverage overlaps, gaps, and redundancies. Unlike deterministic matching on MITRE technique tags or exact field-value overlap, semantic comparison assesses whether two rules with completely different implementations detect the same adversary behavior. Extends to comparing rule sets against CTI reports to verify that detection logic actually covers the described TTPs, not just maps to the right technique ID.

## Problem Statement

Detection engineering teams accumulate rules from multiple sources: vendor-provided content, community repositories (Sigma, Elastic Detection Rules, Splunk Security Content), in-house authored rules, and rules imported from CTI-driven sprints. Over time, this creates three problems that deterministic tooling struggles to solve:

**1. Hidden overlaps**: Two rules may detect the same behavior through completely different query patterns. One Sigma rule detects credential dumping via `process.name: procdump.exe AND command_line|contains: lsass`, while an Elastic rule detects it via Sysmon Event ID 10 where `TargetImage: *lsass.exe AND GrantedAccess` matches specific access masks. These share no field names, no values, and potentially different MITRE sub-technique tags -- yet they detect overlapping activity. Deterministic comparison on field overlap finds nothing.

**2. Illusory coverage**: A rule tagged with `attack.t1053.005` (Scheduled Task) might only detect `schtasks.exe /create` with specific arguments, missing `at.exe`, COM-based task creation, or PowerShell `Register-ScheduledTask`. The MITRE tag suggests coverage, but the detection logic covers only one procedure. Comparing the rule against the full technique description reveals the gap, but this comparison requires understanding both the technique semantics and the query logic.

**3. CTI-to-detection alignment**: After a CTI report describes a threat actor's TTPs, the team needs to verify that existing rules actually detect the specific procedures described -- not just the high-level techniques. A report describing "the actor uses `certutil.exe` to decode Base64-encoded payloads" requires a rule that specifically detects certutil decode operations, not just any rule tagged T1140 (Deobfuscate/Decode Files or Information).

Deterministic tooling can match MITRE tags and find exact field-value overlaps, but it cannot assess semantic equivalence across different query languages or verify that detection logic actually covers a described behavior.

## Prerequisites (What Your SIEM/SOAR Should Already Handle)

- **MITRE ATT&CK tagging**: Rules should have technique/sub-technique tags. Deterministic matching on tags is the first-pass filter -- it narrows the comparison set before semantic analysis.
- **Rule parsing**: Rules from each format should be parseable into a structured representation (metadata + detection logic). pySigma for Sigma, TOML parsing for Elastic rules, etc.
- **Rule inventory**: A complete catalog of active rules across all platforms, accessible programmatically.
- **Tag-based overlap detection**: Simple overlaps (two rules with identical MITRE tags and similar field names) should be identified deterministically. Reserve LLM analysis for cases where tag/field matching is insufficient.

## Where AI Adds Value

1. **Cross-format semantic comparison**: Given two rules in different query languages detecting the same technique, the LLM assesses whether they cover the same behavioral scope:
   - Rule A (Sigma): Detects `schtasks.exe /create` with specific command-line patterns
   - Rule B (KQL): Detects scheduled task creation via `DeviceProcessEvents` AND `DeviceRegistryEvents` for task registration keys
   - LLM assessment: "Rule B has broader coverage. Rule A only detects `schtasks.exe` command-line usage; Rule B also captures scheduled tasks created via registry modification, which covers COM-based and PowerShell-based task creation that bypass `schtasks.exe`."

2. **Coverage gap identification against technique descriptions**: The LLM compares a set of rules tagged with a technique against the ATT&CK technique's procedure examples and identifies uncovered procedures:
   - Input: 3 rules tagged T1003 (OS Credential Dumping)
   - LLM output: "These rules cover LSASS memory access (T1003.001) via Procdump and Mimikatz, and SAM database access (T1003.002) via reg.exe. No rules cover NTDS.dit extraction (T1003.003), LSA Secrets (T1003.004), or DCSync (T1003.006)."

3. **CTI report alignment**: Given a CTI report and a rule set, the LLM maps described adversary procedures to specific rules and identifies gaps:
   - CTI: "The actor uses `certutil -decode` to extract payloads from Base64-encoded certificates stored in `%APPDATA%`"
   - LLM: "Rule 'Certutil Suspicious Activity' partially covers this -- it matches `certutil.exe` with `-decode` argument, but does not check the file path for `%APPDATA%`. Rule 'Suspicious File Creation in AppData' covers the file write but not the certutil execution. Combined, these rules provide layered coverage, but no single rule matches the full procedure chain."

4. **Redundancy assessment**: For rules with significant semantic overlap, the LLM recommends consolidation or differentiation:
   - "Rules 'Suspicious PowerShell Download Cradle' and 'PowerShell Web Request' have 80% behavioral overlap. The first uses command-line regex, the second monitors .NET assembly loads. Consider merging into a single rule with broader detection logic, or keeping both for defense-in-depth with a documented rationale."

## AI Approach

**LLM prompting for semantic rule comparison.**

Three primary workflows:

### Pairwise Rule Comparison
1. Deterministically identify candidate pairs (same or related MITRE tags).
2. For each pair, send both rules' full context (metadata + detection logic) to the LLM.
3. Prompt requests: overlap percentage estimate, unique coverage in each rule, recommendation (redundant, complementary, or independent).

### Coverage Gap Analysis Against ATT&CK
1. Group rules by MITRE technique.
2. For each technique, send the rule group plus the ATT&CK technique description and procedure examples.
3. Prompt requests: covered procedures, uncovered procedures, sub-techniques with no detection, recommendations for new rules.

### CTI Report Alignment
1. Extract TTP descriptions from the CTI report (can be done with a separate LLM call or manually).
2. For each TTP description, retrieve candidate rules by MITRE tag and keyword search.
3. Send TTP description + candidate rules to the LLM.
4. Prompt requests: which rules cover the procedure, which partially cover it, what gaps remain, and what new detection logic would be needed.

All workflows use structured output (JSON) with defined fields to enable aggregation and reporting.

## Data Requirements

### Inputs

| Input | Format | Key Fields Used |
|---|---|---|
| Detection rules (pair or set) | Sigma YAML, Elastic TOML, KQL, SPL, EQL | Rule name, description, MITRE tags, detection/query block, data source |
| MITRE ATT&CK technique data | STIX JSON or technique markdown | Technique description, sub-techniques, procedure examples, data sources |
| CTI report (for alignment workflow) | Markdown, PDF text, or structured STIX | TTP descriptions, IOCs, actor profile, tools used |
| Rule observable inventory (optional) | JSON from UC-16 output | Pre-extracted observables per rule for enriching comparison context |

> **Note:** Alert data follows the SIEM's standard alert schema with normalized source event fields. Rule files follow their format's defined schema (Elastic TOML, Sigma YAML, Splunk YAML, etc.). These are structured, documented formats -- see [data-requirements/](../../data-requirements/) for platform-specific field references.

### Outputs

Structured comparison results. Example for pairwise comparison:

```json
{
  "comparison_id": "comp-001",
  "rule_a": {
    "name": "Scheduled Task Creation via Schtasks",
    "id": "sigma-5c1a",
    "format": "sigma",
    "mitre": ["T1053.005"]
  },
  "rule_b": {
    "name": "Scheduled Task Created via Registry Modification",
    "id": "elastic-8b3f",
    "format": "elastic_kql",
    "mitre": ["T1053.005"]
  },
  "overlap_assessment": "partial",
  "overlap_detail": "Both detect scheduled task creation (T1053.005). Rule A detects only schtasks.exe command-line invocations. Rule B detects task registration via registry key creation under HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache, which captures schtasks.exe, COM-based creation, and PowerShell-based creation.",
  "unique_to_rule_a": "Captures specific schtasks.exe command-line arguments (trigger type, execution path) that are not visible in registry-based detection.",
  "unique_to_rule_b": "Covers task creation methods that do not use schtasks.exe, including COM API and PowerShell Register-ScheduledTask.",
  "recommendation": "complementary - keep both. Rule A provides argument-level visibility for schtasks.exe; Rule B provides broader coverage for non-CLI task creation methods.",
  "combined_coverage_gaps": "Neither rule detects scheduled task creation on Linux/macOS (cron, at, launchd). Neither detects task modification or task hijacking (T1053.005 procedure variant)."
}
```

Example for CTI alignment:

```json
{
  "cti_source": "APT-X Report Q4 2025",
  "ttp_description": "Actor uses certutil.exe -decode to extract base64-encoded payloads from certificate files dropped in %APPDATA%\\Microsoft\\Crypto",
  "matching_rules": [
    {
      "rule_name": "Certutil Decode or Encode Operation",
      "coverage": "partial",
      "detail": "Matches certutil.exe with -decode argument but does not constrain the file path. Will fire on this procedure but also on legitimate certutil decode operations."
    }
  ],
  "gaps": [
    "No rule specifically monitors file creation in %APPDATA%\\Microsoft\\Crypto by non-standard processes.",
    "No rule correlates certutil decode with subsequent execution of the decoded payload."
  ],
  "recommended_detections": [
    "Rule detecting certutil -decode writing to %APPDATA% paths, combined with child process execution from the same directory within a short time window."
  ]
}
```

## Implementation Notes

- **Combinatorial explosion**: Pairwise comparison of N rules produces N*(N-1)/2 pairs. For 500 rules, that is 124,750 comparisons. Mitigate by:
  - Only comparing rules that share at least one MITRE technique tag or data source (deterministic pre-filter).
  - Grouping rules by technique and comparing within groups.
  - Using rule observable inventories (UC-16 output) to pre-filter pairs with no artifact overlap before LLM analysis.
- **Comparison granularity**: At the technique level (T1053) vs. sub-technique level (T1053.005) produces very different results. Default to sub-technique comparison; aggregate up to technique level for executive reporting.
- **CTI parsing**: CTI reports come in many formats. For structured reports (STIX bundles), extract TTPs programmatically. For unstructured reports (PDFs, blog posts), use an LLM to extract TTP descriptions as a preprocessing step.
- **Confidence scoring**: LLM semantic comparisons are inherently judgment-based. Include a confidence indicator in the output and route low-confidence comparisons to human review.
- **Caching**: Comparison results should be cached and only recomputed when one of the compared rules changes.

## Dependencies

- [UC-16: Observable Artifact Extraction](16-observable-artifact-extraction.md) -- Observable inventories improve comparison accuracy and enable pre-filtering.
- Rule inventory across all platforms in parseable format.
- MITRE ATT&CK data (STIX or equivalent) for technique-level gap analysis.
- LLM API access with sufficient context window for multi-rule comparison (8K+ tokens per comparison).

## Complexity Assessment

| Dimension | Rating | Notes |
|---|---|---|
| Data engineering | Medium | Aggregating rules across formats and platforms requires normalization. Pre-filtering pairs at scale requires observable inventory or tag-based indexing. |
| AI/ML complexity | Medium | Multi-document comparison prompting. Requires careful prompt design to avoid superficial analysis. Few-shot examples essential for calibrating depth of comparison. |
| Integration effort | Medium | Results need to feed into coverage dashboards, gap tracking systems, or JIRA for remediation. Not a standalone output. |
| Overall | **Medium** | The comparison logic is prompt-based and manageable. The challenges are data aggregation across platforms and making results actionable in existing workflows. |

## Real-World Considerations

- **Subjective overlap assessment**: Two experienced detection engineers may disagree on whether two rules are "redundant" or "complementary." LLM assessments will similarly vary. Treat LLM output as a starting point for human review, not a final verdict.
- **Defense-in-depth justification**: Overlapping rules are not always bad. If two rules detect the same behavior via different data sources (process events vs. registry events), keeping both provides resilience against data source failures. The LLM should flag overlaps but not automatically recommend consolidation.
- **CTI alignment is time-sensitive**: When a new CTI report drops, teams need alignment results quickly. Pre-compute rule observable inventories and technique groupings so that CTI alignment can run against cached rule analysis rather than re-analyzing every rule from scratch.
- **Gap analysis is only useful if gaps get closed**: The output of gap analysis must feed into a detection engineering backlog with prioritization. A gap report that sits in a dashboard without action is waste.
- **Cross-team value**: Gap analysis results are valuable for communicating detection posture to security leadership. "We cover 12 of 18 known procedures for T1053" is a concrete metric that drives investment decisions.

## Related Use Cases

- [UC-16: Observable Artifact Extraction](16-observable-artifact-extraction.md) -- Observable inventories are the foundation for meaningful rule comparison.
- [UC-18: Rule Quality Assessment](18-rule-quality-assessment.md) -- Quality issues (overly broad rules, incorrect MITRE mappings) must be resolved for accurate gap analysis.
- [UC-19: Detection Rule Generation](19-detection-rule-generation.md) -- Identified gaps become input for generating new detection rules.
- [UC-15: LLM Investigation Guide Generation](15-llm-investigation-guide-generation.md) -- When gap analysis identifies redundant rules for consolidation, investigation guides need updating.

## References

- [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) -- Visualization tool for mapping detection coverage to ATT&CK matrix.
- [DeTT&CT](https://github.com/rabobank-cdc/DeTTECT) -- Framework for scoring detection coverage against ATT&CK, uses data source quality and detection scoring.
- [Sigma Rule Repository](https://github.com/SigmaHQ/sigma) -- Community detection rules for cross-repository comparison.
- [Elastic Detection Rules](https://github.com/elastic/detection-rules) -- Elastic's open detection rule repository.
- [Splunk Security Content](https://github.com/splunk/security_content) -- Splunk's open detection rule repository.
- [MITRE ATT&CK STIX Data](https://github.com/mitre-attack/attack-stix-data) -- Machine-readable ATT&CK data for technique descriptions and procedure examples.
