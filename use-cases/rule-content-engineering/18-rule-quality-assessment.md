# UC-18: Rule Quality Assessment

## Category

Rule Content Engineering

## Summary

Uses an LLM to evaluate the semantic quality of detection rules -- assessing whether the detection logic is specific enough, whether the description accurately reflects what the rule does, whether the MITRE ATT&CK mapping is correct given the actual query logic, and whether the rule has obvious evasion gaps. This goes beyond deterministic validation (syntax correctness, metadata completeness, tag format) to evaluate whether the rule is actually good at detecting what it claims to detect.

## Problem Statement

Detection rule repositories grow over time and quality degrades. Rules are written by different authors with varying levels of expertise, imported from community sources without review, or modified piecemeal over months. The result is a rule set where some rules are precise and well-documented while others are:

- **Overly broad**: A rule claiming to detect T1059.001 (PowerShell) that matches on `process.name: powershell.exe` with no command-line filtering will generate thousands of false positives and detect nothing specific.
- **Overly narrow**: A rule detecting credential dumping that only matches `mimikatz.exe` by process name misses renamed binaries, alternative tools, and the actual technique (LSASS memory access).
- **Incorrectly mapped**: A rule tagged T1003.001 (LSASS Memory) that only looks for `process.name: mimikatz.exe` is not detecting LSASS memory access as a technique -- it is detecting a specific tool. The correct mapping might be T1003 with a note that coverage is tool-specific, or the rule should be rewritten to detect the technique.
- **Misleadingly described**: A rule named "Suspicious Network Connection" with a description that says "detects C2 beaconing" but whose query just matches outbound connections on port 443 from non-browser processes. The description overpromises relative to the detection logic.
- **Evasion-prone**: A rule that matches `schtasks.exe /create` can be evaded by using `schtasks /create` (no `.exe`), using the COM API directly, or using PowerShell's `Register-ScheduledTask`.

Deterministic tooling handles structural quality: Is the YAML valid? Are required metadata fields present? Do MITRE tags match the `Tnnnn.nnn` format? Does the query parse without syntax errors? These are solved problems. But assessing whether the rule's detection logic is semantically correct, sufficiently specific, and aligned with its metadata requires understanding both the security domain and the query's intent.

## Prerequisites (What Your SIEM/SOAR Should Already Handle)

- **Syntax validation**: Rule files should pass schema validation (valid YAML/TOML, correct field names, parseable query syntax). Use existing linters: `sigma check`, Elastic's rule schema validator, Splunk's `savedsearches.conf` validator.
- **Metadata completeness checks**: Required fields (name, description, severity, MITRE tags, author, date) should be enforced by CI/CD checks, not AI.
- **Tag format validation**: MITRE technique IDs should match the `attack.tNNNN.NNN` format (or platform equivalent). This is regex validation.
- **Query syntax validation**: Queries should compile/parse without errors in their target platform. Use platform-specific parsers or dry-run APIs.
- **Rule linting**: Basic linting rules (e.g., "rules should have at least one data source defined", "severity should be one of: low, medium, high, critical") should be deterministic CI checks.

## Where AI Adds Value

The LLM evaluates dimensions of rule quality that require security domain reasoning:

1. **Detection logic specificity**: The LLM assesses whether the query is specific enough to detect the claimed behavior with acceptable precision. Example assessment:
   > "This rule claims to detect T1003.001 (LSASS Memory) but the query only checks `process.name: mimikatz.exe`. This is tool-specific detection, not technique-specific detection. An attacker using Procdump, comsvcs.dll MiniDump, or direct API calls to OpenProcess on LSASS would evade this rule. Recommend: Rewrite to detect LSASS access patterns (Sysmon Event ID 10 with TargetImage lsass.exe and suspicious GrantedAccess values) or rename/retag as tool-specific detection."

2. **Description-to-logic alignment**: The LLM compares what the rule's metadata says it does versus what the detection query actually does. Misalignment erodes analyst trust and causes incorrect prioritization.

3. **MITRE mapping validation**: Given the actual query logic, the LLM assesses whether the assigned MITRE technique is correct. A rule matching `reg.exe add HKLM\...\Run` should be tagged T1547.001 (Registry Run Keys), not T1112 (Modify Registry) -- the latter is a broader technique that does not convey the persistence intent.

4. **Evasion gap identification**: The LLM identifies common evasion paths for the detected behavior that the rule does not cover. This is not exhaustive red-teaming, but identification of well-known bypasses. Example:
   > "This rule detects `schtasks.exe /create`. Known evasion paths: (1) Direct Task Scheduler COM API calls bypassing schtasks.exe, (2) PowerShell `Register-ScheduledTask` cmdlet, (3) `at.exe` (legacy but still functional on some systems), (4) renamed schtasks.exe binary. The rule covers only the most basic procedure variant."

5. **Severity appropriateness**: The LLM evaluates whether the assigned severity matches the detection logic's specificity and the technique's impact. A highly specific rule for credential dumping merits high/critical severity; a broad rule matching common administrative tools should not be critical even if the technique is high-impact.

## AI Approach

**LLM prompting for security domain reasoning.**

Workflow:

1. **Parse rule deterministically**: Extract metadata, detection logic, MITRE tags, data source, and description using appropriate parsers.
2. **Run deterministic checks first**: Syntax, schema, completeness. Pass results to the LLM as context (so it does not waste reasoning on issues already caught).
3. **Construct quality assessment prompt**: Send the rule's full content plus the MITRE technique description(s) for its tagged techniques. Request structured assessment across defined quality dimensions.
4. **Structured output**: The LLM returns a JSON assessment with scores and explanations per dimension.
5. **Aggregate and prioritize**: Rank rules by quality score. Surface the lowest-quality rules for human review and remediation.

Prompt design includes:

- The complete rule (metadata + detection logic)
- The MITRE ATT&CK technique description for each tagged technique
- Explicit quality dimensions to evaluate (specificity, description alignment, MITRE mapping, evasion gaps, severity appropriateness)
- 2-3 few-shot examples showing high-quality assessments for rules of varying quality
- Instruction to be specific and cite the query logic when identifying issues

## Data Requirements

### Inputs

| Input | Format | Key Fields Used |
|---|---|---|
| Detection rule | Sigma YAML, Elastic TOML, Splunk YAML, or raw query | All fields: name, description, severity, MITRE tags, detection/query block, data source, author |
| MITRE ATT&CK technique data | STIX JSON or technique descriptions | Technique name, description, sub-techniques, procedure examples |
| Deterministic check results | JSON | Output from linters and validators -- passed to LLM to avoid redundant analysis |
| Quality rubric (optional) | Markdown or structured text | Organization-specific quality standards (e.g., "all credential access rules must be technique-specific, not tool-specific") |

> **Note:** Alert data follows the SIEM's standard alert schema with normalized source event fields. Rule files follow their format's defined schema (Elastic TOML, Sigma YAML, Splunk YAML, etc.). These are structured, documented formats -- see [data-requirements/](../../data-requirements/) for platform-specific field references.

### Outputs

A structured quality assessment per rule. Example:

```json
{
  "rule_name": "Mimikatz Credential Dumping",
  "rule_id": "sigma-9f3a",
  "overall_quality_score": 4,
  "max_score": 10,
  "dimensions": {
    "detection_specificity": {
      "score": 2,
      "max": 10,
      "assessment": "Rule matches only process.name: mimikatz.exe. This is tool-name detection, trivially evaded by renaming the binary. Does not detect the technique (LSASS memory access) -- detects one tool that performs the technique.",
      "recommendation": "Rewrite to detect LSASS memory access patterns: Sysmon Event ID 10 with TargetImage containing lsass.exe and GrantedAccess values 0x1010, 0x1FFFFF, or 0x1410. Alternatively, keep this rule as a low-effort tool-name indicator and create a separate technique-level rule."
    },
    "description_alignment": {
      "score": 5,
      "max": 10,
      "assessment": "Description says 'Detects credential dumping using Mimikatz'. This is accurate for what the rule does (detect Mimikatz by name), but may mislead analysts into thinking LSASS access is comprehensively covered.",
      "recommendation": "Update description to: 'Detects execution of a process named mimikatz.exe. This is a tool-specific indicator; see rule [X] for technique-level LSASS memory access detection.'"
    },
    "mitre_mapping": {
      "score": 3,
      "max": 10,
      "assessment": "Tagged T1003.001 (LSASS Memory). The mapping implies technique-level coverage, but the rule only detects one tool. More accurate mapping: T1003 (OS Credential Dumping) at the technique level without sub-technique specificity, or keep T1003.001 but add a metadata note indicating tool-specific coverage only.",
      "recommendation": "Add coverage_type: tool_specific to rule metadata. Consider whether your coverage reporting should distinguish tool-specific from technique-specific detections."
    },
    "evasion_gaps": {
      "score": 2,
      "max": 10,
      "assessment": "Known evasion paths: (1) Rename mimikatz.exe to any other name, (2) Use alternative tools: procdump, comsvcs.dll, nanodump, PPLdump, (3) Use in-memory execution without dropping mimikatz.exe to disk, (4) Use Mimikatz functionality compiled into a custom binary (e.g., via Cobalt Strike's kiwi module).",
      "recommendation": "This rule should be one layer in a defense-in-depth approach, not the sole detection for T1003.001."
    },
    "severity_appropriateness": {
      "score": 6,
      "max": 10,
      "assessment": "Severity is 'critical'. Given that the rule only matches a tool name (high FP potential if any legitimate tool uses the same name, but practically low FP for 'mimikatz.exe'), and Mimikatz execution is a genuine high-impact event, 'high' is more appropriate than 'critical'. Reserve 'critical' for technique-level detections with high specificity.",
      "recommendation": "Reduce to 'high' severity."
    }
  },
  "priority": "high",
  "priority_rationale": "Rule is used for a critical technique (credential access) but provides only tool-name-level detection. High risk of false sense of coverage."
}
```

## Implementation Notes

- **Run as batch CI/CD check**: Quality assessment should run against all rules periodically (weekly) or on rule changes (PR/merge trigger). Output a quality report that detection engineers review.
- **Prioritize remediation**: Not all quality issues are equal. A low-specificity rule for a critical technique (credential access, lateral movement) is higher priority than a low-specificity rule for a less impactful technique. Use MITRE technique impact/prevalence to weight quality scores.
- **Avoid LLM-as-linter**: Do not use the LLM to check metadata completeness or YAML syntax. Those are deterministic checks that are faster, cheaper, and more reliable as code. The LLM's value is in the semantic dimensions that code cannot assess.
- **Calibrate with your team**: The first batch of quality assessments should be reviewed by experienced detection engineers to calibrate whether the LLM's specificity expectations match your team's standards. Some organizations intentionally maintain broad rules as tripwires -- the LLM should know this if you include it in the quality rubric.
- **Track quality over time**: Store assessment results with timestamps. Track quality score trends per rule, per author, and per technique category. This makes the quality program measurable.
- **Cost management**: Quality assessment prompts are relatively large (full rule + technique description + few-shot examples). At ~2,000 tokens per rule assessment, a 500-rule batch costs approximately $5-15 depending on model. Running weekly is feasible; running on every commit may be wasteful for unchanged rules.

## Dependencies

- Deterministic linting and validation tools (run first, pass results to LLM)
- MITRE ATT&CK technique data for mapping validation
- LLM API access
- [UC-16: Observable Artifact Extraction](16-observable-artifact-extraction.md) -- Pre-extracted observables provide additional context for specificity assessment

## Complexity Assessment

| Dimension | Rating | Notes |
|---|---|---|
| Data engineering | Low | Rule parsing and MITRE data loading are straightforward. Deterministic check output is simple JSON. |
| AI/ML complexity | Medium | Requires well-crafted prompts with security domain context. Few-shot examples are critical for calibrating assessment depth and consistency. Multi-dimensional scoring requires careful prompt design. |
| Integration effort | Medium | Results need to feed into a quality dashboard or reporting system. Remediation recommendations should create tickets or annotate rules. CI/CD integration requires pipeline configuration. |
| Overall | **Medium** | The LLM prompting is not complex, but building a quality program around it (rubric definition, calibration, tracking, remediation workflow) requires organizational effort. |

## Real-World Considerations

- **Subjectivity in quality**: Quality assessment involves judgment calls. One engineer's "acceptably broad tripwire rule" is another's "noisy waste of analyst time." Define your quality rubric explicitly and include it in the prompt. The LLM should assess against your standards, not abstract ideals.
- **Author sensitivity**: Quality reports that call out individual authors' rules as low-quality can create friction. Frame assessments around rule improvement, not blame. Consider anonymizing authorship in quality reports.
- **Community rule quality**: Rules imported from community repositories (SigmaHQ, Elastic Detection Rules) may score poorly on specificity because they are written to be generic across environments. This is a feature, not a bug -- community rules are starting points. Quality assessment should flag them for environment-specific tuning, not rejection.
- **LLM confidence variation**: The LLM may express high confidence on specificity assessment (where the logic is concrete) but lower confidence on evasion gaps (which require open-ended adversary knowledge). Treat evasion gap identification as suggestive, not comprehensive.
- **The "good enough" threshold**: Not every rule needs a perfect quality score. Define a minimum acceptable quality bar and focus remediation effort on rules below it, particularly for high-impact techniques. Attempting to perfect every rule is not cost-effective.
- **Feedback loop**: When detection engineers fix rules based on LLM quality assessments, track whether the fixes actually improve detection outcomes (reduced FP rate, maintained or improved TP rate). This validates the quality criteria.

## Related Use Cases

- [UC-16: Observable Artifact Extraction](16-observable-artifact-extraction.md) -- Observable specificity directly informs quality assessment.
- [UC-17: Rule Comparison and Gap Analysis](17-rule-comparison-and-gap-analysis.md) -- Quality issues (incorrect MITRE mappings, overly broad rules) distort gap analysis results. Fix quality first.
- [UC-15: LLM Investigation Guide Generation](15-llm-investigation-guide-generation.md) -- Generating investigation guides from low-quality rules propagates quality issues into analyst workflows.
- [UC-19: Detection Rule Generation](19-detection-rule-generation.md) -- Quality assessment criteria should be applied to AI-generated rules as well.
- [UC-23: Synthetic Detection Testing Data Generation](23-synthetic-detection-testing-data.md) -- Quality assessment identifies evasion gaps; UC-23 generates test data targeting those gaps to validate that remediated rules actually detect the evasion variants.

## References

- [Sigma Rule Specification](https://sigmahq.io/sigma-specification/) -- Defines required and optional fields for Sigma rules.
- [MITRE ATT&CK](https://attack.mitre.org/) -- Technique descriptions for mapping validation.
- [Elastic Detection Rules Contribution Guide](https://github.com/elastic/detection-rules/blob/main/CONTRIBUTING.md) -- Example of a detection rule quality standard.
- [SigmaHQ Rule Creation Guide](https://github.com/SigmaHQ/sigma/wiki/Rule-Creation-Guide) -- Community guidelines for Sigma rule quality.
- [Florian Roth - Detection Rule Quality](https://github.com/SigmaHQ/sigma/wiki/Detection) -- Discussion of detection specificity in the Sigma context.
