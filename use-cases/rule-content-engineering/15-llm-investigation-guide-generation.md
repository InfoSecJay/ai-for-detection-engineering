# UC-15: LLM Investigation Guide Generation

## Category

Rule Content Engineering

## Summary

Uses an LLM to generate structured investigation guides (runbooks) for detection rules by reasoning about the rule's detection logic, data sources, and ATT&CK context. The output is an analyst-facing guide that describes what to verify first, which log sources to check, how to distinguish true positives from false positives, what evidence to collect, and when to escalate. This goes beyond template-based documentation because each rule's detection logic demands context-specific reasoning that static templates cannot produce at scale.

## Problem Statement

Detection engineering teams maintain hundreds to thousands of rules across SIEMs. Each rule should have an accompanying investigation guide so Tier 1/2 analysts know how to respond when the rule fires. In practice, most rules ship with either no runbook, a generic boilerplate paragraph, or a description written at authoring time that drifts from the actual detection logic over time.

Writing quality investigation guides manually is expensive: a detection engineer who understands the rule's logic, the data source quirks, and the operational context needs 30-60 minutes per rule. For a rule set of 500+ rules, this is a multi-month project that rarely gets prioritized over writing new detections.

Template-based approaches (e.g., "Step 1: Check the source IP") are too generic to be useful. A guide for a rule detecting LSASS memory access requires fundamentally different investigation steps than one detecting anomalous DNS queries or a cloud IAM policy change. The investigation logic depends on what the rule actually detects, which fields it examines, what the expected attack chain looks like, and what benign activity commonly triggers it.

Deterministic tooling can parse rule metadata, but it cannot reason about what an analyst should do with the alert. That reasoning step is where LLMs add value.

## Prerequisites (What Your SIEM/SOAR Should Already Handle)

- **Rule metadata extraction**: Rule name, description, severity, MITRE ATT&CK tags, data source, and query/detection logic should be programmatically extractable from your rule format (Sigma YAML, Elastic TOML, Splunk savedsearches.conf, etc.). This is parsing, not AI.
- **MITRE ATT&CK mapping**: Rules should already have technique/sub-technique tags. If your rules lack ATT&CK tags, fix that first -- it is a metadata quality problem, not an AI problem.
- **Rule storage in version control**: Rules should live in a Git repository with a consistent format so you can iterate over them programmatically.
- **Existing documentation standards**: Your team should have a defined structure for what a "good" investigation guide contains (sections, depth, terminology). The LLM generates content to fit your standard, not invent one.

## Where AI Adds Value

The LLM reasons about the rule's detection logic to produce investigation-specific guidance that a template engine cannot. Specifically:

1. **Contextual triage steps**: Given that a rule looks for `process.parent.name: winword.exe AND process.name: powershell.exe`, the LLM infers that the analyst should check whether the PowerShell command line contains encoded commands, whether the Word document was opened from email or a browser download, and whether the user is in a group that routinely uses macros.

2. **True positive vs. false positive reasoning**: The LLM identifies likely FP sources based on the rule's logic. A rule matching `schtasks.exe /create` will have different FP patterns (IT automation, SCCM) than one matching `wmic shadowcopy delete` (backup software).

3. **Evidence collection guidance**: Based on what the rule detects, the LLM describes what additional artifacts to collect -- surrounding process tree, network connections from the same host, authentication events in the same timeframe, etc.

4. **Escalation criteria**: The LLM generates specific conditions under which an analyst should escalate, tied to the rule's context (e.g., "Escalate immediately if the parent process is a browser and the child process attempts to disable Windows Defender").

5. **Cross-rule consistency with per-rule specificity**: When processing hundreds of rules, the LLM maintains a consistent structure while tailoring content to each rule's unique detection logic.

## AI Approach

**LLM prompting with few-shot examples.**

The core pattern is:
1. Parse rule metadata and detection logic deterministically (pySigma, custom parsers, or direct YAML/TOML parsing).
2. Construct a structured prompt containing the rule's full context: name, description, severity, MITRE technique, detection query, data source fields, and any existing documentation.
3. Provide 3-5 few-shot examples of high-quality investigation guides written by experienced detection engineers for representative rule types (endpoint process, network connection, cloud API, authentication, file modification).
4. Instruct the LLM to generate a guide following the exact section structure your team uses.
5. Post-process the output: validate section presence, check for hallucinated field names, enforce formatting.

**Why few-shot over fine-tuning**: The task is generation with structure, not classification. Few-shot examples establish the format, tone, and depth. Fine-tuning is warranted only if you have 500+ gold-standard guides and need cost optimization at scale.

This is an evolution of the [sigma-llm-doc](https://github.com/InfoSecJay/sigma-llm-doc) approach, extended with structured prompting, few-shot examples, and post-processing validation.

## Data Requirements

### Inputs

| Input | Format | Key Fields Used |
|---|---|---|
| Detection rule file | Sigma YAML, Elastic TOML, Splunk YAML, or KQL/SPL query | Rule name, description, severity, MITRE tags, detection/query block, data source, log source fields |
| MITRE ATT&CK context | ATT&CK STIX data or technique descriptions | Technique name, description, data sources, mitigations, procedure examples |
| Few-shot example guides | Markdown or structured text | 3-5 exemplary investigation guides written by your team for diverse rule categories |
| Rule metadata enrichment (optional) | JSON/YAML | Historical alert volume, known FP sources, linked incidents |

> **Note:** Alert data follows the SIEM's standard alert schema with normalized source event fields. Rule files follow their format's defined schema (Elastic TOML, Sigma YAML, Splunk YAML, etc.). These are structured, documented formats -- see [data-requirements/](../../data-requirements/) for platform-specific field references.

### Outputs

A structured investigation guide per rule, in markdown or your documentation system's format. Concrete example for a Sigma rule detecting LSASS memory access:

```markdown
## Investigation Guide: Potential LSASS Memory Access via Procdump

### Priority Actions
1. **Verify the process execution chain**: Confirm that `procdump.exe` (or a renamed
   binary with the same hash) was executed with the `-ma lsass.exe` argument. Check
   `process.command_line` for the full arguments.
2. **Check process parent**: Identify the parent process. If the parent is `cmd.exe`
   or `powershell.exe`, determine how that shell was launched. A shell spawned by a
   remote access tool or a service account is higher risk than an interactive admin session.
3. **Validate the user context**: Is the executing user a domain admin or local admin?
   Was this an interactive logon or a service/batch logon?

### Log Sources to Check
- **Sysmon Event ID 10** (ProcessAccess): Look for `TargetImage` matching `lsass.exe`
  with `GrantedAccess` values of `0x1010` or `0x1FFFFF` in the same time window.
- **Sysmon Event ID 1** (ProcessCreate): Full process tree for the host in a +/- 5
  minute window around the alert.
- **Windows Security Event 4688**: Corroborate process creation if Sysmon is unavailable.
- **EDR telemetry**: Check for file writes to `%TEMP%` or the working directory with
  `.dmp` extension immediately after execution.

### True Positive Indicators
- `procdump.exe` executed with `-ma lsass.exe` or `-ma <LSASS PID>` arguments.
- The binary is not signed by Microsoft Sysinternals (renamed/modified procdump).
- Execution occurs outside of a known change window or troubleshooting ticket.
- Dump file written and subsequently accessed by another process or exfiltrated.

### Common False Positive Sources
- **IT diagnostics**: System administrators using Procdump for legitimate crash dump
  collection. Verify against change management or ticketing systems.
- **Monitoring tools**: Some APM or crash reporting tools invoke Procdump legitimately.
  Check if the parent process is a known monitoring agent.
- **Whitelisted paths**: If your organization has approved Procdump usage from specific
  directories (e.g., `C:\Tools\SysInternals\`), verify the execution path.

### Evidence to Collect Before Escalation
- Full process tree (parent, grandparent, child processes)
- Complete command line arguments
- File hash of the executing binary
- Any `.dmp` files created in the surrounding time window
- Network connections from the host within +/- 15 minutes
- Authentication events for the executing user in the past hour

### Escalation Criteria
- Escalate to Tier 3 / IR immediately if:
  - The binary is not the legitimate Sysinternals Procdump
  - No change ticket or admin justification exists
  - Additional credential access indicators are present on the same host
  - The dump file was transferred off the host
```

## Implementation Notes

- **Batch processing pipeline**: Process rules in batch (e.g., nightly CI job). Parse all rules from the repo, generate guides, output to a documentation directory or wiki system. Do not call the LLM inline during alert handling.
- **Consistency enforcement**: The key challenge at scale is consistency. When generating guides for 500+ rules, LLM outputs will drift in structure, depth, and terminology. Mitigate this by:
  - Using a rigid output schema (JSON with required sections, then render to markdown).
  - Validating output against the schema before accepting.
  - Including the same few-shot examples in every prompt to anchor style.
  - Running a second LLM pass to check consistency against your style guide if needed.
- **Hallucination risk**: LLMs may reference field names, log sources, or event IDs that do not exist in your environment. Post-process by cross-referencing generated field names against your SIEM's field list and flagging unknown fields for human review.
- **Iterative refinement**: Start with your highest-severity rules. Have detection engineers review and correct the first 50 guides, then use the best corrections as updated few-shot examples.
- **Version control**: Store generated guides alongside the rules in Git. Regenerate when rules change. Track which model version and prompt version generated each guide.
- **Token management**: Complex rules with long queries may require careful prompt construction to stay within context limits. Summarize or truncate verbose queries while preserving detection-relevant fields.

## Dependencies

- Access to rule repository with parseable rule files
- MITRE ATT&CK data for technique context enrichment
- LLM API access (cloud-hosted or self-hosted)
- Human reviewers for initial quality validation loop

## Complexity Assessment

| Dimension | Rating | Notes |
|---|---|---|
| Data engineering | Low | Rule parsing is straightforward with existing libraries (pySigma, TOML parsers). Few-shot examples require one-time curation effort. |
| AI/ML complexity | Medium | Prompt engineering with few-shot examples. No fine-tuning required initially. Consistency at scale is the main challenge. |
| Integration effort | Low | Batch process outputs markdown/JSON. Integration is writing files to a docs system or wiki API. |
| Overall | **Medium** | The technical implementation is simple. The effort is in curating good few-shot examples, validating outputs, and building the feedback loop with analysts. |

## Real-World Considerations

- **Analyst trust**: Analysts will not follow generated guides if the first few they read contain incorrect field names or irrelevant steps. Invest in quality validation for the initial batch before rolling out broadly.
- **Staleness**: Guides must be regenerated when rules change. Build this into your rule CI/CD pipeline -- when a rule's detection logic is modified, trigger guide regeneration.
- **Organizational knowledge**: The LLM does not know your environment's specific FP sources (e.g., "the finance team runs a scheduled PowerShell script every Monday at 3am"). Consider providing environment-specific context in the prompt or maintaining a FP knowledge base that gets injected as context.
- **Metric**: Track analyst feedback on guide usefulness. A simple thumbs-up/thumbs-down on each guide during alert handling builds a quality signal over time.
- **Cost**: At approximately $0.01-0.05 per guide generation (depending on model and prompt size), generating guides for 1,000 rules costs $10-50. Regeneration on rule changes is negligible. This is not a cost-prohibitive workload.

## Related Use Cases

- [UC-16: Observable Artifact Extraction](16-observable-artifact-extraction.md) -- Extracted observables feed into the "what to look for" section of investigation guides.
- [UC-18: Rule Quality Assessment](18-rule-quality-assessment.md) -- Quality issues identified in rules should be fixed before generating investigation guides from flawed logic.
- [UC-19: Detection Rule Generation](19-detection-rule-generation.md) -- When new rules are generated, investigation guides should be generated alongside them.

## References

- [sigma-llm-doc](https://github.com/InfoSecJay/sigma-llm-doc) -- Original project for LLM-based Sigma rule documentation generation.
- [Sigma Rule Specification](https://sigmahq.io/sigma-specification/) -- Sigma rule format reference.
- [MITRE ATT&CK](https://attack.mitre.org/) -- Technique descriptions used for context enrichment.
- [pySigma](https://github.com/SigmaHQ/pySigma) -- Python library for Sigma rule parsing and manipulation.
