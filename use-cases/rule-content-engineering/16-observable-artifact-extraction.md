# UC-16: Observable Artifact Extraction

## Category

Rule Content Engineering

## Summary

Uses an LLM to extract and classify observable artifacts (indicators, field-value pairs, behavioral patterns) from detection rule queries, particularly when those queries use complex logic, nested conditions, wildcards, or regex that resist straightforward programmatic parsing. The output is a structured inventory of what each rule actually looks for -- process names, file paths, registry keys, network indicators, cloud API calls -- classified by type and assessed for specificity. This enables downstream use cases like coverage mapping, indicator management, and detection gap analysis.

## Problem Statement

Detection rules encode what to look for, but that knowledge is locked inside query syntax. A Sigma rule's detection block, a KQL query, or an SPL search each express observables differently, and extracting a clean list of "this rule looks for these specific artifacts" is harder than it appears.

For simple rules, this is a parsing problem. A Sigma rule with `process.name: mimikatz.exe` yields one observable trivially. But real-world detection rules are often complex:

- KQL queries with nested `where` clauses, `let` statements, `join` operations, and multiple conditions combined with `and`/`or`
- EQL sequences matching multiple events with shared field bindings across sequence steps
- SPL queries using `eval`, `rex`, `lookup`, and subsearches
- Regex patterns and wildcards that imply a class of artifacts rather than a literal value (e.g., `CommandLine|contains: '-enc'` implies Base64-encoded PowerShell, not a single string)
- Boolean logic where the meaningful observable is the combination of conditions, not any individual field

Deterministic parsers handle the straightforward cases well. pySigma can parse Sigma's detection block into field-value mappings. But when you need to understand what a complex KQL query with three joins and a regex extraction is actually observing, you need semantic analysis -- understanding the query's intent, not just its syntax tree.

## Prerequisites (What Your SIEM/SOAR Should Already Handle)

- **Basic field extraction from structured rule formats**: For Sigma rules, pySigma already parses the detection block into field-value pairs. Use it. Do not send simple Sigma rules to an LLM when a parser handles them deterministically.
- **Query syntax validation**: Queries should be syntactically valid before analysis. Malformed queries confuse LLMs just as they confuse parsers.
- **Normalized field naming**: Your rules should use consistent field naming (ECS, CIM, or your own schema). Observable extraction is more useful when field names are normalized.
- **Rule inventory**: You need a catalog of your rules in a parseable format, stored in version control or accessible via API.

## Where AI Adds Value

The LLM performs semantic analysis of query logic that goes beyond syntax parsing:

1. **Complex query interpretation**: Given a KQL query like:
   ```kql
   DeviceProcessEvents
   | where InitiatingProcessFileName in~ ("winword.exe", "excel.exe", "powerpnt.exe")
   | where FileName in~ ("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe")
   | where ProcessCommandLine matches regex @"(?i)(whoami|net\s+user|net\s+group|nltest|dsquery)"
   ```
   The LLM extracts: parent process observables (Office applications), child process observables (command interpreters), and command-line pattern observables (reconnaissance commands) -- and classifies the rule's behavioral pattern as "Office application spawning command interpreter executing reconnaissance."

2. **Wildcard and regex expansion**: A field like `CommandLine|contains|all: ['-nop', '-w hidden', '-enc']` does not describe a single artifact but a behavioral class. The LLM identifies this as "PowerShell execution with execution policy bypass, hidden window, and encoded command" rather than just listing three substrings.

3. **Observable type classification**: The LLM categorizes extracted artifacts by type -- process (name, path, command line), file (path, name, hash, extension), registry (key, value), network (IP, domain, port, protocol), authentication (user, logon type), cloud (API call, resource type, permission) -- enabling downstream filtering and analysis.

4. **Specificity assessment**: The LLM evaluates whether an observable is high-specificity (e.g., a unique tool name like `rubeus.exe`) or low-specificity (e.g., `cmd.exe` which fires constantly). This assessment informs detection tuning and coverage analysis.

5. **Cross-event sequence analysis**: For EQL sequence rules or Splunk transaction-based detections, the LLM identifies which observables appear in which event within the sequence and how they relate (e.g., "Event 1 matches a process creation, Event 2 matches a network connection from the same process within 30 seconds").

## AI Approach

**LLM prompting for query semantic analysis.**

The workflow follows a tiered strategy:

1. **Tier 1 -- Deterministic parsing** (no LLM): For Sigma rules with simple detection blocks, use pySigma or equivalent parsers to extract field-value pairs. Only escalate to the LLM tier when the parser output is insufficient (complex logic, platform-specific queries, regex patterns).

2. **Tier 2 -- LLM extraction**: For complex queries, send the full query text to an LLM with a structured prompt requesting:
   - All observable artifacts as a JSON array
   - Each artifact's type (process, file, registry, network, auth, cloud)
   - Each artifact's specificity rating (high, medium, low)
   - The behavioral pattern the query describes in one sentence
   - Any implicit observables (e.g., "the query implicitly requires Sysmon Event ID 1 data")

3. **Post-processing**: Validate extracted artifacts against known field names in your schema. Flag any artifacts the LLM generated that do not correspond to actual query fields.

Prompt structure:
- System message establishing the LLM as a detection engineering analyst
- The query text and query language identifier
- The rule's metadata (name, description, MITRE mapping) for additional context
- Output schema (JSON) with required fields
- 2-3 few-shot examples covering simple, moderate, and complex queries

## Data Requirements

### Inputs

| Input | Format | Key Fields Used |
|---|---|---|
| Detection rule query | KQL, EQL, SPL, Sigma YAML detection block, or Lucene | Full query text, query language identifier |
| Rule metadata | YAML, TOML, or JSON | Rule name, description, MITRE tags, data source, severity |
| Field schema reference (optional) | JSON/CSV | Known field names in your SIEM schema (ECS, CIM) for validation |

> **Note:** Alert data follows the SIEM's standard alert schema with normalized source event fields. Rule files follow their format's defined schema (Elastic TOML, Sigma YAML, Splunk YAML, etc.). These are structured, documented formats -- see [data-requirements/](../../data-requirements/) for platform-specific field references.

### Outputs

A structured JSON object per rule containing extracted observables. Example output for the KQL query shown above:

```json
{
  "rule_name": "Office Application Spawning Reconnaissance Commands",
  "rule_id": "abc-123",
  "behavioral_summary": "Detects Microsoft Office applications spawning command-line interpreters that execute reconnaissance commands, indicating potential macro-based initial access followed by discovery activity.",
  "observables": [
    {
      "field": "InitiatingProcessFileName",
      "values": ["winword.exe", "excel.exe", "powerpnt.exe"],
      "type": "process",
      "subtype": "parent_process_name",
      "specificity": "medium",
      "note": "Standard Office binaries. Common on endpoints, but significant as parent processes for shells."
    },
    {
      "field": "FileName",
      "values": ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"],
      "type": "process",
      "subtype": "child_process_name",
      "specificity": "medium",
      "note": "Command interpreters and script hosts. Low specificity individually; significant when spawned by Office."
    },
    {
      "field": "ProcessCommandLine",
      "values": ["whoami", "net user", "net group", "nltest", "dsquery"],
      "type": "process",
      "subtype": "command_line_pattern",
      "specificity": "high",
      "note": "Reconnaissance commands commonly used in post-exploitation discovery (T1033, T1087, T1482)."
    }
  ],
  "implicit_requirements": [
    "Requires DeviceProcessEvents table (Microsoft Defender for Endpoint)",
    "Parent-child process relationship must be captured by the data source"
  ],
  "detection_chain": [
    "Office application (initial access vector) -> Command interpreter (execution) -> Reconnaissance command (discovery)"
  ]
}
```

## Implementation Notes

- **Tiered approach is critical**: Do not send every rule to an LLM. Simple Sigma rules with `detection:` blocks containing direct field-value pairs should be parsed deterministically. Reserve LLM calls for queries where a parser would miss semantic meaning -- regex patterns, complex boolean logic, multi-event sequences, platform-specific query languages with procedural elements (SPL eval, KQL let statements).
- **Query language identification**: Ensure the prompt tells the LLM which query language it is analyzing. KQL, EQL, SPL, and Lucene have different semantics for the same-looking syntax. Misidentification leads to incorrect extraction.
- **Batch processing**: Run extraction as a batch job across your rule set. Cache results and re-extract only when rules change (triggered by Git diffs on rule files).
- **Schema validation**: Cross-reference extracted field names against your SIEM's field list. If the LLM reports an observable on field `process.parent.command_line` but your schema uses `process.parent.args`, flag the mismatch. This catches both LLM hallucinations and schema inconsistencies in your rules.
- **Output storage**: Store extraction results in a structured format (JSON, database) alongside the rule. This creates a searchable observable inventory: "Which rules look for `schtasks.exe`?" becomes a database query instead of a grep across query files.

## Dependencies

- pySigma or equivalent parser for deterministic extraction of simple rules
- LLM API access for complex query analysis
- Field schema reference for your SIEM environment (optional but recommended for validation)

## Complexity Assessment

| Dimension | Rating | Notes |
|---|---|---|
| Data engineering | Low | Rule files are already structured. Parsing metadata is straightforward. |
| AI/ML complexity | Low-Medium | Single-turn LLM prompting with structured output. No fine-tuning needed. Prompt engineering focuses on query language awareness and output schema adherence. |
| Integration effort | Low | Batch output to JSON files or database. No real-time integration required. |
| Overall | **Low-Medium** | The tiered approach (deterministic first, LLM for complex cases) keeps AI usage targeted. Main effort is curating few-shot examples across query languages. |

## Real-World Considerations

- **Query language coverage**: Most organizations use 1-2 query languages. Build and test prompts for your specific languages rather than trying to support all languages from day one.
- **False extractions**: LLMs occasionally extract artifacts that are part of the query infrastructure (table names, function calls) rather than security-relevant observables. Include explicit instructions to distinguish between "query mechanics" and "detection-relevant observables."
- **Wildcard semantics**: A wildcard like `*.exe` in a file path means something very different than `mimikatz*` in a process name. The LLM should report wildcards as patterns with context, not expand them into arbitrary values.
- **Maintenance**: When rules are updated, extraction results must be refreshed. Integrate this into your rule CI/CD pipeline.
- **Value compounding**: The extracted observable inventory becomes increasingly valuable as it grows. It enables queries like "show me all rules that detect `certutil.exe`" or "which techniques have no rules looking at registry modifications?" -- questions that are expensive to answer by manually reading queries.

## Related Use Cases

- [UC-15: LLM Investigation Guide Generation](15-llm-investigation-guide-generation.md) -- Extracted observables inform the "what to look for" section of investigation guides.
- [UC-17: Rule Comparison and Gap Analysis](17-rule-comparison-and-gap-analysis.md) -- Observable inventories enable precise comparison of what two rules actually detect.
- [UC-18: Rule Quality Assessment](18-rule-quality-assessment.md) -- Observable specificity ratings feed into quality assessment (low-specificity-only rules may need tuning).

## References

- [pySigma](https://github.com/SigmaHQ/pySigma) -- Python library for Sigma rule parsing; handles deterministic extraction of simple detection blocks.
- [Elastic Common Schema (ECS)](https://www.elastic.co/guide/en/ecs/current/index.html) -- Field naming reference for Elastic-based environments.
- [Splunk Common Information Model (CIM)](https://docs.splunk.com/Documentation/CIM/latest/User/Overview) -- Field naming reference for Splunk environments.
- [MITRE ATT&CK Data Sources](https://attack.mitre.org/datasources/) -- Reference for mapping observables to ATT&CK data source objects.
