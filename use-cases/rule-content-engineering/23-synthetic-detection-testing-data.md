# UC-23: Synthetic Detection Testing Data Generation

## Category

Rule Content Engineering

## Summary

Uses an LLM to generate realistic synthetic log events -- labeled as true positive, false positive, or evasion variant -- for testing whether detection rules actually fire correctly. This addresses the gap between writing a detection rule and knowing whether it works against diverse attack variants, edge cases, and realistic benign activity. Unlike running actual attack simulations (Atomic Red Team, Caldera) or replaying captured logs, the LLM reasons about what log artifacts a technique produces across different environments and generates diverse, schema-compliant test data without requiring execution infrastructure.

## Problem Statement

Detection rules are frequently deployed without meaningful testing. The common failure modes:

1. **No testing at all**: A rule is written or imported from a community repository and deployed directly to production. It may silently fail to match due to field name mismatches, incorrect log source references, or query logic that never evaluates to true against the environment's actual event format. The rule sits in the SIEM generating false confidence in detection coverage.

2. **Running real attacks is expensive and constrained**: Atomic Red Team, Caldera, and purple team exercises require a test environment (often unavailable or not representative of production), safety controls to prevent damage, scheduling coordination, and specialized expertise. Many techniques cannot be safely executed in production environments -- credential dumping, lateral movement, data destruction, or techniques targeting domain controllers. This means most rules are tested against only a handful of known-good procedure variants, if they are tested at all.

3. **Captured log replays are static**: Replaying captured attack logs validates that a rule fires against one specific procedure variant captured at one point in time. It does not test robustness against variations: different parameter orderings, renamed binaries, alternative tools for the same technique, environment-specific field values, or encoding variants. Maintaining a comprehensive library of captured test data for every detection rule is an ongoing burden that scales poorly.

4. **Template-based log generation is shallow**: Tools that generate logs by filling in templates (e.g., "insert a random IP and timestamp into this syslog template") produce structurally valid but behaviorally shallow data. They do not reason about what a realistic attack sequence looks like, what tool variations an attacker would use, or what benign activity is similar enough to cause false positives.

5. **False positive testing is almost never done**: Detection testing almost exclusively focuses on true positives -- "does the rule fire when the attack happens?" The equally important question -- "does the rule fire when legitimate activity happens?" -- is rarely tested because generating realistic benign activity that occupies the same observational space as the attack requires understanding both the attack pattern and legitimate operational workflows.

An LLM can reason about what log artifacts a specific ATT&CK technique produces, generate diverse procedure variants, create realistic benign activity that tests false positive behavior, and adapt generated data to match a specific environment's log schema -- filling the gap between static test approaches and the diversity of real-world attack and operational behavior.

## Prerequisites (What Your SIEM/SOAR Should Already Handle)

- **Log schema documentation**: Your environment's log schemas (ECS field mappings, CIM fields, ASIM fields, or custom schemas) must be documented. The AI generates data conforming to these schemas -- it does not discover or define them.
- **Test/staging SIEM environment**: A staging SIEM or log ingestion pipeline where generated data can be injected and rules evaluated. This is infrastructure, not AI.
- **Detection-as-code CI/CD pipeline**: A pipeline where rules can be tested against injected data and results asserted programmatically. Tools like Elastic's detection-rules repo testing framework, Splunk's `contentctl test`, or custom pytest harnesses. The pipeline ingests test data, evaluates rules, and reports pass/fail.
- **Basic template-based generation for structural validation**: For simple validation (does the rule parse? does the query syntax compile?), template-based tools and platform-native validation handle the job deterministically.
- **Atomic Red Team / Caldera for ground truth**: When you can safely execute a technique in a test environment, do so. Real execution produces real artifacts with full fidelity. AI-generated synthetic data is for when real execution is impractical, when you need diverse variants beyond what a single execution produces, or when you need false-positive test cases that no attack simulation can generate.

## Where AI Adds Value

1. **Technique-aware log artifact reasoning**: The LLM understands what observable artifacts a specific ATT&CK technique produces across different log sources. Given "T1053.005 -- Scheduled Task via schtasks.exe," the LLM generates: a Sysmon Event ID 1 (process creation) with realistic `CommandLine`, `ParentImage`, and `User` fields; a Windows Security Event 4698 (task created) with the task XML; and a Sysmon Event ID 11 (file create) for the task file in `C:\Windows\System32\Tasks\`. This requires security domain knowledge about technique-to-artifact mappings -- not template filling.

2. **Attack variant diversity**: Given a single technique, the LLM generates multiple procedure variants that test rule robustness:
   - Standard: `schtasks /create /tn "UpdateCheck" /tr "powershell.exe -enc JAB..." /sc onlogon`
   - Renamed binary: `C:\Users\Public\svc.exe /create /tn ...` (schtasks.exe copied and renamed)
   - COM API variant: Log sequence showing `taskschd.dll` loaded by a process using the Task Scheduler COM interface directly
   - PowerShell cmdlet: `Register-ScheduledTask` with equivalent parameters
   - Parameter order variation: `/sc onlogon /create /tn "UpdateCheck" /tr ...`

   This directly tests whether a rule detects the technique or merely detects a specific tool invocation (complementing UC-18's quality assessment).

3. **False positive test case generation**: The LLM generates realistic benign activity that resembles the attack pattern but should NOT trigger the rule -- or, if it does, reveals an overly broad rule needing tuning:
   - Legitimate schtasks usage by SCCM deploying a software update task
   - An IT administrator creating a scheduled backup task with a similar command structure
   - Windows Update creating scheduled tasks with SYSTEM-level credentials
   - A monitoring agent creating health-check scheduled tasks

   This is where AI genuinely excels -- reasoning about what legitimate operational activity occupies the same observational space as malicious behavior. No attack simulation tool generates false-positive test cases.

4. **Environment-specific schema adaptation**: Given a target log schema (ECS, CIM, ASIM, or custom), the LLM generates test data with correct field names, data types, and realistic values for that environment. This avoids the common problem where test data uses generic or example field names that do not match the production schema, causing tests to pass on field structure but fail on field naming.

5. **Evasion scenario generation**: Given a detection rule's query logic, the LLM reasons about evasion techniques that would bypass the rule and generates log data representing those evasion attempts:
   > "This rule detects `certutil.exe` with `-urlcache` in the command line. Evasion test cases: (1) Using `certutil` without the `.exe` extension, (2) Using `-URLcache` with different casing, (3) Using `CertReq.exe` as an alternative download utility, (4) Using `curl.exe` (available natively on modern Windows) for the same download operation."

   Evasion test events are labeled with `expected_detection: false` and include a note explaining the evasion technique, directly feeding back into rule improvement.

## AI Approach

**LLM prompting with structured log schema context and ATT&CK technique grounding.**

### Workflow 1: Technique-to-Test-Data Generation

1. Input: ATT&CK technique ID + target log schema + (optional) target detection rule
2. Retrieve technique description and procedure examples from ATT&CK STIX data (deterministic lookup)
3. Construct prompt with: technique description, known procedure examples, target log format/schema definition, available field names and data types, and environment context (OS versions, domain naming conventions, common legitimate software)
4. Request: N true-positive test events across different procedure variants, M false-positive test events representing realistic benign activity, K evasion variant events
5. Output: Structured log events in the target format (JSON, XML, key-value) with labels indicating expected detection outcome (TP, FP, evasion)

### Workflow 2: Rule-Specific Test Data Generation

1. Input: A specific detection rule (full content) + target log schema
2. Parse rule deterministically to extract: query logic, fields referenced, conditions, exceptions/allowlists
3. Construct prompt with: the rule content, its detection logic explained, the target schema, and request for test events that (a) should trigger the rule, (b) should NOT trigger the rule but are in the same behavioral space, (c) represent evasion variants that bypass the rule's specific logic
4. Output: Labeled test event set with expected outcome per event and explanatory notes

### Workflow 3: Attack Scenario Sequence Generation

1. Input: A multi-step attack scenario description or kill chain specification
2. The LLM generates a chronologically coherent sequence of log events across multiple data sources representing the full attack chain
3. Events share consistent entity values (same hostname, user, process tree relationships) and realistic timestamps with appropriate intervals
4. This tests correlation rules and multi-rule detection chains -- whether the sequence of individual rule fires produces the expected correlated detection

## Data Requirements

### Inputs

| Input | Format | Key Fields Used |
|---|---|---|
| ATT&CK technique description | STIX JSON or technique text | Technique name, ID, description, data sources, procedure examples |
| Target log schema | JSON schema, ECS mapping doc, or field reference | Field names, data types, required vs. optional fields |
| Detection rule (optional) | Sigma YAML, Elastic TOML, KQL, SPL, EQL | Detection logic, referenced fields, exception conditions |
| Environment context (optional) | Structured text or JSON | Domain names, common hostnames, legitimate software inventory, OS versions |
| Test coverage specification | Structured request | Number of TP/FP/evasion variants, specific procedure variants to cover |

> **Note:** Alert data follows the SIEM's standard alert schema with normalized source event fields. Rule files follow their format's defined schema (Elastic TOML, Sigma YAML, Splunk YAML, etc.). These are structured, documented formats -- see [data-requirements/](../../data-requirements/) for platform-specific field references.

### Outputs

A labeled set of synthetic log events with expected detection outcomes. Example output for a scheduled task creation test set:

```json
{
  "test_set": "T1053.005-schtasks-creation",
  "target_rule": "Suspicious Scheduled Task Creation",
  "target_schema": "ECS 8.x (Sysmon)",
  "generated_by": "AI-Generated Test Data (requires human review)",
  "events": [
    {
      "label": "true_positive",
      "variant": "standard_schtasks",
      "description": "Basic schtasks.exe creating persistence task with encoded PowerShell",
      "event": {
        "@timestamp": "2025-03-15T14:23:01.000Z",
        "event.code": "1",
        "event.provider": "Microsoft-Windows-Sysmon",
        "process.name": "schtasks.exe",
        "process.executable": "C:\\Windows\\System32\\schtasks.exe",
        "process.command_line": "schtasks /create /tn \"SystemUpdate\" /tr \"powershell.exe -enc SQBuAHYAbwBrAGUALQBXAGUA...\" /sc onlogon /ru SYSTEM",
        "process.parent.name": "cmd.exe",
        "process.parent.executable": "C:\\Windows\\System32\\cmd.exe",
        "user.name": "test_user",
        "host.name": "WORKSTATION-TEST-42",
        "host.os.name": "Windows 10 Enterprise"
      },
      "expected_detection": true,
      "notes": "Standard procedure variant. Rule should fire on schtasks.exe with /create and encoded PowerShell in task action."
    },
    {
      "label": "false_positive",
      "variant": "legitimate_sccm_task",
      "description": "SCCM client creating scheduled task for software deployment",
      "event": {
        "@timestamp": "2025-03-15T02:00:01.000Z",
        "event.code": "1",
        "event.provider": "Microsoft-Windows-Sysmon",
        "process.name": "schtasks.exe",
        "process.executable": "C:\\Windows\\System32\\schtasks.exe",
        "process.command_line": "schtasks /create /tn \"\\Microsoft\\Configuration Manager\\Configuration Manager Health Evaluation\" /tr \"C:\\Windows\\CCM\\ccmeval.exe\" /sc daily /st 00:00",
        "process.parent.name": "CcmExec.exe",
        "process.parent.executable": "C:\\Windows\\CCM\\CcmExec.exe",
        "user.name": "SYSTEM",
        "host.name": "WORKSTATION-TEST-42",
        "host.os.name": "Windows 10 Enterprise"
      },
      "expected_detection": false,
      "notes": "Legitimate SCCM task creation. If rule fires, it needs an exception for CcmExec.exe parent process or Configuration Manager task paths."
    },
    {
      "label": "evasion",
      "variant": "com_api_bypass",
      "description": "Scheduled task created via PowerShell cmdlet, bypassing schtasks.exe entirely",
      "event": {
        "@timestamp": "2025-03-15T14:23:45.000Z",
        "event.code": "1",
        "event.provider": "Microsoft-Windows-Sysmon",
        "process.name": "powershell.exe",
        "process.executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "process.command_line": "powershell.exe -c \"$action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c whoami > C:\\temp\\out.txt'; Register-ScheduledTask -TaskName 'Updater' -Action $action -Trigger (New-ScheduledTaskTrigger -AtLogon)\"",
        "process.parent.name": "explorer.exe",
        "process.parent.executable": "C:\\Windows\\explorer.exe",
        "user.name": "test_user",
        "host.name": "WORKSTATION-TEST-42",
        "host.os.name": "Windows 10 Enterprise"
      },
      "expected_detection": false,
      "notes": "Rule targeting schtasks.exe will miss this. Exposes detection gap: technique T1053.005 can be performed via Register-ScheduledTask cmdlet without invoking schtasks.exe. Consider companion rule."
    }
  ]
}
```

## Implementation Notes

- **Generated data is test data, not ground truth.** Synthetic events are approximations of what real attacks produce. They validate rule logic and field matching, not real-world detection fidelity. Always supplement with real execution (Atomic Red Team) when feasible.
- **Schema validation is deterministic.** After LLM generation, validate that every field name exists in the target schema, data types are correct, and timestamps are well-formed. Do not trust the LLM to produce perfectly schema-compliant output -- run a JSON schema validator post-generation.
- **Label every event explicitly.** Every generated event must carry its expected detection outcome (true positive, false positive, evasion) and explanatory notes. This enables automated test assertions: inject events, assert the rule fires on TP-labeled events, assert it does NOT fire on FP-labeled events, and report which evasion variants it misses.
- **Integrate with detection-as-code CI/CD.** The highest-value integration is generating test data as part of the rule PR/merge pipeline. When a detection engineer submits a new rule, the LLM generates a test set, the pipeline injects the data into a staging SIEM, and the test framework verifies the rule fires correctly. This makes test data generation a CI step, not a manual process.
- **Batch generation for technique sprints.** When building detection for a technique area, generate test data for all related rules simultaneously. This ensures consistent entity values across related tests (same hostname, domain context) and enables testing correlation rules that depend on multiple individual rules firing.
- **Cost is minimal.** Test data generation prompts are moderate-sized (~1,500-3,000 tokens per test set). Generating 20 test sets costs under $1. The cost constraint is human review of generated test data and pipeline integration, not API spend.
- **Hallucination risk in field values.** The LLM may generate field values that look realistic but are technically invalid -- impossible process parent-child relationships, Sysmon event codes that do not correspond to the event type, Windows SIDs with incorrect format, or timestamps that violate causality. Provide explicit schema constraints and validate generated events post-generation. Include a "known valid values" reference for constrained fields (event codes, log provider names).
- **Use obviously synthetic entity values.** Instruct the LLM to use clearly synthetic identifiers (e.g., `WORKSTATION-TEST-42`, `test_user@example.com`, `192.168.100.x`) rather than values that could be mistaken for real environment data. This prevents generated test events from being confused with real security events if they leak into production indices.

## Dependencies

- LLM API access with sufficient context window for test data generation (4K-8K tokens per test set)
- MITRE ATT&CK technique data (STIX repository for technique descriptions and procedure examples)
- Target platform log schema documentation (ECS, CIM, ASIM, or custom)
- Detection-as-code CI/CD pipeline for automated test integration
- [UC-18: Rule Quality Assessment](18-rule-quality-assessment.md) -- Quality assessment identifies evasion gaps; those gaps become test generation targets for UC-23
- [UC-19: Detection Rule Generation](19-detection-rule-generation.md) -- AI-generated rules need AI-generated test data to validate before deployment
- A staging/test SIEM environment for data injection and rule evaluation

## Complexity Assessment

| Dimension | Rating | Notes |
|---|---|---|
| Data engineering | Medium | Requires curated log schema references per target platform, a data injection pipeline for the staging SIEM, and schema validation for generated output. |
| AI/ML complexity | Medium | Prompt engineering requires security domain knowledge about technique artifacts and log source behavior. Few-shot examples of well-structured test events improve output consistency. Multi-variant and false-positive generation add prompt complexity. |
| Integration effort | Medium-High | Full value requires integration with detection-as-code CI/CD pipelines, staging SIEM data injection, and automated test assertion frameworks. The LLM prompting is straightforward; the pipeline around it is the main engineering work. |
| Overall | **Medium** | The LLM prompting is not the hard part. Building the automated test pipeline that consumes generated data and reports results is the real engineering effort -- but that pipeline has value independent of AI and may already exist. |

## Real-World Considerations

- **Synthetic is not real.** AI-generated log events approximate real attack artifacts but may miss subtle details: exact timestamp precision from kernel-level logging, event ordering within the same millisecond, Windows-internal fields populated by the OS but not documented in schemas, or EDR-specific enrichment fields. Use synthetic data for logic validation, not for training ML models or establishing detection baselines.
- **Environment drift.** Generated test data reflects the schema version and field conventions at generation time. If your SIEM schema changes (ECS version upgrade, new fields, renamed fields), regenerate test data. Consider storing the prompt + schema version alongside generated output so test data can be regenerated on demand.
- **False positive test data is the hardest part.** Generating realistic benign activity that resembles attack behavior requires understanding both the attack pattern and the legitimate operational context. LLMs are effective at this because they have exposure to both attack documentation and IT administration workflows -- but human review of false-positive test cases is essential to confirm they represent realistic scenarios for your environment.
- **Do not conflate test pass with detection coverage.** A rule that fires on AI-generated test data has validated its logic, not validated its real-world detection capability. True detection validation requires real telemetry from actual technique execution or representative replayed data. Synthetic testing validates "does the query match the expected fields and values?" -- not "does my environment generate these fields when this attack happens?"
- **Regulatory and compliance context.** Some compliance frameworks (SOC 2, PCI DSS, NIST CSF) require evidence of detection testing. AI-generated test data with labeled outcomes and automated pass/fail results provides auditable test evidence, but document the methodology and get compliance team approval for using synthetic test data.
- **Correlation rule testing requires coordinated generation.** Testing correlation rules (multi-rule, multi-event) requires generating sets of events that share entity values, maintain causal ordering, and span the correct time windows. Workflow 3 (attack scenario sequences) addresses this, but the prompt complexity increases significantly. Start with single-rule test data before attempting correlation sequences.

## Related Use Cases

- [UC-18: Rule Quality Assessment](18-rule-quality-assessment.md) -- UC-18 identifies evasion gaps and quality issues in detection rules; UC-23 generates test data targeting those specific gaps to validate that remediated rules actually detect the identified evasion variants.
- [UC-19: Detection Rule Generation](19-detection-rule-generation.md) -- AI-generated rules from UC-19 need test data from UC-23 to validate before deployment. UC-19 produces the rule; UC-23 produces the test set; the detection engineer reviews both.
- [UC-17: Rule Comparison and Gap Analysis](17-rule-comparison-and-gap-analysis.md) -- Gap analysis identifies techniques with no detection coverage. When new rules are created to fill those gaps, UC-23 generates test data to validate the new rules.
- [UC-16: Observable Artifact Extraction](16-observable-artifact-extraction.md) -- Extracted observables from UC-16 define what field/value patterns a rule matches. UC-23 generates events containing those exact patterns (and variants that test pattern boundaries).
- [UC-15: LLM Investigation Guide Generation](15-llm-investigation-guide-generation.md) -- Investigation guides describe expected artifacts for true positives. UC-23's true-positive test data should produce those same artifacts, providing a consistency check between the guide and the test data.

## References

- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) -- The gold standard for technique-level detection testing via actual execution. UC-23 complements ART when execution is impractical or when diverse variants beyond ART's single-procedure tests are needed.
- [MITRE Caldera](https://github.com/mitre/caldera) -- Adversary emulation platform for multi-step attack simulations. UC-23 complements Caldera by generating test data for techniques that cannot be safely emulated or for false-positive scenarios.
- [Elastic Detection Rules RTA](https://github.com/elastic/detection-rules/tree/main/rta) -- Red Team Automation scripts for Elastic rule testing; a deterministic complement to AI-generated test data.
- [MITRE ATT&CK Data Sources](https://attack.mitre.org/datasources/) -- Reference for which data sources observe each technique; essential context for generating test data with the correct log source and event types.
- [Elastic Common Schema (ECS)](https://www.elastic.co/guide/en/ecs/current/index.html) -- Field reference for generating Elastic-schema-compliant test data.
- [Splunk Common Information Model (CIM)](https://docs.splunk.com/Documentation/CIM/latest/User/Overview) -- Field reference for generating Splunk-schema-compliant test data.
- [OCSF (Open Cybersecurity Schema Framework)](https://schema.ocsf.io/) -- Emerging cross-platform schema standard relevant to vendor-agnostic test data generation.
- [Splunk contentctl](https://github.com/splunk/contentctl) -- Splunk's detection content management tool with built-in test capabilities.
