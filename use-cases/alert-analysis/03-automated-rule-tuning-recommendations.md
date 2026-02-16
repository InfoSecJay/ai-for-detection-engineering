# UC-03: Automated Rule Tuning Recommendations

## Category

Alert Analysis

## Summary

Use an LLM to generate specific, implementable tuning proposals for detection rules — complete with exact exclusion syntax, projected volume reduction, safety assessment, and residual signal analysis. The SIEM provides the entity aggregations, concentration metrics, and volume projections that make tuning quantifiable. The AI provides the contextual reasoning that makes tuning decisions defensible: Is this exclusion safe? Could it mask an attack? What signal remains after tuning? What does the exclusion look like in your SIEM's query language?

## Problem Statement

Detection tuning is the most time-consuming recurring task in detection engineering. With 4,000+ rules, tuning is never "done" — it is a continuous maintenance burden. The bottleneck is not identifying *what* to tune (high-volume, low-cardinality rules are obvious) but rather making *safe, well-reasoned tuning decisions* at scale.

Each tuning decision requires answering several questions:

1. **What specific condition should be excluded?** Not "exclude this user" but "exclude this user when the process is this specific executable running from this specific path." Overly broad exclusions create blind spots. Overly narrow exclusions fail to reduce volume.
2. **Is this exclusion safe?** Could an attacker abuse the excluded condition? Is the excluded entity a known vector for attack (e.g., service accounts, SYSTEM, administrative tools)?
3. **What signal remains after tuning?** If you exclude 95% of volume, what does the remaining 5% look like? Is it still a useful detection, or have you gutted it?
4. **What is the exact syntax?** Elastic KQL, Splunk SPL, Sentinel KQL — the exclusion must be expressed in the correct query language for the target platform. A recommendation that says "exclude service accounts" is not actionable; one that provides `NOT user.name IN ("svc_sccm", "svc_intune") OR (user.name == "svc_sccm" AND process.executable != "C:\\Windows\\CCM\\CcmExec.exe")` is.
5. **What is the projected impact?** Volume reduction should be a hard number, not a guess. This is deterministic — count alerts matching the proposed exclusion condition.

An analyst doing this manually for one rule takes 30-60 minutes of investigation. Doing it across hundreds of noisy rules is a multi-month project. AI can draft the proposals, with humans reviewing and approving.

## Prerequisites (What Your SIEM/SOAR Should Already Handle)

- **Entity aggregation with multi-field breakdown**: Not just "top users" but "top user + host + process combinations." This is a composite or multi-level terms aggregation. The tuning condition often spans multiple fields.
  ```
  // Elastic example
  {
    "aggs": {
      "entity_combos": {
        "composite": {
          "sources": [
            { "user": { "terms": { "field": "user.name" } } },
            { "host": { "terms": { "field": "host.name" } } },
            { "process": { "terms": { "field": "process.name" } } }
          ]
        }
      }
    }
  }
  ```
- **Volume projection for proposed exclusions**: Given a candidate exclusion condition, count how many alerts it would match. This is a filtered count query. Example: "If we exclude `user.name == 'svc_sccm' AND process.name == 'CcmExec.exe'`, how many of the 12,847 alerts are removed?" The SIEM answers this with a simple filtered aggregation.
- **Residual signal characterization**: After applying the exclusion filter, re-run entity aggregations on the remaining alerts. What does the entity distribution look like post-tuning? This tells you whether the remaining signal is diverse (good) or still dominated by another noise source (needs more tuning).
- **Concentration metrics**: What percentage of total volume does each exclusion candidate represent? Pre-compute this so the AI knows the impact of each potential exclusion.
- **Historical exclusion tracking**: If you have a record of past tuning actions (even a spreadsheet), this context helps the AI avoid re-proposing previously rejected exclusions.

## Where AI Adds Value

### 1. Contextual Tuning Proposals

The AI generates exclusion proposals that account for the rule's detection intent. It does not simply say "exclude the top entity." It reasons:

"This rule detects `Suspicious PowerShell Download Cradle`. The top entity is `svc_sccm` executing `powershell.exe -Command "Invoke-WebRequest -Uri https://internal-repo.corp.local/packages/..."`. While this matches the rule's pattern (PowerShell making web requests), the destination is an internal repository, not an external C2 server. Proposed exclusion: exclude when `user.name == 'svc_sccm'` AND `url.domain` matches `*.corp.local`. This preserves detection for the same service account if it reaches external domains."

### 2. Safety Assessment

For each proposed exclusion, the AI evaluates attack-path risk:

- Could an attacker operate under the excluded condition? (e.g., compromised service account, hijacked internal domain)
- Is the excluded entity a known abuse vector in the MITRE ATT&CK framework?
- What is the blast radius if the exclusion is wrong? (single rule vs. multiple rules using the same exclusion)

### 3. Residual Signal Analysis

After proposing exclusions, the AI characterizes what remains:

"After excluding svc_sccm and svc_intune, 247 alerts remain from 4 unique users across 12 hosts. The residual signal shows moderate diversity and includes 2 command line clusters flagged as suspicious in UC-02 analysis. This rule retains meaningful detection capability post-tuning."

### 4. Platform-Specific Exclusion Syntax

The AI generates the exact exclusion clause for the target SIEM platform, ready to paste into the rule definition or exception list:

- Elastic: KQL exception item or rule exception container
- Splunk: `NOT` clause in SPL search or lookup-based exclusion
- Sentinel: KQL `where` clause negation or watchlist exclusion

## AI Approach

**Method**: LLM prompting with rule context, entity metrics, and platform-specific syntax requirements.

### Prompt Architecture

1. **System prompt**: Detection engineering context. Environment details (rule count, data source domains, no analyst disposition data). Platform syntax conventions. Safety assessment framework.

2. **Rule context block**:
```json
{
  "rule_id": "siem-rule-00421",
  "rule_name": "Suspicious PowerShell Encoded Command",
  "rule_description": "Detects use of -EncodedCommand or -enc flags in PowerShell execution",
  "rule_query": "process.name:\"powershell.exe\" AND process.command_line:(*-enc* OR *-EncodedCommand*)",
  "mitre_technique": "T1059.001",
  "mitre_tactic": "Execution",
  "severity": "medium",
  "data_source_domain": "endpoint.process",
  "target_platform": "elastic"
}
```

3. **Entity metric block**: Full cardinality data, top-N distributions with counts and percentages, multi-field co-occurrence data, command line clusters (if available from UC-02).

4. **Task instruction**: "Generate tuning proposals for this rule. For each proposal, provide: (a) the exact exclusion condition in [platform] query syntax, (b) the projected volume reduction as a count and percentage, (c) a safety assessment with risk level, (d) residual signal characterization, and (e) an overall recommendation (APPLY, REVIEW, REJECT)."

### Output Schema

```json
{
  "rule_id": "siem-rule-00421",
  "tuning_proposals": [
    {
      "proposal_id": "TP-001",
      "description": "Exclude SCCM service account encoded PowerShell",
      "exclusion_condition": {
        "human_readable": "Exclude when user is svc_sccm AND parent process is CcmExec.exe",
        "elastic_kql": "user.name:\"svc_sccm\" AND process.parent.name:\"CcmExec.exe\"",
        "splunk_spl": "NOT (user=\"svc_sccm\" AND parent_process_name=\"CcmExec.exe\")",
        "sentinel_kql": "| where not(UserName == \"svc_sccm\" and ParentProcessName == \"CcmExec.exe\")"
      },
      "projected_impact": {
        "alerts_excluded": 11200,
        "pct_volume_reduction": 87.2,
        "remaining_alerts": 1647
      },
      "safety_assessment": {
        "risk_level": "LOW",
        "reasoning": "Exclusion is scoped to svc_sccm executing via CcmExec.exe parent process. An attacker would need to compromise the SCCM service account AND execute via the SCCM agent binary. SCCM abuse is a known technique (T1072), but requiring the specific parent process constrains the exclusion to legitimate SCCM operations."
      },
      "residual_signal": {
        "remaining_volume": 1647,
        "remaining_entity_cardinality": {
          "user.name": 5,
          "host.name": 42
        },
        "assessment": "Residual signal retains 5 users across 42 hosts. Includes interactive users and other service accounts not yet evaluated. Rule retains detection value."
      },
      "recommendation": "APPLY"
    }
  ]
}
```

## Data Requirements

### Inputs

| Data Element | Source | Computation | Notes |
|---|---|---|---|
| Rule definition + query | Rule repository / SIEM API | Direct retrieval | Needed for AI to understand detection logic |
| Rule metadata | Rule repository | Name, description, MITRE mapping, severity, data source | Context for safety reasoning |
| Entity metrics (from UC-02) | Pre-computed metrics | Cardinality, top-N, ratios, clustering results | Foundation for identifying exclusion candidates |
| Multi-field entity combinations | SIEM alert index | Composite aggregation on entity field pairs/triples | Exclusions often span multiple fields |
| Volume per candidate condition | SIEM alert index | Filtered count for each proposed exclusion condition | Deterministic — must be SIEM-computed |
| Residual entity profile | SIEM alert index | Entity aggregations with exclusion filter applied | Shows what remains after tuning |
| Target platform syntax | Configuration | Elastic/Splunk/Sentinel target | Determines exclusion output format |
| Known service accounts list | Environment configuration | Maintained list of authorized service accounts | Improves AI safety reasoning |
| Historical tuning actions | Tuning log (if available) | Past exclusions, rejections, and rationale | Prevents re-proposing rejected exclusions |

### Outputs

**Tuning Report Card (Per-Rule)**

```
===============================================================================
TUNING REPORT: Suspicious PowerShell Encoded Command (siem-rule-00421)
Generated: 2026-02-16 | Platform: Elastic | Period: 30 days
===============================================================================

CURRENT STATE
  Volume (30d):          12,847 alerts
  Daily Average:         428.2 alerts/day
  Trend:                 +300.2% vs prior 30d
  Entity Diversity:      LOW (4 users, 3 hosts, 87 command lines / 12 clusters)
  Dominant Entity:       svc_sccm (87.2% of volume)
  Signal Quality:        POOR — overwhelmingly automated activity

-------------------------------------------------------------------------------
PROPOSAL 1 of 3: Exclude SCCM service account (via CcmExec.exe parent)
-------------------------------------------------------------------------------
  Condition:             user.name == "svc_sccm" AND process.parent.name == "CcmExec.exe"
  Elastic Exception:
    {
      "entries": [
        { "field": "user.name", "operator": "included", "type": "match", "value": "svc_sccm" },
        { "field": "process.parent.name", "operator": "included", "type": "match", "value": "CcmExec.exe" }
      ]
    }

  Volume Reduction:      11,200 alerts removed (87.2%)
  Remaining Volume:      1,647 alerts
  Safety Risk:           LOW
    - Scoped to specific parent process, not blanket user exclusion
    - SCCM abuse (T1072) requires attacker to execute via CcmExec.exe agent
    - Attacker using svc_sccm with a DIFFERENT parent process is NOT excluded
  Recommendation:        APPLY

-------------------------------------------------------------------------------
PROPOSAL 2 of 3: Exclude Intune service account (via IntuneManagement parent)
-------------------------------------------------------------------------------
  Condition:             user.name == "svc_intune" AND process.parent.name == "Microsoft.Management.Services.IntuneWindowsAgent.exe"
  Elastic Exception:
    {
      "entries": [
        { "field": "user.name", "operator": "included", "type": "match", "value": "svc_intune" },
        { "field": "process.parent.name", "operator": "included", "type": "match", "value": "Microsoft.Management.Services.IntuneWindowsAgent.exe" }
      ]
    }

  Volume Reduction:      1,400 alerts removed (10.9%)
  Remaining Volume:      247 alerts (if Proposal 1 also applied)
  Safety Risk:           LOW
    - Same pattern as Proposal 1 — scoped to specific management agent
  Recommendation:        APPLY

-------------------------------------------------------------------------------
PROPOSAL 3 of 3: Exclude helpdesk encoded PowerShell for remote support
-------------------------------------------------------------------------------
  Condition:             user.name == "helpdesk_tsmith" AND process.command_line contains "ConnectWise"
  Elastic Exception:
    {
      "entries": [
        { "field": "user.name", "operator": "included", "type": "match", "value": "helpdesk_tsmith" },
        { "field": "process.command_line", "operator": "included", "type": "wildcard", "value": "*ConnectWise*" }
      ]
    }

  Volume Reduction:      45 alerts removed (0.4%)
  Remaining Volume:      202 alerts (if Proposals 1-2 also applied)
  Safety Risk:           MEDIUM
    - Helpdesk accounts are high-value targets for social engineering
    - ConnectWise has been exploited in supply chain attacks (ref: 2024 ScreenConnect CVE)
    - Excluding ConnectWise-related PowerShell from a helpdesk account could mask
      attacker use of compromised remote support tools
  Recommendation:        REVIEW — discuss with team before applying

===============================================================================
CUMULATIVE IMPACT (if all APPLY proposals implemented)
===============================================================================
  Original Volume:       12,847 alerts/30d
  Excluded Volume:       12,600 alerts (98.1%)
  Remaining Volume:      247 alerts/30d (~8.2/day)
  Remaining Entities:    4 users, 12 hosts, 23 command line clusters
  Residual Signal:       MODERATE — includes interactive user activity and
                         2 suspicious command line patterns identified in UC-02.
                         Rule retains value as a detection for non-automated
                         encoded PowerShell execution.

===============================================================================
POST-TUNING MONITORING RECOMMENDATION
===============================================================================
  - Re-evaluate in 14 days after exclusions are applied
  - Monitor for new entities entering the excluded condition space
    (new service accounts using CcmExec.exe or IntuneWindowsAgent.exe)
  - Set a volume alert: if post-tuning volume exceeds 50/day, investigate
    for new noise source or emerging attack pattern
```

## Implementation Notes

- **Exclusion syntax accuracy is critical**: The AI must produce syntactically valid exclusions for the target platform. Test generated exclusions against the SIEM before applying them. A malformed KQL query in an Elastic exception will silently fail or cause unexpected behavior. Consider a validation step where the generated exclusion is executed as a count query to verify it matches the expected number of alerts.

- **Multi-field exclusions are safer than single-field exclusions**: Excluding `user.name == "svc_sccm"` is dangerous — it blinds you to any abuse of that account. Excluding `user.name == "svc_sccm" AND process.parent.name == "CcmExec.exe"` is much safer — it only excludes the specific operational pattern. The AI should be instructed to always propose the most specific (multi-field) exclusion possible and to flag single-field exclusions as higher risk.

- **Volume projection must be SIEM-computed, not AI-estimated**: The AI proposes the exclusion condition. The SIEM counts how many alerts match it. Do not let the AI estimate volume reduction from percentages in the top-N distribution — those are approximations. Run the actual filtered count query. The implementation pipeline should: (1) AI proposes condition, (2) SIEM computes exact match count, (3) AI incorporates exact count into the report.

- **Iterative proposal refinement**: The AI may propose an exclusion that is too broad. If the human reviewer rejects it and provides feedback ("too broad — scope to the specific executable path, not just the user"), the AI should refine the proposal in a follow-up prompt. Design the pipeline for conversational iteration, not one-shot generation.

- **Exclusion decay and review cadence**: Exclusions should not be permanent. Infrastructure changes, personnel changes, and software updates can make an exclusion stale or dangerous. Include an expiration recommendation in each proposal (e.g., "review in 90 days") and track this in the tuning log.

- **Batch tuning across related rules**: UC-01 may identify clusters of rules that share a noise source. When tuning one rule in the cluster, check whether the same exclusion applies to the others. The AI can be prompted with the full cluster: "These 5 rules all share svc_sccm as a top entity. Propose exclusions for the group, noting which conditions apply to all vs. which are rule-specific."

## Dependencies

- All UC-02 outputs (entity cardinality analysis, clustering results, safety assessments)
- SIEM API access for executing validation count queries against proposed exclusion conditions
- Rule repository access for rule queries and metadata
- Target platform syntax reference (can be included in system prompt or as a reference document)
- (Optional) Tuning log / exclusion history for avoiding re-proposals
- (Optional) Known service accounts list for environment-specific context

## Complexity Assessment

| Dimension | Rating | Notes |
|---|---|---|
| Overall | Medium | Builds on UC-02 data. AI generates structured proposals. Human reviews and approves. |
| Data pipeline | Medium | Requires UC-02 outputs plus multi-field composite aggregations. Volume projection queries must be dynamically generated per proposal. |
| Prompt engineering | Medium-High | Prompt must convey rule intent, entity context, platform syntax rules, and safety framework. Output must be structured and consistent. Iterative refinement adds conversational complexity. |
| AI integration | Medium | Single LLM call per rule, but output must be parsed and validated. Volume projections require a round-trip to the SIEM between AI proposal and final report. |
| Output validation | High | Generated exclusion syntax must be validated for correctness. Safety assessments must be human-reviewed. Volume projections must be SIEM-verified. This is not a "trust the AI" workflow. |
| Maintenance | Medium | Exclusion syntax conventions change with SIEM platform updates. Service account lists change with infrastructure. Safety assessment framework evolves with threat landscape. |

## Real-World Considerations

- **The "just exclude SYSTEM" failure mode**: In every environment, someone eventually proposes excluding the SYSTEM/NT AUTHORITY account from all endpoint rules because it drives the most volume. This is catastrophically wrong for many rules. The AI must be explicitly instructed: "Never propose a blanket SYSTEM exclusion. Always scope SYSTEM exclusions to specific parent processes, specific executable paths, or specific command line patterns."

- **Exclusion stacking creates blind spots**: After 6 months of tuning, a rule might have 15 exclusion conditions. Each was individually safe, but the combination may have carved out so much of the detection surface that the rule is effectively disabled. The AI should analyze the cumulative exclusion set, not just the proposed addition. Include existing exclusions in the prompt context.

- **Tuning velocity matters**: If the team can only review and implement 10 tuning proposals per week, prioritize by volume impact. A single exclusion removing 10,000 alerts/month is more valuable than 20 exclusions each removing 50 alerts/month, even if the total volume reduction is similar. The AI should rank proposals by projected volume reduction.

- **Service account sprawl**: Many environments have undocumented or orphaned service accounts. The AI may flag an unfamiliar service account as a tuning candidate. Do not exclude unfamiliar entities without validating their legitimacy — an attacker-created service account looks exactly like a legitimate one in the alert data. Include a "VALIDATE BEFORE EXCLUDING" flag for any entity not on the known service accounts list.

- **The residual signal test**: After applying all proposed exclusions, ask: "Would this rule have detected [specific real-world attack]?" If the answer is "no" for a well-known attack technique that maps to this rule's MITRE coverage, the tuning has gone too far. The AI can perform this reasoning if given attack scenario descriptions.

- **Exclusions are not the only tuning lever**: Sometimes the right action is not to add exclusions but to modify the rule logic itself — adjust thresholds, add conditions, change the time window. The AI should consider whether the rule's core logic is the problem, not just the entities it fires on. A rule that detects "any scheduled task creation" should probably be rewritten to detect "scheduled task creation with suspicious characteristics," not patched with a growing list of exclusions.

## Related Use Cases

- **UC-01 (Detection Performance Analytics)**: Identifies which rules need tuning and prioritizes them.
- **UC-02 (Entity Cardinality Noise Analysis)**: Provides the entity analysis that UC-03's tuning proposals are based on.
- **UC-04 (Detection Drift Monitoring)**: Post-tuning monitoring to detect if tuning actions caused unintended drift or if new noise sources emerged.

## References

- Elastic: [Detection rule exceptions](https://www.elastic.co/guide/en/security/current/detections-ui-exceptions.html), [Value lists](https://www.elastic.co/guide/en/security/current/detections-ui-exceptions.html#value-lists-exceptions)
- Splunk: [Lookup-based filtering](https://docs.splunk.com/Documentation/Splunk/latest/Knowledge/Aboutlookupsandfieldactions), [Risk-based alerting](https://docs.splunk.com/Documentation/ES/latest/User/RiskScoring)
- Sentinel: [Analytics rule tuning](https://learn.microsoft.com/en-us/azure/sentinel/configure-analytics-rules), [Watchlists for exclusion management](https://learn.microsoft.com/en-us/azure/sentinel/watchlists)
- MITRE ATT&CK: [T1072 - Software Deployment Tools](https://attack.mitre.org/techniques/T1072/), [T1059.001 - PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- Palantir: [Alerting and Detection Strategy Framework](https://github.com/palantir/alerting-detection-strategy-framework) — exclusion documentation standards
