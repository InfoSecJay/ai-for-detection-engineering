# Pillar 2: SOC Process Framework and Maturity

> **Core principle:** "Common SOC workflows do NOT rely on human-to-human communication."

You can have pristine data foundations and still fail at AI if your processes are trapped in people's heads. When an analyst triages an alert, are they following a documented, structured workflow — or are they relying on experience, gut feel, and Slack messages to the senior analyst?

If the answer is the latter, you have tribal knowledge, not process. And AI can't execute tribal knowledge.

**The hard truth:** Weak process + weak data access will kill any AI initiative. If you scored poorly on Pillar 1 (Data Foundations) and score poorly here, stop. AI is not your next investment — process engineering is.

---

## 2.1 Codify Tribal Knowledge

### The Problem

Every SOC has knowledge that lives exclusively in senior analysts' heads:

- "When you see this alert from the Exchange server, check if the user is in the service accounts list — those are always false positives"
- "Alerts from the Tokyo office during their business hours are usually OK, but the same activity from Tokyo at 3 AM local time is suspicious"
- "That detection rule fires on the build servers every Tuesday night during patch cycles — just close it as benign"
- "If the user is in the finance department and the alert involves PowerShell, escalate immediately regardless of the rule severity"

This knowledge is **operationally critical** and **completely invisible to any AI agent**. When the senior analyst who holds this knowledge is on vacation, sick, or leaves the team, it disappears.

### The Solution: Document in Structured, Machine-Readable Formats

Tribal knowledge must be converted into structured artifacts that both humans and machines can consume:

**1. Alert-specific triage procedures (runbooks):**

```yaml
# Example: Structured triage runbook for a detection rule
rule_id: "elastic-rule-12345"
rule_name: "PowerShell Execution with Encoded Command"
triage_steps:
  - step: 1
    action: "Check if the host is a known admin workstation"
    query: "host.name in admin_workstations_list"
    if_true: "Proceed to step 2"
    if_false: "Escalate — unexpected PowerShell from non-admin host"

  - step: 2
    action: "Check if the user is a member of IT Operations"
    query: "user.name in it_operations_group"
    if_true: "Proceed to step 3"
    if_false: "Escalate — non-IT user running encoded PowerShell"

  - step: 3
    action: "Check the decoded command content"
    query: "Decode base64 from process.command_line"
    if_contains: ["Install-Module", "Update-Help", "Set-ExecutionPolicy"]
    then: "Close as benign — routine admin activity"
    otherwise: "Escalate — unusual encoded command from IT user"

known_false_positives:
  - description: "SCCM client health check scripts"
    pattern: "process.parent.name == 'ccmexec.exe'"
    disposition: "benign_true_positive"
  - description: "Tuesday night patch cycle on build servers"
    pattern: "host.group == 'build_servers' AND day_of_week == 'Tuesday' AND hour >= 22"
    disposition: "benign_true_positive"
```

This is not a suggestion. This is the level of specificity your triage documentation needs to reach for AI agents to use it. A vague runbook that says "investigate the alert and determine if it's malicious" is useless to both junior analysts and AI.

**2. Known false positive libraries:**

Every detection rule should have an associated list of known false positive patterns with:
- The specific field conditions that identify the false positive
- Why it's a false positive (business justification)
- When the exception was added and who approved it
- An expiration date or review cadence

**3. Escalation criteria:**

Explicit, conditional escalation rules:
- If asset criticality is "crown jewel" AND alert severity >= "high" → Escalate to Tier 3
- If user is flagged as "terminated" in HR system → Escalate to Insider Threat team
- If threat intel matches a tracked threat actor → Escalate to Threat Intelligence team

These are not guidelines. They are branching logic that a machine can execute.

---

## 2.2 Define Machine-Intelligible Workflows

### What "Machine-Intelligible" Means

A machine-intelligible workflow has:

1. **Explicit inputs:** What data does the workflow consume? (Alert fields, enrichment data, historical context)
2. **Defined decision points:** At each step, what conditions determine the next action?
3. **Clear outputs:** What does the workflow produce? (Disposition, escalation, enrichment request, additional investigation step)
4. **Handoff criteria between AI and human:** At what point does the AI stop and a human takes over?

### Designing AI-Human Handoff Points

This is where most AI deployments go wrong. The handoff between AI and human must be **explicitly defined**, not left to the AI's judgment.

**Good handoff design:**

```
AI Agent Scope:
  - Collect all enrichment data for the alert
  - Check alert fields against known false positive patterns
  - Score confidence based on matching criteria
  - Generate triage summary with evidence and recommendation

  IF confidence >= 95% AND disposition == "known_false_positive":
    → Auto-close with documented reasoning (AI handles end-to-end)

  IF confidence >= 80% AND disposition == "likely_benign":
    → Present to analyst for one-click approval (AI recommends, human confirms)

  IF confidence < 80% OR disposition == "suspicious" OR disposition == "unknown":
    → Full analyst review with AI-generated investigation summary (AI assists, human decides)

  ALWAYS escalate to human if:
    → Asset is "crown_jewel" tier
    → Alert involves privileged account compromise
    → Alert maps to active threat campaign
    → AI confidence is below threshold for any reason
```

**Bad handoff design:**

"The AI will handle routine alerts and escalate anything suspicious to an analyst."

What's "routine"? What's "suspicious"? Who decides? At what confidence level? This is the kind of vague process that leads to AI auto-closing real incidents or flooding analysts with alerts the AI should have handled.

### Workflow Documentation Standards

Every SOC workflow that an AI agent will touch should be documented with:

| Component | Description |
|-----------|-------------|
| **Trigger** | What initiates the workflow (alert type, rule category, data source) |
| **Inputs** | Required data: alert fields, enrichment data, historical context |
| **Decision logic** | Explicit branching conditions at each step |
| **AI scope** | Exactly what the AI agent is authorized to do |
| **Human scope** | What requires human judgment and why |
| **Handoff criteria** | Conditions that transfer control from AI to human (or vice versa) |
| **Outputs** | What the workflow produces: disposition, case, escalation, report |
| **SLA** | Expected completion time for each phase |
| **Fallback** | What happens when the AI fails, times out, or returns low-confidence results |

---

## 2.3 Structured Case Management

### The Problem with Freeform Text

Most SOCs record investigation details in freeform text fields in their ticketing system. This is a natural human communication method, but it's opaque to machines.

**What analysts write:**
> "Checked the user's recent activity and this looks like a normal login from a new device. User confirmed via Slack that they got a new laptop. Closing as FP."

**What machines can parse from that:** Almost nothing useful. The disposition is buried in prose. The investigation steps aren't structured. The evidence isn't linked.

### Move to Structured Fields

Every alert disposition and case record should capture structured data:

```yaml
# Example: Structured alert closure
alert_id: "alert-2024-12345"
rule_id: "elastic-rule-67890"
rule_name: "Login from Unusual Location"

disposition: "benign_true_positive"  # enum: true_positive, false_positive, benign_true_positive
confidence: "high"                    # enum: high, medium, low

investigation_summary:
  steps_taken:
    - action: "Checked user's login history for last 30 days"
      finding: "First login from this geographic region"
    - action: "Queried HR system for user's office location"
      finding: "User relocated to new office last week"
    - action: "Confirmed with user's manager"
      finding: "Manager confirmed relocation"

  mitre_technique: "T1078 - Valid Accounts"
  affected_assets: ["WORKSTATION-4521"]
  affected_users: ["jsmith@company.com"]
  root_cause: "Legitimate user relocation — detection rule lacks location update logic"

  recommended_tuning:
    action: "Add user location change as suppression condition"
    priority: "medium"
    assigned_to: "detection-engineering"

time_to_resolve_minutes: 12
analyst: "analyst-jane"
closed_at: "2024-11-15T14:32:00Z"
```

This structure enables:
- AI agents to learn from past dispositions for the same rule
- Automated metrics calculation (MTTR, FP rates per rule)
- Detection tuning feedback loops (see [Pillar 5](05-metrics-and-feedback.md))
- Trend analysis across rules, analysts, and time periods

### Minimum Required Structured Fields

At a minimum, every alert closure must capture:

| Field | Type | Purpose |
|-------|------|---------|
| `disposition` | Enum (TP / FP / BTP) | Was the alert valid? |
| `confidence` | Enum (high / medium / low) | How confident is the analyst in the disposition? |
| `mitre_technique` | String (T-code) | What technique was involved? |
| `affected_assets` | List of strings | What was impacted? |
| `affected_users` | List of strings | Who was involved? |
| `root_cause` | Freeform string | Why did this happen? (Yes, this one can be freeform) |
| `time_to_resolve` | Integer (minutes) | How long did triage take? |
| `escalated` | Boolean | Was this escalated? |

If your ticketing system doesn't support structured fields on alert records, that's a tooling problem to solve before deploying AI. Most modern platforms (ServiceNow, Jira, SOAR case management) support custom fields.

---

## 2.4 Target Specific Workflows for AI

### Don't "AI All the Things"

The temptation after seeing a compelling demo is to throw AI at every SOC workflow simultaneously. This fails for predictable reasons:

1. **Each workflow needs its own evaluation criteria.** "Did the AI triage this alert correctly?" is a different question from "Did the AI write a good detection rule?" Measuring both at once makes it impossible to know what's working.

2. **Data quality varies by workflow.** Your phishing alert data might be excellent while your cloud IAM alert data is a mess. AI will work well on the first and terribly on the second.

3. **Change management capacity is finite.** Your analysts can absorb one new AI-assisted workflow at a time, not five.

### Selecting Your First AI Workflow

Pick the workflow that has:

- **High volume, low complexity.** Phishing alert triage is a classic starting point: high alert volume, relatively structured data, well-understood triage steps, clear disposition criteria.
- **Good data foundations.** The data for this workflow is already normalized, enriched, and accessible.
- **Documented processes.** Triage procedures exist in a structured format (not just in someone's head).
- **Measurable outcomes.** You can objectively measure whether the AI's dispositions are correct.
- **Low blast radius.** If the AI gets it wrong, the consequences are manageable (a delayed triage, not a missed critical incident).

**Example ranking:**

| Workflow | Volume | Data Quality | Process Maturity | Measurability | Blast Radius | AI Readiness |
|----------|--------|-------------|-----------------|---------------|-------------|-------------|
| Phishing triage | High | Good | High | High | Low | Ready |
| Endpoint alert triage | High | Good | Medium | High | Medium | Almost ready |
| Cloud IAM anomaly review | Medium | Poor | Low | Low | High | Not ready |
| Threat hunt hypothesis | Low | Good | Medium | Low | Low | Experiment |
| Detection rule authoring | Low | Good | High | Medium | Medium | Experiment |

Start with one. Prove value. Expand.

---

## 2.5 Self-Assessment Questions

1. **Are your triage procedures documented in structured, machine-readable formats?** Pull up the runbook for your highest-volume alert. Is it a structured decision tree with explicit conditions, or a paragraph of prose?

2. **Do you have explicit AI-human handoff criteria?** For any workflow where you plan to deploy AI, can you state exactly when the AI stops and a human takes over? Is that threshold written down and approved?

3. **Is your case management structured?** Pull up the last 20 closed alerts. What percentage have structured disposition fields (not just freeform "analyst notes")? If it's below 80%, you have a case management problem.

4. **Can you identify your highest-readiness workflow for AI?** Using the criteria above (volume, data quality, process maturity, measurability, blast radius), which workflow should go first? If you can't answer this, you haven't assessed your processes deeply enough.

5. **Does your process documentation survive team turnover?** If your two most experienced analysts left tomorrow, could the remaining team maintain current triage quality? If the answer is "no," your knowledge is tribal, not institutional.

**Scoring guidance:**
- **4-5 "yes" answers:** Your process maturity is strong enough to support AI. Proceed to Pillar 3.
- **2-3 "yes" answers:** You have process gaps. Invest in structured documentation and case management before AI.
- **0-1 "yes" answers:** Your SOC runs on tribal knowledge. AI will fail. Start with process documentation and structured case management.

---

## Key Takeaway

Process maturity is the difference between "AI-assisted triage" and "AI-generated confusion." If your analysts can't articulate their triage logic in explicit, conditional terms, an AI agent can't learn it, execute it, or be evaluated against it.

The work here is not technical — it's organizational. Writing structured runbooks, defining handoff criteria, moving from freeform notes to structured fields. It's tedious, but it's the work that makes AI viable.

No structured process, no AI. Full stop.
