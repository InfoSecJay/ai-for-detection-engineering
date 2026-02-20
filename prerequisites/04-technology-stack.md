# Pillar 4: Modern SOC Technology Stack

> **Core principle:** "If your tools lack APIs, take them and go back to the 1990s."

Your SOC technology stack must be modern, interoperable, and API-driven. If your detection rules live in a GUI that can't export them, your SOAR platform doesn't have an API, or your SIEM can't be queried programmatically, AI agents have nothing to work with.

This pillar is about ensuring your tooling is ready for machine-speed operations, because AI agents don't click buttons in web consoles.

---

## 4.1 Detection-as-Code

### This Is No Longer Optional

If your detection rules live exclusively in a SIEM GUI, you have a scaling problem, a quality problem, and an AI-readiness problem — all at once.

Detection-as-Code means:

1. **Detection rules are stored in version control (Git).** Every rule has a full change history. You can diff, revert, branch, and merge. You know who changed what and when.

2. **Rules are deployed via CI/CD pipelines.** No manual copy-paste into the SIEM console. A merged pull request triggers automated deployment to your SIEM.

3. **Rules have automated tests.** Unit tests validate that rules fire on known-bad samples and don't fire on known-good samples. Integration tests validate that rules work with the current data schema.

4. **Rules have structured metadata.** MITRE ATT&CK mapping, severity, data source requirements, known false positive patterns, author, last review date — all stored alongside the rule in a structured format (YAML, TOML, JSON).

### Why AI Needs Detection-as-Code

AI agents interact with detection rules as structured data. They need to:

- **Read rules programmatically** to analyze coverage gaps, identify overlaps, or assess quality
- **Propose changes as diffs** that can be reviewed in a pull request, not as prose descriptions
- **Access rule metadata** to understand context: what technique does this rule detect? What data sources does it require? What's the false positive rate?
- **Reference rule history** to understand how a rule has evolved and why changes were made

None of this is possible if rules live in a SIEM GUI with no export API or version history.

### Platform Implementation

**Elastic Security:**
- Detection rules stored as TOML/JSON files in a Git repository
- Elastic's [detection-rules](https://github.com/elastic/detection-rules) repo is the reference implementation
- CI/CD deploys rules via the Kibana Detection Engine API
- Custom rules follow the same format and deployment pipeline

**Splunk:**
- Detection rules as SPL `.conf` files or YAML definitions in Git
- [Splunk Security Content](https://github.com/splunk/security_content) provides the framework
- `contentctl` CLI validates, builds, and deploys detections
- Correlation searches managed via `savedsearches.conf` in version control

**Microsoft Sentinel:**
- Analytics rules as ARM templates or YAML in Git
- [Sentinel-as-Code](https://github.com/Azure/Azure-Sentinel) provides community-contributed rules
- GitHub Actions or Azure DevOps deploy rules via the Sentinel API
- Hunting queries and workbooks follow the same CI/CD pattern

**Sigma (cross-platform):**
- Sigma rules in YAML as the universal detection format
- `sigma-cli` converts to platform-native formats deterministically
- Rules in Git, converted and deployed per-platform via CI/CD
- Note: Sigma-to-native conversion is a deterministic compiler problem, not an AI problem. Use the Sigma CLI.

### Minimum Detection-as-Code Requirements

| Requirement | Why |
|-------------|-----|
| All rules in Git | Version history, collaboration, audit trail |
| CI/CD deployment pipeline | No manual deployment = no manual errors |
| Automated syntax validation | Catch broken rules before deployment |
| Automated unit tests | Validate rules fire correctly on test data |
| Structured metadata per rule | AI and humans need context beyond the query |
| Code review on all changes | Human review before deployment, including AI-proposed changes |

---

## 4.2 API Interoperability

### Every Tool Must Have an API

Audit your SOC toolstack. For every tool, answer:

| Tool | Has API? | API Documented? | Rate Limits Known? | Service Account Provisioned? |
|------|----------|-----------------|--------------------|-----------------------------|
| SIEM | ? | ? | ? | ? |
| SOAR | ? | ? | ? | ? |
| EDR | ? | ? | ? | ? |
| TIP | ? | ? | ? | ? |
| Ticketing | ? | ? | ? | ? |
| CMDB | ? | ? | ? | ? |
| IAM/AD | ? | ? | ? | ? |
| Vuln Scanner | ? | ? | ? | ? |

Any tool without an API is a dead end for AI integration. Either replace it, build a wrapper, or accept that AI agents can't use it.

### Stress-Test API Capacity for AI Agent Volumes

This is the gap most teams discover too late. Your SIEM API that handles 10 analyst queries per minute will need to handle 100+ AI agent queries per minute. Your SOAR API that processes 50 playbook executions per hour may need to handle 500.

**Capacity planning questions:**

1. **What are the documented rate limits for each API?** Many SaaS tools throttle at levels that block agent-scale operations.

2. **What's the actual throughput you need?** If your AI agent triages 200 alerts per hour and each triage requires 5 API calls (SIEM query, CMDB lookup, AD lookup, TIP check, case creation), that's 1,000 API calls per hour — per agent.

3. **What happens when you hit rate limits?** Does the agent queue and retry? Drop the request? Alert an operator? Design for rate limit handling before it happens.

4. **Are there bulk/batch API endpoints?** Fetching 100 alerts one at a time is 100 API calls. A batch endpoint that returns 100 alerts in one call is dramatically more efficient.

5. **Do you need a caching layer?** Enrichment data (asset criticality, user group memberships) changes slowly. A cache with a 15-minute TTL can reduce API load by 80%+ for enrichment lookups.

### MCP (Model Context Protocol) and Tool Integration

If you're building custom AI agents, consider how they access tools. MCP provides a standardized protocol for LLM-tool interaction. Whether you use MCP, custom function calling, or another framework, the principle is the same: the AI agent needs a well-defined interface to each tool in your stack.

Each tool integration should define:
- **Available operations** (read alerts, query logs, create case, update disposition)
- **Required parameters** for each operation
- **Response format** (structured, parseable by the agent)
- **Error handling** (what does the agent do when the tool returns an error?)
- **Authorization scope** (least privilege — the agent should only access what it needs)

---

## 4.3 Alert Correlation via SIEM Rules

### Correlation Is a SIEM Problem, Not an AI Problem

Alert correlation — connecting related events across time, hosts, and users based on shared field values — is what query engines are built for. Your SIEM has correlation capabilities that are deterministic, fast, and don't hallucinate.

Using an LLM to correlate alerts by matching IP addresses, hostnames, or user names is like using a chainsaw to turn a screw. It might technically work, but you have a screwdriver right there.

### Platform Correlation Capabilities

**Elastic — EQL Sequences and ES|QL:**

```eql
// EQL sequence: Detect lateral movement pattern
sequence by user.name with maxspan=15m
  [authentication where event.outcome == "success" and source.ip != "10.0.0.0/8"]
  [process where process.name == "powershell.exe" and process.args : "-enc*"]
  [network where destination.port == 445]
```

```esql
// ES|QL: Correlate failed logins followed by success from same source
FROM logs-authentication-*
| WHERE event.outcome IN ("failure", "success")
| STATS
    failures = COUNT_IF(event.outcome == "failure"),
    successes = COUNT_IF(event.outcome == "success"),
    first_failure = MIN_IF(@timestamp, event.outcome == "failure"),
    first_success = MIN_IF(@timestamp, event.outcome == "success")
  BY source.ip, user.name
| WHERE failures >= 5 AND successes >= 1
| WHERE first_success > first_failure
```

EQL sequences let you define ordered event patterns with time constraints. ES|QL provides SQL-like aggregation and correlation. Both are deterministic, tested, and fast.

**Splunk — Correlation Searches:**

```spl
| tstats summariesonly=t count from datamodel=Authentication
  where Authentication.action=failure by Authentication.src, Authentication.user, _time span=5m
| rename Authentication.* as *
| where count >= 5
| join src user
  [| tstats summariesonly=t count from datamodel=Authentication
   where Authentication.action=success by Authentication.src, Authentication.user, _time span=5m
   | rename Authentication.* as *]
| eval pattern="brute_force_success"
```

Splunk correlation searches run on accelerated data models. They're scheduled, deterministic, and produce structured notable events.

**Sentinel — KQL and Fusion Rules:**

```kql
// KQL: Correlate multiple signals into a single incident
let failed_logins = SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType != "0"
| summarize FailCount = count() by UserPrincipalName, IPAddress;
let successful_logins = SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType == "0"
| project UserPrincipalName, IPAddress, SuccessTime = TimeGenerated;
failed_logins
| join kind=inner successful_logins on UserPrincipalName, IPAddress
| where FailCount >= 5
```

Sentinel Fusion rules automatically correlate alerts from multiple sources (Azure AD, Defender, Sentinel analytics rules) into multi-stage incidents. This is built-in, ML-powered correlation at the platform level.

### When Does AI Enter the Correlation Picture?

AI is relevant for correlation when:
- You need to identify **semantic** relationships, not field-value matches (e.g., "this endpoint alert and this email alert describe the same attacker campaign even though they share no common field values")
- You want to **prioritize** which correlated incidents to investigate first based on learned patterns
- You need to **explain** a chain of correlated events to an analyst in natural language

AI is NOT needed when:
- You're matching events by `source.ip`, `user.name`, `host.name`, or other shared fields
- You're building time-ordered event sequences with known patterns
- You're aggregating counts, calculating statistics, or joining data sets

Use your SIEM's correlation engine first. Use AI for the reasoning layer on top.

### Practical Implementation: Multi-Tier Correlation Framework

For a detailed, production-ready guide to building a multi-tier correlation rule framework using ES|QL, see [Correlation Rule Framework](../concepts/correlation-rule-framework.md). This document designs a 7-rule, 4-tier architecture covering:

- **Tier 1:** Entity-centric correlation (user, host, and IP dimensions)
- **Tier 2:** Kill chain progression, identity-to-endpoint chains, and lateral movement detection
- **Tier 3:** Slow-burn risk accumulation over 7-day windows
- **Tier 4:** Meta-correlation detecting multi-entity campaigns

Each rule includes risk-weighted scoring, security domain categorization, MITRE tactic diversity thresholds, and dynamic severity output — all deterministic, all SIEM-native, and all designed to produce structured input for the AI triage layer described in UC-11 and UC-12.

---

## 4.4 SOAR Automation

### Standard Triage Is a SOAR Workflow, Not AI

Before you deploy an AI agent for alert triage, ask: can this be handled by a deterministic SOAR playbook?

**SOAR should handle:**
- Enrichment lookups (asset, identity, threat intel, vulnerability)
- Known false positive suppression based on exact field matches
- Standard triage steps that follow deterministic logic
- Alert routing based on rule category, severity, and business unit
- Notification and escalation based on defined criteria
- Case creation and structured field population

**AI should handle:**
- Alerts where the disposition is uncertain after enrichment
- Pattern recognition that requires reasoning over multiple signals
- Natural language summarization of investigation context
- Suggesting next investigation steps when the standard playbook doesn't cover the situation

**The handoff model:**

```
Alert fires
    → SOAR playbook enriches the alert (API calls — deterministic)
    → SOAR playbook checks known FP patterns (rule matching — deterministic)
    → If matched: auto-close with documented pattern (no AI needed)
    → If not matched: SOAR passes enriched alert to AI agent
        → AI agent reasons over enriched data
        → AI agent returns structured recommendation
        → SOAR routes based on AI recommendation (escalate, close, request more info)
```

This model means AI only sees the alerts that deterministic automation can't handle. That's a dramatically smaller and more valuable workload than "all alerts."

### SOAR Platform Requirements for AI Integration

Your SOAR platform needs:
- **Webhook/API triggers** to invoke AI agents
- **Structured data passing** (JSON payloads, not screenshot attachments)
- **Response ingestion** (accept AI agent output and continue the workflow)
- **Audit trail** (log which decisions were made by SOAR, which by AI, which by human)
- **Override capability** (human can override any automated or AI-assisted decision)

---

## 4.5 Native Vendor AI vs. Custom Agents

### When to Use Vendor-Native AI

Every major security vendor is shipping AI features: Microsoft Copilot for Security, Google Security AI Workbench, Elastic AI Assistant, Splunk AI Assistant, CrowdStrike Charlotte AI.

**Use vendor-native AI when:**
- The use case is well-scoped and the vendor has trained specifically for it
- Integration is seamless (no custom plumbing)
- You want faster time-to-value with lower engineering effort
- The vendor's model has access to proprietary data or telemetry you don't have
- Compliance or procurement constraints favor vendor solutions

**Limitations of vendor-native AI:**
- You're locked to the vendor's decisions about what the AI can do
- Customization is limited — you can't change the prompts, the model, or the evaluation criteria
- Performance is a black box — you can't inspect why the AI made a specific decision
- Multi-vendor environments require multiple vendor AI tools that don't talk to each other

### When to Build Custom Agents

**Build custom AI agents when:**
- Your workflow spans multiple tools from different vendors
- You need full control over the prompts, model selection, and evaluation criteria
- You have domain-specific knowledge (custom detection rules, proprietary threat intel) that vendor models lack
- You want to iterate rapidly on agent behavior without waiting for vendor roadmaps
- You need transparency into AI decision-making for audit or compliance

**Requirements for custom agents:**
- Engineering capacity to build and maintain the agent
- Access to an LLM (API or self-hosted) with sufficient capability
- Tool integrations (SIEM API, SOAR API, CMDB API, etc.)
- Evaluation framework to measure agent performance
- Operational runbook for monitoring, tuning, and incident response for the agent itself

### The Hybrid Approach

Most mature SOCs will run both:
- Vendor-native AI for use cases where the vendor's integration is genuinely good (e.g., Microsoft Copilot for Sentinel-specific investigation)
- Custom agents for cross-platform workflows, detection engineering tasks, and use cases where vendor AI falls short

The key is measuring both against the same KPIs (see [Pillar 5](05-metrics-and-feedback.md)) and not assuming that "vendor" means "better" or "custom" means "better."

---

## 4.6 Self-Assessment Questions

1. **Are your detection rules managed as code?** Are rules in Git with CI/CD deployment, automated testing, and structured metadata? If rules live only in a SIEM GUI, AI agents can't read, analyze, or propose changes to them.

2. **Do all your SOC tools have documented, stable APIs?** Run the API audit table above. Any tool without an API is a gap. Any tool with undocumented or unstable APIs is a risk.

3. **Have you stress-tested API capacity for agent-scale operations?** Take your expected AI agent query volume and multiply by 3x. Can your APIs handle that? If not, you'll hit rate limits in production.

4. **Are you using your SIEM's correlation capabilities fully?** Before deploying AI for alert correlation, are you using EQL sequences, Splunk correlation searches, KQL joins, or Sentinel Fusion rules? If not, start there — it's cheaper, faster, and deterministic.

5. **Is your SOAR handling deterministic triage automation?** Is your SOAR platform processing known false positives, performing enrichment, and routing alerts — or is it shelfware? If your SOAR isn't doing its job, AI won't fix that.

**Scoring guidance:**
- **4-5 "yes" answers:** Your technology stack is ready for AI agents. Proceed to Pillar 5.
- **2-3 "yes" answers:** You have tooling gaps. Detection-as-code and SOAR automation should be priorities.
- **0-1 "yes" answers:** Your stack is not ready. Invest in modernization — detection-as-code, API-driven tools, SOAR automation — before deploying AI.

---

## Key Takeaway

AI agents are only as capable as the tools they can access. If your detection rules live in a GUI, your SOAR is shelfware, your SIEM's correlation engine is underutilized, and your APIs can't handle the load, no AI model — no matter how sophisticated — will deliver value.

Modernize your stack first. Use your SIEM for correlation. Use your SOAR for deterministic automation. Use detection-as-code for rule management. Then, and only then, add AI for the problems your deterministic tools can't solve.

The best AI deployment is the one with the smallest scope — because everything around it is already handled by the right tool for the job.
