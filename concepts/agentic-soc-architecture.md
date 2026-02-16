# Agentic SOC Architecture

## What "Agentic" Means in This Context

An agentic SOC uses AI agents that can autonomously execute multi-step investigation workflows, make triage decisions, and take bounded actions -- all under human supervision. This is not chatbot-style AI where an analyst asks a question and gets an answer. It is AI that receives an alert, investigates it through a sequence of tool calls, produces a triage recommendation, and presents its work for human review.

The term "agentic" specifically means:
- The AI determines what steps to take based on intermediate results (not following a fixed playbook)
- The AI can invoke tools (SIEM queries, enrichment APIs, EDR lookups) as part of its reasoning
- The AI produces a structured output (triage decision + evidence + narrative) for human review
- The human retains authority over final actions (containment, escalation, closure)

This is a meaningful shift from traditional automation (SOAR playbooks that follow predetermined paths) and from conversational AI (chatbots that answer one question at a time).

---

## How Agentic AI Changes Detection Engineering

### High-Recall Rules Become Viable

This is the single most important architectural implication.

Traditional detection engineering operates under a constraint: every alert a rule generates will be triaged by a human analyst. This creates a hard ceiling on alert volume per rule. A rule that fires 200 times per day is unmanageable for human triage. So detection engineers tune for precision -- they add exclusions, raise thresholds, and narrow scope until the rule produces a manageable volume. In the process, they sacrifice recall. True positives are excluded along with false positives.

**With agentic AI handling initial triage, this constraint relaxes.**

A rule that fires 200 times per day is no longer unmanageable if an AI agent triages 180 of those alerts as benign and surfaces 20 for human review. The detection engineer can write broader rules that catch more technique variants, knowing that the AI will filter the noise.

**Concrete example**:

Traditional approach to detecting credential dumping:
```
Rule: "LSASS Access via Known Tools"
Condition: process.name IN ("mimikatz.exe", "procdump.exe", "comsvcs.dll")
           AND target.process.name == "lsass.exe"
Volume: ~5 alerts/day (precise but misses novel tools)
```

Agentic approach:
```
Rule: "Any Non-Standard LSASS Access"
Condition: target.process.name == "lsass.exe"
           AND source.process.name NOT IN (known_legitimate_lsass_accessors)
Volume: ~150 alerts/day (broad, catches novel tools)
AI triage: Agent investigates each alert, checks source process reputation,
           examines process tree, correlates with other endpoint activity.
           Surfaces ~8-15 alerts/day to human analysts.
```

The broader rule catches the same known tools plus novel ones, living-off-the-land binaries, and process injection techniques. The AI agent handles the increased volume by applying contextual analysis that a static rule cannot.

**This does not mean you should write intentionally noisy rules.** It means you can prioritize recall without being punished by alert volume. The rule should still be as precise as possible -- the AI agent should not be your primary noise filter. But the tolerance for imprecision increases.

### Detection Engineering Shifts from Tuning to Teaching

In a traditional SOC, detection engineers spend substantial time tuning rules: adding exclusions, adjusting thresholds, handling edge cases. This is maintenance work that does not improve detection capability -- it just keeps the alert queue manageable.

In an agentic SOC, some of this tuning shifts to the AI agent. Instead of adding `host.name != "BUILD-SERVER-01"` to the rule exclusion list, you might add context to the agent: "Alerts from build servers in the CI/CD subnet (10.50.0.0/24) that involve compiler-related processes are expected and should be triaged as benign unless they involve outbound network connections."

This is not a panacea. Rule-level tuning is still necessary for performance (broad rules are expensive to run on high-volume data). But the *quality tuning* -- distinguishing signal from noise -- can partially move to the AI triage layer.

---

## The New Feedback Loop

Traditional SOC feedback loop:
```
Detect → Alert → Analyst Triage → Resolve → (maybe) Tune Rule
```

The "maybe" is doing a lot of work. In practice, the feedback loop from analyst triage back to rule tuning is broken in most organizations. Analysts close tickets. Detection engineers rarely see the closure data. Rules are tuned reactively when someone complains about volume, not proactively based on triage outcomes.

Agentic SOC feedback loop:
```
Detect → AI Triage → Human Validation → Feedback to AI + Rule Tuning → Detect
```

### Stage 1: Detect

Detection rules fire and generate alerts. No change from traditional SOC, except rules may be broader (higher recall) because the downstream triage can handle more volume.

### Stage 2: AI Triage

The AI agent receives each alert and executes an investigation workflow:

1. **Enrich**: Query CMDB for host context, AD for user context, threat intel for IOC reputation, vulnerability scanner for host exposure.
2. **Correlate**: Search for related alerts on the same entity within a time window. Check for cross-domain correlation.
3. **Analyze**: Evaluate the enriched, correlated alert against the detection rule's intent. Consider the entity's behavioral baseline. Assess the Signal Quality Score for this rule.
4. **Decide**: Assign a triage recommendation: Escalate (probable true positive), Monitor (suspicious but inconclusive), Close (probable false positive or benign true positive).
5. **Narrate**: Generate a human-readable summary of the investigation, the evidence gathered, and the reasoning behind the recommendation.

### Stage 3: Human Validation

A human analyst reviews the AI agent's triage output. The review focus depends on the AI recommendation:

- **Escalate**: Analyst validates the AI's reasoning and evidence, then proceeds with incident response. The AI's narrative saves the analyst the initial investigation time.
- **Monitor**: Analyst reviews the ambiguity. May agree (add to watch list) or override (escalate or close).
- **Close**: Analyst spot-checks a sample of AI closures. Not every closed alert needs review, but a statistically significant sample should be reviewed to measure AI accuracy.

### Stage 4: Feedback

Human validation outcomes feed back into two systems:

1. **AI agent tuning**: The agent's accuracy is measured by human override rate. If analysts frequently override "Close" to "Escalate," the agent is too permissive. If analysts frequently override "Escalate" to "Close," the agent is too aggressive. This data tunes the agent's decision thresholds.

2. **Rule tuning**: Patterns in AI triage outcomes inform rule modifications. If the AI consistently triages alerts from a specific rule as "Close" with the explanation "legitimate admin tool on IT workstations," the detection engineer can add a precise exclusion to the rule itself, reducing unnecessary AI processing.

### Stage 5: Detect (improved)

The cycle repeats with improved rules (fewer false positives reaching the AI), an improved AI agent (better triage accuracy from feedback), and better data for Signal Quality Scoring (human validation provides ground-truth disposition data).

---

## What It Means for SOC Roles

### Analysts as Agent Supervisors

The Tier 1 analyst role transforms from "triage every alert manually" to "supervise AI triage quality and handle escalations." This is not a reduction in skill requirement -- it is an increase. Supervising an AI agent requires:

- **Understanding what the AI can and cannot do**: Knowing when to trust the agent's recommendation and when to override it.
- **Evaluating AI reasoning**: Reading the agent's narrative and identifying logical gaps or missed evidence.
- **Recognizing AI failure modes**: Understanding that the agent may be confidently wrong (hallucination in narrative, missed correlation, over-reliance on a single enrichment source).
- **Providing quality feedback**: Articulating why an override was made so the feedback improves the agent.

This is harder than traditional alert triage, not easier. An analyst triaging alerts manually can develop intuition from repetition. An analyst supervising an AI agent must maintain that intuition while also critically evaluating automated reasoning that may be subtly wrong in ways that are not obvious.

### Detection Engineers as System Architects

Detection engineers in an agentic SOC are responsible for the entire detection-triage pipeline, not just the rules:

- **Rule design**: Writing rules with appropriate recall/precision tradeoffs for AI-assisted triage.
- **Agent configuration**: Defining the investigation workflow the AI agent follows for each rule type or domain.
- **Feedback loop maintenance**: Ensuring human validation data flows back to both the agent and the rules.
- **Quality measurement**: Operating the Signal Quality Scoring and Detection Confidence Scoring systems to measure end-to-end effectiveness.

### Threat Hunters Leverage AI as a Research Partner

Threat hunters can use AI agents as investigation accelerators:

- "Investigate all hosts that contacted this C2 domain in the last 90 days" -- the AI agent runs the queries, enriches the results, and produces a summary for each host.
- "Find behavioral similarities between this confirmed compromise and any other endpoint activity" -- the AI agent compares process trees, network patterns, and file system activity across the environment.

The hunter directs the investigation. The AI agent handles the mechanical work of running queries and synthesizing results.

---

## Architecture Components

```
┌─────────────┐     ┌───────────────────┐     ┌─────────────────┐
│    SIEM     │────>│  Enrichment Layer  │────>│  AI Triage Agent │
│  (Alerts)   │     │  (CMDB, AD, TI,   │     │                 │
│             │     │   Vuln, Baseline)  │     │  - Investigate  │
└─────────────┘     └───────────────────┘     │  - Correlate    │
                                               │  - Decide       │
                                               │  - Narrate      │
                                               └────────┬────────┘
                                                        │
                                                        v
                                               ┌─────────────────┐
                                               │  Human Review    │
                                               │  Queue           │
                                               │                 │
                                               │  - Escalations  │
                                               │  - Spot checks  │
                                               │  - Overrides    │
                                               └────────┬────────┘
                                                        │
                                                        v
                                               ┌─────────────────┐
                                               │  Feedback Store  │
                                               │                 │
                                               │  - Dispositions │
                                               │  - Overrides    │
                                               │  - Accuracy     │
                                               │    metrics      │
                                               └────────┬────────┘
                                                        │
                                    ┌───────────────────┼───────────────────┐
                                    v                                       v
                           ┌─────────────────┐                    ┌─────────────────┐
                           │  Agent Tuning   │                    │  Rule Tuning    │
                           │                 │                    │                 │
                           │  - Decision     │                    │  - Exclusions   │
                           │    thresholds   │                    │  - Thresholds   │
                           │  - Prompt       │                    │  - Field maps   │
                           │    refinement   │                    │                 │
                           └─────────────────┘                    └─────────────────┘
```

### SIEM (Alert Source)

No architectural change. The SIEM fires alerts as it always has. The difference is that alerts route to the AI triage agent instead of directly to analyst queues. The SIEM query layer should expose an API that the AI agent can call for correlation queries (search for related alerts, historical activity for an entity, etc.).

### Enrichment Layer

A middleware service that aggregates context from multiple sources and presents it through a unified API. The AI agent calls this API to enrich entities. Key data sources:

- **CMDB/Asset Inventory**: Host ownership, department, criticality, OS, role
- **Active Directory / Identity Provider**: User attributes, group memberships, privilege level, manager
- **Threat Intelligence**: IOC reputation, threat actor attribution, campaign context
- **Vulnerability Scanner**: Open vulnerabilities on the host, patch status, exposure score
- **Behavioral Baseline**: Historical activity patterns for the entity (normal login times, typical process execution, usual network destinations)

The enrichment layer should be cacheable and fast. The AI agent will call it for every alert. Latency here directly impacts triage throughput.

### AI Triage Agent

The core component. Implementation choices:

- **LLM backbone**: A capable language model (GPT-4 class or equivalent) with tool-use capability.
- **Tool definitions**: The agent has access to defined tools: SIEM query, enrichment lookup, EDR process tree query, ticket creation, etc.
- **System prompt / context**: Includes the domain-aware entity framework, the rule's metadata and intent, the Signal Quality Score, and any domain-specific triage guidance.
- **Output format**: Structured JSON (triage decision, confidence, evidence list) plus natural-language narrative.
- **Guardrails**: The agent cannot take containment actions (isolate host, block IP, disable account) without human approval. Read-only investigative actions are permitted. Write actions (ticket creation, tag assignment) may be permitted for low-risk categories.

### Human Review Queue

A purpose-built interface (or integration with existing SOAR/ticketing) that presents:

- The AI agent's triage recommendation
- The evidence gathered during investigation
- The AI's narrative explanation
- One-click approve/override controls
- Override reason capture (feeds back to agent tuning)

The queue should be organized by AI confidence: low-confidence decisions get human review first.

### Feedback Store

A persistent data store tracking:

- Every AI triage decision with its evidence and reasoning
- Every human validation outcome (approve, override, reason)
- Accuracy metrics over time (precision, recall, override rate by rule, by domain, by agent version)
- This data feeds into Signal Quality Scoring (as disposition data) and into agent prompt tuning.

---

## Current Maturity: An Honest Assessment

As of early 2026, most agentic SOC implementations are in early stages. Here is a realistic maturity assessment:

### What Works Today

- **AI-assisted triage narration**: LLMs are good at synthesizing enrichment data into readable summaries. This saves analyst time even without autonomous triage decisions.
- **Structured investigation playbooks with AI reasoning**: An AI agent following a defined investigation template (enrich, correlate, summarize) with tool-use works reliably for common alert types (phishing, malware, brute force).
- **Natural language threat hunting**: Analysts describe what they want to find, AI translates to SIEM queries. This is productive today, with human review of query correctness.
- **Report generation**: Weekly/monthly detection posture reports generated by AI from structured data are immediately useful.

### What Is Emerging But Not Mature

- **Autonomous triage decisions**: AI agents can make triage recommendations, but most organizations are not confident enough to let the AI close alerts without human review. The accuracy required to operate autonomously (>99% agreement with human analysts) has not been reliably demonstrated in production at scale.
- **Dynamic investigation paths**: AI agents that deviate from predefined investigation templates based on findings are possible but difficult to validate. "What did the AI decide to skip, and was that the right call?" is hard to audit.
- **Cross-domain investigation**: An AI agent that pivots from endpoint to network to cloud to identity during a single investigation requires tool access across all domains and the ability to reason about cross-domain relationships. This works in demos but is fragile in production.

### What Is Aspirational

- **Self-tuning detection rules**: AI agents that observe their own triage patterns and automatically modify detection rules to reduce false positives. This requires a level of trust in AI reasoning that most organizations are not prepared to extend.
- **Fully autonomous incident response**: AI agents that detect, investigate, contain, and remediate without human intervention. The risk of an AI agent incorrectly isolating a production server or disabling a legitimate user account is too high for current confidence levels.
- **Adversarial resilience**: AI agents that can detect and resist attacker manipulation of their inputs (adversarial examples in logs, deliberate triggering of AI blind spots). This is an active research area with no production solutions.

---

## Risks and Failure Modes

### 1. Automation Complacency

When AI handles triage, analysts may stop critically evaluating the AI's work. "The AI said it's benign, so it must be benign." This is the most dangerous failure mode because it is invisible -- you do not know you have a problem until you miss a real incident.

**Mitigation**: Mandatory spot-check rates. Force analysts to review a random sample of AI-closed alerts (e.g., 5% of all closures). Track the override rate on spot-checks as a leading indicator of complacency.

### 2. Hallucinated Reasoning

LLMs can produce confident, detailed narratives that are factually wrong. An AI agent might "see" a correlation that does not exist, "remember" threat intelligence it fabricated, or produce a logically coherent explanation for a conclusion that the evidence does not support.

**Mitigation**: Require the AI agent to cite specific evidence for every claim in its narrative. The evidence must be verifiable by the reviewing analyst (specific log entry IDs, specific enrichment API responses). Narratives without cited evidence should be flagged for mandatory review.

### 3. Data Quality Dependency

An AI agent is only as good as the data it receives. If the enrichment layer returns stale CMDB data (host was reassigned 3 months ago but the record was not updated), the agent will make triage decisions based on wrong context. If the SIEM is missing logs from a data source, the agent will conclude there is no correlated activity when there actually is -- the data is just absent.

**Mitigation**: Integrate data source health monitoring (from Signal Quality Scoring) into the agent's reasoning. The agent should factor data freshness and completeness into its confidence level. "I found no correlated network activity, but the firewall data source has been intermittent this week -- my confidence is reduced."

### 4. Model Drift and Degradation

LLM behavior can change across model versions. An agent tuned to work well with GPT-4 may behave differently when the model is updated to GPT-4-turbo or a successor. Prompt tuning is version-specific.

**Mitigation**: Version-lock the model in production. Test new model versions against a benchmark set of alerts with known-good triage outcomes before deploying. Track accuracy metrics continuously and alert on degradation.

### 5. Adversarial Manipulation

A sophisticated attacker who understands the AI triage system could deliberately craft their activity to trigger benign-looking patterns in the AI's reasoning. For example, performing malicious actions that mimic known legitimate automation patterns, knowing the AI will close the alert.

**Mitigation**: This is an unsolved problem at the industry level. Practical mitigations include: maintaining human-only review for high-severity alerts, rotating investigation strategies (so attackers cannot predict the AI's approach), and treating any AI-closed alert that later correlates with a confirmed incident as a critical failure requiring root cause analysis.

### 6. Cost and Latency

Running an LLM for every alert is expensive. At 1,000 alerts per day with an average investigation requiring 5 LLM calls, that is 5,000 API calls per day. At $0.03 per 1K input tokens and $0.06 per 1K output tokens (typical for capable models), with an average of 4K tokens per call, that is approximately $600-1,200 per month in API costs alone. At 10,000 alerts per day, costs scale to $6,000-12,000/month.

Latency is also a concern. If each LLM call takes 2-5 seconds and an investigation involves 5-8 calls, triage takes 10-40 seconds per alert. For time-sensitive alerts, this may be too slow.

**Mitigation**: Use AI triage selectively. Not every alert needs AI investigation. Low-severity, high-volume alerts can be triaged by simple deterministic rules (if Signal Quality Score > 80 and rule is well-tuned, fast-track the alert). Reserve AI triage for medium-confidence, ambiguous alerts where it adds the most value. Use smaller, faster models for initial classification and larger models for detailed investigation.

---

## Getting Started: A Practical Progression

### Phase 1: AI-Assisted Narration (Low Risk)

Deploy AI to generate narrative summaries for alerts that are still triaged by humans. The AI does not make decisions -- it summarizes enrichment data into readable text. Analysts benefit from faster context gathering. You learn what the AI gets right and wrong with zero risk to triage quality.

Duration: 1-3 months.

### Phase 2: AI Triage Recommendations (Moderate Risk)

Deploy AI to make triage recommendations alongside the narration. Analysts still review every alert but see the AI's suggestion. Track agreement rate. When the AI's recommendation matches the analyst's decision >90% of the time for a specific rule/domain, consider moving to Phase 3 for that rule/domain.

Duration: 3-6 months.

### Phase 3: AI Triage with Spot-Check (Managed Risk)

For high-agreement rule/domain pairs, allow the AI to close alerts autonomously with mandatory spot-check sampling. Analysts review 100% of escalations and a random sample (5-10%) of closures. Track override rates on spot-checks.

Duration: 6-12 months, expanding gradually.

### Phase 4: Full Agentic Triage (Higher Risk, Higher Reward)

Expand autonomous triage to most alert types. Analysts focus on escalation investigation, spot-check oversight, and feedback provision. Detection engineers focus on rule development, agent tuning, and quality measurement.

Duration: Ongoing. Most organizations will reach Phase 3 before considering Phase 4. Phase 4 requires sustained demonstration of AI accuracy across diverse alert types and attack scenarios.

---

## Measuring Success

### Quantitative Metrics

- **AI accuracy**: Percentage of AI triage decisions that match human analyst judgment (measured via spot-checks and override tracking)
- **Mean time to triage (MTTT)**: Time from alert generation to triage decision. Should decrease with AI assistance.
- **Analyst throughput**: Alerts effectively triaged per analyst per shift. Should increase.
- **Detection coverage**: Number of techniques with Functional or Strong Detection Confidence. Should increase as broader rules become viable.
- **False negative rate**: Incidents discovered through means other than detection rules (third-party notification, user report). Should not increase. If it does, AI triage may be closing real positives.

### Qualitative Indicators

- Analyst satisfaction: Are analysts finding the AI narrations useful? Are they trusting the triage recommendations?
- Investigation depth: Are incidents investigated more thoroughly with AI assistance (more enrichment, more correlation)?
- Feedback loop health: Are analysts providing override reasons? Is the data being used to improve the agent?

The agentic SOC is not a destination. It is an iterative process of expanding AI's role as trust is earned through measured performance. The architecture supports this iteration -- each phase builds on the data and confidence gained in the previous phase.
