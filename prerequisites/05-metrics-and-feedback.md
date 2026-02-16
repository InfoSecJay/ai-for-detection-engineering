# Pillar 5: SOC Metrics and Feedback Loops

> **Core principle:** "You are ready for AI if you can, after adding AI, answer the 'what got better?' question."

If you can't measure your current SOC performance with real numbers, you can't measure whether AI improved it. Every AI vendor will show you impressive demos. The only question that matters is: **did this make our SOC measurably better at its job?**

Without baselines, without KPIs, without feedback loops, you're flying blind. You might deploy an AI agent that makes things worse and never know it — because you never measured "before."

---

## 5.1 Establish Baselines Before AI Deployment

### You Cannot Improve What You Cannot Measure

Before deploying any AI agent, you need current-state measurements for the workflows it will touch. These are your baselines. Without them, any claim about AI effectiveness is anecdotal.

### Core SOC Metrics to Baseline

**Mean Time to Detect (MTTD):**
- How long between when an attack occurs and when your SOC generates an alert?
- This is primarily a detection engineering metric, not an AI metric — but AI use cases like detection gap analysis can impact it.
- Measure per detection category (phishing, endpoint, cloud IAM, lateral movement).

**Mean Time to Respond (MTTR) — or more precisely, Mean Time to Triage:**
- How long between when an alert fires and when an analyst reaches a disposition (TP, FP, BTP)?
- This is the primary metric for AI-assisted triage. Measure it per alert category.
- Break it down: time waiting in queue + time actively investigated + time awaiting enrichment + time in escalation.

**False Positive Rate:**
- What percentage of alerts for each detection rule are false positives?
- Measure per rule, not as an aggregate. A 30% overall FP rate might mean some rules are at 90% FP (and should be tuned or removed) while others are at 5%.
- Track over time — a rule that was 10% FP six months ago might be 40% FP now due to environment changes.

**Alert Volume:**
- Total alerts per day/week/month, broken down by category and severity.
- Alerts per analyst per shift.
- Trend: is volume growing? Shrinking? Holding steady?

**Analyst Disposition Consistency:**
- When two different analysts triage the same alert type, do they reach the same disposition?
- Measure inter-analyst agreement rate. If it's below 80%, your processes are ambiguous (Pillar 2 problem).

**Escalation Rate:**
- What percentage of alerts are escalated from L1 to L2/L3?
- High escalation rates may indicate L1 doesn't have enough context or authority to close alerts — a process or data problem.

### How to Capture Baselines

**Manual approach (if you have structured case data):**

Pull the last 90 days of alert dispositions from your ticketing/SOAR system. Calculate:

```
For each detection rule category:
  - Median time to triage (P50, P90, P99)
  - FP rate = count(FP) / count(all dispositions)
  - Escalation rate = count(escalated) / count(all)
  - Volume = count(alerts) / days
```

**Automated approach (if you have the data in your SIEM or SOAR):**

Build a dashboard that calculates these metrics in real time and stores weekly snapshots. This dashboard becomes your AI performance monitor.

**Splunk example — triage time baseline:**
```spl
index=soar_cases earliest=-90d
| eval triage_time_min = (disposition_time - alert_time) / 60
| stats
    median(triage_time_min) as p50_triage,
    perc90(triage_time_min) as p90_triage,
    count as total_alerts,
    count(eval(disposition="false_positive")) as fp_count
  by rule_category
| eval fp_rate = round(fp_count / total_alerts * 100, 1)
| sort - total_alerts
```

### The Baseline Document

Create a formal baseline document before any AI deployment. It should contain:

| Metric | Current Value | Measurement Period | Data Source | Notes |
|--------|--------------|-------------------|-------------|-------|
| Median triage time (phishing) | 11 min | Last 90 days | SOAR case data | Excludes weekends/after-hours |
| FP rate (phishing rules) | 62% | Last 90 days | SOAR dispositions | Dominated by Rule X and Rule Y |
| Median triage time (endpoint) | 23 min | Last 90 days | SOAR case data | Higher due to manual EDR pivots |
| FP rate (endpoint rules) | 38% | Last 90 days | SOAR dispositions | |
| Analyst agreement rate | 74% | Sampled 200 alerts | Manual audit | Phishing had highest agreement (85%) |

This document is your "before" picture. Guard it. Every "AI saved us X minutes" claim must be measured against it.

---

## 5.2 Build a "Golden Set" for Validation

### What Is a Golden Set?

A Golden Set is a curated collection of **50-100 past incidents with known-correct dispositions** that you use to validate AI agent performance. It's your test suite for AI.

### Building the Golden Set

**Selection criteria:**

1. **Diversity of outcomes:** Include true positives, false positives, and benign true positives in proportions that reflect your actual alert mix.
2. **Range of complexity:** Include simple cases (obvious FP, obvious TP) and hard cases (ambiguous, context-dependent).
3. **Coverage of alert types:** Represent every alert category the AI agent will handle.
4. **Documented investigation paths:** Each Golden Set case includes the full investigation record: what data was examined, what was found, what the disposition was, and why.
5. **Expert-validated:** Senior analysts reviewed and agreed on the dispositions. Not just whatever the original analyst wrote.

**Example Golden Set entry:**

```yaml
golden_set_id: "GS-042"
alert_type: "Suspicious PowerShell Execution"
rule_id: "elastic-rule-12345"
date: "2024-09-15"

# The alert data (anonymized if needed)
alert_data:
  host.name: "WS-FINANCE-012"
  user.name: "jsmith"
  process.name: "powershell.exe"
  process.args: "-EncodedCommand SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA=="
  event.action: "process_created"

# Enrichment context
enrichment:
  asset_criticality: "standard"
  user_department: "Finance"
  user_privileged: false
  threat_intel_match: false
  host_vulnerabilities: ["CVE-2024-1234 (medium)"]

# Expert-validated disposition
correct_disposition: "true_positive"
confidence: "high"
reasoning: "Finance user running encoded PowerShell that decodes to Invoke-WebRequest
  to an external IP. Not consistent with any known business process. Confirmed as
  initial access attempt in subsequent investigation."

# Expected investigation steps
expected_investigation:
  - "Decode the base64 command"
  - "Check destination IP against threat intel"
  - "Review user's PowerShell history for baseline"
  - "Check if host has any other alerts in the same timeframe"

mitre_technique: "T1059.001"
```

### Using the Golden Set

**Initial validation:** Before deploying an AI agent, run every Golden Set case through it. Compare AI dispositions against the known-correct answers.

```
Golden Set Validation Results:
  Total cases: 75
  Correct dispositions: 68 (90.7%)
  False negatives (AI missed real threats): 2 (2.7%)
  False positives (AI flagged benign as malicious): 5 (6.7%)

  Performance by category:
    Phishing: 95% correct (19/20)
    Endpoint: 88% correct (22/25)
    Cloud IAM: 87% correct (13/15)
    Network: 93% correct (14/15)
```

**Ongoing regression testing:** Every time you update the AI agent (new prompts, model upgrade, new tool integrations), re-run the Golden Set. If performance drops, you've introduced a regression.

**Expanding the Golden Set:** Add new cases quarterly, especially cases where the AI got the answer wrong in production. These "hard cases" are the most valuable additions to the set.

---

## 5.3 Agent-Specific KPIs

### Beyond SOC Metrics: Measuring the Agent Itself

SOC-level metrics (MTTR, FP rate) tell you whether outcomes improved. Agent-specific KPIs tell you whether the AI agent is performing well as a component.

**Accuracy Rate:**
- What percentage of AI dispositions match analyst dispositions (or Golden Set answers)?
- Track overall and per alert category
- Set a minimum threshold (e.g., 90% overall accuracy) below which the agent is pulled for review
- Distinguish between error types: false negatives (AI missed a threat) are far more costly than false positives (AI over-escalated)

**Time Savings:**
- For each alert the AI handles, how much analyst time was saved?
- Compare median triage time with AI assistance vs. the baseline without AI
- Don't just measure alerts the AI auto-closed — measure the time savings on alerts where the AI provided a summary that the analyst approved/rejected

**Confidence Calibration:**
- When the AI says it's 90% confident, is it right 90% of the time? 80%? 70%?
- Plot a reliability diagram: predicted confidence (x-axis) vs. actual accuracy (y-axis)
- Perfect calibration is a 45-degree line. If the AI consistently overestimates its confidence, analysts can't trust the confidence scores

```
Confidence Calibration Assessment:
  AI says 95% confident → Actually correct 93% of the time  (well calibrated)
  AI says 85% confident → Actually correct 84% of the time  (well calibrated)
  AI says 75% confident → Actually correct 61% of the time  (OVERCONFIDENT — recalibrate)
  AI says 60% confident → Actually correct 55% of the time  (acceptable)
```

**Coverage:**
- What percentage of total alerts does the AI agent process?
- Of those, what percentage does it handle autonomously vs. with human review?
- Is coverage expanding over time as the agent learns and confidence thresholds are adjusted?

**Latency:**
- How long does the AI agent take to process an alert?
- If the agent takes 5 minutes to process an alert that an analyst could handle in 3 minutes, it's not saving time
- Break down latency: API calls, model inference, tool execution

**Failure Rate:**
- How often does the AI agent fail to produce a result? (API errors, timeouts, model refusals, malformed outputs)
- Failures should trigger fallback to human triage — but high failure rates indicate reliability problems

### KPI Dashboard

Build a real-time dashboard that tracks agent KPIs:

| KPI | Target | Current (7-day) | Trend |
|-----|--------|-----------------|-------|
| Accuracy rate | > 90% | 92.3% | Stable |
| False negative rate | < 2% | 1.1% | Stable |
| Median processing time | < 60s | 34s | Improving |
| Confidence calibration error | < 5% | 3.2% | Stable |
| Coverage (% of alerts processed) | > 70% | 68% | Growing |
| Failure rate | < 1% | 0.4% | Stable |
| Analyst override rate | < 15% | 11.2% | Declining (good) |

Review this dashboard weekly. If any KPI breaches its threshold, investigate immediately.

---

## 5.4 Close the Feedback Loop — Continuous Tuning

### The Feedback Loop Architecture

AI agents in SOC operations must participate in a continuous feedback loop:

```
Alert fires
  → AI agent triages (produces disposition + confidence)
  → Analyst reviews AI disposition (approves, rejects, or modifies)
  → Analyst feedback is logged as structured data
  → Feedback feeds into:
      1. AI agent tuning (prompt adjustments, threshold changes)
      2. Detection rule tuning (FP patterns, severity adjustments)
      3. Golden Set expansion (new validated cases)
      4. KPI recalculation (updated baselines)
  → Improved AI performance on next iteration
```

### Triage Results Feed Back into Detection Tuning

This is where AI-assisted triage becomes genuinely valuable beyond speed: the feedback from AI triage, combined with analyst review, generates structured data that detection engineers can use to improve rules.

**Example feedback-to-tuning pipeline:**

```
AI agent triages 500 alerts for Rule X over 30 days:
  - 310 closed as FP (62% FP rate)
  - 140 closed as BTP (28%)
  - 50 confirmed as TP (10%)

Analysis of the 310 FPs reveals:
  - 180 match pattern: host.group == "build_servers" AND process.parent.name == "jenkins"
  - 95 match pattern: user.name IN service_accounts_list
  - 35 miscellaneous

Action items for detection engineering:
  1. Add exception for Jenkins-triggered builds on build servers (eliminates 58% of FPs)
  2. Add service account exclusion list (eliminates 31% of remaining FPs)
  3. Review remaining 35 FPs for additional patterns
  4. Recalculate rule severity after tuning (FP rate should drop from 62% to ~15%)
```

This pipeline — AI identifies FP patterns at scale, detection engineers create targeted exceptions — is faster and more systematic than manual FP analysis. The AI isn't writing the exceptions; it's identifying the patterns. The detection engineer validates and implements.

### Analyst Feedback Mechanisms

Make it easy for analysts to provide structured feedback on AI decisions:

**For agree decisions:**
- One-click "Approve AI decision" with optional confidence rating
- Logged automatically — no friction

**For disagree decisions:**
- Required fields: what was wrong? (disposition, reasoning, missing context)
- Dropdown for common disagreement reasons:
  - "AI missed critical context" (specify what)
  - "AI used outdated information"
  - "AI disposition was wrong" (specify correct disposition)
  - "AI confidence was too high/low"
- Optional freeform note for edge cases

**Feedback review cadence:**
- Weekly: Agent Supervisor reviews all disagreements, identifies patterns
- Monthly: Detection Engineering reviews AI-driven tuning recommendations
- Quarterly: Re-run Golden Set, update baselines, adjust error budget if needed

### Avoiding Feedback Loop Traps

**Trap 1: Automation bias.** Analysts start auto-approving AI decisions without reading them. Monitor override rates — if they drop below 3%, analysts may be rubber-stamping. Introduce periodic "confidence checks" where you deliberately inject known-wrong AI decisions to see if analysts catch them.

**Trap 2: Feedback drift.** If analysts provide inconsistent feedback (one analyst says TP, another says FP for the same pattern), the feedback data is noisy. Measure inter-analyst agreement on AI review tasks.

**Trap 3: Stale Golden Set.** If you never update the Golden Set, it stops reflecting current attack patterns and environment changes. Schedule quarterly reviews.

**Trap 4: Optimizing for the wrong metric.** If you optimize for speed alone, accuracy suffers. If you optimize for accuracy alone, the agent becomes too conservative. Balance speed, accuracy, and coverage.

---

## 5.5 Self-Assessment Questions

1. **Do you have current baselines for MTTR, FP rate, and alert volume?** Can you pull numbers for the last 90 days, broken down by alert category? If not, you can't measure AI's impact.

2. **Have you built a Golden Set?** Do you have 50-100 expert-validated past incidents that you can use as a test suite for AI agents? If not, you have no way to validate agent performance before deployment.

3. **Are you tracking agent-specific KPIs?** Beyond SOC metrics, are you measuring the AI agent's accuracy, confidence calibration, latency, and failure rate? If not, you're not monitoring the agent as a system component.

4. **Is there a feedback loop from triage to detection tuning?** When AI-assisted triage identifies a high-FP rule, does that information reach the detection engineering team? Is there a process for acting on it?

5. **Can you answer "what got better?"** If someone asks you today what improved since you deployed AI, can you point to specific metrics with before-and-after numbers? If not, you're running on faith, not evidence.

**Scoring guidance:**
- **4-5 "yes" answers:** Your metrics and feedback infrastructure is ready. You can deploy AI and measure its impact.
- **2-3 "yes" answers:** You have measurement gaps. Build baselines and validation sets before deployment.
- **0-1 "yes" answers:** You can't measure AI's impact. Deploy now and you'll never know if it helped, hurt, or made no difference. Invest in measurement infrastructure first.

---

## Key Takeaway

Metrics are not optional overhead. They are the mechanism by which you determine whether AI is worth the investment. Without baselines, you can't measure improvement. Without a Golden Set, you can't validate accuracy. Without agent KPIs, you can't monitor reliability. Without feedback loops, you can't improve over time.

The most common AI deployment failure mode isn't "the AI was bad." It's "we don't know if the AI was good or bad because we never measured."

Measure before. Measure during. Measure after. Close the loop.
