# AI-Ready SOC Readiness Checklist

Use this checklist to assess your organization's readiness for AI deployment in security operations. Each item corresponds to a prerequisite discussed in the Five Pillars documents.

**How to use this checklist:**
- Work through each pillar with your team. Be honest — unchecked boxes are not failures, they're priorities.
- Items are not weighted equally. Data Foundations and Process Maturity are the most critical — if those sections have unchecked boxes, fix them first.
- Review this checklist quarterly. Readiness is not a one-time assessment; it shifts as your environment, team, and tooling change.
- A checked box means "yes, this is in place and actively maintained," not "we did this once two years ago."

---

## Pillar 1 — Data Foundations

- [ ] All log sources are parsed into structured fields using the SIEM's normalized schema (ECS, CIM, ASIM, or equivalent)
- [ ] Common entity fields (`user.name`, `source.ip`, `host.name`, `event.action`, `event.outcome`) are reliably populated across all sources at >95% field population rate
- [ ] Alert enrichment (asset lookup, identity context, threat intel matching, vulnerability data) is automated via SIEM ingest pipelines or SOAR playbooks — not performed manually by analysts
- [ ] All critical security data sources are queryable via documented, stable APIs
- [ ] Past incident data (dispositions, investigation steps, outcomes) is stored in structured, machine-queryable format — not trapped in freeform ticket notes
- [ ] Data quality is actively monitored: automated checks for volume drops, field population degradation, and unmapped sources run on a scheduled basis
- [ ] Data retention meets minimum requirements: 90+ days searchable for investigation, 12+ months for hunting and trend analysis
- [ ] Threat intelligence is integrated programmatically with the SIEM/SOAR — not accessed via a standalone portal that analysts check manually
- [ ] A federated data access layer exists (or is planned) so that AI agents can query across SIEM, SOAR, EDR, CMDB, and ticketing via a unified interface

---

## Pillar 2 — Process Maturity

- [ ] Triage procedures for high-volume alert types are documented in structured, machine-readable formats (decision trees with explicit conditions, not paragraphs of prose)
- [ ] Known false positive patterns are maintained as structured libraries per detection rule, with field conditions, business justification, approval records, and review dates
- [ ] AI-human handoff criteria are explicitly defined for each workflow where AI will operate — specifying exactly when the AI stops and a human takes over, including confidence thresholds and mandatory-escalation conditions
- [ ] Case management uses structured fields for disposition (TP/FP/BTP), MITRE technique, affected assets, affected users, root cause, and time-to-resolve — not just freeform analyst notes
- [ ] The first AI workflow target has been identified using selection criteria: high volume, good data quality, documented process, measurable outcomes, and low blast radius

---

## Pillar 3 — Human Element

- [ ] Leadership has approved a formal AI error budget that defines acceptable false negative rates, false positive rates, auto-close accuracy thresholds, and confidence calibration targets — specific numbers, not vague risk tolerance
- [ ] Analyst roles are redefined for AI collaboration: job descriptions, performance metrics, and daily workflows reflect the shift from manual triage to AI-assisted operations, with clear ownership of AI Logic Editor and Agent Supervisor responsibilities
- [ ] A RACI matrix exists for every AI-assisted workflow, specifying who is Responsible, Accountable, Consulted, and Informed when the AI makes a decision — and explicitly naming the person accountable when the AI gets it wrong
- [ ] Analysts have completed hands-on training for evaluating AI outputs, providing structured feedback, understanding confidence scores, recognizing confabulation, and knowing when to override AI recommendations

---

## Pillar 4 — Technology Stack

- [ ] Detection rules are managed as code: stored in Git with version history, deployed via CI/CD pipelines, validated with automated tests, and accompanied by structured metadata (MITRE mapping, severity, data source requirements, known FP patterns)
- [ ] All SOC tools (SIEM, SOAR, EDR, TIP, CMDB, ticketing, IAM) have documented and stable APIs, with service accounts provisioned and rate limits understood
- [ ] API capacity has been stress-tested for AI agent volumes — accounting for the fact that agents make 10-100x more API calls than human analysts per unit of time
- [ ] The SIEM's native correlation capabilities (EQL sequences, Splunk correlation searches, KQL joins, Sentinel Fusion rules) are actively used for field-based alert correlation — not deferred to AI for problems the query engine already solves
- [ ] SOAR playbooks handle deterministic triage automation (enrichment, known FP suppression, alert routing, case creation) so that AI agents only receive alerts that deterministic logic cannot resolve

---

## Pillar 5 — Metrics & Feedback

- [ ] Current-state baselines exist for key SOC metrics: MTTR per alert category, FP rate per detection rule, alert volume trends, escalation rates, and analyst disposition consistency — covering at least the last 90 days
- [ ] A Golden Set of 50-100 expert-validated past incidents (with known-correct dispositions, full investigation records, and diverse alert types) has been built and is maintained as a regression test suite for AI agents
- [ ] Agent-specific KPIs are defined and tracked: accuracy rate, false negative rate, confidence calibration, processing latency, failure rate, coverage percentage, and analyst override rate — with minimum thresholds that trigger review when breached
- [ ] A feedback loop is in place: analyst agree/disagree decisions on AI outputs are captured as structured data, reviewed weekly, and fed back into AI agent tuning, detection rule tuning, and Golden Set expansion
- [ ] The team can answer the "what got better?" question with specific before-and-after metrics — not anecdotes, not demos, not vendor claims

---

## Scoring

Count your checked boxes:

| Score | Assessment | Recommendation |
|-------|-----------|----------------|
| **25-28 checked** | Your SOC is AI-ready. Deploy with confidence and measure rigorously. | Start with the highest-readiness workflow. Expand based on results. |
| **18-24 checked** | Strong foundation with specific gaps. AI can work in limited scope. | Address unchecked items in Pillars 1-2 first. Pilot AI on your strongest workflow only. |
| **10-17 checked** | Significant gaps across multiple pillars. AI deployment is high-risk. | Invest in foundations: data quality, process documentation, detection-as-code, baselines. Defer AI. |
| **0-9 checked** | Your SOC is not ready for AI. Deploying now will waste resources and erode trust. | Focus entirely on Pillars 1 and 2. AI is a distraction at this maturity level. |

---

## What to Do Next

**If you scored 18+:** Proceed to the [use cases](../use-cases/) section of this repo to identify specific AI applications that match your readiness level.

**If you scored below 18:** Use the unchecked items as your priority list. Each item maps to a specific section in the pillar documents where you'll find detailed guidance on what "done" looks like. Work through them systematically — don't try to fix everything at once.

**Regardless of score:** Revisit this checklist quarterly. Your SOC, environment, and team change. Readiness is a moving target.

---

## References

- [Pillar 1: Data Foundations](01-data-foundations.md)
- [Pillar 2: Process Maturity](02-process-maturity.md)
- [Pillar 3: Human Element](03-human-element.md)
- [Pillar 4: Technology Stack](04-technology-stack.md)
- [Pillar 5: Metrics & Feedback](05-metrics-and-feedback.md)
- Anton Chuvakin, ["Simple to Ask: Is Your SOC AI Ready? Not Simple to Answer!"](https://medium.com/anton-on-security/simple-to-ask-is-your-soc-ai-ready-not-simple-to-answer) (October 2025)
- Anton Chuvakin, ["Beyond 'Is Your SOC AI Ready?' Plan the Journey!"](https://medium.com/anton-on-security/beyond-is-your-soc-ai-ready-plan-the-journey) (January 2026)
