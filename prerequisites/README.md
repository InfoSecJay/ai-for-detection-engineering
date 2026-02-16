# Prerequisites: The Five Pillars of an AI-Ready SOC

## Why This Section Exists

Before you deploy an AI agent to triage alerts, draft detection rules, or summarize incidents, you need to answer a harder question: **Is your SOC ready for AI at all?**

AI use cases in this repo operate on structured data from your SIEM, structured detection rule files, and well-defined SOC processes. But data and rules alone aren't enough. Anton Chuvakin's AI-Ready SOC framework identifies five pillars that must be in place before AI delivers value in security operations:

1. **Data Foundations** — Security context and telemetry that machines can query at scale
2. **Process Maturity** — Codified, machine-intelligible workflows — not tribal knowledge
3. **Human Element** — Culture, roles, and leadership that accept probabilistic outcomes
4. **Technology Stack** — Modern, interoperable, API-driven tools with detection-as-code
5. **Metrics & Feedback Loops** — Baselines, KPIs, and continuous tuning mechanisms

If your SOC is weak on any of these pillars, AI will underperform or fail outright. Fix the foundations first.

---

## What AI Is Not

This repo takes a specific position: **AI should only be applied where deterministic tooling cannot do the job.**

The following are SIEM, SOAR, and data engineering problems — not AI problems:

| Task | Correct Tool | Why Not AI |
|------|-------------|------------|
| Field parsing and log normalization | SIEM ingest pipelines (Logstash, SPL props/transforms, KQL parsers) | Deterministic regex/grok patterns are faster, cheaper, and 100% reliable |
| Log enrichment (asset lookups, geo-IP, threat intel matching) | SOAR playbooks, SIEM lookup tables, enrichment pipelines | API calls return exact answers; LLMs would hallucinate them |
| Alert correlation by shared fields | SIEM correlation rules (EQL sequences, Splunk correlations, KQL joins) | Pattern matching on structured fields is what query engines are built for |
| Asset and identity lookups | CMDB/AD API calls via SOAR | A lookup table gives you the right answer every time |
| Rule format conversion (Sigma to native) | Sigma CLI, deterministic transpilers | Syntax translation has known grammars; LLMs introduce subtle errors |

If you are reaching for an LLM to do any of the above, you have a tooling gap, not an AI gap. Close the tooling gap first.

---

## The Five Pillars — Section Index

| Pillar | Document | Core Question |
|--------|----------|---------------|
| 1. Data Foundations | [01-data-foundations.md](01-data-foundations.md) | Can machines query your security data reliably at scale? |
| 2. Process Maturity | [02-process-maturity.md](02-process-maturity.md) | Are your SOC workflows codified and machine-intelligible? |
| 3. Human Element | [03-human-element.md](03-human-element.md) | Will your people and leadership accept probabilistic outcomes? |
| 4. Technology Stack | [04-technology-stack.md](04-technology-stack.md) | Are your tools API-driven, interoperable, and detection-as-code native? |
| 5. Metrics & Feedback | [05-metrics-and-feedback.md](05-metrics-and-feedback.md) | Can you measure what got better after adding AI? |

After working through the pillars, use the [AI-Ready SOC Readiness Checklist](readiness-checklist.md) to score your organization.

---

## How to Use This Section

**If you are starting from scratch:** Read each pillar document in order. Each one ends with self-assessment questions. Be honest — nobody is watching. If you score poorly on Pillars 1 and 2, stop and fix those before touching AI.

**If you think you are ready:** Jump to the [Readiness Checklist](readiness-checklist.md) and work through it with your team. Any unchecked box is a risk to your AI deployment.

**If you are already running AI agents:** Use the pillar documents to diagnose why things aren't working as expected. In our experience, most failures trace back to Pillar 1 (bad data) or Pillar 2 (undefined processes).

---

## The Perspective Behind This Repo

This repo is written from the perspective of a lead detection engineer managing 4,000+ detection rules across 50+ data source domains. That scale changes what matters:

- A single misconfigured log source can silently break hundreds of rules
- "Tribal knowledge" about how to triage a specific alert type doesn't survive team turnover
- Detection-as-code isn't a nice-to-have — it's the only way to maintain thousands of rules without drowning
- AI that works on 10 demo rules may collapse at 4,000 rules if your data foundations are weak

The advice here is vendor-agnostic but operationally specific. We reference Elastic, Splunk, and Microsoft Sentinel because those are the platforms most detection teams run. The principles apply regardless of your stack.

---

## Credits and References

The Five Pillars framework is adapted from Anton Chuvakin's work on AI-ready SOCs:

- Anton Chuvakin, ["Simple to Ask: Is Your SOC AI Ready? Not Simple to Answer!"](https://medium.com/anton-on-security/simple-to-ask-is-your-soc-ai-ready-not-simple-to-answer-5dc29e1e tried) (October 2025) — Introduces the five pillars and the core argument that SOC readiness is a prerequisite for AI effectiveness.
- Anton Chuvakin, ["Beyond 'Is Your SOC AI Ready?' Plan the Journey!"](https://medium.com/anton-on-security/beyond-is-your-soc-ai-ready-plan-the-journey) (January 2026) — Extends the framework with practical planning guidance, maturity stages, and a roadmap for building toward AI readiness.

We have adapted, extended, and in some cases reframed Chuvakin's pillars to reflect the specific concerns of detection engineering at scale. Any errors or strong opinions are ours, not his.
