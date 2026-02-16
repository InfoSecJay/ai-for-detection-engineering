# Use Case Index

This directory contains 22 documented use cases for applying AI and machine learning to detection engineering and SOC operations. Each use case is a detailed write-up covering what AI actually does, what the SIEM/SOAR should already handle, required data inputs, architecture patterns, and implementation guidance.

## Categorization

Use cases are organized into five categories based on what they operate on and who they serve:

| Category | Focus | Primary Consumer |
|----------|-------|-----------------|
| **Alert Analysis** | Operating on alert log data to measure detection health | Detection engineers |
| **Posture Assessment** | Measuring detection capability against ATT&CK | Detection engineering leads, security leadership |
| **AI-Assisted Triage** | Augmenting analyst triage decisions with AI reasoning | SOC analysts, triage teams |
| **Rule Content Engineering** | Applying AI to detection rule content itself | Detection engineers, content authors |
| **Strategic** | Program-level intelligence and optimization | SOC managers, CISOs, detection engineering leads |

## The Honest Boundary: SIEM/SOAR vs. AI

Every use case in this repo draws an explicit line between what deterministic tooling should handle and where AI genuinely adds value. This is not a philosophical position — it is a practical one. Applying an LLM to a problem that a lookup table, aggregation query, or SOAR playbook can solve makes the system slower, more expensive, and less reliable.

Each use case document includes:

- **Prerequisites (What Your SIEM/SOAR Should Already Handle)** — the deterministic foundations that must be in place before AI is applied.
- **Where AI Adds Value** — the specific reasoning, synthesis, or generation task that deterministic tooling cannot perform.

If your SIEM is not parsing logs correctly, your SOAR is not enriching alerts, or your detection rules lack MITRE mappings, fix those problems first. They are data engineering and tooling problems, not AI problems. See [prerequisites/](../prerequisites/) for the five pillars of an AI-ready SOC.

---

## Status Tracking

All 22 use cases with current development status. Each use case follows the standard [TEMPLATE.md](TEMPLATE.md).

### Alert Analysis

| # | Name | Category | What AI Does | Complexity | Status |
|---|------|----------|-------------|-----------|--------|
| 01 | [Detection Performance Analytics](alert-analysis/01-detection-performance-analytics.md) | Alert Analysis | Synthesizes per-rule metrics into prioritized narratives; identifies cross-rule patterns invisible to individual dashboards | Medium | Draft |
| 02 | [Entity Cardinality Noise Analysis](alert-analysis/02-entity-cardinality-noise-analysis.md) | Alert Analysis | Interprets entity concentration patterns in detection context; clusters near-identical observables by semantic similarity | Medium | Draft |
| 03 | [Automated Rule Tuning Recommendations](alert-analysis/03-automated-rule-tuning-recommendations.md) | Alert Analysis | Generates contextual tuning proposals with safety assessment and residual signal analysis | Medium | Draft |
| 04 | [Detection Drift Monitoring](alert-analysis/04-detection-drift-monitoring.md) | Alert Analysis | Diagnoses likely root cause of rule silence or behavioral drift by cross-referencing data source dependencies | Medium | Draft |
| 05 | [Temporal Pattern Detection](alert-analysis/05-temporal-pattern-detection.md) | Alert Analysis | Identifies complex temporal patterns (business-cycle, shifting schedules) and explains their operational context | Low-Medium | Draft |

### Posture Assessment

| # | Name | Category | What AI Does | Complexity | Status |
|---|------|----------|-------------|-----------|--------|
| 06 | [MITRE ATT&CK Posture Scoring](posture-assessment/06-mitre-attack-posture-scoring.md) | Posture Assessment | Generates health narratives per technique; assesses observable diversity across rules; produces executive posture summaries | High | Draft |
| 07 | [Threat-Informed Gap Prioritization](posture-assessment/07-threat-informed-gap-prioritization.md) | Posture Assessment | Synthesizes CTI reports into structured technique lists; risk-ranks gaps by environmental relevance and attack chain position | Medium-High | Draft |
| 08 | [Kill Chain Completeness Analysis](posture-assessment/08-kill-chain-completeness-analysis.md) | Posture Assessment | Assesses operational meaningfulness of detection at each attack stage; identifies where attackers would evade the detection chain | Medium | Draft |
| 09 | [Cross-Domain Detection Coverage](posture-assessment/09-cross-domain-detection-coverage.md) | Posture Assessment | Evaluates quality and complementarity of cross-domain coverage; identifies where adding a detection domain would provide most value | Medium | Draft |
| 10 | [Executive Posture Reporting](posture-assessment/10-executive-posture-reporting.md) | Posture Assessment | Transforms technical posture scores into leadership-consumable narratives with trend analysis and investment recommendations | Medium | Draft |

### AI-Assisted Triage

| # | Name | Category | What AI Does | Complexity | Status |
|---|------|----------|-------------|-----------|--------|
| 11 | [LLM Triage Verdicts](ai-assisted-triage/11-llm-triage-verdicts.md) | AI-Assisted Triage | Weighs ambiguous signals from enriched alert context; produces structured verdicts with cited reasoning | High | Draft |
| 12 | [Alert Cluster Narrative Synthesis](ai-assisted-triage/12-alert-cluster-narrative-synthesis.md) | AI-Assisted Triage | Generates coherent attack narratives from pre-correlated alert clusters; assesses malicious vs. benign behavior | Medium-High | Draft |
| 13 | [Natural Language Alert Query](ai-assisted-triage/13-natural-language-alert-query.md) | AI-Assisted Triage | Translates natural language questions to SIEM queries (text-to-KQL/ESQL); summarizes results in plain language | Medium | Draft |
| 14 | [Agentic Investigation Execution](ai-assisted-triage/14-agentic-investigation-execution.md) | AI-Assisted Triage | Executes dynamic investigations where next steps depend on findings; reasons about pivot decisions in real time | Very High | Draft |

### Rule Content Engineering

| # | Name | Category | What AI Does | Complexity | Status |
|---|------|----------|-------------|-----------|--------|
| 15 | [LLM Investigation Guide Generation](rule-content-engineering/15-llm-investigation-guide-generation.md) | Rule Content Engineering | Generates structured triage guides by reasoning about detection logic, expected artifacts, and decision points | Medium | Draft |
| 16 | [Observable Artifact Extraction](rule-content-engineering/16-observable-artifact-extraction.md) | Rule Content Engineering | Extracts and classifies observables from complex query logic; assesses specificity of each indicator | Low-Medium | Draft |
| 17 | [Rule Comparison & Gap Analysis](rule-content-engineering/17-rule-comparison-and-gap-analysis.md) | Rule Content Engineering | Semantic comparison of rules across formats and query languages; analyzes rules against source threat reports | Medium | Draft |
| 18 | [Rule Quality Assessment](rule-content-engineering/18-rule-quality-assessment.md) | Rule Content Engineering | Assesses semantic quality, MITRE mapping accuracy, and evasion gaps in detection logic | Medium | Draft |
| 19 | [Detection Rule Generation](rule-content-engineering/19-detection-rule-generation.md) | Rule Content Engineering | Generates candidate detection rules from threat intel, CVE advisories, or ATT&CK technique descriptions | Medium-High | Draft |

### Strategic

| # | Name | Category | What AI Does | Complexity | Status |
|---|------|----------|-------------|-----------|--------|
| 20 | [Analyst Workflow Optimization](strategic/20-analyst-workflow-optimization.md) | Strategic | Identifies investigation patterns across analysts; finds guide gaps; surfaces automation candidates from workflow data | Medium | Draft |
| 21 | [Threat Intelligence Synthesis](strategic/21-threat-intelligence-synthesis.md) | Strategic | Extracts TTPs from natural-language reports; maps to ATT&CK; compares against posture; generates actionable gap briefs with work orders | Medium | Draft |
| 22 | [Detection Program Health Reporting](strategic/22-detection-program-health-reporting.md) | Strategic | Synthesizes all quantitative program metrics into narrative health reports for leadership with trend analysis and investment recommendations | Medium | Draft |

---

## Template

All use cases follow the standard template: [TEMPLATE.md](TEMPLATE.md)

The template enforces the honest boundary between deterministic tooling and AI by requiring both a **Prerequisites** section (what the SIEM/SOAR handles) and a **Where AI Adds Value** section (what the LLM/ML component actually does). If a use case cannot clearly articulate the AI contribution separately from the deterministic foundation, it probably is not an AI use case.

---

## Prerequisites

Before working on any use case, ensure the foundational capabilities described in [prerequisites/](../prerequisites/) are in place:

1. **Data Foundations** — Parsed, normalized, enrichable alert data queryable at scale
2. **Process Maturity** — Codified investigation workflows, structured case management
3. **Human Element** — Leadership acceptance of probabilistic outcomes, redefined analyst roles
4. **Technology Stack** — Detection-as-code, API-driven tools, working SOAR automation
5. **Metrics & Feedback** — Baseline measurements, feedback loops, continuous tuning

Use cases in the **Alert Analysis** and **Posture Assessment** categories have the lightest prerequisites (primarily Pillars 1 and 4). **AI-Assisted Triage** use cases require all five pillars. **Strategic** use cases depend on outputs from multiple other use cases and require organizational maturity across all pillars.
