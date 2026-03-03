# AI for Detection Engineering

A curated, practitioner-maintained reference of AI and machine learning use cases for detection engineering and SOC operations.

---

## Why This Exists

The AI + cybersecurity space is flooded with vendor marketing. Most "AI for SOC" content is product positioning dressed up as thought leadership, and it rarely answers the questions practitioners actually have: *What does this do? What data does it need? How hard is it to build? Is AI even the right tool here?*

This repo is a practical, detection-engineer-authored reference that catalogs actual use cases with enough detail to evaluate feasibility and start building. No vendor alignment. No hype. Just structured, honest documentation of where AI and ML add real value to detection engineering workflows.

---

## The Honest Boundary

Many things marketed as "AI for SOC" are actually SIEM correlation, SOAR automation, and data engineering problems. Slapping an LLM on a workflow that needs a lookup table or a threshold doesn't make it intelligent — it makes it slow and expensive.

This repo draws a hard line between what should be done deterministically and where AI genuinely adds value. Before diving into use cases, read:

- [Prerequisites](prerequisites/) — foundational capabilities that must exist before AI adds value
- [Where AI Fits (And Doesn't)](concepts/where-ai-fits-and-doesnt.md) — the decision framework for deterministic vs. AI approaches

---

## Prerequisites

> **If these aren't in place, start here before looking at AI use cases.**

AI use cases in detection engineering depend on mature foundational capabilities. The [prerequisites](prerequisites/) section covers five pillars that must be operational first:

1. **Structured Alert Data** — normalized, queryable alert logs with consistent field schemas
2. **Detection-as-Code** — version-controlled rule files with metadata (MITRE tags, severity, descriptions)
3. **Entity Resolution** — reliable mapping of observables to business entities (users, hosts, services)
4. **Baseline Metrics** — established true/false positive rates, alert volumes, and triage timing
5. **Automation Foundation** — working SOAR or scripted enrichment pipelines for deterministic tasks

---

## Use Case Index

22 documented use cases organized by category. Each links to a detailed write-up covering what AI actually does, required data inputs, architecture patterns, and implementation guidance.

### Alert Analysis

| # | Use Case | What AI Actually Does | Primary Data Input | Complexity |
|---|----------|----------------------|-------------------|------------|
| 01 | [Detection Performance Analytics](use-cases/alert-analysis/01-detection-performance-analytics.md) | Synthesizes metrics into prioritized narratives; identifies cross-rule patterns | SIEM alert logs | Medium |
| 02 | [Entity Cardinality Noise Analysis](use-cases/alert-analysis/02-entity-cardinality-noise-analysis.md) | Interprets entity patterns in detection context; clusters by semantic similarity | SIEM alert logs | Medium |
| 03 | [Automated Rule Tuning Recommendations](use-cases/alert-analysis/03-automated-rule-tuning-recommendations.md) | Generates contextual tuning proposals with safety assessment | SIEM alert logs, rule files | Medium |
| 04 | [Detection Drift Monitoring](use-cases/alert-analysis/04-detection-drift-monitoring.md) | Diagnoses likely cause of rule silence or behavioral changes | SIEM alert logs, rule files | Medium |
| 05 | [Temporal Pattern Detection](use-cases/alert-analysis/05-temporal-pattern-detection.md) | Identifies complex temporal patterns and explains their business context | SIEM alert logs | Low-Medium |

### Posture Assessment

| # | Use Case | What AI Actually Does | Primary Data Input | Complexity |
|---|----------|----------------------|-------------------|------------|
| 06 | [MITRE ATT&CK Posture Scoring](use-cases/posture-assessment/06-mitre-attack-posture-scoring.md) | Generates health narratives; assesses observable diversity; executive summaries | Alert logs, rule files | High |
| 07 | [Threat-Informed Gap Prioritization](use-cases/posture-assessment/07-threat-informed-gap-prioritization.md) | Synthesizes CTI reports into structured technique lists; risk-ranks gaps | Rule files, CTI reports | Medium-High |
| 08 | [Kill Chain Completeness Analysis](use-cases/posture-assessment/08-kill-chain-completeness-analysis.md) | Assesses operational meaningfulness of detection at each attack stage | Alert logs, rule files | Medium |
| 09 | [Cross-Domain Detection Coverage](use-cases/posture-assessment/09-cross-domain-detection-coverage.md) | Evaluates quality and complementarity of cross-domain coverage | Alert logs, rule files | Medium |
| 10 | [Executive Posture Reporting](use-cases/posture-assessment/10-executive-posture-reporting.md) | Transforms technical metrics into leadership-consumable narratives | Posture scores | Medium |

### AI-Assisted Triage

| # | Use Case | What AI Actually Does | Primary Data Input | Complexity |
|---|----------|----------------------|-------------------|------------|
| 11 | [LLM Triage Verdicts](use-cases/ai-assisted-triage/11-llm-triage-verdicts.md) | Weighs ambiguous signals; produces structured verdicts with reasoning | Enriched alerts | High |
| 12 | [Alert Cluster Narrative Synthesis](use-cases/ai-assisted-triage/12-alert-cluster-narrative-synthesis.md) | Generates coherent attack narratives from pre-correlated alert clusters | Correlated alerts | Medium-High |
| 13 | [Natural Language Alert Query](use-cases/ai-assisted-triage/13-natural-language-alert-query.md) | Translates natural language to SIEM queries; summarizes results | Alert indices | Medium |
| 14 | [Agentic Investigation Execution](use-cases/ai-assisted-triage/14-agentic-investigation-execution.md) | Dynamic investigation with reasoning-driven pivot decisions | Multiple APIs | Very High |

### Rule Content Engineering

| # | Use Case | What AI Actually Does | Primary Data Input | Complexity |
|---|----------|----------------------|-------------------|------------|
| 15 | [LLM Investigation Guide Generation](use-cases/rule-content-engineering/15-llm-investigation-guide-generation.md) | Generates structured triage guides by reasoning about detection logic | Rule files | Medium |
| 16 | [Observable Artifact Extraction](use-cases/rule-content-engineering/16-observable-artifact-extraction.md) | Extracts and classifies observables from complex query logic | Rule files | Low-Medium |
| 17 | [Rule Comparison & Gap Analysis](use-cases/rule-content-engineering/17-rule-comparison-and-gap-analysis.md) | Semantic comparison of rules across formats and query languages | Rule files, CTI reports | Medium |
| 18 | [Rule Quality Assessment](use-cases/rule-content-engineering/18-rule-quality-assessment.md) | Assesses semantic quality, MITRE accuracy, and evasion gaps | Rule files | Medium |
| 19 | [Detection Rule Generation](use-cases/rule-content-engineering/19-detection-rule-generation.md) | Generates candidate detection rules from threat intel or technique descriptions | CTI reports, ATT&CK | Medium-High |

### Strategic

| # | Use Case | What AI Actually Does | Primary Data Input | Complexity |
|---|----------|----------------------|-------------------|------------|
| 20 | [Analyst Workflow Optimization](use-cases/strategic/20-analyst-workflow-optimization.md) | Identifies investigation patterns and generates improvement proposals | Triage workflow data | Medium |
| 21 | [Threat Intelligence Synthesis](use-cases/strategic/21-threat-intelligence-synthesis.md) | Extracts TTPs from reports; compares against posture; generates actionable briefs | CTI reports, posture data | Medium |
| 22 | [Detection Program Health Reporting](use-cases/strategic/22-detection-program-health-reporting.md) | Synthesizes all metrics into narrative program health reports | All metrics | Medium |

---

## Foundational Concepts

Shared frameworks referenced across multiple use cases.

| Concept | Description |
|---------|-------------|
| [Domain-Aware Entity Framework](concepts/domain-aware-entity-framework.md) | Structured approach to entity resolution that maps raw observables to business-context entities across identity, network, endpoint, and cloud domains |
| [Signal Quality Scoring](concepts/signal-quality-scoring.md) | Quantitative scoring model for evaluating the analytical value of individual alert signals based on fidelity, specificity, and enrichment completeness |
| [Detection Confidence Scoring](concepts/detection-confidence-scoring.md) | Framework for assigning and maintaining confidence scores on detection rules based on testing depth, tuning maturity, and real-world validation |
| [Entity Cardinality as FP Proxy](concepts/entity-cardinality-as-fp-proxy.md) | Using the ratio of unique entities triggering a rule as a lightweight, pre-triage indicator of false positive rate |
| [Where AI Fits (And Doesn't)](concepts/where-ai-fits-and-doesnt.md) | Decision framework for distinguishing deterministic automation problems from genuine AI/ML opportunities in detection workflows |
| [Alert Correlation Patterns](concepts/alert-correlation-patterns.md) | Industry survey of alert correlation architectures (entity-centric, kill-chain-centric), weighted scoring models (Splunk RBA, Elastic Entity Risk), temporal windowing, UEBA integration, and building block rule patterns across major platforms |
| [Agentic SOC Architecture](concepts/agentic-soc-architecture.md) | Reference architecture for multi-step, tool-using AI agents that execute investigation workflows with human-in-the-loop controls |

### Practical Implementation

| Document | Description |
|----------|-------------|
| [Correlation Rule Framework](concepts/correlation-rule-framework.md) | Guide to designing a multi-tier ES\|QL correlation framework: entity-centric correlation (user + host), kill chain progression, identity-endpoint chains, lateral movement detection, risk score accumulation, and campaign detection — with production-ready ES\|QL example rules for each tier |

---

## Data Requirements

Specifications for the data structures referenced across use cases.

- [Alert Log Fields](data-requirements/alert-log-fields.md) — required and recommended fields for SIEM alert log data used as AI input
- [Rule File Formats](data-requirements/rule-file-formats.md) — supported detection rule formats (Sigma, SPL, KQL, YARA-L) and required metadata fields
- [Domain Entity Mapping](data-requirements/domain-entity-mapping.md) — schema for mapping raw observables to resolved entities across security domains

---

## References

- [Tools & Projects](references/tools-and-projects.md) — open-source tools, libraries, and projects relevant to AI-assisted detection engineering
- [Vendor Landscape](references/vendor-landscape.md) — factual overview of vendor capabilities mapped to use case categories (no endorsements)
- [Reading List](references/reading-list.md) — papers, blog posts, and talks worth reading on AI/ML applied to security operations

---

## Who This Is For

- **Detection engineers** building or evaluating AI-assisted detection workflows
- **SOC managers** assessing where AI can realistically improve analyst efficiency and detection quality
- **Security architects** designing platforms that integrate AI capabilities into security operations
- **DevSecOps / SOAR engineers** implementing the automation and data pipelines that AI use cases depend on

---

## Author

**Jay Tymchuk**

- GitHub: [InfoSecJay](https://github.com/InfoSecJay)
- LinkedIn: [jay-tymchuk](https://www.linkedin.com/in/jay-tymchuk/)

---

## License

This project is licensed under the [MIT License](LICENSE).
