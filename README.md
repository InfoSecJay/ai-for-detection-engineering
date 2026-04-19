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
- [Where AI Fails](concepts/where-ai-fails.md) — the failure taxonomy and per-use-case mitigations once you've crossed the boundary

## Start Here for Implementation

The use cases below describe *what* the AI does. Before deploying any of them in production, you also need to decide *how* and *in what order*:

- [Deployment Roadmap](docs/deployment-roadmap.md) — phased adoption by SOC size, dependency DAG, pilot → production gates
- [Cost Models](docs/cost-models.md) — token economics, per-use-case spend at current pricing, ROI framing
- [Validation Harness](concepts/validation-harness.md) — golden sets, calibration measurement, regression gates
- [Adversarial AI Considerations](concepts/adversarial-ai-considerations.md) — prompt injection, evasion, feedback poisoning
- [Privacy and Data Handling](docs/privacy-and-data-handling.md) — what leaves your environment and how to control it
- [Governance Mapping](docs/governance-mapping.md) — the artifacts your CISO/Privacy/Audit team will ask for
- [Examples](examples/) — working prompts, golden sets, and eval scaffolding for selected use cases

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

**31 documented use cases** organized by category. Each links to a detailed write-up covering what AI actually does, required data inputs, architecture patterns, and implementation guidance.

The original 23 (UC-01 through UC-23) constitute the foundational catalog. Use cases UC-24 through UC-31 were added April 2026 based on the [Q1–Q2 2026 research review](docs/2026-q1q2-research-review.md), reflecting state-of-the-field as of that date.

### Alert Analysis

| # | Use Case | What AI Actually Does | Primary Data Input | Complexity |
|---|----------|----------------------|-------------------|------------|
| 01 | [Detection Performance Analytics](use-cases/alert-analysis/01-detection-performance-analytics.md) | Synthesizes metrics into prioritized narratives; identifies cross-rule patterns | SIEM alert logs | Medium |
| 02 | [Entity Cardinality Noise Analysis](use-cases/alert-analysis/02-entity-cardinality-noise-analysis.md) | Interprets entity patterns in detection context; clusters by semantic similarity | SIEM alert logs | Medium |
| 03 | [Automated Rule Tuning Recommendations](use-cases/alert-analysis/03-automated-rule-tuning-recommendations.md) | Generates contextual tuning proposals with safety assessment | SIEM alert logs, rule files | Medium |
| 04 | [Detection Drift Monitoring](use-cases/alert-analysis/04-detection-drift-monitoring.md) | Diagnoses likely cause of rule silence or behavioral changes | SIEM alert logs, rule files | Medium |
| 05 | [Temporal Pattern Detection](use-cases/alert-analysis/05-temporal-pattern-detection.md) | Identifies complex temporal patterns and explains their business context | SIEM alert logs | Low-Medium |
| 30 | [Self-Optimizing Closed-Loop Tuning](use-cases/alert-analysis/30-self-optimizing-tuning.md) | Closes the loop on UC-03: dispositions auto-generate, validate, deploy, monitor with rollback | Disposition stream, rule corpus, validation harness | Very High |

### Posture Assessment

| # | Use Case | What AI Actually Does | Primary Data Input | Complexity |
|---|----------|----------------------|-------------------|------------|
| 06 | [MITRE ATT&CK Posture Scoring](use-cases/posture-assessment/06-mitre-attack-posture-scoring.md) | Generates health narratives; assesses observable diversity; executive summaries | Alert logs, rule files | High |
| 07 | [Threat-Informed Gap Prioritization](use-cases/posture-assessment/07-threat-informed-gap-prioritization.md) | Synthesizes CTI reports into structured technique lists; risk-ranks gaps | Rule files, CTI reports | Medium-High |
| 08 | [Kill Chain Completeness Analysis](use-cases/posture-assessment/08-kill-chain-completeness-analysis.md) | Assesses operational meaningfulness of detection at each attack stage | Alert logs, rule files | Medium |
| 09 | [Cross-Domain Detection Coverage](use-cases/posture-assessment/09-cross-domain-detection-coverage.md) | Evaluates quality and complementarity of cross-domain coverage | Alert logs, rule files | Medium |
| 10 | [Executive Posture Reporting](use-cases/posture-assessment/10-executive-posture-reporting.md) | Transforms technical metrics into leadership-consumable narratives | Posture scores | Medium |
| 28 | [Detection Coverage Mapping for Compliance](use-cases/posture-assessment/28-compliance-detection-mapping.md) | Maps detection content to compliance frameworks (NIST, CSA AICM, ISO, PCI, EU AI Act) with cross-regime prioritization | Rule corpus, control libraries, signal quality scores | Medium-High |

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
| 23 | [Synthetic Detection Testing Data Generation](use-cases/rule-content-engineering/23-synthetic-detection-testing-data.md) | Generates diverse, schema-compliant synthetic log events for testing detection rule logic | Rule files, ATT&CK data, log schemas | Medium |
| 24 | [Cross-SIEM Rule Migration & Semantic Translation](use-cases/rule-content-engineering/24-cross-siem-rule-migration.md) | Bulk corpus migration via semantic dedup against target's prebuilt library + intent-aware translation | Source + target rule corpora, schema mappings | High |
| 25 | [AI Agent & MCP Activity Detection](use-cases/rule-content-engineering/25-ai-agent-mcp-detection.md) | Detection content for AI agents, MCP servers, A2A telemetry; OWASP Agentic Top 10 / ATLAS coverage | Agent telemetry, MCP logs, identity context | High |
| 26 | [Continuous Detection Validation (Atomic Test CI)](use-cases/rule-content-engineering/26-continuous-detection-validation.md) | Orchestrated execution of Atomic / Caldera / Stratus tests + diagnosis of failures + evasion variant generation | Rule corpus, test library, isolated test env | High |
| 27 | [AI-Driven Log Source Onboarding & Parser Generation](use-cases/rule-content-engineering/27-log-source-onboarding.md) | Generates ingest configs from vendor docs + samples; suggests schema mappings; monitors field-population drift | Vendor docs, sample logs, schema reference | Medium-High |
| 31 | [Detection Content Provenance & Supply Chain Integrity](use-cases/rule-content-engineering/31-detection-content-provenance.md) | Cryptographic signing, attribution chains, modification anomaly detection, AI-generation tracking | DaC repo, signing infra, AI-gen metadata | Medium-High |

### Strategic

| # | Use Case | What AI Actually Does | Primary Data Input | Complexity |
|---|----------|----------------------|-------------------|------------|
| 20 | [Analyst Workflow Optimization](use-cases/strategic/20-analyst-workflow-optimization.md) | Identifies investigation patterns and generates improvement proposals | Triage workflow data | Medium |
| 21 | [Threat Intelligence Synthesis](use-cases/strategic/21-threat-intelligence-synthesis.md) | Extracts TTPs from reports; compares against posture; generates actionable briefs | CTI reports, posture data | Medium |
| 22 | [Detection Program Health Reporting](use-cases/strategic/22-detection-program-health-reporting.md) | Synthesizes all metrics into narrative program health reports | All metrics | Medium |
| 29 | [SIEM Cost & Data Tiering Optimization](use-cases/strategic/29-siem-cost-data-tiering.md) | Per-source cost vs. coverage analysis; hot/warm/cold tier recommendations with detection-impact modeling | Cost data, ingest volume, dependency map | Medium |

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
| [Where AI Fails](concepts/where-ai-fails.md) | Failure taxonomy (hallucination, calibration drift, anchoring, prompt injection, data quality regression, cost blow-up, feedback poisoning, model drift) with per-use-case mitigations |
| [Adversarial AI Considerations](concepts/adversarial-ai-considerations.md) | Threat model and engineering controls for AI-augmented SOCs: prompt injection, evasion, tool abuse, feedback poisoning, threat-intel poisoning |
| [Validation Harness](concepts/validation-harness.md) | Specification for golden sets, eval runners, regression gates, and continuous production monitoring per use case |

### Practical Implementation

| Document | Description |
|----------|-------------|
| [Correlation Rule Framework](concepts/correlation-rule-framework.md) | Guide to designing a multi-tier ES\|QL correlation framework: entity-centric correlation (user + host), kill chain progression, identity-endpoint chains, lateral movement detection, risk score accumulation, and campaign detection — with production-ready ES\|QL example rules for each tier |
| [Cross-Rule Deduplication](correlation-rules/cross-rule-deduplication.md) | Spec for consolidating overlapping correlation-rule fires into single incidents — expected overlap patterns, tier-priority headline selection, consumption by UC-11/UC-12/UC-14, vendor implementations (Sentinel graph, Splunk RBA, Elastic Attack Discovery) |
| [Identity Resolution Pattern](correlation-rules/identity-resolution-pattern.md) | Reference design for the `lookup-identity-resolution` index that fixes silent false negatives in cross-domain rules (CORR-5E, CORR-1A, CORR-2B, CORR-3A) caused by mismatched user-name formats across domains. Foundational for [UC-25](use-cases/rule-content-engineering/25-ai-agent-mcp-detection.md) typed-entity treatment of agent identities. |

---

## Data Requirements

Specifications for the data structures referenced across use cases.

- [Alert Log Fields](data-requirements/alert-log-fields.md) — required and recommended fields for SIEM alert log data used as AI input
- [Rule File Formats](data-requirements/rule-file-formats.md) — supported detection rule formats (Sigma, SPL, KQL, YARA-L) and required metadata fields
- [Domain Entity Mapping](data-requirements/domain-entity-mapping.md) — schema for mapping raw observables to resolved entities across security domains

---

## Operations

Documentation that turns the use cases above from designs into operating systems:

| Document | Description |
|----------|-------------|
| [Deployment Roadmap](docs/deployment-roadmap.md) | Phased adoption by SOC size archetype (Small / Medium / Large), use-case dependency DAG, per-use-case pilot → production promotion criteria, rollback triggers, **build-vs-buy matrix** |
| [Cost Models](docs/cost-models.md) | Per-use-case token economics at current Claude / GPT pricing, total cost envelopes by SOC size, cost levers (caching, model tiering, on-prem breakeven), budget template |
| [Privacy and Data Handling](docs/privacy-and-data-handling.md) | What leaves your environment per use case, redaction patterns, vendor/region considerations, when to insource inference, per-use-case recommended posture |
| [Governance Mapping](docs/governance-mapping.md) | NIST IR 8596 Cyber AI Profile mapping for detection engineering, NIST 800-53 COSAiS overlays, CSA AICM, EU AI Act Article 15 (Aug 2026 enforcement), ISO 42001, the six artifact set per use case to satisfy audit |
| [2026 Q1–Q2 Research Review](docs/2026-q1q2-research-review.md) | Landscape review of vendor announcements, framework updates (MITRE ATT&CK v18, ATLAS v5.4.0, OWASP Agentic Top 10), and academic research (CTI-REALM, AIDR, FedGraph-AGI). Justifies the UC-24–UC-31 additions and informs build-vs-buy decisions. |

## Examples

Working artifacts for selected use cases — production-shaped prompts, golden eval sets, scoring logic.

- [Examples Index](examples/) — what's there and how to use it
- [TEMPLATE](examples/TEMPLATE/) — starting point for new use case examples
- [UC-15: Investigation Guide Generation](examples/uc-15-investigation-guides/) — recommended starting use case
- [UC-01: Detection Performance Analytics](examples/uc-01-detection-performance/) — two-pass batch analysis with prompt caching
- [UC-11: LLM Triage Verdicts](examples/uc-11-triage-verdicts/) — highest-stakes example with adversarial test gates and calibration measurement

The remaining use cases follow the same template — add as you build them.

## References

- [Tools & Projects](references/tools-and-projects.md) — open-source tools, libraries, and projects relevant to AI-assisted detection engineering
- [Vendor Landscape](references/vendor-landscape.md) — factual overview of vendor capabilities mapped to use case categories (no endorsements)
- [Reading List](references/reading-list.md) — papers, blog posts, and talks worth reading on AI/ML applied to security operations

---

## Out of Scope (Future Companion Repositories)

This repository is scoped to **AI for Detection Engineering**. The following adjacent AI-for-security categories are intentionally deferred and will be addressed in future companion repositories once this one is mature:

- **AI for Threat Intelligence** — IOC extraction from unstructured reports, actor profiling, infrastructure pivoting, victimology synthesis, dark-web monitoring
- **AI for Threat Hunting** — hypothesis generation, iterative hunt-loop agents, anomaly explanation, hunt-to-detection promotion
- **AI for Incident Response** — containment scoping, exec-comms drafting, post-mortem synthesis, BCP triggers
- **AI for Adversary Emulation** — scenario generation, atomic-test selection, detection-coverage validation, purple-team retros
- **AI for Malware & Forensics** — RE assistance, sandbox report synthesis, YARA/Snort/Suricata generation, memory artifact reasoning

UC-21 (Threat Intelligence Synthesis) and UC-23 (Synthetic Detection Testing Data) gesture toward those domains as they intersect with detection engineering. The full categories belong in their own repositories with their own template discipline.

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
