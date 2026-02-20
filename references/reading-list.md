# Reading List

Key industry resources for AI-assisted detection engineering and SOC operations. Organized by category with direct links where available.

---

## Foundational -- AI-Ready SOC

These two posts from Anton Chuvakin frame the prerequisites problem that this repo addresses: what does a SOC actually need to have in place before AI tools can deliver value?

| Resource | Description |
|---|---|
| **Anton Chuvakin, "Simple to Ask: Is Your SOC AI Ready? Not Simple to Answer!"** (October 2025) | Defines the question of SOC AI readiness and breaks down what "ready" actually means — data quality, process maturity, staffing, and tooling prerequisites. Foundational for the [prerequisites](../prerequisites/) section of this repo. [cloud.google.com/blog](https://cloud.google.com/blog/products/identity-security/is-your-soc-ai-ready) |
| **Anton Chuvakin, "Beyond 'Is Your SOC AI Ready?' Plan the Journey!"** (January 2026) | Follow-up that moves from assessment to planning. Provides a framework for sequencing AI adoption based on current maturity. Maps which AI use cases require which prerequisites. [cloud.google.com/blog](https://cloud.google.com/blog/products/identity-security/plan-your-soc-ai-journey) |

---

## Industry Reports & Analysis

| Resource | Description |
|---|---|
| **Gartner 2026 Security Operations Trends** | Annual analysis covering SOC technology adoption, AI/ML in security operations, and the shift toward agentic SOC concepts. Tracks market maturity of autonomous investigation tools. Analyst access required. |
| **OWASP Agentic AI Top 10 (2026)** | Top 10 security risks for agentic AI systems. Essential reading for understanding what can go wrong when deploying AI agents in SOC environments — prompt injection, excessive agency, insecure tool use, data poisoning, etc. [owasp.org/www-project-agentic-ai-top-10](https://owasp.org/www-project-agentic-ai-top-10/) |
| **NIST Cyber AI Profile** | Guidance on managing cybersecurity risks of AI systems. Covers governance, risk assessment, and operational considerations. Relevant for any organization deploying AI in their security pipeline. [nist.gov](https://www.nist.gov/) |
| **MITRE ATLAS (Adversarial Threat Landscape for AI Systems)** | Framework for understanding adversarial attacks against AI/ML systems. Important when AI becomes part of the detection and response pipeline — the AI itself becomes an attack surface. [atlas.mitre.org](https://atlas.mitre.org/) |

---

## Vendor Perspectives on Agentic SOC

These represent vendor viewpoints — read critically, but they contain useful architectural thinking.

| Resource | Description |
|---|---|
| **Prophet AI — Agentic SOC Architecture** | Describes the design of purpose-built SOC agents: how they decompose investigation tasks, maintain context, and produce structured outputs. Useful for understanding what an agentic investigation workflow looks like in practice. [prophet.security](https://www.prophet.security/) |
| **Splunk — AI-Augmented Security Operations** | Splunk's perspective on integrating AI into existing SOC workflows. Covers ML-driven detection, AI-assisted SPL generation, and the role of SOAR in AI-informed response. [splunk.com](https://www.splunk.com/) |
| **Sophos — Agentic AI for Endpoint Security** | Sophos's approach to using agentic AI for endpoint detection and response. Focuses on autonomous threat investigation at the endpoint level. [sophos.com](https://www.sophos.com/) |
| **Microsoft — Copilot for Security** | Microsoft's LLM-powered security assistant. Documentation covers natural language to KQL conversion, incident summarization, and guided investigation. Useful as a reference implementation of LLM-augmented SOC tooling. [microsoft.com/security/copilot](https://www.microsoft.com/en-us/security/business/ai-machine-learning/microsoft-copilot-security) |
| **Elastic — AI Assistant for Security** | Elastic's integrated AI assistant for detection engineering and investigation. Covers alert summarization, rule generation, and ES|QL query assistance. [elastic.co](https://www.elastic.co/security/ai) |

---

## Detection Engineering

| Resource | Description |
|---|---|
| **Elastic Detection Rules Documentation** | Documentation for Elastic's detection rule format, rule types (query, EQL, threshold, ML, new terms, ES\|QL), and the detection engine. Essential reference for building and understanding Elastic detection content. [elastic.co/guide/en/security](https://www.elastic.co/guide/en/security/current/detection-engine-overview.html) |
| **Sigma Specification and pySigma Documentation** | The Sigma rule specification defines the platform-agnostic detection format. pySigma documentation covers rule conversion, backend plugins, and processing pipelines. [sigmahq.io](https://sigmahq.io/) |
| **MITRE ATT&CK Framework** | The standard taxonomy for adversary behavior. Tactics, techniques, sub-techniques, procedures, software, and threat groups. Every detection rule in every platform maps back to this framework. [attack.mitre.org](https://attack.mitre.org/) |
| **MITRE ATT&CK Navigator** | Web tool for creating ATT&CK coverage layers. Used to visualize detection coverage, identify gaps, and compare coverage across rule sets. [mitre-attack.github.io/attack-navigator](https://mitre-attack.github.io/attack-navigator/) |
| **Elastic Common Schema (ECS)** | Field naming and normalization standard used by Elastic. Understanding ECS is necessary for writing detection rules and interpreting alert data in Elastic Security. [elastic.co/guide/en/ecs](https://www.elastic.co/guide/en/ecs/current/index.html) |
| **Splunk Common Information Model (CIM)** | Splunk's data normalization framework. Defines standard field names per data model (Authentication, Endpoint, Network Traffic, etc.). Required for writing portable SPL detections. [docs.splunk.com/Documentation/CIM](https://docs.splunk.com/Documentation/CIM/latest/User/Overview) |

---

## Alert Correlation & Risk-Based Alerting

Deep-dive references on correlation rule architecture, weighted risk scoring, and multi-signal detection patterns. See also [Alert Correlation Patterns](../concepts/alert-correlation-patterns.md) for the full survey.

| Resource | Description |
|---|---|
| **Splunk Guide to Risk-Based Alerting** | The definitive guide to Splunk's RBA architecture -- risk score formulas, risk modifiers, risk incident rules, and the two-layer (risk event + risk notable) design pattern. The reference implementation for weighted scoring models in detection engineering. [splunk.com/blog](https://www.splunk.com/en_us/blog/security/the-new-improved-splunk-guide-to-risk-based-alerting.html) |
| **Splunk RBA: How Risk Scores Work** | Technical documentation on risk score calculation, the `(impact * confidence) / 100` formula, risk modifiers, and risk incident rule configuration. [help.splunk.com](https://help.splunk.com/en/splunk-enterprise-security-7/risk-based-alerting/7.3/introduction/how-risk-scores-work-in-splunk-enterprise-security) |
| **Correlation-Based Detection Rules in Cybersecurity (Andrey Pautov)** | Practitioner analysis of correlation rule types -- from atomic to behavioral -- covering temporal windowing, sequential correlation, and the relationship between building blocks and correlation layers. [medium.com](https://medium.com/@1200km/correlation-based-detection-rules-in-cybersecurity-from-atomic-events-to-behavioral-insight-1b3df31597bb) |
| **Unraveling SIEM Correlation Techniques (Jack Naglieri / Panther)** | Comprehensive breakdown of SIEM correlation patterns: threshold, sequence, temporal, and statistical. Covers Panther's Python-based approach to correlation rule engineering. [panther.com/blog](https://panther.com/blog/unraveling-siem-correlation-techniques) |
| **Microsoft Sentinel Fusion Engine Documentation** | Technical reference for Sentinel's ML-based multi-stage attack detection. Covers how Fusion automatically correlates low-fidelity alerts into high-severity incidents. [learn.microsoft.com](https://learn.microsoft.com/en-us/azure/sentinel/fusion) |
| **Microsoft Sentinel UEBA Behaviors Layer** | Introduction to Sentinel's AI-based UEBA capability that provides normalized behavioral building blocks for detection rules and investigation. [techcommunity.microsoft.com](https://techcommunity.microsoft.com/blog/microsoftsentinelblog/turn-complexity-into-clarity-introducing-the-new-ueba-behaviors-layer-in-microso/4484493) |
| **Elastic ES\|QL New Features (2025)** | Coverage of LOOKUP JOIN (GA), Cross-Cluster Search, INLINE STATS, and resilience features in ES\|QL -- key capabilities for building correlation rules in Elastic. [elastic.co/search-labs](https://www.elastic.co/search-labs/blog/esql-elasticsearch-8-19-9-1) |
| **Elastic Security Detection Engineering Capabilities** | Overview of all rule types in Elastic Security (EQL sequences, threshold, ML, building blocks, ES\|QL) and how they combine for multi-layer detection. [elastic.co/blog](https://www.elastic.co/blog/elastic-security-detection-engineering) |
| **Anvilogic Correlated Threat Scenarios** | Anvilogic's approach to visual correlation rule building -- threading signals across kill chain stages on a drag-and-drop canvas, mapped to ATT&CK. [anvilogic.com](https://www.anvilogic.com/correlated-threat-scenarios) |
| **Panther pypanther Framework** | Panther's Python-based detection framework with class inheritance, programmatic overrides, and testable correlation rules using `MinMatchCount`. [panther.com/blog](https://panther.com/blog/introducing-pypanther-the-future-of-code-driven-detection-and-response) |
| **Anvilogic 2025 State of Detection Engineering Report** | Industry survey on detection engineering maturity, AI adoption (88% expect major AI integration within 3 years), and the state of correlation and coverage practices. [anvilogic.com/report](https://www.anvilogic.com/report/2025-state-of-detection-engineering) |
| **Elastic 2025 State of Detection Engineering** | Elastic's analysis of detection engineering trends -- DaC adoption, CI/CD validation, cross-integration correlation, and structured maturity models. [elastic.co/security-labs](https://www.elastic.co/security-labs/state-of-detection-engineering-at-elastic-2025) |
| **KillChainGraph: ML Framework for Predicting ATT&CK Techniques (2025)** | Academic research on phase-aware ML models that align ATT&CK techniques to kill chain phases, achieving 97-99% F1-scores for adversarial technique prediction. Relevant for predictive correlation rule design. [arxiv.org](https://arxiv.org/html/2508.18230v1) |

---

## Data Quality & SOC Process

| Resource | Description |
|---|---|
| **Anton Chuvakin's Blog (Google Cloud Security)** | Ongoing commentary on SOC operations, detection engineering, and AI readiness. Consistently the most grounded perspective on what actually matters for security operations. [cloud.google.com/blog](https://cloud.google.com/blog/products/identity-security/) |
| **Elastic Blog — Detection Engineering** | Technical posts on detection rule development, EQL query patterns, and detection-as-code practices. [elastic.co/blog](https://www.elastic.co/blog/category/security) |
| **Splunk Blog — Security** | Technical posts on SPL-based detections, analytic stories, and security content development. [splunk.com/blog](https://www.splunk.com/en_us/blog/security.html) |

---

## How to Use This List

- **Starting point**: Begin with the two Anton Chuvakin posts. They frame the entire problem space.
- **For prerequisites**: OWASP Agentic AI Top 10 and NIST Cyber AI Profile address risk management.
- **For detection engineering**: Sigma specification, Elastic detection rules docs, and ECS/CIM references are the operational foundations.
- **For alert correlation and risk-based alerting**: Start with the Splunk RBA Guide and Andrey Pautov's correlation rules post. Then review platform-specific documentation for your SIEM. The [Alert Correlation Patterns](../concepts/alert-correlation-patterns.md) concept document synthesizes cross-platform patterns.
- **For vendor context**: Read the vendor perspectives to understand what products claim to do, then compare against the prerequisites and data requirements documented in this repo.
- **For AI risk**: MITRE ATLAS covers threats to AI systems. OWASP Agentic AI Top 10 covers risks from AI agents.
