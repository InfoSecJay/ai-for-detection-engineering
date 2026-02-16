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
- **For vendor context**: Read the vendor perspectives to understand what products claim to do, then compare against the prerequisites and data requirements documented in this repo.
- **For AI risk**: MITRE ATLAS covers threats to AI systems. OWASP Agentic AI Top 10 covers risks from AI agents.
