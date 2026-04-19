# Reading List

Key industry resources for AI-assisted detection engineering and SOC operations. **Refreshed April 2026.**

---

## Foundational — AI-Ready SOC

These two posts from Anton Chuvakin frame the prerequisites problem this repo addresses: what does a SOC actually need to have in place before AI tools can deliver value?

| Resource | Description |
|---|---|
| **Anton Chuvakin, "Simple to Ask: Is Your SOC AI Ready? Not Simple to Answer!"** (October 2025) | Defines the question of SOC AI readiness. Foundational for the [prerequisites](../prerequisites/) section. [cloud.google.com/blog](https://cloud.google.com/blog/products/identity-security/is-your-soc-ai-ready) |
| **Anton Chuvakin, "Beyond 'Is Your SOC AI Ready?' Plan the Journey!"** (January 2026) | Follow-up that moves from assessment to planning. Maps which AI use cases require which prerequisites. Defines the AI Error Budget concept. [medium.com/anton-on-security](https://medium.com/anton-on-security/beyond-is-your-soc-ai-ready-plan-the-journey-c9654a9ee175) |
| **Anton Chuvakin, "RSA 2026: Agentic Future, Analog Fundamentals"** (April 2026) | Q1–Q2 2026 retrospective from RSA 2026. Frames Detection Engineers as "AI Logic Editors" and analysts as "Supervisors." [medium.com/anton-on-security](https://medium.com/anton-on-security/rsa-2026-agentic-future-analog-fundamentals-the-paradox-of-why-the-old-guard-still-survives-bf93e81eaaa6) |

---

## 2026 Standards & Frameworks

| Resource | Description |
|---|---|
| **OWASP Top 10 for Agentic Applications 2026** (Dec 9, 2025) | Authoritative attack catalog for agentic AI. Adds risks LLM Top-10 doesn't cover: Goal Hijack (ASI01), Identity & Privilege Abuse (ASI03), Human-Agent Trust Exploitation (ASI09), Rogue Agents (ASI10). Introduces the Least-Agency principle. Essential for [UC-25](../use-cases/rule-content-engineering/25-ai-agent-mcp-detection.md). [genai.owasp.org](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) |
| **OWASP Top 10 for LLM Applications** (v2.0, 2025; v3 anticipated late 2026) | Foundational LLM-application security risks. [genai.owasp.org/llm-top-10](https://genai.owasp.org/llm-top-10/) |
| **NIST IR 8596 — Cybersecurity Framework Profile for AI** (Preliminary draft Dec 16, 2025) | Defines Secure / Defend / Thwart focus areas across all six CSF 2.0 functions. The "Defend" focus area carves out AI-enabled detection engineering as a controllable domain — first US standards body framing of detection-engineering AI as such. [csrc.nist.gov/pubs/ir/8596/iprd](https://csrc.nist.gov/pubs/ir/8596/iprd) |
| **NIST 800-53 Control Overlays for Securing AI Systems (COSAiS)** | Annotated outline released Jan 8, 2026; first overlay drafts due Q3 2026. Operationalizes 800-53 controls for AI systems. The missing artifact for compliance-driven detection mapping. [csrc.nist.gov/projects/cosais](https://csrc.nist.gov/projects/cosais) |
| **NIST AI Risk Management Framework (AI RMF 1.0)** | Voluntary, vendor-neutral. The most-cited reference for organizations operationalizing AI governance. Used in [governance-mapping.md](../docs/governance-mapping.md). |
| **MITRE ATT&CK v18** (Oct 2025; in active 2026 use) | Largest defensive overhaul: legacy *Detections* + *Data Sources* retired; replaced with **Detection Strategies** (what behavior) + **Analytics** (platform-specific how). Every existing rule library needs re-mapping. [attack.mitre.org/resources/updates/](https://attack.mitre.org/resources/updates/) |
| **MITRE ATLAS v5.4.0** (Feb 2026) | First 2026 update added agentic AI techniques: Tool Poisoning, Escape to Host, AML.T0096 AI Service API as C2; Zenity contributed AML.CS0042 SesameOp case study (OpenAI Assistants API as C2 backdoor). Essential for [UC-25](../use-cases/rule-content-engineering/25-ai-agent-mcp-detection.md). [atlas.mitre.org](https://atlas.mitre.org/) |
| **CSA AI Controls Matrix (AICM)** | 2026 CSO Award winner (Mar 10, 2026). Foundation for the upcoming STAR for AI certification. CSA also announced the CSAI Foundation (Mar 23, 2026) for "Securing the Agentic Control Plane." [cloudsecurityalliance.org](https://cloudsecurityalliance.org/artifacts/ai-controls-matrix) |
| **EU AI Act — Article 15 Enforcement Aug 2, 2026** | Annex III obligations for high-risk AI become enforceable. Article 15 (cybersecurity controls + automatic logging) is mandatory; penalties up to €15M / 3% global turnover. [Help Net Security on AI agent logging requirements](https://www.helpnetsecurity.com/2026/04/16/eu-ai-act-logging-requirements/) |
| **NSA AI Supply Chain Guidance** (March 18, 2026) | Calls for cryptographic signing across the model lifecycle, verified model registry, AI SBOM. Directly enables AI-rule-supply-chain detection content. Underpins [UC-31](../use-cases/rule-content-engineering/31-detection-content-provenance.md). [Coverage](https://www.logistics-concepts.com/news/digital-supply-chain-nsa-warns-ai-risks-executive-summary-action-plan/) |
| **OpenSSF Model Signing (OMS) Specification** | Cryptographic signing standard for AI models; pattern applies to detection-content signing. [openssf.org/blog/2025/06/25](https://openssf.org/blog/2025/06/25/an-introduction-to-the-openssf-model-signing-oms-specification/) |
| **ISO/IEC 42001:2023** | AI management system standard (analogous to ISO 27001 for InfoSec). CrowdStrike Charlotte AI 2026 ISO 42001 certification is a vendor leading indicator. [iso.org/standard/42001](https://www.iso.org/standard/42001) |
| **Gartner 2026 Cybersecurity Trends** (Feb 5, 2026) | AI Security Platforms as new category; Preemptive Cybersecurity forecast 50% of spend by 2030 (from <5% in 2024); Digital Provenance for AI-generated content. [gartner.com](https://www.gartner.com/en/newsroom/press-releases/2026-02-05-gartner-identifies-the-top-cybersecurity-trends-for-2026) |

---

## Industry Reports & Analysis (Q1–Q2 2026)

| Resource | Description |
|---|---|
| **Mandiant M-Trends 2026** (Apr 2026) | Annual report from Mandiant/Google Cloud based on 500K+ hours of incident response. Documented **PROMPTFLUX**, **PROMPTSTEAL**, and **SesameOp** — malware families that call LLM APIs mid-execution. The single most important threat-landscape paper for understanding AI-aware adversaries in 2026. [cloud.google.com/blog/topics/threat-intelligence/m-trends-2026](https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026) |
| **Microsoft Security Blog — CTI-REALM** (Mar 20, 2026) | Public benchmark for end-to-end agent-driven detection rule generation. Methodology reference for [UC-19](../use-cases/rule-content-engineering/19-detection-rule-generation.md), [UC-21](../use-cases/strategic/21-threat-intelligence-synthesis.md), and the [validation harness](../concepts/validation-harness.md). [microsoft.com](https://www.microsoft.com/en-us/security/blog/2026/03/20/cti-realm-a-new-benchmark-for-end-to-end-detection-rule-generation-with-ai-agents/) |
| **Microsoft Security Blog — The Agentic SOC** (Apr 9, 2026) | Microsoft's framing for the Sentinel-into-Defender consolidation and the agentic SOC architecture. [microsoft.com](https://www.microsoft.com/en-us/security/blog/2026/04/09/the-agentic-soc-rethinking-secops-for-the-next-decade/) |
| **Crogl 2026 State of SecOps Report** | Based on 649 practitioners. Reports 4,330 alerts/day median, only 37% investigated. The empirical case for SOC AI. [crogl.com/newsroom/state-of-secops-ai](https://www.crogl.com/newsroom/state-of-secops-ai) |
| **SANS State of Detection Engineering 2026** | Industry survey of detection-engineering practices, AI adoption, automation. [sans.org](https://www.sans.org/webcasts/state-detection-engineering-2026-what-data-reveals-accuracy-automation-ai-adoption) |
| **SANS 2026 Detection and Response Survey** | Companion survey on detection and response operations. [sans.org](https://www.sans.org/webcasts/sans-2026-detection-response-survey-report) |
| **Help Net Security — AI SOC Vendor Reality Check** (Mar 26, 2026) | "AI SOC vendors are selling a future that production deployments haven't reached yet." Counter-balance to vendor enthusiasm. [helpnetsecurity.com/2026/03/26](https://www.helpnetsecurity.com/2026/03/26/future-ai-soc-vendor-claims/) |
| **Florian Roth — Skepticism on LLMs Writing Detection Rules** (late 2025) | Founder of SigmaHQ argues that the easy cases produce false confidence and the hard cases produce subtly broken rules. Worth reading as a counterpoint to [UC-19](../use-cases/rule-content-engineering/19-detection-rule-generation.md) enthusiasm. [LinkedIn](https://www.linkedin.com/in/floroth/) |

---

## Academic / Research Papers (2026)

| Resource | Description |
|---|---|
| **CTI-REALM (Microsoft Research)** | End-to-end benchmark scoring AI agents on the full DE workflow. 37 CTI reports across Linux/AKS/Azure. Claude models led leaderboard (~0.624–0.685); cloud detections were dramatically harder than Linux. [microsoft.com/research/publication/cti-realm-benchmark](https://www.microsoft.com/en-us/research/publication/cti-realm-benchmark-to-evaluate-agent-performance-on-security-detection-rule-generation-capabilities/) |
| **RulePilot (arXiv 2511.12224)** | LLM agent that writes and converts detection rules across SPL and KQL from natural-language annotations. [arxiv.org](https://arxiv.org/html/2511.12224) |
| **CORTEX (arXiv 2510.00311)** | Multi-agent collaborative LLM architecture for high-stakes alert triage with a fine-grained SOC investigation dataset from production environments. [arxiv.org](https://arxiv.org/html/2510.00311v1) |
| **AIDR / Information-Dense Reasoning (arXiv 2512.08169)** | Achieves higher triage accuracy with **40.6% latency reduction** vs. Chain-of-Thought, with auditability properties for SOC use. Directly relevant to [UC-11](../use-cases/ai-assisted-triage/11-llm-triage-verdicts.md). [arxiv.org](https://arxiv.org/html/2512.08169) |
| **CyberSOCEval (arXiv 2509.20166)** | Open benchmark for malware analysis and threat-intel reasoning. [arxiv.org](https://arxiv.org/html/2509.20166v2) |
| **Decision-Aware Trust Signal Alignment for SOC Alert Triage (arXiv 2601.04486)** | Calibration / trust scoring methodology. Pairs with [UC-11](../use-cases/ai-assisted-triage/11-llm-triage-verdicts.md) and the [validation harness](../concepts/validation-harness.md). [arxiv.org](https://arxiv.org/abs/2601.04486) |
| **FedGraph-AGI (arXiv 2602.16109, Feb 2026)** | Federated graph + AGI reasoning for cross-border insider threat with differential privacy, homomorphic encryption, and secure MPC. The clearest published architecture for federated detection analytics. [arxiv.org](https://arxiv.org/abs/2602.16109) |
| **LanG (arXiv 2604.05440)** | Governance-aware agentic SOC platform; first paper explicitly framing SOC governance as a benchmarking dimension. |
| **KillChainGraph: ML Framework for Predicting ATT&CK Techniques (2025)** | Phase-aware ML models that align ATT&CK techniques to kill chain phases. [arxiv.org](https://arxiv.org/html/2508.18230v1) |

---

## Vendor Perspectives on Agentic SOC

These represent vendor viewpoints — read critically, but they contain useful architectural thinking.

| Resource | Description |
|---|---|
| **Microsoft Sentinel — Agentic SOC Era** | Microsoft's framing of Sentinel MCP and the agentic SOC architecture. [techcommunity.microsoft.com](https://techcommunity.microsoft.com/blog/microsoftsentinelblog/the-agentic-soc-era-how-sentinel-mcp-enables-autonomous-security-reasoning/4491003) |
| **Microsoft Defender — Security Copilot in Defender** | Microsoft's positioning on assistive vs. autonomous AI. [techcommunity.microsoft.com](https://techcommunity.microsoft.com/blog/microsoftthreatprotectionblog/security-copilot-in-defender-empowering-the-soc-with-assistive-and-autonomous-ai/4503047) |
| **Palo Alto Cortex — The SOC Is Now Agentic** (Feb 2026) | Cortex AgentiX positioning. [paloaltonetworks.com/blog](https://www.paloaltonetworks.com/blog/2026/02/soc-agentic-next-evolution-cortex/) |
| **Splunk — From Reactive to Agentic with Enterprise Security at RSAC 2026** | Splunk's RSAC 2026 messaging on Detection Studio and the agent fleet. [splunk.com/blog](https://www.splunk.com/en_us/blog/security/from-reactive-to-agentic-with-enterprise-security-at-rsac-2026.html) |
| **Elastic Security Labs — Why 2026 is the Year for Agentic AI SOC** | Elastic's perspective on 2026 SOC AI adoption and Attack Discovery / agentic ES\|QL. [elastic.co/security-labs](https://www.elastic.co/security-labs/why-2026-is-the-year-to-upgrade-to-an-agentic-ai-soc) |
| **CrowdStrike — Charlotte AI AgentWorks Press Release** | RSA 2026 launch of the AgentWorks ecosystem. [crowdstrike.com](https://www.crowdstrike.com/en-us/press-releases/crowdstrike-launches-charlotte-ai-agentworks-ecosystem-for-building-secure-agents/) |
| **Prophet Security — RSA 2026 Recap** | "What RSA 2026 confirmed: the agentic SOC is here." [prophetsecurity.ai/blog](https://www.prophetsecurity.ai/blog/what-rsa-2026-confirmed-the-agentic-soc-is-here) |
| **Detection at Scale — The AI-Powered Detection Engineer (Naglieri)** | Practitioner take on the role evolution. [detectionatscale.com](https://www.detectionatscale.com/p/the-ai-powered-detection-engineer) |
| **Detect FYI — Agentic Detection Creation: Sigma to Splunk** | Hands-on community walkthrough. [detect.fyi](https://detect.fyi/agentic-detection-creation-from-sigma-to-splunk-rules-or-any-platform-4697e13d9ee3) |

---

## Detection Engineering

| Resource | Description |
|---|---|
| **Elastic Detection Rules Documentation** | Documentation for Elastic's detection rule format and detection engine. [elastic.co/guide/en/security](https://www.elastic.co/guide/en/security/current/detection-engine-overview.html) |
| **Sigma Specification and pySigma Documentation** | The Sigma rule specification and pySigma's conversion framework. [sigmahq.io](https://sigmahq.io/) |
| **MITRE ATT&CK Framework** | The standard taxonomy for adversary behavior. [attack.mitre.org](https://attack.mitre.org/) |
| **Elastic Common Schema (ECS)** | Field naming and normalization standard used by Elastic. [elastic.co/guide/en/ecs](https://www.elastic.co/guide/en/ecs/current/index.html) |
| **Splunk Common Information Model (CIM)** | Splunk's data normalization framework. [docs.splunk.com/Documentation/CIM](https://docs.splunk.com/Documentation/CIM/latest/User/Overview) |
| **Microsoft ASIM** | Sentinel's normalization schema. [learn.microsoft.com](https://learn.microsoft.com/en-us/azure/sentinel/normalization) |

---

## Alert Correlation & Risk-Based Alerting

| Resource | Description |
|---|---|
| **Splunk Guide to Risk-Based Alerting** | The definitive guide to Splunk's RBA architecture. [splunk.com/blog](https://www.splunk.com/en_us/blog/security/the-new-improved-splunk-guide-to-risk-based-alerting.html) |
| **Splunk RBA: How Risk Scores Work** | Technical documentation on risk score calculation. [help.splunk.com](https://help.splunk.com/en/splunk-enterprise-security-7/risk-based-alerting/7.3/introduction/how-risk-scores-work-in-splunk-enterprise-security) |
| **Correlation-Based Detection Rules in Cybersecurity (Andrey Pautov)** | Practitioner analysis of correlation rule types — atomic to behavioral. [medium.com](https://medium.com/@1200km/correlation-based-detection-rules-in-cybersecurity-from-atomic-events-to-behavioral-insight-1b3df31597bb) |
| **Unraveling SIEM Correlation Techniques (Jack Naglieri / Panther)** | Comprehensive breakdown of SIEM correlation patterns. [panther.com/blog](https://panther.com/blog/unraveling-siem-correlation-techniques) |
| **Microsoft Sentinel Fusion Engine Documentation** | Technical reference for Sentinel's ML-based multi-stage attack detection. [learn.microsoft.com](https://learn.microsoft.com/en-us/azure/sentinel/fusion) |
| **Elastic ES\|QL New Features** | LOOKUP JOIN (GA), Cross-Cluster Search, INLINE STATS for correlation rules. [elastic.co/search-labs](https://www.elastic.co/search-labs/blog/esql-elasticsearch-8-19-9-1) |
| **Anvilogic Correlated Threat Scenarios** | Visual correlation rule building threading signals across kill chain stages. [anvilogic.com](https://www.anvilogic.com/correlated-threat-scenarios) |
| **Panther pypanther Framework** | Python-based detection framework with class inheritance and `MinMatchCount`. [panther.com/blog](https://panther.com/blog/introducing-pypanther-the-future-of-code-driven-detection-and-response) |
| **Anvilogic 2025 State of Detection Engineering Report** | Industry survey on DE maturity and AI adoption. [anvilogic.com/report](https://www.anvilogic.com/report/2025-state-of-detection-engineering) |
| **Elastic 2025 State of Detection Engineering** | DaC adoption, CI/CD validation, cross-integration correlation. [elastic.co/security-labs](https://www.elastic.co/security-labs/state-of-detection-engineering-at-elastic-2025) |

---

## Data Quality & SOC Process

| Resource | Description |
|---|---|
| **Anton Chuvakin's Blog (Google Cloud Security)** | Ongoing commentary on SOC operations and AI readiness. The most grounded perspective on what matters. [medium.com/anton-on-security](https://medium.com/anton-on-security/) |
| **Elastic Blog — Detection Engineering** | Technical posts on detection rule development and DaC. [elastic.co/blog](https://www.elastic.co/blog/category/security) |
| **Splunk Blog — Security** | Technical posts on SPL-based detections and security content. [splunk.com/blog](https://www.splunk.com/en_us/blog/security.html) |
| **Microsoft Security Blog** | Defender and Sentinel posts; primary source for Microsoft's AI-in-SOC direction. [microsoft.com/security/blog](https://www.microsoft.com/en-us/security/blog/) |
| **Google Cloud Security Blog (Chronicle, Mandiant)** | Chronicle / SecOps posts and Mandiant threat intelligence. [cloud.google.com/blog](https://cloud.google.com/blog/products/identity-security/) |

---

## Conferences & Events

| Event | Notes |
|---|---|
| **RSA Conference 2026** (Mar–Apr 2026) | Largest single source of 2026 AI SOC product announcements. |
| **DEATHCon 2026** | Detection Engineering and Threat Hunting Conference. Practitioner-focused. [deathcon.io](https://deathcon.io/) |
| **SANS SEC598 — AI and Security Automation for Red, Blue, Purple Teams** | Detection-engineering pedagogy for continuous validation. Anchor reference for [UC-26](../use-cases/rule-content-engineering/26-continuous-detection-validation.md). [sans.org](https://www.sans.org/cyber-security-courses/ai-security-automation) |
| **Black Hat / DEF CON 2026** | Standard tracks; check schedules for AI-focused content. |
| **FIRST Conference 2026** | Annual conference of the Forum of Incident Response and Security Teams. |
| **BSides events** | Local practitioner gatherings; often the best signal on what real teams are actually doing. |

---

## How to Use This List

- **Starting point**: Begin with the two Anton Chuvakin posts. They frame the entire problem space.
- **For prerequisites**: OWASP Top 10 + NIST AI RMF + NIST IR 8596 address risk and governance.
- **For detection engineering**: Sigma specification, Elastic detection rules docs, ECS/CIM/ASIM references are the operational foundations.
- **For alert correlation and risk-based alerting**: Start with the Splunk RBA Guide, then [Alert Correlation Patterns](../concepts/alert-correlation-patterns.md) for the cross-platform synthesis.
- **For vendor context**: Read the vendor perspectives critically; compare against the prerequisites and data requirements documented in this repo.
- **For AI risk and adversarial AI**: MITRE ATLAS, OWASP Agentic Top 10, Mandiant M-Trends 2026 (PROMPTFLUX/PROMPTSTEAL), and [adversarial-ai-considerations.md](../concepts/adversarial-ai-considerations.md).
- **For research methodology**: CTI-REALM (Microsoft) and CyberSOCEval are the public benchmarks; AIDR and Decision-Aware Trust papers cover calibration; CORTEX covers multi-agent triage.
- **For governance**: NIST IR 8596, NIST 800-53 COSAiS, CSA AICM, EU AI Act Article 15, ISO 42001, NSA AI Supply Chain Guidance.
