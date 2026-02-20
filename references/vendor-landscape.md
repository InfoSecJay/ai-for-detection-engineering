# Vendor Landscape

Commercial products and platforms relevant to AI-assisted detection engineering and SOC operations. Inclusion is not endorsement. This page exists to map the landscape, not recommend products.

---

## Agentic SOC Platforms

Startups and products building autonomous or semi-autonomous SOC agent systems that triage, investigate, or respond to alerts without continuous human input.

| Vendor | Approach |
|---|---|
| **Prophet AI** | Purpose-built agentic SOC platform. AI agents perform end-to-end alert triage: contextual enrichment, investigation, determination, and response recommendations. Designed to handle Tier-1 workload autonomously. |
| **Exaforce** | AI-powered SOC analyst agents (Exo Analysts) that investigate alerts, correlate events, and produce analyst-ready reports. Positions agents as virtual SOC team members. |
| **Dropzone AI** | Autonomous SOC analyst that investigates every alert. Pre-trained on SOC investigation procedures. Produces structured investigation reports with verdicts and evidence. |
| **Qevlar AI** | Agentic AI for SOC investigation. Automates the investigation workflow from alert to decision, focusing on reducing mean time to investigate. |
| **Intezer** | AI-powered alert triage and investigation. Combines code analysis heritage with SOC automation. Auto-triages alerts and provides investigation summaries. |
| **D3 Morpheus** | AI-augmented SOAR platform with agentic investigation capabilities. Combines playbook automation with LLM-driven analysis for alert triage. |
| **Stellar Cyber** | Open XDR platform with AI-driven detection and response. Uses ML for alert correlation and investigation assistance across multi-source data. |
| **Conifers AI** | AI SOC agents focused on reducing alert fatigue. Autonomous investigation and triage with human-in-the-loop escalation for high-confidence decisions. |
| **Radiant Security** | AI-powered SOC analyst that performs dynamic investigation of alerts. Builds investigation plans per-alert rather than following static playbooks. |

---

## AI-Augmented SIEM / XDR

Major SIEM and XDR platforms with integrated AI/LLM capabilities.

| Platform | AI Capability |
|---|---|
| **Microsoft Sentinel + Copilot for Security** | LLM-powered assistant embedded in the Sentinel workflow. Natural language querying (KQL generation), incident summarization, guided investigation, and response recommendations. Backed by Microsoft's security-specific model training. |
| **Palo Alto Cortex XSIAM** | ML-driven alert grouping and investigation. Combines XDR telemetry with AI models for automated stitching of related alerts into incidents. XSIAM positions itself as a SOC platform, not just a SIEM. |
| **Splunk AI** | ML Toolkit integration, AI Assistant for SPL generation and search optimization, and anomaly detection models. Integrates with Splunk SOAR for AI-informed response. |
| **Elastic AI Assistant** | LLM-powered assistant integrated into Elastic Security. Alert summarization, investigation guidance, natural language to ES\|QL/KQL conversion, and rule generation assistance. Uses retrieval-augmented generation over security data. |
| **Chronicle / Google SecOps** | Google's security operations platform combining Chronicle SIEM with Gemini AI. Natural language search, AI-generated investigation summaries, and detection rule suggestions. Leverages Google threat intelligence. |

---

## Detection Content Platforms

Platforms focused on detection rule management, optimization, and gap analysis.

| Platform | Focus |
|---|---|
| **SOC Prime** | Detection content marketplace and platform. Community and commercial Sigma-based detection rules. Uncoder for cross-platform rule conversion. Threat Detection Marketplace for sourcing detection content. |
| **Anvilogic** | Detection engineering platform for multi-SIEM environments. Rule lifecycle management, MITRE ATT&CK gap analysis, and detection-as-code workflows. Supports running detections across multiple SIEM backends. |
| **CardinalOps** | Detection posture management. Analyzes existing SIEM rules against MITRE ATT&CK to identify coverage gaps. Recommends new detections based on available data sources and current threat landscape. |

---

## Threat Intelligence + AI

Platforms combining threat intelligence with AI/ML for detection and analysis.

| Platform | Focus |
|---|---|
| **SOCRadar** | Extended threat intelligence platform with AI-assisted analysis. Monitors external attack surface, dark web, and threat actor activity. Provides enrichment data for alert triage. |
| **Recorded Future** | Intelligence platform using NLP and ML to process open, dark, and technical sources. Provides contextualized threat intelligence for enriching detections and alerts. |
| **Mandiant Threat Intelligence** | Google/Mandiant threat intelligence with deep adversary tracking. Threat actor profiles, campaign analysis, and IOC feeds. Integrates with Chronicle for detection enrichment. |

---

## Frameworks & Standards

Industry frameworks relevant to AI in security operations.

| Framework | Description | Link |
|---|---|---|
| **OWASP Agentic AI Top 10 (2026)** | Top 10 security risks specific to agentic AI systems. Directly relevant to understanding risks of deploying AI agents in SOC environments: prompt injection, excessive agency, insecure tool use, etc. | [owasp.org/www-project-agentic-ai-top-10](https://owasp.org/www-project-agentic-ai-top-10/) |
| **NIST Cyber AI Profile** | NIST guidance on managing cybersecurity risks of AI systems. Covers governance, risk assessment, and operational considerations for AI deployment in security contexts. | [nist.gov](https://www.nist.gov/) |
| **Gartner SOC Trends (2026)** | Annual analysis of SOC technology and operational trends. Tracks adoption of AI/ML in security operations, agentic SOC concepts, and detection engineering maturity. | Analyst access required |
| **MITRE ATT&CK** | Adversary tactics, techniques, and procedures knowledge base. The standard framework for mapping detection coverage and threat behavior. | [attack.mitre.org](https://attack.mitre.org/) |
| **MITRE ATLAS** | Adversarial Threat Landscape for AI Systems. Framework for understanding attacks against AI/ML systems — relevant when AI is part of the detection pipeline. | [atlas.mitre.org](https://atlas.mitre.org/) |

---

## Alert Correlation Capabilities by Platform

How major platforms implement alert correlation, risk scoring, and multi-signal detection. For the full cross-platform analysis, see [Alert Correlation Patterns](../concepts/alert-correlation-patterns.md).

| Platform | Correlation Architecture | Key Differentiator |
|---|---|---|
| **Splunk Enterprise Security (RBA)** | Two-layer model: risk rules write to risk index, Risk Incident Rules aggregate risk per entity and generate Risk Notables when thresholds are exceeded. Weighted scoring via `(impact * confidence) / 100` with dynamic risk modifiers (asset criticality, user privilege, threat intel). Default temporal windows: 24-hour burst and 7-day tactic progression. | Most mature weighted scoring model in production. De facto industry reference for risk-based alerting. ATT&CK tactic diversity thresholds built into default rules. |
| **Elastic Security** | Building block rules write to alerts index but are hidden from default view. Correlation via EQL sequence queries (`maxspan` temporal windows), threshold rules, and ES\|QL queries against alert indices. Entity risk scoring aggregates host, user, and service risk. ES\|QL LOOKUP JOIN (GA 2025) enables inline enrichment. | EQL sequence queries with ordered event matching and `maxspan` provide the most expressive deterministic sequence correlation. ES\|QL's INLINE STATS enables threshold aggregation without losing event context. |
| **Microsoft Sentinel** | Fusion ML engine automatically correlates low-fidelity analytics rule alerts into high-severity multi-stage incidents. UEBA Behaviors layer provides AI-generated behavioral building blocks. Incident grouping rules aggregate alerts by entity overlap and time proximity. Transitioning to Defender XDR correlation engine (mid-2025). | Only major platform where correlation is primarily ML-driven (Fusion) rather than authored by detection engineers. Lowest manual effort but less transparency into correlation logic. |
| **Panther** | Python-based detection framework (pypanther). Correlation rules specify `MinMatchCount` for minimum building block rule matches. Class inheritance enables building block and correlation rule coupling. Runs on Snowflake data lakehouse. | Full Python expressiveness for correlation logic. Testable correlation rules via standard Python testing frameworks. Cloud-native architecture. |
| **Anvilogic** | Drag-and-drop Threat Scenario canvas for visual correlation rule building. Threads vendor alerts, queries, and intel-enriched signals across kill chain stages mapped to ATT&CK. Multi-SIEM support (Splunk, Sentinel, Snowflake). Partnership with Databricks (2025) for AI-accelerated detection engineering. | Visual correlation authoring reduces barrier to building multi-stage scenarios. Cross-SIEM correlation is unique in the market. |
| **CrowdStrike Next-Gen SIEM** | Correlation Rule Template Discovery dashboard for adopting pre-built correlation rules. Combines EDR telemetry with third-party data sources for cross-domain correlation. | Tight integration between endpoint telemetry and SIEM correlation. Template-driven approach accelerates adoption. |
| **Google SecOps (Chronicle)** | Risk Analytics for entity-based risk scoring. YARA-L rules with multi-event correlation capabilities. Gemini AI for investigation assistance. | Leverages Google-scale infrastructure for correlation across massive data volumes. |

---

## Landscape Observations

- **Agentic SOC is the current wave.** Multiple startups (2024-2026) are building autonomous investigation agents. The differentiator is not "uses AI" but how much human oversight the system requires and how transparent its reasoning is.
- **SIEM vendors are adding LLM wrappers.** Every major SIEM now has an "AI Assistant" that generates queries and summarizes incidents. These are augmentation tools, not autonomous agents.
- **Detection content platforms solve a different problem.** SOC Prime, Anvilogic, and CardinalOps focus on rule coverage and lifecycle — AI features here are about recommending detections, not triaging alerts.
- **Risk-based alerting is becoming the default architecture.** The Splunk RBA model — building block signals accumulated per entity, correlated through threshold and pattern rules — is being adopted (in variant forms) by Elastic, CrowdStrike, and Google SecOps. The two-layer architecture (building blocks + correlation rules) is now consensus best practice.
- **UEBA and correlation are converging.** Microsoft Sentinel's Behaviors layer and Splunk UBA's risk index integration demonstrate that behavioral analytics and deterministic correlation rules increasingly feed the same risk accumulation pipeline rather than operating as separate systems.
- **The real differentiator is data quality.** All of these tools depend on the same underlying data: properly parsed logs, normalized fields, complete telemetry. The prerequisites documented in this repo apply regardless of which vendor or tool you deploy.
