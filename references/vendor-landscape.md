# Vendor Landscape

Commercial products and platforms relevant to AI-assisted detection engineering and SOC operations. Inclusion is not endorsement. This page exists to map the landscape, not recommend products.

**Last refreshed: April 2026** with Q1–Q2 2026 announcements. The vendor landscape moves faster than this document — refresh quarterly.

---

## Agentic SOC Platforms

Startups and products building autonomous or semi-autonomous SOC agent systems that triage, investigate, or respond to alerts without continuous human input. The 2026 funding flows in this category have been substantial — $400M+ across the named startups in the past 12 months.

| Vendor | 2026 Notable | Approach |
|---|---|---|
| **Prophet Security** | $30M Series A (Feb 2026) + Amex/Citi strategic investments | Productized closed-loop tuning from triage data; autonomous scheduled threat hunts. Marketing claims "0 mins alert dwell time, 4 mins MTTR, 98.5% fewer false positives." |
| **Dropzone AI** | $37M Series B (Q1 2026); **AI Threat Hunter** (Mar 2026) with 250+ MITRE-mapped hunt packs; **AI Threat Intel Analyst** (beta) auto-authors hunt packs from CVEs | Autonomous SOC analyst + autonomous threat hunting. Flat-rate pricing ($36k/yr base, ~4,000 investigations). |
| **Qevlar AI** | $30M raise (Mar 2026, Partech + Forgepoint) | **Deterministic graph orchestration** as anti-hallucination scaffolding. Claims 99.8% accuracy vs. 95–97% human analysts. Customers: Mercedes-Benz, Sodexo, Orange Cyberdefense, ECI, Atos. |
| **Conifers (CognitiveSOC)** | March 2026 release: transparent evidence-based investigations + governed AI operations | Gartner-named "company to beat in AI SOC agents for threat investigation." Strong MSSP focus. |
| **Radiant Security** | 100+ integrations; bundled log management (early 2026) | Strategic shift to compete with the SIEM ingest layer, not just sit above it. |
| **Intezer** | March 2026 platform expansion: **AI-Driven Detection Engineering** + **On-Demand Security Experts** (hybrid escalation) | Forensic-depth investigation rooted in malware-analysis heritage. |
| **D3 Security (Morpheus)** | 2026 differentiation: **purpose-built cybersecurity LLM** (24-month build, 60-person team) + **self-healing integrations** (autonomous parser/connector repair) | "No per-alert charges, no token fees" pricing model. 800+ integrations. Self-healing integrations are genuinely novel. |
| **Stellar Cyber** | v6.4.0 (Q1 2026): coordinated agentic AI in analyst workflows; agentic case summaries | Claims 80%+ analyst productivity, 90%+ FP reduction. |
| **Torq** | $140M Series D at $1.2B valuation (Jan 2026) — largest in category. **Agentic Builder** (Mar 2026) for NL-to-agentic-workflow generation. HyperSOC-2o (Feb 2026) | "The Cursor of security operations" framing. Publicly declares "SOAR is dead." |
| **Tines** | Jan 2026: **AI Interaction Layer** with full MCP server authoring + tunnel support for private MCP | Positioning as orchestration substrate for *other vendors'* AI agents — horizontal play. |
| **Simbian** | RSAC 2026 launch of coordinated three-agent platform: **AI SOC Agent** (GA), **AI Pentest Agent** (GA), **AI Threat Hunt Agent** (private preview) | Multi-agent coordination + **Context Lake** for tribal knowledge. Claims 92% auto-resolution. |
| **Crogl** | $30M ($25M Series A from Menlo + $5M seed from Tola, late 2025/early 2026); 2026 State of SecOps report (4,330 alerts/day, 37% investigated) | "Iron Man suit for security analysts." Quieter on product in 2026. |
| **Andesite** | **FedRAMP High Authorized** (March 2026) — first agentic SOC vendor | "Bionic SOC" framing (human-AI collaboration); no-ETL ingestion; no-training-on-customer-data guarantees. |
| **7AI** | $130M Series A (late 2025/early 2026) — claimed largest cyber Series A ever; AWS Security Hub Extended Plan integration (Feb 2026) | Founded by Lior Div + Yonatan Striem-Amit (ex-Cybereason). "Dynamic Reasoning" for novel-threat investigation without playbooks. |
| **Exaforce** | $75M Series A (Mar 2026) | Multi-model architecture (semantic + statistical + behavioral + LLM) across full SOC lifecycle. |
| **Tracecat** | YC-backed; 2026 prompt-to-automation positioning | **Open-source AI-native SOAR** with sandboxed agent runtime (nsjail). Build-vs-buy alternative for teams that want to own the agent harness. |
| **Adversa AI** | Won "Most Innovative Agentic AI Security" at Global InfoSec Awards (RSAC 2026) | **Not** a SOC vendor — red-teams AI agents themselves. Increasingly relevant as your SOC fills with agents. |
| **Salem Cyber** | Quiet in 2026 | Autonomous alert investigator; no notable 2026 activity surfaced. |
| **AiStrike** | RSAC 2026: launched "**Continuous Detection Engineering**" framing | Productized framing of the closed-loop tuning + validation pattern (relates to UC-26, UC-30). |
| **Sublime Security** | 2026: **ADÉ — Autonomous Detection Engineer** for email | LLM-powered agent that writes deterministic behavioural detections in MQL; "weeks to hours" claim. |

---

## AI-Augmented SIEM / XDR

Major SIEM and XDR platforms with integrated AI/LLM capabilities. Q1–Q2 2026 saw the largest single tranche of native-AI capability shipments in SIEM history.

| Platform | Q1–Q2 2026 Notable | Detection-Engineering-Specific Capabilities |
|---|---|---|
| **Microsoft Sentinel + Defender XDR + Security Copilot** | **Sentinel-into-Defender consolidation** (portal retires July 1, 2026); **Sentinel MCP server (GA)** with multiple tool collections; **AI-Powered SIEM Migration** (Splunk GA, QRadar preview); **Playbook Generator** (preview); **Dynamic Threat Detection Agent**; **Security Analyst Agent** in Defender; **Sentinel data lake** (GA); **Sentinel graph** (preview); Anthropic Claude MCP Connector to Sentinel (preview Apr 1, 2026); **Security Copilot free in E5** starting Apr 20, 2026 | Migration → KQL with intent-based mapping; coverage assessment via MCP Graph Tool; agentic investigation; data lake tiering; embedded copilot chat |
| **Palo Alto Cortex XSIAM + Cortex AgentiX** | **Cortex AgentiX** (next-gen XSOAR) GA in Cortex Cloud and XSIAM; Feb 2026: **Case Investigation Agent**, **Cloud Posture Agent**, **Automation Engineer Agent** (NL → working Python) | Native MCP support; 1,000+ prebuilt integrations; no-code GenAI agent builder with guardrails; trained on "1.2 billion playbook executions" |
| **Splunk + Cisco AI Assistant for Security** | RSAC 2026: **Detection Studio** (GA) with built-in MITRE coverage / quality / performance metrics; **Detection Builder Agent** (Alpha), **Personalized SPL Generator**, **Triage Agent**, **SOP Agent** (multi-modal LLM ingest of runbooks), **Guided Response Agent**, **Automation Builder Agent**; **Malware Threat Reversing Agent** (GA in Attack Analyzer); **Federated Search** (S3 + Iceberg); **Exposure Analytics** (GA Apr–May 2026) | The most comprehensive single-vendor 2026 release; Detection Studio competes directly with UC-06; SOP Agent competes with UC-15; Detection Builder + SPL Generator compete with UC-19 |
| **Elastic Security** | Agentic **ES\|QL self-validation** (every generated query goes through automated checkpoint + self-correction); **Attack Discovery** with persistence + scheduled scans + automated response; **Automatic Migration** for Splunk (ELSER semantic search + GenAI translation); 9 new integrations Q1 2026; AI Assistant available globally (8.19/9.1) | Migration → ES\|QL with semantic dedup; agentic query validation loop; rule-tagging consistency |
| **Google SecOps (Chronicle + Gemini)** | **Triage and Investigation Agent (TIN)** in Public Preview with free trial Apr 1 – Jun 30, 2026; **Unified Rules** (Mar 2, 2026) + pre-GA **Rules API**; YARA-L additions ($risk_entity_to_score, cast.as_int); **MRI entity resolution** (Mar 5, 2026) | Rules API for programmatic deployment + MITRE tag sync; entity risk weighting in YARA-L; TIN dashboards quantify TP vs. FP and time saved |
| **CrowdStrike Falcon** | RSAC 2026: **Charlotte AI AgentWorks Ecosystem** (no-code agent builder + governance) + **Charlotte Agentic SOAR**; Charlotte AI **ISO 42001-certified** for AI governance | AgentWorks for custom agent SDK; partner ecosystem (Anthropic, OpenAI, NVIDIA Nemotron, Bedrock, SageMaker, Accenture, Deloitte, Kroll) |
| **SentinelOne Purple AI** | RSAC 2026: **Auto Investigations (GA)**; **Prompt AI Agent Security** (real-time AI agent governance); **Observo AI** integration (filter/enrich/normalize before SIEM); Purple AI on >50% of all licenses sold in Q4 FY26 | Prompt AI Agent Security competes with the agent governance side of UC-25; Observo AI competes with UC-27 |
| **Exabeam New-Scale** | Jan 2026: industry-first **Agent Behavior Analytics (ABA)** (UEBA for AI agents); board-ready Agentic AI Security dashboard; Apr 2026: ABA expanded to ChatGPT, Microsoft Copilot, Gemini with OWASP Agentic Top 10 coverage | ABA is the leading commercial implementation of UEBA for AI agents — relates directly to UC-25 |
| **Sumo Logic Mo Copilot** | Mo Copilot GA; **Mobot** (NL assistant) + **Query Agent** (NL → log queries); built on Amazon Bedrock | Predominantly analyst-facing; thinner on detection-engineering features than peers |
| **Devo** | No standout Q1/Q2 2026 announcement. Continues **AuDRA** (NL-to-SOAR-playbook builder) | Quietest vendor of the SIEM/XDR set in this window |
| **Databricks Lakewatch (newcomer)** | Launched Mar 24, 2026 | "Open agentic SIEM": detection-as-code with automated test/deploy, **Agent Bricks**, "swarms" for triage/hunting, multi-modal data (video/audio for social engineering / insider threat), Anthropic-powered reasoning, 80% claimed TCO reduction. 15+ partners (Palo Alto, Okta, Cribl, Panther). |

---

## Detection Content Platforms

Platforms focused on detection rule management, optimization, and gap analysis.

| Platform | 2026 Notable | Focus |
|---|---|---|
| **SOC Prime / Uncoder AI** | **Uncoder AI v2** (2026): "10+ source languages, 21+ output platforms," 3× faster, hybrid AI translation that understands intent, MCP-server pattern for agentic detection workflows | Cross-SIEM rule translation, IOC-to-query, ATT&CK auto-tagging, CTI enrichment. Reference vendor for [UC-24](../use-cases/rule-content-engineering/24-cross-siem-rule-migration.md) |
| **Anvilogic** | RSAC 2026: **Blueprints** (NL workflow automation that turns expert practices into reusable AI agents); Monte Copilot continues NL-to-SPL/KQL/SQL; Forge AI Recommendation Engine ranks content by industry/region/tech stack/data feeds present | Detection-as-code for multi-SIEM; cross-SIEM correlation unique in market |
| **CardinalOps** | **Cardinal AI** (launched July 2025, expanded 2026) added agentic exposure-management workflows; extended early 2026 to cover prevention controls in addition to detection | Coverage gap analysis, tuning recommendations, MITRE mapping; CTEM unification |
| **Panther** | **AI SOC Platform GA Mar 19, 2026**; **AI Detection Builder** generates Python detections delivered as **GitHub PRs with auto-generated tests + mandatory human review**; published MCP server | The cleanest implementation of the rule-with-bundled-tests-via-PR pattern |
| **Hunters Pathfinder AI** | Published throughout 2026 | **Self-optimizing detections** (closed-loop): analyst dispositions auto-tune detection logic. Reference vendor for [UC-30](../use-cases/alert-analysis/30-self-optimizing-tuning.md) |
| **LimaCharlie** | 2026: **Agentic MDR pipeline** (Claude Code + LimaCharlie MCP server) writes rules + unit tests + retroactive hunts daily across all customer tenants | Most aggressive agentic-DE implementation in market; everything API-first and audit-logged |
| **Datadog Cloud SIEM** | **Bits AI Security Analyst (GA Mar 23, 2026)** for autonomous triage; published MCP detection rules | Cloud-native SIEM with detection content for MCP server abuse |
| **Axoflow** | RSAC 2026 | **AI-classified ingest pipelines**: supervised AI auto-identifies/classifies/normalizes incoming log streams; pipeline-side anomaly detection for rogue sources |
| **Bronto** | 2026 | AI-based log parsing reference; relates to [UC-27](../use-cases/rule-content-engineering/27-log-source-onboarding.md) |
| **SigmaHQ** | 2026 release: **Sigma Assistant** uses OpenAI to auto-generate Title and Description from Detection block; community `sigma-ai` content for AI-agent attacks (`product: ai_agent`) | Open-source backbone of cross-platform detection content |

---

## Threat Intelligence + AI

Platforms combining threat intelligence with AI/ML for detection and analysis. Note: detailed CTI use cases are deferred to a future companion repository.

| Platform | Focus |
|---|---|
| **SOCRadar** | Extended threat intelligence platform with AI-assisted analysis. Monitors external attack surface, dark web, and threat actor activity. |
| **Recorded Future** | Intelligence platform using NLP and ML to process open, dark, and technical sources. |
| **Mandiant Threat Intelligence (Google Cloud)** | Deep adversary tracking; threat actor profiles, campaign analysis, IOC feeds. **M-Trends 2026** (Apr 2026) documented PROMPTFLUX, PROMPTSTEAL, SesameOp — relevant to UC-25. |

---

## Frameworks & Standards

Industry frameworks relevant to AI in security operations.

| Framework | 2026 Status | Link |
|---|---|---|
| **OWASP Top 10 for LLM Applications** | v2.0 (2025) — current; v3 anticipated late 2026 | [genai.owasp.org/llm-top-10](https://genai.owasp.org/llm-top-10/) |
| **OWASP Top 10 for Agentic Applications 2026** | Released Dec 9, 2025 — Agent Goal Hijack, Identity & Privilege Abuse, Human-Agent Trust Exploitation, Rogue Agents, Least-Agency principle | [genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) |
| **NIST IR 8596 Cyber AI Profile** | Preliminary draft Dec 16, 2025; comments closed Jan 30, 2026. Defines Secure / Defend / Thwart focus areas | [csrc.nist.gov/pubs/ir/8596/iprd](https://csrc.nist.gov/pubs/ir/8596/iprd) |
| **NIST 800-53 COSAiS overlays** | Annotated outline Jan 8, 2026; first overlay drafts due Q3 2026 | [csrc.nist.gov/projects/cosais](https://csrc.nist.gov/projects/cosais) |
| **NIST AI Risk Management Framework** | Active; sector profiles in development | [nist.gov/itl/ai-risk-management-framework](https://www.nist.gov/itl/ai-risk-management-framework) |
| **CSA AI Controls Matrix (AICM)** | 2026 CSO Award winner (Mar 10, 2026); foundation for upcoming STAR for AI certification | [cloudsecurityalliance.org/artifacts/ai-controls-matrix](https://cloudsecurityalliance.org/artifacts/ai-controls-matrix) |
| **ISO/IEC 42001** | AI management system standard; CrowdStrike Charlotte AI 2026 certification reference | [iso.org/standard/42001](https://www.iso.org/standard/42001) |
| **EU AI Act** | High-risk enforcement Aug 2, 2026 (Article 15: cybersecurity controls + automatic logging; penalties up to €15M / 3% global turnover) | [artificialintelligenceact.eu](https://artificialintelligenceact.eu/) |
| **NSA AI Supply Chain Guidance** | March 18, 2026: cryptographic signing across model lifecycle, verified registry, AI SBOM | [logistics-concepts.com/news/digital-supply-chain](https://www.logistics-concepts.com/news/digital-supply-chain-nsa-warns-ai-risks-executive-summary-action-plan/) |
| **MITRE ATT&CK** | v18 (Oct 2025): retired Detections + Data Sources, replaced with Detection Strategies + Analytics — corpus-wide schema migration required | [attack.mitre.org](https://attack.mitre.org/) |
| **MITRE ATLAS** | v5.4.0 (Feb 2026): added agentic AI techniques (Tool Poisoning, Escape to Host, AML.T0096 AI Service API, AML.CS0042 SesameOp case study) | [atlas.mitre.org](https://atlas.mitre.org/) |
| **Gartner 2026 Cybersecurity Trends** | Feb 5, 2026: AI Security Platforms as new category; Preemptive Cybersecurity forecast to reach 50% of spend by 2030 | Analyst access required |

---

## Alert Correlation Capabilities by Platform

How major platforms implement alert correlation, risk scoring, and multi-signal detection. For the full cross-platform analysis, see [Alert Correlation Patterns](../concepts/alert-correlation-patterns.md).

| Platform | Correlation Architecture | Key Differentiator |
|---|---|---|
| **Splunk Enterprise Security (RBA)** | Two-layer model: risk rules write to risk index; Risk Incident Rules aggregate risk per entity. Weighted scoring via `(impact * confidence) / 100` with risk modifiers. Detection Studio (GA 2026) adds built-in MITRE coverage scoring. | Most mature weighted scoring model in production; reference RBA implementation. |
| **Elastic Security** | Building block rules + EQL sequence queries (`maxspan`) + ES\|QL queries against alert indices + entity risk scoring. ES\|QL LOOKUP JOIN (GA 2025) enables inline enrichment. Agentic ES\|QL self-validation (2026). | Most expressive deterministic sequence correlation; agentic query validation loop. |
| **Microsoft Sentinel** | Fusion ML engine + UEBA Behaviors layer + Sentinel MCP server (GA 2026) + Sentinel data lake (GA 2026) + Sentinel graph (preview 2026) + Defender XDR consolidation (July 2026). | Most ML-driven correlation; lowest manual effort; Sentinel graph + MCP unique. |
| **Panther** | Python-based detection framework (pypanther). `MinMatchCount` for building-block coupling. AI Detection Builder (GA Mar 2026) generates Python detections as PRs with tests. Published MCP server. | Full Python expressiveness; cleanest PR-with-tests pattern. |
| **Anvilogic** | Drag-and-drop Threat Scenario canvas; multi-SIEM (Splunk, Sentinel, Snowflake); Blueprints (RSAC 2026) for NL workflow agents. | Visual cross-SIEM correlation authoring; environment-fit content recommendation. |
| **CrowdStrike Next-Gen SIEM** | Correlation Rule Template Discovery; Charlotte AI AgentWorks for custom agent SDKs (RSAC 2026). | Tight EDR + SIEM correlation. |
| **Google SecOps (Chronicle)** | Risk Analytics for entity-based risk scoring; YARA-L multi-event correlation; Unified Rules + Rules API (Mar 2026); MRI entity resolution (Mar 2026). | Google-scale infrastructure; programmatic rule deployment. |
| **Databricks Lakewatch** | Open agentic SIEM with detection-as-code, Agent Bricks, multi-modal correlation. | Newcomer (Mar 2026); open lakehouse architecture; multi-modal evidence. |

---

## 2026 Cross-Platform Themes

These trends are universal across the categories above:

1. **MCP is now table-stakes.** Every major vendor ships at least one MCP server or MCP-aware capability in Q1–Q2 2026.
2. **Closed-loop detection engineering is being productized.** Triage outcomes auto-tune rules at vendors including Hunters, Prophet, Intezer, LimaCharlie.
3. **Cross-SIEM rule migration is solved enough to ship.** Microsoft, Elastic, SOC Prime all have production migration capabilities for the most common direction (X → Sentinel / Elastic).
4. **Detection of agentic AI itself is the fastest-growing new content category.** Driven by OWASP Agentic Top 10, ATLAS v5.4.0, Exabeam ABA, SentinelOne Prompt AI Agent Security, Microsoft Agent 365.
5. **Continuous Detection Validation has been productized** as "Continuous Detection Engineering" (AiStrike) or as the daily-validation loop (LimaCharlie).
6. **AI-driven SOAR / agentic playbook generation is a category.** Torq Agentic Builder, Splunk Automation Builder Agent, AgentiX Automation Engineer, Sentinel Playbook Generator.

---

## Landscape Observations

- **Agentic SOC stopped being marketing and became a product category in Q1 2026.** Every major SIEM/XDR vendor and every notable AI-SOC startup shipped at least one autonomous agent. The differentiator is no longer "uses AI" but how transparent the reasoning is and how mature the safety controls are.
- **Anti-hallucination scaffolding is a marketing point.** Qevlar's "deterministic graph orchestration," Conifers' "transparent reasoning," D3's "purpose-built cybersecurity LLM" — all responses to enterprise skepticism about LLM determinism. The technical substance varies; treat with measured skepticism.
- **Pricing models moving away from per-alert.** D3 explicitly markets "no per-alert, no token fees"; Dropzone publishes flat-rate. The industry consensus is that per-alert pricing perversely incentivizes alert suppression.
- **Federal / regulated-vertical push.** Andesite's FedRAMP High Authorized status (Mar 2026) is a leading indicator; expect more FedRAMP and EU-sovereignty announcements.
- **The reality-check countertrend.** Help Net Security ran a piece in March 2026 titled "AI SOC vendors are selling a future that production deployments haven't reached yet." Worth reading skeptically — many "autonomous" claims still describe analyst approval before write actions.
- **"Autonomous" claims to interrogate carefully.** Read-only autonomy is common; write-action autonomy with no human approval is rare to nonexistent for production deployments. The vendor's auto-eligibility policy is the operative artifact, not the marketing copy.
- **Detection-as-code is going mainstream in product, not just GitHub.** Splunk Detection Studio, Google Unified Rules + Rules API, Lakewatch detection-as-code, AgentiX reusable actions.
- **The real differentiator is data quality.** All of these tools depend on the same underlying data: properly parsed logs, normalized fields, complete telemetry. The prerequisites documented in this repo apply regardless of which vendor or tool you deploy.
