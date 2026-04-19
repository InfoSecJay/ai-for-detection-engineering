# 2026 Q1-Q2 Research Review

A landscape review of AI for Detection Engineering covering January – April 2026. Maps the existing 23 use cases against vendor announcements, framework updates, and academic research from this period. Identifies which use cases are now commoditized by vendors, which are validated by emerging standards, and which gaps in the catalog should be closed.

This is a snapshot. Re-run the analysis at least every six months — the field moves quickly.

---

## Executive Summary

The Jan-Apr 2026 window is the inflection where "agentic SOC" stops being marketing and becomes an actual product category. Every major SIEM/XDR vendor and every notable AI-SOC startup shipped at least one autonomous agent in this window. The signal worth tracking is no longer "does this vendor have AI?" — it's "what specific detection-engineering workflow have they automated, and is the feedback loop closed?"

Six cross-cutting themes emerged:

1. **MCP is now table-stakes.** Microsoft Sentinel MCP server (GA), Palo Alto Cortex AgentiX (native MCP), Tines (MCP authoring as a product), Panther + LimaCharlie + SOC Prime + Datadog (published MCP servers). MCP is the de facto integration substrate.
2. **Closed-loop detection engineering is being productized.** Prophet, Intezer, Hunters Pathfinder, LimaCharlie all market the loop where triage outcomes auto-tune detection logic — not just recommend tuning. The "self-optimizing detection" pattern is an operational shift.
3. **Cross-SIEM rule migration is now solved enough to ship.** Microsoft Sentinel SIEM Migration (Splunk + QRadar → Sentinel), Elastic Automatic Migration, SOC Prime Uncoder AI v2 (10+ source / 21+ target languages). Bulk semantic rule mapping is mainstream.
4. **Detection of agentic AI itself is the fastest-growing new content category.** OWASP Agentic Top 10 (Dec 2025), MITRE ATLAS v5.4.0 with agentic techniques (Feb 2026), Exabeam Agent Behavior Analytics, SentinelOne Prompt AI Agent Security, Microsoft Agent 365, agentshield-ai/sigma-ai. Detection engineers now need content for AI agents, MCP servers, and A2A traffic.
5. **MITRE ATT&CK v18 (Oct 2025) introduced "Detection Strategies + Analytics"** replacing the legacy Detections/Data Sources schema. Every existing rule library needs re-mapping. None of the vendor offerings is end-to-end automated for this.
6. **Standards and regulation accelerated sharply.** NIST IR 8596 Cyber AI Profile (Dec 2025/Jan 2026), NIST 800-53 COSAiS overlays (Jan 2026), CSA AICM (winning 2026 awards), EU AI Act Article 15 enforcement Aug 2026. Detection engineering AI now has a compliance surface.

The 23 existing use cases hold up well. None are obsolete. But seven gap candidates from the prior critique are now validated by 2026 evidence, and the research surfaces three additional gaps the critique did not anticipate.

---

## What Vendors Are Doing (And What's Genuinely New)

### Agentic SOC startups
| Vendor | Notable 2026 move | Genuinely new? |
|---|---|---|
| Prophet Security | $30M Series A + Amex/Citi strategic investments; productized closed-loop tuning from triage data | Closed loop is new |
| Dropzone AI | $37M Series B; **AI Threat Hunter** (250+ MITRE-mapped hunt packs, continuous) + **AI Threat Intel Analyst** (auto-authors hunt packs from CVEs) | Yes — autonomous hunt-pack authoring is new |
| Qevlar AI | $30M raise; **deterministic graph orchestration** as anti-hallucination scaffolding; pivoting to organization-level insight | Pattern is technically substantive |
| Conifers | Mar 2026 release with **transparent evidence-based investigations** + **governed AI operations**; Gartner-named "company to beat" | Governance focus is differentiated |
| Radiant Security | 100+ integrations; **bundled log management** (attacking SIEM ingest) | Yes — strategic shift |
| Intezer | March 2026 platform expansion adds **AI-Driven Detection Engineering** (verdicts feed rule tuning) and **On-Demand Security Experts** (hybrid escalation) | Both new |
| D3 Security (Morpheus) | **Purpose-built cybersecurity LLM** (24-month build, 60-person team); **self-healing integrations** (autonomous parser/connector repair) | Self-healing is genuinely novel |
| Stellar Cyber | v6.4.0 with embedded agentic reasoning; agentic case summaries | Mostly maturation |
| Torq | $140M Series D ($1.2B valuation, largest in category); **Agentic Builder** (NL → agentic workflow) | Yes — natural-language workflow generation is new |
| Tines | Jan 2026 **AI Interaction Layer** with full MCP server authoring, tunnel support for private MCP | Yes — MCP-as-a-product |
| Simbian | RSAC 2026 launch of coordinated three-agent platform (SOC + Pentest + Hunt); **Context Lake** for tribal knowledge | Multi-agent coordination is new |
| Crogl | $30M; State of SecOps 2026 report (4,330 alerts/day, 37% investigated) | Quiet on product |
| Andesite | **FedRAMP High** (Mar 2026) — first agentic SOC vendor | Federal market unlock |
| 7AI | $130M Series A (largest in cyber history); **Dynamic Reasoning** for novel-threat investigation | Funding-led |
| Tracecat | Open-source AI-native SOAR with sandboxed agent runtime; prompt-to-automation | Only meaningful OSS option |
| Adversa AI | Won "Most Innovative Agentic AI Security" at RSAC 2026 — red-teams agents themselves | Adjacent control category |

### SIEM / XDR native AI
| Platform | Notable 2026 capability | Most relevant to DE |
|---|---|---|
| Microsoft Sentinel + Defender XDR + Security Copilot | **Sentinel MCP server (GA)**, **AI-Powered SIEM Migration** (Splunk + QRadar → Sentinel), **Playbook Generator**, **Dynamic Threat Detection Agent**, **Security Analyst Agent**, Sentinel data lake GA, Sentinel graph (preview), Sentinel-into-Defender consolidation deadline July 2026 | All of the above |
| Palo Alto Cortex XSIAM + AgentiX | **Cortex AgentiX** (next-gen XSOAR) GA; agents include **Case Investigation**, **Cloud Posture**, and **Automation Engineer** (NL → tested SOAR playbooks); native MCP support; 1,000+ prebuilt integrations | Automation Engineer Agent + AgentiX |
| Splunk + Cisco | **Detection Studio** (GA — built-in MITRE coverage, quality, performance metrics); **Detection Builder Agent** (Alpha), **Personalized SPL Generator**, **Triage Agent**, **SOP Agent**, **Guided Response Agent**, **Automation Builder Agent**; **Malware Threat Reversing Agent** (GA) | Detection Studio + agents fleet |
| Elastic Security | **Automatic Migration** for Splunk; **agentic ES\|QL self-validation loop** (every generated query goes through self-correction); **Attack Discovery** with persistence, scheduling, automated actions | Migration + self-validation loop |
| Google SecOps | **Triage and Investigation Agent (TIN)** in public preview; **Unified Rules** + **Rules API** (Mar 2026); **MRI entity resolution**; YARA-L `$risk_entity_to_score` | Rules API + MRI |
| CrowdStrike Falcon | **Charlotte AI AgentWorks** (no-code agent builder); **Charlotte Agentic SOAR**; ISO 42001-certified | AgentWorks ecosystem |
| SentinelOne Purple AI | **Auto Investigations (GA)**; **Prompt AI Agent Security** (governance for AI agents); Observo AI integration (in-pipe enrichment) | Observo + Prompt AI Agent Security |
| Exabeam New-Scale | **Agent Behavior Analytics (ABA)** — UEBA for AI agents; expanded Apr 2026 to ChatGPT/Copilot/Gemini; OWASP Agentic Top 10 coverage | ABA — UEBA for AI agents |
| Databricks Lakewatch (newcomer) | **Open agentic SIEM** with detection-as-code, **Agent Bricks**, multi-modal data, 80% TCO claim | New competitive class |

### Detection content engineering tools
| Tool | 2026 capability |
|---|---|
| CardinalOps Cardinal AI | Agentic exposure-management; expanded to prevention controls; rule recommendations from CTI |
| Anvilogic | **Blueprints** (RSAC 2026 — NL workflow agents); Forge AI Recommendation Engine ranks content by industry/region/tech stack/data feeds present |
| SOC Prime Uncoder AI v2 | 10+ source → 21+ target translation; 3× faster; hybrid AI translation that understands intent; MCP-server pattern |
| Microsoft CTI-REALM | **Open-source benchmark** (Inspect-AI) for end-to-end agent-driven detection rule generation; Claude models lead leaderboard (~0.624-0.685) |
| Panther | **AI SOC Platform GA Mar 2026**; **AI Detection Builder** generates Python detections delivered as **GitHub PRs with auto-generated tests**; published MCP server |
| Hunters Pathfinder | **Self-optimizing detections** — analyst dispositions auto-tune rules (closed loop) |
| LimaCharlie | **Agentic MDR pipeline** (Claude Code + LimaCharlie MCP) writes rules + unit tests + retroactive hunts daily across all customer tenants |
| Datadog Cloud SIEM | **Bits AI Security Analyst (GA Mar 2026)**; published MCP detection rules |
| Axoflow | **AI-classified ingest pipelines**; pipeline-side anomaly detection (rogue sources, format drift) |
| SigmaHQ | OpenAI-assisted Title/Description generation; **agentshield-ai/sigma-ai** project — Sigma rules for AI-agent attacks |
| Sublime Security | **ADÉ (Autonomous Detection Engineer)** — LLM agent that writes deterministic MQL detections |
| AiStrike | **Continuous Detection Engineering** (RSAC 2026) — productized framing of the closed-loop concept |

### Standards, frameworks, regulation (Q1-Q2 2026)
| Item | Date | Why DE cares |
|---|---|---|
| MITRE ATLAS v5.4.0 | Feb 2026 | New agentic AI techniques: tool poisoning, escape-to-host, AI Service API as C2 (AML.T0096) |
| MITRE ATT&CK v18 | Oct 2025 (in active 2026 use) | **Detection Strategies + Analytics** replace legacy Detections/Data Sources — every rule library needs re-mapping |
| OWASP Top 10 for Agentic Applications 2026 | Dec 9, 2025 | Goal Hijack, Identity & Privilege Abuse, Human-Agent Trust Exploitation, Rogue Agents — all need detection content |
| NIST IR 8596 Cyber AI Profile | Dec 2025 / Jan 2026 | "Defend" focus area = AI-enabled detection engineering as a controllable domain |
| NIST 800-53 COSAiS overlays | Jan 8, 2026; first overlay drafts due Q3 2026 | Operationalizes 800-53 controls for AI systems |
| CSA AI Controls Matrix (AICM) | Won 2026 CSO Award (Mar 10, 2026) | Foundation for STAR for AI certification |
| EU AI Act Article 15 enforcement | Aug 2, 2026 | Mandatory logging + cybersecurity controls for high-risk AI; €15M / 3% penalties |
| NSA AI Supply Chain Guidance | Mar 18, 2026 | Crypto-signed model lifecycle, model registry, AI SBOM — implies parallel detection-content supply chain |
| Mandiant M-Trends 2026 | Apr 2026 | **PROMPTFLUX / PROMPTSTEAL** — malware that calls LLMs mid-execution to evade detection |
| Gartner 2026 Cybersecurity Trends | Feb 5, 2026 | "AI Security Platforms" as a new category; "Preemptive Cybersecurity" forecast to reach 50% of spend by 2030 |

### Notable academic / research (Jan-Apr 2026)
- **CTI-REALM** (Microsoft, Mar 2026) — end-to-end DE-agent benchmark. **First public eval methodology for the field.**
- **CORTEX** (arXiv 2510.00311) — multi-agent collaborative LLMs for high-stakes alert triage
- **AIDR** (arXiv 2512.08169) — Information-Dense Reasoning: 40.6% latency reduction with auditability
- **CyberSOCEval** (arXiv 2509.20166) — open benchmark for malware analysis and threat-intel reasoning
- **Decision-Aware Trust Signal Alignment** (arXiv 2601.04486) — calibration scoring for LLM triage
- **FedGraph-AGI** (arXiv 2602.16109) — federated cross-border insider threat with differential privacy + HE + secure MPC
- **RulePilot** (arXiv 2511.12224) — LLM agent for SPL/KQL rule writing and conversion

---

## Where the 23 Use Cases Stand Against the 2026 Reality

### Use cases now broadly commoditized by vendors
These are no longer differentiation; they're table-stakes the customer expects to come from the SIEM/XDR. The repository's value here is *vendor-neutral* framing and depth, not novelty.

- **UC-11 LLM Triage Verdicts**: Charlotte AI Detection Triage (98% claim), Google TIN, Microsoft Security Analyst Agent, Splunk Triage Agent, Hunters Pathfinder, Datadog Bits AI, Conifers, Prophet, Qevlar
- **UC-13 Natural Language Alert Query**: Microsoft Sentinel MCP, Sumo Mo Copilot, Elastic AI Assistant ES\|QL, Anvilogic Monte
- **UC-14 Agentic Investigation**: Microsoft Security Analyst Agent, SentinelOne Auto Investigations, Google TIN, AgentiX Case Investigation Agent, Hunters Pathfinder, every named startup
- **UC-12 Cluster Narratives**: Elastic Attack Discovery, all major XDR vendors with "named threat" features
- **UC-15 Investigation Guide Generation**: Splunk SOP Agent (ingests SOPs into ES response plans), Splunk AI Assistant for ES, Anvilogic Monte
- **UC-19 Rule Generation**: Splunk Detection Builder Agent, Panther AI Detection Builder, Sublime ADÉ, CardinalOps TI-Ops, LimaCharlie agentic pipeline, Sigma Assistant, SOC Prime Uncoder
- **UC-06 MITRE Posture Scoring**: Splunk Detection Studio (built-in), Sentinel MCP Graph Tool, Google Rules API MITRE sync, CardinalOps

### Use cases validated as differentiated and worth keeping prominent
These remain less commoditized — vendor coverage is shallow or uneven, and your repo's vendor-neutral, transparent methodology is a real edge.

- **UC-01 Detection Performance Analytics** — vendors show metrics; few generate prioritized cross-rule narratives at scale
- **UC-02 Entity Cardinality Noise Analysis** — domain-aware entity framework is uncommon
- **UC-03 Automated Rule Tuning Recommendations** — vendor versions are mostly closed-loop "auto-apply" without transparency; your "recommend with reasoning" + safety analysis remains valuable
- **UC-04 Detection Drift Monitoring** — almost no vendor coverage at this depth
- **UC-07/08/09 Posture Assessment** — strategic depth uncommon in vendors
- **UC-16 Observable Artifact Extraction** — typically commoditized only inside specific vendor consoles
- **UC-17 Rule Comparison & Gap Analysis** — semantic comparison across formats is rare
- **UC-18 Rule Quality Assessment** — vendor versions are syntactic; semantic quality assessment is rare
- **UC-20 Analyst Workflow Optimization** — uncommon
- **UC-22 Detection Program Health Reporting** — vendor versions are dashboards, not narrative reports

### Use cases the vendor reality has reshaped — needs doc updates
- **UC-06** — must address ATT&CK v18 Detection Strategy / Analytic schema migration
- **UC-19** — should reference CTI-REALM benchmark methodology + Panther's PR-with-tests pattern + Florian Roth skepticism
- **UC-23 Synthetic Test Data** — should note Panther bundles tests with the rule in PR (more integrated pattern)
- **UC-21 CTI Synthesis** — should be marked explicitly as bridging into the Tier-2 CTI repo and only the DE-relevant slice retained here

---

## Validation of the Original Critique's Gap Candidates

The prior critique listed 7 gap candidates. Q1-Q2 2026 evidence validates all of them.

| Gap candidate from prior critique | 2026 validation |
|---|---|
| AI-rule supply-chain integrity / provenance / signing | NSA AI Supply Chain Guidance Mar 2026; OpenSSF Model Signing (OMS) spec; OWASP ASI03 Identity & Privilege Abuse |
| AI-driven SIEM cost optimization | Axoflow AI-classified ingest; SentinelOne Observo AI; Sentinel data lake; ReliaQuest case studies |
| Compliance-driven detection mapping | NIST IR 8596 Cyber AI Profile; NIST 800-53 COSAiS overlays; CSA AICM; EU AI Act Article 15 |
| Continuous detection validation / purple-team automation | SANS SEC598; AiStrike Continuous Detection Engineering; Skyhawk autonomous red team; Picus / AttackIQ continuous validation |
| Federated / privacy-preserving detection analytics | FedGraph-AGI (arXiv 2602.16109); CSA AICM federation guidance |
| Vulnerability-exposure-weighted detection prioritization | Qualys Agent Val (Mar 2026); Tenable One CTEM; CardinalOps prevention-control coverage |
| Threat-model-driven detection design | STRIDE-GPT, ASTRIDE, STRIDE-AI tools active; CISA Secure-by-Design momentum |

---

## New Gaps Surfaced by 2026 Research (Not in the Original Critique)

Three additional gaps the prior critique did not anticipate:

1. **Detection content for agentic AI / AI-agent telemetry as a first-class target.** This is the fastest-growing detection-content category in 2026. OWASP Agentic Top 10, ATLAS v5.4.0, Exabeam ABA, SentinelOne Prompt AI Agent Security, Microsoft Agent 365, agentshield-ai/sigma-ai. None of the 23 use cases addresses *writing detections for AI agents themselves*.

2. **ATT&CK v18 schema migration / Analytic re-mapping.** The Detection Strategy + Analytic model replaces a generation of Detections + Data Sources mappings. Every existing rule library will need re-mapping. No vendor has shipped end-to-end automation for this yet — pure greenfield use case.

3. **Cross-SIEM bulk rule migration with semantic mapping.** The 23 use cases include "rule generation" (from CTI) and "rule comparison" — but bulk migration of an existing corpus from one SIEM to another, using semantic embedding to first match against the target's prebuilt library and only translating the residual via GenAI, is a distinct pattern. Microsoft's Splunk → Sentinel migration is the reference; Elastic and SOC Prime have versions.

---

## Proposed New Use Cases

Eight additions, scoped to detection engineering. Numbering continues from UC-23.

### UC-24: Cross-SIEM Rule Migration & Semantic Translation
**Category**: Rule Content Engineering
**What AI does**: Given a corpus of detection rules in one SIEM's format, embed each rule, search a target SIEM's prebuilt rule library for semantic matches, map matched rules to native equivalents, and translate the unmatched residual to the target query language. Different from UC-19 (from-scratch from CTI) — this is bulk corpus migration anchored on existing prebuilt content.
**Validated by**: Microsoft Sentinel SIEM Migration (Splunk + QRadar), Elastic Automatic Migration, SOC Prime Uncoder AI v2

### UC-25: AI Agent & MCP Activity Detection
**Category**: Alert Analysis (or new subcategory `agentic-ai-detection/`)
**What AI does**: Reasons over telemetry produced by AI agents (tool calls, MCP server traffic, A2A messages, agent identity events) to detect agent goal hijack, tool poisoning, identity abuse, prompt-injection-driven actions, and rogue agents. Includes detection content for OWASP Agentic Top 10 categories and MITRE ATLAS v5.4.0 techniques.
**Validated by**: OWASP Agentic Top 10 (Dec 2025), MITRE ATLAS v5.4.0 (Feb 2026), Exabeam ABA, SentinelOne Prompt AI Agent Security, Microsoft Agent 365, agentshield-ai/sigma-ai, Mandiant M-Trends 2026 (PROMPTFLUX, PROMPTSTEAL)

### UC-26: Continuous Detection Validation (Atomic Test CI Loop)
**Category**: Rule Content Engineering
**What AI does**: Selects appropriate Atomic Red Team / Caldera / Stratus tests for each detection, schedules execution against test environments, evaluates whether the rule fired with expected severity and entities, and produces a coverage report with remediation suggestions for non-firing rules. Distinguishes itself from UC-23 (synthetic test data — generated logs without execution) by orchestrating real attack execution.
**Validated by**: SANS SEC598 ("Always-On Purple Team / Detection CI/CD"), AiStrike Continuous Detection Engineering (RSAC 2026), Skyhawk autonomous red team, Picus / AttackIQ / Cymulate continuous validation, LimaCharlie's daily retroactive validation

### UC-27: AI-Driven Log Source Onboarding & Parser Generation
**Category**: Rule Content Engineering
**What AI does**: Given vendor docs and sample log lines from a new data source, generates ingest pipeline configs (Elastic ingest pipelines, Splunk TAs, Sentinel ASIM parsers), suggests ECS/CIM/ASIM field mappings, validates parsing on additional samples, and surfaces field-population gaps that would degrade downstream rule firing. Includes pipeline-side anomaly detection for rogue data sources, format drift, and rising error rates.
**Validated by**: SentinelOne Observo AI integration, Bronto AI log parsing, Sentinel auto-recommended connectors during migration, Axoflow AI-classified ingest pipelines

### UC-28: Detection Coverage Mapping for Compliance Frameworks
**Category**: Posture Assessment
**What AI does**: Maps existing detection content to compliance control libraries (NIST 800-53 / COSAiS, CSA AICM, ISO 27001 Annex A, PCI DSS 4.0, EU AI Act Article 15 logging requirements, HIPAA Security Rule, sector-specific) and identifies coverage gaps. Distinct from UC-06 (MITRE ATT&CK) — this is regulatory/compliance-mapped, not adversary-mapped. Produces audit-ready evidence packages.
**Validated by**: NIST IR 8596 Cyber AI Profile (Dec 2025/Jan 2026), NIST 800-53 COSAiS overlays (Jan 2026), CSA AICM (2026 CSO Award), EU AI Act Aug 2026 enforcement, sector-specific regulations

### UC-29: SIEM Cost & Data Tiering Optimization
**Category**: Strategic (or new subcategory `cost-optimization/`)
**What AI does**: Analyzes per-data-source cost vs. detection coverage value, recommends tiering decisions (hot SIEM index vs. cold data-lake vs. drop), models the detection-coverage impact of proposed changes (e.g., "dropping `windows.dns.*` will silence 14 rules; here are the alternatives"), and identifies expensive low-value telemetry. Pairs deterministic cost data with AI reasoning over coverage trade-offs.
**Validated by**: Axoflow (50% SIEM-spend reduction claim), ReliaQuest (860 GB/day customer reduction, 43% cost cut), Sentinel data lake, Databricks Lakewatch (80% TCO claim), Splunk Federated Search

### UC-30: Self-Optimizing Closed-Loop Tuning
**Category**: Alert Analysis (extends UC-03)
**What AI does**: Distinct from UC-03 (recommends tuning, human applies) — this is the closed-loop variant where analyst dispositions automatically generate, validate, deploy (often via PR with mandatory review), and monitor tuning changes. Includes guardrails for rollback, blast-radius prediction, and automatic suspension when tuning revert rate exceeds threshold.
**Validated by**: Hunters Pathfinder (self-optimizing detections), Prophet Security (closed-loop from triage data), Intezer AI-Driven Detection Engineering, LimaCharlie agentic MDR pipeline

### UC-31: Detection Content Provenance & Supply Chain Integrity
**Category**: Rule Content Engineering
**What AI does**: Manages detection-content lifecycle with cryptographic signing of authored rules, attribution chains for rules sourced from CTI vendors / community / AI generation, audit trails for every modification, and verification that rules in production match signed source. Detects unauthorized rule modifications, rules sourced from untrusted authors, and AI-generated rules that bypassed required human review. Parallel to AI model supply chain integrity but applied to detection content.
**Validated by**: NSA AI Supply Chain Guidance (Mar 2026), OpenSSF Model Signing (OMS) spec, OWASP Agentic ASI03 (Identity & Privilege Abuse), CSA AICM supply-chain controls

---

## Recommended Updates to Existing Artifacts

The research surfaces specific changes to make to existing files:

### Use case docs
- **[UC-03 Automated Rule Tuning Recommendations](../use-cases/alert-analysis/03-automated-rule-tuning-recommendations.md)** — note relationship to proposed UC-30 (closed-loop variant); add Hunters Pathfinder, Intezer, Prophet to "Real-World Considerations"
- **[UC-06 MITRE ATT&CK Posture Scoring](../use-cases/posture-assessment/06-mitre-attack-posture-scoring.md)** — add ATT&CK v18 Detection Strategy + Analytic schema awareness; note Splunk Detection Studio and Sentinel MCP Graph Tool as commercial alternatives
- **[UC-11 LLM Triage Verdicts](../use-cases/ai-assisted-triage/11-llm-triage-verdicts.md)** — add reference to AIDR / Decision-Aware Trust calibration research; note vendor commoditization and the depth-vs-vendor-neutral framing
- **[UC-14 Agentic Investigation Execution](../use-cases/ai-assisted-triage/14-agentic-investigation-execution.md)** — note Qevlar's "deterministic graph orchestration" pattern; reference Microsoft Security Analyst Agent and Hunters Pathfinder Investigation Orchestration Agent
- **[UC-17 Rule Comparison & Gap Analysis](../use-cases/rule-content-engineering/17-rule-comparison-and-gap-analysis.md)** — note this is the foundation of cross-SIEM migration (UC-24)
- **[UC-19 Detection Rule Generation](../use-cases/rule-content-engineering/19-detection-rule-generation.md)** — reference CTI-REALM benchmark methodology; reference Panther's PR-with-tests pattern; cite Florian Roth's skepticism as the counterpoint
- **[UC-21 Threat Intelligence Synthesis](../use-cases/strategic/21-threat-intelligence-synthesis.md)** — explicitly note that this bridges into the deferred Tier-2 CTI repo
- **[UC-23 Synthetic Detection Testing Data](../use-cases/rule-content-engineering/23-synthetic-detection-testing-data.md)** — relate to proposed UC-26 (Atomic Test CI loop) — UC-23 generates logs, UC-26 orchestrates real execution

### Concept docs
- **[adversarial-ai-considerations.md](../concepts/adversarial-ai-considerations.md)** — add **Attack 9: LLM Call-out Malware** (PROMPTFLUX, PROMPTSTEAL from Mandiant M-Trends 2026); this is detection content about LLM-callout traffic from non-developer hosts
- **[validation-harness.md](../concepts/validation-harness.md)** — reference CTI-REALM as the public benchmark for end-to-end rule generation evaluation; reference CyberSOCEval and Simbian AI in the SOC Benchmark
- **[where-ai-fails.md](../concepts/where-ai-fails.md)** — calibration discussion should cite AIDR and Decision-Aware Trust Signal Alignment papers

### Reference docs
- **[references/vendor-landscape.md](../references/vendor-landscape.md)** — substantial Q1-Q2 2026 update needed; specifically: Microsoft (Sentinel MCP, Migration Experience, Defender consolidation), Splunk Detection Studio + agent fleet, Cortex AgentiX, Charlotte AgentWorks, Purple AI Auto Investigations, Google TIN, Lakewatch (new entrant), Sublime ADÉ, AiStrike, Tracecat, Andesite FedRAMP, Tines AI Interaction Layer; new vendor funding rounds (Prophet, Dropzone, Qevlar, Torq, 7AI)
- **[references/tools-and-projects.md](../references/tools-and-projects.md)** — add: CTI-REALM benchmark, agentshield-ai/sigma-ai, SigmAIQ, LimaCharlie MCP server, Panther MCP server, Sentinel MCP server, Tracecat, Sigma Assistant, STRIDE-GPT
- **[references/reading-list.md](../references/reading-list.md)** — add: OWASP Agentic Top 10 2026, MITRE ATLAS v5.4.0, MITRE ATT&CK v18 release notes, NIST IR 8596 Cyber AI Profile, NIST COSAiS, CSA AICM, EU AI Act Aug 2026 enforcement guidance, M-Trends 2026, CTI-REALM paper, AIDR paper, Anton Chuvakin's RSA 2026 retrospective

### Operations docs
- **[governance-mapping.md](governance-mapping.md)** — significant updates: NIST IR 8596 Cyber AI Profile (the "Defend" focus area is the relevant lens for DE), NIST COSAiS (when overlay drafts publish), CSA AICM mapping, EU AI Act Article 15 logging requirements, ISO 42001 (CrowdStrike now certified, vendor signal)
- **[deployment-roadmap.md](deployment-roadmap.md)** — add notes on which use cases now have viable commercial alternatives so teams can decide build-vs-buy per use case

### Correlation rules
- **[correlation-rules/cross-rule-deduplication.md](../correlation-rules/cross-rule-deduplication.md)** — reference Sentinel graph (preview) as a vendor implementation of cross-rule entity grouping
- Consider whether the catalog should add explicit Tier 7 rules for **AI agent telemetry correlation** (cross-tool calls, MCP-server cross-references, A2A integrity) — would pair with proposed UC-25

---

## Build vs. Buy Decision Guidance (New)

The vendor reality demands an explicit build-vs-buy lens per use case. A starter framework:

| Use Case | Buy if... | Build (use this repo) if... |
|---|---|---|
| UC-11 Triage Verdicts | Single SIEM platform; willing to be locked into vendor decisions | Multi-SIEM environment; need transparency in verdict reasoning; need calibration measurement |
| UC-13 NL Alert Query | Single SIEM | Federated query across multiple platforms |
| UC-14 Agentic Investigation | Tier-1 SIEM + budget for vendor agent | Need read-only / audit-heavy investigation flow; multi-platform |
| UC-15 Investigation Guides | Want it inline in console | Need bulk backfill across rule corpus; want guides in version-controlled repo |
| UC-19 Rule Generation | Single platform; willing to accept vendor opinion | Multi-platform output (Sigma + multiple SIEMs); need rigorous validation harness |
| UC-06 Posture Scoring | Splunk shop (Detection Studio) or Sentinel shop (MCP Graph Tool) | Multi-platform; need vendor-neutral methodology |

Add this as a section in the deployment roadmap.

---

## What's Out of Scope (Confirmed)

Things this research surfaced that are clearly Tier-2 (future companion repos), not detection-engineering:

- **Continuous autonomous threat hunting** (Dropzone Threat Hunter, Prophet, Simbian Threat Hunt Agent) → AI for Threat Hunting
- **Autonomous hunt-pack authoring from CVEs** (Dropzone Threat Intel Analyst) → AI for Threat Hunting
- **Forensic / malware-grade investigation** (Intezer's heritage; SentinelOne Auto Investigations) → AI for Malware & Forensics
- **Autonomous adversary emulation** (Skyhawk autonomous red team, Simbian AI Pentest Agent) → AI for Adversary Emulation
- **NL-to-SOAR-playbook generation** (Torq Agentic Builder, Splunk Automation Builder Agent, AgentiX Automation Engineer Agent) → AI for Incident Response (some overlap with DE — bordering case)

UC-26 (Continuous Detection Validation) sits at the boundary with adversary emulation. It's included in DE because the *purpose* is detection coverage assessment, not red-team operations.

---

## Sources (Selected)

Primary research sources that informed this review. Full citation list in agent reports preserved in conversation history.

### Vendors
- [Prophet Security $30M Series A](https://www.prophetsecurity.ai/blog/prophet-security-raises-30-million-series-a-led-by-accel)
- [Dropzone AI Threat Hunter](https://www.helpnetsecurity.com/2026/03/18/dropzone-ai-ai-threat-hunting/)
- [Qevlar AI $30M raise](https://www.businesswire.com/news/home/20260310058427/en/Qevlar-AI-Raises-30M-to-Shift-Security-Operations)
- [Conifers CognitiveSOC March 2026](https://www.prnewswire.com/news-releases/conifers-expands-cognitivesoc-302718780.html)
- [Intezer AI SOC Platform expansion](https://www.helpnetsecurity.com/2026/03/19/intezer-ai-soc-platform-expanded-capabilities/)
- [Torq Agentic Builder launch](https://torq.io/news/agentic-builder/)
- [Tines AI Interaction Layer](https://siliconangle.com/2026/01/15/tines-launches-ai-interaction-layer/)
- [Andesite FedRAMP High](https://www.prnewswire.com/news-releases/andesite-achieves-fedramp-high-302729588.html)
- [Microsoft Sentinel RSAC 2026](https://techcommunity.microsoft.com/blog/microsoftsentinelblog/whats-new-in-microsoft-sentinel-rsac-2026/4503971)
- [Microsoft AI-Powered SIEM Migration](https://techcommunity.microsoft.com/blog/microsoftsentinelblog/accelerate-your-move-to-microsoft-sentinel/4488505)
- [Cortex AgentiX](https://www.paloaltonetworks.com/cortex/agentix)
- [Splunk Enterprise Security RSAC 2026](https://www.splunk.com/en_us/blog/security/from-reactive-to-agentic-with-enterprise-security-at-rsac-2026.html)
- [CrowdStrike Charlotte AI AgentWorks](https://www.crowdstrike.com/en-us/press-releases/crowdstrike-launches-charlotte-ai-agentworks-ecosystem/)
- [SentinelOne Purple AI Auto Investigations](https://www.sentinelone.com/press/sentinelone-unveils-new-ai-security-offerings/)
- [Google TIN trial](https://docs.cloud.google.com/chronicle/docs/agentic-soc/trial)
- [Exabeam ABA](https://www.exabeam.com/blog/company-news/whats-new-in-new-scale-april-2026-securing-the-agentic-enterprise/)
- [Databricks Lakewatch launch](https://www.databricks.com/company/newsroom/press-releases/databricks-enters-security-market-launch-lakewatch-new-open-agentic)
- [Panther AI SOC Platform GA](https://siliconangle.com/2026/03/19/panther-rolls-ai-soc-platform-agents-learn-improve-time/)
- [LimaCharlie agentic MDR pipeline](https://limacharlie.io/blog/agentic-mdr-pipeline-detection-engineering-at-scale)
- [Hunters Pathfinder AI](https://www.hunters.security/pathfinder-ai)
- [Sublime Security ADÉ](https://www.msspalert.com/news/sublime-security-unveils-ai-agent-to-cut-email-threat-detection-from-weeks-to-hours)
- [SOC Prime Uncoder AI v2](https://socprime.com/blog/uncoder-ai-automates-cross-language-rule-translation-with-hybrid-ai/)
- [CardinalOps Cardinal AI](https://cardinalops.com/blog/introducing-cardinal-ai-agentic-exposure-management/)
- [Anvilogic Blueprints](https://www.helpnetsecurity.com/2026/03/23/anvilogic-blueprints/)

### Standards & frameworks
- [MITRE ATLAS](https://atlas.mitre.org/)
- [MITRE ATT&CK v18 Detection Strategies (Cymulate)](https://cymulate.com/blog/mitre-attack-v18/)
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [NIST IR 8596 Cyber AI Profile preliminary draft](https://csrc.nist.gov/pubs/ir/8596/iprd)
- [NIST 800-53 COSAiS overlays](https://csrc.nist.gov/projects/cosais)
- [CSA AI Controls Matrix (AICM)](https://cloudsecurityalliance.org/artifacts/ai-controls-matrix)
- [EU AI Act 2026 enforcement (Help Net Security)](https://www.helpnetsecurity.com/2026/04/16/eu-ai-act-logging-requirements/)
- [NSA AI Supply Chain Guidance (Mar 2026)](https://www.logistics-concepts.com/news/digital-supply-chain-nsa-warns-ai-risks-executive-summary-action-plan/)
- [Mandiant M-Trends 2026](https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026)
- [Gartner 2026 Cybersecurity Trends](https://www.gartner.com/en/newsroom/press-releases/2026-02-05-gartner-identifies-the-top-cybersecurity-trends-for-2026)

### Research papers
- [Microsoft CTI-REALM blog](https://www.microsoft.com/en-us/security/blog/2026/03/20/cti-realm-a-new-benchmark/)
- [arXiv RulePilot](https://arxiv.org/html/2511.12224)
- [arXiv CORTEX](https://arxiv.org/html/2510.00311v1)
- [arXiv AIDR](https://arxiv.org/html/2512.08169)
- [arXiv FedGraph-AGI](https://arxiv.org/abs/2602.16109)
- [arXiv Decision-Aware Trust Signal Alignment](https://arxiv.org/abs/2601.04486)

### Industry analysis
- [Anton Chuvakin RSA 2026 retrospective](https://medium.com/anton-on-security/rsa-2026-agentic-future-analog-fundamentals-bf93e81eaaa6)
- [Help Net Security: AI SOC vendor reality check](https://www.helpnetsecurity.com/2026/03/26/future-ai-soc-vendor-claims/)
- [Crogl 2026 State of SecOps](https://www.crogl.com/newsroom/state-of-secops-ai)
- [SANS State of Detection Engineering 2026](https://www.sans.org/webcasts/state-detection-engineering-2026)

---

## When to Refresh This Review

- **Quarterly**: scan for new vendor entrants, new funding rounds, new product GAs
- **On any major framework release**: ATT&CK, ATLAS, OWASP, NIST AI RMF profiles
- **On any regulatory enforcement milestone**: EU AI Act Aug 2026, US executive orders, sector-specific mandates
- **At minimum**: every six months, regardless of external triggers

The next refresh should target ~Oct 2026 to capture the EU AI Act enforcement aftermath, MITRE ATT&CK v19, and NIST COSAiS overlay drafts.
