# Tools & Projects

Open source tools and projects relevant to AI-assisted detection engineering, organized by category. **Refreshed April 2026.**

---

## Detection Rule Repositories

| Project | Description | Link |
|---|---|---|
| **SigmaHQ/sigma** | Platform-agnostic detection rules in Sigma YAML format. The largest community-maintained detection rule repository. Rules map to MITRE ATT&CK and cover Windows, Linux, cloud, and application log sources. 2026: Sigma Assistant uses OpenAI to auto-generate Title and Description from Detection block. | [github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) |
| **elastic/detection-rules** | Elastic Security detection rules in TOML format. Includes KQL, EQL, and ES\|QL queries with MITRE mappings. Maintained by Elastic's Threat Research team. 1,300+ prebuilt detections (2026). | [github.com/elastic/detection-rules](https://github.com/elastic/detection-rules) |
| **splunk/security_content** | Splunk Security Content — detection rules (SPL), analytic stories, playbooks, and macros for Splunk Enterprise Security. Organized by MITRE ATT&CK and analytic story. ESCU 5.22 (2026) added MCP detection content. | [github.com/splunk/security_content](https://github.com/splunk/security_content) |
| **agentshield-ai/sigma-ai** | **2026 — community starter content for AI-agent attacks.** Sigma rules with `product: ai_agent` covering prompt injection, MCP tool poisoning, agent identity abuse, credential access via agents. Reference content for [UC-25](../use-cases/rule-content-engineering/25-ai-agent-mcp-detection.md). | [github.com/agentshield-ai/sigma-ai](https://github.com/agentshield-ai/sigma-ai) |

---

## Detection Engineering Tools

| Project | Description | Link |
|---|---|---|
| **SigmaHQ/pySigma** | Python library for processing and converting Sigma rules to platform-specific queries (Elastic, Splunk, Sentinel, etc.). Backend plugin architecture supports custom target platforms. The deterministic floor that any AI translation must beat. | [github.com/SigmaHQ/pySigma](https://github.com/SigmaHQ/pySigma) |
| **AttackIQ/SigmAIQ** | **LangChain + pySigma + LLM toolkit.** Vector embeddings of Sigma rules for similarity search; LLM agents for translation and reverse-translation (backend query → Sigma). Most mature open-source pySigma+LLM project. | [github.com/AttackIQ/SigmAIQ](https://github.com/AttackIQ/SigmAIQ) |
| **LOLRMM** | Living Off the Land RMM — reference of legitimate Remote Monitoring and Management tools abused by attackers. Useful for building detection rules targeting dual-use RMM software. | [lolrmm.io](https://lolrmm.io/) |
| **LOLBAS** | Living Off the Land Binaries and Scripts — companion reference for legitimate Windows binaries abused by attackers. | [lolbas-project.github.io](https://lolbas-project.github.io/) |
| **SOC Prime Sigma Rules / Uncoder.IO** | Community-contributed detection rules in Sigma format on the Threat Detection Marketplace; Uncoder.IO open-source IDE for cross-SIEM detection translation (10+ source / 21+ target). | [socprime.com](https://socprime.com/) / [uncoder.io](https://uncoder.io/) / [github.com/UncoderIO/Uncoder_IO](https://github.com/UncoderIO/Uncoder_IO) |
| **TracecatHQ/tracecat** | **Open-source AI-native SOAR.** Python-based detection logic, sandboxed agent execution (nsjail), prompt-to-automation generation. Build-vs-buy alternative for teams that want detection-as-code with agent execution they own. | [github.com/TracecatHQ/tracecat](https://github.com/TracecatHQ/tracecat) |

---

## ATT&CK Mapping & Visualization

| Project | Description | Link |
|---|---|---|
| **MITRE ATT&CK** | The ATT&CK knowledge base. v18 (Oct 2025) introduced Detection Strategies + Analytics, replacing legacy Detections + Data Sources. | [attack.mitre.org](https://attack.mitre.org/) |
| **MITRE ATT&CK Navigator** | Web application for visualizing ATT&CK technique coverage. Create layers showing detection coverage, red team activity, or gap analysis. | [mitre-attack.github.io/attack-navigator](https://mitre-attack.github.io/attack-navigator/) |
| **MITRE ATLAS** | **Adversarial Threat Landscape for AI Systems.** v5.4.0 (Feb 2026) added agentic AI techniques: Tool Poisoning, Escape to Host, AI Service API as C2 (AML.T0096), SesameOp case study (AML.CS0042). Essential for [UC-25](../use-cases/rule-content-engineering/25-ai-agent-mcp-detection.md). | [atlas.mitre.org](https://atlas.mitre.org/) |
| **DeTT&CT** | Detection and Technique Tracking — framework for scoring detection quality and visibility per ATT&CK technique. Generates Navigator layers from YAML data source and detection scoring files. Inspirational reference for [UC-06](../use-cases/posture-assessment/06-mitre-attack-posture-scoring.md). | [github.com/rabobank-cdc/DeTTECT](https://github.com/rabobank-cdc/DeTTECT) |
| **MITRE ATT&CK STIX Data** | Machine-readable ATT&CK data for technique descriptions and procedure examples. | [github.com/mitre-attack/attack-stix-data](https://github.com/mitre-attack/attack-stix-data) |

---

## AI-Assisted Detection Projects

| Project | Description | Link |
|---|---|---|
| **CTI-REALM (Microsoft)** | **Open-source benchmark for end-to-end agent-driven detection rule generation** (Mar 2026). Read CTI → identify techniques → explore telemetry → iterate KQL → emit Sigma + KQL. 37 reports across Linux/AKS/Azure scenarios. Reference methodology for [UC-19](../use-cases/rule-content-engineering/19-detection-rule-generation.md), [UC-21](../use-cases/strategic/21-threat-intelligence-synthesis.md), [validation harness](../concepts/validation-harness.md). | [microsoft.com/en-us/security/blog/2026/03/20](https://www.microsoft.com/en-us/security/blog/2026/03/20/cti-realm-a-new-benchmark-for-end-to-end-detection-rule-generation-with-ai-agents/) |
| **InfoSecJay/sigma-llm-doc** | LLM-generated investigation guides for Sigma rules. Uses Claude to produce structured investigation and triage documentation for each detection rule. | [github.com/InfoSecJay/sigma-llm-doc](https://github.com/InfoSecJay/sigma-llm-doc) |
| **InfoSecJay/sigma-rules-enriched** | Enriched Sigma rule dataset — Sigma rules augmented with additional context, investigation guidance, and metadata using LLM processing. | [github.com/InfoSecJay/sigma-rules-enriched](https://github.com/InfoSecJay/sigma-rules-enriched) |
| **InfoSecJay/threat-detection-explorer** | Detection content exploration tool — web interface for browsing, searching, and analyzing detection rules with enriched metadata. | [github.com/InfoSecJay/threat-detection-explorer](https://github.com/InfoSecJay/threat-detection-explorer) |

---

## MCP Servers for SOC Workflows

The Model Context Protocol (MCP) standardized in 2025 became table-stakes for AI-augmented SOC tooling in 2026. Notable published MCP servers:

| Server | Description | Link |
|---|---|---|
| **Microsoft Sentinel MCP Server** | GA 2026 with multiple tool collections: data exploration, entity analyzer, agent creation, triage. Anthropic Claude has a first-party connector. | [learn.microsoft.com/en-us/azure/sentinel/datalake/sentinel-mcp-overview](https://learn.microsoft.com/en-us/azure/sentinel/datalake/sentinel-mcp-overview) |
| **Panther MCP Server** | Detection rule writing, alert triage, pattern analysis. One of the more mature implementations. | [panther.com/blog/10-your-detection-engineering-workflows-with-mcp](https://panther.com/blog/10-your-detection-engineering-workflows-with-mcp) |
| **LimaCharlie MCP Server** | Documented MCP server for SecOps agentic workflows; powers their daily MDR pipeline. | [docs.limacharlie.io/docs/mcp-server](https://docs.limacharlie.io/docs/mcp-server) |
| **SOC Prime Uncoder MCP** | MCP-server pattern for agentic detection workflows; integrates with Uncoder AI translation. | [socprime.com/uncoder-ai/](https://socprime.com/uncoder-ai/) |
| **Tines MCP** | Tines AI Interaction Layer (Jan 2026): build MCP servers in Tines, AI Agent actions connect to remote MCP servers, tunnel support for private MCP. | [tines.com/docs/actions/templates/mcp-server](https://www.tines.com/docs/actions/templates/mcp-server/) |
| **Wazuh + Jetbalsa OpenSearch MCP** | OpenSearch MCP server for AI-driven hunts; pairs with Wazuh local-LLM threat hunting. | [wazuh.com/blog/leveraging-artificial-intelligence-for-threat-hunting-in-wazuh](https://wazuh.com/blog/leveraging-artificial-intelligence-for-threat-hunting-in-wazuh/) |
| **Anthropic MCP Specification** | The protocol itself. | [modelcontextprotocol.io](https://modelcontextprotocol.io/) |

---

## Threat Modeling for AI Systems

| Tool | Description | Link |
|---|---|---|
| **STRIDE-GPT** | LLM-assisted threat modeling using STRIDE methodology. Active 2026. | [github.com/mrwadams/stride-gpt](https://github.com/mrwadams/stride-gpt) |
| **ASTRIDE** | Agent-aware STRIDE variant for AI systems. Emerging 2026 tooling. | Various community implementations |

---

## Detection-as-Code Pipelines

| Project | Description | Link |
|---|---|---|
| **infosecB/detection-as-code** | Reference Sigma-to-Splunk DaC pipeline; useful template even as ecosystem matures. | [github.com/infosecB/detection-as-code](https://github.com/infosecB/detection-as-code) |
| **Chainguard Actions** | Secure-by-default GitHub Actions catalog with AI agents detecting unsafe patterns; relevant for [UC-31](../use-cases/rule-content-engineering/31-detection-content-provenance.md) detection-as-code repo security. | [chainguard.dev](https://chainguard.dev/) |
| **Sigstore / cosign** | OpenSSF keyless signing infrastructure. Reference signing platform for [UC-31](../use-cases/rule-content-engineering/31-detection-content-provenance.md). | [sigstore.dev](https://www.sigstore.dev/) / [github.com/sigstore/cosign](https://github.com/sigstore/cosign) |

---

## Adversary Emulation & Validation

| Project | Description | Link |
|---|---|---|
| **MITRE CALDERA** | Adversary emulation platform — automates ATT&CK-based adversary behavior for testing detections. Foundation for [UC-26](../use-cases/rule-content-engineering/26-continuous-detection-validation.md). | [github.com/mitre/caldera](https://github.com/mitre/caldera) |
| **Atomic Red Team** | Library of small, portable detection tests mapped to ATT&CK. The canonical test library for [UC-26](../use-cases/rule-content-engineering/26-continuous-detection-validation.md). 1,000+ tests across 200+ techniques. | [github.com/redcanaryco/atomic-red-team](https://github.com/redcanaryco/atomic-red-team) |
| **DataDog/stratus-red-team** | Cloud-native attack simulation. Coverage for AWS, Azure, GCP, Kubernetes. | [github.com/DataDog/stratus-red-team](https://github.com/DataDog/stratus-red-team) |
| **Elastic Detection Rules RTA** | Red Team Automation scripts for Elastic rule testing. | [github.com/elastic/detection-rules/tree/main/rta](https://github.com/elastic/detection-rules/tree/main/rta) |
| **Splunk contentctl** | Splunk's detection content management tool with built-in test capabilities. | [github.com/splunk/contentctl](https://github.com/splunk/contentctl) |

---

## Forensics & Hunting

| Tool | Description | Link |
|---|---|---|
| **Chainsaw** | Fast Windows event log analysis tool. Parses EVTX files against Sigma rules for rapid triage. | [github.com/WithSecureLabs/chainsaw](https://github.com/WithSecureLabs/chainsaw) |
| **Hayabusa** | Windows event log fast forensics timeline generator. Supports Sigma rules and produces MITRE ATT&CK-mapped timelines. | [github.com/Yamato-Security/hayabusa](https://github.com/Yamato-Security/hayabusa) |
| **BloodHound 9.0** | SpecterOps identity attack-path analysis. April 2026: BloodHound 9.0 + OpenGraph extensions for Okta / GitHub / Jamf + BloodHound Scentry (Feb 2026). Identity-attack-path data feeding entity-based detection. | [github.com/SpecterOps/BloodHound](https://github.com/SpecterOps/BloodHound) |

---

## Schema References

| Reference | Description | Link |
|---|---|---|
| **Elastic Common Schema (ECS)** | Field naming and normalization standard used by Elastic. | [elastic.co/guide/en/ecs](https://www.elastic.co/guide/en/ecs/current/index.html) |
| **Splunk Common Information Model (CIM)** | Splunk's data normalization framework. | [docs.splunk.com/Documentation/CIM](https://docs.splunk.com/Documentation/CIM/latest/User/Overview) |
| **Microsoft ASIM** | Advanced Security Information Model — Sentinel's normalization schema. | [learn.microsoft.com/en-us/azure/sentinel/normalization](https://learn.microsoft.com/en-us/azure/sentinel/normalization) |
| **OCSF** | Open Cybersecurity Schema Framework — emerging cross-platform schema. | [schema.ocsf.io](https://schema.ocsf.io/) |

---

## Data Science / ML Libraries

| Library | Use Case | Link |
|---|---|---|
| **Pandas** | Dataframe manipulation for alert data, rule metadata, and analysis results. | [pandas.pydata.org](https://pandas.pydata.org/) |
| **NumPy** | Numerical operations for scoring, statistical analysis, and array manipulation. | [numpy.org](https://numpy.org/) |
| **SciPy** | Statistical functions for anomaly detection, clustering analysis, and threshold calculations. | [scipy.org](https://scipy.org/) |
| **scikit-learn** | Machine learning algorithms — clustering (DBSCAN, K-Means), classification, dimensionality reduction. | [scikit-learn.org](https://scikit-learn.org/) |
| **Anthropic SDK** | Python SDK for the Claude API. Used for LLM-based rule enrichment, alert summarization, and investigation guide generation. | [github.com/anthropics/anthropic-sdk-python](https://github.com/anthropics/anthropic-sdk-python) |
| **OpenAI SDK** | Python SDK for the OpenAI API. | [github.com/openai/openai-python](https://github.com/openai/openai-python) |
| **elasticsearch-py** | Official Python client for Elasticsearch. Used for querying alert indices, rule metadata, and detection results. | [github.com/elastic/elasticsearch-py](https://github.com/elastic/elasticsearch-py) |
| **splunk-sdk** | Splunk SDK for Python. Used for running SPL queries, managing saved searches, and extracting notable events. | [github.com/splunk/splunk-sdk-python](https://github.com/splunk/splunk-sdk-python) |
| **mitreattack-python** | Python library for working with ATT&CK STIX data. | [github.com/mitre-attack/mitreattack-python](https://github.com/mitre-attack/mitreattack-python) |

---

## Eval Frameworks for AI-DE

| Framework | Description | Link |
|---|---|---|
| **promptfoo** | Open-source LLM eval framework with CI integration. Reference framework for [validation harness](../concepts/validation-harness.md). | [promptfoo.dev](https://www.promptfoo.dev/) |
| **LangSmith** | LangChain's observability + eval platform. | [smith.langchain.com](https://smith.langchain.com/) |
| **Braintrust** | LLM evaluation platform with golden-set management. | [braintrust.dev](https://www.braintrust.dev/) |
| **Inspect AI** | UK AISI eval framework; CTI-REALM benchmark uses Inspect-AI. | [inspect.aisi.org.uk](https://inspect.aisi.org.uk/) |
| **OpenAI Evals** | OpenAI's eval framework. | [github.com/openai/evals](https://github.com/openai/evals) |
