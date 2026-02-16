# Tools & Projects

Open source tools and projects relevant to AI-assisted detection engineering, organized by category.

---

## Detection Rule Repositories

| Project | Description | Link |
|---|---|---|
| **SigmaHQ/sigma** | Platform-agnostic detection rules in Sigma YAML format. The largest community-maintained detection rule repository. Rules map to MITRE ATT&CK and cover Windows, Linux, cloud, and application log sources. | [github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) |
| **elastic/detection-rules** | Elastic Security detection rules in TOML format. Includes KQL, EQL, and ES\|QL queries with MITRE mappings. Maintained by Elastic's Threat Research team. | [github.com/elastic/detection-rules](https://github.com/elastic/detection-rules) |
| **splunk/security_content** | Splunk Security Content — detection rules (SPL), analytic stories, playbooks, and macros for Splunk Enterprise Security. Organized by MITRE ATT&CK and analytic story. | [github.com/splunk/security_content](https://github.com/splunk/security_content) |

---

## Detection Engineering Tools

| Project | Description | Link |
|---|---|---|
| **SigmaHQ/pySigma** | Python library for processing and converting Sigma rules to platform-specific queries (Elastic, Splunk, Sentinel, etc.). Backend plugin architecture supports custom target platforms. | [github.com/SigmaHQ/pySigma](https://github.com/SigmaHQ/pySigma) |
| **LOLRMM** | Living Off the Land RMM — reference of legitimate Remote Monitoring and Management tools abused by attackers. Useful for building detection rules targeting dual-use RMM software. | [lolrmm.io](https://lolrmm.io/) |
| **SOC Prime Sigma Rules** | Community-contributed detection rules in Sigma format hosted on SOC Prime's Threat Detection Marketplace (open portion). | [socprime.com](https://socprime.com/) |
| **Uncoder.IO** | Online tool for converting detection rules between SIEM formats (Sigma, Splunk SPL, KQL, etc.). | [uncoder.io](https://uncoder.io/) |

---

## ATT&CK Mapping & Visualization

| Project | Description | Link |
|---|---|---|
| **MITRE ATT&CK Navigator** | Web application for visualizing ATT&CK technique coverage. Create layers showing detection coverage, red team activity, or gap analysis. Export/import JSON layers for sharing. | [mitre-attack.github.io/attack-navigator](https://mitre-attack.github.io/attack-navigator/) |
| **DeTT&CT** | Detection and Technique Tracking — framework for scoring detection quality and visibility per ATT&CK technique. Generates Navigator layers from YAML data source and detection scoring files. | [github.com/rabobank-cdc/DeTTECT](https://github.com/rabobank-cdc/DeTTECT) |
| **MITRE ATT&CK** | The ATT&CK knowledge base itself. Tactics, techniques, procedures, software, and groups. The standard taxonomy referenced by detection rules across all platforms. | [attack.mitre.org](https://attack.mitre.org/) |

---

## AI-Assisted Detection Projects

| Project | Description | Link |
|---|---|---|
| **InfoSecJay/sigma-llm-doc** | LLM-generated investigation guides for Sigma rules. Uses Claude to produce structured investigation and triage documentation for each detection rule. | [github.com/InfoSecJay/sigma-llm-doc](https://github.com/InfoSecJay/sigma-llm-doc) |
| **InfoSecJay/sigma-rules-enriched** | Enriched Sigma rule dataset — Sigma rules augmented with additional context, investigation guidance, and metadata using LLM processing. | [github.com/InfoSecJay/sigma-rules-enriched](https://github.com/InfoSecJay/sigma-rules-enriched) |
| **InfoSecJay/threat-detection-explorer** | Detection content exploration tool — web interface for browsing, searching, and analyzing detection rules with enriched metadata. | [github.com/InfoSecJay/threat-detection-explorer](https://github.com/InfoSecJay/threat-detection-explorer) |

---

## Data Science / ML Libraries

| Library | Use Case | Link |
|---|---|---|
| **Pandas** | Dataframe manipulation for alert data, rule metadata, and analysis results. Core dependency for any detection data pipeline. | [pandas.pydata.org](https://pandas.pydata.org/) |
| **NumPy** | Numerical operations for scoring, statistical analysis, and array manipulation. | [numpy.org](https://numpy.org/) |
| **SciPy** | Statistical functions for anomaly detection, clustering analysis, and threshold calculations. | [scipy.org](https://scipy.org/) |
| **scikit-learn** | Machine learning algorithms — clustering (DBSCAN, K-Means), classification, dimensionality reduction (PCA, t-SNE), and model evaluation. | [scikit-learn.org](https://scikit-learn.org/) |
| **Anthropic SDK** | Python SDK for the Claude API. Used for LLM-based rule enrichment, alert summarization, and investigation guide generation. | [github.com/anthropics/anthropic-sdk-python](https://github.com/anthropics/anthropic-sdk-python) |
| **elasticsearch-py** | Official Python client for Elasticsearch. Used for querying alert indices, rule metadata, and detection results. | [github.com/elastic/elasticsearch-py](https://github.com/elastic/elasticsearch-py) |
| **splunk-sdk** | Splunk SDK for Python. Used for running SPL queries, managing saved searches, and extracting notable events. | [github.com/splunk/splunk-sdk-python](https://github.com/splunk/splunk-sdk-python) |

---

## Other Useful Tools

| Tool | Description | Link |
|---|---|---|
| **MITRE CALDERA** | Adversary emulation platform — automates ATT&CK-based adversary behavior for testing detections. | [github.com/mitre/caldera](https://github.com/mitre/caldera) |
| **Atomic Red Team** | Library of small, portable detection tests mapped to ATT&CK. Useful for validating that detection rules fire as expected. | [github.com/redcanaryco/atomic-red-team](https://github.com/redcanaryco/atomic-red-team) |
| **Chainsaw** | Fast Windows event log analysis tool. Parses EVTX files against Sigma rules for rapid triage. | [github.com/WithSecureLabs/chainsaw](https://github.com/WithSecureLabs/chainsaw) |
| **Hayabusa** | Windows event log fast forensics timeline generator. Supports Sigma rules and produces MITRE ATT&CK-mapped timelines. | [github.com/Yamato-Security/hayabusa](https://github.com/Yamato-Security/hayabusa) |
