# UC-02: Entity Cardinality Noise Analysis

## Category

Alert Analysis

## Summary

Use an LLM to interpret entity cardinality patterns in the context of what a detection rule is actually trying to detect. The SIEM computes unique counts and top-N entity distributions — that is a solved problem. The AI reads those distributions alongside the rule's intent and reasons about whether observed entities are expected, anomalous, or symptomatic of a tuning gap. Optional embedding-based clustering can group semantically similar entities (e.g., near-identical command lines) that deterministic exact-match aggregations miss.

## Problem Statement

Entity cardinality is the single most informative proxy for detection signal quality when analyst disposition data is unavailable. A rule that fires 10,000 times across 3 unique users is almost certainly noisy. A rule that fires 10,000 times across 7,500 unique users may be detecting a real, widespread condition.

But cardinality alone is not enough. The interpretation depends on context:

- A brute-force detection rule firing on 3 unique `source.ip` values might be *exactly correct* — a focused attack from a small number of IPs. The same 3-IP pattern on a "rare external connection" rule is noise — it is the same 3 scanners hitting every organization on the internet.
- A process creation rule with 500 unique `process.command_line` values sounds diverse, but if 480 of those are trivial variations of the same SCCM deployment command (differing only in a GUID or timestamp), the effective cardinality is much lower than the raw count suggests.
- A DNS rule with 10,000 unique `dns.question.name` values could be a real DNS tunneling campaign (high entropy, algorithmically generated) or normal CDN traffic (high cardinality but entirely benign). The cardinality number is identical; the meaning is opposite.

The SIEM tells you the numbers. It does not tell you what they mean for a specific rule's detection purpose. That is the gap AI fills.

Additionally, different data source domains have fundamentally different entity fields. A network firewall rule's "entities" are IPs and ports. An endpoint process rule's "entities" are users, hosts, processes, and command lines. A cloud identity rule's "entities" are user principals, applications, and tenant IDs. Applying the right entity framework to the right domain is essential — and managing this across 50+ data source domains and 4,000+ rules requires systematization.

## Prerequisites (What Your SIEM/SOAR Should Already Handle)

- **Cardinality aggregation per field**: `cardinality()` (Elastic), `dc()` (Splunk), `dcount()` (KQL) on every entity-relevant field for every rule. This is the foundational query. Example in Elastic:
  ```json
  {
    "aggs": {
      "by_rule": {
        "terms": { "field": "rule.id", "size": 5000 },
        "aggs": {
          "unique_users": { "cardinality": { "field": "user.name" } },
          "unique_hosts": { "cardinality": { "field": "host.name" } },
          "unique_src_ips": { "cardinality": { "field": "source.ip" } },
          "unique_processes": { "cardinality": { "field": "process.name" } }
        }
      }
    }
  }
  ```
- **Top-N entity concentration**: Terms aggregation returning the top 10-25 entities per field with count and percentage of total. This is the distribution shape — not just "how many unique" but "how concentrated."
- **Alert-to-entity ratio**: Volume divided by cardinality per field. Pre-compute this as a derived metric.
- **Cross-field entity co-occurrence**: For a given rule, do the same 3 users always appear on the same 2 hosts? Or do 3 users each appear on different hosts? This is a multi-field terms aggregation or a composite aggregation.
- **Entity persistence over time**: Does the same entity dominate volume consistently (every day for 30 days) or was it a burst? Date histogram sub-aggregated by entity shows this.

## Where AI Adds Value

### 1. Contextual Entity Interpretation

The AI reads the rule's description, MITRE mapping, and data source domain alongside entity metrics and reasons about whether the observed entity pattern matches the rule's intent.

Example reasoning: "Rule `siem-rule-00312` detects 'Unusual Parent-Child Process Relationship.' It has 14,000 alerts in 30 days with only 2 unique `process.parent.name` values: `wmiprvse.exe` (82%) and `services.exe` (18%). For a rule designed to detect *unusual* parent processes, having 98%+ volume from two of the most common parent processes in Windows indicates the rule's definition of 'unusual' is miscalibrated — these parent processes are entirely expected in enterprise environments."

### 2. Semantic Entity Clustering

Raw `process.command_line` cardinality can be misleading. Two command lines:
```
C:\Windows\System32\schtasks.exe /Create /TN "UpdateCheck-{3a7f2b1c}" /TR "powershell.exe -ep bypass -f C:\ProgramData\update.ps1" /SC DAILY
C:\Windows\System32\schtasks.exe /Create /TN "UpdateCheck-{8e4d9f2a}" /TR "powershell.exe -ep bypass -f C:\ProgramData\update.ps1" /SC DAILY
```
These are "different" by exact string matching but semantically identical — they differ only in a GUID. The SIEM counts them as 2 unique command lines. Embedding-based clustering groups them as 1 effective pattern.

This matters at scale: a rule with 500 unique command lines might have only 12 effective patterns after semantic clustering, revealing that apparent diversity is actually repetition with trivial variation.

### 3. Domain-Aware Entity Framework Application

The AI applies the appropriate entity framework based on data source domain, rather than naively computing cardinality on all fields for all rules. It knows that for a `cloud.azure_ad` rule, the relevant entities are `user.principal_name`, `application.id`, and `azure.audit.operation_name` — not `host.name` or `process.name`.

### 4. Safe-to-Exclude Reasoning

Given the top-N entity list, the AI assesses each entity's excludability: "The entity `svc_backup` is a service account appearing in 91% of alerts for a file-deletion detection rule. Excluding it would eliminate the majority of noise. However, backup service accounts are a known target for ransomware operators who abuse legitimate backup tools. Risk assessment: MEDIUM. Recommend conditional exclusion — exclude only when `process.executable` matches the known backup software path, not a blanket user exclusion."

## AI Approach

**Primary method**: LLM prompting with structured entity metric data and rule context.

**Optional enhancement**: Embedding-based clustering for high-cardinality string fields (command lines, URLs, file paths).

### LLM Prompting Component

The prompt structure:

1. **Domain context**: Provide the data source domain, its typical entity fields, and what "normal" cardinality patterns look like for this domain. This can be a static reference document included in the system prompt.

2. **Rule context**: Rule name, description, MITRE technique, severity, data source.

3. **Entity metrics**: Full cardinality data, top-N distributions, alert-to-entity ratios, cross-field co-occurrence, temporal persistence.

4. **Task**: "Analyze the entity distribution for this rule. Assess whether the observed entities are expected given the rule's detection intent. Identify entities that are likely noise sources. For each potential noise entity, assess whether exclusion is safe or could mask genuine threats. Assign a confidence level to each assessment."

### Embedding Clustering Component (Optional)

For fields like `process.command_line`, `url.full`, `file.path`, or `dns.question.name`:

1. Extract all unique values from the rule's alert data.
2. Generate embeddings using a text embedding model (e.g., `text-embedding-3-small` or a local model like `all-MiniLM-L6-v2`).
3. Cluster embeddings using DBSCAN or HDBSCAN (density-based, no need to specify cluster count).
4. Report effective cardinality (number of clusters) alongside raw cardinality.
5. Provide representative examples from each cluster to the LLM for interpretation.

This is a pre-processing step that feeds into the LLM analysis — it is not a standalone AI output.

## Data Requirements

### Inputs

| Data Element | Source | Computation | Notes |
|---|---|---|---|
| Entity cardinality per field | SIEM alert index | `cardinality()` grouped by `rule.id` | One value per entity field per rule |
| Top-N entities per field | SIEM alert index | `terms` agg, top 25, with count + pct | Shows distribution shape |
| Alert-to-entity ratio | Derived | Volume / cardinality per field | Pre-computed |
| Cross-field co-occurrence | SIEM alert index | Composite aggregation on entity field pairs | E.g., user+host combinations |
| Entity temporal persistence | SIEM alert index | Date histogram sub-agged by entity (top 5) | Shows whether top entities are constant or bursty |
| Rule metadata | Rule repository | Name, description, MITRE mapping, severity, data source domain | Required for intent-based reasoning |
| Domain entity framework | Configuration | Mapping of data source domain to relevant entity fields | Static reference, maintained by detection engineering |
| Raw entity values (for clustering) | SIEM alert index | Full unique value list for high-cardinality string fields | Only needed if embedding clustering is used |

### Domain-Aware Entity Framework Reference

This mapping defines which entity fields are meaningful for each data source domain. The AI uses this to focus its analysis on the right fields.

| Data Source Domain | Primary Entities | Secondary Entities | Notes |
|---|---|---|---|
| endpoint.process | `user.name`, `host.name`, `process.name`, `process.command_line` | `process.parent.name`, `process.executable`, `process.hash` | Command line is high-cardinality — consider clustering |
| endpoint.file | `user.name`, `host.name`, `file.path`, `file.name` | `process.name` (the writing process) | File paths often need normalization |
| endpoint.registry | `user.name`, `host.name`, `registry.path` | `process.name` (the modifying process) | Registry paths can be parameterized |
| network.firewall | `source.ip`, `destination.ip`, `destination.port` | `network.protocol`, `source.geo.country` | IP cardinality is the primary signal |
| network.dns | `dns.question.name`, `source.ip` | `dns.question.type`, `dns.response_code` | Domain names may need clustering for DGA detection |
| network.proxy | `url.domain`, `source.ip`, `user.name` | `url.path`, `http.request.method` | URL paths are high-cardinality |
| cloud.azure_ad | `user.principal_name`, `azure.audit.operation_name`, `application.id` | `source.ip`, `azure.audit.result` | Focus on identity and operation |
| cloud.aws | `aws.cloudtrail.user_identity.arn`, `aws.cloudtrail.event_name`, `cloud.region` | `source.ip`, `aws.cloudtrail.request_parameters` | ARN cardinality is key |
| email.gateway | `email.from.address`, `email.to.address`, `email.subject` | `email.attachments.file.name`, `source.ip` | Subject lines need clustering |
| identity.authentication | `user.name`, `source.ip`, `event.outcome` | `user.domain`, `authentication.method` | Failed vs. success ratio matters alongside cardinality |

### Outputs

**Per-Rule Entity Analysis Report**

```
## Entity Analysis: Rare Scheduled Task Created (siem-rule-00673)
**Data Source Domain**: endpoint.process
**30d Volume**: 3,412 | **Entity Summary**: Low user diversity, moderate host diversity

### Entity Breakdown

| Entity Field | Cardinality | Alert:Entity Ratio | Assessment |
|---|---|---|---|
| user.name | 6 | 568:1 | LOW diversity — investigate |
| host.name | 89 | 38:1 | MODERATE diversity — reasonable |
| process.command_line | 312 (raw) / 18 (clustered) | 11:1 (raw) / 190:1 (clustered) | MISLEADING raw cardinality |

### Top Entity Analysis

**user.name distribution:**
- `SYSTEM` — 2,890 alerts (84.7%) — **Expected.** Scheduled tasks created by the
  SYSTEM account are overwhelmingly legitimate (software installers, Group Policy,
  management tools). This entity is a strong exclusion candidate with LOW risk.
- `svc_deploy` — 310 alerts (9.1%) — **Expected.** Deployment service account.
  Consistent daily presence over 30 days. Low risk exclusion.
- `admin_jpark` — 112 alerts (3.3%) — **Investigate.** Admin account creating
  scheduled tasks. Could be legitimate admin activity or could be persistence
  mechanism. Entity appears on 4 different hosts. NOT safe to exclude without review.
- `contractor_mli` — 58 alerts (1.7%) — **Investigate.** Contractor account creating
  scheduled tasks across 12 hosts over 3 days (Feb 1-3), then stops. Bursty pattern
  with wide host spread. Warrants investigation regardless of tuning decision.
- `helpdesk_tsmith` — 27 alerts (0.8%) — **Likely benign.** Helpdesk account, tasks
  created on unique hosts (1:1 ratio), consistent with remote support workflows.
- `jdoe` — 15 alerts (0.4%) — **Anomalous.** Standard user account. Users should
  rarely create scheduled tasks. All 15 alerts on a single host over 2 days.
  Recommend investigation.

### Command Line Clustering Results

Raw cardinality: 312 unique command lines.
After semantic clustering: 18 distinct patterns.

| Cluster | Representative Example | Count | Pattern Description |
|---|---|---|---|
| 1 | `schtasks /create /tn "GoogleUpdate-{GUID}" /tr "C:\Program Files\Google\..." /sc daily` | 1,240 | Google Chrome auto-update. Varies by GUID only. |
| 2 | `schtasks /create /tn "SccmTask-{GUID}" /tr "C:\Windows\ccmcache\..." /sc once` | 890 | SCCM deployment tasks. Varies by GUID and cache path. |
| 3 | `schtasks /create /tn "Backup-Weekly" /tr "C:\Scripts\backup.ps1" /sc weekly` | 310 | Backup scripts. Consistent string. |
| ... | ... | ... | ... |
| 17 | `schtasks /create /tn "WindowsUpdate" /tr "powershell -ep bypass -e [base64]" /sc daily` | 15 | **SUSPICIOUS.** Encoded PowerShell, masquerading as Windows Update. All from user jdoe. |
| 18 | `schtasks /create /tn "SysHealth" /tr "C:\Users\contractor_mli\AppData\Local\Temp\svc.exe" /sc onlogon` | 8 | **SUSPICIOUS.** Executable in user temp directory, persistence via onlogon trigger. From contractor_mli. |

### Assessment Summary

This rule's raw metrics suggest moderate noise (3,412 alerts, 6 users). Entity
analysis reveals a clear separation: 93.8% of volume is attributable to SYSTEM and
svc_deploy (safe to exclude). The remaining 6.2% (212 alerts) contains genuinely
interesting signals, including 2 command line clusters that warrant investigation
as potential persistence mechanisms. Effective signal-to-noise ratio after tuning
would improve from approximately 1:16 to approximately 1:9.
```

## Implementation Notes

- **Domain entity framework is a configuration artifact**: The mapping of data source domains to entity fields should be maintained as a configuration file, not hard-coded in prompts. As new data sources are onboarded, the framework is extended. The AI consumes this configuration at analysis time.

- **Clustering is optional but high-value for specific fields**: Not every entity field benefits from embedding-based clustering. It is most valuable for `process.command_line`, `url.full`, `file.path`, `dns.question.name`, and `email.subject` — fields with high raw cardinality where trivial variations inflate the unique count. For fields like `user.name`, `source.ip`, and `host.name`, raw cardinality is already meaningful.

- **Clustering cost and latency**: Embedding 10,000 unique command lines with `text-embedding-3-small` costs fractions of a cent and takes seconds. DBSCAN clustering on the resulting vectors is sub-second for typical volumes. This is not a performance bottleneck.

- **Entity persistence over time changes the interpretation**: An entity that appears in 30 out of 30 days is a steady-state condition (tuning target). An entity that appears in 2 out of 30 days is a burst (investigation target). The same entity cardinality number can mean very different things depending on temporal distribution. Always include temporal persistence data in the AI prompt.

- **Cross-field co-occurrence reveals entity "profiles"**: If user `jdoe` always appears on host `WS-FINANCE-04` and always runs `powershell.exe`, that is one behavioral profile. If `jdoe` appears on 15 different hosts running 8 different processes, that is a very different profile. The AI should receive co-occurrence data to reason about entity behavior holistically, not field by field in isolation.

- **Batch by data source domain, not alphabetically**: When batching rules for analysis, group by data source domain. This allows the system prompt to include the relevant entity framework section once, and the LLM can apply consistent domain knowledge across the batch.

## Dependencies

- SIEM platform with cardinality, terms, and composite aggregation capabilities
- Rule metadata with data source domain classification
- Domain-aware entity framework configuration file
- LLM API access (standard context window sufficient — per-rule analysis is not token-heavy)
- (Optional) Text embedding model for entity clustering — cloud API or local model
- (Optional) Clustering library (scikit-learn DBSCAN/HDBSCAN) for embedding post-processing

## Complexity Assessment

| Dimension | Rating | Notes |
|---|---|---|
| Overall | Medium | Core analysis is LLM prompting with structured data. Embedding clustering adds modest complexity if used. |
| Data pipeline | Medium | Requires cardinality and terms aggregations per rule per entity field. Query count scales linearly with rules x fields. Pre-compute and store. |
| Prompt engineering | Medium | The domain entity framework and intent-based reasoning require carefully constructed prompts. The AI must understand what "expected" means for each rule type. |
| AI integration | Low-Medium | LLM prompting is straightforward. Embedding clustering (if used) adds a second model and a clustering step, but both are well-understood patterns. |
| Output validation | Medium | Entity assessments ("safe to exclude" vs. "investigate") must be validated by a human before action. The AI provides reasoning, not decisions. |
| Maintenance | Medium | Domain entity framework must be updated as new data sources are onboarded. Embedding clustering parameters may need tuning for new data types. |

## Real-World Considerations

- **Entity cardinality is a proxy, not ground truth**: Low cardinality strongly suggests noise, but it does not prove it. A targeted attack by a single adversary against a single host will have low entity cardinality across all fields — and it is the highest-value alert in your queue. The AI must be prompted to consider this explicitly: "Low cardinality indicates noise in most cases, but for targeted attack techniques (spear phishing, targeted exploitation), low cardinality may indicate a real, focused threat."

- **Service accounts are the dominant noise source**: Across most enterprise environments, a small number of service accounts (SCCM, Intune, monitoring agents, backup tools, vulnerability scanners) drive the majority of alert noise on endpoint rules. An environment-specific "known service accounts" list included in the prompt dramatically improves AI reasoning accuracy.

- **The "exclude SYSTEM" trap**: Blindly excluding the SYSTEM account from endpoint detection rules removes a massive amount of noise but also blinds you to a significant class of attacks — anything that achieves SYSTEM-level execution (kernel exploits, service abuse, named pipe impersonation). The AI should never recommend a blanket SYSTEM exclusion without qualifying the risk per rule.

- **Cardinality thresholds are environment-specific**: "Low cardinality" means different things in a 500-endpoint environment vs. a 50,000-endpoint environment. The AI needs environment context — total user population, host count, typical daily authentication volume — to calibrate its assessments. Include this as environment metadata in the system prompt.

- **Clustering reveals operational patterns, not just noise**: Semantic clustering of command lines often surfaces legitimate operational patterns that are poorly documented. "We did not know that our SCCM deployment creates 47 variations of this scheduled task command" is a real finding that improves both detection tuning and operational visibility.

## Related Use Cases

- **UC-01 (Detection Performance Analytics)**: Surfaces cardinality metrics at a portfolio level; UC-02 deep-dives into individual rule entity analysis.
- **UC-03 (Automated Rule Tuning Recommendations)**: Consumes UC-02's entity assessments to generate specific exclusion syntax and tuning proposals.
- **UC-05 (Temporal Pattern Detection)**: Entity temporal persistence (steady-state vs. bursty) is a temporal pattern that feeds into both UC-02 and UC-05.

## References

- Elastic: [Cardinality aggregation](https://www.elastic.co/guide/en/elasticsearch/reference/current/search-aggregations-metrics-cardinality-aggregation.html), [Composite aggregation](https://www.elastic.co/guide/en/elasticsearch/reference/current/search-aggregations-bucket-composite-aggregation.html)
- Splunk: [dc() function](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/CommonStatsFunctions), [stats command with multiple aggregations](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Stats)
- Sentinel/KQL: [dcount() aggregation function](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/dcount-aggfunction), [make_set()](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/makeset-aggfunction)
- scikit-learn: [DBSCAN clustering](https://scikit-learn.org/stable/modules/generated/sklearn.cluster.DBSCAN.html) for embedding-based entity grouping
- OpenAI: [Text embeddings](https://platform.openai.com/docs/guides/embeddings) — `text-embedding-3-small` for command line / URL similarity
- Sentence Transformers: [all-MiniLM-L6-v2](https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2) — local alternative for embedding generation
