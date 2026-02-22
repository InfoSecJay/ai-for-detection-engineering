# Enterprise Correlation Rule Catalog

## Purpose

This catalog contains 55 production-ready ES|QL correlation rules for Elastic Security. Each rule aggregates, correlates, and risk-scores alerts from `.internal.alerts-security.alerts-default` — the Kibana security alerts index — to surface multi-signal attack patterns that no single detection rule can identify on its own.

**Why correlation rules matter**: Individual detection rules fire on individual events. An attacker's kill chain spans multiple events across multiple data sources. A single "Suspicious PowerShell Download Cradle" alert is noise. That same alert combined with an Okta impossible-travel alert and a firewall C2-beaconing alert for the same user within four hours is an incident. Correlation rules bridge that gap.

**What these rules are NOT**: These are not AI. They are deterministic SIEM queries. Correlating alerts by shared entities (same user, same host, same IP) within a time window is a query problem — not an AI problem. AI adds value downstream: generating narrative summaries of correlated clusters, reasoning about whether a cluster is malicious or benign, and synthesizing investigation context. This catalog handles the correlation. The AI use cases in this repository (UC-11, UC-12, UC-14) operate on the output of these rules.

**Platform**: Elastic Security 8.x+ with ES|QL support.

---

## Catalog Structure

```
correlation-rules/
├── correlation-rule-catalog.md          ← this file (overview + conventions + deployment guide)
├── audit-report.md                     ← audit findings and remediation status
├── tier1-entity-centric/                ← 8 rules (CORR-1A through CORR-1H)
├── tier2-kill-chain-behavioral/         ← 10 rules (CORR-2A through CORR-2J)
├── tier3-risk-accumulation/             ← 5 rules (CORR-3A through CORR-3E)
├── tier4-meta-correlation/              ← 7 rules (CORR-4A through CORR-4G)
├── tier5-domain-specific/               ← 15 rules (CORR-5A through CORR-5O)
└── tier6-novelty-anomaly/               ← 10 rules (CORR-6A through CORR-6J)
```

Each rule is a standalone markdown file following Elastic's hunting rule documentation format: Metadata, Query, Strategy, Severity Logic, Notes, Data Requirements, Dependencies, Validation, and Elastic Comparison.

---

## Rule Index

### Tier 1: Entity-Centric Correlation (8 rules)

Correlates alerts sharing the same entity (user, host, IP, hash) across multiple detection domains within a time window.

| Rule ID | Name | Join Key | Lookback | Priority |
|---------|------|----------|----------|----------|
| [CORR-1A](tier1-entity-centric/corr_1a_multi_domain_alert_correlation_by_user.md) | Multi-Domain Alert Correlation by User | `user.name` | 4h | P1 |
| [CORR-1B](tier1-entity-centric/corr_1b_multi_domain_alert_correlation_by_host.md) | Multi-Domain Alert Correlation by Host | `host.name` | 4h | P1 |
| [CORR-1C](tier1-entity-centric/corr_1c_multi_domain_alert_correlation_by_source_ip.md) | Multi-Domain Alert Correlation by Source IP | `source.ip` | 4h | P2 |
| [CORR-1D](tier1-entity-centric/corr_1d_multi_domain_alert_correlation_by_destination_ip.md) | Multi-Domain Alert Correlation by Destination IP | `destination.ip` | 4h | P2 |
| [CORR-1E](tier1-entity-centric/corr_1e_multi_domain_alert_correlation_by_process_hash.md) | Multi-Domain Alert Correlation by Process Hash | `process.hash.sha256` | 24h | P2 |
| [CORR-1F](tier1-entity-centric/corr_1f_multi_domain_alert_correlation_by_cloud_resource.md) | Multi-Domain Alert Correlation by Cloud Resource | `cloud.instance.id` | 4h | P2 |
| [CORR-1G](tier1-entity-centric/corr_1g_multi_domain_alert_correlation_by_email_address.md) | Multi-Domain Alert Correlation by Email Address | `user.email` | 24h | P3 |
| [CORR-1H](tier1-entity-centric/corr_1h_service_account_anomaly_correlation.md) | Service Account Anomaly Correlation | `user.name` (svc) | 4h | P2 |

### Tier 2: Kill Chain and Behavioral Correlation (10 rules)

Detects multi-stage attack patterns by correlating alerts that follow known kill chain progressions or behavioral attack sequences.

| Rule ID | Name | Pattern | Lookback | Priority |
|---------|------|---------|----------|----------|
| [CORR-2A](tier2-kill-chain-behavioral/corr_2a_kill_chain_progression_by_host.md) | Kill Chain Progression by Host | Early → Mid → Late tactic scoring | 4h | P1 |
| [CORR-2B](tier2-kill-chain-behavioral/corr_2b_identity_to_endpoint_escalation_chain.md) | Identity-to-Endpoint Escalation Chain | Identity anomaly → endpoint alert | 4h | P1 |
| [CORR-2C](tier2-kill-chain-behavioral/corr_2c_lateral_movement_spread.md) | Lateral Movement Spread | Same user on 3+ hosts | 4h | P2 |
| [CORR-2D](tier2-kill-chain-behavioral/corr_2d_privilege_escalation_chain.md) | Privilege Escalation Chain | Low-priv → admin activity | 4h | P1 |
| [CORR-2E](tier2-kill-chain-behavioral/corr_2e_data_staging_and_exfiltration_sequence.md) | Data Staging and Exfiltration Sequence | Collection → staging → exfil | 6h | P1 |
| [CORR-2F](tier2-kill-chain-behavioral/corr_2f_initial_access_to_execution_pipeline.md) | Initial Access to Execution Pipeline | Initial access → execution | 2h | P1 |
| [CORR-2G](tier2-kill-chain-behavioral/corr_2g_credential_access_escalation.md) | Credential Access Escalation | Multiple credential techniques | 4h | P2 |
| [CORR-2H](tier2-kill-chain-behavioral/corr_2h_defense_evasion_cluster.md) | Defense Evasion Cluster | 3+ evasion techniques | 1h | P2 |
| [CORR-2I](tier2-kill-chain-behavioral/corr_2i_cloud_persistence_chain.md) | Cloud Persistence Chain | Auth → IAM change → resource mod | 6h | P2 |
| [CORR-2J](tier2-kill-chain-behavioral/corr_2j_network_beaconing_with_endpoint_activity.md) | Network Beaconing with Endpoint Activity | Network + endpoint alerts | 4h | P2 |

### Tier 3: Risk Accumulation (5 rules)

Implements risk-based alerting (RBA) by continuously scoring entities based on their alert history. The Elastic equivalent of Splunk's Risk-Based Alerting.

| Rule ID | Name | Window | Priority |
|---------|------|--------|----------|
| [CORR-3A](tier3-risk-accumulation/corr_3a_24_hour_entity_risk_score.md) | 24-Hour Entity Risk Score | 24h rolling | P1 |
| [CORR-3B](tier3-risk-accumulation/corr_3b_7_day_entity_risk_accumulation.md) | 7-Day Entity Risk Accumulation | 7d rolling | P2 |
| [CORR-3C](tier3-risk-accumulation/corr_3c_risk_velocity_spike.md) | Risk Velocity Spike | 4h vs baseline | P1 |
| [CORR-3D](tier3-risk-accumulation/corr_3d_peer_group_risk_deviation.md) | Peer Group Risk Deviation | 24h vs peer group | P2 |
| [CORR-3E](tier3-risk-accumulation/corr_3e_critical_asset_risk_threshold.md) | Critical Asset Risk Threshold | 24h, lower threshold | P1 |

### Tier 4: Meta-Correlation (7 rules)

Correlates correlations — detects campaigns, coordinated attacks, and rule behavior anomalies by operating on the output of Tiers 1-3.

| Rule ID | Name | Pattern | Priority |
|---------|------|---------|----------|
| [CORR-4A](tier4-meta-correlation/corr_4a_campaign_detection.md) | Campaign Detection | Shared IOCs across entities | P1 |
| [CORR-4B](tier4-meta-correlation/corr_4b_coordinated_activity_detection.md) | Coordinated Activity Detection | Same TTP, tight window, multiple entities | P1 |
| [CORR-4C](tier4-meta-correlation/corr_4c_repeated_low_severity_cluster.md) | Repeated Low-Severity Cluster | Building block accumulation | P2 |
| [CORR-4D](tier4-meta-correlation/corr_4d_alert_surge_by_rule.md) | Alert Surge by Rule | Rule firing rate anomaly | P2 |
| [CORR-4E](tier4-meta-correlation/corr_4e_silent_rule_reactivation.md) | Silent Rule Reactivation | Rule breaks silence after 30+ days | P2 |
| [CORR-4F](tier4-meta-correlation/corr_4f_cross_tenant_correlation.md) | Cross-Tenant Correlation | Same IOC across tenants | P2 |
| [CORR-4G](tier4-meta-correlation/corr_4g_ttp_diversity_score.md) | TTP Diversity Score | 4+ unique tactics per entity | P2 |

### Tier 5: Domain-Specific Correlation (15 rules)

Leverages domain-specific knowledge about how attacks manifest within and across particular technology stacks.

| Rule ID | Name | Domain(s) | Priority |
|---------|------|-----------|----------|
| [CORR-5A](tier5-domain-specific/corr_5a_endpoint_multi_technique_attack.md) | Endpoint Multi-Technique Attack | Endpoint | P1 |
| [CORR-5B](tier5-domain-specific/corr_5b_identity_brute_force_to_success.md) | Identity Brute Force to Success | Identity | P1 |
| [CORR-5C](tier5-domain-specific/corr_5c_cloud_iam_abuse_chain.md) | Cloud IAM Abuse Chain | Cloud | P1 |
| [CORR-5D](tier5-domain-specific/corr_5d_network_scan_to_exploit_sequence.md) | Network Scan-to-Exploit Sequence | Network FW + NDR | P2 |
| [CORR-5E](tier5-domain-specific/corr_5e_email_phishing_to_endpoint_execution.md) | Email Phishing to Endpoint Execution | Email + Endpoint | P1 |
| [CORR-5F](tier5-domain-specific/corr_5f_dns_tunneling_with_endpoint_beacon.md) | DNS Tunneling with Endpoint Beacon | DNS + Endpoint | P2 |
| [CORR-5G](tier5-domain-specific/corr_5g_proxy_policy_violation_cluster.md) | Proxy Policy Violation Cluster | Proxy | P3 |
| [CORR-5H](tier5-domain-specific/corr_5h_vpn_anomaly_chain.md) | VPN Anomaly Chain | Identity + Network | P2 |
| [CORR-5I](tier5-domain-specific/corr_5i_cloud_storage_exfiltration.md) | Cloud Storage Exfiltration | Cloud + Network | P1 |
| [CORR-5J](tier5-domain-specific/corr_5j_saas_impossible_travel.md) | SaaS Impossible Travel | Identity (geo) | P2 |
| [CORR-5K](tier5-domain-specific/corr_5k_container_escape_chain.md) | Container Escape Chain | Container | P2 |
| [CORR-5L](tier5-domain-specific/corr_5l_insider_threat_risk_composite.md) | Insider Threat Risk Composite | Cross-domain | P2 |
| [CORR-5M](tier5-domain-specific/corr_5m_ndr_alert_with_endpoint_corroboration.md) | NDR Alert with Endpoint Corroboration | NDR + Endpoint | P2 |
| [CORR-5N](tier5-domain-specific/corr_5n_firewall_deny_surge_with_internal_alert.md) | Firewall Deny Surge with Internal Alert | FW + Endpoint | P2 |
| [CORR-5O](tier5-domain-specific/corr_5o_web_server_attack_chain.md) | Web Server Attack Chain | WAF + Endpoint | P2 |

### Tier 6: Novelty and Anomaly Detection (10 rules)

Detects "first-time" and "never-before-seen" patterns by comparing current alerts against historical baselines. Requires 30+ days of baseline data.

| Rule ID | Name | Pattern | Priority |
|---------|------|---------|----------|
| [CORR-6A](tier6-novelty-anomaly/corr_6a_first_time_rule_trigger_for_entity.md) | First-Time Rule Trigger for Entity | Never-seen rule/entity pair | P2 |
| [CORR-6B](tier6-novelty-anomaly/corr_6b_new_source_country_alert_cluster.md) | New Source Country Alert Cluster | Unexpected geo + alerts | P2 |
| [CORR-6C](tier6-novelty-anomaly/corr_6c_off_hours_activity_correlation.md) | Off-Hours Activity Correlation | Outside business hours | P2 |
| [CORR-6D](tier6-novelty-anomaly/corr_6d_dormant_account_activation.md) | Dormant Account Activation | Inactive 90+ days | P2 |
| [CORR-6E](tier6-novelty-anomaly/corr_6e_new_process_host_combination.md) | New Process-Host Combination | Novel binary on host | P2 |
| [CORR-6F](tier6-novelty-anomaly/corr_6f_unusual_port_usage_cluster.md) | Unusual Port Usage Cluster | Non-standard ports | P3 |
| [CORR-6G](tier6-novelty-anomaly/corr_6g_alert_pattern_shift_detection.md) | Alert Pattern Shift Detection | Rule behavior change | P3 |
| [CORR-6H](tier6-novelty-anomaly/corr_6h_first_time_cross_domain_link.md) | First-Time Cross-Domain Link | Entity in new domain | P2 |
| [CORR-6I](tier6-novelty-anomaly/corr_6i_rare_tactic_combination.md) | Rare Tactic Combination | Unusual MITRE pairing | P2 |
| [CORR-6J](tier6-novelty-anomaly/corr_6j_anomalous_alert_volume_by_entity.md) | Anomalous Alert Volume by Entity | Volume z-score spike | P2 |

---

## ES|QL Conventions

All rules in this catalog share these conventions. See individual rule files for the complete queries.

### Namespace Convention

All computed fields use the `Esql.` prefix to distinguish them from source ECS fields:

```
Esql.risk_score          — computed risk score
Esql.domain_count        — count of distinct detection domains
Esql.alert_count         — count of correlated alerts
Esql.correlation_severity — dynamically computed severity
```

### Alert Field Paths

These rules query Elastic Security alerts from `.internal.alerts-security.alerts-default`. The key alert fields used throughout the catalog:

| Field | Purpose | Notes |
|-------|---------|-------|
| `signal.rule.severity` | Alert severity assigned by the detection rule | Legacy field path (pre-8.x). Still populated in 8.x+ for backward compatibility. The modern equivalent is `kibana.alert.severity`. Both work. |
| `kibana.alert.rule.threat.tactic.name` | MITRE ATT&CK tactic name | Canonical path in the alert document schema. |
| `kibana.alert.rule.threat.technique.name` | MITRE ATT&CK technique name | Canonical path in the alert document schema. |
| `kibana.alert.rule.building_block_type` | Building block indicator | Value `"default"` identifies building block alerts. |
| `kibana.alert.rule.name` | Detection rule name | Used for rule diversity counting and meta-correlation. |
| `kibana.alert.workflow_status` | Alert triage status | `"open"`, `"acknowledged"`, `"closed"`. Rules filter on `"open"`. |
| `event.dataset` | Data source identifier | Used for domain categorization. ECS standard field. |

> **Environment adaptation**: If your environment uses different field paths (e.g., custom alert index mappings, `kibana.alert.severity` instead of `signal.rule.severity`), update the field references in the query templates. The detection logic is field-path-agnostic — only the references need to change. Run `FROM .internal.alerts-security.alerts-default | KEEP signal.rule.severity, kibana.alert.severity | LIMIT 5` to verify which fields are populated in your environment.

### Severity Risk Weights

```esql
severity_weight = CASE(
    signal.rule.severity == "critical", 25,
    signal.rule.severity == "high", 15,
    signal.rule.severity == "medium", 8,
    signal.rule.severity == "low", 3,
    1
)
```

These weights are calibrated so that a single critical alert (25) outweighs three low alerts (9) and roughly equals one high + one medium (23).

### Building Block Rule (BBR) Factor

```esql
bbr_factor = CASE(kibana.alert.rule.building_block_type == "default", 0.3, 1.0)
```

Building blocks contribute 30% of their severity weight. They're designed as low-fidelity signals that become meaningful only in aggregate.

### Service Account Exclusion Pattern

```esql
AND NOT user.name IN ("SYSTEM", "Administrator", "LOCAL SERVICE", "NETWORK SERVICE",
    "DWM-1", "DWM-2", "DWM-3", "UMFD-0", "UMFD-1", "UMFD-2",
    "DefaultAccount", "Guest", "WDAGUtilityAccount")
AND NOT (
    user.name LIKE "*$"
    OR user.name LIKE "svc-*" OR user.name LIKE "svc_*" OR user.name LIKE "svc.*"
    OR user.name LIKE "*-svc" OR user.name LIKE "*_svc"
    OR user.name LIKE "service-*" OR user.name LIKE "service_*"
    OR user.name LIKE "sa-*" OR user.name LIKE "sa_*"
    OR user.name LIKE "app-*" OR user.name LIKE "app_*"
    OR user.name LIKE "api-*" OR user.name LIKE "api_*"
    OR user.name LIKE "bot-*" OR user.name LIKE "bot_*"
    OR user.name LIKE "task-*" OR user.name LIKE "task_*"
    OR user.name LIKE "cron-*" OR user.name LIKE "cron_*"
    OR user.name LIKE "MSOL_*" OR user.name LIKE "HealthMail*"
    OR user.name LIKE "SM_*" OR user.name LIKE "AAD_*"
    OR user.name LIKE "Sync_*" OR user.name LIKE "ADSync*"
    OR user.name LIKE "noreply*" OR user.name LIKE "no-reply*"
    OR user.name LIKE "mailbox-*" OR user.name LIKE "shared-*"
)
```

> **Note**: CORR-1H intentionally inverts this pattern to specifically monitor service accounts. Add your organization's custom naming conventions to both this exclusion and the CORR-1H inclusion pattern.

### Domain Categorization Pattern

Maps raw `event.dataset` to normalized security domains:

```esql
domain_category = CASE(
    event.dataset LIKE "endpoint*" OR event.dataset LIKE "sentinelone*"
        OR event.dataset LIKE "windows*" OR event.dataset LIKE "sysmon*"
        OR event.dataset LIKE "microsoft-defender*" OR event.dataset LIKE "crowdstrike*"
        OR event.dataset LIKE "carbon_black*",
        "endpoint",
    event.dataset LIKE "okta*" OR event.dataset LIKE "azure_ad*"
        OR event.dataset LIKE "entra*" OR event.dataset LIKE "onelogin*"
        OR event.dataset LIKE "ping*" OR event.dataset LIKE "auth0*",
        "identity",
    event.dataset LIKE "aws*" OR event.dataset LIKE "gcp*"
        OR event.dataset LIKE "azure*" OR event.dataset LIKE "cloud*"
        OR event.dataset LIKE "o365*",
        "cloud",
    event.dataset LIKE "panw*" OR event.dataset LIKE "fortinet*"
        OR event.dataset LIKE "firewall*" OR event.dataset LIKE "paloalto*"
        OR event.dataset LIKE "checkpoint*",
        "network_fw",
    event.dataset LIKE "extrahop*" OR event.dataset LIKE "zeek*"
        OR event.dataset LIKE "suricata*" OR event.dataset LIKE "ndr*",
        "network_ndr",
    event.dataset LIKE "proxy*" OR event.dataset LIKE "zscaler*"
        OR event.dataset LIKE "bluecoat*" OR event.dataset LIKE "squid*",
        "proxy",
    event.dataset LIKE "dns*",
        "dns",
    event.dataset LIKE "email*" OR event.dataset LIKE "proofpoint*"
        OR event.dataset LIKE "mimecast*",
        "email",
    COALESCE(labels.technology, event.module, "unknown")
)
```

> **Tuning**: Add your environment's custom `event.dataset` values to the appropriate category. Run `FROM .internal.alerts-security.alerts-default | STATS count = COUNT(*) BY event.dataset | SORT count DESC` to see what's in your environment.

---

## Prerequisite Lookup Indices

Correlation rules use `LOOKUP JOIN` to enrich alert data with contextual information. These indices must be created before deploying rules that reference them. All LOOKUP JOINs in this catalog are **optional unless marked required** — rules that use them include comments showing how to remove the enrichment block if the lookup is unavailable.

**Best practices for lookup indices:**
- Use `mode: "lookup"` index mode for all lookup indices (Elasticsearch 8.11+). This optimizes them for LOOKUP JOIN performance.
- Keep lookup indices small (< 100K documents) for best query performance.
- Populate via scheduled Elasticsearch transforms, scripted jobs, or manual CSV uploads — whatever fits your operational maturity.
- Use ILM or manual refresh to keep data current. Stale lookups produce stale enrichment.

| # | Index | Purpose | Key Rules |
|---|-------|---------|-----------|
| 1 | `lookup-critical-assets` | Crown jewel systems/users — maps entity names to business criticality tiers. Populate from your CMDB, asset inventory, or manually for top 50 critical assets. | All Tier 1 (1A–1H), all Tier 2 (2A–2J), CORR-3A, 3E, 5A |
| 2 | `lookup-service-accounts` | Known service accounts with owner team, expected domains, and risk tier. Populate from Active Directory OU, Okta service account groups, or manual inventory. | CORR-1H, 3A, 5B, 5H |
| 3 | `lookup-peer-baselines` | Department/role risk baselines for peer comparison. Populate via a weekly transform that computes average and standard deviation of risk scores per department. | CORR-3D, 6H |
| 4 | `lookup-entity-history` | Historical entity-rule associations for novelty detection. Populate via a daily transform that records first-seen dates for entity+rule pairs. | CORR-6A, 6B, 6E, 6F |
| 5 | `lookup-geo-baselines` | Expected countries per user. Populate from HR records (primary office location) or from a transform analyzing 90 days of authentication geo data. | CORR-5J, 6B |
| 6 | `lookup-business-hours` | Per-user or per-department work schedules in UTC. Populate from HR records or set organization-wide defaults. See CORR-6C for timezone handling notes. | CORR-5L, 6C |
| 7 | `lookup-dormant-accounts` | Accounts inactive 90+ days. Populate via a scheduled query against authentication logs or Active Directory lastLogonTimestamp. | CORR-6D |
| 8 | `lookup-process-baselines` | Expected processes per host or host group. Populate via a transform analyzing 30+ days of endpoint process telemetry. | CORR-6E |
| 9 | `lookup-rule-baselines` | Rule firing rate baselines (average daily count, standard deviation, last fire date). Populate via a weekly transform analyzing detection rule output. | CORR-4D, 4E, 6A, 6G, 6J |
| 10 | `lookup-network-baselines` | Standard/expected ports and protocols. Populate manually (IANA well-known ports) or from network flow analysis. | CORR-6F |
| 11 | `lookup-risk-scores` | Rolling entity risk accumulations (7d, 24h). Populate via a transform that runs CORR-3A/3B logic and writes results to a lookup index. | CORR-3C, 4C, 4D, 6J |

<details>
<summary>Lookup Index Schemas (click to expand)</summary>

### 1. lookup-critical-assets

| Field | Type | Description |
|-------|------|-------------|
| `entity_name` | keyword | Entity identifier — hostname or username (join key). Tier 3 rules join on `entity_name` via `COALESCE(user.name, host.name)`. |
| `asset.criticality` | keyword | `critical`, `high`, `medium`, `low` |
| `asset.environment` | keyword | `production`, `staging`, `development` |
| `asset.business_unit` | keyword | Owning business unit |
| `asset.pci_in_scope` | boolean | PCI DSS scope flag |

> **Populate**: Include both critical hosts (by `host.name`) and critical users (by `user.name`) as `entity_name` values.

### 2. lookup-service-accounts

| Field | Type | Description |
|-------|------|-------------|
| `user.name` | keyword | Service account name (join key) |
| `svc.owner_team` | keyword | Responsible team |
| `svc.expected_domains` | keyword | Comma-separated expected domains |
| `svc.risk_tier` | keyword | `tier1_critical`, `tier2_standard`, `tier3_low` |

### 3. lookup-peer-baselines

| Field | Type | Description |
|-------|------|-------------|
| `department` | keyword | Department name (join key) |
| `role` | keyword | Role category |
| `avg_weekly_risk` | double | Average weekly risk score |
| `std_dev_risk` | double | Standard deviation of weekly risk |

### 4. lookup-entity-history

| Field | Type | Description |
|-------|------|-------------|
| `entity_value` | keyword | Entity identifier (join key) |
| `rule_name` | keyword | Detection rule name |
| `first_seen` | date | First time this entity triggered this rule |
| `known_domains` | keyword (array) | Multi-valued keyword array of domains entity has appeared in. **Must be indexed as a keyword array** (not a comma-separated string) for ES|QL `IN` operator compatibility. |

### 5. lookup-geo-baselines

| Field | Type | Description |
|-------|------|-------------|
| `user.name` | keyword | Username (join key) |
| `expected_countries` | keyword (array) | Multi-valued keyword array of expected country names. **Must be indexed as a keyword array** (not a comma-separated string) for ES|QL `IN` operator compatibility. |
| `last_updated` | date | Last baseline update |

### 6. lookup-business-hours

| Field | Type | Description |
|-------|------|-------------|
| `user.name` | keyword | Username (join key) |
| `timezone` | keyword | IANA timezone |
| `work_start_hour` | integer | Business hours start (0-23) |
| `work_end_hour` | integer | Business hours end (0-23) |

### 7. lookup-dormant-accounts

| Field | Type | Description |
|-------|------|-------------|
| `user.name` | keyword | Username (join key) |
| `last_activity_date` | date | Last observed activity |
| `account_status` | keyword | `dormant`, `disabled`, `active` |

### 8. lookup-process-baselines

| Field | Type | Description |
|-------|------|-------------|
| `host.name` | keyword | Hostname (join key) |
| `process.name` | keyword | Process name |
| `first_seen` | date | First observation |

### 9. lookup-rule-baselines

| Field | Type | Description |
|-------|------|-------------|
| `rule_name` | keyword | Rule name (join key) |
| `avg_daily_alerts` | double | Average daily alert count |
| `std_dev_alerts` | double | Standard deviation |
| `last_fire_date` | date | Last time rule fired |

### 10. lookup-network-baselines

| Field | Type | Description |
|-------|------|-------------|
| `destination.port` | keyword | Port number (join key for CORR-6F) |
| `is_standard` | boolean | Whether this port is considered standard/expected |
| `host.name` | keyword | Optional: hostname for per-host port baselines |
| `expected_ports` | keyword (array) | Optional: multi-valued array of expected ports per host |

> **Note**: CORR-6F joins on `destination.port` to classify ports as standard/non-standard. Populate one row per known-standard port with `is_standard: true`.

### 11. lookup-risk-scores

| Field | Type | Description |
|-------|------|-------------|
| `entity_value` | keyword | Entity identifier (join key) |
| `entity_type` | keyword | `user`, `host`, `ip` |
| `rolling_7d_risk` | double | 7-day rolling risk score |
| `rolling_24h_risk` | double | 24-hour rolling risk score |

</details>

---

## Quick-Start: Minimum Viable Correlation

For teams deploying correlation for the first time, start with these 6 rules:

| Priority | Rule | What It Does |
|----------|------|-------------|
| 1 | **CORR-1A** | User-centric multi-domain alert correlation |
| 2 | **CORR-1B** | Host-centric multi-domain alert correlation |
| 3 | **CORR-2A** | Kill chain tactic progression detection |
| 4 | **CORR-2F** | Initial access → execution pipeline |
| 5 | **CORR-3A** | 24-hour entity risk scoring |
| 6 | **CORR-3E** | Critical asset risk threshold |

These 6 rules provide entity correlation, kill chain detection, and risk scoring — covering the most critical detection gaps with the least deployment effort.

Expand to 15 rules for comprehensive coverage:

| Next 9 | Rule | What It Adds |
|--------|------|-------------|
| 7 | **CORR-1H** | Service account monitoring |
| 8 | **CORR-2B** | Identity-to-endpoint escalation chain |
| 9 | **CORR-3C** | Risk velocity spike detection |
| 10 | **CORR-4A** | Campaign detection (shared IOCs) |
| 11 | **CORR-5B** | Identity brute force to success |
| 12 | **CORR-1C** | Source IP cross-domain correlation |
| 13 | **CORR-2E** | Data staging/exfiltration sequence |
| 14 | **CORR-4C** | Low-severity alert clustering |
| 15 | **CORR-6A** | First-time rule trigger novelty |

---

## Deployment Guide

See individual rule files for detailed ADS metadata. This section covers the overall deployment sequencing.

### 8-Phase Rollout (18+ weeks)

| Phase | Weeks | Tier | Rules | Key Action |
|-------|-------|------|-------|------------|
| 1. Foundation | 1-2 | - | - | Deploy 11 lookup indices, verify building block rules |
| 2. Core Entity | 3-4 | Tier 1 | CORR-1A–1H | User + host correlation first, then remaining entities |
| 3. Kill Chain | 5-6 | Tier 2 | CORR-2A–2J | Kill chain progression + initial access pipeline first |
| 4. Risk Scoring | 7-8 | Tier 3 | CORR-3A–3E | 24h risk score first, then velocity + peer deviation |
| 5. Meta-Correlation | 9-10 | Tier 4 | CORR-4A–4G | Campaign detection first, then alert meta-analysis |
| 6. Domain-Specific | 11-14 | Tier 5 | CORR-5A–5O | Deploy based on available data sources |
| 7. Novelty Detection | 15-18 | Tier 6 | CORR-6A–6J | Requires 30+ days baseline data. Observation mode first. |
| 8. AI Integration | 19+ | - | - | Connect to UC-11, UC-12, UC-14 |

**Core principle**: Each tier depends on the tiers below it. Tier 4 meta-correlation rules aggregate the output of Tier 1-3 rules. Tier 6 novelty rules require 30+ days of baseline data. Skipping phases creates blind spots and false positives that cascade upward.

### Tuning Cadence

| Cadence | Activity |
|---------|----------|
| **Daily** (first 2 weeks) | Review all correlation rule outputs, adjust thresholds |
| **Weekly** (weeks 3-8) | Review false positive rates, tune exclusions |
| **Bi-weekly** (weeks 9-16) | Analyze detection gaps, adjust domain mappings |
| **Monthly** (ongoing) | Update lookup indices, review rule performance metrics |
| **Quarterly** | Full catalog review, retire/add rules based on threat landscape |

### Dependency Map

```
Layer 4: AI Integration
    UC-11 (LLM Triage)  <--- Tier 3 risk scores + Tier 1/2 clusters
    UC-12 (Narratives)   <--- All tier outputs
    UC-14 (Campaigns)    <--- Tier 4 campaign/coordination
        |
Layer 3: Meta-Correlation (Tier 4)
    CORR-4A-4G           <--- Aggregates Tier 1-3 outputs
        |
Layer 2: Risk + Behavior (Tiers 2-3)
    CORR-2A-2J           <--- Kill chain sequences from alert data
    CORR-3A-3E           <--- Risk scores from alert data + lookups
        |
Layer 1: Entity Correlation (Tier 1)
    CORR-1A-1H           <--- Raw alerts from building block + detection rules
        |
Layer 0: Foundation
    Building block rules  ---> .internal.alerts-security.alerts-default
    Detection rules       ---> .internal.alerts-security.alerts-default
    11 Lookup indices     ---> LOOKUP JOIN enrichment for all tiers
```

### Performance Considerations

- **Schedule staggering**: Don't run all 55 rules at the same minute. Stagger within each tier's interval.
- **ILM**: Keep 7-30 days of alerts on hot tier. Correlation rules query the hot tier.
- **Resource budget**: ~250-350 queries/hour across all 55 rules. Peak concurrent: 3-5 with staggering.
- Environments with < 1,000 alerts/day need no special resource allocation.
- Environments with > 10,000 alerts/day should consider dedicated coordinating nodes.

---

## Entity Resolution and the COALESCE Problem

### The Problem

16 rules across Tiers 3, 4, and 6 use `COALESCE(user.name, host.name)` to create a single `entity_name` for grouping. This creates three concrete issues:

1. **Namespace collision**: A user named `WEBSERVER01` and a host named `WEBSERVER01` become the same entity. Their risk scores merge incorrectly.
2. **Silent entity dropping**: When both `user.name` and `host.name` are populated (the majority case for EDR alerts), COALESCE silently discards the second entity. An alert about user `jsmith` on host `WORKSTATION-42` is attributed only to `jsmith` — the host dimension is invisible.
3. **Inconsistent preference**: CORR-3E uses `COALESCE(host.name, user.name)` (host-preferred) while all other rules use `COALESCE(user.name, host.name)` (user-preferred). The same alert is attributed to different entities depending on which rule processes it.

This mirrors a well-documented challenge in the industry. Splunk's Risk-Based Alerting solves it with typed `risk_object` + `risk_object_type`. Elastic's own Entity Analytics engine scores users and hosts in separate indices, never merging them.

### Recommended Pattern: Typed Entity Key

Replace untyped `COALESCE(user.name, host.name)` with a typed composite key:

```esql
// BEFORE (current — problematic)
entity_name = COALESCE(user.name, host.name),

// AFTER (recommended — typed)
entity_type = CASE(
    user.name IS NOT NULL, "user",
    host.name IS NOT NULL, "host",
    "unknown"
),
entity_value = CASE(
    user.name IS NOT NULL, user.name,
    host.name IS NOT NULL, host.name,
    "unknown"
),
```

Then group by `BY entity_type, entity_value` instead of `BY entity_name`.

### Entity Resolution Layers

For cross-source correlation, entity resolution becomes increasingly sophisticated. These layers build on each other:

```
Layer 3: Identity Resolution (highest precision, highest cost)
    lookup-identity-resolution maps raw usernames to canonical identity
    Solves: "CORP\jdoe" == "john.doe@corp.com" == "john.doe" in Okta
    Required for: cross-IdP user correlation

Layer 2: IP-to-Host Resolution
    lookup-host-ip-mapping bridges network alerts (IP-only) to endpoint alerts (hostname)
    Required for: CORR-5M, 5N, 5D (NDR + endpoint, firewall + endpoint)

Layer 1: Typed Entity Key (minimum viable fix)
    entity_type + entity_value composite key
    GROUP BY entity_type, entity_value
    Required for: ALL rules currently using COALESCE
```

### Affected Rules

| Tier | Rules | Pattern | Status |
|------|-------|---------|--------|
| Tier 1 | CORR-1A–1H | Already typed (single entity field per rule) | No change needed |
| Tier 2 | CORR-2A–2J | Already typed (single entity field per rule) | No change needed |
| Tier 3 | CORR-3A, 3B, 3C, 3E | Pattern A: Dual-track (Variant A: User Risk, Variant B: Host Risk) | FIXED |
| Tier 4 | CORR-4A–4G | Pattern B: Typed entity key (`entity_type + entity_value`) | FIXED |
| Tier 6 | CORR-6A, 6G, 6H, 6I, 6J | Pattern B: Typed entity key (`entity_type + entity_value`) | FIXED |

### ECS Entity Fields Reference

When correlating across heterogeneous log sources, these are the key ECS fields per source type:

| Log Source | `user.name` | `host.name` | `source.ip` | `related.user` contents |
|-----------|------------|------------|------------|-------------------------|
| **EDR** | Process owner | Agent hostname | Host IP | [process.user.name] |
| **Windows Security** | SubjectUserName | Workstation | Source IP | [SubjectUserName, TargetUserName] |
| **Okta / Entra ID** | Actor | N/A (cloud) | Client IP | [actor, target_user] |
| **AWS CloudTrail** | IAM principal | N/A (cloud) | Source IP | [IAM user/role] |
| **Firewall** | N/A or srcuser | Observer hostname | Source IP | Often empty |
| **NDR (Zeek/Suricata)** | N/A | N/A | Source IP | Empty |
| **Proxy** | Authenticated user (if any) | N/A | Client IP | [user] if authenticated |

> **Key insight**: Network logs have no `user.name` and no `host.name`. They only have IPs. Correlating network + endpoint alerts requires IP-to-hostname resolution (Layer 2) via a lookup index. The `related.user` multi-valued field contains ALL usernames from an event but does not distinguish actor from target.

### Future Enhancement: Lookup Indices for Identity Resolution

Two additional lookup indices support advanced entity resolution:

| Index | Key Field | Purpose |
|-------|-----------|---------|
| `lookup-identity-resolution` | `user.name` → `canonical_identity` | Maps raw usernames (AD sAMAccountName, UPN, Okta login, AWS IAM) to a single canonical identity. Populated from Active Directory, Okta, and HR system exports. |
| `lookup-host-ip-mapping` | `source.ip` → `resolved_hostname` | Maps IP addresses to hostnames. Populated from DHCP logs, EDR agent data, or DNS resolution logs. Enables network alert → endpoint host correlation. |

These are documented as future enhancements. The typed entity key pattern (Layer 1) should be implemented first as it requires no additional infrastructure.

---

## Appendix: Elastic Higher-Order Rule Comparison

### Gap Analysis

| Capability | Elastic Shipped | This Catalog | Gap Filled |
|-----------|----------------|--------------|------------|
| Entity alert clustering | Threshold count only | CORR-1A-1H: risk-weighted, multi-domain | Cross-domain entity view with risk scoring |
| Kill chain progression | EQL sequences (2-3 events, < 30 min) | CORR-2A-2J: multi-stage, hours, cross-domain | Longer chains, cross-host, risk scoring |
| Risk-based alerting | Not available | CORR-3A-3E: full RBA framework | Splunk RBA equivalent for Elastic |
| Campaign detection | Not available | CORR-4A-4B: shared IOCs, coordination | Campaign-level visibility |
| Alert meta-analysis | Not available | CORR-4C-4G: rule behavior, TTP diversity | Detection engineering feedback loop |
| Domain-specific chains | Some EQL sequences | CORR-5A-5O: 15 domain combinations | Comprehensive domain coverage |
| Baseline-driven novelty | ML (black-box) + New Terms (simple) | CORR-6A-6J: lookup-based, tunable, auditable | Deterministic, risk-weighted novelty |
| Service account monitoring | Limited | CORR-1H: dedicated SA correlation | SA-specific behavioral monitoring |
| AI integration readiness | No | All tiers: structured output for LLMs | UC-11, UC-12, UC-14 ready |

### Recommended Combined Deployment

| Action | Elastic Rule Category | Rationale |
|--------|----------------------|-----------|
| **Keep** | ML anomaly rules | Complementary — catch statistical outliers. Their alerts feed Tier 1 correlation. |
| **Keep** | EQL sequence rules | Complementary — tight-window, same-host sequences. Generate building blocks. |
| **Keep** | Indicator match (TI) rules | No overlap — IOC matching is a different pattern. High-value correlation input. |
| **Keep** | New Terms rules (simple) | Partially complementary. Augment with Tier 6 for risk scoring + asset context. |
| **Replace** | "Multiple Alerts Involving a User/Host" | CORR-1A/1B are strictly superior (domain diversity, risk scoring, tactic awareness). |
| **Replace** | Threshold-based spike rules | CORR-4D + 6J use baseline-relative detection instead of static thresholds. |
| **Add** | - | Tiers 3-4 (RBA + meta-correlation) have no Elastic equivalent. |

---

## Planned Enhancements

### 1. Domain Categorization Standardization

The domain categorization CASE pattern (mapping `event.dataset` to security domains like `endpoint`, `identity`, `cloud`, etc.) varies in completeness across rules. A dedicated data requirements page will standardize the canonical domain list and the `event.dataset` patterns that map to each:

- `endpoint` — EDR, Windows events, Sysmon
- `identity` — IdP (Okta, Entra ID, OneLogin, Ping, Auth0)
- `cloud` — AWS, GCP, Azure, O365
- `network_fw` — Palo Alto, Fortinet, Checkpoint, generic firewalls
- `network_ndr` — ExtraHop, Zeek, Suricata
- `proxy` — Zscaler, Bluecoat, Squid
- `dns` — DNS query/response logs
- `email` — Proofpoint, Mimecast, email security
- `vpn` — VPN authentication and tunnel logs
- `waf` — Web application firewall logs
- `dlp` — Data loss prevention events

This will be a separate reference document linked from this catalog.

### 2. Detection Rule Foundation Requirements

This correlation framework assumes a mature detection rule foundation. For maximum effectiveness, the environment should have:

- **Vendor prebuilt rules**: All applicable Elastic prebuilt detection rules enabled (400+ rules covering MITRE ATT&CK techniques)
- **Community rules**: SigmaHQ rules converted to Elastic format (5,000+ rules across Windows, Linux, cloud, network)
- **LOLRMM**: Living Off the Land Remote Monitoring and Management tool detection rules
- **Building block rules**: Low-fidelity indicator rules that generate alerts for common activities — these accumulate into meaningful signals via Tier 3 risk scoring
- **Indicator/building block rules for vendor alerts**: Each vendor alert (IPS signature, AV detection, etc.) should generate a corresponding building block alert with appropriate severity, ensuring all security events are available for correlation

The end goal is that EVERY security-relevant event in the environment generates an alert (building block or standard) in `.internal.alerts-security.alerts-default`, providing the correlation rules with complete visibility.

> **Reference**: For a comprehensive catalog of 12,000+ detection rules from multiple vendors and community sources, see [Threat Detection Explorer](https://threat-detection-explorer.vercel.app/).

### 3. Cross-Rule Deduplication Guidance

When multiple correlation rules fire for the same entity in the same time window, downstream consumers (analysts, AI triage tools) need deduplication guidance. This will be documented as a separate section covering:

- Expected overlap between tiers (a user triggering CORR-1A + CORR-2B + CORR-3A simultaneously is correct behavior, not a bug)
- How AI tools (UC-11, UC-12) should deduplicate and merge correlated clusters
- Priority ordering when the same entity has alerts from multiple tiers

### 4. ~~Entity Resolution Implementation~~ — COMPLETED

The entity resolution patterns have been applied to all 16 affected rules:
- **Tier 3** (4 rules): Pattern A (Dual-track) — each rule split into Variant A (User Risk) and Variant B (Host Risk), deployed as two separate Elastic Security rules per correlation.
- **Tier 4** (7 rules): Pattern B (Typed entity key) — `entity_type + entity_value` composite key replaces `COALESCE(user.name, host.name)`.
- **Tier 6** (5 rules): Pattern B (Typed entity key) — same approach. CORR-6I uses Transform architecture with a TODO note for future typed entity alignment in the Painless script.
