# Critical Asset Risk Threshold

---

## Metadata

- **Rule ID:** `CORR-3E`
- **Tier:** 3 — Risk Accumulation
- **Author:** Detection Engineering
- **Description:** Apply a lower risk threshold to entities associated with critical and high-criticality assets. Any alert on a crown jewel system matters more -- a single medium-severity alert on a domain controller should receive more attention than a cluster of low-severity alerts on a developer workstation. This rule implements differentiated thresholds based on asset criticality, ensuring that the SOC's response prioritization aligns with business impact. Deploy as two separate Elastic Security rules: one for user risk (Variant A), one for host risk (Variant B). The host variant is the primary use case (critical servers, domain controllers, CA servers), while the user variant covers critical identity accounts (Tier 0 admins, break-glass accounts).
- **Join Key(s):** `user.name` (Variant A) / `host.name` (Variant B)
- **Lookback:** 24 hours
- **Schedule:** Every 15 minutes
- **Priority:** P1
- **Integration:** [alerts](https://www.elastic.co/guide/en/security/current/alerts-ui-manage.html)
- **Language:** `[ES|QL]`

## Query

### Variant A: User Risk (Critical Identity Accounts)

```esql
FROM .internal.alerts-security.alerts-default
| WHERE @timestamp > NOW() - 24 HOURS
    AND kibana.alert.workflow_status == "open"
    AND user.name IS NOT NULL
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
// --- Required: LOOKUP JOIN for asset criticality filtering ---
// This rule REQUIRES lookup-critical-assets. Without it, no results are produced.
| RENAME user.name AS entity_name
| LOOKUP JOIN lookup-critical-assets ON entity_name
| RENAME entity_name AS user.name
// --- End LOOKUP JOIN block ---
| WHERE asset.criticality IN ("critical", "high")
| EVAL
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
    ),
    severity_weight = CASE(
        signal.rule.severity == "critical", 25,
        signal.rule.severity == "high", 15,
        signal.rule.severity == "medium", 8,
        signal.rule.severity == "low", 3,
        1
    ),
    bbr_factor = CASE(kibana.alert.rule.building_block_type == "default", 0.3, 1.0),
    alert_risk = ROUND(severity_weight * bbr_factor)
| STATS
    Esql.risk_score = SUM(alert_risk),
    Esql.alert_count = COUNT(*),
    Esql.host_values = VALUES(host.name),
    Esql.source_ips = COUNT_DISTINCT(source.ip),
    Esql.domain_count = COUNT_DISTINCT(domain_category),
    Esql.domain_values = VALUES(domain_category),
    Esql.rule_count = COUNT_DISTINCT(kibana.alert.rule.name),
    Esql.rule_names = VALUES(kibana.alert.rule.name),
    Esql.max_severity = MAX(severity_weight),
    Esql.severity_values = VALUES(signal.rule.severity),
    Esql.tactic_count = COUNT_DISTINCT(kibana.alert.rule.threat.tactic.name),
    Esql.tactic_values = VALUES(kibana.alert.rule.threat.tactic.name),
    Esql.source_ip_values = VALUES(source.ip),
    Esql.earliest = MIN(@timestamp),
    Esql.latest = MAX(@timestamp),
    Esql.asset_criticality = MAX(asset.criticality),
    Esql.asset_environment = MAX(asset.environment),
    Esql.asset_business_unit = MAX(asset.business_unit)
  BY user.name
| WHERE Esql.risk_score >= 25
| EVAL
    Esql.correlation_severity = CASE(
        Esql.risk_score >= 100 AND Esql.asset_criticality == "critical", "critical",
        Esql.risk_score >= 50 AND Esql.asset_criticality == "critical", "high",
        Esql.risk_score >= 25 AND Esql.asset_criticality == "critical", "high",
        Esql.risk_score >= 25 AND Esql.asset_criticality == "high", "medium",
        "medium"
    ),
    Esql.description = CONCAT(
        "Critical identity risk for user ", user.name,
        " (", Esql.asset_criticality, " asset",
        ", ", COALESCE(Esql.asset_environment, "unknown"), " env",
        ", ", COALESCE(Esql.asset_business_unit, "unknown"), " BU)",
        " | Risk: ", TO_STRING(Esql.risk_score),
        " | ", TO_STRING(Esql.alert_count), " alerts from ",
        TO_STRING(Esql.rule_count), " rules across ",
        TO_STRING(Esql.domain_count), " domains",
        " | ", TO_STRING(Esql.source_ips), " source IPs",
        " | ", TO_STRING(Esql.tactic_count), " MITRE tactics"
    )
| SORT Esql.correlation_severity DESC, Esql.risk_score DESC
| LIMIT 100
```

### Variant B: Host Risk (Critical Infrastructure)

```esql
FROM .internal.alerts-security.alerts-default
| WHERE @timestamp > NOW() - 24 HOURS
    AND kibana.alert.workflow_status == "open"
    AND host.name IS NOT NULL AND host.name != ""
// --- Required: LOOKUP JOIN for asset criticality filtering ---
// This rule REQUIRES lookup-critical-assets. Without it, no results are produced.
| RENAME host.name AS entity_name
| LOOKUP JOIN lookup-critical-assets ON entity_name
| RENAME entity_name AS host.name
// --- End LOOKUP JOIN block ---
| WHERE asset.criticality IN ("critical", "high")
| EVAL
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
    ),
    severity_weight = CASE(
        signal.rule.severity == "critical", 25,
        signal.rule.severity == "high", 15,
        signal.rule.severity == "medium", 8,
        signal.rule.severity == "low", 3,
        1
    ),
    bbr_factor = CASE(kibana.alert.rule.building_block_type == "default", 0.3, 1.0),
    alert_risk = ROUND(severity_weight * bbr_factor)
| STATS
    Esql.risk_score = SUM(alert_risk),
    Esql.alert_count = COUNT(*),
    Esql.accessing_users = COUNT_DISTINCT(user.name),
    Esql.user_values = VALUES(user.name),
    Esql.source_ips = COUNT_DISTINCT(source.ip),
    Esql.domain_count = COUNT_DISTINCT(domain_category),
    Esql.domain_values = VALUES(domain_category),
    Esql.rule_count = COUNT_DISTINCT(kibana.alert.rule.name),
    Esql.rule_names = VALUES(kibana.alert.rule.name),
    Esql.max_severity = MAX(severity_weight),
    Esql.severity_values = VALUES(signal.rule.severity),
    Esql.tactic_count = COUNT_DISTINCT(kibana.alert.rule.threat.tactic.name),
    Esql.tactic_values = VALUES(kibana.alert.rule.threat.tactic.name),
    Esql.source_ip_values = VALUES(source.ip),
    Esql.earliest = MIN(@timestamp),
    Esql.latest = MAX(@timestamp),
    Esql.asset_criticality = MAX(asset.criticality),
    Esql.asset_environment = MAX(asset.environment),
    Esql.asset_business_unit = MAX(asset.business_unit)
  BY host.name
| WHERE Esql.risk_score >= 15
| EVAL
    Esql.correlation_severity = CASE(
        Esql.risk_score >= 75 AND Esql.asset_criticality == "critical", "critical",
        Esql.risk_score >= 40 AND Esql.asset_criticality == "critical", "high",
        Esql.risk_score >= 15 AND Esql.asset_criticality == "critical", "high",
        Esql.risk_score >= 25 AND Esql.asset_criticality == "high", "medium",
        Esql.risk_score >= 15 AND Esql.asset_criticality == "high", "medium",
        "medium"
    ),
    Esql.multi_user_flag = CASE(Esql.accessing_users >= 3, " [MULTI-USER ACCESS]", ""),
    Esql.description = CONCAT(
        "Critical asset risk for host ", host.name,
        " (", Esql.asset_criticality, " asset",
        ", ", COALESCE(Esql.asset_environment, "unknown"), " env",
        ", ", COALESCE(Esql.asset_business_unit, "unknown"), " BU)",
        " | Risk: ", TO_STRING(Esql.risk_score),
        " | ", TO_STRING(Esql.alert_count), " alerts from ",
        TO_STRING(Esql.rule_count), " rules across ",
        TO_STRING(Esql.domain_count), " domains",
        " | ", TO_STRING(Esql.accessing_users), " users, ",
        TO_STRING(Esql.source_ips), " source IPs",
        " | ", TO_STRING(Esql.tactic_count), " MITRE tactics",
        Esql.multi_user_flag
    )
| SORT Esql.correlation_severity DESC, Esql.risk_score DESC
| LIMIT 100
```

## Strategy

**Dual-Track Entity Scoring.** This rule is deployed as two separate Elastic Security rules -- one scoring by `user.name` (Variant A: Critical Identity Accounts) and one scoring by `host.name` (Variant B: Critical Infrastructure). The dual-track split is especially important for critical asset monitoring because the original `COALESCE(host.name, user.name)` approach (host-preferred) would silently drop user-only alerts (e.g., identity-layer alerts for a Tier 0 admin that lack `host.name`) and conflate user-attributed activity with host-attributed activity on the same system.

**Variant B (Host Risk) uses lower thresholds** than Variant A because critical infrastructure hosts (domain controllers, certificate authorities, key management servers) are the original design target of this rule. The host variant threshold of `Esql.risk_score >= 15` means a single high-severity alert on a critical host surfaces for review. The user variant retains the `Esql.risk_score >= 25` threshold from the original rule.

Performs a LOOKUP JOIN against `lookup-critical-assets` immediately after the WHERE clause to filter the alert population down to only entities associated with critical or high-criticality assets. This is the opposite of CORR-3A's approach (which enriches all entities with criticality): CORR-3E starts by limiting scope to high-value targets. The risk scoring uses the same model (severity weights, BBR factor) but applies significantly lower thresholds. The host variant includes additional context metrics: `Esql.accessing_users` (count of distinct users generating alerts on this asset) and `Esql.source_ips` (count of distinct source IPs), which help distinguish between a single user's activity and a multi-user attack on the critical asset. The `[MULTI-USER ACCESS]` flag on the host variant highlights when 3+ distinct users have generated alerts on the same critical host, which is a strong indicator of either a coordinated attack or a widespread compromise.

## Severity Logic

**Variant A (User Risk):**

| Condition | Severity |
|-----------|----------|
| Esql.risk_score >= 100 on critical identity | Critical |
| Esql.risk_score >= 50 on critical identity | High |
| Esql.risk_score >= 25 on critical identity | High |
| Esql.risk_score >= 25 on high-criticality identity | Medium |

**Variant B (Host Risk) -- lower thresholds for critical infrastructure:**

| Condition | Severity |
|-----------|----------|
| Esql.risk_score >= 75 on critical host | Critical |
| Esql.risk_score >= 40 on critical host | High |
| Esql.risk_score >= 15 on critical host | High |
| Esql.risk_score >= 25 on high-criticality host | Medium |
| Esql.risk_score >= 15 on high-criticality host | Medium |

The severity logic prioritizes asset criticality tier alongside risk score. The host variant uses lower thresholds because critical infrastructure hosts are high-value targets where even a single high-severity alert (15 risk) warrants analyst attention. A score of 40 on a critical host (domain controller) is treated as high severity, whereas the same score on a standard host would not yet trigger CORR-3A. This intentional asymmetry ensures crown jewel systems receive faster analyst attention.

## Notes

- **Tier Integration:** Tier 1 rules (CORR-1A for users, CORR-1B for hosts) provide entity-typed short-window correlation that detects immediate multi-signal convergence. These Tier 3 rules provide asset-criticality-aware risk accumulation with lowered thresholds for crown jewel systems. The dual-track split ensures that critical identity accounts (Tier 0 admins, break-glass accounts) and critical infrastructure hosts (domain controllers, CA servers) are each scored and thresholded appropriately.

- **Blind Spots:**
  - **Assets not in the critical assets lookup**: Any critical system not registered in `lookup-critical-assets` is invisible to this rule. It will still be caught by CORR-3A at the standard 50-risk threshold, but it will not receive the lower-threshold treatment or the criticality context. Completeness of the asset inventory is the primary limitation.
  - **Shared admin accounts on critical systems**: If multiple administrators use a shared account (e.g., `admin@dc01`) on a critical system, the host variant's `Esql.accessing_users` metric will show 1 user even though multiple humans are involved. This obscures attribution and may cause the rule to undercount the scope of activity.
  - **Cloud-native critical assets**: Critical cloud resources (S3 buckets containing PII, production databases, key management services) may not have a `host.name` that matches the lookup. Ensure `lookup-critical-assets` includes cloud resource identifiers mapped to their corresponding `host.name` or user identifiers as appropriate.
  - **Dual-track overlap**: An alert on a critical host by a critical user will surface in both variants. This is intentional -- both the host-centric and user-centric views are operationally relevant for critical assets -- but analysts should correlate the two alerts to avoid duplicate investigation.

- **False Positives:**
  - **Scheduled maintenance on critical systems**: Patching, configuration changes, and restarts on domain controllers and other critical infrastructure generate endpoint and identity alerts as expected. This primarily affects the host variant due to its lower threshold of 15. Mitigation: coordinate with IT operations to create maintenance window exclusions, or temporarily elevate the threshold during known change windows.
  - **Patching activities triggering endpoint rules**: Security updates and software deployments on critical servers often trigger endpoint detection rules (new processes, file modifications, service restarts). Mitigation: ensure patching tools and their associated processes are excluded from relevant building block rules, or add them to a patching-activity exclusion list.
  - **Monitoring and health-check systems**: Systems that perform regular health checks against critical assets (e.g., Nagios, Zabbix, SCCM) may generate low-severity alerts that accumulate past the host variant's threshold of 15. Mitigation: register these monitoring accounts in `lookup-service-accounts` and exclude them.

- **Tuning:**
  1. **User variant threshold of 25** for critical identity accounts is moderately aggressive. A single medium-severity alert (8 risk) plus 2 high-severity alerts (30 risk) exceeds this threshold. If this generates too many alerts, increase to 35 or 40.
  2. **Host variant threshold of 15** is intentionally aggressive for critical infrastructure. A single high-severity alert (15 risk) on a domain controller will trigger this rule. This is the original design intent of CORR-3E: any meaningful alert on a crown jewel host deserves attention. If this generates too many alerts on busy critical servers, increase to 25.
  3. **Maintain `lookup-critical-assets` with accurate crown jewel inventory**: This is the single most important tuning action. Conduct quarterly reviews of the asset inventory to ensure new critical systems are added and decommissioned systems are removed. Both user entities (Tier 0 admin accounts, break-glass accounts) and host entities (DCs, CAs, key vaults) should be represented.
  4. **Multi-user access flag** (host variant only): The `[MULTI-USER ACCESS]` annotation in the description helps analysts quickly identify critical hosts being accessed by multiple users. Consider adding a separate threshold trigger for `Esql.accessing_users >= 5` regardless of risk score.
  5. **Environment-based filtering**: Use `asset.environment` to create separate thresholds for production critical assets (lower threshold) vs. staging critical assets (higher threshold).
  6. **Service account exclusion tuning**: The user variant's service account filters follow the CORR-1A pattern. If your environment uses additional service account naming conventions not covered by the default list, add them to the `NOT` clause.

## Data Requirements

- **Index**: `.internal.alerts-security.alerts-default`
- **Required fields**: `@timestamp`, `host.name` or `user.name`, `event.dataset`, `signal.rule.severity`, `kibana.alert.workflow_status`, `kibana.alert.rule.building_block_type`, `kibana.alert.rule.name`, `kibana.alert.rule.threat.tactic.name`, `source.ip`
- **Lookup index**: `lookup-critical-assets` (with `entity_name` as join key; `asset.criticality`, `asset.environment`, `asset.business_unit`, `asset.pci_in_scope` fields)
- **Asset inventory**: A current, complete inventory of critical and high-criticality assets must be maintained in the lookup. This is an organizational process dependency, not just a technical one.

## Dependencies

- **Required**: `lookup-critical-assets` with populated asset criticality data. Without this lookup, the WHERE clause `asset.criticality IN ("critical", "high")` filters out all results and the rule produces no output.
- **Recommended**: CORR-3A for standard-threshold entity risk scoring (handles entities not in the critical assets lookup). CORR-3E is designed to complement, not replace, CORR-3A.

## Validation

**Variant A (User Risk):**
1. Ensure a critical user account (e.g., `tier0-admin@corp.com`) is registered in `lookup-critical-assets` with `asset.criticality = "critical"`.
2. Generate 1 medium-severity identity alert for this user. Risk = 8. Below the 25 threshold -- should NOT fire.
3. Generate 1 high-severity alert (15) + 1 medium alert (8) + 1 low alert (3) = 26 risk. The rule SHOULD fire at high severity (>= 25 on critical identity).
4. Generate 5 high-severity alerts (75) + 2 critical alerts (50) = 125 risk. The rule should fire at critical severity.

**Variant B (Host Risk):**
1. Ensure the target host (e.g., `DC01.corp.local`) is registered in `lookup-critical-assets` with `asset.criticality = "critical"`.
2. Generate 1 medium-severity endpoint alert for this host. Risk = 8. Below the 15 threshold -- should NOT fire.
3. Generate 1 high-severity alert (15) for this host. Risk = 15. The rule SHOULD fire at high severity (>= 15 on critical host).
4. Generate 3 high-severity alerts (45) from 3 different users. Risk = 45, accessing_users = 3. The rule should fire at high severity with `[MULTI-USER ACCESS]` flag.
5. Generate 5 high-severity alerts (75) + 1 critical alert (25) = 100 risk. The rule should fire at critical severity.

## Elastic Comparison

Elastic's Entity Risk Scoring includes an "Asset Criticality" feature that allows assigning criticality levels to entities, which influences their risk score. However, Elastic's implementation applies a blanket multiplier rather than providing a differentiated threshold. CORR-3E goes further by implementing a fundamentally lower detection threshold for critical assets (25 vs. 50), providing asset-specific context fields (environment, business unit, PCI scope), tracking multi-user access patterns on critical assets, and enabling severity logic that combines risk score with criticality tier. The closest Splunk equivalent is adding asset criticality as a risk modifier in RBA, which adjusts scores but does not change threshold behavior.
