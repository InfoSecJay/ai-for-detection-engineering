# Insider Threat Risk Composite

---

## Metadata

- **Rule ID:** `CORR-5L`
- **Tier:** 5 — Domain-Specific Correlation
- **Author:** Detection Engineering
- **Description:** Build a composite insider threat risk score from multiple indicator categories spanning all security domains. Insider threats are characterized not by a single dramatic alert but by an accumulation of individually low-severity indicators: off-hours access, large data transfers, policy violations, unusual resource access, and removable media usage. This rule aggregates these cross-domain behavioral indicators into a unified insider threat score, surfacing users who exhibit 3 or more distinct insider threat indicator categories within a 24-hour period.
- **Join Key(s):** `user.name`
- **Lookback:** 24 hours
- **Schedule:** Every 1 hour
- **Priority:** P2
- **Integration:** [alerts](https://www.elastic.co/guide/en/security/current/alerts-ui-manage.html)
- **Language:** `[ES|QL]`

## Query

```esql
FROM .internal.alerts-security.alerts-default
| WHERE @timestamp > NOW() - 24 HOURS
    AND kibana.alert.workflow_status == "open"
    AND user.name IS NOT NULL
    AND NOT user.name IN ("SYSTEM", "Administrator", "LOCAL SERVICE", "NETWORK SERVICE",
        "DWM-1", "DWM-2", "DWM-3", "UMFD-0", "UMFD-1", "UMFD-2",
        "DefaultAccount", "Guest", "WDAGUtilityAccount")
    AND NOT (
        user.name LIKE "svc-*" OR user.name LIKE "svc_*"
        OR user.name LIKE "app-*" OR user.name LIKE "sa-*"
        OR user.name LIKE "*$" OR user.name LIKE "MSOL_*"
        OR user.name LIKE "HealthMail*" OR user.name LIKE "SM_*"
    )
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
        event.dataset LIKE "dns*", "dns",
        event.dataset LIKE "email*" OR event.dataset LIKE "proofpoint*"
            OR event.dataset LIKE "mimecast*",
            "email",
        COALESCE(labels.technology, event.module, "unknown")
    ),
    severity_weight = CASE(
        signal.rule.severity == "critical", 25,
        signal.rule.severity == "high", 15,
        signal.rule.severity == "medium", 8,
        signal.rule.severity == "low", 3, 1
    ),
    bbr_factor = CASE(kibana.alert.rule.building_block_type == "default", 0.3, 1.0),
    alert_risk = ROUND(severity_weight * bbr_factor),
    alert_hour = DATE_EXTRACT("hour_of_day", @timestamp),
    is_off_hours_access = CASE(
        domain_category == "identity"
            AND (alert_hour < 6 OR alert_hour > 22), 1, 0
    ),
    is_large_data_transfer = CASE(
        (domain_category == "network_fw" OR domain_category == "network_ndr")
            AND (kibana.alert.rule.name LIKE "*Large*Transfer*"
                OR kibana.alert.rule.name LIKE "*Data*Exfil*"
                OR kibana.alert.rule.name LIKE "*Bulk*"
                OR kibana.alert.rule.threat.tactic.name == "Exfiltration"), 1, 0
    ),
    is_policy_violation = CASE(
        domain_category == "proxy", 1, 0
    ),
    is_unusual_resource = CASE(
        domain_category == "cloud"
            AND (kibana.alert.rule.name LIKE "*Unusual*"
                OR kibana.alert.rule.name LIKE "*First*Time*"
                OR kibana.alert.rule.name LIKE "*Anomalous*"
                OR kibana.alert.rule.name LIKE "*Unauthorized*"), 1, 0
    ),
    is_removable_media = CASE(
        domain_category == "endpoint"
            AND (kibana.alert.rule.name LIKE "*USB*"
                OR kibana.alert.rule.name LIKE "*Removable*"
                OR kibana.alert.rule.name LIKE "*External*Device*"
                OR kibana.alert.rule.threat.tactic.name == "Collection"), 1, 0
    )
| STATS
    Esql.alert_count = COUNT(*),
    Esql.first_seen = MIN(@timestamp),
    Esql.last_seen = MAX(@timestamp),
    Esql.total_risk = SUM(alert_risk),
    Esql.has_off_hours = MAX(is_off_hours_access),
    Esql.has_large_transfer = MAX(is_large_data_transfer),
    Esql.has_policy_violation = MAX(is_policy_violation),
    Esql.has_unusual_resource = MAX(is_unusual_resource),
    Esql.has_removable_media = MAX(is_removable_media),
    Esql.domain_count = COUNT_DISTINCT(domain_category),
    Esql.domain_values = VALUES(domain_category),
    Esql.unique_rules = COUNT_DISTINCT(kibana.alert.rule.name),
    Esql.rule_names = VALUES(kibana.alert.rule.name),
    Esql.tactic_values = VALUES(kibana.alert.rule.threat.tactic.name),
    Esql.host_values = VALUES(host.name),
    Esql.source_ips = VALUES(source.ip)
  BY user.name
| EVAL
    Esql.insider_indicator_count = Esql.has_off_hours + Esql.has_large_transfer
        + Esql.has_policy_violation + Esql.has_unusual_resource + Esql.has_removable_media
| WHERE Esql.insider_indicator_count >= 3
| LOOKUP JOIN lookup-business-hours ON user.name
| EVAL
    Esql.insider_score = Esql.total_risk,
    Esql.severity = CASE(
        Esql.insider_indicator_count >= 5, "critical",
        Esql.insider_indicator_count >= 4, "high",
        Esql.insider_indicator_count >= 3, "medium",
        "low"
    ),
    Esql.description = CONCAT(
        "Insider threat risk composite for user ", user.name,
        " | ", TO_STRING(Esql.insider_indicator_count), "/5 indicator categories",
        " | Off-hours: ", TO_STRING(Esql.has_off_hours),
        " | Large transfer: ", TO_STRING(Esql.has_large_transfer),
        " | Policy violation: ", TO_STRING(Esql.has_policy_violation),
        " | Unusual resource: ", TO_STRING(Esql.has_unusual_resource),
        " | Removable media: ", TO_STRING(Esql.has_removable_media),
        " | Insider Score: ", TO_STRING(Esql.insider_score),
        " | ", TO_STRING(Esql.domain_count), " domains",
        " | Window: ", TO_STRING(Esql.first_seen), " to ", TO_STRING(Esql.last_seen)
    )
| SORT Esql.insider_score DESC
| LIMIT 50
```

## Strategy

Filters to open alerts for all domains and classifies each alert into insider threat indicator categories: off-hours access (identity domain), large data transfers (network domain), policy violations (proxy domain), unusual resource access (cloud domain), and removable media or data staging (endpoint domain). Each category contributes a flag. Aggregates by `user.name` and counts the number of distinct indicator categories present. Uses LOOKUP JOIN against `lookup-business-hours` to determine off-hours activity based on the user's timezone. Requires 3+ indicator categories to fire, ensuring the rule captures genuinely multi-faceted insider behavior.

## Severity Logic

| Condition | Severity |
|-----------|----------|
| 5 indicator categories (all present) | Critical |
| 4 indicator categories | High |
| 3 indicator categories | Medium |

## Notes

- **Blind Spots:**
  - Insider threats that operate entirely within expected parameters (authorized access to sensitive data without policy violations)
  - Off-hours detection depends on accurate timezone assignment -- users in non-standard timezones may generate false positives or false negatives
  - Data transfer volume is inferred from alert rule names rather than measured -- actual byte counts are not available in the alert index
  - Removable media detection requires endpoint rules that specifically detect USB/external device usage

- **False Positives:**
  - **Employees during crunch periods**: Legitimate off-hours work combined with high data access during project deadlines. Mitigation: correlate with known project timelines or manager approval workflows.
  - **IT administrators**: Admins who routinely work off-hours, access unusual resources, and transfer large datasets. Mitigation: use `lookup-business-hours` to set appropriate hours per user and exclude known admin roles.
  - **Traveling employees**: Users in different time zones whose local business hours appear as off-hours. Mitigation: keep `lookup-business-hours` updated with current user timezones.

- **Tuning:**
  1. Deploy `lookup-business-hours` to replace the static hour check (6-22) with per-user timezone-aware business hours
  2. Customize the insider indicator CASE patterns for your specific detection rule names
  3. `insider_indicator_count` threshold (default: 3) -- do not lower below 3 (2 indicators generates too many false positives)
  4. Consider adding a data sensitivity dimension -- access to classified or PCI-scoped resources should weight higher than general resource access
  5. Add velocity analysis -- 3 indicators in 4 hours is more concerning than 3 indicators spread across 24 hours

## Data Requirements

- **Index**: `.internal.alerts-security.alerts-default`
- **Required fields**: `user.name`, `event.dataset`, `signal.rule.severity`, `kibana.alert.rule.name`, `kibana.alert.rule.building_block_type`, `kibana.alert.rule.threat.tactic.name`, `@timestamp`, `host.name`, `source.ip`
- **Lookup index**: `lookup-business-hours` (optional but recommended for accurate off-hours detection)
- **Minimum data sources**: Alerts from at least 3 of the 5 indicator domains (identity, network, proxy, cloud, endpoint) to make this rule effective
- **Minimum volume**: Alerts spanning 3+ insider indicator categories for same user within 24h

## Dependencies

Optional: `lookup-business-hours` for per-user timezone-aware off-hours detection.

## Validation

For a test user within a 12-hour window:
1. Generate an after-hours login alert (identity domain, off-hours indicator)
2. Access a sensitive file share and trigger a data access alert (endpoint domain, unusual resource or collection indicator)
3. Copy data to a USB drive (endpoint domain, removable media indicator)
4. Trigger a proxy policy violation by visiting a categorized site (proxy domain, policy violation indicator)

Expected result: User appears with `Esql.insider_indicator_count >= 3`, severity of medium or higher.

## Elastic Comparison

Elastic does not ship a composite insider threat correlation rule. Individual rules exist for each indicator category, but no built-in rule aggregates cross-domain insider threat signals into a unified score. CORR-5L provides this cross-domain behavioral composite that is essential for insider threat programs.
