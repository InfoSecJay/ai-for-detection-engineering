# Multi-Domain Alert Correlation by User

---

## Metadata

- **Rule ID:** `CORR-1A`
- **Tier:** 1 — Entity-Centric Correlation
- **Author:** Detection Engineering
- **Description:** Detect users generating alerts across two or more distinct detection domains within a 4-hour window, indicating that a single identity is exhibiting suspicious behavior across fundamentally different parts of the security stack.
- **Join Key(s):** `user.name`
- **Lookback:** 4 hours
- **Schedule:** Every 10 minutes
- **Priority:** P1
- **Integration:** [alerts](https://www.elastic.co/guide/en/security/current/alerts-ui-manage.html)
- **Language:** `[ES|QL]`

## Query

```esql
FROM .internal.alerts-security.alerts-default
| WHERE @timestamp > NOW() - 4 HOURS
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
            OR event.dataset LIKE "microsoft-defender*" OR event.dataset LIKE "crowdstrike*",
            "endpoint",
        event.dataset LIKE "okta*" OR event.dataset LIKE "azure_ad*"
            OR event.dataset LIKE "entra*", "identity",
        event.dataset LIKE "aws*" OR event.dataset LIKE "gcp*"
            OR event.dataset LIKE "azure*" OR event.dataset LIKE "o365*", "cloud",
        event.dataset LIKE "panw*" OR event.dataset LIKE "fortinet*"
            OR event.dataset LIKE "firewall*", "network_fw",
        event.dataset LIKE "extrahop*" OR event.dataset LIKE "zeek*"
            OR event.dataset LIKE "suricata*", "network_ndr",
        event.dataset LIKE "proxy*" OR event.dataset LIKE "zscaler*", "proxy",
        event.dataset LIKE "dns*", "dns",
        event.dataset LIKE "email*" OR event.dataset LIKE "proofpoint*", "email",
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
    is_critical = CASE(signal.rule.severity == "critical"
        AND kibana.alert.rule.building_block_type IS NULL, 1, 0),
    is_high = CASE(signal.rule.severity == "high"
        AND kibana.alert.rule.building_block_type IS NULL, 1, 0),
    is_bbr = CASE(kibana.alert.rule.building_block_type == "default", 1, 0)
| STATS
    Esql.alert_count = COUNT(*),
    Esql.first_seen = MIN(@timestamp),
    Esql.last_seen = MAX(@timestamp),
    Esql.total_risk_score = SUM(alert_risk),
    Esql.max_single_risk = MAX(alert_risk),
    Esql.tactic_count = COUNT_DISTINCT(kibana.alert.rule.threat.tactic.name),
    Esql.tactic_values = VALUES(kibana.alert.rule.threat.tactic.name),
    Esql.technique_values = VALUES(kibana.alert.rule.threat.technique.name),
    Esql.critical_count = SUM(is_critical),
    Esql.high_count = SUM(is_high),
    Esql.bbr_count = SUM(is_bbr),
    Esql.unique_rules = COUNT_DISTINCT(kibana.alert.rule.name),
    Esql.rule_names = VALUES(kibana.alert.rule.name),
    Esql.domain_count = COUNT_DISTINCT(domain_category),
    Esql.domain_values = VALUES(domain_category),
    Esql.data_source_values = VALUES(event.dataset),
    Esql.host_count = COUNT_DISTINCT(host.name),
    Esql.host_values = VALUES(host.name),
    Esql.ip_values = VALUES(related.ip),
    Esql.source_ip_count = COUNT_DISTINCT(source.ip)
  BY user.name
| WHERE Esql.domain_count >= 2 AND Esql.unique_rules >= 2
    AND (
        Esql.total_risk_score >= 100
        OR (Esql.critical_count > 0 AND Esql.tactic_count >= 3)
        OR (Esql.high_count >= 2 AND Esql.domain_count >= 3)
        OR (Esql.tactic_count >= 4 AND Esql.unique_rules >= 3)
    )
| EVAL
    Esql.correlation_severity = CASE(
        Esql.total_risk_score >= 150 OR (Esql.critical_count > 0 AND Esql.tactic_count >= 4), "critical",
        Esql.total_risk_score >= 100 OR (Esql.critical_count > 0 AND Esql.tactic_count >= 3)
            OR (Esql.high_count >= 3 AND Esql.domain_count >= 3), "high",
        Esql.total_risk_score >= 60 OR (Esql.high_count >= 2 AND Esql.tactic_count >= 3), "medium",
        "low"
    ),
    Esql.description = CONCAT(
        "User ", user.name,
        " | Risk Score: ", TO_STRING(Esql.total_risk_score),
        " | ", TO_STRING(Esql.unique_rules), " rules across ",
        TO_STRING(Esql.domain_count), " security domains",
        " | ", TO_STRING(Esql.tactic_count), " MITRE tactics",
        " | ", TO_STRING(Esql.host_count), " hosts",
        " | ", TO_STRING(Esql.alert_count), " total alerts",
        " | Window: ", TO_STRING(Esql.first_seen), " to ", TO_STRING(Esql.last_seen)
    )
| SORT Esql.total_risk_score DESC
| LIMIT 50
```

## Strategy

Aggregates all open alerts by `user.name` within a 4-hour lookback. Each alert is categorized into a detection domain via `event.dataset`. Severity weights and BBR factors produce a weighted risk score per user. The rule fires when a user has alerts in 2+ distinct domains with sufficient risk signal. A tiered threshold system ensures high-severity correlations surface first.

## Severity Logic

| Condition | Severity |
|-----------|----------|
| risk_score >= 150 OR (critical + 4+ tactics) | Critical |
| risk_score >= 100 OR (critical + 3+ tactics) OR (3+ high + 3+ domains) | High |
| risk_score >= 60 OR (2+ high + 3+ tactics) | Medium |
| Everything else crossing threshold | Low |

## Notes

- **Blind Spots:**
  - Users with no `user.name` populated (common in network-only detections)
  - Service accounts excluded — use CORR-1H for service account monitoring
  - Alerts in `acknowledged`/`closed` workflow status excluded
  - Non-standard `event.dataset` values fall through to "unknown"
- **False Positives:**
  - **IT administrators**: Admins patching systems trigger endpoint + identity + cloud alerts legitimately. Mitigation: cross-reference with change management.
  - **Penetration testing**: Add pen test accounts to temporary exclusion.
  - **DevOps engineers**: Routinely interact with cloud, endpoints, and identity. Mitigation: adjust thresholds for known high-touch users.
- **Tuning:**
  1. `domain_count` threshold (default: 2) — increase to 3 if high cross-domain activity
  2. `total_risk_score` thresholds (60/100/150) — adjust based on severity distribution
  3. Lookback window (default: 4h) — extend to 8h for slow attack progression
  4. Add custom service account patterns to exclusion block

## Data Requirements

- **Index**: `.internal.alerts-security.alerts-default`
- **Required fields**: `user.name`, `event.dataset`, `signal.rule.severity`, `kibana.alert.workflow_status`, `kibana.alert.rule.building_block_type`, `kibana.alert.rule.name`, `kibana.alert.rule.threat.tactic.name`, `@timestamp`, `host.name`, `source.ip`, `related.ip`
- **Minimum volume**: 2+ alerts from 2+ domains for same user in 4h

## Dependencies

None required. Optional: `lookup-critical-assets` for asset enrichment.

## Validation

Red team: Compromise Okta credentials (identity alert), use session to access EC2 via SSM (cloud alert), execute Mimikatz on instance (endpoint alert). Within 2 hours, user should appear with domain_count >= 3.

## Elastic Comparison

Elastic ships "Multiple Alerts Involving a User" — counts alert volume, not domain diversity. No risk scoring, no domain categorization, no dynamic severity. CORR-1A is a substantial upgrade.
