# Multi-Domain Alert Correlation by Host

---

## Metadata

- **Rule ID:** `CORR-1B`
- **Tier:** 1 — Entity-Centric Correlation
- **Author:** Detection Engineering
- **Description:** Detect hosts generating alerts across two or more distinct detection domains. Catches endpoint+NDR+DNS chains, malware infections with network C2, and host-based attack progression spanning multiple users.
- **Join Key(s):** `host.name`
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
    AND host.name IS NOT NULL AND host.name != ""
| EVAL
    domain_category = CASE(
        event.dataset LIKE "endpoint*" OR event.dataset LIKE "sentinelone*"
            OR event.dataset LIKE "windows*" OR event.dataset LIKE "sysmon*", "endpoint",
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
        COALESCE(labels.technology, event.module, "other")
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
    Esql.user_count = COUNT_DISTINCT(user.name),
    Esql.user_values = VALUES(user.name),
    Esql.ip_values = VALUES(related.ip)
  BY host.name
| WHERE Esql.domain_count >= 2 AND Esql.unique_rules >= 2
    AND (
        Esql.total_risk_score >= 80
        OR (Esql.critical_count > 0 AND Esql.tactic_count >= 2)
        OR (Esql.high_count >= 2 AND Esql.domain_count >= 2)
        OR (Esql.tactic_count >= 3 AND Esql.unique_rules >= 3)
    )
| EVAL
    Esql.correlation_severity = CASE(
        Esql.total_risk_score >= 150 OR (Esql.critical_count > 0 AND Esql.tactic_count >= 4), "critical",
        Esql.total_risk_score >= 80 OR (Esql.critical_count > 0 AND Esql.tactic_count >= 2), "high",
        "medium"
    ),
    Esql.description = CONCAT(
        "Host ", host.name,
        " | Risk Score: ", TO_STRING(Esql.total_risk_score),
        " | ", TO_STRING(Esql.unique_rules), " rules across ",
        TO_STRING(Esql.domain_count), " domains",
        " | ", TO_STRING(Esql.tactic_count), " tactics",
        " | ", TO_STRING(Esql.user_count), " users involved",
        " | ", TO_STRING(Esql.alert_count), " total alerts"
    )
| SORT Esql.total_risk_score DESC
| LIMIT 50
```

## Strategy

Aggregates by `host.name`. No service account exclusion — host attribution doesn't depend on user context. Captures user spread (multiple users on same host = potential compromise or shared system).

## Severity Logic

| Condition | Severity |
|-----------|----------|
| risk_score >= 150 OR (critical + 4+ tactics) | Critical |
| risk_score >= 80 OR (critical + 2+ tactics) | High |
| Everything else crossing threshold | Medium |

## Notes

- **Blind Spots:**
  - Hosts with no `host.name` field (pure network alerts by IP only — use CORR-1C/1D)
  - Container environments with ephemeral host names
  - Shared terminal servers/jump boxes generate high FP
- **False Positives:**
  - **Jump boxes/bastion hosts**: Legitimate multi-domain activity. Mitigation: tag in lookup-critical-assets.
  - **Build servers**: CI/CD pipelines trigger endpoint + network + cloud alerts. Mitigation: exclude by environment tag.
- **Tuning:**
  1. Exclude known jump boxes and build servers via lookup
  2. For container environments, correlate on pod label instead of `host.name`
  3. Consider a 1-hour variant for fast-moving ransomware detection

## Data Requirements

- **Index**: `.internal.alerts-security.alerts-default`
- **Required fields**: `host.name`, `event.dataset`, `signal.rule.severity`, `kibana.alert.rule.name`, `kibana.alert.rule.threat.tactic.name`, `@timestamp`, `user.name`
- **Minimum volume**: 2+ alerts from 2+ domains for same host in 4h

## Dependencies

Optional: `lookup-critical-assets` for severity escalation on production/PCI hosts.

## Validation

Red team: Deliver payload to workstation via spearphishing (email), payload executes (endpoint), malware resolves DGA domain (DNS), connects to C2 (firewall/NDR). Host appears with domain_count >= 3.

## Elastic Comparison

Elastic ships "Multiple Alerts on a Single Host" — counts alert quantity, not domain diversity. CORR-1B adds cross-domain counting, risk scoring, user spread analysis, and asset criticality enrichment.
