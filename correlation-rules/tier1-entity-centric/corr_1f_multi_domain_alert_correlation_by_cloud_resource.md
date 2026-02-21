# Multi-Domain Alert Correlation by Cloud Resource

---

## Metadata

- **Rule ID:** `CORR-1F`
- **Tier:** 1 — Entity-Centric Correlation
- **Author:** Detection Engineering
- **Description:** Detect cloud instances generating alerts across cloud API + endpoint + network domains. Catches cloud-specific attack chains where an attacker compromises a cloud instance.
- **Join Key(s):** `cloud.instance.id`
- **Lookback:** 4 hours
- **Schedule:** Every 10 minutes
- **Priority:** P2
- **Integration:** [alerts](https://www.elastic.co/guide/en/security/current/alerts-ui-manage.html)
- **Language:** `[ES|QL]`

## Query

```esql
FROM .internal.alerts-security.alerts-default
| WHERE @timestamp > NOW() - 4 HOURS
    AND kibana.alert.workflow_status == "open"
    AND cloud.instance.id IS NOT NULL
| EVAL
    domain_category = CASE(
        event.dataset LIKE "endpoint*" OR event.dataset LIKE "sentinelone*"
            OR event.dataset LIKE "windows*" OR event.dataset LIKE "sysmon*", "endpoint",
        event.dataset LIKE "okta*" OR event.dataset LIKE "azure_ad*"
            OR event.dataset LIKE "entra*", "identity",
        event.dataset LIKE "aws*" OR event.dataset LIKE "gcp*"
            OR event.dataset LIKE "azure*" OR event.dataset LIKE "o365*", "cloud",
        event.dataset LIKE "panw*" OR event.dataset LIKE "fortinet*", "network_fw",
        event.dataset LIKE "extrahop*" OR event.dataset LIKE "zeek*", "network_ndr",
        COALESCE(labels.technology, event.module, "unknown")
    ),
    severity_weight = CASE(
        signal.rule.severity == "critical", 25,
        signal.rule.severity == "high", 15,
        signal.rule.severity == "medium", 8,
        signal.rule.severity == "low", 3, 1
    ),
    bbr_factor = CASE(kibana.alert.rule.building_block_type == "default", 0.3, 1.0),
    alert_risk = ROUND(severity_weight * bbr_factor)
| STATS
    Esql.alert_count = COUNT(*),
    Esql.first_seen = MIN(@timestamp),
    Esql.last_seen = MAX(@timestamp),
    Esql.total_risk_score = SUM(alert_risk),
    Esql.tactic_count = COUNT_DISTINCT(kibana.alert.rule.threat.tactic.name),
    Esql.tactic_values = VALUES(kibana.alert.rule.threat.tactic.name),
    Esql.unique_rules = COUNT_DISTINCT(kibana.alert.rule.name),
    Esql.rule_names = VALUES(kibana.alert.rule.name),
    Esql.domain_count = COUNT_DISTINCT(domain_category),
    Esql.domain_values = VALUES(domain_category),
    Esql.user_values = VALUES(user.name),
    Esql.cloud_providers = VALUES(cloud.provider),
    Esql.cloud_accounts = VALUES(cloud.account.id)
  BY cloud.instance.id
| WHERE Esql.domain_count >= 2
| EVAL
    Esql.correlation_severity = CASE(
        Esql.total_risk_score >= 100 OR Esql.domain_count >= 4, "critical",
        Esql.total_risk_score >= 50 OR Esql.domain_count >= 3, "high",
        "medium"
    ),
    Esql.description = CONCAT(
        "Cloud instance ", cloud.instance.id,
        " | Risk: ", TO_STRING(Esql.total_risk_score),
        " | ", TO_STRING(Esql.domain_count), " domains",
        " | ", TO_STRING(Esql.unique_rules), " rules"
    )
| SORT Esql.total_risk_score DESC
| LIMIT 50
```

## Strategy

Aggregates by `cloud.instance.id` — stable across cloud API and endpoint telemetry. Essential for cloud-heavy environments.

## Severity Logic

| Condition | Severity |
|-----------|----------|
| risk_score >= 100 OR domain_count >= 4 | Critical |
| risk_score >= 50 OR domain_count >= 3 | High |
| Everything else crossing threshold | Medium |

## Notes

- **Blind Spots:**
  - Serverless workloads (Lambda/Functions) have no instance ID
  - Some CloudTrail actions are account-level, not instance-level
- **False Positives:**
  - Auto-scaling events during bootstrapping
  - IaC deployments (Terraform/CloudFormation)
- **Tuning:**
  - Exclude known auto-scaling group instance IDs during deployment windows
  - Adjust risk thresholds for environments with heavy IaC activity

## Data Requirements

- **Index**: `.internal.alerts-security.alerts-default`
- **Required fields**: `cloud.instance.id`, `event.dataset`, `signal.rule.severity`, `kibana.alert.workflow_status`, `kibana.alert.rule.building_block_type`, `kibana.alert.rule.name`, `kibana.alert.rule.threat.tactic.name`, `@timestamp`, `user.name`, `cloud.provider`, `cloud.account.id`
- **Minimum volume**: 2+ alerts from 2+ domains for same cloud instance in 4h

## Dependencies

None required. Optional: cloud asset inventory lookup for instance classification.

## Validation

Compromise AWS credentials -> SSM Session Manager (cloud alert) -> reconnaissance on instance (endpoint alert) -> security group modification (cloud alert). domain_count >= 2.

## Elastic Comparison

No Elastic cloud-instance-centric correlation rule.
