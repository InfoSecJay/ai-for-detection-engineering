# Multi-Domain Alert Correlation by Email Address

---

## Metadata

- **Rule ID:** `CORR-1G`
- **Tier:** 1 — Entity-Centric Correlation
- **Author:** Detection Engineering
- **Description:** Detect email addresses appearing in alerts across two or more domains. Traces phishing-to-compromise chains through a single email identifier.
- **Join Key(s):** `COALESCE(user.email, email.from.address)`
- **Lookback:** 24 hours
- **Schedule:** Every 30 minutes
- **Priority:** P3
- **Integration:** [alerts](https://www.elastic.co/guide/en/security/current/alerts-ui-manage.html)
- **Language:** `[ES|QL]`

## Query

```esql
FROM .internal.alerts-security.alerts-default
| WHERE @timestamp > NOW() - 24 HOURS
    AND kibana.alert.workflow_status == "open"
    AND (user.email IS NOT NULL OR email.from.address IS NOT NULL)
| EVAL
    corr_email = COALESCE(user.email, email.from.address),
    domain_category = CASE(
        event.dataset LIKE "endpoint*" OR event.dataset LIKE "sentinelone*"
            OR event.dataset LIKE "windows*" OR event.dataset LIKE "sysmon*", "endpoint",
        event.dataset LIKE "okta*" OR event.dataset LIKE "azure_ad*"
            OR event.dataset LIKE "entra*", "identity",
        event.dataset LIKE "aws*" OR event.dataset LIKE "gcp*"
            OR event.dataset LIKE "azure*" OR event.dataset LIKE "o365*", "cloud",
        event.dataset LIKE "panw*" OR event.dataset LIKE "fortinet*", "network_fw",
        event.dataset LIKE "proxy*" OR event.dataset LIKE "zscaler*", "proxy",
        event.dataset LIKE "email*" OR event.dataset LIKE "proofpoint*"
            OR event.dataset LIKE "mimecast*", "email",
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
    Esql.unique_rules = COUNT_DISTINCT(kibana.alert.rule.name),
    Esql.rule_names = VALUES(kibana.alert.rule.name),
    Esql.domain_count = COUNT_DISTINCT(domain_category),
    Esql.domain_values = VALUES(domain_category),
    Esql.hosts = VALUES(host.name),
    Esql.users = VALUES(user.name),
    Esql.source_ips = VALUES(source.ip),
    Esql.subjects = VALUES(email.subject)
  BY corr_email
| WHERE Esql.domain_count >= 2
| EVAL
    Esql.correlation_severity = CASE(
        Esql.total_risk_score >= 80 OR Esql.domain_count >= 4, "critical",
        Esql.total_risk_score >= 40 OR Esql.domain_count >= 3, "high",
        "medium"
    ),
    Esql.description = CONCAT(
        "Email ", corr_email,
        " | Risk: ", TO_STRING(Esql.total_risk_score),
        " | ", TO_STRING(Esql.domain_count), " domains",
        " | ", TO_STRING(Esql.unique_rules), " rules"
    )
| SORT Esql.total_risk_score DESC
| LIMIT 50
```

## Strategy

Uses `COALESCE(user.email, email.from.address)` to unify sender and user email fields. 24-hour lookback because email-to-compromise chains unfold over hours.

## Severity Logic

| Condition | Severity |
|-----------|----------|
| risk_score >= 80 OR domain_count >= 4 | Critical |
| risk_score >= 40 OR domain_count >= 3 | High |
| Everything else crossing threshold | Medium |

## Notes

- **Blind Spots:**
  - Phishing sender address differs from compromised user's address (most common in spearphishing from external domains)
  - `user.email` not consistently populated across identity/cloud sources
- **False Positives:**
  - Shared mailbox activity, distribution lists. Mitigation: exclude known shared/DL addresses.
- **Tuning:**
  - Maintain an exclusion list for shared mailboxes and distribution lists
  - Adjust risk thresholds based on email alert volume

## Data Requirements

- **Index**: `.internal.alerts-security.alerts-default`
- **Required fields**: `user.email`, `email.from.address`, `event.dataset`, `signal.rule.severity`, `kibana.alert.workflow_status`, `kibana.alert.rule.building_block_type`, `kibana.alert.rule.name`, `@timestamp`, `host.name`, `user.name`, `source.ip`, `email.subject`
- **Minimum volume**: 2+ alerts from 2+ domains for same email address in 24h

## Dependencies

None required. Optional: shared mailbox/distribution list exclusion lookup.

## Validation

Credential harvesting email to victim@corp.com (email alert) -> operator logs into Okta as victim@corp.com (identity alert). domain_count >= 2.

## Elastic Comparison

No Elastic email-address cross-domain correlation rule.
