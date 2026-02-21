# Multi-Domain Alert Correlation by Destination IP

---

## Metadata

- **Rule ID:** `CORR-1D`
- **Tier:** 1 — Entity-Centric Correlation
- **Author:** Detection Engineering
- **Description:** Detect destination IPs flagged by multiple internal hosts or detection domains. Catches C2 infrastructure, malicious download servers, and exfiltration endpoints that multiple compromised hosts are reaching.
- **Join Key(s):** `destination.ip`
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
    AND destination.ip IS NOT NULL
    AND NOT CIDR_MATCH(destination.ip, "127.0.0.0/8", "169.254.0.0/16")
| EVAL
    domain_category = CASE(
        event.dataset LIKE "endpoint*" OR event.dataset LIKE "sentinelone*"
            OR event.dataset LIKE "windows*" OR event.dataset LIKE "sysmon*", "endpoint",
        event.dataset LIKE "okta*" OR event.dataset LIKE "azure_ad*", "identity",
        event.dataset LIKE "aws*" OR event.dataset LIKE "gcp*"
            OR event.dataset LIKE "azure*", "cloud",
        event.dataset LIKE "panw*" OR event.dataset LIKE "fortinet*"
            OR event.dataset LIKE "firewall*", "network_fw",
        event.dataset LIKE "extrahop*" OR event.dataset LIKE "zeek*"
            OR event.dataset LIKE "suricata*", "network_ndr",
        event.dataset LIKE "proxy*" OR event.dataset LIKE "zscaler*", "proxy",
        event.dataset LIKE "dns*", "dns",
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
    Esql.source_ips = VALUES(source.ip),
    Esql.source_ip_count = COUNT_DISTINCT(source.ip),
    Esql.hosts = VALUES(host.name),
    Esql.host_count = COUNT_DISTINCT(host.name),
    Esql.users = VALUES(user.name)
  BY destination.ip
| WHERE Esql.domain_count >= 2 AND (Esql.unique_rules >= 2 OR Esql.source_ip_count >= 2)
| EVAL
    Esql.risk_score = ROUND(Esql.total_risk_score
        * CASE(Esql.source_ip_count >= 3, 1.5, Esql.source_ip_count >= 2, 1.25, 1.0)),
    Esql.correlation_severity = CASE(
        Esql.risk_score >= 120 OR (Esql.domain_count >= 4 AND Esql.source_ip_count >= 3), "critical",
        Esql.risk_score >= 60 OR Esql.domain_count >= 3, "high",
        "medium"
    ),
    Esql.description = CONCAT(
        "Destination IP ", TO_STRING(destination.ip),
        " | Risk: ", TO_STRING(Esql.risk_score),
        " | ", TO_STRING(Esql.source_ip_count), " internal sources reaching this destination",
        " | ", TO_STRING(Esql.domain_count), " domains",
        " | ", TO_STRING(Esql.unique_rules), " rules"
    )
| SORT Esql.risk_score DESC
| LIMIT 50
```

## Strategy

Source IP count multiplier amplifies risk when multiple internal hosts reach the same destination — 3+ sources = 1.5x. Three hosts connecting to the same bad IP is a spreading infection or shared watering hole.

## Severity Logic

| Condition | Severity |
|-----------|----------|
| risk_score >= 120 OR (domain_count >= 4 AND source_ip_count >= 3) | Critical |
| risk_score >= 60 OR domain_count >= 3 | High |
| Everything else crossing threshold | Medium |

## Notes

- **Blind Spots:**
  - Domain fronting: traffic to legitimate CDN IPs masks true destination
  - Internal LB IPs: all traffic to a web app appears as traffic to one IP
  - DNS-over-HTTPS bypasses DNS layer visibility
- **False Positives:**
  - Popular SaaS destinations (M365, Google). Mitigation: allow-list SaaS IP ranges.
  - Windows Update / CDN servers. Mitigation: exclude vendor update CIDRs.
- **Tuning:**
  - Maintain SaaS and CDN IP allow-lists to reduce noise
  - Adjust source_ip_count multiplier thresholds based on environment size

## Data Requirements

- **Index**: `.internal.alerts-security.alerts-default`
- **Required fields**: `destination.ip`, `source.ip`, `event.dataset`, `signal.rule.severity`, `kibana.alert.workflow_status`, `kibana.alert.rule.building_block_type`, `kibana.alert.rule.name`, `kibana.alert.rule.threat.tactic.name`, `@timestamp`, `host.name`, `user.name`
- **Minimum volume**: 2+ alerts from 2+ domains for same destination IP in 4h

## Dependencies

None required. Optional: SaaS/CDN IP allow-list lookup for false positive reduction.

## Validation

C2 server at single IP, 3 compromised workstations beacon to it. Firewall + proxy + NDR alert. domain_count >= 3, source_ip_count >= 3.

## Elastic Comparison

No Elastic equivalent for destination-IP cross-domain correlation.
