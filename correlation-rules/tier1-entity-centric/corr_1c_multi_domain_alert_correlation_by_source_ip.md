# Multi-Domain Alert Correlation by Source IP

---

## Metadata

- **Rule ID:** `CORR-1C`
- **Tier:** 1 — Entity-Centric Correlation
- **Author:** Detection Engineering
- **Description:** Detect external source IPs generating alerts across two or more detection domains. Catches external attackers probing your perimeter across multiple surfaces — same IP hitting firewall, triggering IDS, and appearing in identity auth failures.
- **Join Key(s):** `source.ip`
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
    AND source.ip IS NOT NULL
    AND NOT CIDR_MATCH(source.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8")
    AND NOT (event.dataset LIKE "email*" OR event.dataset LIKE "proofpoint*"
        OR event.dataset LIKE "mimecast*")
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
    Esql.dest_ips = VALUES(destination.ip),
    Esql.dest_ports = VALUES(destination.port),
    Esql.hosts = VALUES(host.name),
    Esql.users = VALUES(user.name)
  BY source.ip
| WHERE Esql.domain_count >= 2 AND Esql.unique_rules >= 2
| EVAL
    Esql.correlation_severity = CASE(
        Esql.total_risk_score >= 100 OR Esql.domain_count >= 4, "critical",
        Esql.total_risk_score >= 50 OR Esql.domain_count >= 3, "high",
        "medium"
    ),
    Esql.description = CONCAT(
        "External IP ", TO_STRING(source.ip),
        " | Risk: ", TO_STRING(Esql.total_risk_score),
        " | ", TO_STRING(Esql.unique_rules), " rules across ",
        TO_STRING(Esql.domain_count), " domains",
        " | ", TO_STRING(Esql.tactic_count), " tactics"
    )
| SORT Esql.total_risk_score DESC
| LIMIT 50
```

## Strategy

Filters to external IPs only (excludes RFC 1918). Excludes email-domain alerts because `source.ip` in email logs = sending mail server, not the attacker. Domain-count multiplier is higher (0.30) because external IPs across multiple domains is a stronger signal.

## Severity Logic

| Condition | Severity |
|-----------|----------|
| risk_score >= 100 OR domain_count >= 4 | Critical |
| risk_score >= 50 OR domain_count >= 3 | High |
| Everything else crossing threshold | Medium |

## Notes

- **Blind Spots:**
  - Attackers using different IPs per domain (VPN rotation)
  - CDN/proxy IPs mask true attacker source
  - NAT: all outbound traffic shares the same source.ip
- **False Positives:**
  - Authorized vulnerability scanners. Mitigation: maintain scanner exclusion list.
  - CDN/shared hosting IPs. Mitigation: exclude major CDN CIDRs.
- **Tuning:**
  - Maintain a scanner and CDN IP exclusion list
  - Adjust risk score thresholds based on volume of external-facing alerts

## Data Requirements

- **Index**: `.internal.alerts-security.alerts-default`
- **Required fields**: `source.ip`, `event.dataset`, `signal.rule.severity`, `kibana.alert.workflow_status`, `kibana.alert.rule.building_block_type`, `kibana.alert.rule.name`, `kibana.alert.rule.threat.tactic.name`, `@timestamp`, `destination.ip`, `destination.port`, `host.name`, `user.name`
- **Minimum volume**: 2+ alerts from 2+ domains for same source IP in 4h

## Dependencies

None required. Optional: CDN/scanner IP exclusion lookup for false positive reduction.

## Validation

External scan from single IP (firewall) + credential stuffing from same IP (identity) + web exploit attempt from same IP (proxy). domain_count >= 3.

## Elastic Comparison

No Elastic equivalent. Closest is "Threat Intel IP Indicator Match" — single-event TI matching, not cross-domain aggregation.
