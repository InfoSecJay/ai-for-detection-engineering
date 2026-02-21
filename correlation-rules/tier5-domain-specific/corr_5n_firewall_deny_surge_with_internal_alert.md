# Firewall Deny Surge with Internal Alert

---

## Metadata

- **Rule ID:** `CORR-5N`
- **Tier:** 5 — Domain-Specific Correlation
- **Author:** Detection Engineering
- **Description:** Detect internal IP addresses generating a high volume of firewall deny alerts AND simultaneously having endpoint or other domain alerts. This pattern indicates a compromised host attempting to spread laterally -- the firewall blocks its attempts to reach other network segments while the endpoint detects the malware or attacker activity driving those connection attempts. The combination of "many blocked connections" plus "endpoint detection on the source" is a strong indicator of active compromise with attempted propagation.
- **Join Key(s):** `source.ip` (internal IP)
- **Lookback:** 1 hour
- **Schedule:** Every 10 minutes
- **Priority:** P2
- **Integration:** [alerts](https://www.elastic.co/guide/en/security/current/alerts-ui-manage.html)
- **Language:** `[ES|QL]`

## Query

```esql
FROM .internal.alerts-security.alerts-default
| WHERE @timestamp > NOW() - 1 HOURS
    AND kibana.alert.workflow_status == "open"
    AND source.ip IS NOT NULL
    AND CIDR_MATCH(source.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
    AND (
        event.dataset LIKE "panw*" OR event.dataset LIKE "fortinet*"
        OR event.dataset LIKE "firewall*" OR event.dataset LIKE "paloalto*"
        OR event.dataset LIKE "checkpoint*"
        OR event.dataset LIKE "endpoint*" OR event.dataset LIKE "sentinelone*"
        OR event.dataset LIKE "windows*" OR event.dataset LIKE "sysmon*"
        OR event.dataset LIKE "microsoft-defender*" OR event.dataset LIKE "crowdstrike*"
        OR event.dataset LIKE "carbon_black*"
    )
| EVAL
    domain_category = CASE(
        event.dataset LIKE "panw*" OR event.dataset LIKE "fortinet*"
            OR event.dataset LIKE "firewall*" OR event.dataset LIKE "paloalto*"
            OR event.dataset LIKE "checkpoint*",
            "network_fw",
        event.dataset LIKE "endpoint*" OR event.dataset LIKE "sentinelone*"
            OR event.dataset LIKE "windows*" OR event.dataset LIKE "sysmon*"
            OR event.dataset LIKE "microsoft-defender*" OR event.dataset LIKE "crowdstrike*"
            OR event.dataset LIKE "carbon_black*",
            "endpoint",
        "other"
    ),
    severity_weight = CASE(
        signal.rule.severity == "critical", 25,
        signal.rule.severity == "high", 15,
        signal.rule.severity == "medium", 8,
        signal.rule.severity == "low", 3, 1
    ),
    bbr_factor = CASE(kibana.alert.rule.building_block_type == "default", 0.3, 1.0),
    alert_risk = ROUND(severity_weight * bbr_factor),
    is_fw_deny = CASE(domain_category == "network_fw", 1, 0),
    is_endpoint = CASE(domain_category == "endpoint", 1, 0)
| STATS
    Esql.alert_count = COUNT(*),
    Esql.first_seen = MIN(@timestamp),
    Esql.last_seen = MAX(@timestamp),
    Esql.total_risk = SUM(alert_risk),
    Esql.deny_alert_count = SUM(is_fw_deny),
    Esql.internal_alert_count = SUM(is_endpoint),
    Esql.denied_destinations = COUNT_DISTINCT(destination.ip),
    Esql.destination_values = VALUES(destination.ip),
    Esql.destination_ports = VALUES(destination.port),
    Esql.unique_rules = COUNT_DISTINCT(kibana.alert.rule.name),
    Esql.rule_names = VALUES(kibana.alert.rule.name),
    Esql.tactic_values = VALUES(kibana.alert.rule.threat.tactic.name),
    Esql.host_values = VALUES(host.name),
    Esql.user_values = VALUES(user.name),
    Esql.data_sources = VALUES(event.dataset)
  BY source.ip
| WHERE Esql.deny_alert_count >= 5 AND Esql.internal_alert_count >= 1
| EVAL
    Esql.risk_score = Esql.total_risk,
    Esql.severity = CASE(
        Esql.deny_alert_count >= 20 AND Esql.internal_alert_count >= 1, "critical",
        Esql.deny_alert_count >= 10 AND Esql.internal_alert_count >= 1, "high",
        Esql.deny_alert_count >= 5 AND Esql.internal_alert_count >= 1, "medium",
        "low"
    ),
    Esql.description = CONCAT(
        "Firewall deny surge with endpoint alert from internal IP ", TO_STRING(source.ip),
        " | ", TO_STRING(Esql.deny_alert_count), " firewall deny alerts",
        " | ", TO_STRING(Esql.internal_alert_count), " endpoint alerts",
        " | ", TO_STRING(Esql.denied_destinations), " distinct blocked destinations",
        " | Risk Score: ", TO_STRING(Esql.risk_score),
        " | Window: ", TO_STRING(Esql.first_seen), " to ", TO_STRING(Esql.last_seen)
    )
| SORT Esql.risk_score DESC
| LIMIT 50
```

## Strategy

Filters to internal source IPs by including only RFC 1918 ranges. Classifies alerts into network_fw domain (deny alerts) and endpoint domain. Aggregates by `source.ip` and counts denied connection alerts, endpoint alerts, and destination diversity (how many distinct internal targets the host attempted to reach). Requires both a minimum deny count AND at least one endpoint alert to fire, ensuring the rule captures the "blocked propagation + host compromise" combination.

## Severity Logic

| Condition | Severity |
|-----------|----------|
| deny >= 20 + endpoint alert | Critical |
| deny >= 10 + endpoint alert | High |
| deny >= 5 + endpoint alert | Medium |

## Notes

- **Blind Spots:**
  - Hosts on flat networks without internal firewall segmentation (no deny alerts generated for east-west traffic)
  - Worm propagation over protocols that are allowed through the firewall (e.g., SMB on port 445 if allowed between segments)
  - Source IP attribution failure due to NAT between network segments
  - Endpoints without EDR coverage that generate firewall denies but no endpoint alerts

- **False Positives:**
  - **Misconfigured applications**: Applications attempting to reach decommissioned services or wrong network segments. Mitigation: correlate with application deployment records and network change tickets.
  - **Network migration aftermath**: Hosts with stale DNS or configuration pointing to old network segments. Mitigation: check against recent network change windows.
  - **Discovery/monitoring tools**: Legitimate network monitoring tools that probe multiple destinations. Mitigation: exclude known monitoring tool source IPs.

- **Tuning:**
  1. `deny_alert_count` threshold (default: 5) -- increase to 10 or 20 in environments with noisy firewall alerting
  2. Add destination port analysis -- denies on port 445 (SMB), 3389 (RDP), or 22 (SSH) suggest lateral movement more strongly than denies on random ports
  3. Consider adding time-of-day weighting -- deny surges during off-hours are more suspicious
  4. Add `denied_destinations` to the severity logic -- 20+ denied destinations suggests automated scanning/propagation rather than targeted lateral movement

## Data Requirements

- **Index**: `.internal.alerts-security.alerts-default`
- **Required fields**: `source.ip`, `destination.ip`, `destination.port`, `event.dataset`, `signal.rule.severity`, `kibana.alert.rule.name`, `kibana.alert.rule.building_block_type`, `kibana.alert.rule.threat.tactic.name`, `@timestamp`, `host.name`, `user.name`
- **Minimum data sources**: At least one network firewall integration with deny/block alerting AND at least one endpoint EDR integration
- **Minimum volume**: 5+ firewall deny alerts + 1+ endpoint alert from same internal source IP within 1h

## Dependencies

None required.

## Validation

On a test host:
1. Introduce test malware or simulate a compromised host that attempts to connect to multiple internal IP addresses on blocked ports (generates firewall deny alerts)
2. Simultaneously, ensure the EDR agent detects the malicious process or behavior driving the connection attempts (generates endpoint alert)

Expected result: Internal source IP appears with `Esql.deny_alert_count >= 5`, `Esql.internal_alert_count >= 1`, `Esql.denied_destinations` showing the attempted targets, severity of medium or higher.

## Elastic Comparison

Elastic does not ship a firewall-deny-plus-endpoint correlation rule. Firewall deny alerts and endpoint alerts are triaged independently. CORR-5N connects network-level blocked propagation attempts with host-level malware detection, providing the complete picture of a compromised host attempting to spread.
