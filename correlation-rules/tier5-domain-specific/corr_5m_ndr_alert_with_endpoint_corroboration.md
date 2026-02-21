# NDR Alert with Endpoint Corroboration

---

## Metadata

- **Rule ID:** `CORR-5M`
- **Tier:** 5 — Domain-Specific Correlation
- **Author:** Detection Engineering
- **Description:** Detect when both NDR (network detection and response) and endpoint detection sources generate alerts for the same host within a 2-hour window. NDR provides network-level visibility (traffic patterns, protocol anomalies, signature matches) while endpoint provides host-level visibility (process execution, file operations, memory access). When both detect suspicious activity on the same host, confidence is very high because two fundamentally different detection surfaces are corroborating the same finding. This dual-confirmation pattern dramatically reduces false positives compared to either source alone.
- **Join Key(s):** `host.name` OR `destination.ip`
- **Lookback:** 2 hours
- **Schedule:** Every 10 minutes
- **Priority:** P2
- **Integration:** [alerts](https://www.elastic.co/guide/en/security/current/alerts-ui-manage.html)
- **Language:** `[ES|QL]`

## Query

```esql
FROM .internal.alerts-security.alerts-default
| WHERE @timestamp > NOW() - 2 HOURS
    AND kibana.alert.workflow_status == "open"
    AND host.name IS NOT NULL
    AND (
        event.dataset LIKE "extrahop*" OR event.dataset LIKE "zeek*"
        OR event.dataset LIKE "suricata*" OR event.dataset LIKE "ndr*"
        OR event.dataset LIKE "endpoint*" OR event.dataset LIKE "sentinelone*"
        OR event.dataset LIKE "windows*" OR event.dataset LIKE "sysmon*"
        OR event.dataset LIKE "microsoft-defender*" OR event.dataset LIKE "crowdstrike*"
        OR event.dataset LIKE "carbon_black*"
    )
| EVAL
    domain_category = CASE(
        event.dataset LIKE "extrahop*" OR event.dataset LIKE "zeek*"
            OR event.dataset LIKE "suricata*" OR event.dataset LIKE "ndr*",
            "network_ndr",
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
    is_ndr = CASE(domain_category == "network_ndr", 1, 0),
    is_endpoint = CASE(domain_category == "endpoint", 1, 0),
    is_high_plus = CASE(
        signal.rule.severity == "critical" OR signal.rule.severity == "high", 1, 0
    ),
    ndr_high = CASE(domain_category == "network_ndr" AND is_high_plus == 1, 1, 0),
    endpoint_high = CASE(domain_category == "endpoint" AND is_high_plus == 1, 1, 0)
| STATS
    Esql.alert_count = COUNT(*),
    Esql.first_seen = MIN(@timestamp),
    Esql.last_seen = MAX(@timestamp),
    Esql.total_risk = SUM(alert_risk),
    Esql.has_ndr = MAX(is_ndr),
    Esql.has_endpoint = MAX(is_endpoint),
    Esql.ndr_alert_count = SUM(is_ndr),
    Esql.endpoint_alert_count = SUM(is_endpoint),
    Esql.has_ndr_high = MAX(ndr_high),
    Esql.has_endpoint_high = MAX(endpoint_high),
    Esql.unique_rules = COUNT_DISTINCT(kibana.alert.rule.name),
    Esql.rule_names = VALUES(kibana.alert.rule.name),
    Esql.tactic_values = VALUES(kibana.alert.rule.threat.tactic.name),
    Esql.user_values = VALUES(user.name),
    Esql.process_names = VALUES(process.name),
    Esql.source_ips = VALUES(source.ip),
    Esql.destination_ips = VALUES(destination.ip),
    Esql.data_sources = VALUES(event.dataset)
  BY host.name
| WHERE Esql.has_ndr == 1 AND Esql.has_endpoint == 1
| EVAL
    Esql.risk_score = ROUND(Esql.total_risk * 2.0),
    Esql.severity = CASE(
        Esql.has_ndr_high == 1 AND Esql.has_endpoint_high == 1, "critical",
        Esql.has_ndr == 1 AND Esql.has_endpoint == 1, "high",
        "medium"
    ),
    Esql.description = CONCAT(
        "NDR + endpoint corroboration on host ", host.name,
        " | ", TO_STRING(Esql.ndr_alert_count), " NDR alerts + ",
        TO_STRING(Esql.endpoint_alert_count), " endpoint alerts",
        " | NDR high+: ", TO_STRING(Esql.has_ndr_high),
        " | Endpoint high+: ", TO_STRING(Esql.has_endpoint_high),
        " | Risk Score: ", TO_STRING(Esql.risk_score),
        " (2.0x dual-confirmation bonus)",
        " | Window: ", TO_STRING(Esql.first_seen), " to ", TO_STRING(Esql.last_seen)
    )
| SORT Esql.risk_score DESC
| LIMIT 50
```

## Strategy

Requires alerts from BOTH the network_ndr domain AND the endpoint domain for the same `host.name`. Uses per-domain presence flags to enforce the dual-source requirement. Applies a 2.0x confidence multiplier to the risk score because NDR-plus-endpoint corroboration is a high-confidence indicator. Checks for mutual severity escalation when both domains produce high-or-above severity alerts.

## Severity Logic

| Condition | Severity |
|-----------|----------|
| Both NDR and endpoint at high+ severity | Critical |
| NDR + endpoint match (any severity) | High |
| Fallback | Medium |

## Notes

- **Blind Spots:**
  - Hosts where NDR cannot see traffic (encrypted east-west traffic, hosts on network segments without NDR sensors)
  - Endpoints without EDR agent installed or with agent in degraded mode
  - Host name resolution mismatch between NDR (which may use DNS/IP) and endpoint (which uses the local hostname)
  - NDR alerts that reference IPs rather than hostnames when no DNS resolution is available

- **False Positives:**
  - **Security scanning**: Vulnerability scanners that trigger both NDR signatures and endpoint alerts on scanned targets. Mitigation: exclude known scanner hostnames.
  - **Network monitoring tools**: Tools like Nagios or PRTG that generate network probes (NDR alerts) while running agents on hosts (endpoint alerts). Mitigation: exclude monitoring infrastructure hosts.
  - **Penetration testing**: Authorized pen test activity detected by both NDR and endpoint. Mitigation: maintain pen test host exclusion list.

- **Tuning:**
  1. The 2.0x confidence multiplier is conservative -- consider increasing to 2.5x or 3.0x if dual-confirmation correlations consistently prove to be true positives
  2. Add tactic correlation -- NDR detecting C2 plus endpoint detecting Execution on the same host is stronger than unrelated NDR and endpoint alerts
  3. Consider adding time proximity analysis -- NDR and endpoint alerts within 5 minutes of each other are more likely related than alerts 90 minutes apart
  4. If host name resolution is unreliable between NDR and endpoint, consider adding IP-based correlation as a fallback join key

## Data Requirements

- **Index**: `.internal.alerts-security.alerts-default`
- **Required fields**: `host.name`, `event.dataset`, `signal.rule.severity`, `kibana.alert.rule.name`, `kibana.alert.rule.building_block_type`, `kibana.alert.rule.threat.tactic.name`, `@timestamp`, `user.name`, `process.name`, `source.ip`, `destination.ip`
- **Minimum data sources**: At least one NDR integration (ExtraHop, Zeek, Suricata) AND at least one endpoint EDR integration
- **Minimum volume**: 1+ NDR alert + 1+ endpoint alert for same host within 2h

## Dependencies

None required.

## Validation

On a test host:
1. Generate network traffic that triggers an NDR alert (e.g., Suricata signature match for suspicious protocol behavior or Zeek notice for unusual connection pattern)
2. Simultaneously or shortly after, trigger an endpoint detection (e.g., suspicious process execution or file creation)

Expected result: Host appears with both NDR and endpoint alerts correlated, `Esql.risk_score` reflecting the 2.0x dual-confirmation multiplier, severity of high or critical.

## Elastic Comparison

Elastic does not ship an NDR-to-endpoint cross-domain correlation rule. NDR alerts (from Suricata, Zeek integrations) and endpoint alerts exist in separate alert families. CORR-5M provides the dual-confirmation correlation that dramatically increases confidence when both network and endpoint detection surfaces agree.
