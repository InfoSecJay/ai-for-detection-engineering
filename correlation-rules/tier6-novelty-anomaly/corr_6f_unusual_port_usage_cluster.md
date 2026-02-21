# Unusual Port Usage Cluster

---

## Metadata

- **Rule ID:** `CORR-6F`
- **Tier:** 6 — Novelty and Anomaly Detection
- **Author:** Detection Engineering
- **Description:** Detect hosts or source IPs generating alerts involving destination ports flagged as unusual or non-standard in the network baseline. An internal host suddenly communicating on ports 4444, 8888, and 9001 -- all non-standard -- while also triggering firewall and IDS alerts is a strong indicator of C2 communication, data exfiltration, or unauthorized tunneling.
- **Join Key(s):** `COALESCE(host.name, TO_STRING(source.ip))`
- **Lookback:** 4 hours
- **Schedule:** Every 15 minutes
- **Priority:** P3
- **Integration:** [alerts](https://www.elastic.co/guide/en/security/current/alerts-ui-manage.html)
- **Language:** `[ES|QL]`

## Query

```esql
FROM .internal.alerts-security.alerts-default
| WHERE @timestamp > NOW() - 4 HOURS
    AND kibana.alert.workflow_status == "open"
    AND destination.port IS NOT NULL
    AND (host.name IS NOT NULL OR source.ip IS NOT NULL)
    AND (
        event.dataset LIKE "panw*" OR event.dataset LIKE "fortinet*"
        OR event.dataset LIKE "firewall*" OR event.dataset LIKE "paloalto*"
        OR event.dataset LIKE "checkpoint*"
        OR event.dataset LIKE "extrahop*" OR event.dataset LIKE "zeek*"
        OR event.dataset LIKE "suricata*" OR event.dataset LIKE "ndr*"
        OR event.dataset LIKE "proxy*" OR event.dataset LIKE "zscaler*"
        OR event.dataset LIKE "bluecoat*" OR event.dataset LIKE "squid*"
    )
| EVAL
    entity = COALESCE(host.name, TO_STRING(source.ip)),
    severity_weight = CASE(
        signal.rule.severity == "critical", 25,
        signal.rule.severity == "high", 15,
        signal.rule.severity == "medium", 8,
        signal.rule.severity == "low", 3, 1
    ),
    bbr_factor = CASE(kibana.alert.rule.building_block_type == "default", 0.3, 1.0),
    alert_risk = ROUND(severity_weight * bbr_factor),
    domain_category = CASE(
        event.dataset LIKE "panw*" OR event.dataset LIKE "fortinet*"
            OR event.dataset LIKE "firewall*" OR event.dataset LIKE "paloalto*"
            OR event.dataset LIKE "checkpoint*", "network_fw",
        event.dataset LIKE "extrahop*" OR event.dataset LIKE "zeek*"
            OR event.dataset LIKE "suricata*" OR event.dataset LIKE "ndr*", "network_ndr",
        event.dataset LIKE "proxy*" OR event.dataset LIKE "zscaler*"
            OR event.dataset LIKE "bluecoat*" OR event.dataset LIKE "squid*", "proxy",
        "network"
    )
| LOOKUP JOIN lookup-network-baselines ON destination.port
| WHERE is_standard == false OR is_standard IS NULL
| STATS
    Esql.unusual_port_alerts = COUNT(*),
    Esql.distinct_unusual_ports = COUNT_DISTINCT(destination.port),
    Esql.risk_score = SUM(alert_risk),
    Esql.max_severity = MAX(severity_weight),
    Esql.first_seen = MIN(@timestamp),
    Esql.last_seen = MAX(@timestamp),
    Esql.unusual_port_values = VALUES(destination.port),
    Esql.rule_names = VALUES(kibana.alert.rule.name),
    Esql.unique_rules = COUNT_DISTINCT(kibana.alert.rule.name),
    Esql.domain_count = COUNT_DISTINCT(domain_category),
    Esql.domain_values = VALUES(domain_category),
    Esql.dest_ips = VALUES(destination.ip),
    Esql.tactic_values = VALUES(kibana.alert.rule.threat.tactic.name)
  BY entity
| WHERE Esql.unusual_port_alerts >= 2 AND Esql.distinct_unusual_ports >= 2
| EVAL
    Esql.correlation_severity = CASE(
        Esql.distinct_unusual_ports >= 5, "critical",
        Esql.distinct_unusual_ports >= 3, "high",
        Esql.distinct_unusual_ports >= 2 AND Esql.domain_count >= 2, "medium",
        "medium"
    ),
    Esql.description = CONCAT(
        "Entity ", entity,
        " communicating on ", TO_STRING(Esql.distinct_unusual_ports),
        " UNUSUAL ports: ", TO_STRING(Esql.unusual_port_values),
        " | ", TO_STRING(Esql.unusual_port_alerts), " alerts",
        " | ", TO_STRING(Esql.domain_count), " network domains",
        " | Risk: ", TO_STRING(Esql.risk_score)
    )
| SORT Esql.risk_score DESC
| LIMIT 50
```

## Strategy

Filters to network-related alert domains (network_fw, network_ndr, proxy). Each alert's `destination.port` is checked against `lookup-network-baselines` via `LOOKUP JOIN` to determine whether the port is standard for the environment. Alerts on unusual ports are aggregated by source entity, counting distinct unusual ports and alert volume. The rule requires both minimum alert count and minimum port diversity to filter single-port noise.

## Severity Logic

| Condition | Severity |
|-----------|----------|
| 5+ distinct unusual ports | Critical |
| 3+ distinct unusual ports | High |
| 2+ unusual ports with multi-domain network alerts | Medium |
| 2+ unusual ports (single domain) | Medium |

## Notes

- **Blind Spots:**
  - **Encrypted tunnels**: Traffic on standard ports (443, 80) that tunnels non-standard protocols is invisible to port-based analysis.
  - **Dynamic ports**: Ephemeral/dynamic ports (49152-65535) may be flagged as unusual when they are simply return traffic.
  - **Baseline accuracy**: If `lookup-network-baselines` does not reflect the full range of legitimate ports, false positives increase.

- **False Positives:**
  - **New applications using non-standard ports**: Legitimate applications (development tools, VoIP, collaboration software) using non-standard ports. Mitigation: update `lookup-network-baselines` during application onboarding.
  - **Development environments**: Developers running services on arbitrary ports. Mitigation: tag development subnets and suppress or adjust thresholds.
  - **Port scans by authorized tools**: Vulnerability scanners using non-standard ports. Mitigation: exclude scanner source IPs.

- **Tuning:**
  1. Populate `lookup-network-baselines` with all legitimate ports observed over 30+ days
  2. `distinct_unusual_ports` threshold (default: 2) -- increase to 3 in environments with diverse port usage
  3. Exclude ephemeral port ranges (49152-65535) unless specifically monitoring for high-port C2
  4. Add source subnet context to distinguish server vs. workstation networks
  5. Consider adding a `port_frequency` threshold rather than binary is_standard classification

## Data Requirements

- **Index**: `.internal.alerts-security.alerts-default`
- **Lookup Index**: `lookup-network-baselines` (fields: `destination.port`, `port_frequency`, `is_standard`)
  - **NOTE**: The lookup index schema MUST use `destination.port` as the key field (not `host.name`) to match the LOOKUP JOIN in this query. The `is_standard` boolean field must be present for the WHERE filter to work correctly.
- **Required fields**: `host.name`, `source.ip`, `destination.port`, `destination.ip`, `event.dataset`, `signal.rule.severity`, `kibana.alert.rule.building_block_type`, `kibana.alert.workflow_status`, `@timestamp`, `kibana.alert.rule.name`
- **Minimum volume**: Network baselines populated from 30+ days of firewall/proxy/NDR logs

## Dependencies

- **Required**: `lookup-network-baselines` -- must contain port-to-standard classification
- **Optional**: `lookup-critical-assets` for severity escalation on critical network segments

## Validation

1. From a test workstation, generate alerts on 3+ non-standard ports (e.g., 4444, 8888, 9001) within 2 hours
2. Ensure these ports are NOT in `lookup-network-baselines` or are marked as `is_standard == false`
3. Verify CORR-6F surfaces the entity with `Esql.distinct_unusual_ports >= 3`
4. Confirm that alerts on standard ports (80, 443, 53) do NOT contribute to the unusual port count

## Elastic Comparison

Elastic does not ship a port-novelty correlation rule. Elastic ML has "Unusual Network Port" anomaly detection, but it operates on raw network events, not alert-level data. CORR-6F correlates port anomalies with alert severity and multi-domain network visibility for a more actionable signal.
