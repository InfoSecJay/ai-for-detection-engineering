# Network Beaconing with Endpoint Activity

---

## Metadata

- **Rule ID:** `CORR-2J`
- **Tier:** 2 — Kill Chain and Behavioral Correlation
- **Author:** Detection Engineering
- **Description:** Detect hosts where both network-domain alerts (firewall, NDR, proxy, DNS) AND endpoint-domain alerts fire within a 4-hour window. This cross-domain pairing is particularly significant for C2 detection: a network alert for beaconing or unusual outbound traffic combined with endpoint alerts for suspicious process execution or discovery activity on the same host strongly indicates an active C2 channel with endpoint-side payload activity.
- **Join Key(s):** `host.name`
- **Lookback:** 4 hours
- **Schedule:** Every 15 minutes
- **Priority:** P2
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
            OR event.dataset LIKE "windows*" OR event.dataset LIKE "sysmon*"
            OR event.dataset LIKE "microsoft-defender*" OR event.dataset LIKE "crowdstrike*"
            OR event.dataset LIKE "carbon_black*",
            "endpoint",
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
        event.dataset LIKE "dns*",
            "dns",
        COALESCE(labels.technology, event.module, "other")
    ),
    is_network = CASE(
        domain_category IN ("network_fw", "network_ndr", "proxy", "dns"), 1, 0
    ),
    is_endpoint = CASE(domain_category == "endpoint", 1, 0),
    severity_weight = CASE(
        signal.rule.severity == "critical", 25,
        signal.rule.severity == "high", 15,
        signal.rule.severity == "medium", 8,
        signal.rule.severity == "low", 3, 1
    ),
    bbr_factor = CASE(kibana.alert.rule.building_block_type == "default", 0.3, 1.0),
    alert_risk = ROUND(severity_weight * bbr_factor),
    is_c2_tactic = CASE(
        kibana.alert.rule.threat.tactic.name == "Command and Control", 1, 0
    ),
    is_c2_pattern = CASE(
        kibana.alert.rule.name LIKE "*beacon*"
            OR kibana.alert.rule.name LIKE "*C2*"
            OR kibana.alert.rule.name LIKE "*command and control*"
            OR kibana.alert.rule.name LIKE "*DNS tunnel*"
            OR kibana.alert.rule.name LIKE "*DGA*"
            OR kibana.alert.rule.name LIKE "*domain generation*"
            OR kibana.alert.rule.name LIKE "*cobalt*strike*"
            OR kibana.alert.rule.name LIKE "*sliver*"
            OR kibana.alert.rule.name LIKE "*periodic*beaconing*"
            OR kibana.alert.rule.name LIKE "*unusual*outbound*"
            OR kibana.alert.rule.name LIKE "*suspicious*DNS*", 1, 0
    ),
    is_execution = CASE(
        kibana.alert.rule.threat.tactic.name == "Execution", 1, 0
    )
| STATS
    Esql.alert_count = COUNT(*),
    Esql.first_seen = MIN(@timestamp),
    Esql.last_seen = MAX(@timestamp),
    Esql.total_risk_score = SUM(alert_risk),
    Esql.network_alert_count = SUM(is_network),
    Esql.endpoint_alert_count = SUM(is_endpoint),
    Esql.c2_tactic_count = SUM(is_c2_tactic),
    Esql.c2_pattern_count = SUM(is_c2_pattern),
    Esql.execution_count = SUM(is_execution),
    Esql.tactic_count = COUNT_DISTINCT(kibana.alert.rule.threat.tactic.name),
    Esql.tactic_values = VALUES(kibana.alert.rule.threat.tactic.name),
    Esql.unique_rules = COUNT_DISTINCT(kibana.alert.rule.name),
    Esql.rule_names = VALUES(kibana.alert.rule.name),
    Esql.domain_count = COUNT_DISTINCT(domain_category),
    Esql.domain_values = VALUES(domain_category),
    Esql.user_values = VALUES(user.name),
    Esql.dest_ips = VALUES(destination.ip),
    Esql.dest_ports = VALUES(destination.port),
    Esql.ip_values = VALUES(related.ip)
  BY host.name
| WHERE Esql.network_alert_count >= 1
    AND Esql.endpoint_alert_count >= 1
| EVAL
    Esql.risk_score = ROUND(Esql.total_risk_score * 1.5),
    Esql.has_c2_signal = CASE(
        Esql.c2_tactic_count >= 1 OR Esql.c2_pattern_count >= 1, 1, 0
    ),
    Esql.correlation_severity = CASE(
        Esql.has_c2_signal == 1 AND Esql.execution_count >= 1, "critical",
        Esql.has_c2_signal == 1, "high",
        Esql.network_alert_count >= 1 AND Esql.endpoint_alert_count >= 1, "high",
        "medium"
    ),
    Esql.description = CONCAT(
        "Host ", host.name,
        " | Network Beaconing + Endpoint Activity",
        " | Risk Score: ", TO_STRING(Esql.risk_score),
        " | Network alerts: ", TO_STRING(Esql.network_alert_count),
        " | Endpoint alerts: ", TO_STRING(Esql.endpoint_alert_count),
        " | C2 indicators: ", TO_STRING(Esql.has_c2_signal),
        " | Execution alerts: ", TO_STRING(Esql.execution_count),
        " | ", TO_STRING(Esql.domain_count), " domains",
        " | ", TO_STRING(Esql.unique_rules), " rules",
        " | Dest IPs: ", TO_STRING(Esql.dest_ips)
    )
| SORT Esql.risk_score DESC
| LIMIT 50
```

## Strategy

Each alert is domain-categorized. STATS computes per-domain presence flags for each host. The rule filters for hosts that have at least one network-domain alert AND at least one endpoint-domain alert. Additional classification checks for C2-indicative patterns (Command and Control tactic, beaconing-related rule names, DNS tunneling). A 1.5x cross-domain bonus is applied because network + endpoint correlation crosses fundamentally different detection surfaces.

## Severity Logic

```
CASE(
    Esql.has_c2_signal == 1 AND Esql.execution_count >= 1, "critical",
    Esql.has_c2_signal == 1, "high",
    Esql.network_alert_count >= 1 AND Esql.endpoint_alert_count >= 1, "high",
    "medium"
)
```

| Condition | Severity |
|-----------|----------|
| C2 tactic/pattern alert AND endpoint execution alert on same host | Critical |
| C2 tactic/pattern alert AND any endpoint alert (network anomaly + endpoint) | High |
| Any network-domain alert AND any endpoint alert (cross-domain without C2 signal) | High |
| Fallback | Medium |

## Notes

- **Blind Spots:**
  - Encrypted C2 channels that bypass network detection — if the C2 traffic is successfully encrypted and does not trigger network alerts, only endpoint alerts will be visible
  - Endpoint alerts without matching network alerts due to NAT — if the host's traffic is NATed, the network alert may reference a different IP/host than the endpoint agent
  - C2 frameworks using legitimate cloud services (Azure Blob, S3, GitHub) for staging — these may not trigger network anomaly alerts
  - DNS-over-HTTPS C2 channels that bypass DNS-layer visibility

- **False Positives:**
  - **Software update services with periodic check-ins**: Automatic update mechanisms (Windows Update, application auto-updaters) create periodic outbound connections that may match beaconing patterns, combined with installer execution on the endpoint. Mitigation: exclude known update service destinations and processes.
  - **Cloud-based monitoring agents**: Agents (Datadog, New Relic, Dynatrace) that beacon to cloud endpoints and run local endpoint processes. Mitigation: register monitoring agent processes and destinations.
  - **VPN clients**: VPN software creates persistent tunneled connections (network alert) while running endpoint processes. Mitigation: exclude known VPN process names and destination IPs.

- **Tuning:**
  1. C2 pattern matching — customize `is_c2_pattern` CASE for your detection rule naming conventions
  2. Network domain scope — add or remove network categories from `is_network` based on your stack (e.g., add WAF if available)
  3. Cross-domain bonus (default: 1.5x) — increase to 2.0x if network + endpoint correlation is a high-priority signal in your environment
  4. Add destination IP context: correlate `destination.ip` from network alerts with threat intelligence feeds for known C2 infrastructure
  5. Consider a time-gap variant: require the network alert and endpoint alert to occur within 30 minutes of each other for tighter correlation

## Data Requirements

- **Index**: `.internal.alerts-security.alerts-default`
- **Required fields**: `host.name`, `@timestamp`, `event.dataset`, `signal.rule.severity`, `kibana.alert.workflow_status`, `kibana.alert.rule.building_block_type`, `kibana.alert.rule.name`, `kibana.alert.rule.threat.tactic.name`, `user.name`, `destination.ip`, `destination.port`, `related.ip`
- **Minimum volume**: 1+ network-domain alert AND 1+ endpoint-domain alert for same `host.name` within 4h
- **Critical dependency**: Both network-based detection rules (firewall, NDR, proxy, or DNS) AND endpoint-based detection rules must be deployed and generating alerts

## Dependencies

- No required lookup indices
- Prerequisite: Network-domain detection rules (firewall, NDR, IDS, proxy, DNS) AND endpoint-domain detection rules must both be deployed
- Optional: `lookup-critical-assets` — escalate severity for critical infrastructure hosts
- Complementary: CORR-1B (Host multi-domain) will also fire for these hosts, but CORR-2J adds specific C2-pattern classification and network-endpoint pairing logic

## Validation

Red team scenario:
1. Establish a C2 beacon (Cobalt Strike, Sliver, or similar) from a test host to an external server
2. Ensure the beacon traffic triggers a network detection rule (firewall C2 alert, NDR beaconing alert, or DNS tunneling alert)
3. Execute discovery commands on the endpoint through the C2 channel (triggers endpoint Execution/Discovery alerts)

Expected result: Host appears with `Esql.network_alert_count >= 1`, `Esql.endpoint_alert_count >= 1`, `Esql.has_c2_signal = 1`, severity = critical (if execution is present) or high.

## Elastic Comparison

Elastic does not ship a network-beaconing-with-endpoint-activity correlation rule. Elastic has individual rules for network anomalies (e.g., "Network Connection via Signed Binary") and C2-related detections, but does not correlate network-layer alerts with endpoint-layer alerts on the same host. CORR-2J bridges the network-endpoint visibility gap that is the core challenge in C2 detection.
