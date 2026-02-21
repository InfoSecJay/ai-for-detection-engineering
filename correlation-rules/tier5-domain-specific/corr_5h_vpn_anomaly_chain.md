# VPN Anomaly Chain

---

## Metadata

- **Rule ID:** `CORR-5H`
- **Tier:** 5 — Domain-Specific Correlation
- **Author:** Detection Engineering
- **Description:** Detect a user exhibiting VPN-related anomalies (unusual source location, concurrent sessions) combined with network-layer alerts indicating suspicious post-VPN activity (internal lateral movement, scanning). VPN access is the primary remote entry point for most enterprise environments. An attacker with stolen VPN credentials can appear as a legitimate remote user -- the combination of VPN access anomalies with subsequent network behavior anomalies is a critical indicator of credential compromise and initial access.
- **Join Key(s):** `user.name`
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
    AND user.name IS NOT NULL
    AND (
        event.dataset LIKE "okta*" OR event.dataset LIKE "azure_ad*"
        OR event.dataset LIKE "entra*" OR event.dataset LIKE "onelogin*"
        OR event.dataset LIKE "ping*" OR event.dataset LIKE "auth0*"
        OR event.dataset LIKE "panw*" OR event.dataset LIKE "fortinet*"
        OR event.dataset LIKE "firewall*" OR event.dataset LIKE "paloalto*"
        OR event.dataset LIKE "checkpoint*"
        OR event.dataset LIKE "extrahop*" OR event.dataset LIKE "zeek*"
        OR event.dataset LIKE "suricata*" OR event.dataset LIKE "ndr*"
    )
| EVAL
    domain_category = CASE(
        event.dataset LIKE "okta*" OR event.dataset LIKE "azure_ad*"
            OR event.dataset LIKE "entra*" OR event.dataset LIKE "onelogin*"
            OR event.dataset LIKE "ping*" OR event.dataset LIKE "auth0*",
            "identity",
        event.dataset LIKE "panw*" OR event.dataset LIKE "fortinet*"
            OR event.dataset LIKE "firewall*" OR event.dataset LIKE "paloalto*"
            OR event.dataset LIKE "checkpoint*",
            "network_fw",
        event.dataset LIKE "extrahop*" OR event.dataset LIKE "zeek*"
            OR event.dataset LIKE "suricata*" OR event.dataset LIKE "ndr*",
            "network_ndr",
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
    is_vpn_anomaly = CASE(
        kibana.alert.rule.name LIKE "*VPN*"
            OR kibana.alert.rule.name LIKE "*Impossible*Travel*"
            OR kibana.alert.rule.name LIKE "*Unusual*Location*"
            OR kibana.alert.rule.name LIKE "*Concurrent*Session*"
            OR kibana.alert.rule.name LIKE "*New*Country*"
            OR kibana.alert.rule.name LIKE "*Anomalous*Geo*",
            1, 0
    ),
    is_network_alert = CASE(
        domain_category == "network_fw" OR domain_category == "network_ndr", 1, 0
    ),
    is_lateral_movement = CASE(
        kibana.alert.rule.threat.tactic.name == "Lateral Movement", 1, 0
    )
| STATS
    Esql.alert_count = COUNT(*),
    Esql.first_seen = MIN(@timestamp),
    Esql.last_seen = MAX(@timestamp),
    Esql.total_risk = SUM(alert_risk),
    Esql.has_vpn_anomaly = MAX(is_vpn_anomaly),
    Esql.has_network_alert = MAX(is_network_alert),
    Esql.has_lateral_movement = MAX(is_lateral_movement),
    Esql.source_countries = COUNT_DISTINCT(source.geo.country_name),
    Esql.country_values = VALUES(source.geo.country_name),
    Esql.unique_rules = COUNT_DISTINCT(kibana.alert.rule.name),
    Esql.rule_names = VALUES(kibana.alert.rule.name),
    Esql.tactic_values = VALUES(kibana.alert.rule.threat.tactic.name),
    Esql.source_ips = VALUES(source.ip),
    Esql.host_values = VALUES(host.name),
    Esql.data_sources = VALUES(event.dataset)
  BY user.name
| WHERE Esql.has_vpn_anomaly == 1
    AND (Esql.has_network_alert == 1 OR Esql.source_countries >= 2)
| EVAL
    Esql.risk_score = Esql.total_risk,
    Esql.severity = CASE(
        Esql.has_vpn_anomaly == 1 AND Esql.has_lateral_movement == 1, "critical",
        Esql.has_vpn_anomaly == 1 AND Esql.has_network_alert == 1, "high",
        Esql.has_vpn_anomaly == 1 AND Esql.source_countries >= 2, "medium",
        "low"
    ),
    Esql.description = CONCAT(
        "VPN anomaly chain for user ", user.name,
        " | VPN anomaly: ", TO_STRING(Esql.has_vpn_anomaly),
        " | Network alert: ", TO_STRING(Esql.has_network_alert),
        " | Lateral movement: ", TO_STRING(Esql.has_lateral_movement),
        " | ", TO_STRING(Esql.source_countries), " source countries",
        " | Risk Score: ", TO_STRING(Esql.risk_score),
        " | Window: ", TO_STRING(Esql.first_seen), " to ", TO_STRING(Esql.last_seen)
    )
| SORT Esql.risk_score DESC
| LIMIT 50
```

## Strategy

Correlates identity-domain VPN-related alerts with network-domain alerts for the same user. Tracks geographic diversity of source connections as an additional risk factor. Filters to users who have both VPN anomaly alerts AND network alerts, or who show multi-country source diversity indicating potential credential sharing or compromise.

## Severity Logic

| Condition | Severity |
|-----------|----------|
| VPN anomaly + lateral movement tactic | Critical |
| VPN anomaly + any network alert | High |
| VPN location anomaly (2+ countries) | Medium |

## Notes

- **Blind Spots:**
  - VPN solutions that do not generate alerts through Elastic integrations (on-premises VPN concentrators without log forwarding)
  - Users who legitimately travel frequently (generating location anomaly alerts as false positives)
  - Split-tunnel VPN configurations where only some traffic routes through the VPN (network alerts may not correlate with VPN sessions)
  - Attackers who use VPN credentials from expected locations (same country as the legitimate user)

- **False Positives:**
  - **Frequent travelers**: Employees who connect from multiple countries legitimately. Mitigation: use `lookup-geo-baselines` to establish expected countries per user.
  - **Mobile workforce**: Field workers using cellular connections that route through different country gateways. Mitigation: add known cellular carrier IP ranges to expected patterns.
  - **VPN client reconnections**: VPN drops and reconnects may generate concurrent session alerts. Mitigation: add minimum session overlap duration requirement.

- **Tuning:**
  1. Customize the `is_vpn_anomaly` CASE patterns to match your specific VPN and identity alert rule names
  2. Deploy `lookup-geo-baselines` and add a LOOKUP JOIN to check whether source countries are expected -- this dramatically reduces false positives for traveling users
  3. `source_countries` threshold (default: 2) -- keep at 2 but combine with time analysis (2 countries within 1 hour is more suspicious than 2 countries within 4 hours)
  4. Add VPN session duration analysis if available -- very short VPN sessions followed by network scanning suggest automated credential abuse

## Data Requirements

- **Index**: `.internal.alerts-security.alerts-default`
- **Required fields**: `user.name`, `event.dataset`, `signal.rule.severity`, `kibana.alert.rule.name`, `kibana.alert.rule.building_block_type`, `kibana.alert.rule.threat.tactic.name`, `@timestamp`, `source.ip`, `source.geo.country_name`, `host.name`
- **Minimum data sources**: At least one identity provider integration with VPN/location alerting AND at least one network monitoring integration
- **Minimum volume**: 1+ VPN anomaly alert + (1+ network alert OR 2+ source countries) for same user within 4h

## Dependencies

Optional: `lookup-geo-baselines` for per-user expected country baselines.

## Validation

1. Connect to VPN from an unusual country (or simulate geo-anomaly alert) for a test user
2. After VPN connection, perform internal network scanning activity from the VPN-connected session (triggers network/firewall alerts)

Expected result: User appears with VPN anomaly and network alerts correlated, severity of high (or critical if lateral movement tactic detected).

## Elastic Comparison

Elastic ships individual VPN and geo-anomaly rules but does not correlate VPN access anomalies with subsequent internal network activity. CORR-5H connects the remote access anomaly with its downstream impact, providing a complete picture of VPN credential abuse.
