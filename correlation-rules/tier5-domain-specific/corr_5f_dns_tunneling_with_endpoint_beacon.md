# DNS Tunneling with Endpoint Beacon

---

## Metadata

- **Rule ID:** `CORR-5F`
- **Tier:** 5 — Domain-Specific Correlation
- **Author:** Detection Engineering
- **Description:** Detect a host generating DNS-domain alerts indicative of tunneling (high query volume, unusually long subdomains, TXT record abuse) combined with endpoint-domain alerts indicative of command-and-control activity or suspicious process behavior. DNS tunneling is a preferred exfiltration and C2 channel for advanced attackers because DNS traffic is rarely blocked and often poorly monitored. When DNS anomaly alerts coincide with endpoint C2 or suspicious process alerts on the same host, confidence in active compromise is very high.
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
    AND host.name IS NOT NULL
    AND (
        event.dataset LIKE "dns*"
        OR event.dataset LIKE "endpoint*" OR event.dataset LIKE "sentinelone*"
        OR event.dataset LIKE "windows*" OR event.dataset LIKE "sysmon*"
        OR event.dataset LIKE "microsoft-defender*" OR event.dataset LIKE "crowdstrike*"
        OR event.dataset LIKE "carbon_black*"
    )
| EVAL
    domain_category = CASE(
        event.dataset LIKE "dns*", "dns",
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
    is_dns = CASE(domain_category == "dns", 1, 0),
    is_endpoint = CASE(domain_category == "endpoint", 1, 0),
    is_c2_tactic = CASE(
        kibana.alert.rule.threat.tactic.name == "Command and Control", 1, 0
    )
| STATS
    Esql.alert_count = COUNT(*),
    Esql.first_seen = MIN(@timestamp),
    Esql.last_seen = MAX(@timestamp),
    Esql.total_risk = SUM(alert_risk),
    Esql.dns_alert_count = SUM(is_dns),
    Esql.endpoint_alert_count = SUM(is_endpoint),
    Esql.has_dns_alert = MAX(is_dns),
    Esql.has_endpoint_alert = MAX(is_endpoint),
    Esql.has_c2_tactic = MAX(is_c2_tactic),
    Esql.unique_rules = COUNT_DISTINCT(kibana.alert.rule.name),
    Esql.rule_names = VALUES(kibana.alert.rule.name),
    Esql.tactic_values = VALUES(kibana.alert.rule.threat.tactic.name),
    Esql.user_values = VALUES(user.name),
    Esql.process_names = VALUES(process.name),
    Esql.data_sources = VALUES(event.dataset)
  BY host.name
| WHERE Esql.has_dns_alert == 1 AND Esql.has_endpoint_alert == 1
| EVAL
    Esql.risk_score = Esql.total_risk,
    Esql.severity = CASE(
        Esql.has_c2_tactic == 1 AND Esql.dns_alert_count >= 1, "critical",
        Esql.has_dns_alert == 1 AND Esql.has_endpoint_alert == 1, "high",
        "medium"
    ),
    Esql.description = CONCAT(
        "DNS tunneling with endpoint beacon on host ", host.name,
        " | ", TO_STRING(Esql.dns_alert_count), " DNS alerts + ",
        TO_STRING(Esql.endpoint_alert_count), " endpoint alerts",
        " | C2 tactic present: ", TO_STRING(Esql.has_c2_tactic),
        " | Risk Score: ", TO_STRING(Esql.risk_score),
        " | Window: ", TO_STRING(Esql.first_seen), " to ", TO_STRING(Esql.last_seen)
    )
| SORT Esql.risk_score DESC
| LIMIT 50
```

## Strategy

Requires alerts from BOTH the dns domain AND the endpoint domain for the same `host.name`. Uses INLINE STATS to determine per-domain alert presence without losing individual alert context. Filters to hosts where both domain flags are true. Checks whether endpoint alerts map to the Command and Control tactic for severity escalation.

## Severity Logic

| Condition | Severity |
|-----------|----------|
| DNS tunneling alert + C2 tactic endpoint alert | Critical |
| DNS anomaly alert + any endpoint alert | High |
| Fallback | Medium |

## Notes

- **Blind Spots:**
  - DNS-over-HTTPS (DoH) bypasses traditional DNS monitoring entirely
  - Hosts that resolve DNS through a shared recursive resolver where `host.name` is not preserved in DNS alerts
  - Endpoint alerts without C2 tactic mapping -- attacks classified under other tactics miss the severity escalation
  - Legitimate DNS-heavy applications (e.g., CDN resolvers) that trigger DNS anomaly alerts

- **False Positives:**
  - **DNS-intensive legitimate applications**: Software update checkers, analytics SDKs, and CDN prefetch mechanisms that generate high DNS query volumes. Mitigation: exclude known application DNS patterns.
  - **Security scanning tools**: DNS enumeration tools used by internal security teams. Mitigation: exclude scanner hostnames.
  - **VPN split-tunnel configurations**: Hosts with split tunneling may generate unusual DNS patterns. Mitigation: correlate with VPN connection status.

- **Tuning:**
  1. Add specific DNS tunneling rule names to the `is_dns` classification if your DNS detection rules have unique naming conventions
  2. Consider adding DNS query domain analysis -- alerts involving known DGA patterns or unusually long subdomains warrant additional severity weight
  3. Adjust the lookback window based on your DNS alerting pipeline latency (some DNS alerts arrive with significant delay)
  4. Add process name correlation -- endpoint alerts involving `nslookup.exe`, `dig`, or custom DNS tools alongside DNS anomaly alerts increase confidence

## Data Requirements

- **Index**: `.internal.alerts-security.alerts-default`
- **Required fields**: `host.name`, `event.dataset`, `signal.rule.severity`, `kibana.alert.rule.name`, `kibana.alert.rule.building_block_type`, `kibana.alert.rule.threat.tactic.name`, `@timestamp`, `user.name`, `process.name`
- **Minimum data sources**: At least one DNS monitoring integration AND at least one endpoint EDR integration
- **Minimum volume**: 1+ DNS alert + 1+ endpoint alert for same host within 4h

## Dependencies

None required.

## Validation

1. On a test host, establish a DNS-based C2 channel (e.g., using dnscat2 or iodine) to trigger DNS tunneling detection alerts
2. Execute commands through the C2 channel to trigger endpoint detection alerts (e.g., process execution, file creation)

Expected result: Host appears with both DNS and endpoint alerts correlated, severity of critical if C2 tactic is present.

## Elastic Comparison

Elastic ships DNS-specific rules (e.g., "Potential DNS Tunneling via NsLookup") and endpoint C2 rules independently. No built-in correlation connects DNS anomaly detections with endpoint C2 indicators on the same host. CORR-5F provides this cross-domain DNS-to-endpoint correlation.
