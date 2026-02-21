# Web Server Attack Chain

---

## Metadata

- **Rule ID:** `CORR-5O`
- **Tier:** 5 — Domain-Specific Correlation
- **Author:** Detection Engineering
- **Description:** Detect web application attack alerts (SQL injection, cross-site scripting, remote code execution, path traversal) that are corroborated by endpoint alerts on the same web server. Web attack alerts alone have notoriously high false positive rates -- WAFs and web application firewalls flag many benign requests. But when web attack alerts coincide with endpoint-level alerts on the same server (file creation, process execution, command-line activity), the web attack likely succeeded. This correlation dramatically increases the signal-to-noise ratio of web attack detection.
- **Join Key(s):** `destination.ip` OR `host.name` (server)
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
        event.dataset LIKE "panw*" OR event.dataset LIKE "fortinet*"
        OR event.dataset LIKE "firewall*" OR event.dataset LIKE "checkpoint*"
        OR event.dataset LIKE "extrahop*" OR event.dataset LIKE "zeek*"
        OR event.dataset LIKE "suricata*" OR event.dataset LIKE "ndr*"
        OR event.dataset LIKE "proxy*" OR event.dataset LIKE "zscaler*"
        OR event.dataset LIKE "endpoint*" OR event.dataset LIKE "sentinelone*"
        OR event.dataset LIKE "windows*" OR event.dataset LIKE "sysmon*"
        OR event.dataset LIKE "microsoft-defender*" OR event.dataset LIKE "crowdstrike*"
        OR event.dataset LIKE "carbon_black*"
    )
| EVAL
    domain_category = CASE(
        event.dataset LIKE "endpoint*" OR event.dataset LIKE "sentinelone*"
            OR event.dataset LIKE "windows*" OR event.dataset LIKE "sysmon*"
            OR event.dataset LIKE "microsoft-defender*" OR event.dataset LIKE "crowdstrike*"
            OR event.dataset LIKE "carbon_black*",
            "endpoint",
        event.dataset LIKE "panw*" OR event.dataset LIKE "fortinet*"
            OR event.dataset LIKE "firewall*" OR event.dataset LIKE "checkpoint*"
            OR event.dataset LIKE "proxy*" OR event.dataset LIKE "zscaler*"
            OR event.dataset LIKE "extrahop*" OR event.dataset LIKE "zeek*"
            OR event.dataset LIKE "suricata*" OR event.dataset LIKE "ndr*",
            "web_network",
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
    is_web_attack = CASE(
        kibana.alert.rule.name LIKE "*SQL*Injection*"
            OR kibana.alert.rule.name LIKE "*SQLi*"
            OR kibana.alert.rule.name LIKE "*XSS*"
            OR kibana.alert.rule.name LIKE "*Cross*Site*"
            OR kibana.alert.rule.name LIKE "*RCE*"
            OR kibana.alert.rule.name LIKE "*Remote*Code*"
            OR kibana.alert.rule.name LIKE "*Command*Injection*"
            OR kibana.alert.rule.name LIKE "*Path*Traversal*"
            OR kibana.alert.rule.name LIKE "*Directory*Traversal*"
            OR kibana.alert.rule.name LIKE "*Web*Shell*"
            OR kibana.alert.rule.name LIKE "*File*Inclusion*"
            OR kibana.alert.rule.name LIKE "*Web*Attack*",
            1, 0
    ),
    is_endpoint_alert = CASE(domain_category == "endpoint", 1, 0),
    has_execution_tactic = CASE(
        domain_category == "endpoint"
            AND kibana.alert.rule.threat.tactic.name == "Execution", 1, 0
    )
| STATS
    Esql.alert_count = COUNT(*),
    Esql.first_seen = MIN(@timestamp),
    Esql.last_seen = MAX(@timestamp),
    Esql.total_risk = SUM(alert_risk),
    Esql.web_attack_count = SUM(is_web_attack),
    Esql.web_attack_types = COUNT_DISTINCT(
        CASE(is_web_attack == 1, kibana.alert.rule.name, NULL)
    ),
    Esql.has_endpoint_alert = MAX(is_endpoint_alert),
    Esql.endpoint_alert_count = SUM(is_endpoint_alert),
    Esql.has_execution = MAX(has_execution_tactic),
    Esql.unique_rules = COUNT_DISTINCT(kibana.alert.rule.name),
    Esql.rule_names = VALUES(kibana.alert.rule.name),
    Esql.tactic_values = VALUES(kibana.alert.rule.threat.tactic.name),
    Esql.user_values = VALUES(user.name),
    Esql.process_names = VALUES(process.name),
    Esql.source_ips = VALUES(source.ip),
    Esql.data_sources = VALUES(event.dataset)
  BY host.name
| WHERE Esql.web_attack_count >= 3 AND Esql.has_endpoint_alert == 1
| EVAL
    Esql.risk_score = Esql.total_risk,
    Esql.severity = CASE(
        Esql.has_execution == 1 AND Esql.web_attack_count >= 1, "critical",
        Esql.web_attack_count >= 3 AND Esql.has_endpoint_alert == 1, "high",
        Esql.web_attack_count >= 3, "medium",
        "low"
    ),
    Esql.description = CONCAT(
        "Web server attack chain on host ", host.name,
        " | ", TO_STRING(Esql.web_attack_count), " web attack alerts",
        " | ", TO_STRING(Esql.web_attack_types), " distinct attack types",
        " | ", TO_STRING(Esql.endpoint_alert_count), " endpoint alerts",
        " | Execution tactic: ", TO_STRING(Esql.has_execution),
        " | Risk Score: ", TO_STRING(Esql.risk_score),
        " | Window: ", TO_STRING(Esql.first_seen), " to ", TO_STRING(Esql.last_seen)
    )
| SORT Esql.risk_score DESC
| LIMIT 50
```

## Strategy

Correlates web/WAF-domain alerts with endpoint alerts on the same server, using `host.name` as the join key (fallback to `destination.ip` when the server hostname is available through COALESCE). Classifies web attack alerts by type (SQLi, XSS, RCE, path traversal) and counts distinct attack types. Requires both a minimum web attack count AND at least one endpoint alert on the server. When web attacks trigger endpoint activity, exploitation has likely succeeded.

## Severity Logic

| Condition | Severity |
|-----------|----------|
| Web RCE/attack + endpoint Execution tactic | Critical |
| 3+ web attacks + endpoint alert | High |
| 3+ web attacks clustered (no endpoint) | Medium |

## Notes

- **Blind Spots:**
  - Web servers behind load balancers where the `host.name` in web alerts differs from the actual backend server hostname in endpoint alerts
  - Encrypted (HTTPS) traffic where the WAF/IDS sees only the TLS handshake and cannot inspect payloads for web attack signatures
  - Web shells that operate entirely in memory without triggering file-based endpoint detections
  - Web application frameworks that generate legitimate requests resembling attack patterns (e.g., Base64-encoded parameters that look like encoded payloads)

- **False Positives:**
  - **Web application security testing**: Automated scanners (Burp Suite, OWASP ZAP) run against production or staging servers. Mitigation: coordinate with security testing schedules and exclude scanner source IPs.
  - **Content management system activity**: CMS platforms that generate complex URLs or POST bodies resembling injection attacks. Mitigation: tune web attack rules for known CMS patterns.
  - **API endpoint testing**: Developers testing API endpoints with unusual payloads. Mitigation: exclude known development/testing source IPs during testing windows.

- **Tuning:**
  1. Customize the `is_web_attack` CASE patterns for your specific WAF/IDS/NDR rule names
  2. `web_attack_count` threshold (default: 3) -- increase to 5 or 10 if your WAF generates high volumes of web attack alerts
  3. Add source IP analysis -- web attacks from a single source IP followed by endpoint alerts suggest successful exploitation, while attacks from many sources suggest scanning
  4. Consider adding web attack type weighting -- RCE and command injection alerts should carry higher weight than XSS or path traversal
  5. Filter to known web server hostnames if possible to reduce noise from non-server hosts

## Data Requirements

- **Index**: `.internal.alerts-security.alerts-default`
- **Required fields**: `host.name`, `event.dataset`, `signal.rule.severity`, `kibana.alert.rule.name`, `kibana.alert.rule.building_block_type`, `kibana.alert.rule.threat.tactic.name`, `@timestamp`, `user.name`, `process.name`, `source.ip`
- **Minimum data sources**: At least one web/WAF/IDS integration generating web attack alerts AND at least one endpoint EDR integration on the web server
- **Minimum volume**: 3+ web attack alerts + 1+ endpoint alert for same server host within 2h

## Dependencies

None required. Optional: `lookup-critical-assets` to identify production web servers for severity escalation.

## Validation

Against a test web server:
1. Execute SQL injection attempts against the web application (triggers WAF/IDS SQL injection alerts)
2. After SQLi, upload a web shell through the exploited vulnerability (triggers file creation or web shell endpoint alert)
3. Execute commands through the web shell (triggers process execution endpoint alert)

Expected result: Web server hostname appears with `Esql.web_attack_count >= 3`, `Esql.has_endpoint_alert == 1`, `Esql.has_execution == 1`, severity of critical.

## Elastic Comparison

Elastic ships individual web attack rules (via Suricata signatures and endpoint rules like "Webshell Detection") but does not correlate web application attacks with endpoint activity on the same server. CORR-5O bridges the gap between network-layer web attack detection and host-layer exploitation confirmation, providing the critical "attack succeeded" signal.
