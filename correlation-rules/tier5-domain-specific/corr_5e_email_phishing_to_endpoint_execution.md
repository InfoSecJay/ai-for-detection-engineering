# Email Phishing to Endpoint Execution

---

## Metadata

- **Rule ID:** `CORR-5E`
- **Tier:** 5 — Domain-Specific Correlation
- **Author:** Detection Engineering
- **Description:** Detect the complete phishing attack chain: an email-domain alert (phishing detection, malicious attachment, suspicious link) followed by an endpoint-domain alert for the same user within 4 hours. This cross-domain correlation catches the full attack lifecycle from initial delivery through execution -- the most common initial access vector in enterprise environments. Requiring alerts from BOTH the email and endpoint domains eliminates the noise of email alerts alone (most phishing is blocked) and endpoint alerts alone (many causes).
- **Join Key(s):** `user.name` OR `user.email`
- **Lookback:** 4 hours
- **Schedule:** Every 15 minutes
- **Priority:** P1
- **Integration:** [alerts](https://www.elastic.co/guide/en/security/current/alerts-ui-manage.html)
- **Language:** `[ES|QL]`

## Query

```esql
FROM .internal.alerts-security.alerts-default
| WHERE @timestamp > NOW() - 4 HOURS
    AND kibana.alert.workflow_status == "open"
    AND user.name IS NOT NULL
    AND (
        event.dataset LIKE "endpoint*" OR event.dataset LIKE "sentinelone*"
        OR event.dataset LIKE "windows*" OR event.dataset LIKE "sysmon*"
        OR event.dataset LIKE "microsoft-defender*" OR event.dataset LIKE "crowdstrike*"
        OR event.dataset LIKE "carbon_black*"
        OR event.dataset LIKE "email*" OR event.dataset LIKE "proofpoint*"
        OR event.dataset LIKE "mimecast*"
    )
| EVAL
    domain_category = CASE(
        event.dataset LIKE "endpoint*" OR event.dataset LIKE "sentinelone*"
            OR event.dataset LIKE "windows*" OR event.dataset LIKE "sysmon*"
            OR event.dataset LIKE "microsoft-defender*" OR event.dataset LIKE "crowdstrike*"
            OR event.dataset LIKE "carbon_black*",
            "endpoint",
        event.dataset LIKE "email*" OR event.dataset LIKE "proofpoint*"
            OR event.dataset LIKE "mimecast*",
            "email",
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
    email_ts = CASE(domain_category == "email", @timestamp, NULL),
    endpoint_ts = CASE(domain_category == "endpoint", @timestamp, NULL),
    is_email = CASE(domain_category == "email", 1, 0),
    is_endpoint = CASE(domain_category == "endpoint", 1, 0),
    has_execution_tactic = CASE(
        domain_category == "endpoint"
            AND kibana.alert.rule.threat.tactic.name == "Execution", 1, 0
    )
| STATS
    Esql.alert_count = COUNT(*),
    Esql.first_seen = MIN(@timestamp),
    Esql.last_seen = MAX(@timestamp),
    Esql.total_risk_score = SUM(alert_risk),
    Esql.email_alert_count = SUM(is_email),
    Esql.endpoint_alert_count = SUM(is_endpoint),
    Esql.email_alert_time = MIN(email_ts),
    Esql.endpoint_alert_time = MIN(endpoint_ts),
    Esql.has_execution = MAX(has_execution_tactic),
    Esql.unique_rules = COUNT_DISTINCT(kibana.alert.rule.name),
    Esql.rule_names = VALUES(kibana.alert.rule.name),
    Esql.tactic_values = VALUES(kibana.alert.rule.threat.tactic.name),
    Esql.host_values = VALUES(host.name),
    Esql.source_ips = VALUES(source.ip),
    Esql.data_sources = VALUES(event.dataset)
  BY user.name
| WHERE Esql.email_alert_count >= 1
    AND Esql.endpoint_alert_count >= 1
    AND Esql.endpoint_alert_time > Esql.email_alert_time
| EVAL
    Esql.time_gap_minutes = DATE_DIFF("minute", Esql.email_alert_time, Esql.endpoint_alert_time),
    Esql.risk_score = ROUND(Esql.total_risk_score * 2.0),
    Esql.correlation_severity = CASE(
        Esql.has_execution == 1 AND Esql.email_alert_count >= 1, "critical",
        Esql.endpoint_alert_count >= 1 AND Esql.email_alert_count >= 1, "high",
        "medium"
    ),
    Esql.description = CONCAT(
        "Email phishing to endpoint execution for user ", user.name,
        " | Email alert at: ", TO_STRING(Esql.email_alert_time),
        " | Endpoint alert at: ", TO_STRING(Esql.endpoint_alert_time),
        " | Time gap: ", TO_STRING(Esql.time_gap_minutes), " minutes",
        " | ", TO_STRING(Esql.email_alert_count), " email + ",
        TO_STRING(Esql.endpoint_alert_count), " endpoint alerts",
        " | Risk Score: ", TO_STRING(Esql.risk_score),
        " (2.0x phishing chain multiplier)"
    )
| SORT Esql.risk_score DESC
| LIMIT 50
```

## Strategy

Joins alerts across email and endpoint domains using `user.name` as the correlation key. Uses INLINE STATS to compute per-domain timestamps without losing individual alert rows, then filters to users who have both email and endpoint alerts where the endpoint alert follows the email alert within the 4-hour window. Applies a 2.0x confidence multiplier to the risk score because the cross-domain phishing chain is a high-confidence indicator of successful compromise.

## Severity Logic

| Condition | Severity |
|-----------|----------|
| Phishing email alert + endpoint Execution tactic alert | Critical |
| Phishing email alert + any endpoint alert | High |

## Notes

- **Blind Spots:**
  - User.name mismatch between email and endpoint domains (e.g., email uses `john.smith@corp.com` while endpoint uses `DOMAIN\jsmith`) -- requires identity resolution
  - Email alerts for messages that were quarantined before delivery (the email alert fires but the user never received the phishing email)
  - Endpoint activity on personal devices not covered by EDR
  - Time gaps exceeding 4 hours between email delivery and user opening the attachment

- **False Positives:**
  - **Email security testing**: Simulated phishing campaigns (KnowBe4, Proofpoint) followed by user interaction. Mitigation: exclude known phishing simulation sender domains or campaign IDs.
  - **Legitimate email with coincidental endpoint alerts**: User receives a flagged email AND independently triggers an unrelated endpoint alert. Mitigation: increase confidence by checking if endpoint alert involves file execution from email attachment path.
  - **Email forwarding**: User forwards a flagged email to an analyst, triggering a second email alert, while unrelated endpoint activity occurs. Mitigation: look for identical subjects in email alert context.

- **Tuning:**
  1. Refine the `user.name` join by adding `user.email` as an alternative join key if your environment has email-to-username mapping
  2. Adjust the 2.0x risk multiplier based on observed true positive rates -- increase if phishing chains are consistently true positives
  3. Add file path correlation if available -- endpoint alerts involving files from email attachment directories (e.g., Outlook temp folders) warrant automatic severity escalation
  4. Consider a shorter lookback (2h) for faster-moving phishing campaigns or a longer lookback (8h) for campaigns with delayed execution

## Data Requirements

- **Index**: `.internal.alerts-security.alerts-default`
- **Required fields**: `user.name`, `event.dataset`, `signal.rule.severity`, `kibana.alert.rule.name`, `kibana.alert.rule.building_block_type`, `kibana.alert.rule.threat.tactic.name`, `@timestamp`, `host.name`, `source.ip`
- **Minimum data sources**: At least one email security integration (Proofpoint, Mimecast, or native email alerts) AND at least one endpoint EDR integration
- **Minimum volume**: 1+ email alert + 1+ endpoint alert for same user within 4h, with endpoint after email

## Dependencies

None required. Optional: `lookup-critical-assets` for severity escalation when the targeted user is a high-value target (executive, admin).

## Validation

1. Trigger an email phishing alert for a test user (e.g., send a test phishing email that triggers Proofpoint/Mimecast detection)
2. Within 1 hour, on the same user's workstation, trigger an endpoint alert (e.g., open a simulated malicious attachment that spawns PowerShell)

Expected result: User appears with both email and endpoint alerts correlated, `Esql.time_gap_minutes` showing the time between email and endpoint activity, severity of critical (if endpoint alert has Execution tactic) or high.

## Elastic Comparison

Elastic does not ship a cross-domain email-to-endpoint correlation rule. Email alerts and endpoint alerts exist in separate detection rule families with no built-in connection. CORR-5E bridges this critical gap by correlating the initial delivery vector with the execution stage, providing the full phishing kill chain in a single correlated alert.
