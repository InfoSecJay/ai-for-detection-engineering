# Off-Hours Activity Correlation

---

## Metadata

- **Rule ID:** `CORR-6C`
- **Tier:** 6 — Novelty and Anomaly Detection
- **Author:** Detection Engineering
- **Description:** Detect users generating multiple distinct alerts during hours outside their defined business schedule. A marketing manager triggering "Suspicious PowerShell Download Cradle" and "LSASS Memory Access" at 3 AM on a Tuesday warrants immediate investigation. This rule enriches alerts with per-user business hours from a lookup index and flags off-hours clusters.
- **Join Key(s):** `user.name`
- **Lookback:** Rolling window (current off-hours period)
- **Schedule:** Every 15 minutes
- **Priority:** P2
- **Integration:** [alerts](https://www.elastic.co/guide/en/security/current/alerts-ui-manage.html)
- **Language:** `[ES|QL]`

## Query

```esql
FROM .internal.alerts-security.alerts-default
| WHERE @timestamp > NOW() - 12 HOURS
    AND kibana.alert.workflow_status == "open"
    AND user.name IS NOT NULL
    AND NOT user.name IN ("SYSTEM", "Administrator", "LOCAL SERVICE", "NETWORK SERVICE",
        "DWM-1", "DWM-2", "DWM-3", "UMFD-0", "UMFD-1", "UMFD-2",
        "DefaultAccount", "Guest", "WDAGUtilityAccount")
    AND NOT (
        user.name LIKE "svc-*" OR user.name LIKE "svc_*"
        OR user.name LIKE "app-*" OR user.name LIKE "sa-*"
        OR user.name LIKE "*$" OR user.name LIKE "MSOL_*"
        OR user.name LIKE "HealthMail*" OR user.name LIKE "SM_*"
    )
| EVAL
    hour_of_day = DATE_EXTRACT("hour", @timestamp),
    domain_category = CASE(
        event.dataset LIKE "endpoint*" OR event.dataset LIKE "sentinelone*"
            OR event.dataset LIKE "windows*" OR event.dataset LIKE "sysmon*"
            OR event.dataset LIKE "microsoft-defender*" OR event.dataset LIKE "crowdstrike*"
            OR event.dataset LIKE "carbon_black*", "endpoint",
        event.dataset LIKE "okta*" OR event.dataset LIKE "azure_ad*"
            OR event.dataset LIKE "entra*" OR event.dataset LIKE "onelogin*"
            OR event.dataset LIKE "ping*" OR event.dataset LIKE "auth0*", "identity",
        event.dataset LIKE "aws*" OR event.dataset LIKE "gcp*"
            OR event.dataset LIKE "azure*" OR event.dataset LIKE "cloud*"
            OR event.dataset LIKE "o365*", "cloud",
        event.dataset LIKE "panw*" OR event.dataset LIKE "fortinet*"
            OR event.dataset LIKE "firewall*" OR event.dataset LIKE "paloalto*"
            OR event.dataset LIKE "checkpoint*", "network_fw",
        event.dataset LIKE "extrahop*" OR event.dataset LIKE "zeek*"
            OR event.dataset LIKE "suricata*" OR event.dataset LIKE "ndr*", "network_ndr",
        event.dataset LIKE "proxy*" OR event.dataset LIKE "zscaler*"
            OR event.dataset LIKE "bluecoat*" OR event.dataset LIKE "squid*", "proxy",
        event.dataset LIKE "dns*", "dns",
        event.dataset LIKE "email*" OR event.dataset LIKE "proofpoint*"
            OR event.dataset LIKE "mimecast*", "email",
        COALESCE(labels.technology, event.module, "unknown")
    ),
    severity_weight = CASE(
        signal.rule.severity == "critical", 25,
        signal.rule.severity == "high", 15,
        signal.rule.severity == "medium", 8,
        signal.rule.severity == "low", 3, 1
    ),
    bbr_factor = CASE(kibana.alert.rule.building_block_type == "default", 0.3, 1.0),
    alert_risk = ROUND(severity_weight * bbr_factor),
    is_high_or_critical = CASE(
        signal.rule.severity IN ("high", "critical")
            AND kibana.alert.rule.building_block_type IS NULL, 1, 0
    )
| LOOKUP JOIN lookup-business-hours ON user.name
| EVAL
    business_start = COALESCE(work_start_hour, 8),
    business_end = COALESCE(work_end_hour, 18),
    Esql.is_off_hours = CASE(
        hour_of_day < business_start OR hour_of_day >= business_end, true,
        false
    )
| WHERE Esql.is_off_hours == true
| STATS
    Esql.off_hours_alerts = COUNT(*),
    Esql.off_hours_rules = COUNT_DISTINCT(kibana.alert.rule.name),
    Esql.risk_score = SUM(alert_risk),
    Esql.max_severity = MAX(severity_weight),
    Esql.high_critical_count = SUM(is_high_or_critical),
    Esql.domain_count = COUNT_DISTINCT(domain_category),
    Esql.domain_values = VALUES(domain_category),
    Esql.first_seen = MIN(@timestamp),
    Esql.last_seen = MAX(@timestamp),
    Esql.rule_names = VALUES(kibana.alert.rule.name),
    Esql.tactic_values = VALUES(kibana.alert.rule.threat.tactic.name),
    Esql.host_values = VALUES(host.name),
    Esql.hours_active = VALUES(hour_of_day)
  BY user.name
| WHERE Esql.off_hours_alerts >= 2 AND Esql.off_hours_rules >= 2
| EVAL
    Esql.severity = CASE(
        Esql.max_severity >= 15 AND Esql.domain_count >= 2, "critical",
        Esql.off_hours_rules >= 3 OR Esql.max_severity >= 15, "high",
        Esql.off_hours_alerts >= 2 AND Esql.off_hours_rules >= 2, "medium",
        "medium"
    ),
    Esql.description = CONCAT(
        "User ", user.name,
        " generated ", TO_STRING(Esql.off_hours_alerts), " alerts from ",
        TO_STRING(Esql.off_hours_rules), " rules OUTSIDE business hours",
        " | Active hours: ", TO_STRING(Esql.hours_active),
        " | ", TO_STRING(Esql.domain_count), " domains",
        " | Risk: ", TO_STRING(Esql.risk_score)
    )
| SORT Esql.risk_score DESC
| LIMIT 50
```

## Strategy

Each alert's timestamp hour is extracted and compared against per-user business hours retrieved from `lookup-business-hours` via `LOOKUP JOIN`. Alerts falling outside the defined work window are flagged as off-hours. The rule then aggregates off-hours alerts per user, requiring both a minimum alert count and minimum rule diversity to filter single-rule noise. Severity escalates when off-hours activity spans multiple detection domains or includes high-severity alerts.

## Severity Logic

| Condition | Severity |
|-----------|----------|
| Off-hours + high/critical severity + multi-domain (2+) | Critical |
| Off-hours + 3+ distinct rules OR high/critical severity | High |
| Off-hours + 2+ alerts from 2+ rules | Medium |

## Notes

- **Blind Spots:**
  - **Timezone inaccuracies**: If `lookup-business-hours` does not accurately reflect a user's timezone or schedule, off-hours classification is wrong. Users who travel frequently may have shifting timezones.
  - **Users not in lookup**: Users missing from `lookup-business-hours` default to 08:00-18:00 UTC, which may not match their actual schedule.
  - **Weekend vs. weekday**: This rule does not distinguish weekends from weekdays. A Saturday alert at 10 AM appears as "business hours" even though few employees work weekends.

- **False Positives:**
  - **Shift workers**: Employees on night shifts or rotating schedules legitimately work during off-hours. Mitigation: configure accurate schedules in `lookup-business-hours` per user or department.
  - **On-call engineers**: Engineers responding to incidents outside business hours. Mitigation: integrate with on-call rotation schedules (PagerDuty, Opsgenie) and suppress during on-call windows.
  - **Timezone misconfigurations**: Users assigned wrong timezone in directory services. Mitigation: validate timezone data against HR records.

- **Tuning:**
  1. Default business hours (08:00-18:00) -- adjust per department or user group
  2. `off_hours_alerts` threshold (default: 2) -- increase for roles with known after-hours work
  3. `off_hours_rules` threshold (default: 2) -- prevents single-rule noise from triggering
  4. Add weekend detection by extracting day-of-week from `@timestamp`
  5. Consider integration with on-call scheduling APIs for dynamic suppression

## Data Requirements

- **Index**: `.internal.alerts-security.alerts-default`
- **Lookup Index**: `lookup-business-hours` (fields: `user.name`, `timezone`, `work_start_hour`, `work_end_hour`)
- **Required fields**: `user.name`, `@timestamp`, `event.dataset`, `signal.rule.severity`, `kibana.alert.rule.building_block_type`, `kibana.alert.workflow_status`, `kibana.alert.rule.name`, `kibana.alert.rule.threat.tactic.name`
- **Minimum volume**: Business hours lookup populated for all monitored users

## Dependencies

- **Required**: `lookup-business-hours` -- must contain per-user or per-department work schedules
- **Optional**: On-call rotation data for suppression

## Validation

1. Configure a test user with business hours 09:00-17:00
2. Generate 3 different alerts for that user at 03:00 their local time (e.g., suspicious PowerShell, credential access, network connection)
3. Verify CORR-6C surfaces the user with `Esql.off_hours_alerts >= 3` and `Esql.off_hours_rules >= 3`
4. Confirm that alerts at 14:00 (within business hours) do NOT trigger CORR-6C for the same user

## Elastic Comparison

Elastic does not ship a business-hours correlation rule. Elastic ML has "Unusual Time of Day" anomaly detection, but it operates on raw events (not alerts), uses ML scoring (not deterministic thresholds), and does not correlate multiple alert types. CORR-6C provides deterministic off-hours detection with multi-rule correlation and configurable per-user schedules.
