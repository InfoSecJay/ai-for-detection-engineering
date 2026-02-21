# Identity Brute Force to Success

---

## Metadata

- **Rule ID:** `CORR-5B`
- **Tier:** 5 — Domain-Specific Correlation
- **Author:** Detection Engineering
- **Description:** Detect identity-domain alert patterns where a user experiences multiple failed authentication alerts followed by a successful authentication alert within a 1-hour window. This is the canonical brute force or credential stuffing pattern: the attacker tries many passwords until one works. The transition from failure to success is the critical signal -- failed logins alone are noise, but failed logins followed by success indicate credential compromise.
- **Join Key(s):** `user.name`
- **Lookback:** 1 hour
- **Schedule:** Every 5 minutes
- **Priority:** P1
- **Integration:** [alerts](https://www.elastic.co/guide/en/security/current/alerts-ui-manage.html)
- **Language:** `[ES|QL]`

## Query

```esql
FROM .internal.alerts-security.alerts-default
| WHERE @timestamp > NOW() - 1 HOURS
    AND kibana.alert.workflow_status == "open"
    AND user.name IS NOT NULL
    AND (
        event.dataset LIKE "okta*" OR event.dataset LIKE "azure_ad*"
        OR event.dataset LIKE "entra*" OR event.dataset LIKE "onelogin*"
        OR event.dataset LIKE "ping*" OR event.dataset LIKE "auth0*"
    )
| EVAL
    severity_weight = CASE(
        signal.rule.severity == "critical", 25,
        signal.rule.severity == "high", 15,
        signal.rule.severity == "medium", 8,
        signal.rule.severity == "low", 3, 1
    ),
    bbr_factor = CASE(kibana.alert.rule.building_block_type == "default", 0.3, 1.0),
    alert_risk = ROUND(severity_weight * bbr_factor),
    auth_outcome = CASE(
        kibana.alert.rule.name LIKE "*Brute Force*"
            OR kibana.alert.rule.name LIKE "*Failed*"
            OR kibana.alert.rule.name LIKE "*Invalid*"
            OR kibana.alert.rule.name LIKE "*Denied*"
            OR kibana.alert.rule.name LIKE "*Locked*",
            "failure",
        kibana.alert.rule.name LIKE "*Successful*Auth*After*"
            OR kibana.alert.rule.name LIKE "*Impossible*Travel*"
            OR kibana.alert.rule.name LIKE "*New*Location*"
            OR kibana.alert.rule.name LIKE "*Anomalous*Login*"
            OR kibana.alert.rule.name LIKE "*MFA*Bypass*",
            "success",
        "unknown"
    ),
    is_failure = CASE(auth_outcome == "failure", 1, 0),
    is_success = CASE(auth_outcome == "success", 1, 0),
    failure_ts = CASE(auth_outcome == "failure", @timestamp, NULL),
    success_ts = CASE(auth_outcome == "success", @timestamp, NULL)
| STATS
    Esql.alert_count = COUNT(*),
    Esql.first_seen = MIN(@timestamp),
    Esql.last_seen = MAX(@timestamp),
    Esql.total_risk_score = SUM(alert_risk),
    Esql.failed_count = SUM(is_failure),
    Esql.success_count = SUM(is_success),
    Esql.last_failure_time = MAX(failure_ts),
    Esql.first_success_time = MIN(success_ts),
    Esql.unique_rules = COUNT_DISTINCT(kibana.alert.rule.name),
    Esql.rule_names = VALUES(kibana.alert.rule.name),
    Esql.source_ips = VALUES(source.ip),
    Esql.source_ip_count = COUNT_DISTINCT(source.ip),
    Esql.source_countries = VALUES(source.geo.country_name)
  BY user.name
| WHERE Esql.failed_count >= 5 AND Esql.success_count >= 1
| EVAL
    Esql.has_success_after_fail = CASE(
        Esql.first_success_time IS NOT NULL
            AND Esql.last_failure_time IS NOT NULL
            AND Esql.first_success_time > Esql.last_failure_time, 1,
        Esql.first_success_time IS NOT NULL AND Esql.success_count >= 1, 1,
        0
    )
| WHERE Esql.has_success_after_fail == 1
| EVAL
    Esql.risk_score = Esql.total_risk_score,
    Esql.correlation_severity = CASE(
        Esql.failed_count >= 20 AND Esql.success_count >= 1, "critical",
        Esql.failed_count >= 10 AND Esql.success_count >= 1, "high",
        Esql.failed_count >= 5 AND Esql.success_count >= 1, "medium",
        "low"
    ),
    Esql.description = CONCAT(
        "Identity brute force to success for user ", user.name,
        " | ", TO_STRING(Esql.failed_count), " failed auth alerts",
        " followed by ", TO_STRING(Esql.success_count), " success alerts",
        " | ", TO_STRING(Esql.source_ip_count), " source IPs",
        " | Risk Score: ", TO_STRING(Esql.risk_score),
        " | Window: ", TO_STRING(Esql.first_seen), " to ", TO_STRING(Esql.last_seen)
    )
| SORT Esql.risk_score DESC
| LIMIT 50
```

## Strategy

Filters to identity domain alerts only. Uses alert rule names and tactic/technique metadata to classify alerts as authentication failures or authentication successes. Aggregates by `user.name` and computes both a failure count and a success-after-failure flag by comparing timestamps. The 5-minute schedule ensures rapid detection of successful brute force -- every minute of delay after credential compromise is a minute the attacker operates freely.

## Severity Logic

| Condition | Severity |
|-----------|----------|
| failed >= 20 + success | Critical |
| failed >= 10 + success | High |
| failed >= 5 + success | Medium |

## Notes

- **Blind Spots:**
  - Password spray attacks that distribute attempts across many users (low failure count per user) -- use Tier 4 campaign detection for spray patterns
  - Identity providers that do not generate individual failure alerts (some only alert on aggregate thresholds)
  - Auth success alerts classified as "unknown" due to rule name patterns not matching -- tune the `auth_outcome` CASE statement for your specific rule names
  - Credential stuffing via API endpoints that bypass the identity provider's alert pipeline

- **False Positives:**
  - **Password resets**: User forgets password, fails 5+ times, resets, then succeeds. Mitigation: correlate with password reset events if available.
  - **Shared accounts**: Multiple users attempting to log into a shared account. Mitigation: exclude known shared accounts.
  - **MFA enrollment**: Users failing MFA challenges during initial enrollment. Mitigation: add MFA enrollment rule names to the "unknown" category.

- **Tuning:**
  1. `failed_count` threshold (default: 5) -- increase to 10 if your identity provider generates alerts on individual login failures (high volume)
  2. Customize the `auth_outcome` CASE statement to match your specific Elastic detection rule names for authentication failure and success alerts
  3. Add `source.geo.country_name` to severity logic -- failures from foreign countries followed by success warrant automatic escalation
  4. Consider adding `source.ip` diversity as an additional severity factor -- failures from many IPs suggest distributed attack

## Data Requirements

- **Index**: `.internal.alerts-security.alerts-default`
- **Required fields**: `user.name`, `event.dataset`, `signal.rule.severity`, `kibana.alert.rule.name`, `kibana.alert.rule.building_block_type`, `@timestamp`, `source.ip`, `source.geo.country_name`
- **Minimum data sources**: At least one identity provider integration (Okta, Azure AD/Entra ID, OneLogin, Ping, Auth0)
- **Minimum volume**: 5+ failure alerts + 1+ success alert for same user within 1h

## Dependencies

None required. Optional: `lookup-geo-baselines` to identify unexpected source countries for the user.

## Validation

1. Generate 10 failed Okta login alerts for a test user (trigger the "Okta Brute Force" or similar rule)
2. Immediately after, generate a successful login alert for the same user from the same or different IP

Expected result: User appears with `Esql.failed_count >= 10`, `Esql.has_success_after_fail == 1`, severity of high.

## Elastic Comparison

Elastic ships several identity brute force rules (e.g., "Attempts to Brute Force an Okta User Account") but these detect the failure pattern only. They do not correlate failures with subsequent success, which is the critical indicator of actual compromise versus mere attack attempt. CORR-5B closes this gap by requiring the failure-to-success transition.
