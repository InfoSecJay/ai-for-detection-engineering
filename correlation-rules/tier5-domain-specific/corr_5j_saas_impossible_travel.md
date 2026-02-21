# SaaS Impossible Travel

---

## Metadata

- **Rule ID:** `CORR-5J`
- **Tier:** 5 — Domain-Specific Correlation
- **Author:** Detection Engineering
- **Description:** Detect a user generating identity-domain alerts from two or more distinct geographic locations within a 2-hour window where at least one location is unexpected based on the user's baseline. True impossible travel -- authentication from New York and Tokyo within 30 minutes -- is a definitive indicator of credential compromise. This rule goes beyond simple impossible travel by incorporating baseline comparison to distinguish truly anomalous locations from expected travel patterns.
- **Join Key(s):** `user.name`
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
    AND user.name IS NOT NULL
    AND source.geo.country_name IS NOT NULL
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
    alert_risk = ROUND(severity_weight * bbr_factor)
| STATS
    Esql.alert_count = COUNT(*),
    Esql.first_seen = MIN(@timestamp),
    Esql.last_seen = MAX(@timestamp),
    Esql.total_risk = SUM(alert_risk),
    Esql.location_count = COUNT_DISTINCT(source.geo.country_name),
    Esql.locations = VALUES(source.geo.country_name),
    Esql.time_span_minutes = DATE_DIFF("minute", MIN(@timestamp), MAX(@timestamp)),
    Esql.unique_rules = COUNT_DISTINCT(kibana.alert.rule.name),
    Esql.rule_names = VALUES(kibana.alert.rule.name),
    Esql.tactic_values = VALUES(kibana.alert.rule.threat.tactic.name),
    Esql.source_ips = VALUES(source.ip),
    Esql.source_ip_count = COUNT_DISTINCT(source.ip)
  BY user.name
| WHERE Esql.location_count >= 2
| LOOKUP JOIN lookup-geo-baselines ON user.name
| EVAL
    Esql.has_unexpected_country = CASE(
        expected_countries IS NULL, 1,
        Esql.location_count > 1, 1,
        0
    ),
    Esql.risk_score = Esql.total_risk,
    Esql.severity = CASE(
        Esql.location_count >= 3 AND Esql.time_span_minutes <= 120, "critical",
        Esql.location_count >= 2 AND Esql.has_unexpected_country == 1, "high",
        Esql.location_count >= 2, "medium",
        "low"
    ),
    Esql.description = CONCAT(
        "SaaS impossible travel for user ", user.name,
        " | ", TO_STRING(Esql.location_count), " countries in ",
        TO_STRING(Esql.time_span_minutes), " minutes",
        " | Unexpected location: ", TO_STRING(Esql.has_unexpected_country),
        " | ", TO_STRING(Esql.alert_count), " alerts",
        " | Risk Score: ", TO_STRING(Esql.risk_score),
        " | Window: ", TO_STRING(Esql.first_seen), " to ", TO_STRING(Esql.last_seen)
    )
| WHERE Esql.has_unexpected_country == 1
| SORT Esql.risk_score DESC
| LIMIT 50
```

## Strategy

Filters to identity domain alerts with geographic data. Aggregates by `user.name` to collect distinct source countries and time span. Uses LOOKUP JOIN against `lookup-geo-baselines` to compare observed countries against expected countries for the user. Requires at least 2 distinct countries and at least one unexpected country to fire. The 2-hour lookback and 10-minute schedule provide rapid detection while accounting for the typical delay between authentication events across time zones.

## Severity Logic

| Condition | Severity |
|-----------|----------|
| 3+ countries within 2 hours | Critical |
| 2 unexpected countries | High |
| 1 unexpected country + identity alerts | Medium |

## Notes

- **Blind Spots:**
  - VPN and proxy services that mask true source location (user appears to be in VPN exit country, not actual location)
  - Cloud-based applications that route authentication through regional proxies (user in New York may authenticate through a London proxy)
  - `source.geo.country_name` field not populated when GeoIP enrichment is missing or fails
  - Users with legitimate multi-country activity patterns not captured in `lookup-geo-baselines`

- **False Positives:**
  - **VPN users**: Users connecting through VPN exit nodes in different countries. Mitigation: maintain VPN exit node IP ranges in geo-baseline exclusions.
  - **Frequent international travelers**: Executives and sales teams who regularly access SaaS from multiple countries. Mitigation: keep `lookup-geo-baselines` updated with expected countries per user.
  - **Cloud-hosted virtual desktops**: Users accessing SaaS through cloud-hosted desktops in different regions. Mitigation: add cloud desktop IP ranges to expected patterns.

- **Tuning:**
  1. Deploy and maintain `lookup-geo-baselines` -- this is the single most impactful tuning lever for reducing false positives
  2. `location_count` threshold (default: 2) -- do not lower below 2 (single-country alerts are not impossible travel)
  3. Consider adding city-level analysis for large countries -- authentication from New York and Los Angeles within 30 minutes is suspicious even though both are in the United States
  4. Add time span weighting -- 2 countries in 15 minutes is far more suspicious than 2 countries in 110 minutes

## Data Requirements

- **Index**: `.internal.alerts-security.alerts-default`
- **Required fields**: `user.name`, `event.dataset`, `signal.rule.severity`, `kibana.alert.rule.name`, `kibana.alert.rule.building_block_type`, `kibana.alert.rule.threat.tactic.name`, `@timestamp`, `source.ip`, `source.geo.country_name`
- **Lookup index**: `lookup-geo-baselines` (optional but strongly recommended)
- **Minimum data sources**: At least one identity provider integration with GeoIP enrichment on source IPs
- **Minimum volume**: 2+ identity alerts from 2+ distinct countries for same user within 2h

## Dependencies

Optional but strongly recommended: `lookup-geo-baselines` for per-user expected country baselines. Without it, ALL multi-country activity triggers the rule (higher false positive rate).

## Validation

For a test user, generate authentication alerts from two different countries within 30 minutes:
1. Authenticate from a source IP geolocated to Country A (triggers identity alert)
2. Within 30 minutes, authenticate from a source IP geolocated to Country B (triggers identity alert)

Expected result: User appears with `Esql.location_count >= 2`, `Esql.time_span_minutes <= 30`, severity of high or critical.

## Elastic Comparison

Elastic ships an "Impossible Travel" ML-based anomaly detection rule that uses machine learning to detect geographic anomalies. CORR-5J provides a deterministic alternative that does not require ML job configuration, uses explicit geo-baselines for transparency, and integrates with the correlation rule risk scoring framework. Both approaches are complementary -- the ML rule catches subtle anomalies while CORR-5J provides explainable, threshold-based detection.
