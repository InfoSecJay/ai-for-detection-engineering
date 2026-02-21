# New Source Country Alert Cluster

---

## Metadata

- **Rule ID:** `CORR-6B`
- **Tier:** 6 — Novelty and Anomaly Detection
- **Author:** Detection Engineering
- **Description:** Detect users generating alerts from source countries they have never previously been associated with. An Okta authentication failure from Germany for a user who has only ever authenticated from the United States is inherently suspicious. This rule goes beyond simple impossible-travel by checking whether any alert -- not just auth events -- originates from an unexpected geography.
- **Join Key(s):** `user.name`
- **Lookback:** 24 hours
- **Schedule:** Every 30 minutes
- **Priority:** P2
- **Integration:** [alerts](https://www.elastic.co/guide/en/security/current/alerts-ui-manage.html)
- **Language:** `[ES|QL]`

## Query

```esql
FROM .internal.alerts-security.alerts-default
| WHERE @timestamp > NOW() - 24 HOURS
    AND kibana.alert.workflow_status == "open"
    AND user.name IS NOT NULL
    AND source.geo.country_name IS NOT NULL
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
| LOOKUP JOIN lookup-geo-baselines ON user.name
| EVAL
    Esql.is_new_country = CASE(
        expected_countries IS NULL, true,
        NOT source.geo.country_name IN (expected_countries), true,
        false
    )
| WHERE Esql.is_new_country == true
| STATS
    Esql.new_country_alerts = COUNT(*),
    Esql.new_countries = COUNT_DISTINCT(source.geo.country_name),
    Esql.new_country_values = VALUES(source.geo.country_name),
    Esql.risk_score = SUM(alert_risk),
    Esql.max_severity = MAX(severity_weight),
    Esql.high_critical_count = SUM(is_high_or_critical),
    Esql.first_seen = MIN(@timestamp),
    Esql.last_seen = MAX(@timestamp),
    Esql.rule_names = VALUES(kibana.alert.rule.name),
    Esql.unique_rules = COUNT_DISTINCT(kibana.alert.rule.name),
    Esql.source_ips = VALUES(source.ip),
    Esql.host_values = VALUES(host.name)
  BY user.name
| WHERE Esql.new_country_alerts >= 1
| EVAL
    Esql.severity = CASE(
        Esql.new_countries >= 1 AND Esql.max_severity >= 15, "critical",
        Esql.new_countries >= 2, "high",
        Esql.new_countries >= 1, "medium",
        "medium"
    ),
    Esql.description = CONCAT(
        "User ", user.name,
        " generated ", TO_STRING(Esql.new_country_alerts), " alerts from ",
        TO_STRING(Esql.new_countries), " NEW countries: ",
        TO_STRING(Esql.new_country_values),
        " | Risk: ", TO_STRING(Esql.risk_score),
        " | Rules: ", TO_STRING(Esql.unique_rules)
    )
| SORT Esql.risk_score DESC
| LIMIT 50
```

## Strategy

Filters alerts to those with `source.geo.country_name` populated, then uses `LOOKUP JOIN` against `lookup-geo-baselines` to retrieve each user's historically observed countries. Alerts originating from countries not in the user's baseline are flagged as novel. The rule aggregates novel-country alerts per user, counting distinct new countries and computing a weighted risk score. Severity escalates when multiple new countries appear or when novel-country alerts coincide with high-severity detections.

## Severity Logic

| Condition | Severity |
|-----------|----------|
| New country + high or critical severity alert | Critical |
| 2+ new countries | High |
| 1 new country (medium or lower severity) | Medium |

## Notes

- **Blind Spots:**
  - **Alerts without geo data**: Many alert types (endpoint, cloud API) do not populate `source.geo.country_name`. This rule only operates on geo-enriched alerts.
  - **VPN exit nodes**: Users connecting through corporate VPN appear from the VPN exit country, not their physical location.
  - **Geo-baseline coverage**: Users not in `lookup-geo-baselines` have no expected countries, so the rule treats all countries as new (handled by `expected_countries IS NULL` check).

- **False Positives:**
  - **Business travel**: Employees traveling internationally trigger alerts from new countries legitimately. Mitigation: maintain a travel calendar integration or suppress for known frequent travelers.
  - **VPN egress changes**: Corporate VPN infrastructure changes or new VPN concentrators in different regions. Mitigation: update geo baselines after VPN infrastructure changes.
  - **CDN/proxy geo-shifting**: Some cloud services route traffic through regional endpoints. Mitigation: exclude known CDN/proxy source IPs.

- **Tuning:**
  1. Update `lookup-geo-baselines` weekly from authentication logs (not just alert data)
  2. Add a minimum `alert_risk` threshold to filter low-severity geo anomalies
  3. Consider excluding specific countries known to host corporate VPN egress points
  4. For organizations with heavy travel, increase the threshold to `new_countries >= 2`
  5. Cross-reference with HR travel systems if available

## Data Requirements

- **Index**: `.internal.alerts-security.alerts-default`
- **Lookup Index**: `lookup-geo-baselines` (fields: `user.name`, `expected_countries`, `last_updated`)
- **Required fields**: `user.name`, `source.geo.country_name`, `source.ip`, `signal.rule.severity`, `kibana.alert.rule.building_block_type`, `kibana.alert.workflow_status`, `@timestamp`, `kibana.alert.rule.name`
- **Minimum volume**: Geo baselines populated from 30+ days of authentication data

## Dependencies

- **Required**: `lookup-geo-baselines` -- must contain per-user expected country lists
- **Optional**: `lookup-critical-assets` for severity escalation

## Validation

1. Identify a user whose baseline contains only "United States"
2. Generate an authentication alert from a VPN endpoint in a country NOT in their baseline (e.g., Romania)
3. Verify CORR-6B surfaces the user with `Esql.new_countries >= 1` and the unexpected country in `Esql.new_country_values`
4. Confirm that alerts from the user's expected countries do NOT trigger CORR-6B

## Elastic Comparison

Elastic ships "Impossible Travel" ML rules that detect geographic anomalies based on authentication event timing. CORR-6B differs in three ways: (1) it operates on all alert types with geo data, not just auth events; (2) it uses a deterministic baseline lookup rather than ML; (3) it correlates new-country alerts with severity and rule diversity for richer context. The two approaches are complementary.
