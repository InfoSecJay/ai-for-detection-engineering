# Alert Pattern Shift Detection

---

## Metadata

- **Rule ID:** `CORR-6G`
- **Tier:** 6 — Novelty and Anomaly Detection
- **Author:** Detection Engineering
- **Description:** Detect detection rules whose firing patterns have shifted significantly from their historical baselines. If a rule that normally fires 5 times per day against 3 hosts suddenly fires 50 times against 20 hosts, the rule's target population has changed. This could indicate a new attack campaign, a misconfiguration, or an adversary deliberately triggering rules to create noise. Pattern shift detection monitors the detection rules themselves as data sources.
- **Join Key(s):** `kibana.alert.rule.name`
- **Lookback:** 24 hours
- **Schedule:** Every 2 hours
- **Priority:** P3
- **Integration:** [alerts](https://www.elastic.co/guide/en/security/current/alerts-ui-manage.html)
- **Language:** `[ES|QL]`

## Query

```esql
FROM .internal.alerts-security.alerts-default
| WHERE @timestamp > NOW() - 24 HOURS
    AND kibana.alert.workflow_status == "open"
    AND kibana.alert.rule.name IS NOT NULL
| EVAL
    entity_type = CASE(
        user.name IS NOT NULL, "user",
        host.name IS NOT NULL, "host",
        "unknown"
    ),
    entity_value = CASE(
        user.name IS NOT NULL, user.name,
        host.name IS NOT NULL, host.name,
        "unknown"
    ),
    hour_of_day = DATE_EXTRACT("hour", @timestamp),
    severity_weight = CASE(
        signal.rule.severity == "critical", 25,
        signal.rule.severity == "high", 15,
        signal.rule.severity == "medium", 8,
        signal.rule.severity == "low", 3, 1
    ),
    bbr_factor = CASE(kibana.alert.rule.building_block_type == "default", 0.3, 1.0),
    alert_risk = ROUND(severity_weight * bbr_factor)
| STATS
    Esql.current_count = COUNT(*),
    Esql.current_entities = COUNT_DISTINCT(entity_value),
    Esql.current_risk = SUM(alert_risk),
    Esql.current_max_severity = MAX(severity_weight),
    Esql.current_sources = COUNT_DISTINCT(event.dataset),
    Esql.entity_values = VALUES(entity_value),
    Esql.tactic_values = VALUES(kibana.alert.rule.threat.tactic.name),
    Esql.first_seen = MIN(@timestamp),
    Esql.last_seen = MAX(@timestamp)
  BY kibana.alert.rule.name
| LOOKUP JOIN lookup-rule-baselines ON kibana.alert.rule.name
| WHERE avg_daily_alerts IS NOT NULL AND std_dev_alerts IS NOT NULL
| EVAL
    Esql.count_zscore = ROUND(
        (Esql.current_count - avg_daily_alerts) / GREATEST(std_dev_alerts, 1.0), 2
    ),
    Esql.entity_shift = CASE(
        Esql.current_entities >= 10 AND avg_daily_alerts <= 5, 3,
        Esql.current_entities >= 5 AND avg_daily_alerts <= 3, 2,
        Esql.current_entities >= 3 AND avg_daily_alerts <= 1, 1,
        0
    ),
    Esql.pattern_shift_score = ROUND(
        ABS(Esql.count_zscore) + TO_DOUBLE(Esql.entity_shift), 2
    )
| WHERE Esql.pattern_shift_score >= 4.0
| EVAL
    Esql.correlation_severity = CASE(
        Esql.pattern_shift_score >= 7.0 AND Esql.current_count >= 20, "high",
        Esql.pattern_shift_score >= 5.0, "medium",
        "low"
    ),
    Esql.description = CONCAT(
        "Rule '", kibana.alert.rule.name,
        "' pattern SHIFTED | Shift Score: ", TO_STRING(Esql.pattern_shift_score),
        " | Count Z-Score: ", TO_STRING(Esql.count_zscore),
        " (current=", TO_STRING(Esql.current_count),
        " vs baseline avg=", TO_STRING(avg_daily_alerts), ")",
        " | ", TO_STRING(Esql.current_entities), " entities affected"
    )
| SORT Esql.pattern_shift_score DESC
| LIMIT 50
```

## Strategy

Computes current-window metrics for each detection rule (alert count, distinct entities, time-of-day distribution, severity mix) and compares them against historical baselines stored in `lookup-rule-baselines`. The comparison produces a composite `pattern_shift_score` reflecting how much the current pattern deviates from the historical norm. Rules with significant shifts are surfaced for investigation.

## Severity Logic

| Condition | Severity |
|-----------|----------|
| Pattern shift score >= 7.0 AND current count >= 20 (major shift + high volume) | High |
| Pattern shift score >= 5.0 (moderate shift) | Medium |
| Pattern shift score >= 4.0 (threshold) | Low (informational) |

## Notes

- **Blind Spots:**
  - **New rules without baseline**: Rules recently deployed have no baseline in `lookup-rule-baselines` and are filtered out. Consider a separate "new rule monitoring" process.
  - **Gradual drift**: If baselines are updated frequently, a gradual increase in rule firing rate shifts the baseline without triggering this rule.
  - **Seasonal patterns**: Some rules fire more during specific business periods (month-end, quarter-end). Static baselines do not account for seasonality.

- **False Positives:**
  - **Legitimate infrastructure changes**: Network reconfigurations, domain migrations, or policy changes can shift rule firing patterns. Mitigation: suppress for 48 hours after known infrastructure changes.
  - **Rule modifications by detection engineering**: Tuning a rule's query logic changes its firing pattern. Mitigation: exclude rules modified within the last 48 hours.
  - **Incident response activity**: Active IR causes unusual alert patterns. Mitigation: tag IR periods for suppression.

- **Tuning:**
  1. `pattern_shift_score` threshold (default: 4.0) -- increase for noisy environments
  2. Update `lookup-rule-baselines` weekly with rolling 30-day averages
  3. Add seasonality factors for rules with known cyclic patterns
  4. Exclude rules tagged as "recently tuned" from pattern shift detection
  5. Consider separate thresholds for building block rules vs. standard rules

## Data Requirements

- **Index**: `.internal.alerts-security.alerts-default`
- **Lookup Index**: `lookup-rule-baselines` (fields: `kibana.alert.rule.name`, `avg_daily_alerts`, `std_dev_alerts`, `last_fire_date`)
- **Required fields**: `kibana.alert.rule.name`, `user.name`, `host.name`, `@timestamp`, `event.dataset`, `signal.rule.severity`, `kibana.alert.rule.building_block_type`, `kibana.alert.workflow_status`, `kibana.alert.rule.threat.tactic.name`
- **Minimum volume**: Rule baselines populated from 30+ days of alert history

## Dependencies

- **Required**: `lookup-rule-baselines` -- must contain per-rule firing statistics
- **Optional**: Detection engineering change log for suppression during rule tuning periods

## Validation

1. Identify a detection rule with a stable baseline (e.g., fires 3-5 times daily against 2 hosts)
2. Modify the rule temporarily to fire more broadly (lower threshold), or generate synthetic alerts
3. Verify CORR-6G surfaces the rule with an elevated `Esql.pattern_shift_score`
4. Restore the rule and confirm CORR-6G no longer fires on the next cycle

## Elastic Comparison

Elastic does not ship a rule-pattern-shift correlation. Elastic's Detection Engineering health dashboard shows rule firing rates but does not compare against baselines or compute shift scores. CORR-6G provides automated detection of changes in the detection surface itself -- a meta-detection capability.
