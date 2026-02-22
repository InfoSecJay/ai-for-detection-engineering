# Alert Surge by Rule

---

## Metadata

- **Rule ID:** `CORR-4D`
- **Tier:** 4 — Meta-Correlation
- **Author:** Detection Engineering
- **Description:** Detect when a detection rule fires at 5x or more its historical baseline rate within a 1-hour window. A rule that normally fires twice per hour suddenly firing 20 times indicates either a new attack matching that signature, an infrastructure change creating false positives, or a rule modification. This is a meta-detection: detecting changes in the behavior of the detection system itself. Alert surges are the earliest signal that something in the environment has changed.
- **Join Key(s):** `kibana.alert.rule.name`
- **Lookback:** 1 hour + baseline lookup
- **Schedule:** Every 15 minutes
- **Priority:** P2
- **Integration:** [alerts](https://www.elastic.co/guide/en/security/current/alerts-ui-manage.html)
- **Language:** `[ES|QL]`

## Query

```esql
FROM .internal.alerts-security.alerts-default
| WHERE @timestamp > NOW() - 1 HOURS
    AND kibana.alert.workflow_status == "open"
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
    severity_weight = CASE(
        signal.rule.severity == "critical", 25,
        signal.rule.severity == "high", 15,
        signal.rule.severity == "medium", 8,
        signal.rule.severity == "low", 3,
        1
    ),
    bbr_factor = CASE(kibana.alert.rule.building_block_type == "default", 0.3, 1.0),
    alert_risk = ROUND(severity_weight * bbr_factor)
| STATS
    Esql.current_count = COUNT(*),
    Esql.current_entities = COUNT_DISTINCT(entity_value),
    Esql.current_hosts = COUNT_DISTINCT(host.name),
    Esql.current_risk = SUM(alert_risk),
    Esql.max_severity = MAX(severity_weight),
    Esql.entity_types = VALUES(entity_type),
    Esql.entity_values = VALUES(entity_value),
    Esql.host_values = VALUES(host.name),
    Esql.tactic_values = VALUES(kibana.alert.rule.threat.tactic.name)
  BY kibana.alert.rule.name
| RENAME kibana.alert.rule.name AS rule_name
| LOOKUP JOIN lookup-rule-baselines ON rule_name
| RENAME rule_name AS kibana.alert.rule.name
| EVAL
    Esql.baseline_hourly_avg = ROUND(avg_daily_alerts / 24.0, 2),
    Esql.baseline_hourly_stddev = ROUND(std_dev_alerts / 24.0, 2),
    Esql.surge_ratio = ROUND(Esql.current_count / GREATEST(Esql.baseline_hourly_avg, 1.0), 2)
| WHERE Esql.surge_ratio >= 5.0 AND Esql.current_count >= 10
| EVAL
    Esql.correlation_severity = CASE(
        Esql.surge_ratio >= 20.0, "critical",
        Esql.surge_ratio >= 10.0, "high",
        Esql.surge_ratio >= 5.0, "medium",
        "low"
    ),
    Esql.description = CONCAT(
        "Rule surge: ", kibana.alert.rule.name,
        " | Current: ", TO_STRING(Esql.current_count), " alerts/hour",
        " | Baseline: ", TO_STRING(Esql.baseline_hourly_avg), " alerts/hour",
        " | Surge ratio: ", TO_STRING(Esql.surge_ratio), "x",
        " | Entities: ", TO_STRING(Esql.current_entities),
        " | Hosts: ", TO_STRING(Esql.current_hosts),
        " | Risk: ", TO_STRING(Esql.current_risk)
    )
| SORT Esql.surge_ratio DESC
| LIMIT 50
```

## Strategy

Counts current-hour alert volume per rule using `STATS...BY kibana.alert.rule.name`, then joins against `lookup-rule-baselines` to compare with historical averages. Each entity is represented as a typed composite key (`entity_type` + `entity_value`) using a CASE expression instead of COALESCE, preserving whether the entity is a user or a host. The baseline provides `avg_daily_alerts` and `std_dev_alerts`; the rule derives hourly averages as `avg_daily_alerts / 24`. The surge ratio (`current_count / baseline_hourly_avg`) must reach 5.0x with a minimum of 10 current alerts. Entity spread (`current_entities / baseline_entity_avg`) provides a secondary signal: a rule suddenly affecting many more entities than usual indicates environmental spread, not just repeated alerts on one host.

## Severity Logic

| Condition | Severity |
|-----------|----------|
| surge_ratio >= 20.0 (20x baseline) | Critical |
| surge_ratio >= 10.0 (10x baseline) | High |
| surge_ratio >= 5.0 AND current_count >= 10 | Medium |

Additional escalation criteria (evaluated manually or by downstream AI): if `current_entities >= 3x` the baseline entity count for that rule, escalate one severity level -- this indicates the surge is spreading to new targets, not just repeating on existing ones.

## Notes

- **Blind Spots:**
  - **New rules with no baseline**: Rules deployed within the last 7 days may have no entry in `lookup-rule-baselines`. They will not match the LOOKUP JOIN and will be excluded. Mitigation: seed new rules with conservative baseline values (e.g., avg_daily_alerts = 1) upon deployment.
  - **Seasonal patterns**: Rules that normally spike on certain days (e.g., Monday morning login storms) may trigger false surges. The baseline uses simple averages without day-of-week decomposition. Mitigation: use weekly rolling baselines that account for day-of-week patterns.
  - **Baseline staleness**: If `lookup-rule-baselines` is not refreshed regularly, baselines drift from reality. Mitigation: automate daily baseline recalculation.

- **False Positives:**
  - **Legitimate infrastructure changes**: New firewall rules, new EDR policies, or modified detection rules can cause sudden alert volume increases. Mitigation: cross-reference with change management systems and suppress during known change windows.
  - **Scheduled vulnerability scans**: Weekly or monthly scans that trigger detection rules in bulk. Mitigation: maintain scan schedule awareness and suppress during known scan windows.
  - **Rule modifications**: When a SOC analyst broadens a rule's scope, alert volume increases. This is technically a true positive (the rule is behaving differently) but is expected. Mitigation: reset the rule's baseline after intentional modifications.

- **Tuning:**
  1. **surge_ratio threshold** (default: 5.0) -- the primary sensitivity knob. Lower to 3.0 for critical rules where even small surges matter; raise to 10.0 for noisy rules.
  2. **current_count minimum** (default: 10) -- prevents low-volume rules from triggering on small absolute increases (e.g., baseline = 0.5/hour, current = 3 triggers a 6x ratio but is only 3 alerts).
  3. **Baseline refresh frequency** -- recalculate `lookup-rule-baselines` daily using a 7-day rolling window.
  4. **Per-rule severity overrides** -- critical detection rules (e.g., ransomware, C2 beaconing) should have lower surge thresholds than low-value rules.
  5. **Entity spread comparison** -- add entity count baselines to `lookup-rule-baselines` for richer surge analysis.

## Data Requirements

- **Index**: `.internal.alerts-security.alerts-default`
- **Lookup index**: `lookup-rule-baselines` with fields: `rule_name` (keyword), `avg_daily_alerts` (double), `std_dev_alerts` (double), `last_fire_date` (date)
- **Required fields**: `kibana.alert.rule.name`, `user.name`, `host.name`, `signal.rule.severity`, `kibana.alert.workflow_status`, `kibana.alert.rule.building_block_type`, `kibana.alert.rule.threat.tactic.name`, `@timestamp`
- **Minimum volume**: 10+ alerts from a single rule in 1 hour, exceeding 5x baseline

## Dependencies

- **Required**: `lookup-rule-baselines` -- must be populated and refreshed regularly. Without this lookup, the rule cannot compute surge ratios.
- **Recommended**: Automated baseline calculation job that updates `lookup-rule-baselines` daily from the previous 7-day alert history.

## Validation

1. Identify a rule that normally fires approximately 2 times per hour (baseline_hourly_avg ~2).
2. Trigger that rule 20 times within one hour across multiple hosts (e.g., run the triggering activity on 10 different endpoints).
3. CORR-4D should produce a surge alert with `Esql.surge_ratio >= 10.0` and `Esql.current_count >= 20`.
4. Verify severity resolves to "high" (10x surge).
5. Verify `Esql.current_entities` reflects the number of distinct entities involved.

## Elastic Comparison

Elastic does not ship a rule-level alert surge detection rule. Elastic's built-in monitoring tracks rule execution health (errors, timeouts) but not alert volume anomalies. The closest feature is Kibana's rule monitoring dashboard, which shows execution history but does not alert on volume deviations. CORR-4D provides automated, threshold-based surge detection with baseline comparison that Elastic does not offer natively.
