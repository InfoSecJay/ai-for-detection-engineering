# Silent Rule Reactivation

---

## Metadata

- **Rule ID:** `CORR-4E`
- **Tier:** 4 — Meta-Correlation
- **Author:** Detection Engineering
- **Description:** Detect when a detection rule that has not fired in 30 or more days suddenly produces alerts again. A dormant rule reactivating means either a new attack is matching an old signature, infrastructure has changed to expose previously unseen activity, or the rule was recently re-enabled. Dormant rule reactivation is a high-value signal because it represents a novel event in the detection environment -- the security team has not seen this alert in over a month, which means their mental model does not account for it.
- **Join Key(s):** `kibana.alert.rule.name` + `entity_type + entity_value (typed composite key)`
- **Lookback:** 24 hours + baseline lookup
- **Schedule:** Every 1 hour
- **Priority:** P2
- **Integration:** [alerts](https://www.elastic.co/guide/en/security/current/alerts-ui-manage.html)
- **Language:** `[ES|QL]`

## Query

```esql
FROM .internal.alerts-security.alerts-default
| WHERE @timestamp > NOW() - 24 HOURS
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
    Esql.alert_count = COUNT(*),
    Esql.entity_count = COUNT_DISTINCT(entity_value),
    Esql.entity_types = VALUES(entity_type),
    Esql.entity_values = VALUES(entity_value),
    Esql.host_values = VALUES(host.name),
    Esql.user_values = VALUES(user.name),
    Esql.risk_score = SUM(alert_risk),
    Esql.max_severity_weight = MAX(severity_weight),
    Esql.first_seen = MIN(@timestamp),
    Esql.last_seen = MAX(@timestamp),
    Esql.tactic_values = VALUES(kibana.alert.rule.threat.tactic.name),
    Esql.technique_values = VALUES(kibana.alert.rule.threat.technique.name)
  BY kibana.alert.rule.name
| RENAME kibana.alert.rule.name AS rule_name
| LOOKUP JOIN lookup-rule-baselines ON rule_name
| RENAME rule_name AS kibana.alert.rule.name
| EVAL
    Esql.days_silent = DATE_DIFF("day", last_fire_date, Esql.last_seen)
| WHERE Esql.days_silent >= 30
| EVAL
    Esql.correlation_severity = CASE(
        Esql.days_silent >= 90 AND Esql.max_severity_weight >= 15, "critical",
        Esql.days_silent >= 90, "high",
        Esql.days_silent >= 30, "medium",
        "low"
    ),
    Esql.reactivation_score = ROUND(Esql.risk_score
        * CASE(Esql.days_silent >= 180, 3.0, Esql.days_silent >= 90, 2.0, Esql.days_silent >= 60, 1.5, 1.0)
        * CASE(Esql.entity_count >= 3, 1.5, 1.0)),
    Esql.description = CONCAT(
        "Silent rule reactivated: ", kibana.alert.rule.name,
        " | Silent for ", TO_STRING(Esql.days_silent), " days",
        " | Last fired: ", TO_STRING(last_fire_date),
        " | Now: ", TO_STRING(Esql.alert_count), " alerts",
        " | ", TO_STRING(Esql.entity_count), " entities",
        " | Risk: ", TO_STRING(Esql.reactivation_score)
    )
| SORT Esql.reactivation_score DESC
| LIMIT 50
```

## Strategy

Joins current alerts against `lookup-rule-baselines` to retrieve `last_fire_date` per rule. Computes `days_silent = DATE_DIFF("day", last_fire_date, @timestamp)` and filters to rules where `days_silent >= 30`. Each entity is represented as a typed composite key (`entity_type` + `entity_value`) using a CASE expression instead of COALESCE, preserving whether the entity is a user or a host. The rule captures both the reactivated rule name and the entities involved. Severity escalates with dormancy duration and the severity of the reactivated rule -- a critical rule that has been silent for 90 days reactivating is more alarming than a low-severity rule silent for 31 days.

## Severity Logic

| Condition | Severity |
|-----------|----------|
| days_silent >= 90 AND original alert severity >= high | Critical |
| days_silent >= 90 (any severity) | High |
| days_silent >= 30 | Medium |

Reactivation score multipliers: days_silent >= 180 = 3.0x, >= 90 = 2.0x, >= 60 = 1.5x. Entity count >= 3 = additional 1.5x (dormant rule suddenly affecting multiple entities is more concerning).

## Notes

- **Blind Spots:**
  - **Recently created rules**: Rules deployed within the last 30 days have no dormancy history and will not appear in `lookup-rule-baselines` with a meaningful `last_fire_date`. They are correctly excluded -- a new rule has no "silent period."
  - **Intermittently firing rules**: Rules designed to fire rarely (e.g., seasonal processes, quarterly reporting tools) will trigger CORR-4E whenever they fire after their natural dormant period. This is technically a true positive but may not be actionable.
  - **Baseline not updated**: If `lookup-rule-baselines` is not refreshed, `last_fire_date` becomes stale. A rule that fired last week will still show days_silent based on the outdated baseline.

- **False Positives:**
  - **Seasonal business processes**: Quarterly tax preparation software, annual audit tools, seasonal marketing campaigns that trigger detection rules periodically. Mitigation: document seasonal rules in `lookup-rule-baselines` with a `seasonal` flag.
  - **Rules re-enabled by SOC team**: When analysts intentionally re-enable a previously disabled rule, it appears as a reactivation. Mitigation: cross-reference with rule modification audit logs.
  - **Infrastructure rotation**: New servers or endpoints joining the environment may trigger rules that previously had no targets. Mitigation: correlate with asset onboarding events.

- **Tuning:**
  1. **days_silent threshold** (default: 30) -- raise to 60 or 90 if your environment has many infrequently-firing rules that create noise.
  2. **Baseline refresh frequency** -- `lookup-rule-baselines.last_fire_date` must be updated whenever a rule fires. Automate this with a daily job.
  3. **Seasonal exclusion** -- add a `seasonal` boolean to `lookup-rule-baselines` and exclude rules flagged as seasonal.
  4. **Severity weight consideration** -- the `Esql.max_severity_weight >= 15` check (high or critical) in the severity logic ensures critical severity only for rules that detect serious threats.
  5. **Entity count amplification** -- the entity_count multiplier (1.5x for 3+ entities) can be adjusted based on how unusual multi-entity reactivation is in your environment.

## Data Requirements

- **Index**: `.internal.alerts-security.alerts-default`
- **Lookup index**: `lookup-rule-baselines` with fields: `rule_name` (keyword), `last_fire_date` (date), `avg_daily_alerts` (double), `std_dev_alerts` (double)
- **Required fields**: `kibana.alert.rule.name`, `user.name`, `host.name`, `signal.rule.severity`, `kibana.alert.workflow_status`, `kibana.alert.rule.building_block_type`, `kibana.alert.rule.threat.tactic.name`, `kibana.alert.rule.threat.technique.name`, `@timestamp`
- **Minimum volume**: 1+ alert from a rule whose `last_fire_date` is 30+ days ago

## Dependencies

- **Required**: `lookup-rule-baselines` -- specifically the `last_fire_date` field. Without this lookup, the rule cannot determine dormancy duration.
- **Recommended**: Automated job to update `last_fire_date` in `lookup-rule-baselines` whenever a rule produces alerts. This job should run daily.

## Validation

1. Identify a detection rule in your environment. Record its current `last_fire_date` in `lookup-rule-baselines`.
2. Manually set `last_fire_date` to 60 days ago in the lookup index (simulating dormancy).
3. Trigger the rule by executing the activity it detects.
4. CORR-4E should produce a reactivation alert with `Esql.days_silent >= 60`.
5. Verify severity resolves to "medium" (30-89 days) or "high" (if you set it to 90+ days).
6. After validation, restore the correct `last_fire_date`.

## Elastic Comparison

Elastic does not ship a silent rule reactivation detection rule. Elastic's rule monitoring tracks execution failures and performance but does not analyze alert production patterns over time. There is no native mechanism to alert when a previously dormant rule begins firing again. CORR-4E fills a gap in detection engineering observability that Elastic does not address.
