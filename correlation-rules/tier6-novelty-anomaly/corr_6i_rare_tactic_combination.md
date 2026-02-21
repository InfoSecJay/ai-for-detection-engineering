# Rare Tactic Combination

---

## Metadata

- **Rule ID:** `CORR-6I`
- **Tier:** 6 — Novelty and Anomaly Detection
- **Author:** Detection Engineering
- **Description:** Detect entities exhibiting combinations of MITRE ATT&CK tactics that have rarely or never been observed together in the environment's alert history. Most attacks follow predictable tactic sequences (Initial Access, Execution, Persistence). An entity exhibiting Reconnaissance + Impact (unusual pairing) or Collection + Defense Evasion + Exfiltration (rare triple) stands out because the combination itself is anomalous, even if individual alerts are medium severity.
- **Join Key(s):** `COALESCE(user.name, host.name)`
- **Lookback:** 24 hours
- **Schedule:** Every 1 hour
- **Priority:** P2
- **Integration:** [alerts](https://www.elastic.co/guide/en/security/current/alerts-ui-manage.html)
- **Language:** `[ES|QL]`

## Query

```esql
FROM .internal.alerts-security.alerts-default
| WHERE @timestamp > NOW() - 24 HOURS
    AND kibana.alert.workflow_status == "open"
    AND (user.name IS NOT NULL OR host.name IS NOT NULL)
    AND kibana.alert.rule.threat.tactic.name IS NOT NULL
| EVAL
    entity = COALESCE(user.name, host.name),
    tactic = kibana.alert.rule.threat.tactic.name,
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
    Esql.risk_score = SUM(alert_risk),
    Esql.max_severity = MAX(severity_weight),
    Esql.tactic_count = COUNT_DISTINCT(tactic),
    Esql.tactic_values = VALUES(tactic),
    Esql.first_seen = MIN(@timestamp),
    Esql.last_seen = MAX(@timestamp),
    Esql.rule_names = VALUES(kibana.alert.rule.name),
    Esql.unique_rules = COUNT_DISTINCT(kibana.alert.rule.name),
    Esql.host_values = VALUES(host.name),
    Esql.data_sources = VALUES(event.dataset)
  BY entity
| WHERE Esql.tactic_count >= 2
| EVAL
    Esql.tactic_combination = TO_STRING(MV_SORT(Esql.tactic_values))
| LOOKUP JOIN lookup-rule-baselines ON Esql.tactic_combination
| WHERE known_tactic_pairs IS NULL OR known_tactic_pairs == false
| EVAL
    Esql.severity = CASE(
        Esql.tactic_count >= 3 AND Esql.max_severity >= 15, "high",
        Esql.tactic_count >= 2 AND Esql.max_severity >= 15, "high",
        Esql.tactic_count >= 2, "medium",
        "medium"
    ),
    Esql.description = CONCAT(
        "Entity ", entity,
        " exhibited RARE tactic combination: ", Esql.tactic_combination,
        " | ", TO_STRING(Esql.tactic_count), " tactics across ",
        TO_STRING(Esql.unique_rules), " rules",
        " | ", TO_STRING(Esql.alert_count), " alerts",
        " | Risk: ", TO_STRING(Esql.risk_score)
    )
| SORT Esql.risk_score DESC
| LIMIT 50
```

## Strategy

Collects all MITRE ATT&CK tactics associated with each entity's alerts within the lookback window. Generates a sorted, concatenated tactic-pair identifier for each unique pair of tactics observed. These pair identifiers are checked against `lookup-rule-baselines` (which includes a `known_tactic_pairs` field or a dedicated tactic-pair baseline) to determine rarity. Entities with one or more rare tactic combinations are flagged.

## Severity Logic

| Condition | Severity |
|-----------|----------|
| 2+ rare tactic pairs + high/critical severity (3+ tactics, max severity >= 15) | High |
| 1 rare pair + high/critical severity (2+ tactics, max severity >= 15) | High |
| 1 rare tactic pair (medium or lower severity) | Medium |

## Notes

- **Blind Spots:**
  - **Limited tactic metadata**: Many detection rules do not have MITRE ATT&CK tactic mappings populated. Alerts without tactic metadata are invisible to this rule.
  - **Small alert corpus**: In environments with low alert volume, all tactic combinations may appear "rare" because the baseline has insufficient data to establish common patterns.
  - **Multi-valued tactics**: A single alert may map to multiple tactics, creating tactic combinations within a single alert that are not actually distinct attack steps.

- **False Positives:**
  - **Purple team exercises**: Red team operators deliberately execute unusual tactic combinations. Mitigation: tag purple team accounts and suppress during exercises.
  - **Detection rule testing**: Detection engineers testing rules covering unusual tactic combinations. Mitigation: exclude test accounts and lab environments.
  - **Incomplete tactic mappings**: Rules incorrectly mapped to unusual tactic combinations produce artificial rarity. Mitigation: audit MITRE mappings for accuracy.

- **Tuning:**
  1. Build a tactic-pair frequency baseline from 60+ days of alert data (more than other Tier 6 rules) to avoid treating everything as rare
  2. Set a minimum `alert_count` threshold (e.g., >= 3) to filter entities with too few alerts for meaningful tactic analysis
  3. Exclude specific tactic pairs known to co-occur in your environment (e.g., Defense Evasion + Execution is common)
  4. Weight certain tactic pairs higher than others (Reconnaissance + Impact is more suspicious than Execution + Persistence)
  5. Consider using tactic-pair frequency percentile rather than binary rare/not-rare classification

## Data Requirements

- **Index**: `.internal.alerts-security.alerts-default`
- **Lookup Index**: `lookup-rule-baselines` (fields: `Esql.tactic_combination` or equivalent join key, `known_tactic_pairs`)
- **Required fields**: `user.name`, `host.name`, `kibana.alert.rule.threat.tactic.name`, `signal.rule.severity`, `kibana.alert.rule.building_block_type`, `kibana.alert.workflow_status`, `@timestamp`, `kibana.alert.rule.name`, `event.dataset`
- **Minimum volume**: 60+ days of alert data with tactic mappings to build a meaningful tactic-pair baseline

## Dependencies

- **Required**: `lookup-rule-baselines` -- must contain known tactic-pair frequencies or a dedicated tactic-pair baseline index
- **Optional**: MITRE ATT&CK mapping validation for detection rules

## Validation

1. Generate alerts combining Reconnaissance + Impact tactics for the same entity (unusual pairing in most environments)
2. Ensure this tactic pair is NOT in the baseline (or is marked as rare)
3. Verify CORR-6I surfaces the entity with the rare tactic combination
4. Generate alerts combining Execution + Persistence (common pairing) and confirm CORR-6I does NOT fire

## Elastic Comparison

Elastic does not ship a tactic-combination rarity rule. Elastic's MITRE ATT&CK coverage dashboard shows tactic distribution but does not flag unusual combinations. CORR-6I provides a unique capability to detect attack patterns that are novel at the tactic-sequence level.
