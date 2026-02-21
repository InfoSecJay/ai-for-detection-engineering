# First-Time Rule Trigger for Entity

---

## Metadata

- **Rule ID:** `CORR-6A`
- **Tier:** 6 — Novelty and Anomaly Detection
- **Author:** Detection Engineering
- **Description:** Detect entities (users or hosts) triggering detection rules they have never triggered before. A user who has worked at the company for two years and suddenly fires a "Credential Dumping via LSASS" rule for the first time is far more suspicious than a pentester's lab machine that fires it weekly. This rule surfaces the novelty signal that raw alert volume ignores.
- **Join Key(s):** `COALESCE(user.name, host.name)` + `kibana.alert.rule.name`
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
    AND (user.name IS NOT NULL OR host.name IS NOT NULL)
| EVAL
    entity = COALESCE(user.name, host.name),
    rule_name = kibana.alert.rule.name,
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
| RENAME entity AS entity_value
| LOOKUP JOIN lookup-entity-history ON entity_value, rule_name
| RENAME entity_value AS entity
| WHERE last_seen_date IS NULL
| STATS
    Esql.novel_rules = COUNT_DISTINCT(kibana.alert.rule.name),
    Esql.alert_count = COUNT(*),
    Esql.risk_score = SUM(alert_risk),
    Esql.max_severity = MAX(severity_weight),
    Esql.high_critical_count = SUM(is_high_or_critical),
    Esql.first_seen = MIN(@timestamp),
    Esql.last_seen = MAX(@timestamp),
    Esql.novel_rule_names = VALUES(kibana.alert.rule.name),
    Esql.tactic_values = VALUES(kibana.alert.rule.threat.tactic.name),
    Esql.tactic_count = COUNT_DISTINCT(kibana.alert.rule.threat.tactic.name),
    Esql.host_values = VALUES(host.name),
    Esql.data_sources = VALUES(event.dataset)
  BY entity
| WHERE Esql.novel_rules >= 1
| EVAL
    Esql.correlation_severity = CASE(
        Esql.novel_rules >= 3 AND Esql.max_severity >= 15, "critical",
        Esql.novel_rules >= 2, "high",
        Esql.novel_rules >= 1 AND Esql.max_severity >= 15, "high",
        "medium"
    ),
    Esql.description = CONCAT(
        "Entity ", entity,
        " triggered ", TO_STRING(Esql.novel_rules), " NEVER-BEFORE-SEEN rules",
        " | Risk: ", TO_STRING(Esql.risk_score),
        " | ", TO_STRING(Esql.alert_count), " novel alerts",
        " | ", TO_STRING(Esql.tactic_count), " tactics",
        " | Window: ", TO_STRING(Esql.first_seen), " to ", TO_STRING(Esql.last_seen)
    )
| SORT Esql.risk_score DESC
| LIMIT 50
```

## Strategy

Aggregates all open alerts by entity within a 24-hour window. Each alert's rule name is checked against `lookup-entity-history` using `LOOKUP JOIN` to determine whether this entity has ever triggered this specific rule before. Alerts where `last_seen_date IS NULL` (no historical record) are flagged as novel. The rule then counts how many distinct novel rules each entity has triggered, computes a weighted risk score, and applies severity based on the count and severity of novel rule triggers.

## Severity Logic

| Condition | Severity |
|-----------|----------|
| 3+ novel rules AND at least one high/critical severity alert | Critical |
| 2+ novel rules | High |
| 1 novel rule AND at least one high/critical severity alert | High |
| 1 novel rule with medium or lower severity | Medium |

## Notes

- **Blind Spots:**
  - **New entities**: Any entity with no history in `lookup-entity-history` will have every rule appear as novel. New employees, newly provisioned systems, and recently onboarded hosts will generate a flood of false positives until their baseline is established.
  - **Lookup index staleness**: If `lookup-entity-history` is not updated regularly (recommended: daily), recently seen rule-entity pairs will be treated as novel.
  - **Rule renames**: If a detection rule is renamed, the new name has no history. All entities triggering the renamed rule will appear novel.

- **False Positives:**
  - **New employees**: First week of employment generates novel triggers across all rule types. Mitigation: suppress entities with account creation date < 14 days (requires enrichment from HR/IAM system).
  - **New systems being onboarded**: Fresh deployments trigger endpoint rules for the first time. Mitigation: suppress hosts with first-seen date < 7 days in asset inventory.
  - **Recently deployed detection rules**: A new rule has no history for any entity. Every trigger is "novel." Mitigation: exclude rules deployed within the last 7 days using a rule deployment date lookup or tagging convention.

- **Tuning:**
  1. `novel_rules` threshold (default: 1) -- increase to 2 if new-rule deployments are frequent
  2. Add a minimum `alert_risk` threshold to filter out low-severity novel triggers
  3. Exclude specific rule names known to fire broadly after deployment
  4. Consider adding an entity age filter (suppress entities less than 14 days old)
  5. Update `lookup-entity-history` daily via a scheduled transform or scripted pipeline

## Data Requirements

- **Index**: `.internal.alerts-security.alerts-default`
- **Lookup Index**: `lookup-entity-history` (fields: `entity`, `rule_name`, `last_seen_date`, `first_seen`, `known_domains`)
- **Required fields**: `user.name`, `host.name`, `kibana.alert.rule.name`, `signal.rule.severity`, `kibana.alert.rule.building_block_type`, `kibana.alert.workflow_status`, `@timestamp`, `event.dataset`, `kibana.alert.rule.threat.tactic.name`
- **Minimum volume**: At least 30 days of historical data in lookup-entity-history for meaningful novelty detection

## Dependencies

- **Required**: `lookup-entity-history` -- must be populated and maintained with historical entity-rule associations
- **Optional**: `lookup-critical-assets` for severity escalation on critical assets

## Validation

Trigger a detection rule against a host that has never fired that specific rule. For example:
1. Identify a workstation that has never triggered "Suspicious PowerShell Execution"
2. Execute a benign PowerShell download cradle on that workstation
3. Verify the rule fires and CORR-6A surfaces the entity with `Esql.novel_rules >= 1`
4. Confirm that a host which has historically triggered that same rule does NOT appear in CORR-6A results

## Elastic Comparison

Elastic does not ship a "first-time rule trigger per entity" correlation rule. The closest feature is the Risk Score engine, which accumulates risk over time but does not flag novelty. Elastic's ML anomaly detection jobs can detect unusual rule firing patterns but require ML node capacity and are not deterministic. CORR-6A provides deterministic, explainable novelty detection without ML infrastructure.
