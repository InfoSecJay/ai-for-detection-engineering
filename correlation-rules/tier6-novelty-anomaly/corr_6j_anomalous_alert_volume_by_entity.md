# Anomalous Alert Volume by Entity

---

## Metadata

- **Rule ID:** `CORR-6J`
- **Tier:** 6 — Novelty and Anomaly Detection
- **Author:** Detection Engineering
- **Description:** Detect entities generating a statistically anomalous volume of alerts relative to their historical baseline. An entity that normally generates 1-2 alerts per 4-hour window suddenly generating 15+ is a significant deviation that warrants investigation regardless of alert severity or type. This rule applies z-score-based statistical anomaly detection to alert volume per entity.
- **Join Key(s):** `COALESCE(user.name, host.name)`
- **Lookback:** 4 hours
- **Schedule:** Every 15 minutes
- **Priority:** P2
- **Integration:** [alerts](https://www.elastic.co/guide/en/security/current/alerts-ui-manage.html)
- **Language:** `[ES|QL]`

## Query

```esql
FROM .internal.alerts-security.alerts-default
| WHERE @timestamp > NOW() - 4 HOURS
    AND kibana.alert.workflow_status == "open"
    AND (user.name IS NOT NULL OR host.name IS NOT NULL)
| EVAL
    entity = COALESCE(user.name, host.name),
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
    alert_risk = ROUND(severity_weight * bbr_factor)
| STATS
    Esql.current_count = COUNT(*),
    Esql.current_rules = COUNT_DISTINCT(kibana.alert.rule.name),
    Esql.risk_score = SUM(alert_risk),
    Esql.max_severity = MAX(severity_weight),
    Esql.domain_count = COUNT_DISTINCT(domain_category),
    Esql.domain_values = VALUES(domain_category),
    Esql.first_seen = MIN(@timestamp),
    Esql.last_seen = MAX(@timestamp),
    Esql.rule_names = VALUES(kibana.alert.rule.name),
    Esql.tactic_values = VALUES(kibana.alert.rule.threat.tactic.name),
    Esql.host_values = VALUES(host.name),
    Esql.source_ips = VALUES(source.ip)
  BY entity
| LOOKUP JOIN lookup-risk-scores ON entity
| WHERE baseline_avg_4h_count IS NOT NULL AND baseline_stddev IS NOT NULL
| EVAL
    Esql.volume_zscore = ROUND(
        (TO_DOUBLE(Esql.current_count) - baseline_avg_4h_count)
            / GREATEST(baseline_stddev, 1.0), 2
    )
| WHERE Esql.volume_zscore >= 3.0 AND Esql.current_count >= 5
| EVAL
    Esql.severity = CASE(
        Esql.volume_zscore >= 5.0, "critical",
        Esql.volume_zscore >= 4.0, "high",
        Esql.volume_zscore >= 3.0, "medium",
        "medium"
    ),
    Esql.description = CONCAT(
        "Entity ", entity,
        " alert volume ANOMALY | Z-Score: ", TO_STRING(Esql.volume_zscore),
        " | Current: ", TO_STRING(Esql.current_count), " alerts in 4h",
        " (baseline avg: ", TO_STRING(baseline_avg_4h_count),
        ", stddev: ", TO_STRING(baseline_stddev), ")",
        " | ", TO_STRING(Esql.current_rules), " rules across ",
        TO_STRING(Esql.domain_count), " domains",
        " | Risk: ", TO_STRING(Esql.risk_score)
    )
| SORT Esql.volume_zscore DESC
| LIMIT 50
```

## Strategy

Computes the current 4-hour alert count and rule diversity per entity, then retrieves the entity's historical baseline (average 4-hour count and standard deviation) from `lookup-risk-scores` or `lookup-entity-history` via `LOOKUP JOIN`. A z-score is computed: `(current_count - baseline_avg) / GREATEST(baseline_stddev, 1)`. Entities with z-scores at or above 3.0 (three standard deviations above the mean) and a minimum absolute count are flagged. Severity escalates with z-score magnitude.

## Severity Logic

| Condition | Severity |
|-----------|----------|
| Z-score >= 5.0 (extreme outlier, 5+ standard deviations) | Critical |
| Z-score >= 4.0 (major outlier) | High |
| Z-score >= 3.0 (significant outlier) | Medium |

## Notes

- **Blind Spots:**
  - **New entities without baseline**: Entities not present in `lookup-risk-scores` (no `baseline_avg_4h_count`) are filtered out. New users and hosts have no baseline for comparison.
  - **Gradual volume increase**: If baselines are updated frequently and alert volume increases gradually over weeks, the baseline drifts upward and the anomaly is never detected.
  - **Zero-baseline entities**: Entities with a historical average of 0 alerts per 4 hours technically have infinite z-score for any alert. The `GREATEST(baseline_stddev, 1.0)` floor prevents division by zero but may over- or under-weight these cases.

- **False Positives:**
  - **Scheduled tasks generating batch alerts**: Automated processes (backup jobs, patch deployments, scheduled scans) generate alert bursts at predictable times. Mitigation: compute baselines that account for time-of-day and day-of-week patterns.
  - **Known noisy periods**: Month-end processing, quarterly audits, or marketing campaigns may spike alert volume. Mitigation: maintain a calendar of expected high-volume periods and suppress or adjust z-score thresholds.
  - **Noisy detection rules**: A single misconfigured rule firing rapidly inflates alert count without indicating compromise. Mitigation: combine z-score with rule diversity (`Esql.current_rules >= 2`) for higher confidence.

- **Tuning:**
  1. `volume_zscore` threshold (default: 3.0) -- increase to 4.0 for entities with high baseline variance
  2. `current_count` minimum (default: 5) -- prevents low-baseline entities from triggering on trivial volume
  3. Update baselines weekly using rolling 30-day averages per 4-hour window
  4. Consider separate baselines for business hours vs. off-hours
  5. Add a minimum `current_rules` filter (e.g., >= 2) to require rule diversity, not just volume
  6. For entities with zero baseline, consider a separate "new entity" alert rather than z-score anomaly

## Data Requirements

- **Index**: `.internal.alerts-security.alerts-default`
- **Lookup Index**: `lookup-risk-scores` (fields: `entity`, `baseline_avg_4h_count`, `baseline_stddev`) or `lookup-entity-history` with equivalent fields
- **Required fields**: `user.name`, `host.name`, `event.dataset`, `signal.rule.severity`, `kibana.alert.rule.building_block_type`, `kibana.alert.workflow_status`, `@timestamp`, `kibana.alert.rule.name`, `kibana.alert.rule.threat.tactic.name`, `source.ip`
- **Minimum volume**: Entity baselines populated from 30+ days of alert data with per-4-hour granularity

## Dependencies

- **Required**: `lookup-risk-scores` -- must contain per-entity 4-hour volume baselines (average and standard deviation)
- **Optional**: `lookup-entity-history` as an alternative baseline source

## Validation

1. Identify an entity that normally generates 1-2 alerts per 4-hour window (verify in `lookup-risk-scores`)
2. Generate 15+ alerts for that entity within a 4-hour window (e.g., rapid process execution, multiple failed logins)
3. Verify CORR-6J surfaces the entity with `Esql.volume_zscore >= 3.0` and severity "medium" or higher
4. Confirm that an entity at its normal volume does NOT trigger CORR-6J

## Elastic Comparison

Elastic's ML anomaly detection provides user and host anomaly scoring based on event volume, but operates on raw events (not alerts), uses opaque ML models (not explainable z-scores), and requires ML node infrastructure. CORR-6J provides transparent, deterministic statistical anomaly detection on alert volume with configurable thresholds and human-readable z-scores. The two approaches are complementary: ML for event-level anomalies, CORR-6J for alert-level anomalies.
