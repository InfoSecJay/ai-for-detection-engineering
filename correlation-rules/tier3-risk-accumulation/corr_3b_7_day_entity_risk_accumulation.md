# 7-Day Entity Risk Accumulation

---

## Metadata

- **Rule ID:** `CORR-3B`
- **Tier:** 3 — Risk Accumulation
- **Author:** Detection Engineering
- **Description:** Detect entities accumulating sustained risk over a 7-day window. Unlike CORR-3A which catches 24-hour risk spikes, this rule catches patient adversaries whose daily risk contribution is too low to trigger CORR-3A but whose weekly accumulation is significant. The additional requirement of alerts on 2+ distinct days ensures this rule fires on sustained activity patterns rather than single-day spikes that CORR-3A already handles.
- **Join Key(s):** `user.name`, `host.name` (separate scores per entity type via COALESCE)
- **Lookback:** 7 days
- **Schedule:** Every 2 hours
- **Priority:** P2
- **Integration:** [alerts](https://www.elastic.co/guide/en/security/current/alerts-ui-manage.html)
- **Language:** `[ES|QL]`

## Query

```esql
FROM .internal.alerts-security.alerts-default
| WHERE @timestamp > NOW() - 7 DAYS
    AND kibana.alert.workflow_status == "open"
    AND (user.name IS NOT NULL OR host.name IS NOT NULL)
| EVAL
    entity_name = COALESCE(user.name, host.name),
    entity_type = CASE(user.name IS NOT NULL, "user", "host"),
    alert_day = DATE_TRUNC(1 day, @timestamp),
    domain_category = CASE(
        event.dataset LIKE "endpoint*" OR event.dataset LIKE "sentinelone*"
            OR event.dataset LIKE "windows*" OR event.dataset LIKE "sysmon*"
            OR event.dataset LIKE "microsoft-defender*" OR event.dataset LIKE "crowdstrike*"
            OR event.dataset LIKE "carbon_black*",
            "endpoint",
        event.dataset LIKE "okta*" OR event.dataset LIKE "azure_ad*"
            OR event.dataset LIKE "entra*" OR event.dataset LIKE "onelogin*"
            OR event.dataset LIKE "ping*" OR event.dataset LIKE "auth0*",
            "identity",
        event.dataset LIKE "aws*" OR event.dataset LIKE "gcp*"
            OR event.dataset LIKE "azure*" OR event.dataset LIKE "cloud*"
            OR event.dataset LIKE "o365*",
            "cloud",
        event.dataset LIKE "panw*" OR event.dataset LIKE "fortinet*"
            OR event.dataset LIKE "firewall*" OR event.dataset LIKE "paloalto*"
            OR event.dataset LIKE "checkpoint*",
            "network_fw",
        event.dataset LIKE "extrahop*" OR event.dataset LIKE "zeek*"
            OR event.dataset LIKE "suricata*" OR event.dataset LIKE "ndr*",
            "network_ndr",
        event.dataset LIKE "proxy*" OR event.dataset LIKE "zscaler*"
            OR event.dataset LIKE "bluecoat*" OR event.dataset LIKE "squid*",
            "proxy",
        event.dataset LIKE "dns*",
            "dns",
        event.dataset LIKE "email*" OR event.dataset LIKE "proofpoint*"
            OR event.dataset LIKE "mimecast*",
            "email",
        COALESCE(labels.technology, event.module, "unknown")
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
    Esql.risk_score_7d = SUM(alert_risk),
    Esql.alert_count = COUNT(*),
    Esql.active_days = COUNT_DISTINCT(alert_day),
    Esql.domain_count = COUNT_DISTINCT(domain_category),
    Esql.domain_values = VALUES(domain_category),
    Esql.rule_count = COUNT_DISTINCT(kibana.alert.rule.name),
    Esql.rule_names = VALUES(kibana.alert.rule.name),
    Esql.max_severity = MAX(severity_weight),
    Esql.severity_values = VALUES(signal.rule.severity),
    Esql.tactic_count = COUNT_DISTINCT(kibana.alert.rule.threat.tactic.name),
    Esql.tactic_values = VALUES(kibana.alert.rule.threat.tactic.name),
    Esql.earliest = MIN(@timestamp),
    Esql.latest = MAX(@timestamp),
    Esql.entity_type = MAX(entity_type)
  BY entity_name
| WHERE Esql.risk_score_7d >= 150
    AND Esql.active_days >= 2
| EVAL
    Esql.correlation_severity = CASE(
        Esql.risk_score_7d >= 500 AND Esql.active_days >= 5, "critical",
        Esql.risk_score_7d >= 300, "high",
        Esql.risk_score_7d >= 150, "medium",
        "low"
    ),
    Esql.avg_daily_risk = ROUND(Esql.risk_score_7d / Esql.active_days),
    Esql.description = CONCAT(
        "7-day risk accumulation for ", Esql.entity_type, " ", entity_name,
        " | 7d Risk: ", TO_STRING(Esql.risk_score_7d),
        " | Active days: ", TO_STRING(Esql.active_days), "/7",
        " | Avg daily risk: ", TO_STRING(ROUND(Esql.risk_score_7d / Esql.active_days)),
        " | ", TO_STRING(Esql.alert_count), " alerts from ",
        TO_STRING(Esql.rule_count), " rules across ",
        TO_STRING(Esql.domain_count), " domains",
        " | ", TO_STRING(Esql.tactic_count), " MITRE tactics",
        " | Window: ", TO_STRING(Esql.earliest), " to ", TO_STRING(Esql.latest)
    )
| SORT Esql.risk_score_7d DESC
| LIMIT 100
```

## Strategy

Same scoring methodology as CORR-3A (severity weights, BBR factor, alert_risk computation) but applied over a 7-day lookback. The critical additional metric is `Esql.active_days = COUNT_DISTINCT(DATE_TRUNC(1 day, @timestamp))` which counts how many distinct calendar days within the 7-day window had alerts for this entity. The dual-threshold requirement (risk >= 150 AND active_days >= 2) filters out single-day alert bursts (which CORR-3A catches) and surfaces only entities with sustained, multi-day risk patterns. The higher risk threshold (150 vs. 50 for CORR-3A) compensates for the longer window to avoid surfacing chronically noisy entities.

## Severity Logic

| Condition | Severity |
|-----------|----------|
| Esql.risk_score_7d >= 500 AND Esql.active_days >= 5 | Critical |
| Esql.risk_score_7d >= 300 | High |
| Esql.risk_score_7d >= 150 | Medium |

The critical threshold requires both high cumulative risk AND sustained activity across 5+ days. A single catastrophic day (500 risk in one day) is handled by CORR-3A; CORR-3B's critical threshold is reserved for entities under prolonged, sustained attack or persistent compromise.

## Notes

- **Blind Spots:**
  - **Low-and-slow attacks**: An adversary generating 20 risk points per day (e.g., two low-severity alerts and one medium building block) accumulates only 140 over 7 days -- below the 150 threshold. This represents the fundamental trade-off between noise reduction and detection sensitivity.
  - **Score decay not modeled**: A high-severity event from 6 days ago carries the same weight as one from 1 hour ago. This can surface stale risk alongside fresh risk. True decay modeling requires either a transform index or more complex EVAL logic that is not practical in a single ES|QL query.
  - **Alert closure before evaluation**: If analysts aggressively close alerts (changing `workflow_status` from `open`), those alerts are excluded from the 7-day accumulation, potentially causing the entity to fall below threshold even though the underlying activity occurred.

- **False Positives:**
  - **Chronically noisy hosts**: Domain controllers, SIEM log collectors, and network appliances that generate daily low-severity alerts from poorly tuned detection rules will chronically exceed the threshold. Mitigation: identify these hosts in the first 2 weeks of operation and either tune the contributing rules, increase the threshold for these entity types, or exclude specific rule IDs from the accumulation.
  - **Long-running IT projects**: Multi-day infrastructure migrations, cloud environment buildouts, and application rollouts generate sustained cross-domain alerts. Mitigation: coordinate with IT operations to create temporary exclusions for known change windows.
  - **Penetration testing engagements**: Multi-day pen tests will trigger this rule by design. Mitigation: add pen test accounts and target hosts to a temporary exclusion list for the engagement duration.

- **Tuning:**
  1. **Threshold of 150** assumes a moderate detection rule set. Environments with 1,000+ detection rules (including many building blocks) may need to increase to 200-300 to manage noise.
  2. **Active days threshold of 2** is the minimum for "sustained activity." Increase to 3 if you want to focus exclusively on multi-day campaigns and accept a wider blind spot for 2-day bursts.
  3. **Exclude specific rule IDs**: If particular detection rules are chronic noise contributors across many entities, consider excluding them from the 7-day accumulation by adding a `NOT kibana.alert.rule.name IN (...)` filter.
  4. **Consider entity type separation**: Host entities typically accumulate more risk than user entities due to endpoint telemetry volume. Running separate host and user variants with different thresholds (e.g., 200 for hosts, 150 for users) may produce more balanced results.

## Data Requirements

- **Index**: `.internal.alerts-security.alerts-default`
- **Required fields**: `@timestamp`, `user.name` or `host.name`, `event.dataset`, `signal.rule.severity`, `kibana.alert.workflow_status`, `kibana.alert.rule.building_block_type`, `kibana.alert.rule.name`, `kibana.alert.rule.threat.tactic.name`
- **Performance note**: A 7-day lookback across a high-volume alerts index may be expensive. Ensure the alerts index has appropriate time-based partitioning and that the ES|QL query runs within the configured timeout. If performance is an issue, consider filtering to only `open` alerts (already done) and adding a minimum severity filter (e.g., excluding informational-only alerts).

## Dependencies

- None required. This rule operates entirely on the alerts index with no lookup joins.
- **Optional**: `lookup-critical-assets` can be added (as in CORR-3A) for criticality weighting. Omitted here to keep the 7-day query lighter, but the LOOKUP JOIN pattern from CORR-3A can be appended after the STATS block.

## Validation

Generate 3 low-severity alerts per day for 5 consecutive days for the same host. Example:
1. Day 1: 3 low-severity endpoint alerts (3 * 3 = 9 risk)
2. Day 2: 3 low-severity identity alerts (3 * 3 = 9 risk)
3. Day 3: 3 low-severity cloud alerts (3 * 3 = 9 risk)
4. Day 4: 2 medium-severity endpoint alerts + 1 low-severity alert (2 * 8 + 3 = 19 risk)
5. Day 5: 3 medium-severity alerts (3 * 8 = 24 risk)
6. Total: 9 + 9 + 9 + 19 + 24 = 70 risk -- below threshold

To actually trigger the rule, increase Day 4 and 5 contributions, or add a few high-severity alerts. The point: this rule requires genuine sustained risk, not easily triggered by accident.

Adjusted validation: 2 high-severity alerts per day for 5 days = 5 * (2 * 15) = 150 risk, active_days = 5. This exactly meets the threshold.

## Elastic Comparison

Elastic's Entity Risk Scoring engine tracks entity risk over time but does not natively expose an "active days" metric or require sustained multi-day activity as a threshold criterion. Splunk's "ATT&CK Tactic Threshold Exceeded for Object Over Previous 7 Days" is the closest industry equivalent, but it thresholds on tactic count rather than cumulative risk score. CORR-3B combines both concepts: cumulative risk scoring over a 7-day window with a sustained-activity requirement that prevents single-day spikes from triggering the rule.
