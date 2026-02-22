# 7-Day Entity Risk Accumulation

---

## Metadata

- **Rule ID:** `CORR-3B`
- **Tier:** 3 — Risk Accumulation
- **Author:** Detection Engineering
- **Description:** Detect entities accumulating sustained risk over a 7-day window. Unlike CORR-3A which catches 24-hour risk spikes, this rule catches patient adversaries whose daily risk contribution is too low to trigger CORR-3A but whose weekly accumulation is significant. The additional requirement of alerts on 2+ distinct days ensures this rule fires on sustained activity patterns rather than single-day spikes that CORR-3A already handles. Deploy as two separate Elastic Security rules: one for user risk (Variant A), one for host risk (Variant B).
- **Join Key(s):** `user.name` (Variant A) / `host.name` (Variant B)
- **Lookback:** 7 days
- **Schedule:** Every 2 hours
- **Priority:** P2
- **Integration:** [alerts](https://www.elastic.co/guide/en/security/current/alerts-ui-manage.html)
- **Language:** `[ES|QL]`

## Query

### Variant A: User Risk

```esql
FROM .internal.alerts-security.alerts-default
| WHERE @timestamp > NOW() - 7 DAYS
    AND kibana.alert.workflow_status == "open"
    AND user.name IS NOT NULL
    AND NOT user.name IN ("SYSTEM", "Administrator", "LOCAL SERVICE", "NETWORK SERVICE",
        "DWM-1", "DWM-2", "DWM-3", "UMFD-0", "UMFD-1", "UMFD-2",
        "DefaultAccount", "Guest", "WDAGUtilityAccount")
    AND NOT (
        user.name LIKE "*$"
        OR user.name LIKE "svc-*" OR user.name LIKE "svc_*" OR user.name LIKE "svc.*"
        OR user.name LIKE "*-svc" OR user.name LIKE "*_svc"
        OR user.name LIKE "service-*" OR user.name LIKE "service_*"
        OR user.name LIKE "sa-*" OR user.name LIKE "sa_*"
        OR user.name LIKE "app-*" OR user.name LIKE "app_*"
        OR user.name LIKE "api-*" OR user.name LIKE "api_*"
        OR user.name LIKE "bot-*" OR user.name LIKE "bot_*"
        OR user.name LIKE "task-*" OR user.name LIKE "task_*"
        OR user.name LIKE "cron-*" OR user.name LIKE "cron_*"
        OR user.name LIKE "MSOL_*" OR user.name LIKE "HealthMail*"
        OR user.name LIKE "SM_*" OR user.name LIKE "AAD_*"
        OR user.name LIKE "Sync_*" OR user.name LIKE "ADSync*"
        OR user.name LIKE "noreply*" OR user.name LIKE "no-reply*"
        OR user.name LIKE "mailbox-*" OR user.name LIKE "shared-*"
    )
| EVAL
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
    Esql.host_values = VALUES(host.name),
    Esql.domain_count = COUNT_DISTINCT(domain_category),
    Esql.domain_values = VALUES(domain_category),
    Esql.rule_count = COUNT_DISTINCT(kibana.alert.rule.name),
    Esql.rule_names = VALUES(kibana.alert.rule.name),
    Esql.max_severity = MAX(severity_weight),
    Esql.severity_values = VALUES(signal.rule.severity),
    Esql.tactic_count = COUNT_DISTINCT(kibana.alert.rule.threat.tactic.name),
    Esql.tactic_values = VALUES(kibana.alert.rule.threat.tactic.name),
    Esql.earliest = MIN(@timestamp),
    Esql.latest = MAX(@timestamp)
  BY user.name
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
        "7-day risk accumulation for user ", user.name,
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

### Variant B: Host Risk

```esql
FROM .internal.alerts-security.alerts-default
| WHERE @timestamp > NOW() - 7 DAYS
    AND kibana.alert.workflow_status == "open"
    AND host.name IS NOT NULL AND host.name != ""
| EVAL
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
    Esql.user_values = VALUES(user.name),
    Esql.domain_count = COUNT_DISTINCT(domain_category),
    Esql.domain_values = VALUES(domain_category),
    Esql.rule_count = COUNT_DISTINCT(kibana.alert.rule.name),
    Esql.rule_names = VALUES(kibana.alert.rule.name),
    Esql.max_severity = MAX(severity_weight),
    Esql.severity_values = VALUES(signal.rule.severity),
    Esql.tactic_count = COUNT_DISTINCT(kibana.alert.rule.threat.tactic.name),
    Esql.tactic_values = VALUES(kibana.alert.rule.threat.tactic.name),
    Esql.earliest = MIN(@timestamp),
    Esql.latest = MAX(@timestamp)
  BY host.name
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
        "7-day risk accumulation for host ", host.name,
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

**Dual-Track Entity Scoring.** Like CORR-3A, this rule is deployed as two separate Elastic Security rules -- one scoring by `user.name` (Variant A) and one scoring by `host.name` (Variant B). Splitting user and host scoring over the 7-day window is especially important because the longer lookback amplifies the divergence between user-centric and host-centric risk profiles. A shared workstation used by multiple users will accumulate host risk from all users combined, which is the correct host-centric view, while each individual user's 7-day risk is tracked independently to catch identity-layer patterns like slow credential abuse or gradual privilege escalation.

Same scoring methodology as CORR-3A (severity weights, BBR factor, alert_risk computation) but applied over a 7-day lookback. The critical additional metric is `Esql.active_days = COUNT_DISTINCT(DATE_TRUNC(1 day, @timestamp))` which counts how many distinct calendar days within the 7-day window had alerts for this entity. The dual-threshold requirement (risk >= 150 AND active_days >= 2) filters out single-day alert bursts (which CORR-3A catches) and surfaces only entities with sustained, multi-day risk patterns. The higher risk threshold (150 vs. 50 for CORR-3A) compensates for the longer window to avoid surfacing chronically noisy entities.

The user variant (A) includes service account exclusion filters aligned with the CORR-1A pattern. The host variant (B) omits service account filtering since host names do not follow service account naming patterns. Each variant captures cross-entity context: the user variant records `VALUES(host.name)` to show which hosts the user was active on, and the host variant records `VALUES(user.name)` to show which users were active on the host.

## Severity Logic

| Condition | Severity |
|-----------|----------|
| Esql.risk_score_7d >= 500 AND Esql.active_days >= 5 | Critical |
| Esql.risk_score_7d >= 300 | High |
| Esql.risk_score_7d >= 150 | Medium |

The critical threshold requires both high cumulative risk AND sustained activity across 5+ days. A single catastrophic day (500 risk in one day) is handled by CORR-3A; CORR-3B's critical threshold is reserved for entities under prolonged, sustained attack or persistent compromise.

## Notes

- **Tier Integration:** Tier 1 rules (CORR-1A for users, CORR-1B for hosts) provide entity-typed short-window correlation (typically 1-4 hours) that detects immediate multi-signal convergence. These Tier 3 rules provide the longer-window (7-day) risk accumulation that catches patient, sustained attack patterns that neither short-window correlations nor 24-hour risk scoring (CORR-3A) can detect. The dual-track split at Tier 3 aligns with the entity-typed design already established at Tier 1.

- **Blind Spots:**
  - **Low-and-slow attacks**: An adversary generating 20 risk points per day (e.g., two low-severity alerts and one medium building block) accumulates only 140 over 7 days -- below the 150 threshold. This represents the fundamental trade-off between noise reduction and detection sensitivity.
  - **Score decay not modeled**: A high-severity event from 6 days ago carries the same weight as one from 1 hour ago. This can surface stale risk alongside fresh risk. True decay modeling requires either a transform index or more complex EVAL logic that is not practical in a single ES|QL query.
  - **Alert closure before evaluation**: If analysts aggressively close alerts (changing `workflow_status` from `open`), those alerts are excluded from the 7-day accumulation, potentially causing the entity to fall below threshold even though the underlying activity occurred.
  - **Dual-track overlap**: An alert with both `user.name` and `host.name` populated will contribute risk to both the user variant and the host variant. This is intentional -- the same activity is relevant from both perspectives -- but analysts should be aware that a single underlying event may surface in two separate correlation alerts.

- **False Positives:**
  - **Chronically noisy hosts**: Domain controllers, SIEM log collectors, and network appliances that generate daily low-severity alerts from poorly tuned detection rules will chronically exceed the host variant threshold. Mitigation: identify these hosts in the first 2 weeks of operation and either tune the contributing rules, increase the threshold for the host variant, or exclude specific rule IDs from the accumulation.
  - **Long-running IT projects**: Multi-day infrastructure migrations, cloud environment buildouts, and application rollouts generate sustained cross-domain alerts. Mitigation: coordinate with IT operations to create temporary exclusions for known change windows.
  - **Penetration testing engagements**: Multi-day pen tests will trigger this rule by design. Mitigation: add pen test accounts and target hosts to a temporary exclusion list for the engagement duration.

- **Tuning:**
  1. **Threshold of 150** assumes a moderate detection rule set. Environments with 1,000+ detection rules (including many building blocks) may need to increase to 200-300 to manage noise. Consider different thresholds for the user variant (150) and host variant (200) since hosts tend to accumulate more endpoint telemetry noise over 7 days.
  2. **Active days threshold of 2** is the minimum for "sustained activity." Increase to 3 if you want to focus exclusively on multi-day campaigns and accept a wider blind spot for 2-day bursts.
  3. **Exclude specific rule IDs**: If particular detection rules are chronic noise contributors across many entities, consider excluding them from the 7-day accumulation by adding a `NOT kibana.alert.rule.name IN (...)` filter.
  4. **Service account exclusion tuning**: The user variant's service account filters follow the CORR-1A pattern. If your environment uses additional service account naming conventions not covered by the default list, add them to the `NOT` clause.

## Data Requirements

- **Index**: `.internal.alerts-security.alerts-default`
- **Required fields**: `@timestamp`, `user.name` or `host.name`, `event.dataset`, `signal.rule.severity`, `kibana.alert.workflow_status`, `kibana.alert.rule.building_block_type`, `kibana.alert.rule.name`, `kibana.alert.rule.threat.tactic.name`
- **Performance note**: A 7-day lookback across a high-volume alerts index may be expensive. Ensure the alerts index has appropriate time-based partitioning and that the ES|QL query runs within the configured timeout. If performance is an issue, consider filtering to only `open` alerts (already done) and adding a minimum severity filter (e.g., excluding informational-only alerts).

## Dependencies

- None required. This rule operates entirely on the alerts index with no lookup joins.
- **Optional**: `lookup-critical-assets` can be added (as in CORR-3A) for criticality weighting. Omitted here to keep the 7-day query lighter, but the LOOKUP JOIN pattern from CORR-3A can be appended after the STATS block using the RENAME pattern: `| RENAME user.name AS entity_name | LOOKUP JOIN lookup-critical-assets ON entity_name | RENAME entity_name AS user.name` (for Variant A) or `| RENAME host.name AS entity_name | LOOKUP JOIN lookup-critical-assets ON entity_name | RENAME entity_name AS host.name` (for Variant B).

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
