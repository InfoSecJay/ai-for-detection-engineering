# Risk Velocity Spike

---

## Metadata

- **Rule ID:** `CORR-3C`
- **Tier:** 3 — Risk Accumulation
- **Author:** Detection Engineering
- **Description:** Detect entities whose current risk accumulation rate dramatically exceeds their historical baseline. An entity that normally accumulates 5 risk points per 4-hour window but suddenly accumulates 50 is experiencing a velocity spike -- regardless of whether the absolute score of 50 would trigger CORR-3A on its own. This rule catches the transition from quiet to active, which is often the earliest indicator of compromise. Deploy as two separate Elastic Security rules: one for user risk (Variant A), one for host risk (Variant B).
- **Join Key(s):** `user.name` (Variant A) / `host.name` (Variant B)
- **Lookback:** 4 hours (current window); baseline from `lookup-risk-scores`
- **Schedule:** Every 15 minutes
- **Priority:** P1
- **Integration:** [alerts](https://www.elastic.co/guide/en/security/current/alerts-ui-manage.html)
- **Language:** `[ES|QL]`

## Query

### Variant A: User Risk

```esql
FROM .internal.alerts-security.alerts-default
| WHERE @timestamp > NOW() - 4 HOURS
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
    Esql.current_risk = SUM(alert_risk),
    Esql.alert_count = COUNT(*),
    Esql.host_values = VALUES(host.name),
    Esql.domain_count = COUNT_DISTINCT(domain_category),
    Esql.domain_values = VALUES(domain_category),
    Esql.rule_count = COUNT_DISTINCT(kibana.alert.rule.name),
    Esql.rule_names = VALUES(kibana.alert.rule.name),
    Esql.tactic_count = COUNT_DISTINCT(kibana.alert.rule.threat.tactic.name),
    Esql.tactic_values = VALUES(kibana.alert.rule.threat.tactic.name),
    Esql.earliest = MIN(@timestamp),
    Esql.latest = MAX(@timestamp)
  BY user.name
// --- Required: LOOKUP JOIN for baseline risk comparison ---
// lookup-risk-scores must contain entity_value and rolling_24h_risk fields.
// Without this lookup, velocity calculation is not meaningful.
| RENAME user.name AS entity_value
| LOOKUP JOIN lookup-risk-scores ON entity_value
| RENAME entity_value AS user.name
// --- End LOOKUP JOIN block ---
| EVAL
    baseline_avg_4h = COALESCE(ROUND(rolling_24h_risk / 6), 0),
    Esql.risk_velocity = ROUND(TO_DOUBLE(Esql.current_risk) / TO_DOUBLE(GREATEST(baseline_avg_4h, 1))),
    Esql.baseline_avg_4h = baseline_avg_4h
| WHERE Esql.risk_velocity >= 5.0
    AND Esql.current_risk >= 20
| EVAL
    Esql.correlation_severity = CASE(
        Esql.risk_velocity >= 20, "critical",
        Esql.risk_velocity >= 10, "high",
        Esql.risk_velocity >= 5, "medium",
        "low"
    ),
    Esql.description = CONCAT(
        "Risk velocity spike for user ", user.name,
        " | Current 4h risk: ", TO_STRING(Esql.current_risk),
        " | Baseline avg 4h: ", TO_STRING(Esql.baseline_avg_4h),
        " | Velocity: ", TO_STRING(Esql.risk_velocity), "x baseline",
        " | ", TO_STRING(Esql.alert_count), " alerts from ",
        TO_STRING(Esql.rule_count), " rules across ",
        TO_STRING(Esql.domain_count), " domains",
        " | ", TO_STRING(Esql.tactic_count), " MITRE tactics"
    )
| SORT Esql.risk_velocity DESC
| LIMIT 50
```

### Variant B: Host Risk

```esql
FROM .internal.alerts-security.alerts-default
| WHERE @timestamp > NOW() - 4 HOURS
    AND kibana.alert.workflow_status == "open"
    AND host.name IS NOT NULL AND host.name != ""
| EVAL
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
    Esql.current_risk = SUM(alert_risk),
    Esql.alert_count = COUNT(*),
    Esql.user_values = VALUES(user.name),
    Esql.domain_count = COUNT_DISTINCT(domain_category),
    Esql.domain_values = VALUES(domain_category),
    Esql.rule_count = COUNT_DISTINCT(kibana.alert.rule.name),
    Esql.rule_names = VALUES(kibana.alert.rule.name),
    Esql.tactic_count = COUNT_DISTINCT(kibana.alert.rule.threat.tactic.name),
    Esql.tactic_values = VALUES(kibana.alert.rule.threat.tactic.name),
    Esql.earliest = MIN(@timestamp),
    Esql.latest = MAX(@timestamp)
  BY host.name
// --- Required: LOOKUP JOIN for baseline risk comparison ---
// lookup-risk-scores must contain entity_value and rolling_24h_risk fields.
// Without this lookup, velocity calculation is not meaningful.
| RENAME host.name AS entity_value
| LOOKUP JOIN lookup-risk-scores ON entity_value
| RENAME entity_value AS host.name
// --- End LOOKUP JOIN block ---
| EVAL
    baseline_avg_4h = COALESCE(ROUND(rolling_24h_risk / 6), 0),
    Esql.risk_velocity = ROUND(TO_DOUBLE(Esql.current_risk) / TO_DOUBLE(GREATEST(baseline_avg_4h, 1))),
    Esql.baseline_avg_4h = baseline_avg_4h
| WHERE Esql.risk_velocity >= 5.0
    AND Esql.current_risk >= 20
| EVAL
    Esql.correlation_severity = CASE(
        Esql.risk_velocity >= 20, "critical",
        Esql.risk_velocity >= 10, "high",
        Esql.risk_velocity >= 5, "medium",
        "low"
    ),
    Esql.description = CONCAT(
        "Risk velocity spike for host ", host.name,
        " | Current 4h risk: ", TO_STRING(Esql.current_risk),
        " | Baseline avg 4h: ", TO_STRING(Esql.baseline_avg_4h),
        " | Velocity: ", TO_STRING(Esql.risk_velocity), "x baseline",
        " | ", TO_STRING(Esql.alert_count), " alerts from ",
        TO_STRING(Esql.rule_count), " rules across ",
        TO_STRING(Esql.domain_count), " domains",
        " | ", TO_STRING(Esql.tactic_count), " MITRE tactics"
    )
| SORT Esql.risk_velocity DESC
| LIMIT 50
```

## Strategy

**Dual-Track Entity Scoring.** This rule is deployed as two separate Elastic Security rules -- one scoring by `user.name` (Variant A) and one scoring by `host.name` (Variant B). Velocity detection benefits significantly from entity-type separation because users and hosts have fundamentally different baseline risk profiles. A domain controller's baseline risk is naturally higher than a typical user's baseline, so a unified COALESCE-based approach would either set velocity thresholds too high for users (missing real spikes) or too low for hosts (generating noise). With dual-track scoring, each entity type's velocity is measured against its own baseline in `lookup-risk-scores`.

Computes the current 4-hour risk score for each entity using the standard severity weight and BBR factor model. Then performs a LOOKUP JOIN against `lookup-risk-scores` (using `entity_value` as the join key) to retrieve the entity's historical baseline average 4-hour risk (`rolling_24h_risk` divided by 6 as a proxy for average 4h segments, or a direct `baseline_avg_4h` field if maintained). The RENAME pattern (`user.name` -> `entity_value` -> LOOKUP -> `entity_value` -> `user.name`) bridges the entity field name to the lookup's join key. The risk velocity is computed as `current_risk / GREATEST(baseline_avg_4h, 1)` -- the GREATEST function prevents division by zero for entities with no historical risk. The rule fires when velocity >= 5.0 (5x baseline) AND the absolute current risk meets a minimum threshold of 20 to prevent noise amplification on near-zero baselines (e.g., an entity going from 1 to 5 risk would be 5x velocity but is not meaningful).

The user variant (A) includes service account exclusion filters aligned with the CORR-1A pattern. The host variant (B) omits service account filtering since host names do not follow service account naming patterns. Each variant captures cross-entity context: the user variant records `VALUES(host.name)` to show which hosts the user was active on, and the host variant records `VALUES(user.name)` to show which users were active on the host.

## Severity Logic

| Condition | Severity |
|-----------|----------|
| Esql.risk_velocity >= 20 (20x baseline) | Critical |
| Esql.risk_velocity >= 10 (10x baseline) | High |
| Esql.risk_velocity >= 5 (5x baseline) | Medium |

A 20x velocity spike means an entity that normally generates ~2 risk points per 4 hours is suddenly generating 40+. This is a dramatic behavioral shift that demands immediate attention.

## Notes

- **Tier Integration:** Tier 1 rules (CORR-1A for users, CORR-1B for hosts) provide entity-typed short-window correlation (typically 1-4 hours) that detects immediate multi-signal convergence. These Tier 3 rules provide baseline-relative velocity detection that catches the transition from quiet to active, which complements both the short-window Tier 1 correlations and the absolute-threshold Tier 3 rules (CORR-3A, CORR-3B). The dual-track split at Tier 3 aligns with the entity-typed design already established at Tier 1.

- **Blind Spots:**
  - **New entities with no baseline**: Entities not present in `lookup-risk-scores` will have a `baseline_avg_4h` of 0, which is floored to 1 by the GREATEST function. This means any entity with 20+ current risk and no history will have a velocity of 20+ and trigger as critical. The minimum absolute threshold (current_risk >= 20) prevents trivial new-entity alerts, but new employees or newly provisioned hosts generating moderate alert volume during onboarding will trigger this rule. Consider adding a `last_updated` check from the lookup to filter entities with fewer than 7 days of baseline history.
  - **Gradual escalation that shifts baseline upward**: If an attacker slowly increases their activity over weeks, the rolling baseline in `lookup-risk-scores` will shift upward, and a sudden spike will appear as a smaller velocity multiplier than it should be. This is an inherent limitation of baseline-relative detection.
  - **Baseline staleness**: The `lookup-risk-scores` index must be regularly updated (recommended: daily recalculation). Stale baselines produce inaccurate velocity calculations.
  - **Dual-track overlap**: An alert with both `user.name` and `host.name` populated will contribute risk to both the user variant and the host variant. This is intentional -- a velocity spike may be meaningful from both the user and host perspectives -- but analysts should be aware that a single underlying event may surface in two separate velocity alerts.

- **False Positives:**
  - **First-day employees**: New users generating their first alerts (MFA enrollment, new device registration, initial access to resources) will have no baseline and may trigger as velocity spikes in the user variant. Mitigation: implement a grace period by checking the entity's first appearance date in the lookup.
  - **Systems returning from maintenance**: Hosts that were offline for maintenance or patching, then return to service and generate a burst of alerts as detections fire on accumulated changes. This primarily affects the host variant. Mitigation: correlate with change management data if available, or maintain a maintenance window lookup.
  - **Shift changes in 24/7 environments**: A user whose alerts are concentrated in one shift may appear to spike when they work an unusual shift. The 4-hour window mitigates this somewhat, but shift-related patterns should be monitored during initial tuning.

- **Tuning:**
  1. **Velocity multiplier of 5x** is conservative. Environments with high baseline variance may need to increase to 10x to reduce false positives. Environments with very stable baselines may decrease to 3x for earlier detection. Consider different velocity thresholds for user variant (5x) and host variant (8x) since hosts tend to have higher baseline variance.
  2. **Minimum absolute threshold of 20** prevents noise amplification. Increase to 30 or 40 if the rule generates too many alerts from low-risk entities with zero baselines.
  3. **Baseline calculation method**: The query uses `rolling_24h_risk / 6` as a proxy for average 4-hour risk. If your `lookup-risk-scores` index contains a more precise `baseline_avg_4h` field, substitute it directly.
  4. **New entity handling**: Add an explicit filter for entities with a minimum baseline history (e.g., `AND rolling_7d_risk IS NOT NULL`) to exclude entities with no history. This trades off detection of newly compromised new entities for reduced false positives.
  5. **Service account exclusion tuning**: The user variant's service account filters follow the CORR-1A pattern. If your environment uses additional service account naming conventions not covered by the default list, add them to the `NOT` clause.

## Data Requirements

- **Index**: `.internal.alerts-security.alerts-default`
- **Required fields**: `@timestamp`, `user.name` or `host.name`, `event.dataset`, `signal.rule.severity`, `kibana.alert.workflow_status`, `kibana.alert.rule.building_block_type`, `kibana.alert.rule.name`, `kibana.alert.rule.threat.tactic.name`
- **Lookup index**: `lookup-risk-scores` (with `entity_value` as join key, `rolling_24h_risk` field for baseline calculation). The RENAME pattern bridges `user.name`/`host.name` to `entity_value` for the LOOKUP JOIN and renames back after enrichment.
- **Baseline maintenance**: The `lookup-risk-scores` index must be populated and refreshed by a scheduled transform or pipeline that computes rolling risk averages per entity. This is an infrastructure dependency that must be established before deploying CORR-3C. With dual-track scoring, ensure both user entities and host entities are represented in the lookup with their respective `entity_value` keys.

## Dependencies

- **Required**: `lookup-risk-scores` with populated `rolling_24h_risk` per entity. Without this lookup, the baseline defaults to 0 for all entities and the velocity calculation is meaningless (every entity with 20+ current risk would fire).
- **Recommended**: CORR-3A running in production to provide the 24-hour risk context that feeds into the baseline calculation.

## Validation

Entity with historically 0-5 risk score (baseline_avg_4h ~ 1) suddenly accumulates 50+ in a 4-hour window:
1. Establish a baseline by ensuring the entity has at least 7 days of low-risk history in `lookup-risk-scores` (e.g., `rolling_24h_risk = 6`, giving baseline_avg_4h = 1).
2. Generate 3 high-severity alerts (3 * 15 = 45) and 1 medium alert (8) within 4 hours for the entity. Current risk = 53.
3. Velocity = 53 / 1 = 53x. This would trigger as critical (>= 20x).
4. Verify the rule surfaces this entity with the correct velocity and severity.

## Elastic Comparison

Elastic does not ship a velocity-based risk detection rule. The closest capability is Elastic's ML anomaly detection jobs which can identify sudden changes in entity behavior, but these operate on raw event data rather than on accumulated risk scores. Splunk's RBA does not natively include velocity detection either -- it relies on fixed thresholds. CORR-3C fills a gap that exists across all major SIEM platforms by combining risk accumulation with baseline-relative velocity analysis.
