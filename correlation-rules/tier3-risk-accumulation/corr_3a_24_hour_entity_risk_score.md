# 24-Hour Entity Risk Score

---

## Metadata

- **Rule ID:** `CORR-3A`
- **Tier:** 3 — Risk Accumulation
- **Author:** Detection Engineering
- **Description:** Compute a rolling 24-hour risk score for every entity (user or host) that has generated alerts, enriched with asset criticality from a lookup index. Fire when the accumulated risk crosses severity-tiered thresholds. This is the foundational risk accumulation rule -- the ES|QL equivalent of Splunk's "Risk Threshold Exceeded for Object Over 24 Hour Period." Deploy as two separate Elastic Security rules: one for user risk (Variant A), one for host risk (Variant B).
- **Join Key(s):** `user.name` (Variant A) / `host.name` (Variant B)
- **Lookback:** 24 hours
- **Schedule:** Every 30 minutes
- **Priority:** P1
- **Integration:** [alerts](https://www.elastic.co/guide/en/security/current/alerts-ui-manage.html)
- **Language:** `[ES|QL]`

## Query

### Variant A: User Risk

```esql
FROM .internal.alerts-security.alerts-default
| WHERE @timestamp > NOW() - 24 HOURS
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
    Esql.risk_score_24h = SUM(alert_risk),
    Esql.alert_count = COUNT(*),
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
// --- Optional: LOOKUP JOIN for asset criticality enrichment ---
// If lookup-critical-assets is available, enrich risk with criticality weighting.
// If not available, remove this block — the rule still functions without enrichment.
| RENAME user.name AS entity_name
| LOOKUP JOIN lookup-critical-assets ON entity_name
| RENAME entity_name AS user.name
| EVAL
    criticality_multiplier = CASE(
        asset.criticality == "critical", 1.5,
        asset.criticality == "high", 1.2,
        1.0
    ),
    Esql.risk_score = ROUND(Esql.risk_score_24h * criticality_multiplier),
    Esql.asset_criticality = COALESCE(asset.criticality, "standard")
// --- End optional LOOKUP JOIN block ---
| WHERE Esql.risk_score >= 50
| EVAL
    Esql.correlation_severity = CASE(
        Esql.risk_score >= 200, "critical",
        Esql.risk_score >= 100, "high",
        Esql.risk_score >= 50, "medium",
        "low"
    ),
    Esql.description = CONCAT(
        "24h risk score for user ", user.name,
        " | Risk: ", TO_STRING(Esql.risk_score),
        " (raw: ", TO_STRING(Esql.risk_score_24h),
        ", criticality: ", Esql.asset_criticality, "x", TO_STRING(criticality_multiplier), ")",
        " | ", TO_STRING(Esql.alert_count), " alerts from ",
        TO_STRING(Esql.rule_count), " rules across ",
        TO_STRING(Esql.domain_count), " domains",
        " | Max severity: ", TO_STRING(Esql.max_severity),
        " | ", TO_STRING(Esql.tactic_count), " MITRE tactics",
        " | Window: ", TO_STRING(Esql.earliest), " to ", TO_STRING(Esql.latest)
    )
| SORT Esql.risk_score DESC
| LIMIT 100
```

### Variant B: Host Risk

```esql
FROM .internal.alerts-security.alerts-default
| WHERE @timestamp > NOW() - 24 HOURS
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
    Esql.risk_score_24h = SUM(alert_risk),
    Esql.alert_count = COUNT(*),
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
// --- Optional: LOOKUP JOIN for asset criticality enrichment ---
// If lookup-critical-assets is available, enrich risk with criticality weighting.
// If not available, remove this block — the rule still functions without enrichment.
| RENAME host.name AS entity_name
| LOOKUP JOIN lookup-critical-assets ON entity_name
| RENAME entity_name AS host.name
| EVAL
    criticality_multiplier = CASE(
        asset.criticality == "critical", 1.5,
        asset.criticality == "high", 1.2,
        1.0
    ),
    Esql.risk_score = ROUND(Esql.risk_score_24h * criticality_multiplier),
    Esql.asset_criticality = COALESCE(asset.criticality, "standard")
// --- End optional LOOKUP JOIN block ---
| WHERE Esql.risk_score >= 50
| EVAL
    Esql.correlation_severity = CASE(
        Esql.risk_score >= 200, "critical",
        Esql.risk_score >= 100, "high",
        Esql.risk_score >= 50, "medium",
        "low"
    ),
    Esql.description = CONCAT(
        "24h risk score for host ", host.name,
        " | Risk: ", TO_STRING(Esql.risk_score),
        " (raw: ", TO_STRING(Esql.risk_score_24h),
        ", criticality: ", Esql.asset_criticality, "x", TO_STRING(criticality_multiplier), ")",
        " | ", TO_STRING(Esql.alert_count), " alerts from ",
        TO_STRING(Esql.rule_count), " rules across ",
        TO_STRING(Esql.domain_count), " domains",
        " | Max severity: ", TO_STRING(Esql.max_severity),
        " | ", TO_STRING(Esql.tactic_count), " MITRE tactics",
        " | Window: ", TO_STRING(Esql.earliest), " to ", TO_STRING(Esql.latest)
    )
| SORT Esql.risk_score DESC
| LIMIT 100
```

## Strategy

**Dual-Track Entity Scoring.** This rule is deployed as two separate Elastic Security rules -- one scoring by `user.name` (Variant A) and one scoring by `host.name` (Variant B). Splitting user and host scoring eliminates the ambiguity of `COALESCE(user.name, host.name)`, which forced every alert into a single entity bucket and could conflate a user's identity-layer activity with an unrelated host's endpoint telemetry. With dual-track scoring, a user accumulates risk from all alerts attributed to that user across any host, and a host accumulates risk from all alerts on that host regardless of which user was logged in. Both perspectives are operationally valuable and often complementary: the user track catches identity-centric attack chains (credential theft, lateral movement across hosts), while the host track catches endpoint-centric attack chains (malware execution, persistence, defense evasion on a single system).

Each alert is assigned a severity weight (critical=25, high=15, medium=8, low=3, default=1) and a building block factor (building_block=0.3, standard=1.0). The per-alert risk is `alert_risk = ROUND(severity_weight * bbr_factor)`. The STATS block computes the raw 24-hour risk score, alert count, domain diversity, rule diversity, max severity, and time window. An optional LOOKUP JOIN against `lookup-critical-assets` retrieves the entity's asset criticality tier. A criticality multiplier (critical_asset=1.5, high=1.2, default=1.0) amplifies the risk score for high-value targets. The final `Esql.risk_score` is the criticality-adjusted accumulated risk. Entities with `Esql.risk_score >= 50` surface for analyst review.

The user variant (A) includes service account exclusion filters aligned with the CORR-1A pattern, preventing Windows built-in accounts, machine accounts (trailing `$`), and common service account naming conventions from inflating user risk scores. The host variant (B) does not require service account exclusion since host names do not follow service account naming patterns. Each variant captures cross-entity context: the user variant records `VALUES(host.name)` to show which hosts the user was active on, and the host variant records `VALUES(user.name)` to show which users were active on the host.

## Severity Logic

| Condition | Severity |
|-----------|----------|
| Esql.risk_score >= 200 | Critical |
| Esql.risk_score >= 100 | High |
| Esql.risk_score >= 50 | Medium |

## Notes

- **Tier Integration:** Tier 1 rules (CORR-1A for users, CORR-1B for hosts) provide entity-typed short-window correlation (typically 1-4 hours) that detects immediate multi-signal convergence. These Tier 3 rules provide the longer-window (24-hour) risk accumulation that catches slower, sustained attack patterns that individual short-window correlations miss. The dual-track split at Tier 3 aligns with the entity-typed design already established at Tier 1.

- **Blind Spots:**
  - **Sub-threshold attacks**: Adversaries who deliberately keep each individual alert below detection thresholds, generating fewer than 50 risk points of accumulated activity in a 24-hour window. The threshold is intentionally low (50), but a sufficiently patient attacker generating only 1-2 low-severity alerts per day will not trigger this rule.
  - **Entity name variations**: The same human or system may appear under different `user.name` values across data sources (e.g., `jsmith` in Windows, `john.smith@corp.com` in Okta, `arn:aws:iam::123456:user/john.smith` in AWS). Without identity resolution, risk for the same real entity is split across multiple computed entity names and may not cross the threshold for any single name.
  - **Closed/acknowledged alerts**: Only `open` workflow status alerts contribute. If analysts close alerts as they arrive (before the 24h window is fully evaluated), the accumulated risk score is artificially reduced.
  - **Dual-track overlap**: An alert with both `user.name` and `host.name` populated will contribute risk to both the user variant and the host variant. This is intentional -- the same activity is relevant from both perspectives -- but analysts should be aware that a single underlying event may surface in two separate correlation alerts.

- **False Positives:**
  - **Noisy detection rules inflating scores**: A single poorly tuned rule firing 20 times for the same entity in 24 hours can push a benign entity above the threshold. Monitor which rules contribute the most risk via `Esql.rule_names` and tune or convert them to building blocks.
  - **Legitimate IT administrator activity**: Admins performing mass operations (patching, deployments, user provisioning) routinely generate cross-domain alerts. Mitigation: register high-activity admin accounts in a lookup and apply elevated thresholds, or tag them in `lookup-critical-assets` with an operational role that informs threshold adjustment.
  - **Scheduled automation**: The user variant's service account exclusion filters handle most automation noise. For the host variant, backup jobs, SCCM deployments, and orchestration tools can still accumulate risk. Mitigation: monitor `Esql.user_values` in the host variant to identify whether automation accounts are the primary contributors.

- **Tuning:**
  1. **Risk threshold of 50** is a starting point. Run the rule for 2 weeks and review the volume. If generating more than 20 alerts per day, increase to 75 or 100. If generating fewer than 2 per day, the threshold is appropriate or may even be lowered. Consider different thresholds for the user variant (50) and host variant (75) since hosts tend to accumulate more endpoint telemetry noise.
  2. **Criticality multiplier** values (1.5 for critical, 1.2 for high) should be validated against your organization's asset inventory. Some environments may need a 2.0 multiplier for domain controllers and certificate authorities.
  3. **Severity weight calibration**: If your detection rule set is heavily skewed toward medium-severity rules, the medium weight of 8 may need adjustment to prevent threshold inflation.
  4. **Building block factor**: The 0.3 factor assumes BBRs are low-fidelity. If your building blocks are well-curated and high-quality, consider raising to 0.5.
  5. **Service account exclusion tuning**: The user variant's service account filters follow the CORR-1A pattern. If your environment uses additional service account naming conventions not covered by the default list, add them to the `NOT` clause.

## Data Requirements

- **Index**: `.internal.alerts-security.alerts-default`
- **Required fields**: `@timestamp`, `user.name` or `host.name`, `event.dataset`, `signal.rule.severity`, `kibana.alert.workflow_status`, `kibana.alert.rule.building_block_type`, `kibana.alert.rule.name`, `kibana.alert.rule.threat.tactic.name`
- **Lookup index**: `lookup-critical-assets` (with `entity_name` as join key, `asset.criticality` field)
- **Minimum volume**: Any entity with 50+ accumulated risk points in a 24h window (e.g., 2 high-severity standard alerts = 30 risk, plus 3 medium building blocks = ROUND(8*0.3)*3 = 6 risk = 36 total -- would not fire; but 4 high-severity alerts = 60 risk -- fires)

## Dependencies

- **Required**: `lookup-critical-assets` for asset criticality enrichment. Without this lookup, the LOOKUP JOIN returns NULL for `asset.criticality` and the criticality multiplier defaults to 1.0, which means the rule still functions but without criticality weighting.
- **Recommended**: Building block detection rules contributing low-fidelity signals that accumulate into meaningful risk.

## Validation

Generate a mix of 5+ low and medium-severity alerts for the same user over a 12-hour period to exceed the threshold of 50. Example scenario:
1. Trigger 2 medium-severity endpoint alerts (2 * 8 = 16)
2. Trigger 1 high-severity identity alert (15)
3. Trigger 3 low-severity cloud building block alerts (3 * ROUND(3 * 0.3) = 3 * 1 = 3)
4. Trigger 2 medium-severity network alerts (2 * 8 = 16)
5. Total: 16 + 15 + 3 + 16 = 50 -- exactly at threshold

If the entity is in `lookup-critical-assets` with `asset.criticality = "critical"`, the score becomes ROUND(50 * 1.5) = 75, which crosses the medium threshold comfortably and approaches high.

## Elastic Comparison

Elastic's Entity Risk Scoring (Entity Analytics) provides a similar capability through a built-in risk engine that aggregates detection alert risk scores per entity. However, Elastic's implementation operates as a background transform rather than a configurable detection rule. CORR-3A provides several advantages: explicit control over severity weights and BBR factors, LOOKUP JOIN for asset criticality weighting, configurable thresholds with dynamic severity assignment, and full visibility into the scoring logic. The trade-off is operational maintenance -- you own the scoring logic rather than relying on the platform's built-in engine.
