# Privilege Escalation Chain

---

## Metadata

- **Rule ID:** `CORR-2D`
- **Tier:** 2 — Kill Chain and Behavioral Correlation
- **Author:** Detection Engineering
- **Description:** Detect users who initially generate alerts in a non-admin context and subsequently generate alerts in an elevated/admin context within a 4-hour window. This sequence — low-privilege alert followed by high-privilege alert — indicates successful privilege escalation.
- **Join Key(s):** `user.name`
- **Lookback:** 4 hours
- **Schedule:** Every 15 minutes
- **Priority:** P1
- **Integration:** [alerts](https://www.elastic.co/guide/en/security/current/alerts-ui-manage.html)
- **Language:** `[ES|QL]`

## Query

```esql
FROM .internal.alerts-security.alerts-default
| WHERE @timestamp > NOW() - 4 HOURS
    AND kibana.alert.workflow_status == "open"
    AND user.name IS NOT NULL
    AND NOT user.name IN ("SYSTEM", "Administrator", "LOCAL SERVICE", "NETWORK SERVICE",
        "DWM-1", "DWM-2", "DWM-3", "UMFD-0", "UMFD-1", "UMFD-2",
        "DefaultAccount", "Guest", "WDAGUtilityAccount")
    AND NOT (
        user.name LIKE "svc-*" OR user.name LIKE "svc_*"
        OR user.name LIKE "app-*" OR user.name LIKE "sa-*"
        OR user.name LIKE "*$" OR user.name LIKE "MSOL_*"
        OR user.name LIKE "HealthMail*" OR user.name LIKE "SM_*"
    )
| EVAL
    severity_weight = CASE(
        signal.rule.severity == "critical", 25,
        signal.rule.severity == "high", 15,
        signal.rule.severity == "medium", 8,
        signal.rule.severity == "low", 3, 1
    ),
    bbr_factor = CASE(kibana.alert.rule.building_block_type == "default", 0.3, 1.0),
    alert_risk = ROUND(severity_weight * bbr_factor),
    is_admin_context = CASE(
        kibana.alert.rule.threat.tactic.name == "Privilege Escalation", 1,
        kibana.alert.rule.name LIKE "*privilege*escalation*", 1,
        kibana.alert.rule.name LIKE "*admin*", 1,
        kibana.alert.rule.name LIKE "*UAC*bypass*", 1,
        kibana.alert.rule.name LIKE "*sudo*", 1,
        kibana.alert.rule.name LIKE "*root*", 1,
        kibana.alert.rule.name LIKE "*SYSTEM*", 1,
        process.name IN ("runas.exe", "sudo", "doas", "pkexec"), 1,
        0
    ),
    is_non_admin = CASE(is_admin_context == 0, 1, 0),
    admin_ts = CASE(is_admin_context == 1, @timestamp, NULL),
    non_admin_ts = CASE(is_non_admin == 1, @timestamp, NULL),
    is_critical_alert = CASE(
        signal.rule.severity == "critical"
        AND kibana.alert.rule.building_block_type IS NULL, 1, 0
    ),
    is_high_alert = CASE(
        signal.rule.severity == "high"
        AND kibana.alert.rule.building_block_type IS NULL, 1, 0
    )
| STATS
    Esql.alert_count = COUNT(*),
    Esql.first_seen = MIN(@timestamp),
    Esql.last_seen = MAX(@timestamp),
    Esql.total_risk_score = SUM(alert_risk),
    Esql.admin_alert_count = SUM(is_admin_context),
    Esql.non_admin_alert_count = SUM(is_non_admin),
    Esql.earliest_admin = MIN(admin_ts),
    Esql.earliest_non_admin = MIN(non_admin_ts),
    Esql.critical_count = SUM(is_critical_alert),
    Esql.high_count = SUM(is_high_alert),
    Esql.tactic_count = COUNT_DISTINCT(kibana.alert.rule.threat.tactic.name),
    Esql.tactic_values = VALUES(kibana.alert.rule.threat.tactic.name),
    Esql.unique_rules = COUNT_DISTINCT(kibana.alert.rule.name),
    Esql.rule_names = VALUES(kibana.alert.rule.name),
    Esql.host_values = VALUES(host.name),
    Esql.host_count = COUNT_DISTINCT(host.name),
    Esql.ip_values = VALUES(related.ip)
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
    Esql.total_risk_score = ROUND(Esql.total_risk_score * criticality_multiplier),
    Esql.asset_criticality = COALESCE(asset.criticality, "standard")
// --- End optional LOOKUP JOIN block ---
| WHERE Esql.admin_alert_count >= 1
    AND Esql.non_admin_alert_count >= 1
    AND Esql.earliest_admin > Esql.earliest_non_admin
| EVAL
    Esql.risk_score = ROUND(Esql.total_risk_score * 2.0),
    Esql.escalation_gap_minutes = ROUND(DATE_DIFF("minutes", Esql.earliest_non_admin, Esql.earliest_admin)),
    Esql.correlation_severity = CASE(
        Esql.critical_count >= 1, "critical",
        Esql.high_count >= 1, "high",
        "medium"
    ),
    Esql.description = CONCAT(
        "User ", user.name,
        " | Privilege Escalation Chain",
        " | Risk Score: ", TO_STRING(Esql.risk_score),
        " | Non-admin alerts: ", TO_STRING(Esql.non_admin_alert_count),
        " | Admin-context alerts: ", TO_STRING(Esql.admin_alert_count),
        " | Escalation gap: ", TO_STRING(Esql.escalation_gap_minutes), " min",
        " | ", TO_STRING(Esql.host_count), " hosts",
        " | ", TO_STRING(Esql.unique_rules), " rules"
    )
| SORT Esql.risk_score DESC
| LIMIT 50
```

## Strategy

Each alert is evaluated for indicators of admin/elevated context: user roles containing "admin", processes commonly used for administration (e.g., `powershell.exe` with admin-context rule names), or Windows SIDs ending in `-500` (local Administrator). INLINE STATS computes the earliest timestamp for non-admin alerts and the earliest timestamp for admin-context alerts per user. The rule filters for users where the admin-context alert occurs after the non-admin alert. A 2.0x risk multiplier is applied because confirmed privilege escalation is a high-severity progression. An optional LOOKUP JOIN against `lookup-critical-assets` applies a criticality multiplier to amplify risk for high-value assets. Remove this block if the lookup is unavailable.

## Severity Logic

```
CASE(
    Esql.critical_count >= 1, "critical",    -- Priv esc chain with critical-severity alert
    Esql.high_count >= 1, "high",            -- Priv esc chain with high-severity alert
    "medium"                                  -- Confirmed priv esc, lower-severity alerts
)
```

| Condition | Severity |
|-----------|----------|
| Confirmed privilege escalation chain AND at least one critical-severity alert | Critical |
| Confirmed privilege escalation chain AND at least one high-severity alert | High |
| Confirmed privilege escalation chain, all medium or lower severity | Medium |

## Notes

- **Blind Spots:**
  - Pre-existing admin accounts — users who are already domain admins will not exhibit the low-to-high context shift; all their alerts appear as "admin context" from the start
  - Service accounts with elevated privileges by design — excluded by the service account filter, but monitored separately in CORR-1H
  - Privilege escalation via OS exploit that does not generate an admin-context alert (e.g., kernel exploits that silently elevate)
  - Alerts without sufficient metadata to determine admin vs. non-admin context

- **False Positives:**
  - **Approved privilege requests (PIM/PAM)**: Users legitimately requesting temporary admin access through Azure PIM or CyberArk, then performing admin tasks. Mitigation: correlate with PIM/PAM approval logs via lookup.
  - **Developers using sudo legitimately**: Developer triggers a low-severity alert, then uses `sudo` for package installation. Mitigation: tune the `is_admin_context` patterns to exclude known benign sudo usage.
  - **Scheduled maintenance windows**: Admin performs routine tasks that escalate privilege level. Mitigation: suppress during documented maintenance windows.

- **Tuning:**
  1. Refine `is_admin_context` detection patterns based on your environment's rule naming conventions
  2. Add Windows Security Event 4672 (Special Privileges Assigned to New Logon) as an additional admin indicator if available in alert metadata
  3. Escalation gap filter — add `AND Esql.escalation_gap_minutes <= 120` for fast escalation detection
  4. Risk multiplier (default: 2.0) — reduce to 1.5 if false positive rate is high
  5. Consider adding a LOOKUP JOIN to `lookup-critical-assets` to escalate severity when the target host is in production/PCI scope

## Data Requirements

- **Index**: `.internal.alerts-security.alerts-default`
- **Required fields**: `user.name`, `@timestamp`, `signal.rule.severity`, `kibana.alert.workflow_status`, `kibana.alert.rule.building_block_type`, `kibana.alert.rule.name`, `kibana.alert.rule.threat.tactic.name`, `process.name`, `host.name`, `related.ip`
- **Minimum volume**: 1+ non-admin-context alert AND 1+ admin-context alert for same `user.name` within 4h

## Dependencies

- No required lookup indices
- **Optional**: `lookup-critical-assets` — applies criticality multiplier to risk scores. If unavailable, remove the LOOKUP JOIN block from the query.
- Optional: PIM/PAM integration via lookup index to suppress approved privilege requests

## Validation

Red team scenario:
1. Generate a low-privilege alert for a test user (e.g., suspicious process execution as standard user)
2. Escalate to local admin via a known technique (e.g., UAC bypass, token manipulation, PrintSpoofer)
3. Perform an admin-context action that triggers a high-severity alert (e.g., dump credentials with elevated privileges)

Expected result: User appears with `Esql.earliest_admin > Esql.earliest_non_admin`, `Esql.risk_score = SUM(alert_risk) * 2.0`, severity = high or critical.

## Elastic Comparison

Elastic ships individual privilege escalation detection rules (UAC bypass, Token Manipulation, etc.) but does not ship a correlation rule that detects the transition from non-admin to admin context across multiple alerts. CORR-2D adds the sequential context — it does not detect the escalation technique itself but rather the before/after pattern that confirms privilege escalation succeeded.
