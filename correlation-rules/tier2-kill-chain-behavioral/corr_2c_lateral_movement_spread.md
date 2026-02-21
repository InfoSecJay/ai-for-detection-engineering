# Lateral Movement Spread

---

## Metadata

- **Rule ID:** `CORR-2C`
- **Tier:** 2 — Kill Chain and Behavioral Correlation
- **Author:** Detection Engineering
- **Description:** Detect a single user account generating alerts on three or more distinct hosts within a 4-hour window, with additional weighting when alerts include Lateral Movement tactic mappings. This pattern is the hallmark of an attacker moving laterally through the network using compromised credentials.
- **Join Key(s):** `user.name`
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
    AND user.name IS NOT NULL
    AND host.name IS NOT NULL AND host.name != ""
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
    has_latmove_tactic = CASE(
        kibana.alert.rule.parameters.threat.tactic.name == "Lateral Movement", 1, 0
    )
| STATS
    Esql.alert_count = COUNT(*),
    Esql.first_seen = MIN(@timestamp),
    Esql.last_seen = MAX(@timestamp),
    Esql.total_risk = SUM(alert_risk),
    Esql.host_count = COUNT_DISTINCT(host.name),
    Esql.host_values = VALUES(host.name),
    Esql.latmove_alert_count = SUM(has_latmove_tactic),
    Esql.tactic_count = COUNT_DISTINCT(kibana.alert.rule.parameters.threat.tactic.name),
    Esql.tactic_values = VALUES(kibana.alert.rule.parameters.threat.tactic.name),
    Esql.technique_values = VALUES(kibana.alert.rule.threat.technique.name),
    Esql.unique_rules = COUNT_DISTINCT(kibana.alert.rule.name),
    Esql.rule_names = VALUES(kibana.alert.rule.name),
    Esql.domain_count = COUNT_DISTINCT(
        CASE(
            event.dataset LIKE "endpoint*" OR event.dataset LIKE "sentinelone*"
                OR event.dataset LIKE "windows*" OR event.dataset LIKE "sysmon*", "endpoint",
            event.dataset LIKE "okta*" OR event.dataset LIKE "azure_ad*"
                OR event.dataset LIKE "entra*", "identity",
            event.dataset LIKE "aws*" OR event.dataset LIKE "gcp*"
                OR event.dataset LIKE "azure*", "cloud",
            event.dataset LIKE "panw*" OR event.dataset LIKE "fortinet*", "network_fw",
            event.dataset LIKE "extrahop*" OR event.dataset LIKE "zeek*", "network_ndr",
            COALESCE(labels.technology, event.module, "unknown")
        )
    ),
    Esql.ip_values = VALUES(related.ip)
  BY user.name
| WHERE Esql.host_count >= 3
| EVAL
    Esql.risk_score = ROUND(Esql.total_risk * (Esql.host_count / 2)),
    Esql.correlation_severity = CASE(
        Esql.host_count >= 5, "critical",
        Esql.host_count >= 3 AND Esql.latmove_alert_count >= 1, "high",
        Esql.host_count >= 3, "medium",
        "medium"
    ),
    Esql.description = CONCAT(
        "User ", user.name,
        " | Lateral Movement Spread",
        " | ", TO_STRING(Esql.host_count), " distinct hosts",
        " | Risk Score: ", TO_STRING(Esql.risk_score),
        " | Lateral Movement alerts: ", TO_STRING(Esql.latmove_alert_count),
        " | ", TO_STRING(Esql.unique_rules), " rules",
        " | ", TO_STRING(Esql.alert_count), " total alerts",
        " | Window: ", TO_STRING(Esql.first_seen), " to ", TO_STRING(Esql.last_seen)
    )
| SORT Esql.risk_score DESC
| LIMIT 50
```

## Strategy

Alerts are grouped by `user.name`. The query counts distinct `host.name` values per user. Users with alerts spanning 3+ hosts pass filtering. Alerts tagged with the "Lateral Movement" tactic receive additional weighting. The risk score is amplified by `host_count / 2` — a user touching 6 hosts gets a 3x multiplier. The host count threshold of 3 balances detection sensitivity against the false positive rate from users who routinely access multiple systems.

## Severity Logic

```
CASE(
    Esql.host_count >= 5, "critical",
    Esql.host_count >= 3 AND Esql.latmove_alert_count >= 1, "high",
    Esql.host_count >= 3, "medium",
    "medium"
)
```

| Condition | Severity |
|-----------|----------|
| User alerts on 5+ distinct hosts | Critical |
| User alerts on 3+ hosts with at least one Lateral Movement tactic alert | High |
| User alerts on 3+ hosts without Lateral Movement tactic | Medium |

## Notes

- **Blind Spots:**
  - Lateral movement using different accounts per hop (e.g., pass-the-hash to a different local admin on each system) — this rule tracks a single `user.name` across hosts
  - Slow-and-low movement exceeding the 4-hour lookback window — an attacker moving to one new host per day will not trigger
  - Hosts missing `host.name` field (pure network detections without endpoint context)
  - Service accounts excluded — use CORR-1H for service account lateral spread

- **False Positives:**
  - **IT deployment tools**: SCCM, Intune, Ansible pushing software updates to many hosts as the same user. Mitigation: exclude deployment accounts or raise `host_count` threshold for known deployment users.
  - **Patch management systems**: Vulnerability scanners and patching tools running as a single account across many hosts. Mitigation: register in `lookup-service-accounts`.
  - **Helpdesk support**: Remote support staff connecting to multiple workstations. Mitigation: create a helpdesk user group exclusion.

- **Tuning:**
  1. `host_count` threshold (default: 3) — increase to 5 for environments with high legitimate lateral activity (e.g., IT departments)
  2. Lookback window (default: 4h) — extend to 8h for slow lateral movement campaigns
  3. Add a time-gap filter: exclude users who had alerts on the same hosts in the previous 24h (repeat baseline activity)
  4. Risk multiplier (default: `host_count / 2`) — reduce to `host_count / 3` if risk inflation is excessive
  5. Consider an additional hash-based variant (CORR-1E already covers cross-host hash spread)

## Data Requirements

- **Index**: `.internal.alerts-security.alerts-default`
- **Required fields**: `user.name`, `host.name`, `@timestamp`, `signal.rule.severity`, `kibana.alert.workflow_status`, `kibana.alert.rule.building_block_type`, `kibana.alert.rule.name`, `kibana.alert.rule.parameters.threat.tactic.name`, `event.dataset`, `related.ip`
- **Minimum volume**: 3+ alerts on 3+ distinct hosts for same `user.name` within 4h

## Dependencies

- No required lookup indices
- Optional: `lookup-critical-assets` — escalate severity when lateral movement reaches critical assets
- Complementary: CORR-1E (process hash spread) catches lateral movement via binary propagation; CORR-2C catches it via credential reuse

## Validation

Red team scenario:
1. Using the same compromised credentials, execute a suspicious binary (e.g., PsExec, SharpHound) on 4 different hosts within a 2-hour window
2. Each execution should trigger at least one detection rule (Execution or Lateral Movement tactic)

Expected result: User appears with `Esql.host_count = 4`, `Esql.latmove_alert_count >= 1`, severity = high, risk score = `SUM(alert_risk) * 2`.

## Elastic Comparison

Elastic does not ship a user-centric lateral movement spread correlation rule. The "Lateral Movement Detection Alert" rules are individual technique-level detections (PsExec, RDP, WMI), not cross-host aggregations. CORR-2C aggregates across hosts to detect the pattern of spread regardless of which lateral movement technique is used.
