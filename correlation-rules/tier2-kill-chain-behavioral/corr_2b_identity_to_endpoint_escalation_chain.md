# Identity-to-Endpoint Escalation Chain

---

## Metadata

- **Rule ID:** `CORR-2B`
- **Tier:** 2 — Kill Chain and Behavioral Correlation
- **Author:** Detection Engineering
- **Description:** Detect users who generate alerts in both the identity domain (IdP/SSO — Okta, Entra ID, etc.) AND the endpoint domain (EDR/Sysmon/Windows events) within a 4-hour window, where the identity alert precedes the endpoint alert. This pattern indicates a compromised credential being used to authenticate, followed by malicious activity on the endpoint — the canonical credential-theft-to-compromise chain.
- **Join Key(s):** `user.name` (cross-domain)
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
            OR event.dataset LIKE "azure*" OR event.dataset LIKE "o365*",
            "cloud",
        event.dataset LIKE "panw*" OR event.dataset LIKE "fortinet*"
            OR event.dataset LIKE "firewall*", "network_fw",
        event.dataset LIKE "extrahop*" OR event.dataset LIKE "zeek*"
            OR event.dataset LIKE "suricata*", "network_ndr",
        event.dataset LIKE "proxy*" OR event.dataset LIKE "zscaler*", "proxy",
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
    alert_risk = ROUND(severity_weight * bbr_factor),
    is_identity = CASE(domain_category == "identity", 1, 0),
    is_endpoint = CASE(domain_category == "endpoint", 1, 0),
    identity_ts = CASE(domain_category == "identity", @timestamp, NULL),
    endpoint_ts = CASE(domain_category == "endpoint", @timestamp, NULL),
    is_identity_high_plus = CASE(
        domain_category == "identity" AND signal.rule.severity IN ("critical", "high"), 1, 0
    ),
    is_endpoint_high_plus = CASE(
        domain_category == "endpoint" AND signal.rule.severity IN ("critical", "high"), 1, 0
    )
| STATS
    Esql.alert_count = COUNT(*),
    Esql.first_seen = MIN(@timestamp),
    Esql.last_seen = MAX(@timestamp),
    Esql.total_risk = SUM(alert_risk),
    Esql.identity_alert_count = SUM(is_identity),
    Esql.endpoint_alert_count = SUM(is_endpoint),
    Esql.earliest_identity = MIN(identity_ts),
    Esql.earliest_endpoint = MIN(endpoint_ts),
    Esql.identity_high_plus = MAX(is_identity_high_plus),
    Esql.endpoint_high_plus = MAX(is_endpoint_high_plus),
    Esql.tactic_count = COUNT_DISTINCT(kibana.alert.rule.parameters.threat.tactic.name),
    Esql.tactic_values = VALUES(kibana.alert.rule.parameters.threat.tactic.name),
    Esql.unique_rules = COUNT_DISTINCT(kibana.alert.rule.name),
    Esql.rule_names = VALUES(kibana.alert.rule.name),
    Esql.domain_count = COUNT_DISTINCT(domain_category),
    Esql.domain_values = VALUES(domain_category),
    Esql.host_values = VALUES(host.name),
    Esql.host_count = COUNT_DISTINCT(host.name),
    Esql.ip_values = VALUES(related.ip)
  BY user.name
| WHERE Esql.identity_alert_count >= 1
    AND Esql.endpoint_alert_count >= 1
    AND Esql.earliest_identity <= Esql.earliest_endpoint
| EVAL
    Esql.risk_score = ROUND(Esql.total_risk * 1.5),
    Esql.escalation_gap_minutes = ROUND(DATE_DIFF("minutes", Esql.earliest_identity, Esql.earliest_endpoint)),
    Esql.correlation_severity = CASE(
        Esql.identity_high_plus == 1 AND Esql.endpoint_high_plus == 1, "critical",
        Esql.identity_high_plus == 1, "high",
        Esql.endpoint_high_plus == 1, "high",
        "medium"
    ),
    Esql.description = CONCAT(
        "User ", user.name,
        " | Identity-to-Endpoint Escalation",
        " | Risk Score: ", TO_STRING(Esql.risk_score),
        " | Identity alerts: ", TO_STRING(Esql.identity_alert_count),
        " | Endpoint alerts: ", TO_STRING(Esql.endpoint_alert_count),
        " | Escalation gap: ", TO_STRING(Esql.escalation_gap_minutes), " min",
        " | ", TO_STRING(Esql.host_count), " hosts",
        " | ", TO_STRING(Esql.unique_rules), " rules",
        " | Window: ", TO_STRING(Esql.first_seen), " to ", TO_STRING(Esql.last_seen)
    )
| SORT Esql.risk_score DESC
| LIMIT 50
```

## Strategy

All alerts for a user are domain-categorized. INLINE STATS computes per-domain alert counts and earliest timestamps for each user. The rule filters for users who have at least one identity-domain alert AND at least one endpoint-domain alert, AND where the identity alert timestamp precedes the endpoint alert timestamp. A 1.5x cross-domain bonus is applied to the risk score because identity-to-endpoint escalation crosses fundamentally different detection surfaces.

## Severity Logic

```
CASE(
    Esql.identity_high_plus == 1 AND Esql.endpoint_high_plus == 1, "critical",
    Esql.identity_high_plus == 1, "high",
    Esql.endpoint_high_plus == 1, "high",
    "medium"
)
```

| Condition | Severity |
|-----------|----------|
| Both identity AND endpoint alerts are high or critical severity | Critical |
| Identity alert is high+ severity, endpoint any severity | High |
| Endpoint alert is high+ severity, identity any severity | High |
| Both domains present, neither high+ | Medium |

## Notes

- **Blind Spots:**
  - Different usernames between IdP and endpoint (e.g., `john.doe@corp.com` in Okta vs. `CORP\jdoe` on endpoint) — username normalization must happen upstream or in a lookup
  - Time gaps exceeding 4 hours between the identity anomaly and subsequent endpoint activity
  - Endpoint alerts that fire before the identity alert (reversed temporal order is filtered out — but the attacker may already have been on the endpoint before the identity anomaly was detected)
  - Cloud-managed devices where endpoint telemetry uses a different user identifier than the IdP

- **False Positives:**
  - **Helpdesk users**: Legitimate password resets (identity alert) followed by remote support tool usage on endpoints (endpoint alert). Mitigation: exclude known helpdesk accounts or tag in lookup.
  - **New employee onboarding**: First-time MFA enrollment (identity alert) plus initial software installation (endpoint alert). Mitigation: correlate with HR onboarding dates.
  - **VPN + endpoint management**: VPN authentication anomaly (identity) followed by routine endpoint management activity. Mitigation: tune identity rule sensitivity for VPN-related alerts.

- **Tuning:**
  1. Escalation gap threshold — add `AND Esql.escalation_gap_minutes <= 120` to focus on rapid escalation chains
  2. Remove temporal ordering constraint (`Esql.earliest_identity <= Esql.earliest_endpoint`) if you want bidirectional detection
  3. Add `AND Esql.host_count >= 1` to require endpoint activity to be tied to a specific host
  4. Cross-domain bonus multiplier (default: 1.5) — increase to 2.0 for high-value user populations
  5. Add username normalization via LOOKUP JOIN against a username mapping index if IdP and endpoint use different naming conventions

## Data Requirements

- **Index**: `.internal.alerts-security.alerts-default`
- **Required fields**: `user.name`, `event.dataset`, `@timestamp`, `signal.rule.severity`, `kibana.alert.workflow_status`, `kibana.alert.rule.building_block_type`, `kibana.alert.rule.name`, `kibana.alert.rule.parameters.threat.tactic.name`, `host.name`, `related.ip`
- **Minimum volume**: 1+ identity-domain alert AND 1+ endpoint-domain alert for the same `user.name` within 4h
- **Critical dependency**: Consistent `user.name` field across identity and endpoint data sources

## Dependencies

- No required lookup indices
- Optional: `lookup-critical-assets` — escalate severity for privileged users
- Upstream requirement: Username normalization between IdP and endpoint sources (either at ingest or via lookup)

## Validation

Red team scenario:
1. Trigger an Okta impossible-travel alert or failed MFA alert for the test user (identity domain)
2. Within 1 hour, execute a malware sample or suspicious tool (e.g., Mimikatz) on an endpoint logged in as the same user (endpoint domain)

Expected result: User appears with `Esql.identity_alert_count >= 1`, `Esql.endpoint_alert_count >= 1`, `Esql.earliest_identity <= Esql.earliest_endpoint`, severity = critical (if both alerts are high+).

## Elastic Comparison

Elastic does not ship an identity-to-endpoint escalation correlation rule. The Risk Score engine accumulates risk per user across all domains but does not evaluate cross-domain temporal ordering or require specific domain pairings. CORR-2B adds explicit identity-then-endpoint sequencing, cross-domain bonus scoring, and escalation gap measurement.
