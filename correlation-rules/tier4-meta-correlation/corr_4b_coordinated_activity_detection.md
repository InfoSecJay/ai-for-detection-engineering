# Coordinated Activity Detection

---

## Metadata

- **Rule ID:** `CORR-4B`
- **Tier:** 4 — Meta-Correlation
- **Author:** Detection Engineering
- **Description:** Detect coordinated activity where three or more distinct entities perform the same MITRE ATT&CK tactic within a 15-minute window. This pattern indicates either a coordinated attack (ransomware deployment, worm propagation, coordinated credential harvesting) or a mass administrative action. The time-tactic co-occurrence across multiple entities is the distinguishing signal.
- **Join Key(s):** `time_bucket` + `kibana.alert.rule.threat.tactic.name`
- **Lookback:** 1 hour
- **Schedule:** Every 10 minutes
- **Priority:** P1
- **Integration:** [alerts](https://www.elastic.co/guide/en/security/current/alerts-ui-manage.html)
- **Language:** `[ES|QL]`

## Query

```esql
FROM .internal.alerts-security.alerts-default
| WHERE @timestamp > NOW() - 1 HOURS
    AND kibana.alert.workflow_status == "open"
    AND kibana.alert.rule.threat.tactic.name IS NOT NULL
| EVAL
    time_bucket = BUCKET(@timestamp, 15 minutes),
    entity = COALESCE(user.name, host.name),
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
| WHERE entity IS NOT NULL
| STATS
    Esql.entity_count = COUNT_DISTINCT(entity),
    Esql.alert_count = COUNT(*),
    Esql.host_spread = COUNT_DISTINCT(host.name),
    Esql.user_spread = COUNT_DISTINCT(user.name),
    Esql.risk_score = SUM(alert_risk),
    Esql.unique_rules = COUNT_DISTINCT(kibana.alert.rule.name),
    Esql.rule_names = VALUES(kibana.alert.rule.name),
    Esql.domain_count = COUNT_DISTINCT(domain_category),
    Esql.domain_values = VALUES(domain_category),
    Esql.entity_values = VALUES(entity),
    Esql.host_values = VALUES(host.name)
  BY time_bucket, kibana.alert.rule.threat.tactic.name
| WHERE Esql.entity_count >= 3 AND Esql.host_spread >= 3
| EVAL
    Esql.coordination_score = ROUND(Esql.risk_score
        * CASE(Esql.entity_count >= 10, 2.0, Esql.entity_count >= 5, 1.5, 1.0)
        * CASE(Esql.host_spread >= 10, 1.5, Esql.host_spread >= 5, 1.25, 1.0)),
    Esql.correlation_severity = CASE(
        Esql.entity_count >= 10, "critical",
        Esql.entity_count >= 5, "high",
        Esql.entity_count >= 3, "medium",
        "low"
    ),
    Esql.description = CONCAT(
        "Coordinated ", kibana.alert.rule.threat.tactic.name,
        " at ", TO_STRING(time_bucket),
        " | ", TO_STRING(Esql.entity_count), " entities",
        " | ", TO_STRING(Esql.host_spread), " hosts",
        " | ", TO_STRING(Esql.alert_count), " alerts",
        " | ", TO_STRING(Esql.unique_rules), " rules",
        " | ", TO_STRING(Esql.domain_count), " domains",
        " | Coordination Score: ", TO_STRING(Esql.coordination_score)
    )
| SORT Esql.coordination_score DESC
| LIMIT 50
```

## Strategy

Buckets alerts into 15-minute time windows using `BUCKET(@timestamp, 15 minutes)`, then aggregates by the combination of time bucket and tactic. The rule fires when 3+ distinct entities and 3+ distinct hosts appear in the same tactic-time bucket. This catches coordinated lateral movement (multiple hosts executing the same tactic simultaneously), synchronized ransomware detonation, and worm-like propagation. The 15-minute bucket size balances granularity (catching tight coordination) with tolerance (allowing for slight timing variations in propagation).

## Severity Logic

| Condition | Severity |
|-----------|----------|
| entity_count >= 10 in same tactic within 15-min bucket | Critical |
| entity_count >= 5 in same tactic within 15-min bucket | High |
| entity_count >= 3 AND host_spread >= 3 | Medium |

Coordination score multipliers: entity_count >= 10 = 2.0x, >= 5 = 1.5x. Host spread >= 10 = additional 1.5x, >= 5 = 1.25x.

## Notes

- **Blind Spots:**
  - **Multi-tactic coordination**: Coordinated attacks where each target receives a different tactic (e.g., host A gets Execution, host B gets Persistence, host C gets Defense Evasion) will not cluster because the rule groups by tactic.
  - **Time-spread coordination**: Attacks that coordinate across a window longer than 15 minutes (e.g., 30-minute staggered deployment) may split across two buckets, reducing entity count in each.
  - **Alerts without MITRE tactic mapping**: Custom rules or rules lacking `threat.tactic.name` are excluded entirely.

- **False Positives:**
  - **Group Policy pushes**: GPO deployments that trigger endpoint detection rules across many hosts simultaneously (e.g., new startup script flagged as "Execution"). Mitigation: correlate with Active Directory GPO change events and suppress during known deployment windows.
  - **SCCM/Intune deployments**: Mass software deployments triggering the same rule on many hosts within minutes. Mitigation: exclude known deployment time windows or tag deployment-related rules.
  - **Security scanning**: Vulnerability scanners or EDR deployment pushes across the environment. Mitigation: maintain scanner and deployment tool exclusion list.
  - **Patch Tuesday**: Windows Update on many hosts simultaneously triggers endpoint rules. Mitigation: suppress during known patch windows.

- **Tuning:**
  1. **Time bucket size** (default: 15 minutes) -- increase to 30 minutes if your environment has slower propagation patterns; decrease to 5 minutes for tighter coordination detection.
  2. **entity_count threshold** (default: 3) -- raise to 5 in large environments (5,000+ hosts) where mass administrative actions are common.
  3. **host_spread threshold** (default: 3) -- this is the key differentiator from single-host correlation. Raise if GPO/SCCM false positives are high.
  4. **Tactic exclusions** -- consider excluding "Defense Evasion" if your EDR generates high-volume building block alerts for common evasion techniques across many hosts.
  5. **Schedule frequency** (default: 10 minutes) -- this is a fast-schedule rule by design. Do not extend beyond 15 minutes or you risk missing rapid coordination.

## Data Requirements

- **Index**: `.internal.alerts-security.alerts-default`
- **Required fields**: `kibana.alert.rule.threat.tactic.name`, `user.name`, `host.name`, `event.dataset`, `signal.rule.severity`, `kibana.alert.workflow_status`, `kibana.alert.rule.building_block_type`, `kibana.alert.rule.name`, `@timestamp`
- **Minimum volume**: 3+ distinct entities with the same tactic in the same 15-minute window

## Dependencies

- **Required**: None.
- **Upstream**: Requires detection rules to have MITRE ATT&CK tactic mappings populated in `kibana.alert.rule.threat.tactic.name`.

## Validation

1. Trigger the same detection rule (e.g., "Suspicious PowerShell Execution" mapped to Execution tactic) on 5 different hosts within a 10-minute window.
2. Each host should be operated by a different user.
3. CORR-4B should produce a coordinated activity alert with `Esql.entity_count >= 5` and `Esql.host_spread >= 5` for the Execution tactic.
4. Verify the `time_bucket` groups all 5 into the same 15-minute window.
5. Verify severity resolves to "high" (5 entities in same tactic).

## Elastic Comparison

Elastic does not ship a coordinated activity detection rule. Elastic's "Multiple Alerts on a Single Host" and "Multiple Alerts Involving a User" are entity-scoped, not environment-scoped. They detect alert volume for one entity, not the same tactic appearing across many entities simultaneously. CORR-4B provides cross-entity temporal-tactic correlation that Elastic does not offer.
