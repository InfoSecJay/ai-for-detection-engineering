# Repeated Low-Severity Cluster

---

## Metadata

- **Rule ID:** `CORR-4C`
- **Tier:** 4 — Meta-Correlation
- **Author:** Detection Engineering
- **Description:** Detect entities accumulating a high volume of individually insignificant alerts (low and medium severity) from diverse detection rules over 24 hours. A single low-severity building block alert is noise. Ten low-severity alerts from three different rules across multiple detection domains for the same entity is a pattern. This rule catches slow-burn reconnaissance, persistent low-and-slow attacks, and misconfigured systems that deserve investigation despite never triggering a single high-severity alert.
- **Join Key(s):** `COALESCE(user.name, host.name)`
- **Lookback:** 24 hours
- **Schedule:** Every 1 hour
- **Priority:** P2
- **Integration:** [alerts](https://www.elastic.co/guide/en/security/current/alerts-ui-manage.html)
- **Language:** `[ES|QL]`

## Query

```esql
FROM .internal.alerts-security.alerts-default
| WHERE @timestamp > NOW() - 24 HOURS
    AND kibana.alert.workflow_status == "open"
    AND signal.rule.severity IN ("low", "medium")
| EVAL
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
        signal.rule.severity == "medium", 8,
        signal.rule.severity == "low", 3,
        1
    ),
    bbr_factor = CASE(kibana.alert.rule.building_block_type == "default", 0.3, 1.0),
    alert_risk = ROUND(severity_weight * bbr_factor),
    is_low = CASE(signal.rule.severity == "low", 1, 0),
    is_medium = CASE(signal.rule.severity == "medium", 1, 0),
    is_bbr = CASE(kibana.alert.rule.building_block_type == "default", 1, 0)
| WHERE entity IS NOT NULL
| STATS
    Esql.total_count = COUNT(*),
    Esql.low_count = SUM(is_low),
    Esql.medium_count = SUM(is_medium),
    Esql.bbr_count = SUM(is_bbr),
    Esql.rule_diversity = COUNT_DISTINCT(kibana.alert.rule.name),
    Esql.rule_names = VALUES(kibana.alert.rule.name),
    Esql.domain_count = COUNT_DISTINCT(domain_category),
    Esql.domain_values = VALUES(domain_category),
    Esql.risk_score = SUM(alert_risk),
    Esql.first_seen = MIN(@timestamp),
    Esql.last_seen = MAX(@timestamp),
    Esql.tactic_count = COUNT_DISTINCT(kibana.alert.rule.parameters.threat.tactic.name),
    Esql.tactic_values = VALUES(kibana.alert.rule.parameters.threat.tactic.name),
    Esql.host_values = VALUES(host.name),
    Esql.user_values = VALUES(user.name)
  BY entity
| WHERE Esql.total_count >= 10 AND Esql.rule_diversity >= 3
| EVAL
    Esql.severity = CASE(
        Esql.rule_diversity >= 5 AND Esql.domain_count >= 3, "high",
        Esql.rule_diversity >= 3 AND Esql.total_count >= 15, "high",
        Esql.total_count >= 10, "medium",
        "low"
    ),
    Esql.description = CONCAT(
        "Low-severity cluster for ", entity,
        " | ", TO_STRING(Esql.total_count), " alerts (",
        TO_STRING(Esql.low_count), " low, ",
        TO_STRING(Esql.medium_count), " medium, ",
        TO_STRING(Esql.bbr_count), " building blocks)",
        " | ", TO_STRING(Esql.rule_diversity), " distinct rules",
        " | ", TO_STRING(Esql.domain_count), " domains",
        " | ", TO_STRING(Esql.tactic_count), " tactics",
        " | Risk: ", TO_STRING(Esql.risk_score),
        " | Window: ", TO_STRING(Esql.first_seen), " to ", TO_STRING(Esql.last_seen)
    )
| SORT Esql.risk_score DESC
| LIMIT 50
```

## Strategy

Filters to only low and medium severity alerts (and preferentially building block rules) to isolate the signal that Tiers 1-3 would not surface on their own. Aggregates by entity and counts total alerts, rule diversity (`COUNT_DISTINCT(kibana.alert.rule.name)`), and domain diversity. The rule fires when total count >= 10 AND rule diversity >= 3 -- ensuring the cluster is not just a single noisy rule firing repeatedly. Risk is the sum of individual alert_risk scores, which naturally accumulates from many small contributions. The rule diversity filter is the critical differentiator: it distinguishes "ten different suspicious behaviors" from "the same false positive firing ten times."

## Severity Logic

| Condition | Severity |
|-----------|----------|
| rule_diversity >= 5 AND domain_count >= 3 (5+ rules across 3+ domains) | High |
| rule_diversity >= 3 AND total_count >= 15 (diverse + voluminous) | High |
| total_count >= 10 AND rule_diversity >= 3 (base threshold) | Medium |

No critical severity -- by definition, this rule only processes low and medium severity alerts. If the cluster warrants critical attention, the underlying alerts should have been higher severity, and Tiers 1-3 would have caught them.

## Notes

- **Blind Spots:**
  - **Truly random noise**: Coincidental low-severity alerts from unrelated sources hitting the same entity. The rule_diversity >= 3 filter mitigates this but cannot eliminate it entirely.
  - **Single noisy rule**: If one misconfigured rule fires 50 times for an entity, rule_diversity = 1, so CORR-4C will not fire. This is by design -- repeated false positives from one rule are a tuning problem, not a correlation signal.
  - **Alerts without entity fields**: Alerts where both `user.name` and `host.name` are NULL are excluded.

- **False Positives:**
  - **Misconfigured endpoints**: Endpoints with broken configurations (e.g., disabled services, missing patches) that trigger multiple low-severity rules chronically. Mitigation: investigate the root cause and either fix the configuration or create targeted suppressions.
  - **Monitoring agents**: Security monitoring tools (e.g., EDR health checks, vulnerability scanners) that trigger building block rules as a side effect. Mitigation: exclude known monitoring agent activities by rule name or process.
  - **Developer workstations**: Developers running compilers, debuggers, and scripting tools that trigger multiple low-severity behavioral rules. Mitigation: tag developer hosts and raise thresholds for that group.

- **Tuning:**
  1. **total_count threshold** (default: 10) -- the primary volume knob. Raise to 15 or 20 in noisy environments.
  2. **rule_diversity threshold** (default: 3) -- the most important quality filter. Do not lower below 3 or the rule will fire on repeated false positives from 1-2 rules.
  3. **domain_count in severity** (default: 3 for high) -- this ensures high severity only when the low-severity cluster spans multiple detection surfaces.
  4. **BBR-only mode** -- consider adding `AND kibana.alert.rule.building_block_type == "default"` to the WHERE clause if you want to focus exclusively on building block signal accumulation.
  5. **Lookback window** (default: 24h) -- reduce to 12h if 24h produces too many clusters; extend to 48h for very slow reconnaissance patterns.

## Data Requirements

- **Index**: `.internal.alerts-security.alerts-default`
- **Required fields**: `user.name`, `host.name`, `event.dataset`, `signal.rule.severity`, `kibana.alert.workflow_status`, `kibana.alert.rule.building_block_type`, `kibana.alert.rule.name`, `kibana.alert.rule.parameters.threat.tactic.name`, `@timestamp`
- **Minimum volume**: 10+ low/medium severity alerts from 3+ distinct rules for the same entity in 24h

## Dependencies

- **Required**: None.
- **Upstream**: Relies on building block rules being deployed and generating low-severity alerts. The value of CORR-4C scales directly with the number of building block rules in the environment.

## Validation

1. Generate 12 different low-severity building block alerts against the same host over an 18-hour period. Use at least 4 different rules (e.g., suspicious process creation, unusual network connection, registry modification, scheduled task creation).
2. Ensure at least 3 different `event.dataset` values are represented (e.g., endpoint, network, identity).
3. CORR-4C should produce a cluster with `Esql.total_count >= 12`, `Esql.rule_diversity >= 4`, and `Esql.domain_count >= 3`.
4. Verify severity resolves to "high" (rule_diversity >= 5 AND domain_count >= 3, or rule_diversity >= 3 AND total_count >= 15).

## Elastic Comparison

Elastic does not ship a low-severity cluster detection rule. Elastic's Risk Score engine accumulates risk per entity but does not differentiate between one high-severity alert and ten low-severity alerts from diverse rules. CORR-4C specifically targets the "death by a thousand cuts" pattern that flat risk accumulation misses -- it requires both volume AND diversity, which the native Risk Score does not enforce.
