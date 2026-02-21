# Endpoint Multi-Technique Attack

---

## Metadata

- **Rule ID:** `CORR-5A`
- **Tier:** 5 — Domain-Specific Correlation
- **Author:** Detection Engineering
- **Description:** Detect a single host generating endpoint-domain alerts that span three or more distinct MITRE ATT&CK techniques within a 2-hour window. This pattern indicates an active hands-on-keyboard attack or automated exploitation toolkit operating on the host, producing process creation chains, file modifications, registry changes, and suspicious network connections that individually may be medium severity but collectively represent a multi-technique compromise.
- **Join Key(s):** `host.name`
- **Lookback:** 2 hours
- **Schedule:** Every 10 minutes
- **Priority:** P1
- **Integration:** [alerts](https://www.elastic.co/guide/en/security/current/alerts-ui-manage.html)
- **Language:** `[ES|QL]`

## Query

```esql
FROM .internal.alerts-security.alerts-default
| WHERE @timestamp > NOW() - 2 HOURS
    AND kibana.alert.workflow_status == "open"
    AND host.name IS NOT NULL
    AND (
        event.dataset LIKE "endpoint*" OR event.dataset LIKE "sentinelone*"
        OR event.dataset LIKE "windows*" OR event.dataset LIKE "sysmon*"
        OR event.dataset LIKE "microsoft-defender*" OR event.dataset LIKE "crowdstrike*"
        OR event.dataset LIKE "carbon_black*"
    )
| EVAL
    severity_weight = CASE(
        signal.rule.severity == "critical", 25,
        signal.rule.severity == "high", 15,
        signal.rule.severity == "medium", 8,
        signal.rule.severity == "low", 3, 1
    ),
    bbr_factor = CASE(kibana.alert.rule.building_block_type == "default", 0.3, 1.0),
    alert_risk = ROUND(severity_weight * bbr_factor)
| STATS
    Esql.alert_count = COUNT(*),
    Esql.first_seen = MIN(@timestamp),
    Esql.last_seen = MAX(@timestamp),
    Esql.total_risk = SUM(alert_risk),
    Esql.technique_count = COUNT_DISTINCT(kibana.alert.rule.parameters.threat.technique.id),
    Esql.technique_values = VALUES(kibana.alert.rule.parameters.threat.technique.id),
    Esql.tactic_count = COUNT_DISTINCT(kibana.alert.rule.threat.tactic.name),
    Esql.tactic_values = VALUES(kibana.alert.rule.threat.tactic.name),
    Esql.unique_rules = COUNT_DISTINCT(kibana.alert.rule.name),
    Esql.rule_names = VALUES(kibana.alert.rule.name),
    Esql.user_values = VALUES(user.name),
    Esql.process_names = VALUES(process.name),
    Esql.file_paths = VALUES(file.path)
  BY host.name
| WHERE Esql.technique_count >= 3
| EVAL
    Esql.risk_score = ROUND(Esql.total_risk * Esql.technique_count),
    Esql.severity = CASE(
        Esql.technique_count >= 5, "critical",
        Esql.technique_count >= 4, "high",
        Esql.technique_count >= 3, "medium",
        "low"
    ),
    Esql.description = CONCAT(
        "Endpoint multi-technique attack on host ", host.name,
        " | ", TO_STRING(Esql.technique_count), " distinct techniques",
        " | ", TO_STRING(Esql.tactic_count), " tactics",
        " | Risk Score: ", TO_STRING(Esql.risk_score),
        " | ", TO_STRING(Esql.alert_count), " alerts",
        " | Window: ", TO_STRING(Esql.first_seen), " to ", TO_STRING(Esql.last_seen)
    )
| SORT Esql.risk_score DESC
| LIMIT 50
```

## Strategy

Filters exclusively to the endpoint domain using `event.dataset` pattern matching. Counts distinct technique IDs from the alert threat metadata to measure technique diversity rather than raw alert volume. Computes a composite score by multiplying the summed alert risk by the technique count, rewarding breadth of attacker activity. The technique count threshold of 3 ensures the rule fires only when meaningfully diverse endpoint behaviors are observed on a single host.

## Severity Logic

| Condition | Severity |
|-----------|----------|
| technique_count >= 5 | Critical |
| technique_count >= 4 | High |
| technique_count >= 3 | Medium |

## Notes

- **Blind Spots:**
  - Attacks using a single technique repeatedly (e.g., pure credential dumping) will not trigger this rule -- use Tier 1 host-centric correlation instead
  - Fileless attacks that do not generate endpoint alerts (e.g., pure identity-layer attacks)
  - Endpoints without EDR coverage produce no alerts to correlate
  - Technique IDs must be populated in `kibana.alert.rule.parameters.threat.technique.id` -- rules without ATT&CK mappings are invisible

- **False Positives:**
  - **Red team exercises**: Penetration testers running multi-technique toolkits on a single host. Mitigation: exclude red team hosts by name or tag during engagement windows.
  - **Software deployment tools**: SCCM/Intune deployments that trigger process creation, registry modification, and file write alerts simultaneously. Mitigation: correlate with change management windows.
  - **Security scanning tools**: Vulnerability scanners running on endpoints may trigger multiple technique-mapped alerts. Mitigation: maintain scanner host exclusion list.

- **Tuning:**
  1. `technique_count` threshold (default: 3) -- increase to 4 if endpoint rules have broad ATT&CK mappings that inflate technique diversity
  2. Lookback window (default: 2h) -- decrease to 1h for faster detection of active exploitation, increase to 4h for slow attack chains
  3. Add exclusions for known build servers and CI/CD runners that legitimately execute diverse processes
  4. Consider filtering out building block alerts entirely (`kibana.alert.rule.building_block_type IS NULL`) if BBR technique mappings inflate counts

## Data Requirements

- **Index**: `.internal.alerts-security.alerts-default`
- **Required fields**: `host.name`, `event.dataset`, `signal.rule.severity`, `kibana.alert.rule.building_block_type`, `kibana.alert.rule.parameters.threat.technique.id`, `kibana.alert.rule.threat.tactic.name`, `kibana.alert.rule.name`, `@timestamp`, `user.name`, `process.name`, `file.path`
- **Minimum data sources**: At least one endpoint EDR integration (Elastic Defend, SentinelOne, CrowdStrike, Microsoft Defender, Carbon Black, or Sysmon)
- **Minimum volume**: 3+ endpoint alerts with distinct technique IDs on same host within 2h

## Dependencies

None required. Optional: `lookup-critical-assets` for asset criticality enrichment to escalate severity on production/PCI hosts.

## Validation

On a single test host within a 1-hour window:
1. Trigger a suspicious process spawn alert (e.g., PowerShell download cradle -- Execution technique)
2. Trigger a registry persistence alert (e.g., Run key modification -- Persistence technique)
3. Trigger a credential dump alert (e.g., LSASS memory access -- Credential Access technique)

Expected result: Host appears with `Esql.technique_count >= 3` and severity of medium or higher.

## Elastic Comparison

Elastic does not ship an endpoint-domain-specific multi-technique correlation rule. The closest built-in rule is "Multiple Alerts Involving a Single Host" which counts alert volume without domain filtering, technique diversity analysis, or risk scoring. CORR-5A provides domain-specific context that the generic rule cannot.
