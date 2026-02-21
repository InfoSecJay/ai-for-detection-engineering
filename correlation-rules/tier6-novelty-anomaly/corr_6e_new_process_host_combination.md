# New Process-Host Combination

---

## Metadata

- **Rule ID:** `CORR-6E`
- **Tier:** 6 — Novelty and Anomaly Detection
- **Author:** Detection Engineering
- **Description:** Detect alerts involving processes (identified by SHA-256 hash) that have never been observed on the triggering host's group before. A process hash seen on 500 workstations in the sales department is normal. That same hash appearing on a domain controller for the first time -- while also triggering a detection rule -- is a strong indicator of lateral movement or unauthorized software deployment.
- **Join Key(s):** `host.name` + `process.hash.sha256`
- **Lookback:** 24 hours
- **Schedule:** Every 30 minutes
- **Priority:** P2
- **Integration:** [alerts](https://www.elastic.co/guide/en/security/current/alerts-ui-manage.html)
- **Language:** `[ES|QL]`

## Query

```esql
FROM .internal.alerts-security.alerts-default
| WHERE @timestamp > NOW() - 24 HOURS
    AND kibana.alert.workflow_status == "open"
    AND host.name IS NOT NULL
    AND process.hash.sha256 IS NOT NULL
    AND NOT process.hash.sha256 IN (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
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
    alert_risk = ROUND(severity_weight * bbr_factor),
    is_high_or_critical = CASE(
        signal.rule.severity IN ("high", "critical")
            AND kibana.alert.rule.building_block_type IS NULL, 1, 0
    )
| LOOKUP JOIN lookup-process-baselines ON host.name, process.hash.sha256
| WHERE first_seen IS NULL
| STATS
    Esql.novel_processes = COUNT_DISTINCT(process.hash.sha256),
    Esql.alert_count = COUNT(*),
    Esql.risk_score = SUM(alert_risk),
    Esql.max_severity = MAX(severity_weight),
    Esql.high_critical_count = SUM(is_high_or_critical),
    Esql.first_seen = MIN(@timestamp),
    Esql.last_seen = MAX(@timestamp),
    Esql.process_names = VALUES(process.name),
    Esql.process_hashes = VALUES(process.hash.sha256),
    Esql.rule_names = VALUES(kibana.alert.rule.name),
    Esql.unique_rules = COUNT_DISTINCT(kibana.alert.rule.name),
    Esql.tactic_values = VALUES(kibana.alert.rule.threat.tactic.name),
    Esql.user_values = VALUES(user.name)
  BY host.name
| WHERE Esql.novel_processes >= 1
| EVAL
    Esql.severity = CASE(
        Esql.novel_processes >= 1 AND Esql.max_severity >= 15, "critical",
        Esql.novel_processes >= 1 AND Esql.alert_count >= 3, "high",
        Esql.novel_processes >= 1 AND Esql.max_severity >= 8, "medium",
        "medium"
    ),
    Esql.description = CONCAT(
        "Host ", host.name,
        " executed ", TO_STRING(Esql.novel_processes), " NEVER-BEFORE-SEEN processes",
        " | Processes: ", TO_STRING(Esql.process_names),
        " | ", TO_STRING(Esql.alert_count), " alerts from ",
        TO_STRING(Esql.unique_rules), " rules",
        " | Risk: ", TO_STRING(Esql.risk_score)
    )
| SORT Esql.risk_score DESC
| LIMIT 50
```

## Strategy

Filters to endpoint-domain alerts with valid process hashes. Each alert's process hash is checked against `lookup-process-baselines` via `LOOKUP JOIN`, matching on host group and process hash. Processes with no baseline entry (`first_seen IS NULL`) are flagged as novel. The rule aggregates novel processes per host, counting distinct new hashes and correlating with alert severity. This enriches existing endpoint alerts with novelty context rather than creating entirely new signals.

## Severity Logic

| Condition | Severity |
|-----------|----------|
| Novel process + high or critical severity alert | Critical |
| Novel process + 3+ total alerts | High |
| Novel process + medium severity alert | Medium |
| Novel process (low severity) | Medium |

## Notes

- **Blind Spots:**
  - **Fileless attacks**: Malware executing entirely in memory without a distinct process hash bypasses this rule.
  - **LOLBins**: Living-off-the-land binaries (powershell.exe, cmd.exe) have well-known hashes that will appear in every baseline. Novel LOLBin usage is invisible to hash-based novelty.
  - **Host group granularity**: If `lookup-process-baselines` groups hosts too broadly (e.g., "all workstations"), rare but legitimate software appears in the baseline. Too narrow and everything appears novel.

- **False Positives:**
  - **Software deployments**: New software pushed via SCCM, Intune, or GPO triggers novel process hashes across many hosts simultaneously. Mitigation: suppress during known deployment windows or correlate with SCCM deployment logs.
  - **System updates**: OS patches introduce new system binaries. Mitigation: refresh baselines after patch cycles.
  - **New tools being adopted**: IT-approved tools not yet in baseline. Mitigation: pre-populate baselines during tool approval process.

- **Tuning:**
  1. Refresh `lookup-process-baselines` weekly from endpoint telemetry (not just alerts)
  2. Use host group (role/department) rather than individual host for baseline matching to reduce noise from legitimate software diversity
  3. Exclude known LOLBin hashes from novelty checks (they are always "known")
  4. Add deployment window suppression for scheduled software rollouts
  5. Consider a minimum `alert_risk` threshold to filter low-severity novel process alerts

## Data Requirements

- **Index**: `.internal.alerts-security.alerts-default`
- **Lookup Index**: `lookup-process-baselines` (fields: `host.name`, `process.hash.sha256`, `first_seen`, `frequency`)
- **Required fields**: `host.name`, `process.hash.sha256`, `process.name`, `event.dataset`, `signal.rule.severity`, `kibana.alert.rule.building_block_type`, `kibana.alert.workflow_status`, `@timestamp`, `kibana.alert.rule.name`, `user.name`
- **Minimum volume**: Process baselines populated from 30+ days of endpoint telemetry per host group

## Dependencies

- **Required**: `lookup-process-baselines` -- must contain host-to-process-hash mappings with first-seen dates
- **Optional**: `lookup-critical-assets` for severity escalation on critical servers (domain controllers, database servers)

## Validation

1. Identify a host group (e.g., "finance workstations") and verify the process baseline is populated
2. Execute a benign custom binary (unique hash) on a host in that group that triggers an endpoint alert
3. Verify CORR-6E surfaces the host with `Esql.novel_processes >= 1` and the custom binary in `Esql.process_names`
4. Execute a common system binary that IS in the baseline and confirm it does NOT trigger CORR-6E

## Elastic Comparison

Elastic ships "Unusual Process Execution" ML rules that flag anomalous process activity. CORR-6E differs by using deterministic hash-based baseline comparison rather than ML scoring, operating on alert data rather than raw process events, and providing explainable output (exact process names and hashes rather than anomaly scores). Both approaches complement each other.
