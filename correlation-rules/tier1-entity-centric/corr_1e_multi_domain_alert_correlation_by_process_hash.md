# Multi-Domain Alert Correlation by Process Hash

---

## Metadata

- **Rule ID:** `CORR-1E`
- **Tier:** 1 — Entity-Centric Correlation
- **Author:** Detection Engineering
- **Description:** Detect the same executable (SHA-256 hash) generating alerts on multiple hosts or across multiple detection domains. Catches malware lateral movement, supply chain compromises, and commodity malware campaigns.
- **Join Key(s):** `process.hash.sha256`
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
    AND process.hash.sha256 IS NOT NULL
    AND NOT process.hash.sha256 IN (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
| EVAL
    domain_category = CASE(
        event.dataset LIKE "endpoint*" OR event.dataset LIKE "sentinelone*"
            OR event.dataset LIKE "windows*" OR event.dataset LIKE "sysmon*", "endpoint",
        event.dataset LIKE "panw*" OR event.dataset LIKE "fortinet*", "network_fw",
        event.dataset LIKE "extrahop*" OR event.dataset LIKE "zeek*", "network_ndr",
        event.dataset LIKE "proxy*" OR event.dataset LIKE "zscaler*", "proxy",
        COALESCE(labels.technology, event.module, "unknown")
    ),
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
    Esql.total_risk_score = SUM(alert_risk),
    Esql.tactic_values = VALUES(kibana.alert.rule.threat.tactic.name),
    Esql.unique_rules = COUNT_DISTINCT(kibana.alert.rule.name),
    Esql.rule_names = VALUES(kibana.alert.rule.name),
    Esql.domain_count = COUNT_DISTINCT(domain_category),
    Esql.domain_values = VALUES(domain_category),
    Esql.host_count = COUNT_DISTINCT(host.name),
    Esql.host_values = VALUES(host.name),
    Esql.user_values = VALUES(user.name),
    Esql.process_names = VALUES(process.name)
  BY process.hash.sha256
| WHERE Esql.host_count >= 2 OR Esql.domain_count >= 2
| EVAL
    Esql.risk_score = ROUND(Esql.total_risk_score
        * CASE(Esql.host_count >= 5, 2.0, Esql.host_count >= 3, 1.5, Esql.host_count >= 2, 1.25, 1.0)
        * CASE(Esql.domain_count >= 2, 1.25, 1.0)),
    Esql.correlation_severity = CASE(
        Esql.risk_score >= 100 OR (Esql.host_count >= 5 AND Esql.domain_count >= 2), "critical",
        Esql.risk_score >= 50 OR Esql.host_count >= 3, "high",
        Esql.risk_score >= 25, "medium",
        "low"
    ),
    Esql.description = CONCAT(
        "Hash ", process.hash.sha256,
        " | ", TO_STRING(Esql.host_count), " hosts",
        " | ", TO_STRING(Esql.domain_count), " domains",
        " | Risk: ", TO_STRING(Esql.risk_score)
    )
| SORT Esql.risk_score DESC
| LIMIT 50
```

## Strategy

24-hour lookback (longer than user/host) because binary propagation is slower than interactive attacks. Host-count multiplier heavily amplifies risk for hashes on many hosts (2x for 5+). Empty file hash excluded.

## Severity Logic

| Condition | Severity |
|-----------|----------|
| risk_score >= 100 OR (host_count >= 5 AND domain_count >= 2) | Critical |
| risk_score >= 50 OR host_count >= 3 | High |
| risk_score >= 25 | Medium |
| Everything else crossing threshold | Low |

## Notes

- **Blind Spots:**
  - Fileless malware (no hash), polymorphic malware (unique hash per host), LOLBins (legitimate OS binary hashes)
- **False Positives:**
  - LOLBin alerts (powershell.exe, cmd.exe have identical hashes across hosts). Mitigation: maintain LOLBin hash exclusion list.
  - Legitimate software deployment via SCCM/Intune.
- **Tuning:**
  - Maintain a LOLBin hash exclusion list for common OS binaries
  - Adjust host_count multiplier thresholds based on fleet size
  - Consider excluding known software deployment hashes

## Data Requirements

- **Index**: `.internal.alerts-security.alerts-default`
- **Required fields**: `process.hash.sha256`, `event.dataset`, `signal.rule.severity`, `kibana.alert.workflow_status`, `kibana.alert.rule.building_block_type`, `kibana.alert.rule.name`, `kibana.alert.rule.threat.tactic.name`, `@timestamp`, `host.name`, `user.name`, `process.name`
- **Minimum volume**: 2+ alerts for same hash on 2+ hosts or 2+ domains in 24h

## Dependencies

None required. Optional: LOLBin hash exclusion lookup, software deployment hash allow-list.

## Validation

Deploy custom implant to 3 workstations. Each EDR alerts. One firewall also alerts on C2 callback. host_count=3, domain_count=2.

## Elastic Comparison

No Elastic equivalent. Closest is "Threat Intel Hash Indicator Match" — single TI check, not cross-host/cross-domain aggregation.
