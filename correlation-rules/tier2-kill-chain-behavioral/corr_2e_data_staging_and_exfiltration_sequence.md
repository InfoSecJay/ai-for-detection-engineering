# Data Staging and Exfiltration Sequence

---

## Metadata

- **Rule ID:** `CORR-2E`
- **Tier:** 2 — Kill Chain and Behavioral Correlation
- **Author:** Detection Engineering
- **Description:** Detect hosts or users exhibiting a data staging and exfiltration sequence: collection (accessing sensitive data), staging (compressing/archiving/moving data to a staging location), and exfiltration (transferring data to an external destination). Presence of at least 2 of 3 stages within 6 hours indicates active data theft preparation or execution.
- **Join Key(s):** `host.name`, `user.name`
- **Lookback:** 6 hours
- **Schedule:** Every 15 minutes
- **Priority:** P1
- **Integration:** [alerts](https://www.elastic.co/guide/en/security/current/alerts-ui-manage.html)
- **Language:** `[ES|QL]`

## Query

```esql
FROM .internal.alerts-security.alerts-default
| WHERE @timestamp > NOW() - 6 HOURS
    AND kibana.alert.workflow_status == "open"
    AND host.name IS NOT NULL AND host.name != ""
| EVAL
    severity_weight = CASE(
        signal.rule.severity == "critical", 25,
        signal.rule.severity == "high", 15,
        signal.rule.severity == "medium", 8,
        signal.rule.severity == "low", 3, 1
    ),
    bbr_factor = CASE(kibana.alert.rule.building_block_type == "default", 0.3, 1.0),
    alert_risk = ROUND(severity_weight * bbr_factor),
    data_stage = CASE(
        kibana.alert.rule.parameters.threat.tactic.name == "Collection", "collection",
        kibana.alert.rule.name LIKE "*archive*"
            OR kibana.alert.rule.name LIKE "*compress*"
            OR kibana.alert.rule.name LIKE "*staging*"
            OR kibana.alert.rule.name LIKE "*rar *"
            OR kibana.alert.rule.name LIKE "*7zip*"
            OR kibana.alert.rule.name LIKE "*7-zip*"
            OR kibana.alert.rule.name LIKE "*zip *"
            OR kibana.alert.rule.name LIKE "*tar *"
            OR kibana.alert.rule.name LIKE "*makecab*", "staging",
        kibana.alert.rule.parameters.threat.tactic.name == "Exfiltration", "exfiltration",
        kibana.alert.rule.name LIKE "*exfil*"
            OR kibana.alert.rule.name LIKE "*large upload*"
            OR kibana.alert.rule.name LIKE "*data transfer*"
            OR kibana.alert.rule.name LIKE "*outbound*"
            OR kibana.alert.rule.name LIKE "*upload*external*", "exfiltration",
        "other"
    ),
    is_collection = CASE(data_stage == "collection", 1, 0),
    is_staging = CASE(data_stage == "staging", 1, 0),
    is_exfiltration = CASE(data_stage == "exfiltration", 1, 0)
| STATS
    Esql.alert_count = COUNT(*),
    Esql.first_seen = MIN(@timestamp),
    Esql.last_seen = MAX(@timestamp),
    Esql.total_risk = SUM(alert_risk),
    Esql.has_collection = MAX(is_collection),
    Esql.has_staging = MAX(is_staging),
    Esql.has_exfiltration = MAX(is_exfiltration),
    Esql.collection_count = SUM(is_collection),
    Esql.staging_count = SUM(is_staging),
    Esql.exfiltration_count = SUM(is_exfiltration),
    Esql.tactic_values = VALUES(kibana.alert.rule.parameters.threat.tactic.name),
    Esql.unique_rules = COUNT_DISTINCT(kibana.alert.rule.name),
    Esql.rule_names = VALUES(kibana.alert.rule.name),
    Esql.user_values = VALUES(user.name),
    Esql.user_count = COUNT_DISTINCT(user.name),
    Esql.ip_values = VALUES(related.ip)
  BY host.name
| EVAL
    Esql.stages_present = Esql.has_collection + Esql.has_staging + Esql.has_exfiltration
| WHERE Esql.stages_present >= 2
| EVAL
    Esql.risk_score = ROUND(Esql.total_risk * Esql.stages_present),
    Esql.correlation_severity = CASE(
        Esql.stages_present >= 3, "critical",
        Esql.has_collection == 1 AND Esql.has_exfiltration == 1, "critical",
        Esql.stages_present >= 2, "high",
        "medium"
    ),
    Esql.description = CONCAT(
        "Host ", host.name,
        " | Data Staging/Exfiltration Sequence",
        " | Stages: ", TO_STRING(Esql.stages_present), "/3",
        " (collection=", TO_STRING(Esql.has_collection),
        " staging=", TO_STRING(Esql.has_staging),
        " exfiltration=", TO_STRING(Esql.has_exfiltration), ")",
        " | Risk Score: ", TO_STRING(Esql.risk_score),
        " | ", TO_STRING(Esql.user_count), " users",
        " | ", TO_STRING(Esql.unique_rules), " rules",
        " | ", TO_STRING(Esql.alert_count), " total alerts",
        " | Window: ", TO_STRING(Esql.first_seen), " to ", TO_STRING(Esql.last_seen)
    )
| SORT Esql.risk_score DESC
| LIMIT 50
```

## Strategy

Each alert is mapped to a data theft stage using CASE logic: Collection tactic alerts map to "collection", alerts with rule names matching archive/compress/staging patterns map to "staging", and Exfiltration tactic alerts or alerts matching large outbound transfer patterns map to "exfiltration". STATS aggregates by `host.name` to determine which stages are present. Hosts with 2+ stages pass filtering. The risk score is multiplied by the number of stages present — all 3 stages = 3x multiplier, reflecting a complete data theft pipeline.

## Severity Logic

```
CASE(
    Esql.stages_present >= 3, "critical",
    Esql.has_collection == 1 AND Esql.has_exfiltration == 1, "critical",
    Esql.stages_present >= 2, "high",
    "medium"
)
```

| Condition | Severity |
|-----------|----------|
| All 3 stages present (collection + staging + exfiltration) | Critical |
| Collection + exfiltration (skipped staging or staging not detected) | Critical |
| Any 2 of 3 stages present | High |
| Fallback | Medium |

## Notes

- **Blind Spots:**
  - Exfiltration via physical media (USB drives, printed documents) — no network-based exfiltration alert generated
  - Cloud-native exfiltration not tagged with the Exfiltration tactic (e.g., sharing a OneDrive link externally may be classified under a different tactic or no tactic)
  - Low-and-slow exfiltration spread over more than 6 hours (e.g., trickle exfiltration at 1 MB/hour)
  - Staging in memory rather than disk (no archive/compress process alert)

- **False Positives:**
  - **Legitimate backup operations**: Backup agents compressing files (staging alert) and uploading to cloud backup (exfiltration alert). Mitigation: exclude known backup processes and destinations.
  - **Large file transfers to approved cloud storage**: Users uploading project archives to approved SharePoint/S3. Mitigation: maintain an approved destination list and exclude matching alerts.
  - **Database export workflows**: ETL processes that collect, stage, and transfer data as part of normal business operations. Mitigation: register in `lookup-service-accounts` with expected domains.

- **Tuning:**
  1. Stage-mapping patterns — refine `data_stage` CASE logic for your detection rule naming conventions
  2. Lookback window (default: 6h) — extend to 12h for insider threat scenarios
  3. Add temporal ordering: require collection timestamp < staging timestamp < exfiltration timestamp for strict sequencing
  4. Add data volume context: enrich with `network.bytes` or `file.size` if available in alert metadata
  5. Create a user-keyed variant by changing `BY host.name` to `BY user.name` for insider threat focus

## Data Requirements

- **Index**: `.internal.alerts-security.alerts-default`
- **Required fields**: `host.name`, `@timestamp`, `signal.rule.severity`, `kibana.alert.workflow_status`, `kibana.alert.rule.building_block_type`, `kibana.alert.rule.name`, `kibana.alert.rule.parameters.threat.tactic.name`, `user.name`, `related.ip`
- **Minimum volume**: 2+ alerts matching 2+ distinct data theft stages for same `host.name` within 6h
- **Critical dependency**: Detection rules for archive/compress/staging activity must exist and have consistent naming patterns

## Dependencies

- No required lookup indices
- Prerequisite: Detection rules covering Collection, archive/compress, and Exfiltration tactics must be deployed
- Optional: `lookup-critical-assets` — escalate severity for hosts containing sensitive data
- Complementary: DLP (Data Loss Prevention) alerts fed into the security alerts index significantly improve exfiltration stage detection

## Validation

Red team scenario:
1. Access sensitive files on a test host (triggers Collection tactic alert — e.g., "Sensitive File Access" rule)
2. Compress files into an archive in a temp directory (triggers staging alert — e.g., "Archive Creation via Command Line" rule)
3. Upload the archive to an external cloud storage service (triggers Exfiltration tactic alert — e.g., "Large Outbound Transfer" rule)

Expected result: Host appears with `Esql.stages_present = 3`, severity = critical, risk score = `SUM(alert_risk) * 3`.

## Elastic Comparison

Elastic does not ship a data staging/exfiltration sequence correlation rule. Individual rules exist for specific techniques (archive creation, large outbound transfer) but no rule correlates them into a coherent data theft pipeline. CORR-2E connects the dots between Collection, staging, and Exfiltration to surface the complete attack pattern.
