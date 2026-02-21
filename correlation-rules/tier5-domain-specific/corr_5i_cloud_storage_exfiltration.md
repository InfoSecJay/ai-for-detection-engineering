# Cloud Storage Exfiltration

---

## Metadata

- **Rule ID:** `CORR-5I`
- **Tier:** 5 — Domain-Specific Correlation
- **Author:** Detection Engineering
- **Description:** Detect cloud storage abuse patterns where a user modifies storage permissions (S3 bucket policies, GCS IAM bindings, Azure Blob access policies) and then performs bulk data access or grants public access. This is the canonical cloud exfiltration pattern: the attacker first weakens access controls on a storage resource, then extracts data through the widened access. Either action alone may be a legitimate administrative change -- the combination within a short window is a strong exfiltration indicator.
- **Join Key(s):** `user.name`, `cloud.account.id`
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
    AND user.name IS NOT NULL
    AND cloud.account.id IS NOT NULL
    AND (
        event.dataset LIKE "aws*" OR event.dataset LIKE "gcp*"
        OR event.dataset LIKE "azure*" OR event.dataset LIKE "cloud*"
        OR event.dataset LIKE "o365*"
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
    is_permission_change = CASE(
        kibana.alert.rule.name LIKE "*Bucket*Policy*"
            OR kibana.alert.rule.name LIKE "*Storage*Permission*"
            OR kibana.alert.rule.name LIKE "*Blob*Access*"
            OR kibana.alert.rule.name LIKE "*S3*ACL*"
            OR kibana.alert.rule.name LIKE "*Storage*IAM*",
            1, 0
    ),
    is_bulk_access = CASE(
        kibana.alert.rule.name LIKE "*Bulk*Download*"
            OR kibana.alert.rule.name LIKE "*Large*Transfer*"
            OR kibana.alert.rule.name LIKE "*Mass*Object*"
            OR kibana.alert.rule.name LIKE "*Exfiltration*"
            OR kibana.alert.rule.name LIKE "*Data*Transfer*"
            OR kibana.alert.rule.threat.tactic.name == "Exfiltration",
            1, 0
    ),
    is_public_grant = CASE(
        kibana.alert.rule.name LIKE "*Public*Access*"
            OR kibana.alert.rule.name LIKE "*Public*Bucket*"
            OR kibana.alert.rule.name LIKE "*Public*Blob*"
            OR kibana.alert.rule.name LIKE "*Anonymous*Access*"
            OR kibana.alert.rule.name LIKE "*World*Readable*",
            1, 0
    )
| STATS
    Esql.alert_count = COUNT(*),
    Esql.first_seen = MIN(@timestamp),
    Esql.last_seen = MAX(@timestamp),
    Esql.total_risk = SUM(alert_risk),
    Esql.has_permission_change = MAX(is_permission_change),
    Esql.has_bulk_access = MAX(is_bulk_access),
    Esql.has_public_grant = MAX(is_public_grant),
    Esql.storage_action_count = COUNT(*),
    Esql.unique_rules = COUNT_DISTINCT(kibana.alert.rule.name),
    Esql.rule_names = VALUES(kibana.alert.rule.name),
    Esql.tactic_values = VALUES(kibana.alert.rule.threat.tactic.name),
    Esql.source_ips = VALUES(source.ip),
    Esql.cloud_providers = VALUES(cloud.provider)
  BY user.name, cloud.account.id
| WHERE Esql.storage_action_count >= 2
    AND (Esql.has_permission_change == 1 OR Esql.has_public_grant == 1)
| EVAL
    Esql.risk_score = Esql.total_risk,
    Esql.severity = CASE(
        Esql.has_public_grant == 1 AND Esql.has_bulk_access == 1, "critical",
        Esql.has_permission_change == 1 AND Esql.has_bulk_access == 1, "high",
        "medium"
    ),
    Esql.description = CONCAT(
        "Cloud storage exfiltration pattern by user ", user.name,
        " in account ", cloud.account.id,
        " | Permission change: ", TO_STRING(Esql.has_permission_change),
        " | Bulk access: ", TO_STRING(Esql.has_bulk_access),
        " | Public grant: ", TO_STRING(Esql.has_public_grant),
        " | ", TO_STRING(Esql.storage_action_count), " storage actions",
        " | Risk Score: ", TO_STRING(Esql.risk_score),
        " | Window: ", TO_STRING(Esql.first_seen), " to ", TO_STRING(Esql.last_seen)
    )
| SORT Esql.risk_score DESC
| LIMIT 50
```

## Strategy

Filters to cloud domain alerts and classifies them into storage-specific categories: permission changes, bulk access patterns, and public access grants. Aggregates by user and cloud account. Requires at least 2 storage-related actions AND either a permission change or a public access grant to fire. The permission change is the "preparation" step and the bulk access or public grant is the "execution" step of the exfiltration.

## Severity Logic

| Condition | Severity |
|-----------|----------|
| public_grant + bulk_download | Critical |
| permission_change + bulk_access | High |
| Fallback (permission change or public grant with 2+ actions) | Medium |

## Notes

- **Blind Spots:**
  - Data exfiltration through pre-signed URLs that do not generate additional alerts after initial URL generation
  - Cross-account exfiltration where the attacker copies data to an external account (the source account sees only the read, not the write)
  - Cloud storage access through SDKs or CLI tools that may not generate per-object alerts
  - Storage services not covered by alert rules (e.g., some organizations lack alerts for GCS or Azure Blob specifically)

- **False Positives:**
  - **Data migration projects**: Legitimate bulk data transfers between storage accounts. Mitigation: correlate with change management and known migration timelines.
  - **Backup operations**: Backup services that modify bucket policies and perform bulk reads. Mitigation: exclude known backup service accounts.
  - **Public website hosting**: Developers making S3 buckets public for static website hosting. Mitigation: exclude known web hosting buckets by name if available.

- **Tuning:**
  1. Customize the `is_permission_change`, `is_bulk_access`, and `is_public_grant` CASE patterns for your specific cloud detection rule names
  2. `storage_action_count` threshold (default: 2) -- keep low to catch the minimal exfiltration pattern (permission change + download)
  3. Add cloud resource identifier (e.g., S3 bucket name, GCS bucket name) to the STATS output if available for more precise investigation context
  4. Consider adding time-of-day weighting -- storage permission changes outside business hours warrant escalation

## Data Requirements

- **Index**: `.internal.alerts-security.alerts-default`
- **Required fields**: `user.name`, `cloud.account.id`, `event.dataset`, `signal.rule.severity`, `kibana.alert.rule.name`, `kibana.alert.rule.building_block_type`, `kibana.alert.rule.threat.tactic.name`, `@timestamp`, `source.ip`, `cloud.provider`
- **Minimum data sources**: At least one cloud provider integration with storage-specific detection rules (AWS CloudTrail with S3 data events, GCP Audit Logs, Azure Activity Logs)
- **Minimum volume**: 2+ cloud storage-related alerts for same user and account within 6h, including at least one permission change or public grant

## Dependencies

None required. Optional: `lookup-critical-assets` to identify cloud accounts containing sensitive data for severity escalation.

## Validation

In a test cloud account within a 2-hour window:
1. Change an S3 bucket policy to allow broader access (triggers bucket policy change alert)
2. Perform a bulk download of objects from the bucket (triggers bulk access or exfiltration alert)

Expected result: User and account combination appears with `Esql.has_permission_change == 1`, `Esql.has_bulk_access == 1`, severity of high.

## Elastic Comparison

Elastic ships individual cloud storage rules (e.g., "AWS S3 Bucket Policy Added to Share with External Account", "AWS CloudTrail Log Deleted") but does not correlate storage permission changes with subsequent bulk data access. CORR-5I detects the preparation-then-execution exfiltration pattern.
