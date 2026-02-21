# Cloud IAM Abuse Chain

---

## Metadata

- **Rule ID:** `CORR-5C`
- **Tier:** 5 — Domain-Specific Correlation
- **Author:** Detection Engineering
- **Description:** Detect a single user performing multiple IAM-related actions within the same cloud account that together indicate privilege escalation or persistence establishment. The pattern of creating roles, attaching policies, and generating access keys is the canonical cloud IAM abuse chain -- each action individually may be legitimate, but the combination within a short window by the same user is a strong indicator of account compromise and privilege escalation.
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
    is_role_create = CASE(
        kibana.alert.rule.name LIKE "*Role*Creat*"
            OR kibana.alert.rule.name LIKE "*IAM*Role*"
            OR kibana.alert.rule.name LIKE "*Service Account*Creat*",
            1, 0
    ),
    is_policy_change = CASE(
        kibana.alert.rule.name LIKE "*Policy*Attach*"
            OR kibana.alert.rule.name LIKE "*Policy*Modif*"
            OR kibana.alert.rule.name LIKE "*Permission*Change*"
            OR kibana.alert.rule.name LIKE "*Privilege*Escalat*"
            OR kibana.alert.rule.name LIKE "*Admin*Policy*"
            OR kibana.alert.rule.name LIKE "*IAM*Policy*",
            1, 0
    ),
    is_key_create = CASE(
        kibana.alert.rule.name LIKE "*Access Key*Creat*"
            OR kibana.alert.rule.name LIKE "*API Key*"
            OR kibana.alert.rule.name LIKE "*Secret*Creat*"
            OR kibana.alert.rule.name LIKE "*Credential*Creat*"
            OR kibana.alert.rule.name LIKE "*Service Account Key*",
            1, 0
    )
| STATS
    Esql.alert_count = COUNT(*),
    Esql.first_seen = MIN(@timestamp),
    Esql.last_seen = MAX(@timestamp),
    Esql.total_risk_score = SUM(alert_risk),
    Esql.iam_action_count = COUNT(*),
    Esql.distinct_iam_actions = COUNT_DISTINCT(kibana.alert.rule.name),
    Esql.has_role_create = MAX(is_role_create),
    Esql.has_policy_change = MAX(is_policy_change),
    Esql.has_key_create = MAX(is_key_create),
    Esql.unique_rules = COUNT_DISTINCT(kibana.alert.rule.name),
    Esql.rule_names = VALUES(kibana.alert.rule.name),
    Esql.tactic_values = VALUES(kibana.alert.rule.threat.tactic.name),
    Esql.technique_values = VALUES(kibana.alert.rule.threat.technique.name),
    Esql.source_ips = VALUES(source.ip),
    Esql.cloud_providers = VALUES(cloud.provider)
  BY user.name, cloud.account.id
| WHERE Esql.distinct_iam_actions >= 3
| EVAL
    Esql.iam_combo_score = Esql.has_role_create + Esql.has_policy_change + Esql.has_key_create,
    Esql.risk_score = Esql.total_risk_score,
    Esql.correlation_severity = CASE(
        Esql.has_role_create == 1 AND Esql.has_policy_change == 1 AND Esql.has_key_create == 1, "critical",
        Esql.iam_combo_score >= 2, "high",
        Esql.distinct_iam_actions >= 3, "medium",
        "low"
    ),
    Esql.description = CONCAT(
        "Cloud IAM abuse chain by user ", user.name,
        " in account ", cloud.account.id,
        " | ", TO_STRING(Esql.distinct_iam_actions), " distinct IAM actions",
        " | Role create: ", TO_STRING(Esql.has_role_create),
        " | Policy change: ", TO_STRING(Esql.has_policy_change),
        " | Key create: ", TO_STRING(Esql.has_key_create),
        " | Risk Score: ", TO_STRING(Esql.risk_score),
        " | Window: ", TO_STRING(Esql.first_seen), " to ", TO_STRING(Esql.last_seen)
    )
| SORT Esql.risk_score DESC
| LIMIT 50
```

## Strategy

Filters to cloud domain alerts and uses alert rule names and technique metadata to classify IAM-related actions. Aggregates by the compound key of `user.name` and `cloud.account.id` to scope correlation within a single account. Tracks flags for the three critical IAM abuse indicators: role creation, policy changes, and key creation. Requires at least 3 distinct IAM actions to fire, ensuring the rule captures multi-step abuse rather than single administrative actions.

## Severity Logic

| Condition | Severity |
|-----------|----------|
| role_create + policy_change + key_create (all three) | Critical |
| Any 2 of role_create, policy_change, key_create | High |
| 3+ distinct IAM actions | Medium |

## Notes

- **Blind Spots:**
  - IAM abuse via the cloud console that does not generate distinct alerts per action (some providers batch console operations)
  - Cross-account role assumption chains where the attacker pivots between accounts (each account sees only partial activity)
  - Cloud providers not covered by the `event.dataset` filter patterns
  - Alert rule names that do not match the LIKE patterns in the `is_role_create`, `is_policy_change`, and `is_key_create` classifications

- **False Positives:**
  - **IaC deployments**: Terraform, CloudFormation, or Pulumi creating roles, attaching policies, and generating keys as part of automated infrastructure provisioning. Mitigation: exclude known IaC service accounts (e.g., `terraform-*`, `cloudformation-*`).
  - **Cloud administrator onboarding**: Admins setting up new service accounts with appropriate permissions. Mitigation: correlate with change management tickets.
  - **Security tool provisioning**: CSPM and CIEM tools that create audit roles and keys. Mitigation: add tool-specific service accounts to exclusion.

- **Tuning:**
  1. Customize the `is_role_create`, `is_policy_change`, and `is_key_create` CASE patterns to match your specific Elastic detection rule names for cloud IAM alerts
  2. `distinct_iam_actions` threshold (default: 3) -- lower to 2 if you have fewer cloud IAM detection rules
  3. Add `cloud.provider` to the severity logic if certain providers warrant higher severity (e.g., production AWS account vs. sandbox GCP project)
  4. Consider adding time-of-day logic -- IAM changes outside business hours warrant escalation

## Data Requirements

- **Index**: `.internal.alerts-security.alerts-default`
- **Required fields**: `user.name`, `cloud.account.id`, `event.dataset`, `signal.rule.severity`, `kibana.alert.rule.name`, `kibana.alert.rule.building_block_type`, `kibana.alert.rule.threat.tactic.name`, `@timestamp`, `source.ip`, `cloud.provider`
- **Minimum data sources**: At least one cloud provider integration (AWS CloudTrail, GCP Audit Logs, Azure Activity Logs)
- **Minimum volume**: 3+ cloud IAM-related alerts for same user and account within 6h

## Dependencies

None required. Optional: `lookup-critical-assets` to identify production cloud accounts for severity escalation.

## Validation

In a test cloud account within a 2-hour window:
1. Create a new IAM role (triggers IAM role creation alert)
2. Attach an administrator policy to the role (triggers policy attachment alert)
3. Create access keys for a new or existing user (triggers access key creation alert)

Expected result: User and account combination appears with `Esql.iam_combo_score == 3`, severity of critical.

## Elastic Comparison

Elastic ships individual cloud IAM rules (e.g., "AWS IAM User Created Access Keys", "AWS IAM Policy Attached to Role") but does not correlate them into a chain for the same user and account. Each fires independently. CORR-5C detects the multi-step IAM abuse pattern that is invisible when each alert is triaged in isolation.
