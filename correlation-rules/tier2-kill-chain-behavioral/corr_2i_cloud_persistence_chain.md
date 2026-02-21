# Cloud Persistence Chain

---

## Metadata

- **Rule ID:** `CORR-2I`
- **Tier:** 2 — Kill Chain and Behavioral Correlation
- **Author:** Detection Engineering
- **Description:** Detect cloud attack chains spanning authentication anomaly, IAM/permission modification, and resource creation/modification. This three-stage sequence — compromise cloud identity, escalate permissions, establish persistence via new resources — is the canonical cloud intrusion playbook. Presence of 2+ of these 3 stages for the same user within 6 hours indicates an active cloud compromise.
- **Join Key(s):** `user.name`, `cloud.account.id`
- **Lookback:** 6 hours
- **Schedule:** Every 15 minutes
- **Priority:** P2
- **Integration:** [alerts](https://www.elastic.co/guide/en/security/current/alerts-ui-manage.html)
- **Language:** `[ES|QL]`

## Query

```esql
FROM .internal.alerts-security.alerts-default
| WHERE @timestamp > NOW() - 6 HOURS
    AND kibana.alert.workflow_status == "open"
    AND user.name IS NOT NULL
    AND (
        event.dataset LIKE "aws*" OR event.dataset LIKE "gcp*"
        OR event.dataset LIKE "azure*" OR event.dataset LIKE "o365*"
        OR event.dataset LIKE "okta*" OR event.dataset LIKE "entra*"
        OR event.dataset LIKE "cloud*"
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
    cloud_stage = CASE(
        kibana.alert.rule.name LIKE "*impossible travel*"
            OR kibana.alert.rule.name LIKE "*suspicious login*"
            OR kibana.alert.rule.name LIKE "*MFA*bypass*"
            OR kibana.alert.rule.name LIKE "*brute force*"
            OR kibana.alert.rule.name LIKE "*anomalous*login*"
            OR kibana.alert.rule.name LIKE "*unusual*auth*"
            OR kibana.alert.rule.name LIKE "*password spray*"
            OR kibana.alert.rule.name LIKE "*credential stuff*"
            OR kibana.alert.rule.name LIKE "*unauthorized*access*"
            OR kibana.alert.rule.parameters.threat.tactic.name == "Initial Access", "auth",
        kibana.alert.rule.name LIKE "*IAM*"
            OR kibana.alert.rule.name LIKE "*iam*"
            OR kibana.alert.rule.name LIKE "*role*creat*"
            OR kibana.alert.rule.name LIKE "*role*modif*"
            OR kibana.alert.rule.name LIKE "*policy*attach*"
            OR kibana.alert.rule.name LIKE "*policy*modif*"
            OR kibana.alert.rule.name LIKE "*permission*change*"
            OR kibana.alert.rule.name LIKE "*privilege*escalat*"
            OR kibana.alert.rule.name LIKE "*access key*creat*"
            OR kibana.alert.rule.name LIKE "*service account*creat*"
            OR kibana.alert.rule.parameters.threat.tactic.name == "Privilege Escalation", "iam_change",
        kibana.alert.rule.name LIKE "*instance*launch*"
            OR kibana.alert.rule.name LIKE "*instance*creat*"
            OR kibana.alert.rule.name LIKE "*VM*creat*"
            OR kibana.alert.rule.name LIKE "*bucket*creat*"
            OR kibana.alert.rule.name LIKE "*storage*creat*"
            OR kibana.alert.rule.name LIKE "*lambda*creat*"
            OR kibana.alert.rule.name LIKE "*function*creat*"
            OR kibana.alert.rule.name LIKE "*resource*creat*"
            OR kibana.alert.rule.name LIKE "*security group*modif*"
            OR kibana.alert.rule.name LIKE "*network*modif*"
            OR kibana.alert.rule.parameters.threat.tactic.name == "Persistence", "resource_mod",
        "other"
    ),
    is_auth = CASE(cloud_stage == "auth", 1, 0),
    is_iam_change = CASE(cloud_stage == "iam_change", 1, 0),
    is_resource_mod = CASE(cloud_stage == "resource_mod", 1, 0)
| STATS
    Esql.alert_count = COUNT(*),
    Esql.first_seen = MIN(@timestamp),
    Esql.last_seen = MAX(@timestamp),
    Esql.total_risk = SUM(alert_risk),
    Esql.has_auth = MAX(is_auth),
    Esql.has_iam = MAX(is_iam_change),
    Esql.has_resource = MAX(is_resource_mod),
    Esql.auth_count = SUM(is_auth),
    Esql.iam_count = SUM(is_iam_change),
    Esql.resource_count = SUM(is_resource_mod),
    Esql.tactic_values = VALUES(kibana.alert.rule.parameters.threat.tactic.name),
    Esql.unique_rules = COUNT_DISTINCT(kibana.alert.rule.name),
    Esql.rule_names = VALUES(kibana.alert.rule.name),
    Esql.cloud_accounts = VALUES(cloud.account.id),
    Esql.cloud_providers = VALUES(cloud.provider),
    Esql.ip_values = VALUES(source.ip)
  BY user.name
| EVAL
    Esql.stages_present = Esql.has_auth + Esql.has_iam + Esql.has_resource
| WHERE Esql.stages_present >= 2
| EVAL
    Esql.risk_score = ROUND(Esql.total_risk * Esql.stages_present),
    Esql.correlation_severity = CASE(
        Esql.stages_present >= 3, "critical",
        Esql.has_auth == 1 AND Esql.has_iam == 1, "high",
        Esql.has_iam == 1 AND Esql.has_resource == 1, "high",
        "medium"
    ),
    Esql.description = CONCAT(
        "User ", user.name,
        " | Cloud Persistence Chain",
        " | Stages: ", TO_STRING(Esql.stages_present), "/3",
        " (auth=", TO_STRING(Esql.has_auth),
        " iam=", TO_STRING(Esql.has_iam),
        " resource=", TO_STRING(Esql.has_resource), ")",
        " | Risk Score: ", TO_STRING(Esql.risk_score),
        " | Cloud accounts: ", TO_STRING(Esql.cloud_accounts),
        " | ", TO_STRING(Esql.unique_rules), " rules",
        " | ", TO_STRING(Esql.alert_count), " alerts",
        " | Window: ", TO_STRING(Esql.first_seen), " to ", TO_STRING(Esql.last_seen)
    )
| SORT Esql.risk_score DESC
| LIMIT 50
```

## Strategy

Each alert is mapped to a cloud attack stage: authentication anomalies (impossible travel, suspicious login, MFA bypass) map to "auth", IAM/role/policy changes map to "iam_change", and resource creation/modification (VM launch, storage creation, Lambda deployment) map to "resource_mod". STATS aggregates by `user.name` to determine which stages are present. Users with 2+ stages pass filtering. The risk score is multiplied by the number of stages present. The 6-hour lookback accommodates the slower pace of cloud attack chains.

## Severity Logic

```
CASE(
    Esql.stages_present >= 3, "critical",
    Esql.has_auth == 1 AND Esql.has_iam == 1, "high",
    Esql.has_iam == 1 AND Esql.has_resource == 1, "high",
    "medium"
)
```

| Condition | Severity |
|-----------|----------|
| All 3 cloud stages present (auth anomaly + IAM change + resource mod) | Critical |
| Auth anomaly + IAM/permission change | High |
| IAM/permission change + resource creation/modification | High |
| Any other 2-stage combination | Medium |

## Notes

- **Blind Spots:**
  - Cross-account attacks where the attacker assumes a role in a different account — the `user.name` may change across accounts
  - Assumed role chains that obscure the original identity (e.g., AssumeRole -> AssumeRole chains in AWS)
  - CloudTrail gaps — if cloud audit logging is incomplete, stages may be invisible
  - Cloud alerts from providers not matching the `event.dataset` filter patterns

- **False Positives:**
  - **DevOps deploying infrastructure as code**: Terraform or CloudFormation deployments naturally involve auth, IAM changes, and resource creation. Mitigation: register IaC service accounts in `lookup-service-accounts` and exclude from this rule.
  - **Scheduled IAM rotation processes**: Automated key rotation triggers IAM alerts + new resource creation. Mitigation: identify rotation schedules and suppress.
  - **Cloud migration activities**: Large-scale migrations involve many IAM and resource changes. Mitigation: maintain a migration-active accounts list.

- **Tuning:**
  1. Cloud stage classification — customize patterns for your cloud detection rule naming conventions
  2. Lookback window (default: 6h) — extend to 12h for cloud environments with slower attack progression
  3. Add cloud account context: if `cloud.account.id` changes between stages, this is a cross-account attack and should be severity-escalated
  4. Add geographic context: correlate `source.ip` geographic location across stages for additional anomaly signal
  5. Consider filtering to specific cloud providers if multi-cloud alerts are generating FPs from routine operations

## Data Requirements

- **Index**: `.internal.alerts-security.alerts-default`
- **Required fields**: `user.name`, `@timestamp`, `signal.rule.severity`, `kibana.alert.workflow_status`, `kibana.alert.rule.building_block_type`, `kibana.alert.rule.name`, `kibana.alert.rule.parameters.threat.tactic.name`, `event.dataset`, `cloud.account.id`, `cloud.provider`, `source.ip`
- **Minimum volume**: 2+ cloud alerts matching 2+ distinct cloud attack stages for same `user.name` within 6h
- **Critical dependency**: Cloud provider audit logging (CloudTrail, Azure Activity Log, GCP Audit Log) must be ingested and generating detection alerts

## Dependencies

- No required lookup indices
- Prerequisite: Cloud detection rules covering authentication anomalies, IAM changes, and resource modifications must be deployed
- Optional: `lookup-service-accounts` — exclude known IaC and automation service accounts
- Complementary: CORR-1F (Cloud Resource correlation) catches cloud instance-centric patterns; CORR-2I catches user-centric cloud attack chains

## Validation

Red team scenario:
1. Log in to AWS from an unusual location or VPN exit point (triggers auth anomaly alert)
2. Create a new IAM role with AdministratorAccess policy (triggers IAM change alert)
3. Launch an EC2 instance using the new role (triggers resource creation alert)

Expected result: User appears with `Esql.stages_present = 3`, severity = critical, risk score = `SUM(alert_risk) * 3`.

## Elastic Comparison

Elastic does not ship a cloud persistence chain correlation rule. Individual cloud rules exist (e.g., "AWS IAM Roles Created", "AWS EC2 Instance Created with New Key Pair") but are not correlated into a multi-stage cloud attack chain. CORR-2I connects authentication anomalies to IAM changes to resource creation, surfacing the complete cloud compromise progression.
