# Service Account Anomaly Correlation

---

## Metadata

- **Rule ID:** `CORR-1H`
- **Tier:** 1 — Entity-Centric Correlation
- **Author:** Detection Engineering
- **Description:** Detect service accounts generating alerts across three or more detection domains. Service accounts are excluded from CORR-1A because their cross-domain activity is expected — but they're also prime targets for attackers (broad privileges, no MFA, less scrutiny). HIGHER thresholds compensate for expected behavior.
- **Join Key(s):** `user.name`
- **Lookback:** 4 hours
- **Schedule:** Every 10 minutes
- **Priority:** P2
- **Integration:** [alerts](https://www.elastic.co/guide/en/security/current/alerts-ui-manage.html)
- **Language:** `[ES|QL]`

## Query

```esql
FROM .internal.alerts-security.alerts-default
| WHERE @timestamp > NOW() - 4 HOURS
    AND kibana.alert.workflow_status == "open"
    AND user.name IS NOT NULL
    AND (
        // Windows built-in service identities
        user.name IN ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE")
        // Windows machine accounts (trailing $)
        OR user.name LIKE "*$"
        // Common service account naming conventions
        OR user.name LIKE "svc-*" OR user.name LIKE "svc_*" OR user.name LIKE "svc.*"
        OR user.name LIKE "*-svc" OR user.name LIKE "*_svc"
        OR user.name LIKE "service-*" OR user.name LIKE "service_*"
        OR user.name LIKE "sa-*" OR user.name LIKE "sa_*"
        OR user.name LIKE "app-*" OR user.name LIKE "app_*"
        OR user.name LIKE "api-*" OR user.name LIKE "api_*"
        OR user.name LIKE "bot-*" OR user.name LIKE "bot_*"
        OR user.name LIKE "task-*" OR user.name LIKE "task_*"
        OR user.name LIKE "cron-*" OR user.name LIKE "cron_*"
        // Microsoft infrastructure accounts
        OR user.name LIKE "MSOL_*" OR user.name LIKE "HealthMail*"
        OR user.name LIKE "SM_*" OR user.name LIKE "AAD_*"
        OR user.name LIKE "Sync_*" OR user.name LIKE "ADSync*"
        // Shared/functional mailboxes and noreply
        OR user.name LIKE "noreply*" OR user.name LIKE "no-reply*"
        OR user.name LIKE "mailbox-*" OR user.name LIKE "shared-*"
        // LOOKUP JOIN enrichment below catches registered accounts not matching patterns
    )
| EVAL
    domain_category = CASE(
        event.dataset LIKE "endpoint*" OR event.dataset LIKE "sentinelone*"
            OR event.dataset LIKE "windows*" OR event.dataset LIKE "sysmon*", "endpoint",
        event.dataset LIKE "okta*" OR event.dataset LIKE "azure_ad*"
            OR event.dataset LIKE "entra*", "identity",
        event.dataset LIKE "aws*" OR event.dataset LIKE "gcp*"
            OR event.dataset LIKE "azure*" OR event.dataset LIKE "o365*", "cloud",
        event.dataset LIKE "panw*" OR event.dataset LIKE "fortinet*"
            OR event.dataset LIKE "firewall*", "network_fw",
        event.dataset LIKE "extrahop*" OR event.dataset LIKE "zeek*"
            OR event.dataset LIKE "suricata*", "network_ndr",
        event.dataset LIKE "proxy*" OR event.dataset LIKE "zscaler*", "proxy",
        event.dataset LIKE "dns*", "dns",
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
    Esql.tactic_count = COUNT_DISTINCT(kibana.alert.rule.threat.tactic.name),
    Esql.tactic_values = VALUES(kibana.alert.rule.threat.tactic.name),
    Esql.unique_rules = COUNT_DISTINCT(kibana.alert.rule.name),
    Esql.rule_names = VALUES(kibana.alert.rule.name),
    Esql.domain_count = COUNT_DISTINCT(domain_category),
    Esql.domain_values = VALUES(domain_category),
    Esql.host_count = COUNT_DISTINCT(host.name),
    Esql.host_values = VALUES(host.name),
    Esql.source_ip_count = COUNT_DISTINCT(source.ip)
  BY user.name
// --- Optional: LOOKUP JOIN for expected-domain comparison ---
// If lookup-service-accounts is available, enrich with expected behavior.
// If not available, remove this block — the rule still functions on pattern matching alone.
| LOOKUP JOIN lookup-service-accounts ON user.name
| EVAL
    Esql.is_registered = CASE(svc.owner_team IS NOT NULL, true, false),
    Esql.expected_domains = COALESCE(svc.expected_domains, "unknown"),
    Esql.svc_risk_tier = COALESCE(svc.risk_tier, "unregistered")
// --- End optional LOOKUP JOIN block ---
| WHERE Esql.domain_count >= 3
| EVAL
    Esql.correlation_severity = CASE(
        Esql.total_risk_score >= 150 OR Esql.domain_count >= 5, "critical",
        Esql.total_risk_score >= 75 OR Esql.domain_count >= 4, "high",
        Esql.total_risk_score >= 40, "medium",
        "low"
    ),
    Esql.description = CONCAT(
        "Service account ", user.name,
        " [", Esql.svc_risk_tier, "]",
        " | Risk: ", TO_STRING(Esql.total_risk_score),
        " | ", TO_STRING(Esql.domain_count), " domains (threshold: 3)",
        " | ", TO_STRING(Esql.unique_rules), " rules",
        " | ", TO_STRING(Esql.host_count), " hosts",
        " | Expected domains: ", Esql.expected_domains
    )
| SORT Esql.total_risk_score DESC
| LIMIT 50
```

## Strategy

Inverts CORR-1A's exclusion — ONLY matches service account patterns using a comprehensive naming convention list covering Windows built-ins, machine accounts ($), common prefixes (svc-, app-, api-, bot-, task-, cron-), Microsoft infrastructure accounts (MSOL_, AAD_, Sync_), and functional mailboxes. An optional LOOKUP JOIN against `lookup-service-accounts` enriches with owner team, expected domains, and risk tier. domain_count threshold raised to 3 (vs 2 for CORR-1A). Risk thresholds elevated 50% (150/75/40 vs 100/50/25). If the LOOKUP JOIN is unavailable, remove that block — the rule still functions on pattern matching alone.

## Severity Logic

| Condition | Severity |
|-----------|----------|
| risk_score >= 150 OR domain_count >= 5 | Critical |
| risk_score >= 75 OR domain_count >= 4 | High |
| risk_score >= 40 | Medium |
| Everything else crossing threshold | Low |

## Notes

- **Blind Spots:**
  - Attackers who compromise accounts not matching naming patterns (caught by CORR-1A instead)
  - Custom naming schemes not in WHERE clause — add your organization's conventions (e.g., `run-*`, `batch_*`, `infra-*`)
  - Cloud provider-managed identities (AWS Lambda execution roles, GCP service accounts with email format, Azure Managed Identities) may not match these patterns — register them in `lookup-service-accounts`
- **False Positives:**
  - Orchestration tools (Ansible, Terraform, SCCM) operating across multiple domains by design. Mitigation: register in `lookup-service-accounts` with expected domains.
  - Backup agents (Veeam, Commvault) touching endpoint + cloud + network. Mitigation: register with expected domains.
  - CI/CD pipelines (Jenkins, GitHub Actions runners) authenticating across identity + cloud + endpoint. Mitigation: register with expected domains.
- **Tuning:**
  1. Add organization-specific service account naming patterns to the WHERE clause
  2. Register known service accounts in `lookup-service-accounts` with expected domain activity
  3. Adjust `domain_count` threshold (default: 3) based on service account behavior
  4. Use the `Esql.svc_risk_tier` enrichment to apply different thresholds for tier1_critical vs tier3_low service accounts
  5. If `lookup-service-accounts` is unavailable, remove the LOOKUP JOIN block — the rule still functions on naming pattern matching

## Data Requirements

- **Index**: `.internal.alerts-security.alerts-default`
- **Required fields**: `user.name`, `event.dataset`, `signal.rule.severity`, `kibana.alert.workflow_status`, `kibana.alert.rule.building_block_type`, `kibana.alert.rule.name`, `kibana.alert.rule.threat.tactic.name`, `@timestamp`, `host.name`, `source.ip`
- **Minimum volume**: 3+ alerts from 3+ domains for same service account in 4h

## Dependencies

- **Optional**: `lookup-service-accounts` — enriches with owner team, expected domains, and risk tier. If unavailable, remove the LOOKUP JOIN block from the query. The rule still functions on naming pattern matching alone.

## Validation

Compromise svc-backup-agent -> authenticate to Okta (identity, not expected) -> enumerate cloud resources (cloud) -> lateral movement to workstation (endpoint). domain_count = 3.

## Elastic Comparison

No Elastic service-account-specific cross-domain correlation rule.
