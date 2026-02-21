# Cross-Tenant Correlation

---

## Metadata

- **Rule ID:** `CORR-4F`
- **Tier:** 4 — Meta-Correlation
- **Author:** Detection Engineering
- **Description:** Detect the same indicator of compromise appearing in alerts across two or more cloud accounts, tenants, or organizational boundaries. In multi-cloud and multi-tenant environments, an attacker who compromises one tenant often pivots to others using the same tooling and infrastructure. The same C2 IP appearing in both your AWS production account and your Azure development account is a strong campaign signal that entity-centric rules within a single tenant cannot detect.
- **Join Key(s):** `process.hash.sha256`, `destination.ip`, `dns.question.name` across `cloud.account.id` or `observer.name`
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
| EVAL
    shared_ioc = COALESCE(process.hash.sha256, destination.ip, dns.question.name),
    tenant_id = COALESCE(cloud.account.id, observer.name),
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
| WHERE shared_ioc IS NOT NULL
    AND tenant_id IS NOT NULL
| STATS
    Esql.tenant_count = COUNT_DISTINCT(tenant_id),
    Esql.tenant_values = VALUES(tenant_id),
    Esql.entity_count = COUNT_DISTINCT(entity),
    Esql.entity_values = VALUES(entity),
    Esql.alert_count = COUNT(*),
    Esql.risk_score = SUM(alert_risk),
    Esql.unique_rules = COUNT_DISTINCT(kibana.alert.rule.name),
    Esql.rule_names = VALUES(kibana.alert.rule.name),
    Esql.domain_count = COUNT_DISTINCT(domain_category),
    Esql.domain_values = VALUES(domain_category),
    Esql.first_seen = MIN(@timestamp),
    Esql.last_seen = MAX(@timestamp),
    Esql.max_severity_weight = MAX(severity_weight),
    Esql.tactic_values = VALUES(kibana.alert.rule.threat.tactic.name),
    Esql.host_values = VALUES(host.name),
    Esql.user_values = VALUES(user.name)
  BY shared_ioc
| WHERE Esql.tenant_count >= 2
| EVAL
    Esql.cross_tenant_score = ROUND(Esql.risk_score
        * CASE(Esql.tenant_count >= 3, 2.0, Esql.tenant_count >= 2, 1.5, 1.0)
        * CASE(Esql.entity_count >= 5, 1.5, 1.0)),
    Esql.correlation_severity = CASE(
        Esql.tenant_count >= 3, "critical",
        Esql.tenant_count >= 2 AND Esql.max_severity_weight >= 15, "high",
        Esql.tenant_count >= 2, "medium",
        "low"
    ),
    Esql.description = CONCAT(
        "Cross-tenant IOC: ", shared_ioc,
        " | ", TO_STRING(Esql.tenant_count), " tenants: ", TO_STRING(Esql.tenant_values),
        " | ", TO_STRING(Esql.entity_count), " entities",
        " | ", TO_STRING(Esql.alert_count), " alerts",
        " | ", TO_STRING(Esql.domain_count), " domains",
        " | Score: ", TO_STRING(Esql.cross_tenant_score)
    )
| SORT Esql.cross_tenant_score DESC
| LIMIT 50
```

## Strategy

Flattens each alert into its shared IOC using `COALESCE(process.hash.sha256, destination.ip, dns.question.name)`, then aggregates by that IOC across `cloud.account.id` values. The rule fires when 2+ distinct tenants/accounts share the same IOC. For organizations with multiple Elastic deployments behind a single SIEM, `observer.name` can serve as the tenant differentiator instead of `cloud.account.id`. Entity count provides spread context within each tenant. This rule is only relevant for organizations with multiple cloud accounts or tenants feeding into the same Elastic cluster.

## Severity Logic

| Condition | Severity |
|-----------|----------|
| tenant_count >= 3 (IOC in 3+ tenants) | Critical |
| tenant_count >= 2 AND alert severity includes high or critical | High |
| tenant_count >= 2 | Medium |

Cross-tenant score multipliers: tenant_count >= 3 = 2.0x, >= 2 = 1.5x. Entity count >= 5 = additional 1.5x.

## Notes

- **Blind Spots:**
  - **Single-tenant environments**: This rule is irrelevant for organizations with a single cloud account and no multi-tenant architecture. It will never fire.
  - **Different IOCs per tenant**: Sophisticated attackers may use unique tooling and infrastructure per tenant, producing no shared IOC across tenant boundaries.
  - **Tenant ID not populated**: If `cloud.account.id` and `observer.name` are both NULL for alerts, the rule excludes them. Ensure cloud integrations populate account identifiers.
  - **COALESCE priority**: Same limitation as CORR-4A -- IOC selection priority means alerts with multiple IOC fields will only be grouped by the highest-priority field.

- **False Positives:**
  - **Shared infrastructure across tenants**: Common administrative tools, monitoring agents, and shared services that operate across all tenants with the same binaries and endpoints. Mitigation: maintain a cross-tenant shared infrastructure allow-list.
  - **Cloud provider IPs**: AWS, Azure, and GCP service IPs that appear in alerts from multiple tenants. Mitigation: exclude cloud provider management plane IP ranges.
  - **Shared security tooling**: EDR agents, vulnerability scanners, and SIEM collectors that connect to the same destinations from all tenants. Mitigation: exclude known security tool IOCs.

- **Tuning:**
  1. **tenant_count threshold** (default: 2) -- in environments with 10+ tenants, consider raising to 3 to reduce noise from shared infrastructure.
  2. **Tenant identifier field** -- choose between `cloud.account.id` (cloud-native) and `observer.name` (multi-SIEM). Adjust the COALESCE order based on your architecture.
  3. **IOC exclusion list** -- critical for reducing false positives. Maintain a lookup of known cross-tenant shared IOCs (admin tool hashes, monitoring IPs, management domains).
  4. **Per-tenant baseline** -- consider adding per-tenant expected IOC counts to differentiate between "shared infra" and "shared attack."

## Data Requirements

- **Index**: `.internal.alerts-security.alerts-default`
- **Required fields**: `process.hash.sha256`, `destination.ip`, `dns.question.name`, `cloud.account.id`, `observer.name`, `user.name`, `host.name`, `event.dataset`, `signal.rule.severity`, `kibana.alert.workflow_status`, `kibana.alert.rule.building_block_type`, `kibana.alert.rule.name`, `kibana.alert.rule.threat.tactic.name`, `@timestamp`
- **Minimum volume**: 1+ alert with a shared IOC from 2+ distinct tenant identifiers in 24h

## Dependencies

- **Required**: None.
- **Prerequisite**: Multiple cloud accounts or tenants feeding alerts into the same Elastic cluster with `cloud.account.id` or `observer.name` populated.

## Validation

1. From two different cloud accounts (e.g., AWS account A and AWS account B), generate alerts that reference the same C2 IP address.
2. Ensure both accounts' alerts are ingested into the same `.internal.alerts-security.alerts-default` index with distinct `cloud.account.id` values.
3. CORR-4F should produce a cross-tenant alert with `Esql.tenant_count >= 2` and the shared C2 IP as `shared_ioc`.
4. Verify `Esql.tenant_values` lists both account IDs.
5. Verify severity resolves to "medium" (2 tenants) or "high" (2 tenants with high-severity underlying alerts).

## Elastic Comparison

Elastic does not ship a cross-tenant correlation rule. Elastic's multi-space and cross-cluster search features provide data access but not automated cross-tenant IOC correlation. The Risk Score engine operates per-entity within a single Kibana space. CORR-4F provides automated cross-boundary IOC correlation that Elastic does not offer natively. For Elastic Cloud deployments with multiple clusters, this rule requires cross-cluster replication or a centralized alert aggregation index.
