# First-Time Cross-Domain Link

---

## Metadata

- **Rule ID:** `CORR-6H`
- **Tier:** 6 — Novelty and Anomaly Detection
- **Author:** Detection Engineering
- **Description:** Detect entities appearing in detection domains they have never historically been associated with. A user who has only ever appeared in identity-domain alerts (Okta, Azure AD) suddenly generating endpoint-domain alerts (EDR, Sysmon) represents a fundamental shift in that entity's risk profile. This rule identifies the first time an entity crosses into a new detection domain.
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
    AND (user.name IS NOT NULL OR host.name IS NOT NULL)
| EVAL
    entity = COALESCE(user.name, host.name),
    domain_category = CASE(
        event.dataset LIKE "endpoint*" OR event.dataset LIKE "sentinelone*"
            OR event.dataset LIKE "windows*" OR event.dataset LIKE "sysmon*"
            OR event.dataset LIKE "microsoft-defender*" OR event.dataset LIKE "crowdstrike*"
            OR event.dataset LIKE "carbon_black*", "endpoint",
        event.dataset LIKE "okta*" OR event.dataset LIKE "azure_ad*"
            OR event.dataset LIKE "entra*" OR event.dataset LIKE "onelogin*"
            OR event.dataset LIKE "ping*" OR event.dataset LIKE "auth0*", "identity",
        event.dataset LIKE "aws*" OR event.dataset LIKE "gcp*"
            OR event.dataset LIKE "azure*" OR event.dataset LIKE "cloud*"
            OR event.dataset LIKE "o365*", "cloud",
        event.dataset LIKE "panw*" OR event.dataset LIKE "fortinet*"
            OR event.dataset LIKE "firewall*" OR event.dataset LIKE "paloalto*"
            OR event.dataset LIKE "checkpoint*", "network_fw",
        event.dataset LIKE "extrahop*" OR event.dataset LIKE "zeek*"
            OR event.dataset LIKE "suricata*" OR event.dataset LIKE "ndr*", "network_ndr",
        event.dataset LIKE "proxy*" OR event.dataset LIKE "zscaler*"
            OR event.dataset LIKE "bluecoat*" OR event.dataset LIKE "squid*", "proxy",
        event.dataset LIKE "dns*", "dns",
        event.dataset LIKE "email*" OR event.dataset LIKE "proofpoint*"
            OR event.dataset LIKE "mimecast*", "email",
        COALESCE(labels.technology, event.module, "unknown")
    ),
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
| RENAME entity AS entity_value
| LOOKUP JOIN lookup-entity-history ON entity_value
| RENAME entity_value AS entity
| EVAL
    Esql.is_new_domain = CASE(
        known_domains IS NULL, true,
        NOT domain_category IN (known_domains), true,
        false
    )
// NOTE: The IN operator above requires `known_domains` to be a multi-valued keyword array field, NOT a comma-separated string.
| WHERE Esql.is_new_domain == true
| STATS
    Esql.new_domain_alerts = COUNT(*),
    Esql.new_domains = VALUES(domain_category),
    Esql.new_domain_count = COUNT_DISTINCT(domain_category),
    Esql.risk_score = SUM(alert_risk),
    Esql.max_severity = MAX(severity_weight),
    Esql.high_critical_count = SUM(is_high_or_critical),
    Esql.first_seen = MIN(@timestamp),
    Esql.last_seen = MAX(@timestamp),
    Esql.rule_names = VALUES(kibana.alert.rule.name),
    Esql.unique_rules = COUNT_DISTINCT(kibana.alert.rule.name),
    Esql.tactic_values = VALUES(kibana.alert.rule.threat.tactic.name),
    Esql.host_values = VALUES(host.name),
    Esql.source_ips = VALUES(source.ip)
  BY entity
| EVAL
    Esql.correlation_severity = CASE(
        Esql.max_severity >= 15 AND domain_category == "endpoint", "critical",
        Esql.new_domain_count >= 2, "high",
        Esql.new_domain_count >= 1, "medium",
        "medium"
    ),
    Esql.description = CONCAT(
        "Entity ", entity,
        " appeared in ", TO_STRING(Esql.new_domain_count),
        " NEW domain(s): ", TO_STRING(Esql.new_domains),
        " | ", TO_STRING(Esql.new_domain_alerts), " alerts from ",
        TO_STRING(Esql.unique_rules), " rules",
        " | Risk: ", TO_STRING(Esql.risk_score)
    )
| SORT Esql.risk_score DESC
| LIMIT 50
```

## Strategy

Each alert is categorized into a detection domain using the standard domain categorization pattern. The entity's historically known domains are retrieved from `lookup-entity-history` via `LOOKUP JOIN`. Alerts in domains not present in the entity's historical `known_domains` field are flagged as novel cross-domain links. The rule aggregates these novel-domain alerts per entity and applies severity based on which domains are new and the severity of associated alerts.

## Severity Logic

| Condition | Severity |
|-----------|----------|
| User appearing in endpoint domain for first time + high/critical alert | Critical |
| Entity in 2+ new domains | High |
| Entity in 1 new domain | Medium |

## Notes

- **Blind Spots:**
  - **New entities**: Entities with no history in `lookup-entity-history` (where `known_domains IS NULL`) have all domains appear as new. This produces noise until the entity's baseline is established.
  - **Domain categorization changes**: If the domain categorization logic is updated, previously categorized alerts may now fall into different domains, causing false novelty signals.
  - **Shared entity names**: Common usernames (e.g., "admin") across different systems may conflate domain histories.

- **False Positives:**
  - **Users getting new responsibilities**: A finance user given access to cloud infrastructure legitimately appears in cloud-domain alerts for the first time. Mitigation: integrate with HR role-change notifications.
  - **Systems being repurposed**: A workstation converted to a server may begin generating network-domain alerts. Mitigation: update asset inventory and refresh baselines.
  - **New data source onboarding**: Adding a new EDR tool means all entities appear in endpoint domain for the "first time" from that tool's perspective. Mitigation: refresh baselines after onboarding new data sources.

- **Tuning:**
  1. Suppress entities less than 14 days old (no established domain profile)
  2. Treat `known_domains IS NULL` as informational rather than alerting
  3. Weight certain domain transitions higher (identity-to-endpoint is more suspicious than cloud-to-identity)
  4. Update `lookup-entity-history` known_domains field daily
  5. Consider a "domain transition suspiciousness" matrix: some transitions are benign, others are red flags

## Data Requirements

- **Index**: `.internal.alerts-security.alerts-default`
- **Lookup Index**: `lookup-entity-history` (fields: `entity_value`, `known_domains`, `first_seen`, `rule_name`)
  - **IMPORTANT**: The `known_domains` field in `lookup-entity-history` MUST be stored as a multi-valued keyword array (not a comma-separated string) for the IN operator to work correctly. When indexing, ensure each domain category is a separate array element.
- **Required fields**: `user.name`, `host.name`, `event.dataset`, `signal.rule.severity`, `kibana.alert.rule.building_block_type`, `kibana.alert.workflow_status`, `@timestamp`, `kibana.alert.rule.name`, `kibana.alert.rule.threat.tactic.name`, `source.ip`
- **Minimum volume**: Entity domain history populated from 30+ days of alert data

## Dependencies

- **Required**: `lookup-entity-history` -- must contain per-entity `known_domains` field
- **Optional**: `lookup-critical-assets` for severity escalation on critical assets crossing domains

## Validation

1. Identify a user who has historically only appeared in identity-domain alerts (Okta/Azure AD)
2. Trigger an endpoint alert for that user (e.g., suspicious process execution on a workstation they log into)
3. Verify CORR-6H surfaces the user with `Esql.new_domains` containing "endpoint"
4. Confirm that an alert in the user's already-known domain does NOT trigger CORR-6H

## Elastic Comparison

Elastic does not ship a cross-domain novelty rule. The closest capability is the Entity Analytics risk score, which accumulates risk across domains but does not flag the first-time domain crossing as a distinct signal. CORR-6H provides a unique "domain boundary crossing" detection that is not available in any Elastic built-in rule.
