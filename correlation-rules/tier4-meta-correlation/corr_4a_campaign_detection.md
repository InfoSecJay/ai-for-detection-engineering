# Campaign Detection

---

## Metadata

- **Rule ID:** `CORR-4A`
- **Tier:** 4 — Meta-Correlation
- **Author:** Detection Engineering
- **Description:** Detect campaigns where the same indicator of compromise (file hash, IP address, domain name, or URL) appears in alerts involving three or more distinct entities within 24 hours. An IOC touching one entity is an incident. The same IOC touching three or more distinct users or hosts is a campaign -- either active lateral movement, a supply chain compromise, or a commodity malware wave. This rule surfaces the shared IOC as the campaign pivot point.
- **Join Key(s):** `process.hash.sha256`, `destination.ip`, `dns.question.name`, `url.domain`
- **Lookback:** 24 hours
- **Schedule:** Every 30 minutes
- **Priority:** P1
- **Integration:** [alerts](https://www.elastic.co/guide/en/security/current/alerts-ui-manage.html)
- **Language:** `[ES|QL]`

## Query

```esql
FROM .internal.alerts-security.alerts-default
| WHERE @timestamp > NOW() - 24 HOURS
    AND kibana.alert.workflow_status == "open"
| EVAL
    shared_ioc = COALESCE(process.hash.sha256, destination.ip, dns.question.name, url.domain),
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
    AND entity IS NOT NULL
| STATS
    Esql.entity_count = COUNT_DISTINCT(entity),
    Esql.alert_count = COUNT(*),
    Esql.unique_rules = COUNT_DISTINCT(kibana.alert.rule.name),
    Esql.rule_names = VALUES(kibana.alert.rule.name),
    Esql.domain_count = COUNT_DISTINCT(domain_category),
    Esql.domain_values = VALUES(domain_category),
    Esql.risk_score = SUM(alert_risk),
    Esql.first_seen = MIN(@timestamp),
    Esql.last_seen = MAX(@timestamp),
    Esql.entity_values = VALUES(entity),
    Esql.tactic_values = VALUES(kibana.alert.rule.parameters.threat.tactic.name),
    Esql.tactic_count = COUNT_DISTINCT(kibana.alert.rule.parameters.threat.tactic.name),
    Esql.host_values = VALUES(host.name),
    Esql.user_values = VALUES(user.name)
  BY shared_ioc
| WHERE Esql.entity_count >= 3
| EVAL
    Esql.campaign_score = ROUND(Esql.risk_score
        * CASE(Esql.entity_count >= 10, 2.0, Esql.entity_count >= 5, 1.5, 1.0)
        * CASE(Esql.domain_count >= 3, 1.5, Esql.domain_count >= 2, 1.25, 1.0)),
    Esql.severity = CASE(
        Esql.entity_count >= 10, "critical",
        Esql.entity_count >= 5, "high",
        Esql.entity_count >= 3, "medium",
        "low"
    ),
    Esql.description = CONCAT(
        "Campaign IOC: ", shared_ioc,
        " | ", TO_STRING(Esql.entity_count), " entities affected",
        " | ", TO_STRING(Esql.alert_count), " total alerts",
        " | ", TO_STRING(Esql.unique_rules), " rules",
        " | ", TO_STRING(Esql.domain_count), " domains",
        " | Risk: ", TO_STRING(Esql.campaign_score),
        " | Window: ", TO_STRING(Esql.first_seen), " to ", TO_STRING(Esql.last_seen)
    )
| SORT Esql.campaign_score DESC
| LIMIT 50
```

## Strategy

Flattens each alert into its most specific IOC using `COALESCE(process.hash.sha256, destination.ip, dns.question.name, url.domain)`, then aggregates by that IOC across all entities. Entity count is computed via `COUNT_DISTINCT(COALESCE(user.name, host.name))` to deduplicate users and hosts into a single entity space. The rule fires when the same IOC spans three or more distinct entities. Risk score is the sum of individual alert risk scores across all entities sharing the IOC. Domain diversity (how many detection domains saw the IOC) provides additional campaign confidence.

## Severity Logic

| Condition | Severity |
|-----------|----------|
| entity_count >= 10 (IOC across 10+ entities) | Critical |
| entity_count >= 5 (IOC across 5-9 entities) | High |
| entity_count >= 3 (IOC across 3-4 entities) | Medium |

Campaign score multipliers: entity_count >= 10 = 2.0x, >= 5 = 1.5x base risk. Domain diversity >= 3 = additional 1.5x, >= 2 = 1.25x.

## Notes

- **Blind Spots:**
  - **Polymorphic malware**: Malware that generates a unique hash per target will not share a `process.hash.sha256` across entities. Each infection appears as an isolated incident.
  - **IP rotation per victim**: Attackers using different C2 infrastructure (IP, domain) per compromised entity will not produce a shared IOC.
  - **Legitimate shared services**: CDN IPs, popular SaaS domains, and shared infrastructure create false IOC overlap. Well-known benign IOCs must be excluded.
  - **COALESCE priority**: The IOC selection uses COALESCE priority order (hash > IP > domain > URL). An alert with both a hash and a destination IP will only be grouped by hash. If different alerts for the same campaign populate different IOC fields, they will not cluster.

- **False Positives:**
  - **Common legitimate software hashes**: Widely deployed binaries (e.g., Chrome updater, Zoom installer) trigger alerts on multiple hosts with the same hash. Mitigation: maintain an allow-list of known-good hashes or exclude LOLBin hashes.
  - **Shared DNS names**: Common domains like `microsoft.com`, `google.com`, `amazonaws.com` appear across many entities. Mitigation: exclude well-known benign domains via a lookup or WHERE clause.
  - **CDN and cloud provider IPs**: Destination IPs belonging to major CDN providers (Cloudflare, Akamai, Fastly) will cluster many entities. Mitigation: exclude known CDN CIDR ranges.
  - **Software deployment waves**: SCCM/Intune deployments push the same binary to many hosts simultaneously. Mitigation: cross-reference with change management windows.

- **Tuning:**
  1. **entity_count threshold** (default: 3) -- raise to 5 in large environments (10,000+ endpoints) to reduce noise from commodity software.
  2. **shared_ioc exclusion list** -- maintain a lookup of known-benign hashes, IPs, and domains. The most impactful tuning lever for this rule.
  3. **Lookback window** (default: 24h) -- reduce to 8h if campaign detection speed matters more than catch-all coverage.
  4. **COALESCE field order** -- adjust priority based on your telemetry. If your environment has strong DNS visibility but weak hash visibility, consider reordering.
  5. **Campaign score multipliers** -- adjust the entity_count and domain_count multipliers based on your environment size.

## Data Requirements

- **Index**: `.internal.alerts-security.alerts-default`
- **Required fields**: `process.hash.sha256`, `destination.ip`, `dns.question.name`, `url.domain`, `user.name`, `host.name`, `event.dataset`, `signal.rule.severity`, `kibana.alert.workflow_status`, `kibana.alert.rule.building_block_type`, `kibana.alert.rule.name`, `kibana.alert.rule.parameters.threat.tactic.name`, `@timestamp`
- **Minimum volume**: 3+ entities with alerts sharing the same IOC value in 24h

## Dependencies

- **Required**: None.
- **Recommended**: IOC allow-list (benign hashes, CDN IPs, common domains) as a lookup index or inline exclusion.
- **Upstream**: Benefits from Tiers 1-3 populating domain categories and risk scores on alerts.

## Validation

1. Deploy the same custom malware hash (or benign test binary flagged by a test rule) to 5 different hosts operated by different users.
2. Ensure each deployment triggers at least one alert with `process.hash.sha256` populated.
3. Within 24 hours, CORR-4A should produce a campaign cluster with `Esql.entity_count >= 5` and the shared hash as the `shared_ioc`.
4. Validate that `Esql.entity_values` lists all 5 distinct entities.
5. Verify that severity resolves to "high" (5 entities).

## Elastic Comparison

Elastic does not ship a campaign detection rule. The closest feature is the Risk Score engine, which accumulates risk per entity but does not pivot on shared IOCs across entities. Elastic's "Threat Intel Indicator Match" rules match single alerts against TI feeds but do not aggregate IOC-entity relationships across the environment. CORR-4A provides environment-wide IOC campaign clustering that Elastic does not offer natively.
