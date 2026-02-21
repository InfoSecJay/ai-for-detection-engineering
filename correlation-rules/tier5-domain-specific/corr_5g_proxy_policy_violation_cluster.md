# Proxy Policy Violation Cluster

---

## Metadata

- **Rule ID:** `CORR-5G`
- **Tier:** 5 — Domain-Specific Correlation
- **Author:** Detection Engineering
- **Description:** Detect a single user or source IP generating a cluster of proxy policy violation alerts across multiple URL categories and distinct destinations within a 4-hour window. While individual proxy blocks are routine (users clicking ads, miscategorized sites), a cluster of violations across diverse categories (malware, hacking tools, anonymizers, adult content) from a single source indicates either a compromised host attempting to reach multiple malicious destinations or an insider deliberately circumventing security controls.
- **Join Key(s):** `user.name` OR `source.ip`
- **Lookback:** 4 hours
- **Schedule:** Every 15 minutes
- **Priority:** P3
- **Integration:** [alerts](https://www.elastic.co/guide/en/security/current/alerts-ui-manage.html)
- **Language:** `[ES|QL]`

## Query

```esql
FROM .internal.alerts-security.alerts-default
| WHERE @timestamp > NOW() - 4 HOURS
    AND kibana.alert.workflow_status == "open"
    AND (
        event.dataset LIKE "proxy*" OR event.dataset LIKE "zscaler*"
        OR event.dataset LIKE "bluecoat*" OR event.dataset LIKE "squid*"
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
    Esql.join_entity = COALESCE(user.name, TO_STRING(source.ip))
| STATS
    Esql.alert_count = COUNT(*),
    Esql.first_seen = MIN(@timestamp),
    Esql.last_seen = MAX(@timestamp),
    Esql.total_risk = SUM(alert_risk),
    Esql.violation_count = COUNT(*),
    Esql.distinct_categories = COUNT_DISTINCT(rule.category),
    Esql.category_values = VALUES(rule.category),
    Esql.distinct_destinations = COUNT_DISTINCT(url.domain),
    Esql.destination_values = VALUES(url.domain),
    Esql.unique_rules = COUNT_DISTINCT(kibana.alert.rule.name),
    Esql.rule_names = VALUES(kibana.alert.rule.name),
    Esql.host_values = VALUES(host.name),
    Esql.source_ips = VALUES(source.ip)
  BY Esql.join_entity
| WHERE Esql.violation_count >= 5 AND Esql.distinct_categories >= 2
| EVAL
    Esql.risk_score = Esql.total_risk,
    Esql.severity = CASE(
        Esql.violation_count >= 20, "high",
        Esql.violation_count >= 10 AND Esql.distinct_categories >= 3, "high",
        Esql.violation_count >= 5, "medium",
        "low"
    ),
    Esql.description = CONCAT(
        "Proxy policy violation cluster for ", Esql.join_entity,
        " | ", TO_STRING(Esql.violation_count), " violations",
        " across ", TO_STRING(Esql.distinct_categories), " categories",
        " | ", TO_STRING(Esql.distinct_destinations), " distinct destinations",
        " | Risk Score: ", TO_STRING(Esql.risk_score),
        " | Window: ", TO_STRING(Esql.first_seen), " to ", TO_STRING(Esql.last_seen)
    )
| SORT Esql.risk_score DESC
| LIMIT 50
```

## Strategy

Filters to proxy domain alerts and aggregates by the user name (falling back to source IP as string when user name is unavailable). Counts violation volume, category diversity, and destination diversity. The dual threshold of violation count AND category diversity ensures the rule fires only on behaviorally significant clusters, not on a user repeatedly hitting the same blocked site.

## Severity Logic

| Condition | Severity |
|-----------|----------|
| violation_count >= 20 | High |
| violation_count >= 10 + 3+ categories | High |
| violation_count >= 5 | Medium |

## Notes

- **Blind Spots:**
  - Users on VPN or direct internet connections that bypass the proxy entirely
  - HTTPS traffic where the proxy sees only the SNI hostname, not the full URL or category (category classification depends on the proxy vendor's URL database)
  - Proxy alerts that lack `rule.category` or `url.domain` fields -- these alerts contribute to count but not to diversity metrics
  - Mobile devices and personal hotspots that bypass corporate proxy infrastructure

- **False Positives:**
  - **Researchers and threat intelligence analysts**: Deliberately visiting categorized malicious sites for analysis. Mitigation: exclude known research team user accounts or source IPs.
  - **Miscategorized legitimate sites**: Proxy vendor URL databases contain errors. Mitigation: review categories in violation clusters and submit recategorization requests.
  - **Browser extensions and ad blockers**: Some extensions trigger proxy policy violations through background requests. Mitigation: identify common extension-generated domains and exclude them.

- **Tuning:**
  1. `violation_count` threshold (default: 5) -- increase to 10 in environments with aggressive proxy policies that generate many blocks for routine browsing
  2. `distinct_categories` threshold (default: 2) -- increase to 3 if your proxy classifies many legitimate sites into security categories
  3. Add specific high-risk category weighting -- violations in "malware", "command-and-control", or "phishing" categories should carry higher weight than "adult" or "gambling"
  4. Consider time-of-day analysis -- proxy violations during off-hours warrant escalation

## Data Requirements

- **Index**: `.internal.alerts-security.alerts-default`
- **Required fields**: `event.dataset`, `signal.rule.severity`, `kibana.alert.rule.name`, `kibana.alert.rule.building_block_type`, `@timestamp`, `user.name`, `source.ip`, `rule.category`, `url.domain`, `host.name`
- **Minimum data sources**: At least one web proxy integration (Zscaler, Blue Coat/Symantec, Squid, or similar)
- **Minimum volume**: 5+ proxy policy violation alerts from same user/IP within 4h spanning 2+ categories

## Dependencies

None required.

## Validation

From a single user or IP, trigger proxy blocks across multiple categories within a 2-hour window:
1. Attempt to visit a known malware distribution site (malware category)
2. Attempt to visit a known hacking tools site (hacking category)
3. Attempt to visit a known anonymizer/proxy site (anonymizer category)
4. Repeat enough times to exceed the violation_count threshold

Expected result: User/IP appears with `Esql.violation_count >= 5`, `Esql.distinct_categories >= 2`, severity of medium or higher.

## Elastic Comparison

Elastic does not ship proxy-specific policy violation clustering rules. Proxy integrations generate individual alerts per blocked request. CORR-5G aggregates these into behaviorally meaningful clusters that distinguish routine individual blocks from pattern-of-concern violation bursts.
