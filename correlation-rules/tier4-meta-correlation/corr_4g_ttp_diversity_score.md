# TTP Diversity Score

---

## Metadata

- **Rule ID:** `CORR-4G`
- **Tier:** 4 — Meta-Correlation
- **Author:** Detection Engineering
- **Description:** Detect entities associated with alerts spanning four or more distinct MITRE ATT&CK tactics within 24 hours. High tactic diversity for a single entity is an extremely strong signal of a full-spectrum attack in progress. Legitimate users and systems rarely generate alerts across Initial Access, Execution, Persistence, and Lateral Movement in the same day. An entity touching 4+ tactics is either under active compromise progressing through the kill chain or is a red team exercise. This rule complements Tier 1's cross-domain correlation (which counts detection domains) by counting attack-lifecycle stages (tactics).
- **Join Key(s):** `entity_type + entity_value (typed composite key)`
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
    AND kibana.alert.rule.threat.tactic.name IS NOT NULL
| EVAL
    entity_type = CASE(
        user.name IS NOT NULL, "user",
        host.name IS NOT NULL, "host",
        "unknown"
    ),
    entity_value = CASE(
        user.name IS NOT NULL, user.name,
        host.name IS NOT NULL, host.name,
        "unknown"
    ),
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
| WHERE entity_value IS NOT NULL AND entity_value != "unknown"
| STATS
    Esql.unique_tactics = COUNT_DISTINCT(kibana.alert.rule.threat.tactic.name),
    Esql.tactic_values = VALUES(kibana.alert.rule.threat.tactic.name),
    Esql.unique_techniques = COUNT_DISTINCT(kibana.alert.rule.threat.technique.name),
    Esql.technique_values = VALUES(kibana.alert.rule.threat.technique.name),
    Esql.alert_count = COUNT(*),
    Esql.risk_score = SUM(alert_risk),
    Esql.unique_rules = COUNT_DISTINCT(kibana.alert.rule.name),
    Esql.rule_names = VALUES(kibana.alert.rule.name),
    Esql.domain_count = COUNT_DISTINCT(domain_category),
    Esql.domain_values = VALUES(domain_category),
    Esql.first_seen = MIN(@timestamp),
    Esql.last_seen = MAX(@timestamp),
    Esql.host_values = VALUES(host.name),
    Esql.user_values = VALUES(user.name)
  BY entity_type, entity_value
| WHERE Esql.unique_tactics >= 4
| EVAL
    Esql.ttp_diversity_ratio = ROUND(TO_DOUBLE(Esql.unique_techniques) / GREATEST(TO_DOUBLE(Esql.alert_count), 1.0), 3),
    Esql.ttp_score = ROUND(Esql.risk_score
        * CASE(Esql.unique_tactics >= 6, 2.5, Esql.unique_tactics >= 5, 2.0, Esql.unique_tactics >= 4, 1.5, 1.0)
        * CASE(Esql.ttp_diversity_ratio >= 0.5, 1.5, Esql.ttp_diversity_ratio >= 0.25, 1.25, 1.0)),
    Esql.correlation_severity = CASE(
        Esql.unique_tactics >= 6, "critical",
        Esql.unique_tactics >= 5, "high",
        Esql.unique_tactics >= 4, "medium",
        "low"
    ),
    Esql.description = CONCAT(
        "TTP diversity for ", entity_type, ":", entity_value,
        " | ", TO_STRING(Esql.unique_tactics), " tactics: ", TO_STRING(Esql.tactic_values),
        " | ", TO_STRING(Esql.unique_techniques), " techniques",
        " | Diversity ratio: ", TO_STRING(Esql.ttp_diversity_ratio),
        " | ", TO_STRING(Esql.alert_count), " alerts from ",
        TO_STRING(Esql.unique_rules), " rules",
        " | ", TO_STRING(Esql.domain_count), " domains",
        " | TTP Score: ", TO_STRING(Esql.ttp_score),
        " | Window: ", TO_STRING(Esql.first_seen), " to ", TO_STRING(Esql.last_seen)
    )
| SORT Esql.ttp_score DESC
| LIMIT 50
```

## Strategy

Aggregates all alerts by typed entity key (`entity_type, entity_value`) using a CASE expression instead of COALESCE, preserving whether the entity is a user or a host, and counts distinct MITRE tactics and techniques. The `unique_tactics` count is the primary threshold (>= 4). The TTP diversity ratio (`unique_techniques / alert_count`) measures whether the alerts represent diverse attack behaviors or the same technique repeating. A high ratio (closer to 1.0) means every alert is a different technique -- indicating a sophisticated, multi-faceted attack. A low ratio means the same technique is generating many alerts -- indicating either a persistent single-vector attack or a noisy rule.

## Severity Logic

| Condition | Severity |
|-----------|----------|
| unique_tactics >= 6 (6+ MITRE tactics for one entity) | Critical |
| unique_tactics >= 5 | High |
| unique_tactics >= 4 | Medium |

TTP score multipliers: unique_tactics >= 6 = 2.5x, >= 5 = 2.0x, >= 4 = 1.5x. TTP diversity ratio >= 0.5 = additional 1.5x (half or more of all alerts are distinct techniques), >= 0.25 = 1.25x.

## Notes

- **Blind Spots:**
  - **Alerts without MITRE tactic mapping**: Detection rules that lack `threat.tactic.name` are excluded entirely. In environments where many custom rules do not have MITRE mappings, significant activity may be invisible to this rule.
  - **Tactic consolidation**: MITRE ATT&CK maps multiple techniques to the same tactic. An entity exhibiting 10 different techniques across only 2 tactics (e.g., all Execution and Defense Evasion) has high technique diversity but low tactic diversity, and will not trigger CORR-4G at the default threshold.
  - **Multi-value tactic fields**: Some rules map to multiple tactics. If ES|QL counts multi-value fields differently, the tactic count may be inflated or deflated depending on how `COUNT_DISTINCT` handles multi-valued fields.

- **False Positives:**
  - **Red team exercises**: Active red team engagements deliberately walk through the kill chain, generating alerts across many tactics. Mitigation: exclude known red team user accounts or host names during engagement windows.
  - **Security testing tools**: Tools like Atomic Red Team, MITRE Caldera, or Infection Monkey that test detection coverage across multiple tactics. Mitigation: run testing from designated hosts and exclude those hosts.
  - **IT administrators performing diverse activities**: Admins who log in remotely (Initial Access tactic), run scripts (Execution), modify services (Persistence), change firewall rules (Defense Evasion), and access network shares (Lateral Movement) may span multiple tactics legitimately. Mitigation: establish admin-specific tactic count baselines.

- **Tuning:**
  1. **unique_tactics threshold** (default: 4) -- the primary sensitivity control. MITRE ATT&CK has 14 tactics; an entity touching 4+ in 24 hours is unusual. Raise to 5 if your environment has broad MITRE coverage that inflates tactic counts.
  2. **TTP diversity ratio** -- use as a secondary filter. Entities with ratio >= 0.5 are exhibiting highly diverse behavior (every other alert is a new technique). Entities with ratio < 0.1 have one technique repeating many times -- less interesting.
  3. **Lookback window** (default: 24h) -- reduce to 12h if you want to catch faster kill chain progression; extend to 48h for APT-style slow progressions.
  4. **Tactic exclusions** -- consider excluding "Reconnaissance" and "Resource Development" if pre-compromise tactics generate alerts that inflate counts for external-facing entities.
  5. **Minimum alert count** -- add a `WHERE Esql.alert_count >= 4` if you want to ensure the tactic diversity is backed by sufficient alert volume (not just 4 isolated alerts).

## Data Requirements

- **Index**: `.internal.alerts-security.alerts-default`
- **Required fields**: `kibana.alert.rule.threat.tactic.name`, `kibana.alert.rule.threat.technique.name`, `user.name`, `host.name`, `event.dataset`, `signal.rule.severity`, `kibana.alert.workflow_status`, `kibana.alert.rule.building_block_type`, `kibana.alert.rule.name`, `@timestamp`
- **Minimum volume**: Alerts spanning 4+ distinct MITRE tactics for the same entity in 24h

## Dependencies

- **Required**: None.
- **Upstream**: Requires detection rules to have MITRE ATT&CK tactic and technique mappings populated. The rule's value scales directly with the breadth of MITRE coverage in your detection library.

## Validation

1. For a single test user or host, generate alerts spanning at least 6 different MITRE tactics within 24 hours:
   - **Initial Access**: Simulate phishing or external remote service alert.
   - **Execution**: Run suspicious PowerShell or script interpreter alert.
   - **Persistence**: Create scheduled task or registry run key alert.
   - **Defense Evasion**: Trigger process injection or indicator removal alert.
   - **Credential Access**: Simulate LSASS access or brute force alert.
   - **Lateral Movement**: Trigger remote service or pass-the-hash alert.
2. CORR-4G should produce a TTP diversity alert with `Esql.unique_tactics >= 6`.
3. Verify severity resolves to "critical" (6+ tactics).
4. Verify `Esql.tactic_values` lists all 6 tactic names.
5. Check that `Esql.ttp_diversity_ratio` reflects the technique-to-alert ratio.

## Elastic Comparison

Elastic does not ship a TTP diversity detection rule. Elastic's Risk Score engine and "Multiple Alerts" rules count alert volume and severity but do not measure MITRE tactic breadth. The closest Elastic feature is the MITRE ATT&CK coverage dashboard in Kibana, which visualizes tactic coverage across the detection library but does not alert when a single entity triggers alerts across many tactics. CORR-4G provides automated kill-chain-breadth detection per entity that Elastic does not offer natively.
