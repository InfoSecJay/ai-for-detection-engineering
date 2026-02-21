# Peer Group Risk Deviation

---

## Metadata

- **Rule ID:** `CORR-3D`
- **Tier:** 3 — Risk Accumulation
- **Author:** Detection Engineering
- **Description:** Detect users whose 24-hour risk score significantly deviates from their peer group's baseline. An IT administrator with a risk score of 60 might be normal for IT administrators but would be alarming for an HR department member. This rule normalizes risk by peer group to catch compromised accounts whose activity diverges from what is expected for their role, regardless of whether the absolute risk crosses a fixed threshold.
- **Join Key(s):** `user.name`
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
    AND user.name IS NOT NULL
    AND NOT user.name IN ("SYSTEM", "Administrator", "LOCAL SERVICE", "NETWORK SERVICE",
        "DWM-1", "DWM-2", "DWM-3", "UMFD-0", "UMFD-1", "UMFD-2",
        "DefaultAccount", "Guest", "WDAGUtilityAccount")
    AND NOT (
        user.name LIKE "svc-*" OR user.name LIKE "svc_*"
        OR user.name LIKE "app-*" OR user.name LIKE "sa-*"
        OR user.name LIKE "*$" OR user.name LIKE "MSOL_*"
        OR user.name LIKE "HealthMail*" OR user.name LIKE "SM_*"
    )
| EVAL
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
| STATS
    Esql.user_risk = SUM(alert_risk),
    Esql.alert_count = COUNT(*),
    Esql.domain_count = COUNT_DISTINCT(domain_category),
    Esql.domain_values = VALUES(domain_category),
    Esql.rule_count = COUNT_DISTINCT(kibana.alert.rule.name),
    Esql.rule_names = VALUES(kibana.alert.rule.name),
    Esql.tactic_count = COUNT_DISTINCT(kibana.alert.rule.threat.tactic.name),
    Esql.tactic_values = VALUES(kibana.alert.rule.threat.tactic.name),
    Esql.earliest = MIN(@timestamp),
    Esql.latest = MAX(@timestamp)
  BY user.name
| LOOKUP JOIN lookup-peer-baselines ON user.name
| EVAL
    Esql.peer_avg_risk = COALESCE(avg_weekly_risk, 0),
    Esql.peer_stddev = COALESCE(std_dev_risk, 1),
    Esql.peer_deviation = ROUND(
        TO_DOUBLE(Esql.user_risk - Esql.peer_avg_risk) / TO_DOUBLE(GREATEST(Esql.peer_stddev, 1))
    ),
    Esql.department = COALESCE(department, "unknown")
| WHERE Esql.peer_deviation >= 3.0
    AND Esql.user_risk >= 30
| EVAL
    Esql.correlation_severity = CASE(
        Esql.peer_deviation >= 5.0, "critical",
        Esql.peer_deviation >= 4.0, "high",
        Esql.peer_deviation >= 3.0, "medium",
        "low"
    ),
    Esql.description = CONCAT(
        "Peer group risk deviation for user ", user.name,
        " | Department: ", Esql.department,
        " | User 24h risk: ", TO_STRING(Esql.user_risk),
        " | Peer avg: ", TO_STRING(Esql.peer_avg_risk),
        " | Peer stddev: ", TO_STRING(Esql.peer_stddev),
        " | Deviation: ", TO_STRING(Esql.peer_deviation), " sigma",
        " | ", TO_STRING(Esql.alert_count), " alerts from ",
        TO_STRING(Esql.rule_count), " rules across ",
        TO_STRING(Esql.domain_count), " domains"
    )
| SORT Esql.peer_deviation DESC
| LIMIT 50
```

## Strategy

Computes the 24-hour risk score per user using the standard risk scoring model (identical to CORR-3A's per-user calculation). Then performs a LOOKUP JOIN against `lookup-peer-baselines` using the user's department (or group) as the join key to retrieve the peer group's average risk (`peer_avg_risk`) and standard deviation (`peer_stddev`). The peer deviation is computed as `(user_risk - peer_avg_risk) / GREATEST(peer_stddev, 1)` -- a standard z-score calculation. The rule fires when the deviation exceeds 3.0 standard deviations AND the absolute user risk is at least 30 (to prevent triggering on peer groups with near-zero baselines where even trivial risk appears as a large deviation).

## Severity Logic

| Condition | Severity |
|-----------|----------|
| Esql.peer_deviation >= 5.0 (5+ standard deviations) | Critical |
| Esql.peer_deviation >= 4.0 (4+ standard deviations) | High |
| Esql.peer_deviation >= 3.0 (3+ standard deviations) | Medium |

In a normal distribution, 3 standard deviations encompasses 99.7% of the population. An entity at 3+ sigma is a statistical outlier by definition. At 5+ sigma, the probability of this being normal behavior is vanishingly small.

## Notes

- **Blind Spots:**
  - **Small peer groups**: A department with 3 people cannot produce meaningful statistical baselines. One outlier in a group of 3 massively skews the peer average and standard deviation. Recommend a minimum peer group size of 10 for meaningful comparison -- groups smaller than this should be excluded from peer deviation analysis.
  - **Users in unique roles**: A CISO, a sole security engineer, or a DBA with no peers in the lookup will have no baseline to compare against. The COALESCE defaults handle the null case but produce a deviation relative to zero, which may or may not be meaningful.
  - **Stale peer baselines**: If the `lookup-peer-baselines` index is not regularly refreshed (recommended: weekly), the baselines will drift from reality, producing inaccurate deviations.
  - **Cross-department role overlap**: A developer who also has security responsibilities may be in the "Engineering" peer group but exhibit activity patterns more like the "Security" peer group. Peer grouping by department alone is a simplification.

- **False Positives:**
  - **Team leads and managers**: Users with legitimately broader access patterns than their peer group (e.g., a team lead who accesses both developer tools and administrative systems). Mitigation: create separate peer groups for leads/managers, or adjust the deviation threshold upward for known broad-access roles.
  - **Security team members conducting authorized testing**: Security engineers running purple team exercises will deviate from their peers. Mitigation: coordinate with the security team to exclude testing periods or testing accounts.
  - **Seasonal business activity**: Quarter-end finance activity, year-end auditing, or project deadlines that cause specific users to exhibit atypical access patterns. Mitigation: if seasonal patterns are predictable, adjust peer baselines accordingly.

- **Tuning:**
  1. **Standard deviation threshold**: 3.0 sigma is the statistical default. Increase to 4.0 in noisy environments where many users slightly exceed 3 sigma. Decrease to 2.5 only if the environment has very stable peer groups with low variance.
  2. **Minimum peer group size**: Recommend filtering out peer groups with fewer than 10 members in the lookup population. Add a `peer_group_size` field to `lookup-peer-baselines` and filter on it.
  3. **Minimum absolute risk (30)**: This prevents triggering on peer groups with near-zero baselines where any risk appears as a large deviation. Adjust based on your environment's average user risk level.
  4. **Peer group definition**: The lookup joins on `user.name` but the baselines are computed by department. Consider alternative groupings: role, business unit, geographic location, or a combination. The most effective peer grouping depends on your organization's structure.
  5. **Baseline refresh cadence**: Weekly recalculation is recommended. Daily is better but more computationally expensive. Monthly is too stale for fast-changing environments.

## Data Requirements

- **Index**: `.internal.alerts-security.alerts-default`
- **Required fields**: `@timestamp`, `user.name`, `event.dataset`, `signal.rule.severity`, `kibana.alert.workflow_status`, `kibana.alert.rule.building_block_type`, `kibana.alert.rule.name`, `kibana.alert.rule.threat.tactic.name`
- **Lookup index**: `lookup-peer-baselines` (with `user.name` as join key; `department`, `avg_weekly_risk`, `std_dev_risk` fields). This lookup must be pre-populated with per-user department mappings and per-department risk statistics.
- **Identity enrichment**: Requires that `user.name` values in the alerts index can be mapped to department/role in the lookup. This depends on an identity enrichment pipeline (AD sync, HRIS integration, or manual mapping).

## Dependencies

- **Required**: `lookup-peer-baselines` with populated per-user department mappings and per-department risk statistics. Without this lookup, the query cannot compute meaningful peer deviations.
- **Recommended**: CORR-3A running in production to validate individual entity risk scores before layering peer comparison on top.
- **Infrastructure**: An identity enrichment pipeline that maps `user.name` to `department` and maintains this mapping in the lookup index.

## Validation

In a department of 50 users averaging risk=10 with stddev=5, generate alerts pushing one user to risk=50:
1. Ensure the target user is mapped in `lookup-peer-baselines` with `department = "Engineering"`, `avg_weekly_risk = 10`, `std_dev_risk = 5`.
2. Generate 3 high-severity alerts (3 * 15 = 45) and 1 low-severity alert (3) for the target user. Total risk = 48.
3. Peer deviation = (48 - 10) / 5 = 7.6 sigma. This triggers as critical (>= 5.0).
4. Verify the rule surfaces this user with correct peer group context and deviation score.

## Elastic Comparison

Elastic does not ship a peer-group-based risk deviation rule. Microsoft Sentinel's UEBA provides peer comparison through its behavioral analytics engine, which compares entity behavior to peers automatically. Splunk UBA also provides peer group analysis. CORR-3D implements this concept using deterministic ES|QL with explicit peer group definitions, giving the detection engineer full control over peer grouping logic and deviation thresholds. The trade-off is that peer baselines must be manually maintained in a lookup index rather than being automatically computed by an ML engine.
