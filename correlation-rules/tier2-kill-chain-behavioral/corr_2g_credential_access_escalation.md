# Credential Access Escalation

---

## Metadata

- **Rule ID:** `CORR-2G`
- **Tier:** 2 — Kill Chain and Behavioral Correlation
- **Author:** Detection Engineering
- **Description:** Detect hosts where multiple distinct credential access techniques are observed within a 4-hour window. An attacker using two or more credential harvesting techniques on the same host — LSASS access, SAM dump, Kerberoasting, DCSync, credential file access — indicates systematic credential harvesting rather than a single opportunistic attempt.
- **Join Key(s):** `host.name`
- **Lookback:** 4 hours
- **Schedule:** Every 15 minutes
- **Priority:** P2
- **Integration:** [alerts](https://www.elastic.co/guide/en/security/current/alerts-ui-manage.html)
- **Language:** `[ES|QL]`

## Query

```esql
FROM .internal.alerts-security.alerts-default
| WHERE @timestamp > NOW() - 4 HOURS
    AND kibana.alert.workflow_status == "open"
    AND host.name IS NOT NULL AND host.name != ""
    AND kibana.alert.rule.parameters.threat.tactic.name == "Credential Access"
| EVAL
    severity_weight = CASE(
        signal.rule.severity == "critical", 25,
        signal.rule.severity == "high", 15,
        signal.rule.severity == "medium", 8,
        signal.rule.severity == "low", 3, 1
    ),
    bbr_factor = CASE(kibana.alert.rule.building_block_type == "default", 0.3, 1.0),
    alert_risk = ROUND(severity_weight * bbr_factor),
    cred_technique = CASE(
        kibana.alert.rule.name LIKE "*LSASS*"
            OR kibana.alert.rule.name LIKE "*lsass*"
            OR kibana.alert.rule.name LIKE "*credential dump*"
            OR kibana.alert.rule.name LIKE "*mimikatz*"
            OR kibana.alert.rule.name LIKE "*procdump*lsass*", "lsass_access",
        kibana.alert.rule.name LIKE "*SAM*"
            OR kibana.alert.rule.name LIKE "*registry*credential*"
            OR kibana.alert.rule.name LIKE "*sam database*"
            OR kibana.alert.rule.name LIKE "*shadow copy*sam*", "sam_dump",
        kibana.alert.rule.name LIKE "*kerberoast*"
            OR kibana.alert.rule.name LIKE "*SPN*"
            OR kibana.alert.rule.name LIKE "*service ticket*", "kerberoasting",
        kibana.alert.rule.name LIKE "*DCSync*"
            OR kibana.alert.rule.name LIKE "*dcsync*"
            OR kibana.alert.rule.name LIKE "*replication*"
            OR kibana.alert.rule.name LIKE "*DRS*", "dcsync",
        kibana.alert.rule.name LIKE "*keylog*"
            OR kibana.alert.rule.name LIKE "*input capture*", "keylogging",
        kibana.alert.rule.name LIKE "*brute*"
            OR kibana.alert.rule.name LIKE "*password spray*"
            OR kibana.alert.rule.name LIKE "*credential stuff*", "brute_force",
        kibana.alert.rule.name LIKE "*NTDS*"
            OR kibana.alert.rule.name LIKE "*ntds.dit*", "ntds_dump",
        kibana.alert.rule.name LIKE "*credential*file*"
            OR kibana.alert.rule.name LIKE "*password*file*"
            OR kibana.alert.rule.name LIKE "*credential*vault*"
            OR kibana.alert.rule.name LIKE "*browser*password*"
            OR kibana.alert.rule.name LIKE "*chrome*credential*", "credential_file_access",
        kibana.alert.rule.name LIKE "*AS-REP*"
            OR kibana.alert.rule.name LIKE "*asreproast*", "asreproasting",
        "other_cred_access"
    )
| STATS
    Esql.alert_count = COUNT(*),
    Esql.first_seen = MIN(@timestamp),
    Esql.last_seen = MAX(@timestamp),
    Esql.total_risk = SUM(alert_risk),
    Esql.technique_count = COUNT_DISTINCT(cred_technique),
    Esql.technique_types = VALUES(cred_technique),
    Esql.unique_rules = COUNT_DISTINCT(kibana.alert.rule.name),
    Esql.rule_names = VALUES(kibana.alert.rule.name),
    Esql.user_values = VALUES(user.name),
    Esql.user_count = COUNT_DISTINCT(user.name),
    Esql.ip_values = VALUES(related.ip)
  BY host.name
| WHERE Esql.technique_count >= 2
| EVAL
    Esql.risk_score = ROUND(Esql.total_risk * Esql.technique_count),
    Esql.correlation_severity = CASE(
        Esql.technique_count >= 4, "critical",
        Esql.technique_count >= 3, "high",
        Esql.technique_count >= 2, "medium",
        "medium"
    ),
    Esql.description = CONCAT(
        "Host ", host.name,
        " | Credential Access Escalation",
        " | ", TO_STRING(Esql.technique_count), " distinct credential techniques",
        " | Risk Score: ", TO_STRING(Esql.risk_score),
        " | Techniques: ", TO_STRING(Esql.technique_types),
        " | ", TO_STRING(Esql.user_count), " users",
        " | ", TO_STRING(Esql.unique_rules), " rules",
        " | ", TO_STRING(Esql.alert_count), " alerts"
    )
| SORT Esql.risk_score DESC
| LIMIT 50
```

## Strategy

Filters alerts to only those with the Credential Access tactic. Each alert's rule name is pattern-matched against known credential access technique categories to classify the technique type. STATS aggregates by `host.name` and counts distinct technique types. Hosts with 2+ distinct credential techniques pass filtering. The risk score is multiplied by the technique count — more techniques = higher confidence of deliberate credential harvesting.

## Severity Logic

```
CASE(
    Esql.technique_count >= 4, "critical",     -- 4+ distinct credential techniques
    Esql.technique_count >= 3, "high",          -- 3 distinct credential techniques
    Esql.technique_count >= 2, "medium",        -- 2 distinct credential techniques
    "medium"
)
```

| Condition | Severity |
|-----------|----------|
| 4+ distinct credential access techniques on same host | Critical |
| 3 distinct credential access techniques | High |
| 2 distinct credential access techniques | Medium |

## Notes

- **Blind Spots:**
  - Novel credential access techniques not recognized by the rule name pattern matching — new tools or renamed rules will fall into "other_cred_access" and count as a single technique
  - Cloud credential attacks (OAuth token theft, SSM parameter store access) occur in a different host context and will not correlate with endpoint-based credential techniques
  - Credential access alerts that lack the "Credential Access" tactic mapping are excluded from this rule entirely

- **False Positives:**
  - **Credential scanning tools used by security teams**: Vulnerability assessment tools that probe for credential weaknesses (e.g., CrackMapExec in audit mode). Mitigation: exclude known security tool hosts or schedule scanning during maintenance windows.
  - **Active Directory health check tools**: Tools like PingCastle or BloodHound Collectors (when used by the blue team). Mitigation: register scanning accounts in `lookup-service-accounts`.
  - **Purple team credential attack exercises**: Planned exercises running multiple techniques. Mitigation: add temporary exclusions during exercise windows.

- **Tuning:**
  1. `technique_count` threshold (default: 2) — increase to 3 if security tools generate multiple credential technique alerts
  2. Credential technique classification — customize `cred_technique` CASE patterns for your detection rule naming conventions
  3. Exclude "other_cred_access" from counting: `AND cred_technique != "other_cred_access"` to only count positively identified techniques
  4. Add user context: if all alerts are from the same user, it may be a single attacker; if multiple users, the system may be compromised at a deeper level
  5. Consider a companion rule that correlates credential access techniques across hosts (same technique on multiple hosts = broader campaign)

## Data Requirements

- **Index**: `.internal.alerts-security.alerts-default`
- **Required fields**: `host.name`, `@timestamp`, `signal.rule.severity`, `kibana.alert.workflow_status`, `kibana.alert.rule.building_block_type`, `kibana.alert.rule.name`, `kibana.alert.rule.parameters.threat.tactic.name`, `user.name`, `related.ip`
- **Minimum volume**: 2+ Credential Access alerts matching 2+ distinct technique patterns for same `host.name` within 4h

## Dependencies

- No required lookup indices
- Prerequisite: Detection rules for credential access techniques (LSASS access, Kerberoasting, DCSync, etc.) must be deployed
- Optional: `lookup-critical-assets` — escalate severity for domain controllers and credential stores

## Validation

Red team scenario: On a single test host within a 2-hour window:
1. Perform an LSASS memory dump (e.g., using Mimikatz `sekurlsa::logonpasswords`)
2. Execute a Kerberoasting attack (e.g., using Rubeus `kerberoast`)
3. Attempt a DCSync attack (e.g., using Mimikatz `lsadump::dcsync`)

Expected result: Host appears with `Esql.technique_count = 3`, techniques = [lsass_access, kerberoasting, dcsync], severity = high, risk score = `SUM(alert_risk) * 3`.

## Elastic Comparison

Elastic ships individual credential access detection rules (LSASS Access, Kerberoasting, DCSync, etc.) but does not ship a correlation rule that counts distinct credential techniques per host. CORR-2G surfaces the pattern of systematic credential harvesting — multiple techniques on the same host indicates an attacker exhaustively extracting credentials, not a single opportunistic attempt.
