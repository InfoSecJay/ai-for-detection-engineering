# Defense Evasion Cluster

---

## Metadata

- **Rule ID:** `CORR-2H`
- **Tier:** 2 — Kill Chain and Behavioral Correlation
- **Author:** Detection Engineering
- **Description:** Detect hosts where three or more distinct defense evasion techniques are observed within a 1-hour window. An attacker actively disabling security controls, clearing logs, and masquerading processes in rapid succession indicates deliberate preparation for a high-impact action (ransomware deployment, data exfiltration). The short 1-hour lookback and aggressive 5-minute schedule reflect the urgency: defense evasion clustering often precedes imminent impact.
- **Join Key(s):** `host.name`
- **Lookback:** 1 hour
- **Schedule:** Every 5 minutes
- **Priority:** P2
- **Integration:** [alerts](https://www.elastic.co/guide/en/security/current/alerts-ui-manage.html)
- **Language:** `[ES|QL]`

## Query

```esql
FROM .internal.alerts-security.alerts-default
| WHERE @timestamp > NOW() - 1 HOURS
    AND kibana.alert.workflow_status == "open"
    AND host.name IS NOT NULL AND host.name != ""
    AND kibana.alert.rule.threat.tactic.name == "Defense Evasion"
| EVAL
    severity_weight = CASE(
        signal.rule.severity == "critical", 25,
        signal.rule.severity == "high", 15,
        signal.rule.severity == "medium", 8,
        signal.rule.severity == "low", 3, 1
    ),
    bbr_factor = CASE(kibana.alert.rule.building_block_type == "default", 0.3, 1.0),
    alert_risk = ROUND(severity_weight * bbr_factor),
    evasion_technique = CASE(
        kibana.alert.rule.name LIKE "*log clear*"
            OR kibana.alert.rule.name LIKE "*event log*delet*"
            OR kibana.alert.rule.name LIKE "*clear event*"
            OR kibana.alert.rule.name LIKE "*wevtutil*clear*"
            OR kibana.alert.rule.name LIKE "*audit log*clear*", "log_clearing",
        kibana.alert.rule.name LIKE "*disable*antivirus*"
            OR kibana.alert.rule.name LIKE "*disable*defender*"
            OR kibana.alert.rule.name LIKE "*tamper*protection*"
            OR kibana.alert.rule.name LIKE "*disable*security*"
            OR kibana.alert.rule.name LIKE "*stop*security*service*"
            OR kibana.alert.rule.name LIKE "*kill*edr*"
            OR kibana.alert.rule.name LIKE "*disable*edr*", "security_disable",
        kibana.alert.rule.name LIKE "*timestomp*"
            OR kibana.alert.rule.name LIKE "*time*stamp*modif*"
            OR kibana.alert.rule.name LIKE "*SetFileTime*", "timestomping",
        kibana.alert.rule.name LIKE "*process*inject*"
            OR kibana.alert.rule.name LIKE "*dll*inject*"
            OR kibana.alert.rule.name LIKE "*hollowing*"
            OR kibana.alert.rule.name LIKE "*APC*inject*"
            OR kibana.alert.rule.name LIKE "*thread*inject*", "process_injection",
        kibana.alert.rule.name LIKE "*masquerad*"
            OR kibana.alert.rule.name LIKE "*rename*executable*"
            OR kibana.alert.rule.name LIKE "*suspicious*path*"
            OR kibana.alert.rule.name LIKE "*double*extension*", "masquerading",
        kibana.alert.rule.name LIKE "*obfuscat*"
            OR kibana.alert.rule.name LIKE "*encoded*command*"
            OR kibana.alert.rule.name LIKE "*base64*"
            OR kibana.alert.rule.name LIKE "*deobfuscat*", "obfuscation",
        kibana.alert.rule.name LIKE "*AMSI*bypass*"
            OR kibana.alert.rule.name LIKE "*ETW*bypass*"
            OR kibana.alert.rule.name LIKE "*patch*amsi*", "amsi_etw_bypass",
        kibana.alert.rule.name LIKE "*rootkit*"
            OR kibana.alert.rule.name LIKE "*hidden*file*"
            OR kibana.alert.rule.name LIKE "*indicator*removal*", "indicator_removal",
        kibana.alert.rule.name LIKE "*firewall*rule*"
            OR kibana.alert.rule.name LIKE "*modify*firewall*"
            OR kibana.alert.rule.name LIKE "*disable*firewall*", "firewall_modification",
        "other_evasion"
    )
| STATS
    Esql.alert_count = COUNT(*),
    Esql.first_seen = MIN(@timestamp),
    Esql.last_seen = MAX(@timestamp),
    Esql.total_risk_score = SUM(alert_risk),
    Esql.technique_count = COUNT_DISTINCT(evasion_technique),
    Esql.technique_types = VALUES(evasion_technique),
    Esql.unique_rules = COUNT_DISTINCT(kibana.alert.rule.name),
    Esql.rule_names = VALUES(kibana.alert.rule.name),
    Esql.user_values = VALUES(user.name),
    Esql.user_count = COUNT_DISTINCT(user.name),
    Esql.process_names = VALUES(process.name),
    Esql.ip_values = VALUES(related.ip)
  BY host.name
| WHERE Esql.technique_count >= 3
| EVAL
    Esql.risk_score = ROUND(Esql.total_risk_score * Esql.technique_count),
    Esql.correlation_severity = CASE(
        Esql.technique_count >= 5, "critical",
        Esql.technique_count >= 4, "high",
        Esql.technique_count >= 3, "medium",
        "medium"
    ),
    Esql.description = CONCAT(
        "Host ", host.name,
        " | Defense Evasion Cluster",
        " | ", TO_STRING(Esql.technique_count), " distinct evasion techniques in 1h",
        " | Risk Score: ", TO_STRING(Esql.risk_score),
        " | Techniques: ", TO_STRING(Esql.technique_types),
        " | ", TO_STRING(Esql.user_count), " users",
        " | ", TO_STRING(Esql.unique_rules), " rules",
        " | ", TO_STRING(Esql.alert_count), " alerts",
        " | Window: ", TO_STRING(Esql.first_seen), " to ", TO_STRING(Esql.last_seen)
    )
| SORT Esql.risk_score DESC
| LIMIT 50
```

## Strategy

Filters alerts to only those with the Defense Evasion tactic. Each alert is classified into an evasion technique category via rule name pattern matching. STATS aggregates by `host.name` and counts distinct technique types. Hosts with 3+ distinct evasion techniques pass filtering. The risk score is multiplied by the technique count. The tight schedule ensures near-real-time detection of active defense teardown.

## Severity Logic

```
CASE(
    Esql.technique_count >= 5, "critical",    -- 5+ distinct evasion techniques in 1 hour
    Esql.technique_count >= 4, "high",         -- 4 distinct evasion techniques
    Esql.technique_count >= 3, "medium",       -- 3 distinct evasion techniques
    "medium"
)
```

| Condition | Severity |
|-----------|----------|
| 5+ distinct defense evasion techniques on same host in 1h | Critical |
| 4 distinct evasion techniques | High |
| 3 distinct evasion techniques | Medium |

## Notes

- **Blind Spots:**
  - Evasion techniques that successfully evade detection — by definition, if the evasion technique works, no alert is generated and the technique is invisible to this rule
  - Slow evasion activities spread over more than 1 hour — an attacker disabling controls over the course of a workday will not trigger the 1-hour window
  - Defense evasion alerts not tagged with the "Defense Evasion" tactic are excluded
  - Novel evasion techniques not matching rule name patterns fall into "other_evasion"

- **False Positives:**
  - **Security tools performing endpoint hardening**: Configuration management tools (e.g., SCCM deploying GPOs that modify firewall rules, update AV settings, and clear old logs). Mitigation: schedule hardening pushes and suppress during those windows.
  - **AV remediation actions**: Antivirus cleaning malware may trigger log clearing, process termination, and file modification alerts. Mitigation: exclude known AV remediation process chains.
  - **System administrators**: IT staff performing maintenance (clearing logs, modifying firewall rules, updating security software). Mitigation: correlate with change management tickets.

- **Tuning:**
  1. `technique_count` threshold (default: 3) — increase to 4 if security tooling generates high evasion-classified alert volume
  2. Lookback window (default: 1h) — keep short; extend to 2h only for slow environments
  3. Schedule (default: 5 min) — this is the fastest schedule in Tier 2; keep it tight because defense evasion clustering often precedes imminent ransomware or data destruction
  4. Evasion technique classification — customize patterns for your detection rule naming conventions
  5. Add "urgency" flag: if `log_clearing` AND `security_disable` are both present, auto-escalate to critical regardless of technique count

## Data Requirements

- **Index**: `.internal.alerts-security.alerts-default`
- **Required fields**: `host.name`, `@timestamp`, `signal.rule.severity`, `kibana.alert.workflow_status`, `kibana.alert.rule.building_block_type`, `kibana.alert.rule.name`, `kibana.alert.rule.threat.tactic.name`, `user.name`, `process.name`, `related.ip`
- **Minimum volume**: 3+ Defense Evasion alerts matching 3+ distinct technique patterns for same `host.name` within 1h

## Dependencies

- No required lookup indices
- Prerequisite: Detection rules for defense evasion techniques (log clearing, AV disabling, process injection, etc.) must be deployed with "Defense Evasion" tactic mapping
- Optional: `lookup-critical-assets` — escalate severity for production/PCI hosts

## Validation

Red team scenario: On a single test host within 30 minutes:
1. Clear the Windows Security event log (triggers log clearing alert)
2. Disable Windows Defender real-time protection (triggers security disabling alert)
3. Perform process injection into svchost.exe (triggers process injection alert)

Expected result: Host appears with `Esql.technique_count = 3`, techniques = [log_clearing, security_disable, process_injection], severity = medium, risk score = `SUM(alert_risk) * 3`.

## Elastic Comparison

Elastic ships individual defense evasion detection rules (Event Log Clearing, Disabling Windows Defender, Process Injection, etc.) but does not ship a correlation rule that clusters multiple evasion techniques on a single host within a tight time window. CORR-2H surfaces the pattern of active defense teardown — which is a stronger indicator of imminent high-impact activity than any individual evasion technique alone.
