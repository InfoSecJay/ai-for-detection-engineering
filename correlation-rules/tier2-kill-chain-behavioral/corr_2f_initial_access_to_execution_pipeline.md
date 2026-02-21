# Initial Access to Execution Pipeline

---

## Metadata

- **Rule ID:** `CORR-2F`
- **Tier:** 2 — Kill Chain and Behavioral Correlation
- **Author:** Detection Engineering
- **Description:** Detect hosts where an Initial Access alert is followed by an Execution alert within a 2-hour window. This is the canonical compromise sequence: an attacker gains a foothold (phishing, web exploit, drive-by download) and then executes malicious code. The short 2-hour lookback and fast 10-minute schedule prioritize rapid detection of this critical transition.
- **Join Key(s):** `host.name`
- **Lookback:** 2 hours
- **Schedule:** Every 10 minutes
- **Priority:** P1
- **Integration:** [alerts](https://www.elastic.co/guide/en/security/current/alerts-ui-manage.html)
- **Language:** `[ES|QL]`

## Query

```esql
FROM .internal.alerts-security.alerts-default
| WHERE @timestamp > NOW() - 2 HOURS
    AND kibana.alert.workflow_status == "open"
    AND host.name IS NOT NULL AND host.name != ""
    AND kibana.alert.rule.threat.tactic.name IN (
        "Initial Access", "Execution"
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
    is_initial_access = CASE(
        kibana.alert.rule.threat.tactic.name == "Initial Access", 1, 0
    ),
    is_execution = CASE(
        kibana.alert.rule.threat.tactic.name == "Execution", 1, 0
    ),
    initial_access_ts = CASE(
        kibana.alert.rule.threat.tactic.name == "Initial Access", @timestamp, NULL
    ),
    execution_ts = CASE(
        kibana.alert.rule.threat.tactic.name == "Execution", @timestamp, NULL
    ),
    is_phishing = CASE(
        kibana.alert.rule.name LIKE "*phish*"
            OR kibana.alert.rule.name LIKE "*macro*"
            OR kibana.alert.rule.name LIKE "*malicious attachment*"
            OR kibana.alert.rule.name LIKE "*spearphish*", 1, 0
    ),
    is_web_exploit = CASE(
        kibana.alert.rule.name LIKE "*exploit*"
            OR kibana.alert.rule.name LIKE "*drive-by*"
            OR kibana.alert.rule.name LIKE "*web shell*"
            OR kibana.alert.rule.name LIKE "*CVE-*", 1, 0
    )
| STATS
    Esql.alert_count = COUNT(*),
    Esql.first_seen = MIN(@timestamp),
    Esql.last_seen = MAX(@timestamp),
    Esql.total_risk_score = SUM(alert_risk),
    Esql.initial_access_count = SUM(is_initial_access),
    Esql.execution_count = SUM(is_execution),
    Esql.earliest_initial_access = MIN(initial_access_ts),
    Esql.earliest_execution = MIN(execution_ts),
    Esql.has_phishing = MAX(is_phishing),
    Esql.has_web_exploit = MAX(is_web_exploit),
    Esql.tactic_values = VALUES(kibana.alert.rule.threat.tactic.name),
    Esql.technique_values = VALUES(kibana.alert.rule.threat.technique.name),
    Esql.unique_rules = COUNT_DISTINCT(kibana.alert.rule.name),
    Esql.rule_names = VALUES(kibana.alert.rule.name),
    Esql.user_values = VALUES(user.name),
    Esql.ip_values = VALUES(related.ip)
  BY host.name
| WHERE Esql.initial_access_count >= 1
    AND Esql.execution_count >= 1
    AND Esql.earliest_execution > Esql.earliest_initial_access
| EVAL
    Esql.risk_score = ROUND(Esql.total_risk_score * 1.5),
    Esql.access_to_execution_minutes = ROUND(DATE_DIFF("minutes", Esql.earliest_initial_access, Esql.earliest_execution)),
    Esql.correlation_severity = CASE(
        Esql.has_phishing == 1 AND Esql.execution_count >= 1, "critical",
        Esql.has_web_exploit == 1 AND Esql.execution_count >= 1, "high",
        Esql.initial_access_count >= 1 AND Esql.execution_count >= 1, "high",
        "medium"
    ),
    Esql.description = CONCAT(
        "Host ", host.name,
        " | Initial Access to Execution Pipeline",
        " | Risk Score: ", TO_STRING(Esql.risk_score),
        " | Initial Access alerts: ", TO_STRING(Esql.initial_access_count),
        " | Execution alerts: ", TO_STRING(Esql.execution_count),
        " | Access-to-execution gap: ", TO_STRING(Esql.access_to_execution_minutes), " min",
        " | Phishing involved: ", TO_STRING(Esql.has_phishing),
        " | Web exploit involved: ", TO_STRING(Esql.has_web_exploit),
        " | ", TO_STRING(Esql.unique_rules), " rules"
    )
| SORT Esql.risk_score DESC
| LIMIT 50
```

## Strategy

Alerts are tagged with kill chain stage flags. STATS computes the earliest timestamp for Initial Access alerts and the earliest timestamp for Execution alerts per host. The rule filters for hosts where an Execution alert follows an Initial Access alert. Additional context is extracted: whether the initial access was phishing-related or web-exploit-related for more granular severity classification. A 1.5x risk multiplier is applied for the confirmed initial-access-to-execution chain.

## Severity Logic

```
CASE(
    Esql.has_phishing == 1 AND Esql.execution_count >= 1, "critical",
    Esql.has_web_exploit == 1 AND Esql.execution_count >= 1, "high",
    Esql.initial_access_count >= 1 AND Esql.execution_count >= 1, "high",
    "medium"
)
```

| Condition | Severity |
|-----------|----------|
| Phishing-based initial access followed by execution | Critical |
| Web exploit-based initial access followed by execution | High |
| Any initial access followed by execution | High |
| Fallback | Medium |

## Notes

- **Blind Spots:**
  - Initial access via removable media (USB) — may not generate an "Initial Access" tactic alert
  - Delayed execution exceeding the 2-hour lookback window — attacker gains access and waits hours or days before executing
  - Initial access and execution detected by different host identifiers (e.g., email gateway uses a different host field than the endpoint agent)
  - Fileless execution techniques that evade Execution tactic detection

- **False Positives:**
  - **Users opening legitimate email attachments that trigger broad rules**: Overly sensitive macro or attachment rules firing on benign Office documents, followed by legitimate application execution. Mitigation: tune initial access rules to reduce FP rate on benign attachments.
  - **Software installation processes**: Download from vendor site (Initial Access pattern match) followed by installer execution. Mitigation: maintain a list of approved software download domains.
  - **Browser-based applications**: Web application loading triggers browser security alerts (Initial Access), followed by legitimate plugin execution. Mitigation: exclude known browser process chains.

- **Tuning:**
  1. Lookback window (default: 2h) — this is intentionally short; extend to 4h only if initial access and execution are commonly separated by longer intervals
  2. Schedule (default: every 10 min) — faster than other Tier 2 rules because this transition is the most time-critical
  3. Add process chain context: correlate `process.parent.name` from the execution alert with the initial access vector
  4. Phishing and web exploit patterns — customize for your rule naming conventions
  5. Consider filtering out building block alerts from the initial access side to reduce noise

## Data Requirements

- **Index**: `.internal.alerts-security.alerts-default`
- **Required fields**: `host.name`, `@timestamp`, `signal.rule.severity`, `kibana.alert.workflow_status`, `kibana.alert.rule.building_block_type`, `kibana.alert.rule.name`, `kibana.alert.rule.threat.tactic.name`, `kibana.alert.rule.threat.technique.name`, `user.name`, `related.ip`
- **Minimum volume**: 1+ Initial Access alert AND 1+ Execution alert for same `host.name` within 2h
- **Critical dependency**: Detection rules for Initial Access AND Execution must both be deployed and properly tactic-mapped

## Dependencies

- No required lookup indices
- Prerequisite: Detection rules covering both Initial Access and Execution tactics must be deployed
- Optional: `lookup-critical-assets` — escalate severity for high-value hosts
- Complementary: CORR-2A (Kill Chain Progression) will also detect this pattern as part of a broader multi-stage chain

## Validation

Red team scenario:
1. Send a test phishing email with a macro-enabled document to the test user on the target host
2. User opens the document and enables macros (triggers Initial Access alert)
3. Macro spawns PowerShell or cmd.exe and executes a payload (triggers Execution alert)
4. Ensure both alerts fire within 30 minutes on the same host

Expected result: Host appears with `Esql.initial_access_count >= 1`, `Esql.execution_count >= 1`, `Esql.has_phishing = 1`, severity = critical.

## Elastic Comparison

Elastic does not ship an initial-access-to-execution pipeline correlation rule. Individual rules detect phishing (e.g., "Suspicious MS Office Child Process") and execution (e.g., "Suspicious PowerShell Execution") independently. CORR-2F correlates them temporally on the same host to confirm the initial access actually led to code execution — the critical transition from "alert" to "compromise."
