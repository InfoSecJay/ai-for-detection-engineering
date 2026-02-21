# Kill Chain Progression by Host

---

## Metadata

- **Rule ID:** `CORR-2A`
- **Tier:** 2 — Kill Chain and Behavioral Correlation
- **Author:** Detection Engineering
- **Description:** Detect hosts exhibiting alerts that span multiple kill chain stages — early (Initial Access/Reconnaissance/Resource Development), mid (Execution through Lateral Movement), and late (Collection/C2/Exfiltration/Impact) — within a 4-hour window. A host progressing through two or more kill chain stages indicates an active, advancing compromise rather than isolated alert noise.
- **Join Key(s):** `host.name`
- **Lookback:** 4 hours
- **Schedule:** Every 15 minutes
- **Priority:** P1
- **Integration:** [alerts](https://www.elastic.co/guide/en/security/current/alerts-ui-manage.html)
- **Language:** `[ES|QL]`

## Query

```esql
FROM .internal.alerts-security.alerts-default
| WHERE @timestamp > NOW() - 4 HOURS
    AND kibana.alert.workflow_status == "open"
    AND host.name IS NOT NULL AND host.name != ""
| EVAL
    severity_weight = CASE(
        signal.rule.severity == "critical", 25,
        signal.rule.severity == "high", 15,
        signal.rule.severity == "medium", 8,
        signal.rule.severity == "low", 3, 1
    ),
    bbr_factor = CASE(kibana.alert.rule.building_block_type == "default", 0.3, 1.0),
    alert_risk = ROUND(severity_weight * bbr_factor),
    kill_chain_stage = CASE(
        kibana.alert.rule.parameters.threat.tactic.name IN (
            "Initial Access", "Reconnaissance", "Resource Development"
        ), "early",
        kibana.alert.rule.parameters.threat.tactic.name IN (
            "Execution", "Persistence", "Privilege Escalation", "Defense Evasion",
            "Credential Access", "Discovery", "Lateral Movement"
        ), "mid",
        kibana.alert.rule.parameters.threat.tactic.name IN (
            "Collection", "Command and Control", "Exfiltration", "Impact"
        ), "late",
        "unmapped"
    ),
    is_early = CASE(kill_chain_stage == "early", 1, 0),
    is_mid = CASE(kill_chain_stage == "mid", 1, 0),
    is_late = CASE(kill_chain_stage == "late", 1, 0)
| STATS
    Esql.alert_count = COUNT(*),
    Esql.first_seen = MIN(@timestamp),
    Esql.last_seen = MAX(@timestamp),
    Esql.total_risk = SUM(alert_risk),
    Esql.has_early = MAX(is_early),
    Esql.has_mid = MAX(is_mid),
    Esql.has_late = MAX(is_late),
    Esql.tactic_count = COUNT_DISTINCT(kibana.alert.rule.parameters.threat.tactic.name),
    Esql.tactic_values = VALUES(kibana.alert.rule.parameters.threat.tactic.name),
    Esql.technique_values = VALUES(kibana.alert.rule.threat.technique.name),
    Esql.unique_rules = COUNT_DISTINCT(kibana.alert.rule.name),
    Esql.rule_names = VALUES(kibana.alert.rule.name),
    Esql.user_values = VALUES(user.name),
    Esql.user_count = COUNT_DISTINCT(user.name),
    Esql.ip_values = VALUES(related.ip)
  BY host.name
| EVAL
    Esql.stage_count = Esql.has_early + Esql.has_mid + Esql.has_late
| WHERE Esql.stage_count >= 2
| EVAL
    Esql.risk_score = ROUND(Esql.total_risk * Esql.stage_count),
    Esql.correlation_severity = CASE(
        Esql.stage_count >= 3, "critical",
        Esql.stage_count >= 2 AND Esql.has_late == 1, "high",
        Esql.stage_count >= 2, "high",
        "medium"
    ),
    Esql.description = CONCAT(
        "Host ", host.name,
        " | Kill Chain Stages: ", TO_STRING(Esql.stage_count), "/3",
        " (early=", TO_STRING(Esql.has_early),
        " mid=", TO_STRING(Esql.has_mid),
        " late=", TO_STRING(Esql.has_late), ")",
        " | Risk Score: ", TO_STRING(Esql.risk_score),
        " | ", TO_STRING(Esql.tactic_count), " MITRE tactics",
        " | ", TO_STRING(Esql.unique_rules), " rules",
        " | ", TO_STRING(Esql.alert_count), " alerts",
        " | Window: ", TO_STRING(Esql.first_seen), " to ", TO_STRING(Esql.last_seen)
    )
| SORT Esql.risk_score DESC
| LIMIT 50
```

## Strategy

Each alert is mapped to a kill chain stage using `kibana.alert.rule.parameters.threat.tactic.name`. The query computes boolean flags (`has_early`, `has_mid`, `has_late`) per host, then counts how many distinct stages are represented. Hosts with alerts in 2+ stages pass filtering. The risk score is amplified by the stage count — a host with all three stages gets a 3x multiplier because full kill chain traversal within 4 hours is a high-confidence indicator of active compromise.

## Severity Logic

```
CASE(
    Esql.stage_count >= 3, "critical",              -- Full kill chain traversal
    Esql.stage_count >= 2 AND Esql.has_late == 1, "high",  -- Late-stage involvement
    Esql.stage_count >= 2, "high",                   -- Two stages present
    "medium"                                         -- Fallback
)
```

| Condition | Severity |
|-----------|----------|
| All 3 kill chain stages present | Critical |
| 2 stages including late stage (C2/exfil/impact) | High |
| 2 stages (early + mid or other combos) | High |
| Fallback | Medium |

## Notes

- **Blind Spots:**
  - Attacks spanning more than 4 hours between stages — slow-and-low progressions where Initial Access occurs in the morning and Execution occurs in the afternoon will be missed
  - MITRE ATT&CK tactics not mapped in detection rule metadata — alerts without `kibana.alert.rule.parameters.threat.tactic.name` populated fall into "unmapped" and are excluded from stage counting
  - Alerts missing `host.name` (pure network-based detections with only IP addresses)
  - Multi-host attack chains where different stages occur on different hosts (use CORR-2C for lateral movement tracking)

- **False Positives:**
  - **Legitimate administrative activity spanning multiple tactics**: An admin performing a deployment may trigger Initial Access (remote login), Execution (running scripts), and Persistence (service installation) alerts within hours. Mitigation: cross-reference with change management tickets and maintenance windows.
  - **Purple team exercises**: Planned adversary simulation will intentionally walk the kill chain. Mitigation: tag purple team accounts in lookup-critical-assets or add temporary exclusions.
  - **Security tool activity**: Vulnerability scanners and EDR response actions can generate multi-tactic alerts. Mitigation: exclude known security tool host patterns.

- **Tuning:**
  1. `stage_count` threshold (default: 2) — keep at 2 for detection breadth; move to 3 if FP rate is too high
  2. Lookback window (default: 4h) — extend to 8h for environments with slower attack progression; reduce to 2h for high-speed ransomware detection
  3. Add `AND kill_chain_stage != "unmapped"` filter if too many alerts lack tactic metadata
  4. Consider a host-group variant (e.g., `host.os.type == "windows"` only) for Windows-specific kill chains
  5. Risk multiplier (default: `stage_count`) — reduce to `stage_count * 0.75` if risk scores are inflated

## Data Requirements

- **Index**: `.internal.alerts-security.alerts-default`
- **Required fields**: `host.name`, `@timestamp`, `signal.rule.severity`, `kibana.alert.workflow_status`, `kibana.alert.rule.building_block_type`, `kibana.alert.rule.name`, `kibana.alert.rule.parameters.threat.tactic.name`, `kibana.alert.rule.threat.technique.name`, `user.name`, `related.ip`
- **Minimum volume**: 2+ alerts from 2+ distinct kill chain stages for the same host within 4h
- **Critical dependency**: Detection rules MUST have MITRE ATT&CK tactic mappings populated. Rules without tactic metadata are invisible to this correlation.

## Dependencies

- No required lookup indices
- Optional: `lookup-critical-assets` — escalate severity for production/PCI hosts
- Prerequisite: Detection rules must have MITRE ATT&CK tactic mappings in `kibana.alert.rule.parameters.threat.tactic.name`

## Validation

Red team scenario: On a single test host within a 2-hour window:
1. Simulate reconnaissance scan or phishing payload delivery (triggers early-stage alert)
2. Execute credential dumping tool (e.g., Mimikatz — triggers mid-stage Credential Access alert)
3. Perform lateral movement or establish C2 channel (triggers late-stage alert)

Expected result: Host appears with `Esql.stage_count = 3`, severity = critical, risk score = `SUM(alert_risk) * 3`.

## Elastic Comparison

Elastic does not ship a kill-chain-progression correlation rule. The closest native capability is the Risk Score engine, which accumulates risk per entity but does not evaluate kill chain stage ordering or progression. Elastic's "Alerts Involving Multiple MITRE Techniques" counts technique diversity but does not group by kill chain stage. CORR-2A adds explicit stage classification, temporal ordering awareness, and stage-count-based severity amplification.
