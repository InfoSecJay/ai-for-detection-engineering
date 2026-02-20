# Correlation Rule Framework: From Single Rule to Multi-Tier Detection

## Overview

This document analyzes a common ES|QL correlation rule pattern — "alerts from multiple integrations for a single user" — identifies its strengths and critical gaps, and designs a production-grade multi-tier correlation framework. The framework splits a single monolithic correlation rule into a family of specialized rules that — together — implement the risk-based, entity-centric, kill-chain-aware correlation architecture that industry-leading detection teams use in 2025-2026.

**The big idea:** Your 4,000+ detection rules are the building blocks. The correlation layer turns those building blocks into high-fidelity, analyst-facing incidents. This framework is the bridge between raw alert volume and actionable intelligence — and it's the prerequisite layer that must exist *before* LLMs add narrative synthesis, triage verdicts, and investigation automation on top.

---

## Part 1: The Baseline Pattern and Its Gaps

### The Common Pattern

The starting point is a pattern many Elastic Security teams implement as their first correlation rule. The typical structure:

1. **Query the SIEM alerts/signals index** (e.g., `.internal.alerts-security.alerts-default` or a custom signals index)
2. **Filter** to alerts with a populated `user.name`, excluding system and service accounts
3. **EVAL** severity flags (critical/high/medium/low) excluding building block rules from severity counts, while counting BBRs separately
4. **STATS BY user.name** aggregating: alert count, timestamps, distinct tactic/technique names, severity breakdown, distinct rule names, distinct data sources, related IPs, and host names
5. **WHERE threshold**: minimum N unique rules, minimum N data sources, at least one high or critical alert
6. **EVAL description** generating a human-readable summary

### What This Pattern Does Well

1. **Queries the alert index directly.** Operating on the signals/alerts index instead of raw logs is the correct approach for correlation rules. The hard detection work is already done — correlation operates on the output.

2. **Excludes building block rules from severity counts.** Filtering on `kibana.alert.rule.building_block_type` in severity EVAL is smart. BBRs are designed to be low-fidelity signals — they shouldn't inflate the severity picture.

3. **Counts BBRs separately.** Keeping BBR count as a distinct metric preserves context without letting BBR volume distort the correlation logic.

4. **Aggregates rich context per user.** The STATS block captures everything an analyst needs: rule names, tactics, techniques, data sources, IPs, hostnames, severity breakdown, timestamps.

5. **Requires cross-data-source diversity.** Enforcing multi-source correlation means the rule won't fire on alerts from a single integration. This is the right instinct.

6. **Requires minimum severity.** A high/critical threshold prevents low-severity-only noise from generating correlation alerts.

7. **Namespace prefix on computed fields (e.g., `Esql.*`).** This makes correlation-generated fields instantly identifiable in the alert document. Clean practice.

### Critical Gaps

#### Gap 1: Single Entity Dimension (User Only)

**Problem:** The rule correlates exclusively by `user.name`. This misses three major attack patterns:

- **Host-centric attacks:** Malware lands on a host and operates under multiple user contexts (or SYSTEM). Endpoint + network + DNS alerts all point to the same `host.name`, but no single `user.name` ties them together.
- **IP-centric attacks:** An external attacker IP hits multiple services (firewall deny → web server exploit attempt → SSH brute force). The pivot entity is `source.ip`, not `user.name`.
- **Cross-entity attacks:** An attacker compromises a user's credentials (identity alerts on `user.name`), logs into a host (endpoint alerts on `host.name`), and exfiltrates data (network alerts on `source.ip`). The most dangerous attacks span all three entity types.

**Impact:** You're blind to any attack that doesn't converge on a single user identity. That's a significant portion of real-world intrusions.

#### Gap 2: No Risk Scoring — All Alerts Count Equally

**Problem:** A critical EDR alert detecting LSASS memory access contributes the same weight as a low-severity firewall block. The threshold logic (`>= 2 rules AND > 2 sources AND 1+ high/critical`) is binary: you either cross it or you don't.

**What leading teams do:** Splunk's Risk-Based Alerting assigns `risk_score = (impact × confidence) / 100` per event, with modifiers for asset criticality and user privilege. The correlation threshold fires on *accumulated risk*, not raw counts. A single critical EDR alert (risk 80) plus a medium Okta anomaly (risk 25) might cross the threshold. Three low-severity firewall blocks (risk 5 each) would not.

**Impact:** Equal weighting creates two failure modes:
- **Under-alerting:** A truly dangerous critical + medium pair from EDR + Okta doesn't fire because it's only 2 data sources (needs >2).
- **Over-alerting:** Three low-severity building block alerts from endpoint + cloud + identity fire the rule despite being individually innocuous.

#### Gap 3: No Temporal Awareness

**Problem:** The rule has no time constraint within its query. The lookback window is set entirely by the Kibana rule schedule configuration. But there's no distinction between:
- 5 alerts in 10 minutes (burst — likely active attack or a single incident)
- 5 alerts over 7 days (background noise — coincidental alerts for a busy user)

**What leading teams do:** Multiple correlation rules with different temporal windows:
- **Burst detection (1-4 hours):** Catches active attacks with rapid alert generation.
- **Slow-burn detection (24 hours):** Catches attacks that spread activity across a workday.
- **Campaign detection (7 days):** Catches multi-stage attacks with patient adversaries.

Decay mechanisms reduce the weight of older alerts within longer windows so stale signals don't dominate.

**Impact:** Without temporal logic, the rule's effectiveness depends entirely on the Kibana schedule configuration. A 24-hour lookback catches both true positives and coincidental alert clusters with equal enthusiasm.

#### Gap 4: No Kill Chain Progression Logic

**Problem:** Many implementations capture tactic counts and tactic values in the STATS output — but never use them in the threshold logic. Tactic diversity is the single strongest indicator of a real multi-stage attack:

- **User with 5 alerts, all "Execution" tactic:** Probably a noisy user running scripts. 5 similar alerts, no progression.
- **User with 3 alerts spanning "Initial Access" → "Execution" → "Credential Access":** This is kill chain progression. Even with fewer total alerts, this pattern is far more dangerous.

**What leading teams do:** Splunk's out-of-the-box RBA includes "ATT&CK Tactic Threshold Exceeded for Object Over Previous 7 Days" which fires when an entity spans N+ distinct tactics. The threshold is typically 3-4 tactics. Microsoft Sentinel's Fusion engine does this automatically with ML.

**Impact:** The most valuable signal the rule captures (tactic diversity) is collected but ignored in the correlation logic.

#### Gap 5: Data Source Count Is Misleading

**Problem:** Using `COUNT_DISTINCT(event.dataset)` counts raw dataset values. This overcounts cross-domain diversity because:

- `aws.cloudtrail` and `aws.s3access` = 2 datasets but both are AWS (same domain)
- `endpoint.events.process` and `endpoint.events.file` = 2 datasets but both are endpoint (same domain)
- `sentinelone.alert` and `sentinelone.threat` = 2 datasets but both are SentinelOne

A threshold of "> 2 data sources" is easily passed by a user with only endpoint alerts from 3 endpoint datasets. That's not cross-domain correlation — it's intra-domain noise.

**Common bug:** Many implementations compute a `data_source` field via `COALESCE(event.dataset, labels.technology, event.module)` but then forget to use it in STATS, counting `event.dataset` instead of the computed field.

**Impact:** False sense of cross-domain coverage. Rules fire when they shouldn't because 3 endpoint datasets ≠ 3 security domains.

#### Gap 6: No Host Spread Analysis

**Problem:** Host names are often captured as `VALUES(host.name)` for context, but the number of distinct hosts isn't used in the correlation logic. A user triggering alerts on 1 host is different from a user triggering alerts on 15 hosts:

- **1 host:** User is doing something suspicious on their workstation.
- **15 hosts:** User is moving laterally, or their credentials are being used across the environment.

**Impact:** Missing a critical lateral movement indicator that's already in the data.

#### Gap 7: Minimal Service Account Exclusions

**Problem:** Most initial implementations exclude only a handful of accounts (e.g., `SYSTEM`, `Administrator`). In a large-scale environment with SentinelOne, Okta, AWS, etc., there are many more system/service identities that generate legitimate multi-source alerts:

- Windows: `LOCAL SERVICE`, `NETWORK SERVICE`, `DWM-*`, `UMFD-*`, machine accounts (`$` suffix)
- Cloud: AWS service-linked roles, Lambda execution roles, automation users
- Okta: system integrations, SCIM provisioning accounts
- General: `svc-*`, `app-*`, CI/CD service accounts

**Impact:** Service accounts are the #1 source of false positive correlation alerts because they legitimately operate across multiple data sources by design.

#### Gap 8: Static Single-Tier Threshold

**Problem:** Most implementations use a single threshold (e.g., `>= 2 rules AND > 2 data sources AND (critical > 0 OR high > 0)`). Everything that crosses this threshold gets the same treatment. There's no distinction between:

- **Clearly malicious:** 8 alerts, 5 data sources, 3 critical, spanning 6 tactics
- **Borderline:** 2 alerts, 3 data sources, 1 high, 1 tactic

Both generate the same correlation alert. The analyst gets no signal about which to prioritize.

**What leading teams do:** Tiered thresholds with dynamic severity assignment:
- **Critical correlation:** Risk score > 150 OR critical alerts + 4+ tactics
- **High correlation:** Risk score > 100 OR multiple high alerts + 3+ domains
- **Medium correlation:** Risk score > 60 OR 3+ tactics + 4+ rules

**Impact:** Analyst fatigue from treating all correlation alerts with equal urgency.

#### Gap 9: No Velocity / Baseline Comparison

**Problem:** The rule doesn't distinguish between a user who always generates 5 alerts per day (normal for an IT admin) and a user who normally generates 0 alerts and suddenly has 5 today (anomalous). Both cross the same threshold.

**What leading teams do:** UEBA integration provides behavioral baselines. Some implementations use `INLINE STATS` or transform indices to compare current alert counts against rolling averages. The correlation threshold is adjusted per entity based on historical behavior.

**Impact:** IT admins, security testers, and DevOps engineers constantly trigger correlation alerts because their legitimate multi-domain activity consistently exceeds static thresholds.

#### Gap 10: No Geographic or Network Context in Correlation Logic

**Problem:** IP values are often captured for context but not analyzed. Source IP geolocation, impossible travel detection, and VPN/proxy indicators are not used in the correlation logic.

**Impact:** Misses a strong signal — a user's alerts coming from a foreign IP + multiple domains is far more suspicious than the same alerts from a known corporate IP.

---

## Part 2: The Multi-Tier Correlation Framework

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    4,000+ Detection Rules                       │
│  (Standalone alerts + Building block rules)                     │
│  SentinelOne | Okta | AWS | Firewall | NDR | Proxy | DNS | ... │
└────────────────────┬────────────────────────────────────────────┘
                     │ Alerts written to signals index
                     ▼
┌─────────────────────────────────────────────────────────────────┐
│              TIER 1: Entity-Centric Correlation                 │
│                                                                 │
│  Rule 1A: User-Centric Multi-Source Correlation     │
│  Rule 1B: Host-Centric Multi-Source (new)                       │
│  Rule 1C: Source IP Correlation (new)                           │
│                                                                 │
│  → Detects: alert accumulation per entity across domains        │
│  → Schedule: every 5-15 min, lookback 1-4 hours                 │
└────────────────────┬────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────┐
│              TIER 2: Kill Chain & Behavioral                    │
│                                                                 │
│  Rule 2A: Kill Chain Progression (user or host)                 │
│  Rule 2B: Identity-to-Endpoint Chain (Okta → EDR)              │
│  Rule 2C: Lateral Movement Spread (user across N hosts)         │
│                                                                 │
│  → Detects: attack stage progression, cross-domain chains       │
│  → Schedule: every 15-30 min, lookback 4-24 hours               │
└────────────────────┬────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────┐
│              TIER 3: Risk Score Accumulation                    │
│                                                                 │
│  Rule 3A: Cumulative Risk Score Breach (user)                   │
│  Rule 3B: Cumulative Risk Score Breach (host)                   │
│                                                                 │
│  → Detects: slow-burn risk accumulation over extended windows   │
│  → Schedule: every 30-60 min, lookback 24h-7d                   │
└────────────────────┬────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────┐
│              TIER 4: Meta-Correlation                            │
│                                                                 │
│  Rule 4A: Multi-Entity Campaign Detection                       │
│                                                                 │
│  → Detects: multiple entities hitting Tier 1-3 rules            │
│  → Schedule: every 30-60 min, lookback 4-24 hours               │
│  → Queries: correlation alert index (alerts from Tiers 1-3)     │
└────────────────────┬────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────┐
│              AI LAYER (Future / UC-11, UC-12)                   │
│                                                                 │
│  LLM Cluster Narrative Synthesis                                │
│  LLM Triage Verdicts                                            │
│  Agentic Investigation                                          │
│                                                                 │
│  → Consumes: correlation alerts with all contributing signals   │
│  → Produces: narratives, verdicts, investigation reports        │
└─────────────────────────────────────────────────────────────────┘
```

### Design Principles

1. **Domain categorization over dataset counting.** Group `event.dataset` values into security domains (endpoint, identity, cloud, network, proxy, dns, email). Count distinct *domains*, not distinct datasets.

2. **Weighted risk scoring.** Every alert contributes a risk score = `severity_weight × bbr_factor × tactic_weight`. Correlation thresholds fire on accumulated risk, not raw counts.

3. **Tactic diversity as a first-class threshold.** Kill chain breadth (distinct MITRE tactics) is weighted independently of total alert count.

4. **Host spread as a correlation signal.** For user-centric rules, the number of distinct hosts the user touched is an input to the correlation logic.

5. **Tiered severity output.** Correlation alerts get a dynamically computed severity (critical/high/medium) based on the strength of the correlation signal. Not all correlations are equal.

6. **Multiple temporal windows.** Different rules operate on different lookback windows to catch burst attacks (hours), daily attacks (24h), and slow-burn campaigns (7d).

7. **Service account handling via lookup tables.** Instead of growing the `NOT user.name LIKE...` list, use a LOOKUP JOIN to a service account exceptions index (when available) or a comprehensive pattern list.

---

## Part 3: ES|QL Rule Implementations

### Common Patterns

#### Security Domain Categorization

Used across all rules. Maps raw `event.dataset` to a normalized security domain:

```esql
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
)
```

> **Note:** Adapt these patterns to your actual `event.dataset` values. Run `FROM .internal.alerts-security.alerts-default | STATS count = COUNT(*) BY event.dataset | SORT count DESC` to see what's in your environment.

#### Severity Risk Weights

```esql
severity_weight = CASE(
    signal.rule.severity == "critical", 25,
    signal.rule.severity == "high", 15,
    signal.rule.severity == "medium", 8,
    signal.rule.severity == "low", 3,
    1
)
```

These weights are inspired by Splunk RBA's `(impact × confidence)` model, simplified for ES|QL. The ratios matter more than the absolute numbers — critical is ~8x low, high is ~5x low. Tune these to your environment.

#### Building Block Risk Factor

```esql
bbr_factor = CASE(
    kibana.alert.rule.building_block_type == "default", 0.3,
    1.0
)
```

Building blocks contribute 30% of their severity weight. They're designed as low-fidelity signals that become meaningful only in aggregate. Don't zero them out (they carry valid signal), but don't let them compete with standalone high-confidence detections.

#### Service Account Exclusion Patterns

```esql
// Comprehensive service account exclusion
AND NOT user.name IN ("SYSTEM", "Administrator", "LOCAL SERVICE", "NETWORK SERVICE",
    "DWM-1", "DWM-2", "DWM-3", "UMFD-0", "UMFD-1", "UMFD-2",
    "DefaultAccount", "Guest", "WDAGUtilityAccount")
AND NOT (
    user.name LIKE "svc-*"
    OR user.name LIKE "svc_*"
    OR user.name LIKE "app-*"
    OR user.name LIKE "sa-*"
    OR user.name LIKE "*$"           // Machine accounts
    OR user.name LIKE "MSOL_*"       // Azure AD Connect
    OR user.name LIKE "HealthMail*"  // Exchange health mailbox
    OR user.name LIKE "SM_*"         // Exchange managed service
)
```

> **Future improvement:** When ES|QL LOOKUP JOIN is available in your version, replace this with a join to a managed service account exceptions lookup index. This moves maintenance from the rule query to a data management workflow.

---

### Rule 1A: User-Centric Multi-Source Correlation

**Purpose:** Detect when a single user accumulates alerts across multiple security domains with sufficient risk to warrant analyst attention. This is the foundational user-centric correlation rule.

**Schedule:** Every 10 minutes, lookback 4 hours

**Key design features:**
- Risk scoring replaces flat counting
- Domain categorization replaces raw dataset counting
- Tactic diversity feeds the threshold logic
- Host spread is captured and used
- Tiered severity output
- Comprehensive service account exclusions

```esql
FROM .internal.alerts-security.alerts-default
| WHERE
    user.name IS NOT NULL
    AND NOT user.name IN ("SYSTEM", "Administrator", "LOCAL SERVICE", "NETWORK SERVICE",
        "DWM-1", "DWM-2", "DWM-3", "UMFD-0", "UMFD-1", "UMFD-2",
        "DefaultAccount", "Guest", "WDAGUtilityAccount")
    AND NOT (
        user.name LIKE "svc-*"
        OR user.name LIKE "svc_*"
        OR user.name LIKE "app-*"
        OR user.name LIKE "sa-*"
        OR user.name LIKE "*$"           // Machine accounts
        OR user.name LIKE "MSOL_*"       // Azure AD Connect
        OR user.name LIKE "HealthMail*"  // Exchange health mailbox
        OR user.name LIKE "SM_*"         // Exchange managed service
    )
| EVAL
    // --- Risk Scoring ---
    severity_weight = CASE(
        signal.rule.severity == "critical", 25,
        signal.rule.severity == "high", 15,
        signal.rule.severity == "medium", 8,
        signal.rule.severity == "low", 3,
        1
    ),
    bbr_factor = CASE(kibana.alert.rule.building_block_type == "default", 0.3, 1.0),
    alert_risk = ROUND(severity_weight * bbr_factor),

    // --- Security Domain Categorization ---
    domain_category = CASE(
        event.dataset LIKE "endpoint*" OR event.dataset LIKE "sentinelone*"
            OR event.dataset LIKE "windows*" OR event.dataset LIKE "sysmon*", "endpoint",
        event.dataset LIKE "okta*" OR event.dataset LIKE "azure_ad*"
            OR event.dataset LIKE "entra*", "identity",
        event.dataset LIKE "aws*" OR event.dataset LIKE "gcp*"
            OR event.dataset LIKE "azure*" OR event.dataset LIKE "o365*", "cloud",
        event.dataset LIKE "panw*" OR event.dataset LIKE "fortinet*"
            OR event.dataset LIKE "firewall*", "network_fw",
        event.dataset LIKE "extrahop*" OR event.dataset LIKE "zeek*"
            OR event.dataset LIKE "suricata*", "network_ndr",
        event.dataset LIKE "proxy*" OR event.dataset LIKE "zscaler*", "proxy",
        event.dataset LIKE "dns*", "dns",
        event.dataset LIKE "email*" OR event.dataset LIKE "proofpoint*", "email",
        COALESCE(labels.technology, event.module, "other")
    ),

    // --- Severity Flags (excluding BBRs) ---
    is_critical = CASE(signal.rule.severity == "critical" AND kibana.alert.rule.building_block_type IS NULL, 1, 0),
    is_high = CASE(signal.rule.severity == "high" AND kibana.alert.rule.building_block_type IS NULL, 1, 0),
    is_medium = CASE(signal.rule.severity == "medium" AND kibana.alert.rule.building_block_type IS NULL, 1, 0),
    is_low = CASE(signal.rule.severity == "low" AND kibana.alert.rule.building_block_type IS NULL, 1, 0),
    is_bbr = CASE(kibana.alert.rule.building_block_type == "default", 1, 0),

    data_source = COALESCE(event.dataset, labels.technology, event.module)

| STATS
    // Core metrics
    Esql.alert_count = COUNT(*),
    Esql.first_seen = MIN(@timestamp),
    Esql.last_seen = MAX(@timestamp),

    // Risk accumulation
    Esql.total_risk_score = SUM(alert_risk),
    Esql.max_single_risk = MAX(alert_risk),

    // MITRE ATT&CK coverage
    Esql.tactic_count = COUNT_DISTINCT(kibana.alert.rule.threat.tactic.name),
    Esql.tactic_values = VALUES(kibana.alert.rule.threat.tactic.name),
    Esql.technique_values = VALUES(kibana.alert.rule.threat.technique.name),
    Esql.subtechnique_values = VALUES(kibana.alert.rule.threat.technique.subtechnique.name),

    // Severity breakdown (excluding BBRs)
    Esql.critical_count = SUM(is_critical),
    Esql.high_count = SUM(is_high),
    Esql.medium_count = SUM(is_medium),
    Esql.low_count = SUM(is_low),
    Esql.bbr_count = SUM(is_bbr),

    // Rule diversity
    Esql.unique_rules = COUNT_DISTINCT(kibana.alert.rule.name),
    Esql.rule_names = VALUES(kibana.alert.rule.name),
    Esql.unique_alert_ids = COUNT_DISTINCT(kibana.alert.uuid),
    Esql.severity_values = VALUES(signal.rule.severity),

    // Security domain diversity (THIS is the cross-domain signal)
    Esql.domain_count = COUNT_DISTINCT(domain_category),
    Esql.domain_values = VALUES(domain_category),
    Esql.data_source_count = COUNT_DISTINCT(data_source),
    Esql.data_source_values = VALUES(data_source),

    // Host spread (lateral movement indicator)
    Esql.host_count = COUNT_DISTINCT(host.name),
    Esql.host_values = VALUES(host.name),

    // Network context
    Esql.ip_values = VALUES(related.ip),
    Esql.source_ip_count = COUNT_DISTINCT(source.ip)

  BY user.name

// --- Tiered Thresholds ---
| WHERE
    Esql.domain_count >= 2
    AND Esql.unique_rules >= 2
    AND (
        // Tier: Critical — overwhelming signal
        Esql.total_risk_score >= 100
        OR
        // Tier: High — critical alert with multi-tactic coverage
        (Esql.critical_count > 0 AND Esql.tactic_count >= 3)
        OR
        // Tier: High — multiple high-severity across 3+ domains
        (Esql.high_count >= 2 AND Esql.domain_count >= 3)
        OR
        // Tier: Medium — broad tactic coverage signals kill chain
        (Esql.tactic_count >= 4 AND Esql.unique_rules >= 3)
    )

// --- Dynamic Severity Assignment ---
| EVAL
    Esql.correlation_severity = CASE(
        Esql.total_risk_score >= 150 OR (Esql.critical_count > 0 AND Esql.tactic_count >= 4), "critical",
        Esql.total_risk_score >= 100 OR (Esql.critical_count > 0 AND Esql.tactic_count >= 3)
            OR (Esql.high_count >= 3 AND Esql.domain_count >= 3), "high",
        Esql.total_risk_score >= 60 OR (Esql.high_count >= 2 AND Esql.tactic_count >= 3), "medium",
        "low"
    ),
    Esql.description = CONCAT(
        "User ", user.name,
        " | Risk Score: ", TO_STRING(Esql.total_risk_score),
        " | ", TO_STRING(Esql.unique_rules), " rules across ",
        TO_STRING(Esql.domain_count), " security domains",
        " | ", TO_STRING(Esql.tactic_count), " MITRE tactics",
        " | ", TO_STRING(Esql.host_count), " hosts",
        " | ", TO_STRING(Esql.alert_count), " total alerts",
        " | Window: ", TO_STRING(Esql.first_seen), " to ", TO_STRING(Esql.last_seen)
    )
```

---

### Rule 1B: Host-Centric Multi-Source Correlation (New)

**Purpose:** Detect when a single host accumulates alerts across multiple security domains. Catches endpoint compromise chains, malware infections with network C2, and host-based attack progression that may span multiple users.

**Schedule:** Every 10 minutes, lookback 4 hours

**Why it's needed:** An attacker who compromises a host may operate as SYSTEM, create new local accounts, or use multiple service accounts. User-centric correlation misses this entirely. Host-centric correlation catches:
- EDR process alert + NDR C2 beacon + DNS DGA query on same host
- SentinelOne threat + firewall block + proxy block on same host
- Multiple users triggering alerts on the same compromised server

```esql
FROM .internal.alerts-security.alerts-default
| WHERE
    host.name IS NOT NULL
    AND host.name != ""
| EVAL
    severity_weight = CASE(
        signal.rule.severity == "critical", 25,
        signal.rule.severity == "high", 15,
        signal.rule.severity == "medium", 8,
        signal.rule.severity == "low", 3,
        1
    ),
    bbr_factor = CASE(kibana.alert.rule.building_block_type == "default", 0.3, 1.0),
    alert_risk = ROUND(severity_weight * bbr_factor),

    domain_category = CASE(
        event.dataset LIKE "endpoint*" OR event.dataset LIKE "sentinelone*"
            OR event.dataset LIKE "windows*" OR event.dataset LIKE "sysmon*", "endpoint",
        event.dataset LIKE "okta*" OR event.dataset LIKE "azure_ad*"
            OR event.dataset LIKE "entra*", "identity",
        event.dataset LIKE "aws*" OR event.dataset LIKE "gcp*"
            OR event.dataset LIKE "azure*" OR event.dataset LIKE "o365*", "cloud",
        event.dataset LIKE "panw*" OR event.dataset LIKE "fortinet*"
            OR event.dataset LIKE "firewall*", "network_fw",
        event.dataset LIKE "extrahop*" OR event.dataset LIKE "zeek*"
            OR event.dataset LIKE "suricata*", "network_ndr",
        event.dataset LIKE "proxy*" OR event.dataset LIKE "zscaler*", "proxy",
        event.dataset LIKE "dns*", "dns",
        COALESCE(labels.technology, event.module, "other")
    ),

    is_critical = CASE(signal.rule.severity == "critical" AND kibana.alert.rule.building_block_type IS NULL, 1, 0),
    is_high = CASE(signal.rule.severity == "high" AND kibana.alert.rule.building_block_type IS NULL, 1, 0),
    is_bbr = CASE(kibana.alert.rule.building_block_type == "default", 1, 0)

| STATS
    Esql.alert_count = COUNT(*),
    Esql.first_seen = MIN(@timestamp),
    Esql.last_seen = MAX(@timestamp),
    Esql.total_risk_score = SUM(alert_risk),
    Esql.tactic_count = COUNT_DISTINCT(kibana.alert.rule.threat.tactic.name),
    Esql.tactic_values = VALUES(kibana.alert.rule.threat.tactic.name),
    Esql.technique_values = VALUES(kibana.alert.rule.threat.technique.name),
    Esql.critical_count = SUM(is_critical),
    Esql.high_count = SUM(is_high),
    Esql.bbr_count = SUM(is_bbr),
    Esql.unique_rules = COUNT_DISTINCT(kibana.alert.rule.name),
    Esql.rule_names = VALUES(kibana.alert.rule.name),
    Esql.severity_values = VALUES(signal.rule.severity),
    Esql.domain_count = COUNT_DISTINCT(domain_category),
    Esql.domain_values = VALUES(domain_category),
    Esql.data_source_values = VALUES(event.dataset),

    // User spread (multiple users on same host = compromise or shared system)
    Esql.user_count = COUNT_DISTINCT(user.name),
    Esql.user_values = VALUES(user.name),

    Esql.ip_values = VALUES(related.ip)

  BY host.name

| WHERE
    Esql.domain_count >= 2
    AND Esql.unique_rules >= 2
    AND (
        Esql.total_risk_score >= 80
        OR (Esql.critical_count > 0 AND Esql.tactic_count >= 2)
        OR (Esql.high_count >= 2 AND Esql.domain_count >= 2)
        OR (Esql.tactic_count >= 3 AND Esql.unique_rules >= 3)
    )

| EVAL
    Esql.correlation_severity = CASE(
        Esql.total_risk_score >= 150 OR (Esql.critical_count > 0 AND Esql.tactic_count >= 4), "critical",
        Esql.total_risk_score >= 80 OR (Esql.critical_count > 0 AND Esql.tactic_count >= 2), "high",
        "medium"
    ),
    Esql.description = CONCAT(
        "Host ", host.name,
        " | Risk Score: ", TO_STRING(Esql.total_risk_score),
        " | ", TO_STRING(Esql.unique_rules), " rules across ",
        TO_STRING(Esql.domain_count), " domains",
        " | ", TO_STRING(Esql.tactic_count), " tactics",
        " | ", TO_STRING(Esql.user_count), " users involved",
        " | ", TO_STRING(Esql.alert_count), " total alerts"
    )
```

---

### Rule 2A: Kill Chain Progression Detection (New)

**Purpose:** Detect when a single entity (user or host) accumulates alerts that span multiple stages of the MITRE ATT&CK kill chain, indicating a potential multi-stage attack. This rule fires on *tactic diversity and progression* rather than raw alert volume or risk score.

**Schedule:** Every 15 minutes, lookback 24 hours

**Why it's needed:** This is the highest-signal correlation pattern. An entity with 3 alerts spanning Initial Access → Execution → Credential Access is far more dangerous than an entity with 10 alerts all in the Execution tactic. This rule catches what the Tier 1 rules might miss if individual risk scores are low.

**Why 24-hour lookback:** Real multi-stage attacks often span hours. A patient adversary might achieve initial access in the morning and begin lateral movement in the afternoon.

```esql
FROM .internal.alerts-security.alerts-default
| WHERE
    user.name IS NOT NULL
    AND NOT user.name IN ("SYSTEM", "Administrator", "LOCAL SERVICE", "NETWORK SERVICE",
        "DefaultAccount", "Guest")
    AND NOT (
        user.name LIKE "svc-*" OR user.name LIKE "svc_*"
        OR user.name LIKE "*$"
    )
    // Only non-building-block alerts OR high-value building blocks
    AND (
        kibana.alert.rule.building_block_type IS NULL
        OR signal.rule.severity IN ("high", "critical")
    )
    // Must have tactic mapping
    AND kibana.alert.rule.threat.tactic.name IS NOT NULL
| EVAL
    // Map each alert to kill chain phase flags
    // Early-stage tactics (pre-compromise / initial foothold)
    is_recon = CASE(kibana.alert.rule.threat.tactic.name == "Reconnaissance", 1, 0),
    is_resource_dev = CASE(kibana.alert.rule.threat.tactic.name == "Resource Development", 1, 0),
    is_initial_access = CASE(kibana.alert.rule.threat.tactic.name == "Initial Access", 1, 0),

    // Mid-stage tactics (establish & expand)
    is_execution = CASE(kibana.alert.rule.threat.tactic.name == "Execution", 1, 0),
    is_persistence = CASE(kibana.alert.rule.threat.tactic.name == "Persistence", 1, 0),
    is_priv_escalation = CASE(kibana.alert.rule.threat.tactic.name == "Privilege Escalation", 1, 0),
    is_defense_evasion = CASE(kibana.alert.rule.threat.tactic.name == "Defense Evasion", 1, 0),

    // Late-stage tactics (operate on objectives)
    is_credential_access = CASE(kibana.alert.rule.threat.tactic.name == "Credential Access", 1, 0),
    is_discovery = CASE(kibana.alert.rule.threat.tactic.name == "Discovery", 1, 0),
    is_lateral_movement = CASE(kibana.alert.rule.threat.tactic.name == "Lateral Movement", 1, 0),
    is_collection = CASE(kibana.alert.rule.threat.tactic.name == "Collection", 1, 0),

    // End-stage tactics (mission objectives)
    is_c2 = CASE(kibana.alert.rule.threat.tactic.name == "Command and Control", 1, 0),
    is_exfiltration = CASE(kibana.alert.rule.threat.tactic.name == "Exfiltration", 1, 0),
    is_impact = CASE(kibana.alert.rule.threat.tactic.name == "Impact", 1, 0),

    domain_category = CASE(
        event.dataset LIKE "endpoint*" OR event.dataset LIKE "sentinelone*"
            OR event.dataset LIKE "windows*" OR event.dataset LIKE "sysmon*", "endpoint",
        event.dataset LIKE "okta*" OR event.dataset LIKE "azure_ad*"
            OR event.dataset LIKE "entra*", "identity",
        event.dataset LIKE "aws*" OR event.dataset LIKE "gcp*"
            OR event.dataset LIKE "azure*", "cloud",
        event.dataset LIKE "panw*" OR event.dataset LIKE "fortinet*", "network_fw",
        event.dataset LIKE "extrahop*" OR event.dataset LIKE "zeek*", "network_ndr",
        COALESCE(labels.technology, event.module, "other")
    )

| STATS
    Esql.alert_count = COUNT(*),
    Esql.first_seen = MIN(@timestamp),
    Esql.last_seen = MAX(@timestamp),
    Esql.tactic_count = COUNT_DISTINCT(kibana.alert.rule.threat.tactic.name),
    Esql.tactic_values = VALUES(kibana.alert.rule.threat.tactic.name),
    Esql.technique_values = VALUES(kibana.alert.rule.threat.technique.name),
    Esql.unique_rules = COUNT_DISTINCT(kibana.alert.rule.name),
    Esql.rule_names = VALUES(kibana.alert.rule.name),
    Esql.severity_values = VALUES(signal.rule.severity),
    Esql.domain_count = COUNT_DISTINCT(domain_category),
    Esql.domain_values = VALUES(domain_category),
    Esql.host_count = COUNT_DISTINCT(host.name),
    Esql.host_values = VALUES(host.name),

    // Kill chain phase presence (1 = saw at least one alert in this phase)
    Esql.saw_recon = MAX(is_recon),
    Esql.saw_initial_access = MAX(is_initial_access),
    Esql.saw_execution = MAX(is_execution),
    Esql.saw_persistence = MAX(is_persistence),
    Esql.saw_priv_escalation = MAX(is_priv_escalation),
    Esql.saw_defense_evasion = MAX(is_defense_evasion),
    Esql.saw_credential_access = MAX(is_credential_access),
    Esql.saw_discovery = MAX(is_discovery),
    Esql.saw_lateral_movement = MAX(is_lateral_movement),
    Esql.saw_collection = MAX(is_collection),
    Esql.saw_c2 = MAX(is_c2),
    Esql.saw_exfiltration = MAX(is_exfiltration),
    Esql.saw_impact = MAX(is_impact)

  BY user.name

// Calculate kill chain breadth and progression
| EVAL
    // Count distinct phases touched
    Esql.kill_chain_breadth = Esql.saw_recon + Esql.saw_initial_access + Esql.saw_execution
        + Esql.saw_persistence + Esql.saw_priv_escalation + Esql.saw_defense_evasion
        + Esql.saw_credential_access + Esql.saw_discovery + Esql.saw_lateral_movement
        + Esql.saw_collection + Esql.saw_c2 + Esql.saw_exfiltration + Esql.saw_impact,

    // Early-stage presence (pre-exploitation)
    Esql.early_stage = CASE(
        Esql.saw_recon == 1 OR Esql.saw_initial_access == 1 OR Esql.saw_execution == 1, 1, 0
    ),
    // Mid-stage presence (establish foothold)
    Esql.mid_stage = CASE(
        Esql.saw_persistence == 1 OR Esql.saw_priv_escalation == 1
            OR Esql.saw_defense_evasion == 1 OR Esql.saw_credential_access == 1, 1, 0
    ),
    // Late-stage presence (operate on objectives)
    Esql.late_stage = CASE(
        Esql.saw_lateral_movement == 1 OR Esql.saw_collection == 1
            OR Esql.saw_c2 == 1 OR Esql.saw_exfiltration == 1 OR Esql.saw_impact == 1, 1, 0
    ),

    // Cross-stage progression score (0-3, 3 = full kill chain)
    Esql.stage_progression = Esql.early_stage + Esql.mid_stage + Esql.late_stage

// Threshold: Must span at least 3 distinct tactics AND show cross-stage progression
| WHERE
    Esql.kill_chain_breadth >= 3
    AND Esql.stage_progression >= 2
    AND Esql.unique_rules >= 3

| EVAL
    Esql.correlation_severity = CASE(
        Esql.stage_progression == 3 AND Esql.kill_chain_breadth >= 5, "critical",
        Esql.stage_progression == 3 OR Esql.kill_chain_breadth >= 4, "high",
        "medium"
    ),
    Esql.description = CONCAT(
        "Kill chain progression for user ", user.name,
        " | ", TO_STRING(Esql.kill_chain_breadth), " ATT&CK tactics",
        " spanning ", TO_STRING(Esql.stage_progression), "/3 kill chain stages",
        " (early:", TO_STRING(Esql.early_stage),
        " mid:", TO_STRING(Esql.mid_stage),
        " late:", TO_STRING(Esql.late_stage), ")",
        " | ", TO_STRING(Esql.unique_rules), " rules",
        " across ", TO_STRING(Esql.domain_count), " domains",
        " on ", TO_STRING(Esql.host_count), " hosts"
    )
```

> **Variant:** Create a parallel version of this rule using `BY host.name` instead of `BY user.name` to catch host-centric kill chain progression (malware infection → C2 → lateral movement).

---

### Rule 2B: Identity-to-Endpoint Escalation Chain (New)

**Purpose:** Detect the specific pattern of identity-layer alerts (Okta, Azure AD) followed by endpoint-layer alerts for the same user — the classic credential compromise → post-exploitation chain.

**Schedule:** Every 15 minutes, lookback 8 hours

**Why it's needed:** This is one of the most common real-world attack patterns: attacker compromises credentials (detected by identity provider) → uses those credentials to access endpoint (detected by EDR). The combination of identity + endpoint alerts for the same user in a short window is extremely high-signal but easy to miss if each domain is triaged independently.

```esql
FROM .internal.alerts-security.alerts-default
| WHERE
    user.name IS NOT NULL
    AND NOT user.name IN ("SYSTEM", "Administrator", "LOCAL SERVICE", "NETWORK SERVICE")
    AND NOT (
        user.name LIKE "svc-*" OR user.name LIKE "svc_*"
        OR user.name LIKE "*$"
    )
    AND kibana.alert.rule.building_block_type IS NULL
| EVAL
    domain_category = CASE(
        event.dataset LIKE "endpoint*" OR event.dataset LIKE "sentinelone*"
            OR event.dataset LIKE "windows*" OR event.dataset LIKE "sysmon*", "endpoint",
        event.dataset LIKE "okta*" OR event.dataset LIKE "azure_ad*"
            OR event.dataset LIKE "entra*", "identity",
        event.dataset LIKE "aws*" OR event.dataset LIKE "gcp*"
            OR event.dataset LIKE "azure*", "cloud",
        "other"
    ),
    is_identity_alert = CASE(domain_category == "identity", 1, 0),
    is_endpoint_alert = CASE(domain_category == "endpoint", 1, 0),
    is_cloud_alert = CASE(domain_category == "cloud", 1, 0)

| STATS
    Esql.alert_count = COUNT(*),
    Esql.first_seen = MIN(@timestamp),
    Esql.last_seen = MAX(@timestamp),
    Esql.identity_alert_count = SUM(is_identity_alert),
    Esql.endpoint_alert_count = SUM(is_endpoint_alert),
    Esql.cloud_alert_count = SUM(is_cloud_alert),
    Esql.tactic_count = COUNT_DISTINCT(kibana.alert.rule.threat.tactic.name),
    Esql.tactic_values = VALUES(kibana.alert.rule.threat.tactic.name),
    Esql.technique_values = VALUES(kibana.alert.rule.threat.technique.name),
    Esql.unique_rules = COUNT_DISTINCT(kibana.alert.rule.name),
    Esql.rule_names = VALUES(kibana.alert.rule.name),
    Esql.severity_values = VALUES(signal.rule.severity),
    Esql.host_values = VALUES(host.name),
    Esql.host_count = COUNT_DISTINCT(host.name),
    Esql.ip_values = VALUES(related.ip),
    Esql.data_source_values = VALUES(event.dataset)

  BY user.name

// The key threshold: alerts from identity domain AND (endpoint OR cloud domain)
| WHERE
    Esql.identity_alert_count >= 1
    AND (Esql.endpoint_alert_count >= 1 OR Esql.cloud_alert_count >= 1)
    AND Esql.unique_rules >= 2

| EVAL
    // Determine the chain type
    Esql.chain_type = CASE(
        Esql.identity_alert_count >= 1 AND Esql.endpoint_alert_count >= 1 AND Esql.cloud_alert_count >= 1,
            "identity → endpoint + cloud",
        Esql.identity_alert_count >= 1 AND Esql.endpoint_alert_count >= 1,
            "identity → endpoint",
        Esql.identity_alert_count >= 1 AND Esql.cloud_alert_count >= 1,
            "identity → cloud",
        "identity → other"
    ),
    Esql.correlation_severity = CASE(
        Esql.identity_alert_count >= 1 AND Esql.endpoint_alert_count >= 1 AND Esql.cloud_alert_count >= 1, "critical",
        Esql.tactic_count >= 3, "high",
        "high"
    ),
    Esql.description = CONCAT(
        "Identity-to-endpoint chain for user ", user.name,
        " | Chain: ", Esql.chain_type,
        " | ", TO_STRING(Esql.identity_alert_count), " identity alerts + ",
        TO_STRING(Esql.endpoint_alert_count), " endpoint alerts + ",
        TO_STRING(Esql.cloud_alert_count), " cloud alerts",
        " | ", TO_STRING(Esql.unique_rules), " rules",
        " | ", TO_STRING(Esql.host_count), " hosts"
    )
```

---

### Rule 2C: Lateral Movement Spread Detection (New)

**Purpose:** Detect when a single user triggers alerts on an unusually high number of distinct hosts, indicating potential lateral movement or credential abuse across the environment.

**Schedule:** Every 15 minutes, lookback 12 hours

**Why it's needed:** A user who normally touches 1-2 hosts but suddenly triggers alerts on 8 hosts is likely compromised with their credentials being used for lateral movement. This pattern is invisible to per-host correlation and is only partially visible to the user-centric Rule 1A (which captures host count but doesn't threshold on it specifically).

```esql
FROM .internal.alerts-security.alerts-default
| WHERE
    user.name IS NOT NULL
    AND host.name IS NOT NULL
    AND NOT user.name IN ("SYSTEM", "Administrator", "LOCAL SERVICE", "NETWORK SERVICE")
    AND NOT (
        user.name LIKE "svc-*" OR user.name LIKE "svc_*"
        OR user.name LIKE "*$"
    )
    // Include BBRs here — lateral movement often detected by lower-fidelity rules
| EVAL
    domain_category = CASE(
        event.dataset LIKE "endpoint*" OR event.dataset LIKE "sentinelone*"
            OR event.dataset LIKE "windows*" OR event.dataset LIKE "sysmon*", "endpoint",
        event.dataset LIKE "okta*" OR event.dataset LIKE "azure_ad*", "identity",
        event.dataset LIKE "aws*" OR event.dataset LIKE "gcp*"
            OR event.dataset LIKE "azure*", "cloud",
        event.dataset LIKE "panw*" OR event.dataset LIKE "fortinet*", "network_fw",
        COALESCE(labels.technology, event.module, "other")
    )

| STATS
    Esql.alert_count = COUNT(*),
    Esql.first_seen = MIN(@timestamp),
    Esql.last_seen = MAX(@timestamp),
    Esql.host_count = COUNT_DISTINCT(host.name),
    Esql.host_values = VALUES(host.name),
    Esql.unique_rules = COUNT_DISTINCT(kibana.alert.rule.name),
    Esql.rule_names = VALUES(kibana.alert.rule.name),
    Esql.tactic_count = COUNT_DISTINCT(kibana.alert.rule.threat.tactic.name),
    Esql.tactic_values = VALUES(kibana.alert.rule.threat.tactic.name),
    Esql.technique_values = VALUES(kibana.alert.rule.threat.technique.name),
    Esql.severity_values = VALUES(signal.rule.severity),
    Esql.domain_count = COUNT_DISTINCT(domain_category),
    Esql.domain_values = VALUES(domain_category),
    Esql.ip_values = VALUES(related.ip)

  BY user.name

// Threshold: alerts on 4+ distinct hosts (tune per environment)
| WHERE
    Esql.host_count >= 4
    AND Esql.unique_rules >= 2

| EVAL
    Esql.correlation_severity = CASE(
        Esql.host_count >= 10 AND Esql.tactic_count >= 3, "critical",
        Esql.host_count >= 7 OR (Esql.host_count >= 4 AND Esql.tactic_count >= 3), "high",
        "medium"
    ),
    Esql.description = CONCAT(
        "Lateral movement spread for user ", user.name,
        " | ", TO_STRING(Esql.host_count), " distinct hosts",
        " | ", TO_STRING(Esql.unique_rules), " rules",
        " | ", TO_STRING(Esql.tactic_count), " tactics",
        " across ", TO_STRING(Esql.domain_count), " domains",
        " | ", TO_STRING(Esql.alert_count), " total alerts"
    )
```

> **Tuning note:** The `host_count >= 4` threshold must be calibrated per environment. IT admins and deployment automation may legitimately touch many hosts. Consider maintaining a lookup table of users with high expected host counts and adjusting thresholds for them.

---

### Rule 3A: Cumulative Risk Score Breach — Slow Burn (New)

**Purpose:** Catch slow-burn attacks where individual alerts are low-to-medium severity and spread across days, but the cumulative risk signal is meaningful. This is the ES|QL equivalent of Splunk's "Risk Threshold Exceeded for Object Over Previous 7 Days."

**Schedule:** Every 60 minutes, lookback 7 days

**Why it's needed:** Patient adversaries deliberately keep individual alert severity low. No single alert is alarming. But over a week, the same user has: 2 low-severity Okta anomalies + 3 medium endpoint alerts + 1 medium cloud alert + 4 building block alerts. Individually, none of these cross any threshold. Cumulatively, the risk score exceeds the threshold.

```esql
FROM .internal.alerts-security.alerts-default
| WHERE
    user.name IS NOT NULL
    AND NOT user.name IN ("SYSTEM", "Administrator", "LOCAL SERVICE", "NETWORK SERVICE",
        "DefaultAccount", "Guest")
    AND NOT (
        user.name LIKE "svc-*" OR user.name LIKE "svc_*"
        OR user.name LIKE "*$"
    )
| EVAL
    severity_weight = CASE(
        signal.rule.severity == "critical", 25,
        signal.rule.severity == "high", 15,
        signal.rule.severity == "medium", 8,
        signal.rule.severity == "low", 3,
        1
    ),
    bbr_factor = CASE(kibana.alert.rule.building_block_type == "default", 0.3, 1.0),
    alert_risk = ROUND(severity_weight * bbr_factor),

    domain_category = CASE(
        event.dataset LIKE "endpoint*" OR event.dataset LIKE "sentinelone*"
            OR event.dataset LIKE "windows*" OR event.dataset LIKE "sysmon*", "endpoint",
        event.dataset LIKE "okta*" OR event.dataset LIKE "azure_ad*"
            OR event.dataset LIKE "entra*", "identity",
        event.dataset LIKE "aws*" OR event.dataset LIKE "gcp*"
            OR event.dataset LIKE "azure*" OR event.dataset LIKE "o365*", "cloud",
        event.dataset LIKE "panw*" OR event.dataset LIKE "fortinet*", "network_fw",
        event.dataset LIKE "extrahop*" OR event.dataset LIKE "zeek*", "network_ndr",
        event.dataset LIKE "proxy*" OR event.dataset LIKE "zscaler*", "proxy",
        event.dataset LIKE "dns*", "dns",
        COALESCE(labels.technology, event.module, "other")
    )

| STATS
    Esql.alert_count = COUNT(*),
    Esql.first_seen = MIN(@timestamp),
    Esql.last_seen = MAX(@timestamp),
    Esql.total_risk_score = SUM(alert_risk),
    Esql.tactic_count = COUNT_DISTINCT(kibana.alert.rule.threat.tactic.name),
    Esql.tactic_values = VALUES(kibana.alert.rule.threat.tactic.name),
    Esql.technique_values = VALUES(kibana.alert.rule.threat.technique.name),
    Esql.unique_rules = COUNT_DISTINCT(kibana.alert.rule.name),
    Esql.rule_names = VALUES(kibana.alert.rule.name),
    Esql.severity_values = VALUES(signal.rule.severity),
    Esql.domain_count = COUNT_DISTINCT(domain_category),
    Esql.domain_values = VALUES(domain_category),
    Esql.host_count = COUNT_DISTINCT(host.name),
    Esql.host_values = VALUES(host.name),
    Esql.ip_values = VALUES(related.ip)

  BY user.name

// Higher threshold for 7-day window (prevents chronic noisy users from firing)
| WHERE
    Esql.total_risk_score >= 200
    AND Esql.unique_rules >= 4
    AND Esql.domain_count >= 2
    AND Esql.tactic_count >= 3

| EVAL
    Esql.correlation_severity = CASE(
        Esql.total_risk_score >= 400 AND Esql.tactic_count >= 5, "critical",
        Esql.total_risk_score >= 300 OR Esql.tactic_count >= 4, "high",
        "medium"
    ),
    Esql.description = CONCAT(
        "7-day risk accumulation for user ", user.name,
        " | Total Risk: ", TO_STRING(Esql.total_risk_score),
        " | ", TO_STRING(Esql.unique_rules), " rules",
        " across ", TO_STRING(Esql.domain_count), " domains",
        " | ", TO_STRING(Esql.tactic_count), " tactics",
        " | ", TO_STRING(Esql.host_count), " hosts",
        " | ", TO_STRING(Esql.alert_count), " alerts over 7 days"
    )
```

---

### Rule 4A: Multi-Entity Campaign Detection (New)

**Purpose:** Detect when multiple distinct users or hosts trigger correlation-level alerts within the same time window, indicating a coordinated attack campaign rather than isolated compromises.

**Schedule:** Every 30 minutes, lookback 4 hours

**Why it's needed:** If 5 different users all trigger correlation alerts in the same 4-hour window, something bigger is happening — credential spray attack, widespread phishing campaign landing simultaneously, or ransomware spreading through the environment. Individual entity correlation catches each victim. Campaign detection catches the pattern across victims.

**Note:** This rule queries the *correlation alert output* — it operates on alerts generated by Rules 1A/1B/2A-2C, not on the raw signals index. This makes it a meta-correlation rule.

```esql
FROM .internal.alerts-security.alerts-default
| WHERE
    kibana.alert.rule.name LIKE "*Correlation*" OR kibana.alert.rule.name LIKE "*correlation*"
    OR kibana.alert.rule.name LIKE "*Kill Chain*" OR kibana.alert.rule.name LIKE "*kill chain*"
    OR kibana.alert.rule.name LIKE "*Lateral*" OR kibana.alert.rule.name LIKE "*lateral*"
    OR kibana.alert.rule.name LIKE "*Identity*Chain*"
    OR kibana.alert.rule.name LIKE "*Risk*Score*Breach*"
| STATS
    Esql.correlated_users = COUNT_DISTINCT(user.name),
    Esql.correlated_hosts = COUNT_DISTINCT(host.name),
    Esql.user_values = VALUES(user.name),
    Esql.host_values = VALUES(host.name),
    Esql.correlation_rule_names = VALUES(kibana.alert.rule.name),
    Esql.total_correlation_alerts = COUNT(*),
    Esql.first_seen = MIN(@timestamp),
    Esql.last_seen = MAX(@timestamp),
    Esql.tactic_values = VALUES(kibana.alert.rule.threat.tactic.name),
    Esql.ip_values = VALUES(related.ip)

// No GROUP BY — this is a global aggregation across all entities

// Threshold: 3+ distinct entities hit by correlation alerts
| WHERE
    Esql.correlated_users >= 3 OR Esql.correlated_hosts >= 3

| EVAL
    Esql.correlation_severity = CASE(
        Esql.correlated_users >= 10 OR Esql.correlated_hosts >= 10, "critical",
        Esql.correlated_users >= 5 OR Esql.correlated_hosts >= 5, "high",
        "medium"
    ),
    Esql.description = CONCAT(
        "Potential campaign: ",
        TO_STRING(Esql.correlated_users), " users and ",
        TO_STRING(Esql.correlated_hosts), " hosts triggered correlation alerts",
        " | ", TO_STRING(Esql.total_correlation_alerts), " correlation alerts in window"
    )
```

> **Alternative approach for Rule 4A:** If your correlation rules write to a separate index or use a specific tag, filter on that instead of rule name patterns. This is more robust than pattern-matching rule names.

---

## Part 4: Deployment and Tuning Guide

### Recommended Rule Configuration

| Rule | Schedule | Lookback | Expected Volume | Building Block? |
|------|----------|----------|-----------------|-----------------|
| 1A: User-Centric Multi-Source | 10 min | 4 hours | 5-20/day | No |
| 1B: Host-Centric Multi-Source | 10 min | 4 hours | 5-15/day | No |
| 2A: Kill Chain Progression | 15 min | 24 hours | 1-5/day | No |
| 2B: Identity-Endpoint Chain | 15 min | 8 hours | 2-8/day | No |
| 2C: Lateral Movement Spread | 15 min | 12 hours | 1-5/day | No |
| 3A: 7-Day Risk Accumulation | 60 min | 7 days | 2-10/day | No |
| 4A: Campaign Detection | 30 min | 4 hours | Rare (0-1/week) | No |

### Rollout Order

1. **Start with Rule 1A** — the user-centric correlation rule. If replacing an existing correlation rule, run Rule 1A alongside it for 2 weeks and compare outputs. The risk-scored version should produce fewer but higher-quality alerts.

2. **Add Rule 1B** — host-centric. This will immediately surface host-based attack chains you're currently blind to.

3. **Add Rule 2A** — kill chain progression. This catches the patterns that Rules 1A/1B miss when individual alert risk is low but tactic diversity is high.

4. **Add Rule 2B** — identity-endpoint chain. This is specialized but very high-fidelity for credential compromise scenarios.

5. **Add Rule 2C and 3A** — lateral movement and slow-burn risk. These are the "advanced" rules that catch patient adversaries.

6. **Add Rule 4A** — campaign detection. Only after Tiers 1-3 are stable, since this depends on their output.

### Tuning Strategy

**Week 1-2:** Run each new rule in "alert but don't escalate" mode. Monitor output.

**Identify these tuning needs:**
- Service accounts that need exclusion (add to the NOT LIKE list or lookup table)
- Chronic noisy users/hosts (consider per-entity threshold overrides)
- Domain categorization gaps (new event.dataset values not matching CASE patterns)
- Threshold adjustments (too many/few alerts per day)

**Ongoing:**
- Review `domain_category` patterns quarterly as new data sources are onboarded
- Adjust risk score weights based on analyst feedback on alert quality
- Track false positive rate per correlation rule the same way you track it for standalone rules

---

## Part 5: How This Feeds the AI Layer

This correlation framework is the **deterministic prerequisite** for the AI use cases described in the project's use-case docs:

### UC-12: Alert Cluster Narrative Synthesis

Each correlation alert from Tier 1-3 is a pre-built alert cluster ready for LLM narrative generation. The correlation alert contains:
- All contributing rule names, tactics, techniques
- Entity context (user, hosts, IPs)
- Risk score and severity breakdown
- Timeline (first_seen to last_seen)

The LLM receives this structured cluster and generates: "Between 14:02 and 14:11, user jsmith generated 7 alerts spanning Initial Access (Okta MFA bypass), Execution (PowerShell download cradle on WKSTN-4421), and Credential Access (LSASS memory access). The identity-to-endpoint chain and kill chain progression pattern is consistent with hands-on-keyboard post-exploitation following credential compromise."

**Without the correlation framework:** The LLM would receive raw alert lists and have to discover the entity grouping, temporal relationships, and kill chain patterns itself — poorly and inconsistently.

**With the correlation framework:** The LLM receives pre-grouped, pre-scored, pre-classified clusters and focuses on what AI is actually good at: narrative synthesis, contextual reasoning, and verdict generation.

### UC-11: LLM Triage Verdicts

The `Esql.correlation_severity` field feeds LLM confidence calibration:
- Critical correlation → LLM provides high-confidence verdict with detailed reasoning
- Medium correlation → LLM may request additional enrichment before rendering verdict

The structured fields (`domain_values`, `tactic_values`, `kill_chain_breadth`, `stage_progression`) give the LLM specific dimensions to reason about rather than trying to derive these from raw alert data.

### UC-14: Agentic Investigation Execution

An AI agent receiving a Tier 2A (kill chain progression) alert knows exactly which kill chain stages are covered and which are missing. It can plan investigations to fill the gaps: "We see Initial Access and Credential Access. I should check for Persistence indicators on the affected hosts and look for Lateral Movement indicators in the authentication logs."

---

## Part 6: What This Framework Doesn't Do (Yet)

### Not Addressed — Needs UEBA or ML

1. **Per-entity baseline comparison:** "Is this user's current alert volume anomalous relative to their history?" Requires either a UEBA platform or a transform/lookup table tracking rolling averages per entity.

2. **Peer group analysis:** "Is this user's behavior anomalous relative to users in the same department/role?" Requires identity enrichment and statistical modeling beyond what ES|QL thresholds provide.

3. **Geographic anomaly correlation:** "Are these alerts coming from an unusual location for this user?" Requires source.geo enrichment on alerts and a baseline of expected geolocations per user.

### Not Addressed — Needs EQL Sequences

4. **Ordered temporal sequences:** "Did Initial Access happen *before* Execution, which happened *before* Credential Access?" ES|QL aggregation can detect that all three tactics are present but cannot enforce temporal ordering. For strict sequence detection, use EQL:

```eql
sequence by user.name with maxspan=4h
  [any where kibana.alert.rule.threat.tactic.name == "Initial Access"]
  [any where kibana.alert.rule.threat.tactic.name == "Execution"]
  [any where kibana.alert.rule.threat.tactic.name == "Credential Access"]
```

Consider adding EQL sequence rules as complementary rules alongside the ES|QL aggregation rules.

### Not Addressed — Needs Infrastructure

5. **Asset criticality weighting:** "Alerts on the domain controller should score higher than alerts on a developer laptop." Requires a maintained asset criticality lookup that can be joined at query time (LOOKUP JOIN when available, or enrichment at ingest time).

6. **User privilege weighting:** "Alerts for a domain admin should score higher." Requires identity enrichment mapping user.name to privilege tier.

7. **Threat intelligence enrichment:** "Alerts involving known-bad IPs/domains should score higher." Requires TI enrichment on the alert documents or a TI lookup that can be joined.

These are all achievable — they're data engineering prerequisites, not AI problems. Each represents a force multiplier on the correlation framework once implemented.

---

## Summary

The common "alerts from multiple integrations for a single user" pattern is a solid starting point. Here's how this framework improves on it:

| Dimension | Typical Baseline | Framework |
|-----------|----------|-----------|
| Entity types | User only | User + Host + IP |
| Scoring model | Count-based threshold | Weighted risk accumulation |
| Kill chain awareness | Captured but unused | First-class threshold dimension |
| Data source counting | Raw event.dataset | Security domain categories |
| Temporal windows | Single (from schedule) | Multiple (4h, 8h, 12h, 24h, 7d) |
| Severity output | Single tier | Dynamic critical/high/medium |
| Service account handling | 4 patterns | 15+ patterns + lookup path |
| Host spread | Captured, not used | Dedicated lateral movement rule |
| Cross-domain chains | Implicit | Explicit identity → endpoint rule |
| Campaign detection | None | Meta-correlation on Tier 1-3 output |
| AI integration | None | Structured input for LLM triage |
| Number of rules | 1 | 7 (3 tiers + 1 meta) |

The framework transforms a single correlation rule into a system that catches attack patterns at multiple scales — from 4-hour bursts to 7-day campaigns, from single-entity incidents to multi-entity campaigns, from simple multi-source correlation to kill-chain-aware progression detection.

And all of this is deterministic. No AI required. This is the SIEM doing its job. The AI layer comes next — and it will be dramatically more effective operating on the structured, scored, classified output of this framework than on raw alert data.
