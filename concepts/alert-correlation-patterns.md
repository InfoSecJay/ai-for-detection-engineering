# Alert Correlation Patterns: Industry State of the Art (2025-2026)

## Overview

This document surveys how industry-leading detection engineering teams approach alert correlation rules in 2025-2026. It covers the dominant correlation architectures (user-centric, asset-centric, kill-chain-centric), weighted scoring models, temporal windowing, MITRE ATT&CK integration, entity behavior analytics, and platform-specific capabilities across Splunk, Elastic, Microsoft Sentinel, Panther, and Anvilogic.

Alert correlation is the practice of grouping related alerts, identifying parent-child relationships, and surfacing root causes instead of symptoms. The fundamental shift in 2025-2026 is the move away from one-alert-one-incident thinking toward multi-signal, entity-centric correlation where individual low-fidelity signals are accumulated and scored before generating analyst-facing incidents.

---

## 1. Multi-Signal Correlation Patterns

Modern detection engineering teams organize correlation around four primary patterns. These are not mutually exclusive -- mature programs combine them.

### User-Centric Correlation

All signals are joined on a resolved user identity (e.g., `user.name`, `actor.alternateId`, `user_identity.arn`). The question being answered: *What is this user doing across all systems, and does the aggregate pattern look malicious?*

**How it works:** Every detection that fires for a given user contributes a signal to that user's risk profile. Signals from identity providers (Okta, Entra ID), endpoints (process execution under that user context), cloud APIs (CloudTrail actions by that IAM principal), and email (messages sent/received by that user) are joined on the resolved user identity. When the accumulated signals cross a threshold or match a pattern, a correlated incident is generated.

**Where it excels:** Insider threat detection, compromised credential detection, account takeover chains. Any scenario where the attacker operates under a single identity across multiple systems.

**Where it fails:** Attackers who pivot between identities (credential theft leading to impersonation of a different user). Environments where user identity resolution is poor (shared accounts, service accounts mapped to generic names, inconsistent naming between systems).

**Implementation examples:**
- Splunk RBA: Risk events are assigned to a `risk_object` of type `user`. Risk incident rules aggregate risk scores per user over a time window.
- Microsoft Sentinel UEBA: The Behaviors layer maps anomalies to user entities and builds behavioral timelines per user across data sources.
- Elastic Entity Analytics: Entity risk scoring tracks risk score changes for user entities across SIEM, cloud, and endpoint sources.

### Asset-Centric (Host-Centric) Correlation

All signals are joined on a resolved host identity (e.g., `host.name`, `host.id`, `agent.id`, `source.ip` mapped to asset inventory). The question: *What is happening on this machine across all telemetry sources?*

**How it works:** Endpoint detections, network alerts involving this host's IP, identity events where this host is the source, and cloud events originating from this host are accumulated against the asset identity. Correlation looks for patterns like: process execution alert + network C2 beacon alert + DNS anomaly alert, all on the same host within a time window.

**Where it excels:** Endpoint compromise detection, malware infection chains, host-based kill chain progression. Any scenario where the attacker establishes a foothold on a single machine and operates from it.

**Where it fails:** Cloud-native environments where "host" is ephemeral (serverless, containers). Environments where host identity resolution is unreliable (DHCP churn, NAT obscuring real source IPs). Attacks that distribute activity across many hosts to avoid per-host threshold triggering.

**Implementation examples:**
- Splunk RBA: Risk events assigned to a `risk_object` of type `system`.
- Elastic Entity Analytics: Entity risk scoring for host entities correlating endpoint, network, and cloud signals.
- Palo Alto Cortex XSIAM: ML-driven alert grouping stitches related alerts for the same endpoint into unified incidents.

### Session-Centric Correlation

Signals are joined on a session identifier (e.g., authentication session ID, VPN session, cloud API session token). The question: *Within this authenticated session, does the sequence of actions constitute an attack?*

**How it works:** A session is a bounded period of authenticated activity. Correlation tracks all actions within a session and evaluates them as a sequence. This is particularly powerful for cloud environments where CloudTrail events share a session token, or for web application attacks where a session cookie ties together a series of requests.

**Where it excels:** Cloud privilege escalation (sequence of API calls within a single assumed-role session), web application attacks, post-authentication abuse chains.

**Where it fails:** Attacks that span multiple sessions. Environments where session tracking is unreliable or sessions are extremely short-lived.

### Kill-Chain-Centric Correlation

Signals are joined on a combination of entity (user or host) and ATT&CK tactic progression. The question: *Is this entity experiencing a sequence of activities that maps to a multi-stage attack?*

**How it works:** Each detection rule is tagged with its ATT&CK tactic(s). Correlation rules look for an entity accumulating signals across multiple tactics in a sequence that suggests attack progression -- for example, Initial Access signal followed by Execution signal followed by Credential Access signal on the same host within a time window.

**Where it excels:** APT detection, sophisticated multi-stage attacks that would otherwise appear as isolated low-severity alerts at each individual stage.

**Where it fails:** Attacks that do not follow canonical kill chain ordering. High false positive rates if tactic mappings are inaccurate or if legitimate administrative activity touches multiple tactics. Requires high-quality ATT&CK tagging on all contributing rules.

**Implementation examples:**
- Splunk RBA: The out-of-the-box risk incident rule "ATT&CK Tactic Threshold Exceeded for Object Over Previous 7 Days" fires when a single entity accumulates risk events spanning a configurable number of distinct ATT&CK tactics.
- Microsoft Sentinel Fusion: The Fusion correlation engine uses ML to automatically detect multistage attacks by correlating anomalous behaviors across kill chain stages, generating "Possible multistage attack activities detected by Fusion" incidents.
- Anvilogic Threat Scenarios: Drag-and-drop canvas for building multi-stage correlation rules mapped to ATT&CK, threading vendor alerts, queries, and intel-enriched detections across kill chain stages.

---

## 2. Weighted Scoring Models for Alert Correlation

### Splunk Risk-Based Alerting (RBA) -- The Reference Implementation

Splunk's RBA is the most widely adopted weighted scoring model for alert correlation in the industry as of 2025-2026. The core architecture:

**Risk Score Formula:**

```
risk_score = (impact * confidence) / 100
```

Where `impact` (0-100) represents the potential damage if the activity is truly malicious, and `confidence` (0-100) represents how likely this specific observation is to be malicious. Both are set by the detection author.

**Risk Modifiers:**

Risk scores are dynamically modified based on contextual attributes of the observed entity:
- **Asset criticality:** A domain controller or crown-jewel database server receives a higher risk modifier than a developer workstation.
- **User privilege level:** Activity by a domain admin receives a higher modifier than a standard user.
- **External exposure:** An internet-facing server receives a higher modifier than an internal-only system.
- **Threat intelligence match:** An IP or domain appearing in threat feeds receives an additional risk modifier.

**Risk Incident Rules (RIR):**

Risk events accumulate in the risk index. Risk Incident Rules periodically scan the risk index for entities whose aggregated risk exceeds defined thresholds. The default out-of-the-box rules use two temporal windows:
- "Risk Threshold Exceeded for Object Over 24 Hour Period" -- short-term burst detection.
- "ATT&CK Tactic Threshold Exceeded for Object Over Previous 7 Days" -- multi-stage progression detection.

When a Risk Incident Rule fires, it generates a Risk Notable -- a high-fidelity, correlated alert that aggregates all contributing risk events for the entity. Analysts triage Risk Notables, not individual risk events.

**Why it works:** RBA reduces alert volume dramatically while increasing fidelity. Individual noisy detections that would generate too many false positives as standalone alerts are repurposed as risk contributors. A single failed SSH login is not an alert -- it is a risk event worth 5 points. Five failed SSH logins from different source IPs against the same server, combined with a new user account creation and a firewall policy change, all within 24 hours? That crosses the threshold and generates one high-confidence Risk Notable.

### Elastic Entity Risk Scoring

Elastic's approach (as of 8.x/9.x) calculates risk scores per entity (host, user, service) using signals from the SIEM detection engine, cloud security, and endpoint protection. Risk scores are aggregated using detection alerts and their severities. The Entity Analytics dashboard visualizes risk score changes over time, enabling analysts to identify entities experiencing escalating risk.

### Google SecOps Risk Analytics

Google Chronicle/SecOps provides Risk Analytics that evaluates risk associated with entities based on alert context, user behavior, and asset exposure. Automated risk scoring correlates diverse telemetry including SIEM logs, EDR alerts, IAM data, and network flows.

### General Weighted Scoring Design Principles (Cross-Platform)

Regardless of platform, effective weighted scoring models share these characteristics:

1. **Dual-axis scoring:** Separate impact and confidence dimensions, multiplied together. This prevents a high-impact/low-confidence event from scoring the same as a low-impact/high-confidence event.
2. **Context modifiers:** Static scores are adjusted by dynamic context (asset criticality, user privilege, threat intel enrichment).
3. **Decay factors:** Risk scores should decrease over time if no additional signals appear. Algorithms assign a decay factor to each risk type specifying how soon the risk score returns to normal. Without decay, stale risk accumulates and creates noise.
4. **Threshold tuning:** Risk incident thresholds must be calibrated per environment. A threshold of 100 risk points may generate 5 incidents/day in one environment and 500 in another. Threshold tuning is an ongoing operational activity.
5. **Transparency:** Every Risk Notable should show its contributing risk events -- analysts must be able to understand why this entity crossed the threshold.

---

## 3. Temporal Windowing and Decay in Correlation Rules

### Temporal Windows

Temporal windowing defines the time boundary within which events must occur to be correlated. All correlation rules depend on temporal logic.

**Fixed Windows:**

The simplest approach: "count events within the last N hours/days."
- Splunk RBA default: 24-hour window (short-term) and 7-day window (multi-stage).
- Elastic EQL `maxspan`: Constrains sequence queries to a specific timespan. All events in a matching sequence must occur within this duration from the first event's timestamp. Example: `sequence by host.name with maxspan=15m` requires all events in the sequence to occur within 15 minutes.
- Microsoft Sentinel Fusion: Uses 30 days of historical data to train the ML correlation engine, but individual incident correlations are bounded to shorter operational windows.

**Sliding Windows:**

Events are continuously evaluated as they arrive. The window "slides" forward in time. Most SIEM correlation engines implement sliding windows for real-time detection.

**Session-Bounded Windows:**

The window is defined by a logical session rather than a fixed time. Start when authentication occurs, end when the session terminates. Useful for cloud API correlation where a session token defines the activity boundary.

**Sequence Windows (Ordered Temporal Correlation):**

Events must occur in a specific order within the time window. Elastic's EQL sequence queries are the canonical example:

```
sequence by host.name with maxspan=30m
  [process where event.type == "start" and process.name == "powershell.exe"]
  [network where destination.port == 443]
  [file where event.action == "creation" and file.extension == "exe"]
```

This fires only if: PowerShell starts, then makes an HTTPS connection, then an executable file is created -- all on the same host within 30 minutes, in that order.

### Decay Mechanisms

Decay addresses a fundamental problem: risk events that occurred 6 days ago should not carry the same weight as events that occurred 1 hour ago when evaluating whether an entity is currently under attack.

**Linear Decay:**

Risk score decreases by a fixed amount per time unit. Simple but often too aggressive -- a significant event from 3 days ago may still be relevant.

```
effective_score = original_score - (decay_rate * hours_since_event)
```

**Exponential Decay:**

Risk score decreases exponentially, preserving more weight for recent events while gradually reducing older ones. More commonly used in practice.

```
effective_score = original_score * e^(-lambda * hours_since_event)
```

Where `lambda` is the decay constant. A half-life of 24 hours means an event retains 50% of its original risk score after one day.

**Step Decay:**

Risk score drops at defined intervals rather than continuously. For example: full score for 24 hours, 50% for days 2-3, 25% for days 4-7, then drops to zero. Easier to reason about and tune than continuous decay.

**No Decay (Window-Based):**

Some implementations skip decay entirely and instead use hard window boundaries. Events contribute full risk within the window and zero risk outside it. Splunk's default RBA rules operate this way -- the 24-hour and 7-day windows are hard boundaries, not decay curves. This is simpler to implement and explain but creates "cliff edges" where an entity's risk drops suddenly when old events fall outside the window.

**Platform-Specific Decay:**

- Splunk RBA: Default rules use window-based (no decay). Custom risk incident rules can implement decay by applying time-based multipliers in the SPL search.
- UEBA platforms (Exabeam, Microsoft Sentinel UEBA): Typically use exponential or algorithmic decay where the weight assigned to each risk type includes a decay factor specifying how quickly the risk score returns to normal.
- Elastic Entity Risk Scoring: Risk scores incorporate alert recency as a factor in the aggregate calculation.

---

## 4. MITRE ATT&CK Kill Chain Coverage Scoring in Correlation

### Tactic-Based Correlation Thresholds

The most operationally useful application of ATT&CK in correlation is not per-technique scoring but tactic diversity scoring: how many distinct ATT&CK tactics has this entity triggered signals in?

**Splunk's approach:** The "ATT&CK Tactic Threshold Exceeded" risk incident rule fires when a single risk object accumulates risk events spanning N or more distinct ATT&CK tactics within 7 days. The default threshold is typically 3-4 distinct tactics, but this is environment-dependent.

**Why tactic diversity matters more than technique count:** An entity with 10 risk events all in the Execution tactic may just be a noisy build server running scripts. An entity with 3 risk events spanning Initial Access, Execution, and Credential Access is exhibiting multi-stage attack progression -- even if the total risk score is lower.

### Kill Chain Progression Scoring

Advanced implementations assign bonus scores when an entity's accumulated signals demonstrate kill chain progression:

```
progression_bonus = base_bonus * (number_of_distinct_tactics - minimum_tactic_threshold)
```

For example, if the minimum threshold is 2 distinct tactics:
- 2 tactics: No bonus (threshold just met).
- 3 tactics: base_bonus * 1.
- 5 tactics: base_bonus * 3.

This rewards diversity of attack stages over depth in a single stage.

### ML-Based Kill Chain Prediction

Research published in 2025 demonstrates phase-aware ML frameworks that align MITRE ATT&CK techniques with the Lockheed Martin Cyber Kill Chain phases, achieving F1-scores of 97-99% for predicting adversarial techniques across kill chain phases. This enables predictive correlation -- given observed techniques in early phases, predict likely techniques in later phases and pre-position detection.

### 2025 MITRE ATT&CK Evaluations: Correlation Implications

The 2025 MITRE ATT&CK Enterprise Evaluation (featuring Scattered Spider and state-sponsored TTP emulation across endpoint, identity, and cloud) reinforced that platforms must automatically correlate telemetry into meaningful alerts across hybrid environments, particularly when multiple data sources must come together to explain a significant event. Vendors achieving top marks demonstrated cross-domain correlation as a core capability, not an add-on.

---

## 5. Entity Behavior Analytics Integration with Correlation Rules

### The UEBA + Correlation Architecture

UEBA systems and correlation rules serve different but complementary functions:

- **Correlation rules** are deterministic: "IF event A AND event B for the same entity within time window T, THEN alert." They detect known patterns.
- **UEBA** is probabilistic: "This entity's behavior deviates from its established baseline by N standard deviations." It detects unknown-unknown anomalies.

The integration pattern used by leading teams in 2025-2026:

1. **UEBA anomalies as risk contributors:** UEBA anomaly scores feed into the risk-based alerting pipeline as risk events. A user whose behavior is anomalous (unusual login time, unusual resource access) receives risk points from UEBA even if no deterministic rule fired. These risk points accumulate alongside rule-generated risk events.

2. **Correlation rules as UEBA context:** When a correlation rule fires, UEBA behavioral context enriches the incident. The analyst sees not just "these 4 rules fired for this user" but also "this user's behavior has been anomalous for 3 days across these dimensions."

3. **Behavioral baselines inform correlation thresholds:** UEBA baselines help tune correlation rule thresholds per entity. A user who normally generates 2 risk events per week should have a lower correlation threshold than an IT admin who legitimately generates 10 risk events per week through normal administrative activity.

### Microsoft Sentinel UEBA Behaviors Layer (2025-2026)

Microsoft Sentinel introduced the UEBA Behaviors layer as a core AI-based capability that fundamentally changes how SOC teams investigate. Key characteristics:

- Provides a unified, contextual view of security activity across diverse data sources.
- SOC analysts investigate incidents by querying behaviors tied to the entities involved, rather than searching raw logs.
- Detection engineers build simpler, more explainable rules using normalized, high-fidelity behaviors as building blocks.
- Enables correlation rules like "new AWS access key creation combined with privilege escalation within a defined time window" to be expressed against behavior objects rather than raw events.

### Splunk UEBA Integration

Splunk UBA (User Behavior Analytics) integrates with Splunk Enterprise Security to:
- Feed anomaly scores into the risk index alongside rule-generated risk events.
- Provide peer group analysis -- comparing a user's behavior to similar users.
- Generate threat models that combine behavioral anomalies with known TTP patterns.

### Cross-Platform UEBA Integration Patterns

Regardless of platform, the integration follows a common architecture:

```
Raw Events --> Detection Rules --> Risk Events (deterministic)
Raw Events --> UEBA Engine   --> Anomaly Scores (probabilistic)
                                        |
                                        v
                              Risk Accumulation Layer
                                        |
                                        v
                              Risk Incident Rules / Correlation
                                        |
                                        v
                              Analyst-Facing Incidents
```

The key design decision is whether UEBA anomalies carry the same weight as rule-generated risk events. Most implementations weight them lower (UEBA anomaly = 5-15 risk points vs. deterministic rule = 20-80 risk points) to prevent behavioral noise from dominating the risk profile.

---

## 6. Building Block Rules and Correlation Layers

### The Two-Layer Architecture

Leading detection engineering teams in 2025-2026 structure their rule sets into two distinct layers:

**Layer 1: Building Block Rules**

Building block rules detect atomic or near-atomic behaviors that are individually too noisy or too low-confidence to generate analyst-facing alerts. They are designed to produce signals, not alerts.

Characteristics:
- Low severity (informational or low).
- High volume expected.
- Do not appear in the primary alert queue.
- Write to a signals/risk index rather than the alerts index.
- Optimized for coverage breadth -- it is acceptable for building blocks to have higher false positive rates because they are not triaged individually.

**Elastic's implementation:** Building block rules write to the alerts indices but are filtered out of the default Alerts table view. They are visible only when explicitly queried or when they contribute to a correlation rule alert. This allows correlation rules to reference building block alert data without cluttering the analyst experience.

**Splunk's implementation:** Risk rules write risk events to the `risk` index. These risk events are never surfaced as standalone notables. They exist solely as inputs to Risk Incident Rules.

**Panther's implementation:** Panther supports correlation rules with `MinMatchCount` -- a minimum number of building block rules must match before the correlation rule fires. Building blocks are expressed as Python classes with inheritance and programmatic overrides.

**Layer 2: Correlation Rules**

Correlation rules consume building block signals and generate analyst-facing incidents. They implement the actual correlation logic: entity joining, temporal windowing, threshold evaluation, and pattern matching.

Characteristics:
- Medium to high severity.
- Low volume (by design -- the correlation reduces noise).
- Appear in the primary alert queue as incidents.
- Each correlated incident includes references to all contributing building block signals.
- Optimized for precision -- correlation rules should have low false positive rates.

### Building Block Design Best Practices

1. **One behavior per building block.** Each building block should detect exactly one atomic behavior. "PowerShell execution with encoded command" is a building block. "PowerShell execution with encoded command followed by network connection to external IP" is a correlation rule, not a building block.

2. **Rich metadata on building blocks.** Every building block should carry ATT&CK tactic/technique tags, a risk score (impact and confidence), data source domain classification, and entity field mappings. This metadata is consumed by correlation rules.

3. **Building blocks should be testable independently.** Even though they do not generate analyst alerts, building blocks must be validated for correctness. Panther's approach of expressing building blocks as testable Python classes is a strong pattern.

4. **Version-control building blocks alongside correlation rules.** The building block and the correlation rule that consumes it are a coupled pair. Changes to building block logic can silently break correlation rules. Detection-as-code practices (CI/CD validation, automated testing) should cover both layers.

### Microsoft Sentinel's Multi-Layer Correlation

Microsoft Sentinel implements correlation at multiple layers:

1. **Analytics Rules** (equivalent to building blocks and standalone detections): Scheduled queries that generate alerts.
2. **Fusion Engine**: ML-based correlation that automatically combines alerts from different analytics rules and data connectors into multi-stage attack incidents. Fusion operates on top of the analytics rule layer and requires no manual correlation rule authoring.
3. **Incident Grouping**: Configurable rules that group related alerts into incidents based on entity overlap, time proximity, and alert similarity.

The Fusion engine represents a distinct approach: rather than requiring detection engineers to author explicit correlation rules, it uses ML to discover correlations automatically. As of mid-2025, Fusion's functionality is being absorbed into the Microsoft Defender XDR correlation engine, reflecting the broader industry trend of SIEM+XDR convergence.

### Anvilogic Threat Scenarios

Anvilogic takes a visual approach to correlation layer design:

- **Building blocks:** Individual detections, vendor alerts, and intel-enriched signals.
- **Threat Scenarios:** Drag-and-drop canvas where building blocks are connected into multi-stage scenarios, mapped to ATT&CK tactics, and deployed as correlation rules.
- **Cross-platform:** Threat Scenarios can consume signals from multiple SIEM backends (Splunk, Sentinel, Snowflake), enabling correlation across data platforms.

---

## 7. Entity-Type Differentiation in Correlation

### User-Entity Correlation

**Join fields:** `user.name`, `user.id`, `user.email`, `actor.alternateId` (Okta), `user_identity.arn` (AWS).

**Unique challenges:**
- Shared/service accounts create false correlations (multiple humans mapping to one user entity).
- User identity may differ across systems (Okta `john.smith@corp.com` vs. Windows `DOMAIN\jsmith` vs. AWS `arn:aws:iam::123456:user/john.smith`). Identity resolution is a prerequisite -- see the [Domain-Aware Entity Framework](domain-aware-entity-framework.md).
- Privileged users generate more legitimate activity that overlaps with attacker behavior, requiring higher correlation thresholds.

**Correlation patterns specific to user entities:**
- Impossible travel: Same user authenticating from geographically distant locations within a time window shorter than travel time.
- Privilege escalation chains: User requests elevated permissions followed by sensitive API calls.
- Account takeover sequence: Password reset + MFA change + unusual login location.

### Host-Entity Correlation

**Join fields:** `host.name`, `host.id`, `agent.id`, `observer.hostname`, `source.ip` (when mapped to asset inventory).

**Unique challenges:**
- DHCP environments: IP addresses change, breaking IP-based correlation over time. Must resolve to a stable host identifier.
- Ephemeral hosts (containers, serverless): Host entities may exist for seconds or minutes. Correlation windows must account for short host lifetimes.
- Multi-homed hosts: A single host with multiple network interfaces appears as multiple IP addresses. Correlation must map all interfaces to one host entity.

**Correlation patterns specific to host entities:**
- Infection chain: Malware download + process execution + persistence mechanism + C2 communication, all on one host.
- Lateral movement target: Multiple source hosts attempting to connect to the same destination host using different protocols.
- Data staging: Large file creation + compression + outbound network transfer from one host.

### Network-Entity Correlation

**Join fields:** `source.ip`, `destination.ip`, `source.ip`+`destination.ip`+`destination.port` (network tuple), `dns.question.name`, `url.domain`.

**Unique challenges:**
- IP addresses are not stable identities (DHCP, NAT, CDN, cloud elastic IPs).
- Network entities are relationships (source-to-destination) rather than single objects. Correlation must handle directional relationships.
- Encrypted traffic reduces observable content, limiting the signals available for correlation.

**Correlation patterns specific to network entities:**
- C2 beaconing: Regular-interval connections from the same source to the same destination, with consistent packet sizes.
- Scanning followed by exploitation: Port scan from source IP followed by exploit attempt to discovered open ports.
- DNS-based attack chain: DGA domain resolution + successful connection to resolved IP + data transfer to that IP.

### Cross-Entity Correlation (The Highest Value)

The most powerful correlations join signals across entity types:

- **User + Host:** "This user authenticated anomalously AND this user's primary workstation shows malware indicators." Joins user-entity risk with host-entity risk.
- **Host + Network:** "This host executed a suspicious process AND this host's IP is communicating with a known C2 domain." Joins host-entity risk with network-entity signals.
- **User + Host + Network:** "This user's identity was compromised (identity signals) AND the host they logged into shows post-exploitation activity (endpoint signals) AND that host is communicating externally on unusual ports (network signals)." This three-way correlation is the gold standard for high-confidence incident generation.

Cross-entity correlation requires the entity resolution capabilities described in the [Domain-Aware Entity Framework](domain-aware-entity-framework.md) to map between entity types (e.g., mapping a `user.name` to the `host.name` values that user typically authenticates to).

---

## 8. Elastic ES|QL Capabilities for Correlation Rules

### ES|QL Overview for Detection Engineering

ES|QL (Elasticsearch Query Language) is Elastic's pipe-based query language that has seen rapid capability expansion in 2025-2026. Key features relevant to correlation rules:

### LOOKUP JOIN (GA as of 2025)

The LOOKUP JOIN command enables dynamic enrichment within a single piped query, fundamentally simplifying data correlation:

```esql
FROM logs-endpoint.events.process-*
| WHERE process.name == "powershell.exe"
| LOOKUP JOIN threat_intel ON process.hash.sha256
| WHERE threat_intel.malicious == true
```

This removes the need for data denormalization or complex client-side joins. For correlation rules, LOOKUP JOIN enables:
- Merging security logs with employee directory data (user privilege levels, department) at query time.
- Enriching alerts with threat intelligence data within the detection rule itself.
- Joining endpoint events with asset inventory for criticality-based scoring.

### Cross-Cluster Search

ES|QL supports querying across geographically distributed Elasticsearch clusters, breaking down silos between security, observability, and operational telemetry workloads. For correlation rules, this means:
- A single correlation rule can query endpoint data in one cluster and network data in another.
- Organizations with regional data residency requirements can still run cross-region correlation.

### INLINE STATS (Elasticsearch 9.2)

The INLINE STATS command allows aggregation within a piped query without losing the individual event rows:

```esql
FROM logs-endpoint.events.process-*
| WHERE event.category == "process"
| INLINE STATS alert_count = COUNT(*) BY host.name
| WHERE alert_count > 5
```

This enables threshold-based correlation directly in ES|QL queries -- count the number of events per entity and filter to entities exceeding the threshold, while preserving all the individual events for context.

### TS Command (Elasticsearch 9.2)

The TS command provides native time-series analysis capabilities, useful for detecting temporal patterns in alert data (periodicity, trending, burst detection).

### EQL Sequence Queries (Existing, Continued Relevance)

Elastic's Event Query Language (EQL) remains the primary tool for ordered sequence correlation. Key capabilities:

- **`sequence by` with `maxspan`:** Match ordered event sequences on the same entity within a time constraint.
- **`until` clauses:** Define events that terminate a sequence (e.g., a successful login terminates a brute-force sequence).
- **Missing event clauses:** Detect the absence of an expected event in a sequence (e.g., process start without a corresponding process end).
- **Multiple join keys:** Sequence events can share different fields (`by` keyword), enabling correlation on complex entity relationships.

### Resilience Features

- **`allow_partial_results`:** Queries complete even when some shards are temporarily unavailable. For correlation rules running as scheduled detections, this prevents rule failures during rolling upgrades or transient node issues.
- **Automatic shard-level retry:** ES|QL retries failed shard operations, improving stability for time-critical correlation rules.
- **Live Query Monitoring (Tech Preview):** API for inspecting currently running queries, useful for debugging slow or stuck correlation rules.

### Elastic Building Block + ES|QL Correlation Pattern

The practical pattern for Elastic correlation rules in 2025-2026:

1. **Building block rules (EQL or KQL):** Individual detection rules marked as building blocks. They write alerts to the `.alerts-security.*` index but are hidden from the default Alerts view.
2. **Correlation rules (ES|QL):** Scheduled rules that query the alerts index for building block alerts, aggregate by entity, apply thresholds and temporal logic, and generate correlated alerts that appear in the analyst-facing Alerts view.

```esql
FROM .alerts-security.alerts-default
| WHERE kibana.alert.building_block_type IS NOT NULL
| WHERE kibana.alert.risk_score > 20
| STATS
    total_risk = SUM(kibana.alert.risk_score),
    distinct_tactics = COUNT_DISTINCT(threat.tactic.name),
    alert_count = COUNT(*)
  BY host.name
| WHERE total_risk > 100 AND distinct_tactics >= 3
```

This query finds hosts where building block alerts accumulate enough risk and span enough ATT&CK tactics to warrant a correlated incident.

---

## Key Takeaways for Detection Engineering Teams

1. **Adopt a two-layer architecture.** Separate building block rules (high coverage, high noise tolerance) from correlation rules (high precision, analyst-facing). This is the consensus best practice across all major platforms.

2. **Start with entity-centric correlation.** User-centric and host-centric correlation deliver the most value with the least complexity. Kill-chain-centric and session-centric correlation are valuable but require more mature ATT&CK tagging and entity resolution.

3. **Implement weighted scoring, not just threshold counting.** Raw event counts are a poor proxy for risk. Weight signals by impact, confidence, asset criticality, and user privilege. Splunk's RBA model is the reference architecture, but the principles apply to any platform.

4. **Design temporal windows intentionally.** The choice of correlation window directly affects detection quality. Too short and you miss slow-burn attacks. Too long and you accumulate stale noise. Use multiple windows (24-hour for burst detection, 7-day for progression) and consider decay mechanisms for longer windows.

5. **MITRE ATT&CK tactic diversity is more valuable than technique count.** A correlation rule that fires when an entity spans 3+ distinct ATT&CK tactics is more reliable than one that fires on a raw risk score threshold alone.

6. **UEBA and correlation rules are complementary, not competing.** Feed UEBA anomaly scores into the risk accumulation pipeline alongside deterministic rule signals, but weight them differently.

7. **Entity resolution is the foundation.** Every correlation pattern depends on reliably joining signals to the correct entity. Invest in identity resolution, asset inventory mapping, and cross-domain field normalization before investing in complex correlation logic.

8. **Correlation rules need the same engineering rigor as detection rules.** Version control, automated testing, CI/CD validation, and regular tuning apply to correlation rules. A broken correlation rule can silently suppress high-fidelity incidents.

---

## References

### Platform Documentation

- [Splunk Risk-Based Alerting Guide](https://www.splunk.com/en_us/blog/security/risk-based-alerting-the-new-frontier-for-siem.html)
- [Splunk RBA: How Risk Scores Work](https://help.splunk.com/en/splunk-enterprise-security-7/risk-based-alerting/7.3/introduction/how-risk-scores-work-in-splunk-enterprise-security)
- [Splunk Risk Scoring in Enterprise Security](https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.3/risk-based-alerting/risk-scoring-in-splunk-enterprise-security)
- [Elastic ES|QL Reference](https://www.elastic.co/docs/reference/query-languages/esql)
- [Elastic EQL Syntax Reference](https://www.elastic.co/docs/reference/query-languages/eql/eql-syntax)
- [Elastic Detection Engineering Capabilities](https://www.elastic.co/blog/elastic-security-detection-engineering)
- [Elastic Entity Risk Scoring](https://www.elastic.co/docs/solutions/security/advanced-entity-analytics/entity-risk-scoring)
- [Elastic ES|QL New Features (2025)](https://www.elastic.co/search-labs/blog/esql-elasticsearch-8-19-9-1)
- [Elastic Security 9.0: ES|QL Lookup Join](https://www.elastic.co/blog/whats-new-elastic-security-9-0-0)
- [Microsoft Sentinel Fusion Engine](https://learn.microsoft.com/en-us/azure/sentinel/fusion)
- [Microsoft Sentinel UEBA](https://learn.microsoft.com/en-us/azure/sentinel/identify-threats-with-entity-behavior-analytics)
- [Microsoft Sentinel UEBA Behaviors Layer](https://techcommunity.microsoft.com/blog/microsoftsentinelblog/turn-complexity-into-clarity-introducing-the-new-ueba-behaviors-layer-in-microso/4484493)
- [Panther Correlation Rules Documentation](https://docs.panther.com/detections/rules)
- [Panther pypanther Framework](https://panther.com/blog/introducing-pypanther-the-future-of-code-driven-detection-and-response)
- [Anvilogic Correlated Threat Scenarios](https://www.anvilogic.com/correlated-threat-scenarios)
- [Anvilogic Detection Coverage Maturity](https://www.anvilogic.com/detection-coverage-maturity)

### Industry Research and Analysis

- [Anvilogic 2025 State of Detection Engineering Report](https://www.anvilogic.com/report/2025-state-of-detection-engineering)
- [Elastic 2025 State of Detection Engineering](https://www.elastic.co/security-labs/state-of-detection-engineering-at-elastic-2025)
- [Correlation-Based Detection Rules in Cybersecurity (Andrey Pautov)](https://medium.com/@1200km/correlation-based-detection-rules-in-cybersecurity-from-atomic-events-to-behavioral-insight-1b3df31597bb)
- [Unraveling SIEM Correlation Techniques (Jack Naglieri / Panther)](https://panther.com/blog/unraveling-siem-correlation-techniques)
- [SIEM Correlation Rules: Fine-Tune Detection Logic at Scale (Cymulate)](https://cymulate.com/cybersecurity-glossary/siem-correlation-rules/)
- [KillChainGraph: ML Framework for Predicting ATT&CK Techniques (2025)](https://arxiv.org/html/2508.18230v1)
- [CrowdStrike Correlation Rule Template Discovery](https://www.crowdstrike.com/en-us/blog/boost-soc-detection-content-correlation-rule-template-discovery-dashboard/)
- [UEBA Complete 2025 Guide (Exabeam)](https://www.exabeam.com/explainers/ueba/what-ueba-stands-for-and-a-5-minute-ueba-primer/)

### Practical Implementation

- **[Correlation Rule Framework](correlation-rule-framework.md)** -- Production-ready ES|QL implementation guide for the patterns described in this document. Designs a 7-rule, 4-tier framework implementing risk-weighted scoring, security domain categorization, kill chain progression detection, lateral movement spread analysis, and multi-entity campaign detection. Start here if you want to build, not just understand.

### Related Concepts in This Repository

- [Domain-Aware Entity Framework](domain-aware-entity-framework.md) -- entity field definitions per domain, essential for correlation join logic.
- [Signal Quality Scoring](signal-quality-scoring.md) -- scoring model that feeds into correlation rule evaluation, particularly the co-occurrence and cross-domain correlation dimensions.
- [Detection Confidence Scoring](detection-confidence-scoring.md) -- per-rule confidence scores that inform which building blocks are reliable enough to contribute to correlation.
- [UC-08: Kill Chain Completeness Analysis](../use-cases/posture-assessment/08-kill-chain-completeness-analysis.md) -- uses kill-chain-centric correlation to identify detection breakpoints.
- [UC-09: Cross-Domain Detection Coverage](../use-cases/posture-assessment/09-cross-domain-detection-coverage.md) -- evaluates whether cross-domain correlation is feasible based on entity overlap and rule complementarity.
- [UC-12: Alert Cluster Narrative Synthesis](../use-cases/ai-assisted-triage/12-alert-cluster-narrative-synthesis.md) -- synthesizes correlated alert clusters into coherent narratives for analyst consumption.
