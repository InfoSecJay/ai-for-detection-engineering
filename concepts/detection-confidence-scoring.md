# Detection Confidence Scoring

## Overview

Detection Confidence Scoring rolls up individual rule-level Signal Quality Scores into a technique-level assessment. While Signal Quality tells you "how well is this specific rule performing?", Detection Confidence tells you "how well can we actually detect this technique across our environment?"

A technique covered by four mediocre rules that all look at the same artifact from the same data source is not well-detected. A technique covered by two strong rules that examine different artifacts from different domains is genuinely well-detected. Detection Confidence captures this distinction.

---

## Inputs

For each MITRE ATT&CK technique (or sub-technique), gather:

1. **All mapped rules**: Every detection rule tagged to this technique
2. **Signal Quality Score**: The 0-100 score for each rule (from Signal Quality Scoring)
3. **Entity fields used**: Which primary and secondary entity fields each rule examines
4. **Data source domain**: Which domain each rule operates in (from the Domain-Aware Entity Framework)
5. **Alert status**: Whether the rule has fired in the scoring window

---

## Scoring Components

### Base Score: Weighted Average Signal Quality

Start with the average Signal Quality Score across all rules mapped to the technique, weighted by alert volume:

```
base_score = sum(rule_signal_quality_i * rule_alert_volume_i) / sum(rule_alert_volume_i)
```

Volume weighting ensures that rules with actual production data influence the score more than rules with minimal alerts. Rules with zero alerts are excluded from the base score calculation but contribute to the silence penalty.

If all rules have zero alerts, the base score is 0.

---

### Multiplier 1: Observable Diversity

**What it measures**: Are the rules for this technique detecting genuinely different artifacts, or are they all looking at the same thing?

**Why it matters**: Five rules that all detect "PowerShell execution" by matching on `process.name == powershell.exe` with slight command-line variations are, functionally, one detection with five signatures. One rule detecting PowerShell execution via process creation and another detecting it via script block logging are genuinely different observations.

**Calculation**:

Identify the distinct "observable signatures" across all rules for the technique. An observable signature is defined by the combination of:
- Primary entity fields used in the rule's detection logic
- The specific detection mechanism (e.g., string matching, threshold, aggregation)

```
unique_observable_sets = count of distinct (primary_field_set, detection_mechanism) combinations

observable_diversity_multiplier = min(1.5, 0.7 + (0.2 * unique_observable_sets))
```

| Unique Observable Sets | Multiplier | Interpretation |
|------------------------|------------|----------------|
| 1 | 0.9 | Single observation point -- limited |
| 2 | 1.1 | Two distinct observations -- good |
| 3 | 1.3 | Three distinct observations -- strong |
| 4+ | 1.5 (cap) | Rich observable coverage |

The multiplier starts below 1.0 for single-observation techniques because relying on a single artifact type is inherently fragile.

---

### Multiplier 2: Domain Breadth

**What it measures**: Does detection for this technique span multiple data source domains?

**Why it matters**: A technique detected only on endpoints is blind to the technique when it occurs in cloud infrastructure. Cross-domain detection provides defense-in-depth and catches technique variants that may not manifest identically in every domain.

**Calculation**:

```
unique_domains = count of distinct data source domains across all rules for the technique

domain_breadth_multiplier = min(1.4, 0.8 + (0.2 * unique_domains))
```

| Unique Domains | Multiplier | Interpretation |
|----------------|------------|----------------|
| 1 | 1.0 | Single domain -- acceptable but not robust |
| 2 | 1.2 | Two domains -- good cross-domain coverage |
| 3+ | 1.4 (cap) | Multi-domain -- strong defense-in-depth |

Note: Domain breadth multiplier starts at 1.0 (not below) for a single domain because many techniques genuinely only manifest in one domain (e.g., registry persistence is inherently a Windows endpoint phenomenon).

---

### Penalty: Silence

**What it measures**: What proportion of rules mapped to this technique have not fired in the scoring window?

**Why it matters**: A rule that has never fired is either:
1. Detecting something that hasn't happened (ideal scenario -- but you can't verify the rule works)
2. Broken (query error, data source misconfiguration, field mapping mismatch)
3. Too specific (thresholds too tight, indicators too narrow)

Without knowing which case applies, silent rules must be penalized. The penalty is progressive -- one silent rule out of four is a mild concern; three silent rules out of four is a serious reliability question.

**Calculation**:

```
silence_ratio = count(rules with 0 alerts) / count(all rules for technique)

silence_penalty = 1.0 - (0.5 * silence_ratio^2)
```

The squared term makes the penalty gentle for low silence ratios and aggressive for high ones:

| Silence Ratio | Penalty Multiplier | Effect |
|---------------|-------------------|--------|
| 0% (no silent rules) | 1.00 | No penalty |
| 25% (1 of 4 silent) | 0.97 | Minimal penalty |
| 50% (2 of 4 silent) | 0.88 | Moderate penalty |
| 75% (3 of 4 silent) | 0.72 | Significant penalty |
| 100% (all silent) | 0.50 | Severe penalty (score halved) |

---

## Composite Detection Confidence Score

```
detection_confidence = base_score
    * observable_diversity_multiplier
    * domain_breadth_multiplier
    * silence_penalty
```

The result is clamped to 0-100.

---

## Confidence Tiers

| Tier | Score Range | Description | Operational Meaning |
|------|-------------|-------------|---------------------|
| **Strong** | 80-100 | High-quality rules, diverse observables, cross-domain coverage, active firing | This technique is well-detected. Review periodically but no urgent action needed. |
| **Functional** | 60-79 | Decent rules with some gaps in diversity or domain coverage | Detection works but has known blind spots. Prioritize for improvement when resources allow. |
| **Degraded** | 40-59 | Rules are firing but signal quality is mediocre, or coverage is narrow | Detection exists but produces unreliable signals. Tuning needed. May be generating analyst fatigue. |
| **Abandoned** | 20-39 | Rules are mostly silent, poorly performing, or lack diversity | Detection is nominally present but practically ineffective. Major rework or replacement needed. |
| **Blind** | 0-19 | No effective detection capability | This technique is not detected. Either no rules exist, all rules are broken, or data sources are missing. Highest priority for new detection development. |

---

## Worked Example

### Technique: T1059.001 - PowerShell

Four rules are mapped to this technique:

#### Rule 1: "Suspicious PowerShell Download Cradle" (Windows Endpoint / Sysmon)
- **Signal Quality Score**: 56
- **Alert volume**: 847 (30-day window)
- **Primary entity fields**: `host.name`, `user.name`, `process.name`
- **Detection mechanism**: String match on `process.command_line`
- **Domain**: Windows Endpoint
- **Observable signature**: {process creation, command_line string match}

#### Rule 2: "PowerShell Base64 Encoded Command" (Windows Endpoint / Sysmon)
- **Signal Quality Score**: 71
- **Alert volume**: 234
- **Primary entity fields**: `host.name`, `user.name`, `process.name`
- **Detection mechanism**: Regex match on `process.command_line` for `-EncodedCommand` or `-enc`
- **Domain**: Windows Endpoint
- **Observable signature**: {process creation, command_line regex match}

These two rules use the same primary entity fields and the same general mechanism (command line matching), so they share the same observable signature category: {process creation, command_line pattern match}. They count as **1 unique observable set**.

#### Rule 3: "PowerShell Script Block Logging - Suspicious Keywords" (Windows Endpoint / Windows Security)
- **Signal Quality Score**: 68
- **Alert volume**: 412
- **Primary entity fields**: `host.name`, `user.name`, script block content (via `powershell.scriptblock.text`)
- **Detection mechanism**: Keyword match on script block content
- **Domain**: Windows Endpoint
- **Observable signature**: {script block logging, content keyword match}

This rule uses a fundamentally different artifact (script block content vs. process command line). It counts as a **2nd unique observable set**.

#### Rule 4: "Outbound Connection Following PowerShell Execution" (Network Firewall / Palo Alto)
- **Signal Quality Score**: 0 (no alerts in the scoring window)
- **Alert volume**: 0
- **Primary entity fields**: `source.ip`, `destination.ip`, `destination.port`
- **Detection mechanism**: Correlation -- firewall connection within 60 seconds of PowerShell process start
- **Domain**: Network Firewall
- **Observable signature**: {network connection, temporal correlation}
- **Status**: Silent

This rule uses network-layer artifacts. It counts as a **3rd unique observable set** and a **2nd domain**.

---

### Step 1: Base Score

Only rules with alerts contribute to the base score:

```
base_score = (56 * 847 + 71 * 234 + 68 * 412) / (847 + 234 + 412)
base_score = (47,432 + 16,614 + 28,016) / 1,493
base_score = 92,062 / 1,493
base_score = 61.66
```

### Step 2: Observable Diversity Multiplier

Three unique observable sets: {command_line pattern match}, {script block keyword match}, {network temporal correlation}

```
observable_diversity_multiplier = min(1.5, 0.7 + (0.2 * 3)) = min(1.5, 1.3) = 1.3
```

### Step 3: Domain Breadth Multiplier

Two unique domains: Windows Endpoint, Network Firewall

```
domain_breadth_multiplier = min(1.4, 0.8 + (0.2 * 2)) = min(1.4, 1.2) = 1.2
```

### Step 4: Silence Penalty

One silent rule out of four:

```
silence_ratio = 1 / 4 = 0.25
silence_penalty = 1.0 - (0.5 * 0.25^2) = 1.0 - (0.5 * 0.0625) = 1.0 - 0.03125 = 0.969
```

### Step 5: Composite Score

```
detection_confidence = 61.66 * 1.3 * 1.2 * 0.969
detection_confidence = 61.66 * 1.3 = 80.16
detection_confidence = 80.16 * 1.2 = 96.19
detection_confidence = 96.19 * 0.969 = 93.21
```

Clamped to 100: **detection_confidence = 93.21**

### Wait -- that seems high for a 56-scoring rule. Let's unpack why.

The base score of 61.66 is moderate. But the multipliers reward this technique's detection posture:

1. **Three distinct observable sets** (1.3x): The rules are not all doing the same thing. Command-line matching, script block analysis, and network correlation are genuinely different detection approaches. An attacker would need to evade all three.

2. **Two domains** (1.2x): Endpoint and network coverage means the detection isn't entirely dependent on endpoint agent health.

3. **Minimal silence penalty** (0.969x): Only one rule is silent, and it's the network correlation rule -- which may simply mean no PowerShell execution was followed by a suspicious outbound connection (a legitimate absence of the correlation condition).

The score of 93 places this in the **Strong** tier. This is appropriate -- T1059.001 is genuinely well-detected with diverse, multi-domain coverage. The individual rule scores have room for improvement (especially the download cradle rule at 56), but the overall detection posture is robust.

### What would degrade this score?

If Rules 1 and 2 were the only rules (single observable set, single domain, no silence), the score would be:

```
base = (56 * 847 + 71 * 234) / (847 + 234) = 64,046 / 1,081 = 59.25
observable_diversity = 0.9 (single set, below-1.0 penalty)
domain_breadth = 1.0 (single domain)
silence_penalty = 1.0 (no silent rules)

detection_confidence = 59.25 * 0.9 * 1.0 * 1.0 = 53.33
```

Score: **53.33** -- Degraded tier. Two rules doing essentially the same thing from the same data source provide much less confidence than the diverse four-rule setup, even though neither of the individual rules scored poorly.

---

## Using Detection Confidence Scores

### Prioritizing Detection Engineering Work

Sort techniques by Detection Confidence ascending. The Blind and Abandoned tiers are your highest-priority gaps. But also look for:

- **High-priority techniques in Degraded tier**: These are worse than Blind in some ways -- you think you have detection, but it's unreliable. Analysts may be ignoring alerts from these rules, creating a false sense of coverage.
- **Techniques with high base scores but low multipliers**: Good rules, but too narrow. Adding a rule in a different domain or targeting a different observable would significantly boost confidence.
- **Techniques with many silent rules**: Investigate whether the rules are broken before investing in new detection. Sometimes fixing data source mappings is more valuable than writing new rules.

### Reporting to Leadership

The five tiers translate directly into a coverage heat map:

- Count of techniques per tier
- Trend over time (are we moving techniques from Degraded to Functional?)
- Coverage by tactic (are we Blind to all Initial Access techniques?)

### Feedback Loop

Detection Confidence scores should be recalculated weekly (or daily if feasible). Track:

1. Score changes over time per technique
2. What caused the change (new rule added? existing rule tuned? data source went offline?)
3. Whether tuning efforts resulted in measurable score improvement

This creates a measurable, objective feedback loop for detection engineering work.

---

## Limitations

1. **MITRE mapping quality**: The score is only as good as the rule-to-technique mappings. Miscategorized rules will distort technique-level scores.

2. **Absence vs. presence**: A high Detection Confidence score for T1059.001 means your existing rules are working well. It does not mean you detect all variants of PowerShell abuse. New attack techniques within the same MITRE category may evade every existing rule.

3. **Silent rule ambiguity**: The silence penalty treats all silent rules the same. A rule detecting a rare, nation-state technique that hasn't been observed in your environment is penalized identically to a broken rule. Manual review of silent rules remains necessary.

4. **Multiplier caps**: The observable diversity and domain breadth multipliers are capped, which means adding a 5th observable set provides no additional score benefit. This is intentional -- diminishing returns are real -- but it means the score does not distinguish between 4 and 10 observable sets.

5. **No attacker model**: The score does not consider how likely an attacker is to use this technique, or how sophisticated the attacker would need to be to evade the existing rules. It measures detection capability, not detection adequacy against a specific threat model. Threat-informed prioritization should be applied on top of Detection Confidence scores.
