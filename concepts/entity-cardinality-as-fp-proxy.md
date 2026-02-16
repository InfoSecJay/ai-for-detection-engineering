# Entity Cardinality as False Positive Proxy

## The Problem

The gold standard for measuring detection rule quality is analyst disposition data: for every alert, did a human analyst mark it as true positive, false positive, or benign true positive? With disposition data, you can calculate a rule's true positive rate directly.

Most organizations do not have this data. The reasons are practical:

1. **Analysts do not consistently record dispositions.** SOAR platforms support it, but compliance is low. Under alert fatigue, analysts close tickets without categorizing them.
2. **Disposition taxonomies vary.** What one analyst calls "false positive" another calls "benign true positive." There is no universal standard.
3. **Historical data is sparse.** Even if you start collecting dispositions today, you need months of data before statistical measures become meaningful.
4. **Some alerts are never triaged.** In overloaded SOCs, low-severity alerts age out of queues without human review.

Entity cardinality analysis provides a **proxy signal** for false positive rates when disposition data is unavailable. It is not a replacement -- it is a reasonable approximation that lets you assess rule quality today, with data you already have.

---

## Core Insight

**A detection rule's entity distribution tells you about its signal quality even without knowing which individual alerts are true or false positives.**

The underlying assumption:

- A rule that triggers on 500 unique hosts in a 30-day window is probably catching a broad, common behavior pattern. Unless the rule specifically targets a widespread attack (like WannaCry spreading laterally), most of those 500 hosts are likely exhibiting normal behavior that happens to match the rule. The rule is probably noisy.

- A rule that triggers on 3 specific hosts is probably detecting something targeted. Those 3 hosts are either compromised or doing something genuinely unusual. The rule is probably more precise.

This is not always true. But it is true often enough to be a useful heuristic.

---

## Key Metrics

### 1. Alert-to-Entity Ratio

The simplest measure: how many alerts per unique entity?

```
alert_to_entity_ratio = total_alerts / count_distinct(primary_entity)
```

**Example for a Windows endpoint rule keyed on `host.name`**:
- Rule A: 1,200 alerts, 8 distinct hosts. Ratio = 150. Each flagged host is generating many alerts -- either the hosts are genuinely active threats, or the rule is firing repeatedly on the same benign activity.
- Rule B: 1,200 alerts, 800 distinct hosts. Ratio = 1.5. The rule fires on almost every host it touches exactly once or twice. This is either a very widespread attack or a very noisy rule.

**Interpretation**: High ratio (many alerts per entity) suggests concentrated activity. Low ratio (close to 1) suggests the rule matches broadly. Neither is inherently good or bad -- the interpretation depends on what the rule is designed to detect.

### 2. Top-N Concentration

What percentage of total alert volume comes from the top N entities?

```
top_n_pct = sum(alert_count for top N entities) / total_alerts * 100
```

Commonly measured at N=1, N=5, and N=10.

**Example**:
- Rule C: Top-1 host = 62% of alerts, Top-5 hosts = 91%. Extreme concentration. One host is the primary driver of this rule's alert volume.
- Rule D: Top-1 host = 4% of alerts, Top-5 hosts = 18%. Very distributed. No single entity stands out.

**What concentration tells you**:

| Top-5 Concentration | Likely Scenario |
|---------------------|-----------------|
| > 80% | Dominated by a few entities. Investigate those specific entities -- they are either persistent threats or persistent FP generators. |
| 40-80% | Moderate concentration. Some entities are more active than others, but the rule catches activity across a meaningful population. |
| < 40% | Highly distributed. The rule is casting a wide net. Unless it targets a widespread attack, this suggests low precision. |

### 3. Entropy

Shannon entropy of the entity value distribution, capturing the shape beyond simple counts.

```
entropy = -sum(p_i * log2(p_i))
    where p_i = alerts_for_entity_i / total_alerts

normalized_entropy = entropy / log2(count_distinct(entity))
    # 0 = all alerts from one entity
    # 1 = perfectly uniform distribution
```

**Why entropy matters more than just distinct count**:

Consider two rules, both with 100 distinct hosts and 1,000 alerts:

- Rule E: Host-1 has 910 alerts, hosts 2-100 have 1 alert each. Distinct count = 100, but normalized entropy = 0.15. This rule is functionally a single-host detector.
- Rule F: Each host has 10 alerts. Distinct count = 100, normalized entropy = 1.0. The rule triggers uniformly.

Distinct count alone says these rules are identical. Entropy reveals they are fundamentally different.

---

## Interpretation Thresholds

These thresholds are starting points. They must be calibrated per environment and per domain. The values below assume a 30-day scoring window for endpoint detection rules.

### For Rules Where Concentrated Activity = Better Signal

Most endpoint rules, identity rules, and targeted threat detection rules fall in this category.

| Metric | Good Signal | Moderate Signal | Noisy Signal |
|--------|-------------|-----------------|--------------|
| Distinct entities | < 20 | 20-200 | > 200 |
| Alert-to-entity ratio | > 50 | 10-50 | < 10 |
| Top-5 concentration | > 60% | 30-60% | < 30% |
| Normalized entropy | < 0.4 | 0.4-0.7 | > 0.7 |

**Worked example -- good signal**:

Rule: "LSASS Memory Dump via Comsvcs.dll"
- 47 alerts over 30 days
- 3 distinct hosts
- Alert-to-entity ratio: 15.7
- Top-5 concentration: 100% (only 3 hosts)
- Normalized entropy: 0.82 (somewhat distributed across the 3, not dominated by 1)

Assessment: **Good signal**. Three hosts are running a known credential dumping technique. The moderate entropy across those three hosts suggests this is not a single misconfiguration but possibly three independent events worth investigating.

**Worked example -- noisy signal**:

Rule: "PowerShell Execution with Script Block Logging"
- 14,782 alerts over 30 days
- 2,341 distinct hosts
- Alert-to-entity ratio: 6.3
- Top-5 concentration: 8%
- Normalized entropy: 0.91

Assessment: **Noisy**. This rule triggers on nearly every host that runs PowerShell. The very high distinct entity count, low ratio, low concentration, and high entropy all converge on the same conclusion: the rule is too broad for an environment where PowerShell is widely used.

### For Rules Where Distributed Activity = Better Signal

Some rules are specifically designed to detect widespread activity: lateral movement scanning, worm propagation, or distributed credential stuffing. For these rules, the interpretation inverts.

| Metric | Good Signal | Moderate Signal | Weak Signal |
|--------|-------------|-----------------|-------------|
| Distinct entities | > 100 | 20-100 | < 20 |
| Alert-to-entity ratio | < 5 | 5-20 | > 20 |
| Top-5 concentration | < 20% | 20-50% | > 50% |
| Normalized entropy | > 0.8 | 0.5-0.8 | < 0.5 |

**Worked example -- distributed detection**:

Rule: "Internal Port Scan Detected" (network firewall)
- 892 alerts over 30 days
- 412 distinct source IPs
- Alert-to-entity ratio: 2.2
- Top-5 concentration: 14%
- Normalized entropy: 0.88

Assessment: This looks concerning -- 412 internal hosts triggered a port scan rule. However, the metric profile is actually **expected for a scanning detection rule**. The question is whether 412 scanning hosts is normal for this environment. If the environment has 50,000 hosts, 412 scanners is less than 1% -- possibly normal network discovery tools. If the environment has 500 hosts, 412 is 82% -- something is very wrong.

Context matters. Cardinality metrics provide the starting point, not the final answer.

---

## Multi-Entity Analysis

The most powerful application of entity cardinality is analyzing multiple entity fields simultaneously for the same rule.

**Example**: A rule keyed on both `host.name` and `user.name`:
- 500 alerts
- 200 distinct hosts
- 5 distinct users

This reveals that 5 user accounts are triggering the rule across 200 different hosts. That pattern -- few users, many hosts -- is characteristic of:
- A service account running a scheduled task across infrastructure
- A compromised credential being used for lateral movement
- An admin account performing legitimate mass operations

The cross-entity ratio (200 hosts / 5 users = 40 hosts per user) tells a story that neither dimension alone conveys.

**Matrix approach**:

For each pair of primary entity fields, compute:

```
cross_entity_ratio = count_distinct(field_A) / count_distinct(field_B)
```

| Pattern | Interpretation |
|---------|---------------|
| Many hosts, few users | Service accounts, lateral movement, or admin activity |
| Few hosts, many users | Shared workstations, jump hosts, or compromised hosts serving many users |
| Many hosts, many users | Broad rule matching common behavior |
| Few hosts, few users | Targeted activity -- highest signal |

---

## Limitations

### 1. Cardinality is not causation

High entity cardinality correlates with noisiness but does not prove it. A worm spreading to 500 hosts would produce high cardinality and be entirely true positive. The proxy works most of the time because most high-cardinality rules in practice are noisy -- but exceptions exist.

### 2. Environment size dependency

A rule triggering on 50 unique hosts means different things in a 200-host environment vs. a 50,000-host environment. Thresholds must be expressed as percentages of the total entity population, not absolute numbers. If you have asset inventory data, normalize:

```
entity_coverage = count_distinct(entity) / total_population(entity_type)
```

A rule covering 25% of all hosts is probably noisy. A rule covering 0.1% of all hosts is probably targeted.

### 3. Time window sensitivity

A 7-day window and a 90-day window for the same rule will produce different cardinality metrics. Longer windows accumulate more unique entities. Standardize on a consistent window (recommended: 30 days) for comparability.

### 4. Entity resolution quality

If `host.name` has inconsistent values (some logs use FQDN, some use short hostname, some use IP address), the distinct count will be artificially inflated. Entity resolution (normalizing `SERVER01`, `server01.corp.local`, and `10.1.2.3` to the same host) must happen before cardinality analysis.

### 5. Does not capture alert severity

A rule generating 1,000 alerts on 500 hosts where all alerts are informational severity is different from the same distribution where all alerts are critical. Cardinality analysis is severity-blind. Weighting by severity or combining with severity-based filtering is recommended when severity data is available and reliable.

---

## Upgrade Path: When Disposition Data Becomes Available

When your SOC begins reliably recording analyst dispositions (TP/FP/BTP) on alerts, the entity cardinality approach should transition from primary scoring mechanism to validation mechanism:

### Phase 1: Disposition Collection (0-3 months)

- Continue using cardinality as the primary FP proxy
- Begin collecting disposition data on new alerts
- Require disposition on all high-severity alerts; encourage on medium-severity

### Phase 2: Correlation Validation (3-6 months)

- Compare cardinality-predicted FP rates with actual disposition-derived FP rates
- Calculate the correlation coefficient between your cardinality-based score and the actual TP rate
- Identify rules where the proxy diverges from reality (these are the rules where cardinality analysis was misleading)
- Adjust domain-specific thresholds based on observed correlations

### Phase 3: Hybrid Scoring (6-12 months)

- Use disposition-derived FP rate as the primary signal quality indicator where data is sufficient (100+ dispositioned alerts per rule)
- Fall back to cardinality-based scoring for rules with insufficient disposition data
- Weight the two signals proportionally to disposition data availability:

```
hybrid_score = (disposition_weight * disposition_score) + (cardinality_weight * cardinality_score)

where:
  disposition_weight = min(1.0, dispositioned_alerts / 100)
  cardinality_weight = 1.0 - disposition_weight
```

### Phase 4: Disposition-Primary (12+ months)

- Disposition data is the primary input for Signal Quality Scoring
- Cardinality metrics continue to be calculated as a sanity check and for new rules without disposition history
- Cardinality divergence from disposition becomes an alert of its own: "Rule X has high cardinality (predicted noisy) but 90% TP rate (actually precise) -- investigate why"

---

## Why This Works (And Why It's Good Enough)

The entity cardinality approach works because of a fundamental property of detection rules: **rules that match a specific malicious behavior tend to match it on specific entities, while rules that match a broad behavioral pattern tend to match it everywhere.**

This is not a universal law. It is an empirical observation that holds in the majority of SOC environments. The exceptions (widespread attacks detected by precise rules, narrowly-targeted benign activity matching broad rules) exist but are the minority case.

When you lack disposition data, you have three options:

1. **Guess.** Assume all rules are equally effective. This is what most organizations do by default, and it provides zero insight.
2. **Ask analysts to rate rules subjectively.** This captures real knowledge but is inconsistent, unscalable, and introduces bias.
3. **Measure entity cardinality.** This uses data you already have, runs automatically, scales to thousands of rules, and produces consistent, reproducible results.

Option 3 is not perfect. But it is dramatically better than options 1 and 2, and it provides a quantitative foundation that can be improved over time as better data (dispositions) becomes available.

The goal is not to replace human judgment. The goal is to give human judgment a starting point that is better than nothing.
