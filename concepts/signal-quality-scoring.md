# Signal Quality Scoring

## Overview

Signal Quality Scoring assigns a deterministic 0-100 score to each detection rule based on the statistical characteristics of its alert population over a defined time window. The score answers one question: **how likely is this rule to produce alerts that a human analyst would find worth investigating?**

The scoring math is entirely deterministic. No AI, no machine learning, no probabilistic models. Every score is reproducible given the same input data. AI is used only downstream -- to generate natural-language narratives explaining what the scores mean and to synthesize recommendations. The numbers themselves come from straightforward statistical calculations.

---

## Scoring Dimensions

### 1. Entity Diversity

**What it measures**: How many distinct values appear in the rule's primary entity fields over the scoring window.

**Why it matters**: A rule that triggers on 2,000 unique hostnames is behaving differently from a rule that triggers on 3 specific hostnames. Neither is inherently better, but the difference is critical for interpretation.

**Calculation**:

```
entity_diversity(field) = count_distinct(field) / total_alerts
```

**Normalization**: Map to 0-100 using domain-specific reference ranges.

For a Windows endpoint rule keyed on `host.name`:
- 0-10 distinct hosts out of 1,000 alerts: Score 85-100 (highly concentrated, likely targeted detection)
- 11-100 distinct hosts: Score 50-84 (moderate spread)
- 101-500 distinct hosts: Score 20-49 (broad detection)
- 500+ distinct hosts: Score 0-19 (likely noisy)

The interpretation inverts for some domains. For DNS rules keyed on `dns.question.name`, high cardinality in query names is expected and may indicate DGA detection (which is good). The domain config specifies the normalization direction.

```
normalized_diversity = interpolate(
    raw_ratio,
    domain_config.diversity_range_low,
    domain_config.diversity_range_high,
    domain_config.diversity_direction  # "lower_is_better" or "higher_is_better"
)
```

---

### 2. Entity Concentration

**What it measures**: How much of the alert volume is dominated by the top-N entity values.

**Why it matters**: If one hostname generates 90% of a rule's alerts, that single host is either compromised or a persistent false positive source. Either way, the rule's signal quality depends on what happens when you look at that host.

**Calculation**:

```
top_n_concentration(field, n) = sum(alerts for top N values of field) / total_alerts
```

Standard measurement uses top-1, top-5, and top-10.

**Normalization**:

```
concentration_score = 100 * (1 - top_5_concentration) if domain expects distributed alerts
concentration_score = 100 * top_5_concentration if domain expects concentrated alerts
```

For most rules, moderate concentration (top-5 accounts for 30-60% of alerts) scores highest. Extreme concentration in either direction is penalized:
- Top-5 = 95% of alerts: Score 20 (one source dominates, likely FP or misconfiguration)
- Top-5 = 50% of alerts: Score 80 (healthy concentration)
- Top-5 = 5% of alerts: Score 40 (extremely distributed, rule may be too broad)

---

### 3. Entity Entropy

**What it measures**: Shannon entropy of the entity field value distribution.

**Why it matters**: Entropy captures the shape of the distribution beyond simple counts. A rule with 100 distinct hostnames where each appears exactly once (uniform distribution, high entropy) behaves differently from a rule with 100 distinct hostnames where one appears 900 times and the other 99 appear once each (skewed distribution, low entropy).

**Calculation**:

```
entropy(field) = -sum(p_i * log2(p_i)) for each distinct value i
    where p_i = count(value_i) / total_alerts

max_entropy = log2(count_distinct(field))

normalized_entropy = entropy(field) / max_entropy  # 0 to 1
```

**Normalization to 0-100**:

For endpoint rules (where concentrated signals are usually better):
```
entropy_score = 100 * (1 - normalized_entropy)
```

For network rules detecting scanning (where distributed signals are expected):
```
entropy_score = 100 * normalized_entropy
```

The domain configuration specifies which direction is "good."

---

### 4. Volume Stability

**What it measures**: How consistent the rule's alert volume is over time.

**Why it matters**: A rule that fires 10 alerts per day consistently is easier to baseline and triage than a rule that fires 0 alerts for three weeks then 5,000 in one day. Volume stability does not mean "low volume" -- it means predictable volume.

**Calculation**:

Compute daily alert counts over the scoring window (default: 30 days). Then:

```
coefficient_of_variation = std_dev(daily_counts) / mean(daily_counts)

stability_score = 100 * max(0, 1 - coefficient_of_variation)
```

Interpretation:
- CV = 0.1 (very stable): Score 90
- CV = 0.5 (moderate variance): Score 50
- CV = 2.0 (highly volatile): Score 0

**Special case**: Rules with zero alerts in the scoring window receive a volume stability score of 0 and trigger the silence penalty (see Detection Confidence Scoring).

---

### 5. Periodicity

**What it measures**: Whether the rule's alert pattern shows regular temporal cycles.

**Why it matters**: Periodic firing patterns (every 24 hours, every Monday, every 5 minutes) almost always indicate automated/scheduled activity rather than attacker behavior. A rule that fires like clockwork is detecting cron jobs, backup scripts, or monitoring tools -- not threats.

**Calculation**:

Compute autocorrelation of the hourly alert time series:

```
autocorrelation(lag) = correlation(timeseries, shift(timeseries, lag))

max_periodic_autocorrelation = max(autocorrelation(lag) for lag in [1h, 4h, 8h, 12h, 24h, 168h])

periodicity_score = 100 * (1 - max_periodic_autocorrelation)
```

A rule with strong 24-hour periodicity (autocorrelation = 0.9 at lag=24h) gets a periodicity score of 10 (bad). A rule with no detectable periodicity (max autocorrelation = 0.1) gets a score of 90 (good).

---

### 6. Co-occurrence Rate

**What it measures**: How often this rule fires alongside other rules for the same entity within a time window.

**Why it matters**: An alert that fires in isolation is harder to validate. An alert that fires alongside two other rules for the same host in the same 15-minute window is part of a corroborated detection chain. Rules that frequently co-occur with other rules produce higher-confidence signals.

**Calculation**:

```
co_occurrence_rate = alerts_with_at_least_one_co_occurring_rule / total_alerts

co_occurrence_window = 15 minutes (configurable)
co_occurrence_join_field = primary entity field (e.g., host.name for endpoint rules)
```

**Normalization**:

```
co_occurrence_score = 100 * co_occurrence_rate
```

A rule where 70% of alerts co-occur with other rules scores 70. A rule that always fires alone scores close to 0.

---

### 7. Cross-Domain Correlation

**What it measures**: Whether this rule's alerts correlate with alerts from rules in different data source domains.

**Why it matters**: An endpoint detection that correlates with a network detection for the same entity (e.g., same source IP appears in both a process execution alert and a firewall block alert within 30 minutes) is much stronger than either detection alone. Cross-domain correlation is the highest form of alert validation short of human analysis.

**Calculation**:

```
cross_domain_rate = alerts_with_correlated_alert_in_different_domain / total_alerts

correlation_window = 30 minutes (configurable)
correlation_join = mapped entity fields (see Domain-Aware Entity Framework cross-domain mapping)
```

**Normalization**:

```
cross_domain_score = 100 * min(1, cross_domain_rate / 0.3)
```

The denominator (0.3) reflects the expectation that even well-correlated rules rarely exceed 30% cross-domain correlation. Reaching 30% or higher earns a perfect 100.

---

### 8. Data Source Health

**What it measures**: Whether the data sources feeding this rule are actually delivering data consistently.

**Why it matters**: A rule cannot produce meaningful alerts if its data source has gaps. A rule with a perfect entity distribution but a data source that was offline for 15 of the last 30 days is unreliable.

**Calculation**:

```
expected_events_per_day = baseline from data source health monitoring
actual_events_per_day = observed event count per day

daily_health = min(1, actual_events_per_day / expected_events_per_day)
data_source_health_score = 100 * mean(daily_health over scoring window)
```

A data source delivering 100% of expected volume every day scores 100. A data source that went silent for 10 of 30 days scores approximately 67.

---

## Domain-Specific Weights

Not all dimensions matter equally for all rule types. The composite score uses domain-specific weights:

### Windows Endpoint Rules

| Dimension | Weight | Rationale |
|-----------|--------|-----------|
| Entity Diversity | 0.15 | Important but secondary to command line analysis |
| Entity Concentration | 0.15 | Helps identify FP-generating hosts |
| Entity Entropy | 0.10 | Distribution shape matters |
| Volume Stability | 0.10 | Baseline predictability |
| Periodicity | 0.15 | Critical -- catches cron/scheduled task noise |
| Co-occurrence Rate | 0.15 | Attack chains are common on endpoints |
| Cross-Domain Correlation | 0.10 | Valuable but not always available |
| Data Source Health | 0.10 | Foundation reliability |

**Additional**: Command line diversity gets a 1.3x multiplier on the entity diversity dimension when `process.command_line` is a secondary entity field. This is applied as:

```
effective_entity_diversity = entity_diversity_score * 1.3 (capped at 100)
    if domain == windows_endpoint and rule uses process.command_line
```

### Network Firewall Rules

| Dimension | Weight | Rationale |
|-----------|--------|-----------|
| Entity Diversity | 0.20 | IP diversity is the primary signal |
| Entity Concentration | 0.20 | Top-talker analysis is critical |
| Entity Entropy | 0.10 | Distribution shape |
| Volume Stability | 0.10 | Baseline predictability |
| Periodicity | 0.10 | Less important -- some scanning is periodic |
| Co-occurrence Rate | 0.10 | Firewall rules often fire in clusters |
| Cross-Domain Correlation | 0.10 | Endpoint correlation strengthens network detections |
| Data Source Health | 0.10 | Foundation reliability |

### Cloud AWS Rules

| Dimension | Weight | Rationale |
|-----------|--------|-----------|
| Entity Diversity | 0.15 | Identity diversity matters |
| Entity Concentration | 0.20 | Account/identity concentration is key signal |
| Entity Entropy | 0.10 | Distribution shape |
| Volume Stability | 0.10 | Baseline predictability |
| Periodicity | 0.15 | Critical -- catches scheduled automation (Lambda, Config rules) |
| Co-occurrence Rate | 0.10 | CloudTrail events often cluster by session |
| Cross-Domain Correlation | 0.10 | Cloud + identity correlation is valuable |
| Data Source Health | 0.10 | CloudTrail delivery can lag or have gaps |

### Identity (Okta) Rules

| Dimension | Weight | Rationale |
|-----------|--------|-----------|
| Entity Diversity | 0.15 | User diversity |
| Entity Concentration | 0.20 | A few users generating most alerts is meaningful |
| Entity Entropy | 0.10 | Distribution shape |
| Volume Stability | 0.10 | Auth patterns should be stable |
| Periodicity | 0.10 | Some periodicity is normal (shift changes) |
| Co-occurrence Rate | 0.15 | Auth alerts clustering is strong signal |
| Cross-Domain Correlation | 0.10 | Identity + endpoint correlation is powerful |
| Data Source Health | 0.10 | Okta log delivery reliability |

---

## Composite Formula

The final Signal Quality Score is a weighted sum:

```
signal_quality_score = sum(
    dimension_weight_i * dimension_score_i
    for each dimension i
)
```

Where `dimension_weight_i` comes from the domain-specific weight table and `dimension_score_i` is the normalized 0-100 score for that dimension.

The result is naturally bounded to 0-100 because all dimension scores are 0-100 and all weights sum to 1.0.

**No AI is involved in this calculation.** The score is a pure function of the alert data and the configuration. Given the same alerts and the same config, the score is identical every time.

---

## Example Calculation

### Scenario: Windows Endpoint Rule "Suspicious PowerShell Download Cradle"

**Rule**: Detects `powershell.exe` with command lines containing `(New-Object Net.WebClient).DownloadString` or `Invoke-WebRequest` piped to `Invoke-Expression`.

**Scoring window**: Last 30 days

**Raw data**:
- Total alerts: 847
- Distinct `host.name` values: 12
- Distinct `user.name` values: 8
- Distinct `process.command_line` values: 23
- Top-5 hosts account for: 78% of alerts
- Top-1 host accounts for: 41% of alerts

**Dimension calculations**:

**1. Entity Diversity (host.name)**:
- 12 distinct hosts / 847 alerts = 0.014 ratio
- For Windows endpoint, low ratio with few distinct hosts: Score = **82** (concentrated, good for targeted detection)

**2. Entity Concentration**:
- Top-5 = 78%, Top-1 = 41%
- Moderate-to-high concentration: Score = **55** (one host dominates, investigate it)

**3. Entity Entropy (host.name)**:
- Distribution: host-A = 347, host-B = 112, host-C = 89, hosts D-L = 299 combined
- Shannon entropy = 2.68, max entropy = log2(12) = 3.58
- Normalized entropy = 0.75
- For endpoint (lower entropy = more concentrated = better): Score = 100 * (1 - 0.75) = **25**

**4. Volume Stability**:
- Daily counts: mean = 28.2, std_dev = 11.4
- CV = 11.4 / 28.2 = 0.40
- Score = 100 * (1 - 0.40) = **60**

**5. Periodicity**:
- Autocorrelation at 24h lag: 0.72 (strong daily pattern)
- Score = 100 * (1 - 0.72) = **28** (penalty for periodic firing)

**6. Co-occurrence Rate**:
- 340 of 847 alerts co-occur with other endpoint rules within 15 min
- Rate = 0.40
- Score = **40**

**7. Cross-Domain Correlation**:
- 85 of 847 alerts have correlated network/proxy alerts within 30 min
- Rate = 0.10
- Score = 100 * min(1, 0.10 / 0.30) = **33**

**8. Data Source Health**:
- Sysmon data present all 30 days, minor gaps on 2 days (95% delivery)
- Score = **95**

**Weighted composite (Windows Endpoint weights)**:

| Dimension | Score | Weight | Weighted |
|-----------|-------|--------|----------|
| Entity Diversity | 82 | 0.15 | 12.30 |
| Entity Concentration | 55 | 0.15 | 8.25 |
| Entity Entropy | 25 | 0.10 | 2.50 |
| Volume Stability | 60 | 0.10 | 6.00 |
| Periodicity | 28 | 0.15 | 4.20 |
| Co-occurrence Rate | 40 | 0.15 | 6.00 |
| Cross-Domain Correlation | 33 | 0.10 | 3.30 |
| Data Source Health | 95 | 0.10 | 9.50 |
| **Total** | | **1.00** | **52.05** |

**Command line diversity multiplier**: 23 distinct command lines across 847 alerts shows moderate diversity. Apply 1.3x to entity diversity weighted contribution: 12.30 * 1.3 = 15.99. Adjusted total: **55.74**

**Final Signal Quality Score: 56 / 100**

### Interpretation

This rule scores in the mid-range. The key findings:

1. **Strong entity concentration** (82 on diversity) -- the rule is detecting activity on a small set of hosts, which is good for a targeted detection.
2. **Significant periodicity penalty** (28) -- the strong 24-hour cycle suggests at least some of these alerts are triggered by scheduled automation (probably a legitimate PowerShell script running daily on the top host).
3. **Moderate co-occurrence** (40) -- some alerts correlate with other endpoint detections, lending credibility.
4. **Low cross-domain correlation** (33) -- limited network-level corroboration.

**Recommendation** (this is where AI-generated narrative adds value): "Investigate host-A (41% of volume) for a scheduled PowerShell task generating false positives. The daily periodicity and single-host concentration suggest a legitimate automation script. Excluding this host would likely raise the rule's signal quality score to the 70+ range. The remaining alerts show meaningful co-occurrence with other endpoint detections and warrant continued monitoring."

That narrative is generated by AI. The score of 56 is not.

---

## Scoring Window and Refresh

- **Default scoring window**: 30 days rolling
- **Minimum data requirement**: 10 alerts in the window (rules with fewer are flagged as "insufficient data" rather than scored)
- **Refresh cadence**: Daily recalculation recommended; weekly is acceptable for large environments
- **Historical tracking**: Store daily scores to visualize trends. A declining score indicates a rule's detection environment is changing (new FP sources, data source degradation, etc.)

---

## Edge Cases

### Zero-Alert Rules
Rules with 0 alerts in the scoring window receive no Signal Quality Score. They are instead flagged with a **silence indicator** that feeds into the Detection Confidence Scoring system as a silence penalty.

### Very Low Volume Rules
Rules with 1-9 alerts in the scoring window receive a score flagged as "low confidence." The statistical measures (entropy, periodicity, concentration) are unreliable with small sample sizes. These rules are scored but their results carry a reduced weight when rolling up to Detection Confidence.

### Rules Across Multiple Data Sources
Some rules query multiple data source types (e.g., a correlation rule joining endpoint and network data). These rules are scored against the domain of their **primary data source** (as specified in the rule metadata). If no primary is specified, the domain is inferred from the entity fields used in the rule's grouping clause.

### New Rules
Rules deployed within the scoring window receive a prorated score based on available data. A rule deployed 10 days ago is scored on 10 days of data with a "new rule" flag. The minimum data requirement (10 alerts) still applies.
