# UC-05: Temporal Pattern Detection

## Category

Alert Analysis

## Summary

Use statistical analysis and LLM interpretation to identify and explain temporal patterns in detection rule alert data that go beyond basic periodicity. The SIEM handles simple periodicity detection — business hours firing, daily spikes, weekly cycles — through date histogram aggregations. AI adds value by identifying complex, irregular, or context-dependent temporal patterns: business-cycle-aligned behavior, gradually shifting schedules, holiday-correlated patterns, and correlations with external calendars. More importantly, the AI explains *why* a temporal pattern exists and *what it means* for detection engineering decisions.

## Problem Statement

Most detection rules exhibit temporal patterns. Some are obvious: a login-failure rule spikes at 9 AM when employees arrive. Some are subtle: a software inventory rule fires every third Thursday, aligned with the IT patching cycle. Some are concerning: a data exfiltration rule fires in a pattern that avoids business hours and shifts timing by 15 minutes each day, consistent with adversary operational security.

Basic periodicity (daily, weekly, business hours) is detectable with SIEM date histogram aggregations. But several classes of temporal patterns exceed what simple histogram analysis reveals:

- **Business-cycle alignment**: Alerts that correlate with pay periods, quarter-end close, compliance audit windows, or deployment sprints. These are not fixed calendar intervals — they shift with the business calendar.
- **Shifting patterns**: A scheduled task that was running at 2:00 AM but is now running at 2:15 AM, and next week at 2:30 AM. The drift is subtle and invisible in a weekly summary, but over months it shifts the rule's firing window into a different operational context.
- **Multi-scale periodicity**: A rule that fires with both a daily pattern (business hours) AND a monthly pattern (quarter-end spike). Decomposing overlaid periodicities requires more than a single-scale histogram.
- **External calendar correlation**: Alerts that spike on public holidays, during school vacation periods, on patch Tuesdays, or during known vendor maintenance windows. These correlations are invisible without external calendar data.
- **Absence patterns**: Time windows when a rule *should* fire (based on its typical pattern) but does not. This is the temporal analog of silent-rule drift — the rule fires, but with gaps that may indicate intermittent data source issues.
- **Adversary-aligned patterns**: Alert patterns that are consistent with human adversary work hours in a specific time zone, or patterns that deliberately avoid the organization's business hours. This is a low-frequency but high-value detection signal.

The challenge is not just detecting these patterns but interpreting them. A monthly spike in a data-access rule could be a scheduled compliance report or a monthly data exfiltration operation. The temporal pattern alone does not determine which — but combined with entity analysis, the rule's intent, and organizational context, an AI can provide an informed assessment.

## Prerequisites (What Your SIEM/SOAR Should Already Handle)

- **Date histogram aggregation**: Hourly, daily, and weekly alert counts per rule. This is the foundational temporal data structure. Every SIEM supports this natively.
  ```
  // Elastic example — hourly alert distribution over 30 days
  {
    "aggs": {
      "by_rule": {
        "terms": { "field": "rule.id", "size": 5000 },
        "aggs": {
          "hourly": {
            "date_histogram": {
              "field": "@timestamp",
              "calendar_interval": "hour"
            }
          }
        }
      }
    }
  }
  ```
- **Hour-of-day and day-of-week distributions**: Aggregate alert counts by hour (0-23) and day of week (Mon-Sun) independent of date. This shows the "typical week" shape. Splunk: `eval hour=strftime(_time, "%H") | stats count by rule_name, hour`. KQL: `summarize count() by RuleName, bin(TimeGenerated, 1h) % 24h`.
- **Basic periodicity flagging**: Identify rules that fire predominantly during business hours (e.g., 70%+ of alerts between 08:00-18:00 local time) vs. 24/7 vs. off-hours. This is a derived metric from the hour-of-day distribution.
- **Time series data export**: The ability to export alert time series data (timestamp + rule ID + entity fields) for external statistical analysis. Not all temporal analysis needs to happen inside the SIEM.

## Where AI Adds Value

### 1. Complex Pattern Recognition via Statistical Methods

Some temporal patterns require statistical decomposition before they are interpretable:

- **Seasonal-Trend decomposition (STL)**: Separate a rule's alert time series into trend, seasonal, and residual components. The trend shows long-term volume direction. The seasonal component reveals periodicity. The residual shows unexplained variation — which may be the most interesting signal.
- **Autocorrelation analysis**: Compute the autocorrelation function (ACF) to identify periodicities at multiple scales. A rule might have strong autocorrelation at lag 24 (daily pattern) AND lag 168 (weekly pattern) AND lag 720 (monthly pattern).
- **Fourier transform for frequency identification**: Convert the time series to the frequency domain to identify dominant periodicities without assuming a specific interval.

These are statistical methods, not AI. But they produce outputs that are difficult for non-specialists to interpret. The LLM reads the statistical results and produces plain-language explanations.

### 2. External Calendar Correlation

The AI correlates temporal patterns with external calendars:

- **Business calendar**: "This rule's monthly spike aligns with the last business day of each month, consistent with month-end financial close activities."
- **Patch calendar**: "Alert volume spikes on the second Tuesday of each month, aligned with Microsoft Patch Tuesday. The rule detects software installation activity, which is expected during patching."
- **Holiday calendar**: "This rule is silent on US federal holidays and the week between Christmas and New Year. The rule detects employee workstation activity — silence during holidays is expected."
- **Adversary work patterns**: "This rule fires predominantly between 09:00-17:00 UTC+3 (Moscow/Riyadh time zone), which corresponds to 01:00-09:00 local time. The alerts are concentrated on weekdays. This pattern is consistent with human-operated activity from UTC+3, occurring outside the organization's business hours."

### 3. Pattern Shift Detection

The AI identifies patterns that are changing over time:

"This rule's peak firing hour has shifted from 02:00 to 03:15 over the past 60 days. The shift is linear — approximately 1.25 minutes per day. This is consistent with a scheduled task that uses a relative timer (e.g., 'run 2 hours after system boot') on a system whose boot time is gradually shifting, likely due to increasing boot duration from accumulated software. Alternatively, it could indicate a time-zone configuration issue drifting relative to UTC."

### 4. Absence Pattern Detection

The AI identifies time windows where alerts are unexpectedly absent:

"This rule fires consistently at 03:00 daily (backup-related process execution). However, it was absent on Feb 8, Feb 9, and Feb 10. These dates fall on a Saturday, Sunday, and Monday (President's Day). If the backup job is configured to skip weekends and holidays, this absence is expected. If it is configured to run daily regardless, the absence indicates the backup job failed for 3 consecutive days."

### 5. Pattern Explanation for Detection Engineering Decisions

The AI translates temporal patterns into actionable detection engineering guidance:

"This rule fires 92% during business hours. If the detection intent is to identify after-hours suspicious activity, the rule is miscalibrated — it is mostly detecting normal business operations. Consider adding a time-of-day filter to exclude business hours, or conversely, create a separate rule variant specifically for off-hours occurrences with higher severity."

## AI Approach

**Method**: Statistical analysis for pattern extraction + LLM interpretation for explanation and context.

### Two-Stage Architecture

**Stage 1: Statistical Pattern Extraction (Deterministic)**

This stage does not use AI. It applies standard time series analysis to the alert data:

1. **Hourly binning**: Convert alert timestamps to hour-of-day and day-of-week distributions.
2. **STL decomposition**: Apply Seasonal-Trend decomposition using LOESS (Python `statsmodels.tsa.seasonal.STL`) to extract trend, seasonal, and residual components. Test seasonal periods of 24 (daily), 168 (weekly), and 720 (monthly).
3. **Autocorrelation**: Compute ACF with lags up to 720 hours (30 days) to identify dominant periodicities.
4. **Peak detection**: Identify recurring peak hours/days using local maxima in the seasonal component.
5. **Shift detection**: Compare peak timing in the first half vs. second half of the analysis window to detect systematic pattern shifts.
6. **Absence detection**: Identify gaps in expected firing patterns by comparing actual counts to the seasonal expectation, flagging windows where actual < expected - 2*residual_stddev.
7. **External calendar tagging**: Tag each day in the time series with external calendar attributes (business day, holiday, patch Tuesday, quarter-end, etc.).

Output: A structured statistical profile per rule.

```json
{
  "rule_id": "siem-rule-00550",
  "temporal_profile": {
    "dominant_periodicities": [
      { "period_hours": 24, "strength": 0.87, "description": "strong daily" },
      { "period_hours": 168, "strength": 0.42, "description": "moderate weekly" }
    ],
    "peak_hours": [9, 10, 11, 14, 15, 16],
    "quiet_hours": [0, 1, 2, 3, 4, 5, 22, 23],
    "business_hours_pct": 78.4,
    "weekend_pct": 8.2,
    "peak_shift": {
      "detected": false
    },
    "absence_windows": [
      { "date": "2026-01-20", "day_of_week": "Monday", "note": "MLK Day (US holiday)" },
      { "date": "2026-02-08", "day_of_week": "Sunday", "note": "weekend" }
    ],
    "external_calendar_correlations": [
      { "calendar": "us_holidays", "correlation": 0.91, "direction": "negative" },
      { "calendar": "patch_tuesday", "correlation": 0.12, "direction": "positive" }
    ],
    "trend": "stable",
    "residual_anomalies": [
      { "date": "2026-02-03", "actual": 847, "expected": 120, "zscore": 6.1 }
    ]
  }
}
```

**Stage 2: LLM Interpretation**

The LLM receives the statistical profile, the rule context (name, description, intent, MITRE mapping), and any relevant entity data. It produces a human-readable temporal analysis.

Prompt structure:
1. Rule context (name, description, detection intent, data source domain)
2. Statistical temporal profile (JSON from Stage 1)
3. External calendar context (holidays, business cycles, known maintenance windows)
4. Entity data (optional — from UC-02, if the temporal pattern is entity-specific)
5. Task: "Explain the temporal patterns observed for this rule. For each pattern, assess whether it is expected given the rule's intent, identify any patterns that suggest miscalibration or concern, and provide recommendations."

## Data Requirements

### Inputs

| Data Element | Source | Computation | Notes |
|---|---|---|---|
| Alert timestamps per rule | SIEM alert index | Raw timestamps, grouped by rule | Foundation for all temporal analysis |
| Hour-of-day distribution | Derived | Count per hour (0-23), aggregated across analysis window | Collapses date, shows daily shape |
| Day-of-week distribution | Derived | Count per day (Mon-Sun), aggregated across analysis window | Shows weekly shape |
| Date histogram (hourly) | SIEM alert index | Hourly alert count time series | Full resolution time series for statistical analysis |
| STL decomposition | Derived (external) | Trend + seasonal + residual components | Requires Python/R — not in-SIEM |
| Autocorrelation function | Derived (external) | ACF with lags up to 720 hours | Identifies multi-scale periodicity |
| External calendar | Configuration | US holidays, Patch Tuesday dates, quarter-end dates, business calendar | Static calendar data, updated annually |
| Rule metadata | Rule repository | Name, description, MITRE mapping, severity, intent | Context for LLM interpretation |
| Entity temporal data (optional) | SIEM alert index | Top entity time series (per-entity hourly histogram) | Reveals entity-specific temporal patterns |

### Outputs

**Temporal Pattern Analysis Report**

```
===============================================================================
TEMPORAL PATTERN ANALYSIS
Rule: Lateral Movement via PsExec (siem-rule-00550)
Generated: 2026-02-16 | Analysis Period: 90 days
===============================================================================

PATTERN SUMMARY
---------------
  Primary Pattern:       Business hours, weekdays (78.4% of alerts between 08:00-18:00)
  Secondary Pattern:     Moderate weekly cycle (lower volume Wed/Thu vs Mon/Tue/Fri)
  Trend:                 Stable (no significant volume change over 90 days)
  Holiday Correlation:   Strong negative (r=-0.91 with US holidays — rule goes silent)
  Patch Tuesday Effect:  None (r=0.12, not significant)

PATTERN INTERPRETATION
----------------------
  This rule detects PsExec usage for lateral movement. The strong business-hours
  pattern indicates the detected activity is predominantly performed by humans
  during working hours. The holiday correlation confirms this — when employees are
  off, PsExec usage drops to near zero.

  The mid-week dip (Wed/Thu lower than Mon/Tue/Fri) is an unusual sub-pattern.
  Possible explanations:
    - IT deployment activities are concentrated at the start and end of the work
      week, with mid-week reserved for other tasks
    - Change management windows are Mon/Tue and Thu/Fri, with a Wed freeze
    - This is within normal variation and may not be meaningful

  Assessment: The temporal pattern is CONSISTENT with legitimate IT administrative
  PsExec usage. If this rule's intent is to detect adversary lateral movement,
  the business-hours pattern suggests it is primarily capturing authorized admin
  activity, not attacker behavior. Adversary PsExec usage would more likely occur
  during off-hours or show no business-hour correlation.

ANOMALOUS WINDOWS
-----------------
  Feb 3, 2026: 847 alerts (expected: ~120, z-score: 6.1)
    - Extreme spike, 7x expected volume
    - Already identified in UC-04 as correlated with SCCM APAC deployment
    - Temporal context: spike occurred during business hours (09:00-17:00),
      consistent with managed deployment activity, not attacker behavior

ENTITY-SPECIFIC TEMPORAL PATTERNS
----------------------------------
  When decomposed by top entities:

  admin_jpark (IT admin):
    - Pattern: Mon-Fri, 08:30-17:30, lunch break gap at 12:00-13:00
    - Assessment: Classic human work schedule. Consistent across 90 days.
    - Interpretation: Routine IT administrative activity.

  svc_deploy (service account):
    - Pattern: Fires at exactly 06:00 daily, including weekends
    - Assessment: Automated scheduled task, not human-driven.
    - Interpretation: Deployment automation running on a fixed schedule.
    - Note: This entity shows NO business-hour pattern — the business-hour
      pattern in the aggregate data is driven by other entities.

  contractor_mli (contractor):
    - Pattern: Feb 1-3 only, 10:00-22:00 (12-hour work sessions)
    - Assessment: Bursty, intensive activity over 3 days with unusually
      long work hours.
    - Interpretation: Short-term project work OR suspicious extended session.
      The 12-hour continuous blocks are unusual for legitimate contractor work.
      Cross-reference with UC-02 entity analysis — this entity was flagged
      for investigation there as well.

DETECTION ENGINEERING RECOMMENDATIONS
--------------------------------------
  1. CONSIDER adding a time-of-day severity modifier: PsExec usage during
     off-hours (22:00-06:00) on this rule should be elevated to HIGH severity,
     as legitimate admin usage is concentrated in business hours.

  2. CONSIDER creating a separate rule variant for off-hours PsExec that
     triggers immediate investigation, given that the benign baseline is
     near zero during those hours.

  3. The svc_deploy entity fires at 06:00 daily regardless of day. If this is
     a known deployment automation, exclude it (per UC-03 recommendations) to
     remove the fixed-schedule noise from the entity pool, making anomalous
     timing easier to detect in the remaining signal.

  4. The contractor_mli 12-hour sessions warrant investigation independent of
     this temporal analysis. Flag to SOC for review.
```

**Multi-Rule Temporal Correlation Report**

```
===============================================================================
CROSS-RULE TEMPORAL CORRELATION
Data Source Domain: endpoint.process (247 active rules)
===============================================================================

CORRELATED TIMING CLUSTERS
---------------------------

Cluster A: "Business Hours IT Tools" (34 rules)
  Rules that fire predominantly Mon-Fri 08:00-18:00 with holiday gaps.
  Common trait: All detect usage of legitimate IT administration tools
  (PsExec, PowerShell remoting, WMI, RDP, SCCM).
  Assessment: These rules are collectively measuring IT operational tempo,
  not adversary activity. Consider:
    - Grouping for bulk tuning reviews
    - Adding business-hours context to alert triage (lower priority in-hours)
    - Creating off-hours variants with elevated severity

Cluster B: "Daily Automation" (18 rules)
  Rules that fire at fixed times (02:00-06:00) daily including weekends.
  Common trait: All triggered by service accounts running scheduled tasks.
  Assessment: Fully automated activity. Temporal pattern is the strongest
  indicator that these are noise — they fire with clock precision.
  Recommendation: Priority tuning targets for UC-03.

Cluster C: "Patch Tuesday Surge" (8 rules)
  Rules that spike on the second Tuesday of each month and the following
  2-3 days. Common trait: All detect software installation, service
  modification, or executable creation.
  Assessment: Patch deployment activity. Expected and benign.
  Recommendation: Consider a "Patch Tuesday" suppression window that
  reduces severity for these 8 rules during the known patching window
  (second Tue-Thu of each month).

Cluster D: "No Pattern / Sporadic" (12 rules)
  Rules with no detectable temporal pattern — alerts distributed randomly
  across all hours and days.
  Assessment: These are the most likely to contain genuine threat signals.
  Sporadic timing is consistent with adversary activity (which does not
  follow business schedules) or with rare, event-driven detections.
  Recommendation: Prioritize these rules for signal quality analysis (UC-02).
  Their lack of pattern makes them harder to tune but potentially more
  valuable.
```

## Implementation Notes

- **Statistical analysis runs outside the SIEM**: STL decomposition, autocorrelation, and Fourier analysis are not native SIEM capabilities. Export alert time series data to a Python environment (Jupyter notebook, scheduled script, or data pipeline) for statistical processing. Libraries: `statsmodels` for STL, `scipy.signal` for FFT, `pandas` for time series manipulation.

- **External calendar data is simple to maintain**: A static file with dates tagged as holidays, Patch Tuesdays, quarter-ends, etc. is sufficient. Update it once per year. The US federal holiday calendar, Microsoft Patch Tuesday schedule, and fiscal quarter dates cover the majority of relevant external calendars. Organization-specific calendars (deployment windows, maintenance windows) add value if available.

- **Entity-level temporal decomposition is where the real value is**: Aggregate temporal patterns for a rule often mask entity-specific patterns. A rule that looks like it fires 24/7 might actually be two overlapping patterns: a service account firing at 02:00 and human users firing during business hours. Decompose temporal patterns by top entities whenever possible.

- **Pattern detection sensitivity tuning**: The autocorrelation threshold for declaring a "significant" periodicity needs calibration. A strict threshold (e.g., ACF > 0.7) catches only strong patterns. A lenient threshold (ACF > 0.3) catches weak patterns that may be noise. Start strict and relax as you build confidence in the analysis pipeline.

- **LLM interpretation is the lightweight component**: The statistical analysis is the heavy lifting. The LLM reads the structured statistical output and generates explanations. Prompt complexity is low compared to UC-01 through UC-04 because the input is already analyzed and structured — the AI is explaining results, not performing analysis.

- **Time zone awareness**: All temporal analysis must account for the organization's time zone(s). An alert at 02:00 UTC might be 21:00 local time (business hours on the US West Coast) or 02:00 local time (off-hours in UTC). If the organization spans multiple time zones, entity-level temporal analysis should use the entity's local time zone where possible.

## Dependencies

- SIEM alert data with timestamps (all SIEMs provide this)
- Python environment with `statsmodels`, `scipy`, `pandas` for statistical analysis
- External calendar data (holidays, Patch Tuesday, business calendar)
- Rule metadata (name, description, intent, MITRE mapping)
- LLM API access (standard context window sufficient — temporal profiles are compact)
- (Optional) Entity-level temporal data from UC-02 analysis pipeline
- (Optional) Organization time zone mapping for multi-timezone environments

## Complexity Assessment

| Dimension | Rating | Notes |
|---|---|---|
| Overall | Low-Medium | Statistical methods are well-established. LLM interpretation is straightforward. |
| Data pipeline | Low-Medium | Time series export from SIEM is trivial. Statistical processing is standard Python. External calendar is a static file. |
| Prompt engineering | Low | Input is pre-structured statistical output. The LLM explains results, not performs analysis. Less prompt complexity than UC-01 through UC-04. |
| AI integration | Low | Single LLM call per rule batch. No chaining, tool use, or retrieval. |
| Statistical analysis | Medium | STL decomposition, autocorrelation, and FFT are standard but require familiarity with time series methods. Parameter selection (seasonal period, ACF lag depth) requires some experimentation. |
| Output validation | Low-Medium | Temporal patterns are visually verifiable — plot the time series and confirm the AI's description matches the chart. Statistical metrics (periodicity strength, correlation coefficients) are deterministic and auditable. |
| Maintenance | Low | Calendar updates annually. Statistical parameters rarely need adjustment once calibrated. |

## Real-World Considerations

- **Most temporal patterns are boring**: The vast majority of rules fire during business hours because most IT activity happens during business hours. The AI should not over-explain obvious patterns. The high-value findings are the exceptions — rules that fire off-hours, rules with shifting patterns, rules with holiday correlations that do not match the rule's intent.

- **Adversary timing analysis is speculative**: Claiming that a pattern "matches adversary work hours in UTC+3" is an observation, not a conclusion. Many legitimate activities also follow business-hour patterns in various time zones (offshore development teams, global vendor support). The AI should present temporal alignment with external time zones as a data point for investigation, not as an attribution.

- **Scheduled task drift is real and common**: Windows Task Scheduler tasks configured with "start at 02:00 with up to 30-minute random delay" produce a slowly shifting pattern as the random delay accumulates. This appears as gradual peak shift in the time series. It is almost always benign but can cause a rule to drift into a different operational window over months.

- **Temporal patterns change with organizational changes**: A company that acquires a division in a different time zone will see immediate changes in temporal patterns for identity and access rules. Office relocations, shift-work changes, and remote-work policies all affect when activity occurs. The AI should be provided with organizational context if available.

- **Low-volume rules have noisy temporal patterns**: A rule with 5 alerts in 30 days does not have a meaningful temporal pattern — any distribution analysis on 5 data points is noise. Set a minimum volume threshold (e.g., 50+ alerts in the analysis window) before performing temporal analysis. Below that threshold, simply report "insufficient data for temporal analysis."

- **The "no pattern" finding is itself a finding**: Rules with truly random temporal distributions (no business-hour pattern, no weekly cycle, no periodicity) are worth noting. In an enterprise environment, most activity is structured. A rule that fires with no temporal structure may be detecting external-driven activity (attack scans, internet noise) or genuinely anomalous behavior that does not follow organizational rhythms.

## Related Use Cases

- **UC-01 (Detection Performance Analytics)**: Surfaces basic periodicity as one of many metrics; UC-05 provides deep temporal analysis.
- **UC-02 (Entity Cardinality Noise Analysis)**: Entity-level temporal decomposition combines UC-02's entity data with UC-05's temporal methods.
- **UC-04 (Detection Drift Monitoring)**: Temporal pattern shifts (e.g., a rule that moved from business hours to 24/7) are a form of drift that bridges UC-04 and UC-05.

## References

- Python statsmodels: [STL decomposition](https://www.statsmodels.org/stable/generated/statsmodels.tsa.seasonal.STL.html) — Seasonal-Trend decomposition using LOESS
- SciPy: [Signal processing (FFT)](https://docs.scipy.org/doc/scipy/reference/signal.html) — Fourier transform for periodicity detection
- Pandas: [Time series functionality](https://pandas.pydata.org/docs/user_guide/timeseries.html) — resampling, rolling windows, time zone handling
- Elastic: [Date histogram aggregation](https://www.elastic.co/guide/en/elasticsearch/reference/current/search-aggregations-bucket-datehistogram-aggregation.html)
- Splunk: [timechart command](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Timechart), [predict command](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Predict)
- Sentinel/KQL: [make-series operator](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/make-seriesoperator), [series_decompose()](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/series-decomposefunction)
- Microsoft Patch Tuesday schedule: [Security Update Guide](https://msrc.microsoft.com/update-guide/) — second Tuesday of each month
