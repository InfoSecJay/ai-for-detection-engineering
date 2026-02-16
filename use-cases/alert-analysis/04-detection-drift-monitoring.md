# UC-04: Detection Drift Monitoring

## Category

Alert Analysis

## Summary

Use an LLM to diagnose the likely cause of detection drift — rules that have gone silent, experienced significant volume shifts, or deviated from established baselines. The SIEM handles the detection of drift itself (volume time series, silence monitoring, baseline deviation) through deterministic statistical analysis. The AI reads the drift signal alongside cross-rule correlation data, data source health metrics, and rule dependency context to produce a diagnostic assessment explaining *why* drift occurred and *what to do about it*.

## Problem Statement

Detection drift is the gradual or sudden degradation of a detection rule's effectiveness. It manifests in several ways:

- **Silent rules**: A rule that was producing alerts stops firing entirely. Is the threat gone, the data source broken, or the rule logic invalidated by a schema change?
- **Volume spikes**: A rule's alert volume suddenly increases 5x. Is this a real attack campaign, a configuration change that broadened the rule's match criteria, or a new noise source?
- **Volume decay**: Alert volume gradually decreases over weeks. Is the threat landscape shifting, the population of monitored entities shrinking, or is a data pipeline intermittently dropping events?
- **Entity profile shift**: The rule still fires at the same volume, but the entities triggering it have changed completely. The "who" or "what" changed even though the "how much" did not.

In an environment with 4,000+ rules, drift happens constantly. Rules go silent because data sources change field names in an update. Volume spikes because a new tool is deployed. Gradual decay occurs because a log source is slowly being migrated to a new format. Without proactive monitoring, drift is only discovered when an incident reveals a rule was blind — the worst possible time to find out.

The detection of drift is straightforward: compare current metrics to a baseline and flag deviations beyond a threshold. Any SIEM can do this. The diagnosis of drift is the hard problem. When a rule goes silent, the analyst must investigate: Is the underlying data source healthy? Are peer rules on the same data source also silent? Did the data schema change? Was there an infrastructure change? This investigation is time-consuming and requires cross-referencing multiple data points — exactly what an LLM is good at when given the right context.

## Prerequisites (What Your SIEM/SOAR Should Already Handle)

- **Volume baseline per rule**: A rolling average (30-day or 90-day) of daily alert volume for each rule. This is a scheduled aggregation query stored in a metrics index. Any SIEM can compute this.
  ```
  // Elastic example — daily volume per rule
  POST /alerts-*/_search
  {
    "size": 0,
    "query": { "range": { "@timestamp": { "gte": "now-30d" } } },
    "aggs": {
      "by_rule": {
        "terms": { "field": "rule.id", "size": 5000 },
        "aggs": {
          "daily": {
            "date_histogram": { "field": "@timestamp", "calendar_interval": "day" },
            "aggs": { "count": { "value_count": { "field": "_id" } } }
          }
        }
      }
    }
  }
  ```
- **Silence detection**: Rules with zero alerts over a configurable window (e.g., 7 days) where the rule was previously active (had alerts in the prior 30 days). This is a comparison of current and historical volume — trivially computable.
- **Baseline deviation flags**: Rules whose current daily average deviates beyond a threshold (e.g., +/- 50% from 30-day baseline, or > 2 standard deviations). This is basic statistical analysis.
- **Data source health monitoring**: Event counts per index or data source over the same time windows. If the `winlogbeat-*` index is receiving 0 events, every rule depending on it will be silent — and the diagnosis is obvious. The SIEM should surface this independently of rule-level analysis.
- **Peer rule grouping**: Rules should be tagged or classifiable by their primary data source (e.g., all rules querying `endpoint.process` events, all rules querying `network.dns` events). This allows cross-referencing — if one DNS rule goes silent, check all DNS rules.

## Where AI Adds Value

### 1. Cross-Rule Correlation for Drift Diagnosis

When a rule goes silent, the AI checks its peer group:

- Are other rules on the same data source also silent? If yes, the problem is the data source, not the rule.
- Are only rules matching a specific field silent? Perhaps a field was renamed or its values changed format.
- Did a specific subset of rules (e.g., all rules using `process.command_line` with a regex) go silent while rules using `process.name` on the same data source are fine? Likely a field-level issue.

This cross-referencing is technically possible with SIEM queries, but in practice it requires an analyst to manually form and test hypotheses across rule groups. The AI can evaluate multiple hypotheses simultaneously given the right data.

### 2. Data Source Dependency Analysis

The AI maps each drifting rule to its data source dependencies and checks their health:

"Rule `siem-rule-00887` (DNS Tunneling via High Entropy Subdomain) has been silent for 12 days. This rule queries the `dns` data source. Data source health check: the `packetbeat-*` index is receiving DNS events at normal volume (14M events/day). However, the specific field `dns.question.subdomain` has zero values in the last 12 days — the field `dns.question.name` now contains the full FQDN without subdomain extraction. Likely cause: Packetbeat version upgrade on Feb 4th changed field mapping."

### 3. Infrastructure Change Correlation

If change management data is available (even as a text summary), the AI can correlate drift timing with known changes:

"Volume spike on rules `siem-rule-00421` through `siem-rule-00435` (all endpoint.process rules) began Feb 3rd. Change log entry for Feb 3rd: 'Deployed CrowdStrike Falcon sensor to 2,400 workstations in APAC region.' The volume increase is proportional to the expanded sensor deployment. This is expected growth, not anomalous drift."

### 4. Diagnostic Prioritization

Not all drift is equally urgent. The AI assesses severity:

- Silent rule on an active data source with MITRE coverage for a critical technique = **Critical** — you have a detection gap.
- Volume spike on a low-severity informational rule = **Low** — monitor but no immediate action.
- Gradual volume decay on a rule that still fires above a useful threshold = **Medium** — investigate at next review cycle.

### 5. Remediation Guidance

Beyond diagnosis, the AI suggests next steps:

"Diagnosis: Field rename in Packetbeat upgrade. Remediation: Update rule query to reference `dns.question.registered_domain` instead of `dns.question.subdomain`. Verify field exists in current mapping with `GET packetbeat-*/_mapping/field/dns.question.registered_domain`. Update all 23 DNS rules that reference the deprecated field."

## AI Approach

**Method**: LLM prompting with cross-rule correlation data.

### Prompt Architecture

1. **System prompt**: Detection engineering context. Rule portfolio size. Data source domain taxonomy. Diagnostic framework (data source issue > field-level issue > rule logic issue > legitimate volume change).

2. **Drift signal block**: The specific drift event(s) being diagnosed:
```json
{
  "drift_events": [
    {
      "rule_id": "siem-rule-00887",
      "rule_name": "DNS Tunneling via High Entropy Subdomain",
      "drift_type": "silence",
      "last_alert_date": "2026-02-04",
      "days_silent": 12,
      "baseline_daily_avg": 23.4,
      "baseline_period": "30d",
      "data_source_domain": "network.dns",
      "mitre_technique": "T1071.004",
      "severity": "high"
    }
  ]
}
```

3. **Cross-rule context block**: Status of peer rules on the same data source:
```json
{
  "peer_rules_same_datasource": [
    {
      "rule_id": "siem-rule-00881",
      "rule_name": "DNS Query to Known Malicious Domain",
      "status": "active",
      "volume_30d": 342,
      "fields_used": ["dns.question.name"]
    },
    {
      "rule_id": "siem-rule-00884",
      "rule_name": "Excessive DNS Queries to Single Domain",
      "status": "active",
      "volume_30d": 1205,
      "fields_used": ["dns.question.name", "source.ip"]
    },
    {
      "rule_id": "siem-rule-00889",
      "rule_name": "DNS Query with Encoded Subdomain",
      "status": "silent_since_feb04",
      "volume_30d": 0,
      "baseline_daily_avg": 8.7,
      "fields_used": ["dns.question.subdomain"]
    }
  ]
}
```

4. **Data source health block**: Index-level and field-level health metrics:
```json
{
  "data_source_health": {
    "index_pattern": "packetbeat-*",
    "event_volume_30d": 420000000,
    "daily_avg": 14000000,
    "trend": "stable",
    "field_health": {
      "dns.question.name": { "non_null_pct": 99.8, "status": "healthy" },
      "dns.question.subdomain": { "non_null_pct": 0.0, "last_non_null": "2026-02-04", "status": "MISSING" },
      "dns.question.registered_domain": { "non_null_pct": 99.8, "first_seen": "2026-02-04", "status": "NEW" }
    }
  }
}
```

5. **Change log context** (if available):
```json
{
  "recent_changes": [
    {
      "date": "2026-02-04",
      "description": "Upgraded Packetbeat from 8.11 to 8.14 across all DNS sensors",
      "systems_affected": ["dns-sensor-01", "dns-sensor-02", "dns-sensor-03"]
    }
  ]
}
```

6. **Task instruction**: "Diagnose the drift event(s). For each, provide: (a) most likely root cause, (b) confidence level, (c) supporting evidence from peer rules and data source health, (d) severity assessment, (e) recommended remediation steps."

## Data Requirements

### Inputs

| Data Element | Source | Computation | Notes |
|---|---|---|---|
| Volume baseline per rule | Pre-computed metrics | 30-day rolling daily average | Stored in metrics index, updated daily |
| Current volume per rule | SIEM alert index | Count over current window | Compared to baseline |
| Silence flag | Derived | Rules with 0 alerts where baseline > 0 | Simple comparison |
| Deviation magnitude | Derived | `(current_daily_avg - baseline_daily_avg) / baseline_daily_avg` | Percentage change from baseline |
| Peer rule status | Pre-computed metrics | Volume + drift flags for rules sharing same data source domain | Grouped by data source tag |
| Data source event volume | SIEM index stats | Event count per source index over same time windows | Index-level health |
| Field-level health | SIEM index mapping + stats | Non-null percentage per field, first/last seen dates | Detects field renames, disappearances |
| Rule-to-data-source mapping | Rule repository | Which index/data source each rule queries | May be derivable from rule query |
| Rule-to-field mapping | Rule repository or query parsing | Which fields each rule references | Enables field-level drift correlation |
| Change management log | ITSM system (if available) | Recent infrastructure changes with dates and descriptions | Optional but high-value for correlation |
| Entity profile baseline | Pre-computed metrics | Historical top-N entities per rule | Detects entity profile shift |

### Outputs

**Drift Diagnostic Report**

```
===============================================================================
DRIFT DIAGNOSTIC REPORT
Generated: 2026-02-16 | Analysis Period: 30 days
===============================================================================

CRITICAL DRIFT EVENTS (2)
===============================================================================

--- EVENT 1: Rule Cluster Silence — DNS Subdomain Rules ---

  Affected Rules:
    - siem-rule-00887: DNS Tunneling via High Entropy Subdomain (SILENT 12 days)
    - siem-rule-00889: DNS Query with Encoded Subdomain (SILENT 12 days)
    - siem-rule-00892: Subdomain Length Anomaly (SILENT 12 days)

  Severity:          CRITICAL
  Confidence:        HIGH (95%)
  MITRE Coverage Gap: T1071.004 (Application Layer Protocol: DNS)

  Diagnosis:
    All three silent rules share a common dependency: the field
    `dns.question.subdomain`. This field has been absent (0% non-null) since
    Feb 4th. Peer rules on the same data source that use `dns.question.name`
    instead (siem-rule-00881, siem-rule-00884) continue to fire normally. The
    underlying index (packetbeat-*) is receiving DNS events at normal volume
    (14M events/day).

  Root Cause:
    Packetbeat upgrade from 8.11 to 8.14 on Feb 4th changed DNS field mappings.
    The field `dns.question.subdomain` has been replaced by a decomposition into
    `dns.question.registered_domain` and `dns.question.top_level_domain`. The
    subdomain component is now embedded in `dns.question.name` but no longer
    extracted as a separate field.

  Evidence:
    1. All silent rules reference `dns.question.subdomain` — no other field
    2. Field health: `dns.question.subdomain` non-null rate dropped from 99.8%
       to 0.0% on exactly Feb 4th
    3. New field `dns.question.registered_domain` appeared on Feb 4th (99.8%
       non-null)
    4. Change log entry: Packetbeat 8.11 → 8.14 upgrade on Feb 4th
    5. Peer rules using `dns.question.name` are unaffected

  Remediation:
    1. IMMEDIATE: Rewrite 3 affected rules to derive subdomain from
       `dns.question.name` minus `dns.question.registered_domain`
       Example KQL:
         let subdomain = replace_regex(dns_question_name,
           strcat("\\.", registered_domain, "$"), "");
    2. VALIDATE: Test rewritten rules against last 12 days of DNS events to
       verify they would have fired
    3. PREVENT: Add field-level health monitoring to CI/CD pipeline —
       alert when rule-referenced fields disappear from the index mapping
    4. REVIEW: Check Packetbeat 8.14 changelog for other field changes that
       may affect remaining DNS rules

  Estimated Fix Effort: 2-3 hours (rewrite 3 rules + validation)

--- EVENT 2: Volume Spike — Endpoint Process Rules ---

  Affected Rules:
    - siem-rule-00421: Suspicious PowerShell Encoded Command (+300%, 12,847 alerts)
    - siem-rule-00089: PowerShell Download Cradle (+180%, 4,230 alerts)
    - siem-rule-00415: Encoded PowerShell via WMI (+250%, 8,100 alerts)
    - siem-rule-00310: Process Execution from Temp Directory (+90%, 2,400 alerts)
    (+ 10 additional endpoint.process rules with >50% volume increase)

  Severity:          MEDIUM
  Confidence:        HIGH (90%)

  Diagnosis:
    14 endpoint.process rules experienced simultaneous volume increases beginning
    Feb 3rd. The increases are not uniform — they range from +50% to +300% —
    but all share timing alignment. Entity analysis reveals the volume increase
    is driven by two service accounts (svc_sccm, svc_intune) that were already
    present as noise sources but whose activity scaled up.

  Root Cause:
    Infrastructure change on Feb 3rd: SCCM software deployment push to APAC
    region (2,400 workstations). The management tools execute encoded PowerShell,
    download payloads from internal repositories, and create temporary executables
    — all of which match multiple detection rules. The activity is legitimate but
    was not accompanied by pre-deployment tuning.

  Evidence:
    1. All 14 rules share `endpoint.process` data source domain
    2. svc_sccm and svc_intune account for 85-95% of volume increase across rules
    3. Spike timing aligns with change log: "SCCM deployment to APAC" on Feb 3rd
    4. New hosts in alerts match APAC asset inventory naming convention (AP-WS-*)
    5. No new users or unexpected entities appeared — same service accounts,
       increased scale

  Remediation:
    1. Apply tuning recommendations from UC-03 for the top 5 rules by volume
       (estimated 80% total reduction across affected rules)
    2. Establish a pre-deployment notification process: when large-scale
       deployments are planned, detection engineering is notified to pre-apply
       temporary tuning or expected-volume adjustments
    3. Consider a deployment-aware suppression mechanism: a watchlist of
       "active deployment windows" that temporarily raises alert thresholds
       for management-tool rules during planned deployments

  Estimated Fix Effort: 4-6 hours (tuning) + process improvement (ongoing)

===============================================================================
MEDIUM DRIFT EVENTS (3)
===============================================================================

  1. siem-rule-01201 — "Kerberos Golden Ticket Indicators"
     Drift: Gradual volume decay (-65% over 60 days, from 45/day to 16/day)
     Likely Cause: Domain controller log forwarding degradation — 2 of 5 DCs
     showing reduced event volume. Not a rule logic issue.
     Action: Investigate DC log forwarding pipeline.

  2. siem-rule-00550 — "Lateral Movement via PsExec"
     Drift: Entity profile shift — same volume, but source IPs changed completely
     Previous top IPs: 10.1.50.x range (IT admin subnet)
     Current top IPs: 10.4.200.x range (unknown subnet)
     Action: INVESTIGATE — entity profile shift with unknown source may indicate
     actual lateral movement or unauthorized PsExec usage from new network segment.

  3. siem-rule-00773 — "Outbound Connection to Rare External IP"
     Drift: Volume spike +120% (from 200/day to 440/day)
     Likely Cause: New SaaS application onboarded — connections to previously
     unseen IPs are "rare" by definition. Will normalize as the baseline adapts.
     Action: Monitor. Consider adding SaaS provider IP ranges to allow list.

===============================================================================
LOW DRIFT EVENTS (8)
===============================================================================
  [Summarized — minor deviations within expected variation, no action required]
```

## Implementation Notes

- **Drift detection cadence**: Run the baseline comparison daily. Most drift is identified within 1-3 days of onset. For silence detection specifically, a 48-hour silence window on a previously active rule is a reasonable trigger — some rules legitimately fire sporadically, so a 7-day window reduces false positives.

- **Field-level health monitoring is high-value and underutilized**: Most SIEM deployments monitor index-level health (is the index receiving events?) but not field-level health (are specific fields populated?). A field that silently becomes null breaks any rule referencing it. Implement field-level monitoring by sampling index mappings and non-null percentages on a schedule. This is a SIEM/pipeline problem, not an AI problem — but it provides critical data for AI diagnosis.

- **Peer rule grouping requires a taxonomy**: For cross-rule correlation to work, every rule must be tagged with its data source domain. If your rule repository does not have this metadata, deriving it from rule queries is the first step. This can itself be an AI task (parsing rule queries to identify target indices and key fields), but it is a one-time classification effort, not an ongoing analysis.

- **Change log integration is the highest-leverage enhancement**: The difference between "3 DNS rules went silent for unknown reasons" and "3 DNS rules went silent because of the Packetbeat upgrade on Feb 4th" is the change log. Even a simple text feed of recent changes (from ServiceNow, Jira, or a shared document) dramatically improves diagnostic accuracy. The AI does not need structured change data — it can reason over free-text change descriptions.

- **Entity profile shift is the subtlest drift type**: Volume-based drift is obvious. Entity profile shift — same volume, different entities — is invisible to volume monitoring. Detecting it requires comparing current top-N entity distributions to historical baselines. This is a more complex SIEM query but is essential for catching scenarios where a rule's meaning changes even though its numbers look stable.

- **False positive management**: Not every baseline deviation is meaningful. A rule that averages 5 alerts/day and produces 12 one day is technically a +140% spike, but it is within normal variation for a low-volume rule. Set minimum volume thresholds before flagging drift. A useful heuristic: only flag rules with baseline > 10 alerts/day for percentage-based deviation; for lower-volume rules, use absolute thresholds (e.g., flag if daily count > baseline + 3*stddev).

## Dependencies

- Pre-computed volume baselines per rule (daily aggregation stored in metrics index)
- Data source health monitoring (index-level and field-level)
- Rule-to-data-source mapping (from rule repository or derived from queries)
- Peer rule grouping by data source domain
- LLM API access (standard context window sufficient per diagnostic batch)
- (Optional) Change management log integration
- (Optional) Entity profile baselines for entity shift detection

## Complexity Assessment

| Dimension | Rating | Notes |
|---|---|---|
| Overall | Medium | Drift detection is deterministic. Drift diagnosis via AI is the value-add. |
| Data pipeline | Medium-High | Requires volume baselines, data source health, field-level monitoring, peer rule grouping, and optionally change log integration. More data sources than UC-01 through UC-03. |
| Prompt engineering | Medium | The diagnostic framework (data source > field > rule logic > legitimate change) must be conveyed clearly. Cross-rule context adds prompt size but not complexity. |
| AI integration | Low-Medium | Single LLM call per diagnostic batch. No chaining or tool use. Output is narrative with structured fields. |
| Output validation | Medium | Diagnoses should be validated by checking the identified root cause. Remediation steps should be reviewed before implementation. |
| Maintenance | Medium | Baselines need recomputation as environment evolves. Peer rule groupings need updating as rules are added/removed. Field-level monitoring must track index mapping changes. |

## Real-World Considerations

- **Drift is normal and constant**: In a 4,000-rule environment, expect 5-15 drift events per week. Most are benign (infrastructure changes, data source updates, legitimate volume fluctuation). The AI's job is to rapidly triage and diagnose, reducing the analyst's investigation time from 30-60 minutes per event to a 2-minute review of the diagnostic report.

- **Silent rules are the highest-priority drift**: A noisy rule is annoying. A silent rule is dangerous. Silent rules mean detection gaps — threats in the rule's coverage area are undetected. Prioritize silence investigation over volume-spike investigation in every case.

- **Schema changes are the #1 cause of silent rules**: In practice, the most common reason rules go silent is a data source schema change — field renames, value format changes, or field deprecation. This happens during agent upgrades (Beats, Sysmon, CrowdStrike, etc.), SIEM platform updates, and log pipeline reconfigurations. Field-level monitoring catches this quickly; without it, silent rules can persist for months.

- **The "expected silence" problem**: Some rules legitimately fire rarely — a rule detecting a specific exploit may only fire during active exploitation campaigns. These rules will be flagged as "silent" by drift monitoring but require no action. Maintain a list of rules with expected low/zero volume (e.g., honeypot rules, specific exploit detections) to suppress false positive drift alerts.

- **Post-tuning drift monitoring**: After applying tuning from UC-03, monitor the tuned rule for 7-14 days to verify the tuning behaved as expected. The AI diagnostic should check: Did volume decrease to the projected level? Did any unexpected entities start dominating the post-tuning signal? Did the residual signal maintain expected entity diversity?

## Related Use Cases

- **UC-01 (Detection Performance Analytics)**: Provides the baseline metrics that drift monitoring compares against.
- **UC-02 (Entity Cardinality Noise Analysis)**: Entity profile shift detection requires the entity baselines established in UC-02.
- **UC-03 (Automated Rule Tuning Recommendations)**: Post-tuning monitoring is a specific drift monitoring scenario.
- **UC-05 (Temporal Pattern Detection)**: Some drift manifests as temporal pattern changes — a rule that used to fire business hours only now fires 24/7 — which bridges UC-04 and UC-05.

## References

- Elastic: [Machine learning anomaly detection](https://www.elastic.co/guide/en/machine-learning/current/ml-ad-overview.html), [Index monitoring](https://www.elastic.co/guide/en/elasticsearch/reference/current/index-modules-stats.html)
- Splunk: [Anomaly detection commands](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Anomalydetection), [Data model acceleration](https://docs.splunk.com/Documentation/Splunk/latest/Knowledge/Aboutdatamodels)
- Sentinel: [Analytics rule health monitoring](https://learn.microsoft.com/en-us/azure/sentinel/monitor-analytics-rule-integrity), [Data connector health](https://learn.microsoft.com/en-us/azure/sentinel/monitor-data-connector-health)
- MITRE ATT&CK: Detection coverage mapping — understanding which techniques lose coverage when rules drift
- Elastic: [ECS field reference](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) — for understanding field mapping changes across versions
