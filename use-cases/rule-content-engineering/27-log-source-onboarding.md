# UC-27: AI-Driven Log Source Onboarding & Parser Generation

## Category

Rule Content Engineering

## Summary

Accelerates the onboarding of new log sources by using an LLM to read vendor documentation and sample log lines, then generate ingest pipeline configs (Elastic ingest pipelines, Splunk Technology Add-ons, Sentinel ASIM parsers, Chronicle parsers), suggest ECS/CIM/ASIM field mappings, validate parsing against additional samples, and surface field-population gaps that would degrade downstream detection rule firing. Includes pipeline-side anomaly detection for rogue data sources, format drift, and rising error rates. Detection coverage cannot exist without telemetry — this use case removes the data-engineering bottleneck that holds back every other use case in the catalog.

## Problem Statement

Detection engineering teams routinely wait weeks to months for new log sources to be ingested. The bottleneck is rarely the SIEM's capacity to ingest — it's the human time required to:

- Read vendor documentation and identify the relevant log shape (often poorly documented)
- Write a parser that extracts every field correctly across log variants
- Map extracted fields to the platform's normalized schema (ECS, CIM, ASIM)
- Test against representative sample data, including edge cases the vendor docs don't mention
- Coordinate with the SIEM platform team for deployment
- Monitor post-deployment for parser regressions and format drift

A typical mid-size environment has 50–200 log sources. A typical large environment has 200–1,000+. Each source requires bespoke onboarding work. Adding a single new SaaS application can take 2–6 weeks of effort that has nothing to do with writing detection rules — but without it, detection coverage for that application is zero.

The deterministic part — *running* a parser, *applying* a regex, *validating* a JSON schema — is exactly what SIEM platforms do. The AI-shaped parts are: (a) reading vendor documentation and sample logs to draft a parser, (b) reasoning about which extracted fields map to which normalized fields (and why), (c) detecting field-shape changes over time that suggest format drift, and (d) flagging downstream detection rules that would silently break when a parser changes.

This use case is about removing the data-engineering bottleneck that holds back the *rest* of the catalog. Detection rules cannot detect on data that isn't ingested. Posture scoring cannot score techniques whose telemetry is missing. Triage verdicts cannot reason over context that isn't present.

## Prerequisites (What Your SIEM/SOAR Should Already Handle)

- **Programmatic ingest pipeline configuration.** Your SIEM platform must allow ingest pipelines to be defined as code (Elastic ingest pipelines as JSON; Splunk TAs as conf files; Sentinel ASIM parsers as KQL functions; Chronicle parsers as parser files). If your platform requires GUI clicking, you cannot AI-generate ingest config.
- **Sample log access.** Either via vendor-provided sandboxes, on-call retrieval from the source system, or a deliberate "logging tap" environment that captures samples without putting them in production. The AI cannot generate parsers for log shapes it has never seen.
- **Schema mapping documentation.** ECS, CIM, ASIM specifications are public; your environment's adopted schema is your source of truth. The AI must know which schema to target.
- **A staging ingest environment.** Parsers must be tested against representative data before production deployment. If you have to deploy parsers directly to production to test them, fix that first.
- **Field-population monitoring.** Per-source, per-field, percentage of events with that field populated. This is what drift detection observes. Standard SIEM data-quality capability.
- **Detection rule dependency map.** Which rules depend on which fields from which sources? Without this, you cannot warn DEs that a parser change will break their rules. This is metadata that your detection-as-code pipeline should already maintain.

## Where AI Adds Value

### 1. Parser Generation from Documentation + Samples

Given vendor documentation (URL or text) and 50–500 sample log lines, the AI generates an ingest pipeline configuration in the target platform's format. For Elastic, an ingest pipeline JSON. For Splunk, a `props.conf` + `transforms.conf` pair plus a `tags.conf` for CIM tagging. For Sentinel, a parser KQL function. For Chronicle, a parser config.

The output handles the common cases: structured JSON logs, key-value logs, multiline logs, custom delimited formats, syslog wrappers around vendor payloads. It also handles the harder cases: nested JSON with vendor-specific shapes, mixed-format logs (header + JSON body), log lines that vary by event type within the same source.

### 2. Schema Mapping with Justification

For each extracted field, the AI proposes the normalized field mapping with reasoning:

- `auth.actor.uid` → ECS `user.name` (vendor calls this "actor uid" but it's the username field)
- `client.geo.country` → ECS `source.geo.country_name`
- `request.path` → ECS `url.path`

Critical: the AI should *explicitly flag* fields that don't have a clean normalized mapping rather than inventing one. A field with no good ECS home should be carried under the vendor namespace (`vendor.original_field_name`) and flagged for human review.

### 3. Field-Population Validation

After deployment, the AI consumes per-field population rates and flags:

- Fields the documentation describes but that are absent from real logs (vendor doc lies)
- Fields the documentation omits but that appear in real logs (undocumented additions)
- Fields whose population rate drops below a baseline threshold (drift)
- Fields whose value distribution shifts significantly (cardinality shift, type change)

These are early-warning signals. A drop in `process.command_line` population from 99% to 60% means downstream detection rules are silently degrading.

### 4. Downstream Rule Impact Analysis

Before deploying a parser change to production, the AI cross-references the change against the detection rule dependency map and reports: "This parser change renames `event_action` to `event.action` (ECS-aligned). 47 detection rules currently reference `event_action`. They will silently fail to match after deployment unless updated."

### 5. Rogue Data Source Detection

Pipeline-side anomaly detection: when a new source IP or new event_dataset value appears at the ingest layer that doesn't match an authorized source, flag it. This is mostly deterministic, but the AI judges whether the new source is a misnamed-but-legitimate source vs. a true unauthorized source by reasoning about the data shape and origin.

### 6. Cost Estimation Pre-Ingest

Given a sample, the AI estimates ingest volume and storage cost in your SIEM. Pairs with [UC-29](29-siem-cost-data-tiering.md). Helps the architecture review decide tiering before the firehose is opened.

## AI Approach

**Multi-stage LLM with deterministic validation gates.**

1. **Documentation + sample analysis (LLM)** — LLM reads vendor docs and 50–500 sample log lines. Identifies log shape, event types, key fields.

2. **Parser draft (LLM with platform-specific prompts)** — Generate the ingest config in the target platform's format. System prompt includes the platform's parser conventions and example pipelines.

3. **Parser validation (deterministic)** — Submit to the platform's parser engine. If the parser rejects, retry with error feedback (capped retries).

4. **Sample re-parse (deterministic)** — Apply the parser to a fresh sample (held out from the draft input). Measure field extraction completeness and correctness.

5. **Schema mapping (LLM)** — For each extracted field, propose normalized mapping with justification. Flag low-confidence mappings.

6. **Downstream impact (deterministic + LLM)** — Cross-reference proposed changes against detection rule dependency map. LLM summarizes what would break.

7. **Production monitoring (deterministic + LLM)** — Continuous field-population monitoring. LLM produces narratives when drift is detected.

## Data Requirements

### Inputs

| Input | Format | Key Fields Used |
|---|---|---|
| Vendor documentation | URL or PDF or HTML | Log format spec, field definitions, event taxonomy |
| Sample log lines | Plain text or JSON | 50–500 representative samples spanning event types |
| Target platform | Configuration | Elastic / Splunk / Sentinel / Chronicle / etc. |
| Normalized schema spec | YAML / JSON | ECS / CIM / ASIM / custom |
| Existing parsers (for reference) | Platform-native | Pattern library to draw conventions from |
| Detection rule dependency map | YAML / JSON | `rule_id` → `[fields_referenced]` |
| Per-field population baseline | Time series | Per-source, per-field, daily population rates |
| Authorized source inventory | YAML / JSON | List of authorized source IPs, hostnames, dataset values |

### Outputs

**Generated Elastic ingest pipeline (example for a SaaS app — Looker logs):**

```json
{
  "description": "Looker audit log parser — generated UC-27 2026-04-18, validated 99.2% field extraction across 500 samples",
  "processors": [
    {
      "json": {
        "field": "message",
        "target_field": "looker"
      }
    },
    {
      "rename": {
        "field": "looker.user.email",
        "target_field": "user.email",
        "ignore_missing": true
      }
    },
    {
      "rename": {
        "field": "looker.action",
        "target_field": "event.action",
        "ignore_missing": true
      }
    },
    {
      "rename": {
        "field": "looker.outcome",
        "target_field": "event.outcome",
        "ignore_missing": true
      }
    },
    {
      "set": {
        "field": "event.module",
        "value": "looker"
      }
    },
    {
      "set": {
        "field": "event.dataset",
        "value": "looker.audit"
      }
    },
    {
      "geoip": {
        "field": "looker.client_ip",
        "target_field": "source.geo",
        "ignore_missing": true
      }
    }
  ],
  "_uc27_metadata": {
    "generated": "2026-04-18T14:32:00Z",
    "vendor_doc_url": "https://cloud.google.com/looker/docs/admin-panel-events",
    "samples_analyzed": 500,
    "field_extraction_rate": 0.992,
    "schema_mapping_confidence": "high",
    "review_required_fields": ["looker.dashboard.id"],
    "rationale_for_review": "looker.dashboard.id has no clean ECS mapping; carried under vendor namespace pending human decision"
  }
}
```

**Schema mapping report:**

```
=============================================================================
LOG SOURCE ONBOARDING: Looker Audit Logs
Generated: 2026-04-18 | Target: Elastic ECS
=============================================================================

Fields extracted (12 of 12 documented fields):
  Confident mappings (high confidence):
    looker.user.email           → user.email
    looker.action               → event.action
    looker.outcome              → event.outcome
    looker.client_ip            → source.ip + source.geo (geoip enrichment)
    looker.user.role            → user.roles[]
    looker.timestamp            → @timestamp
    looker.session_id           → session.id

  Confident mappings (medium confidence):
    looker.user.id              → user.id (also matches `user.uid` — preferred user.id per ECS guidance)

  Flagged for human review:
    looker.dashboard.id         → vendor namespace (no clean ECS mapping)
    looker.query.text           → vendor namespace (could be url.query but Looker query syntax differs)
    looker.permission_set       → vendor namespace (potentially user.roles[] but Looker permission_set has different semantics)

  No mapping (vendor-specific business logic):
    looker.workspace.id         → vendor namespace

Validation against held-out sample (250 events):
  Parsing success rate:         99.6% (1 malformed JSON sample)
  Field extraction completeness: 99.2%
  Geo enrichment success:       100%

Downstream detection rule impact:
  No existing rules depend on Looker fields (new source)
  Coverage opportunity: 14 of 47 SaaS-targeting rules in catalog could use this source
```

**Drift alert (post-production):**

```
=============================================================================
INGEST DRIFT DETECTED: Okta System Logs
Date: 2026-04-18 (compared to 30-day baseline)
=============================================================================

Field population changes:
  user.name:                97.4% → 91.2%  (-6.2pp)  ← significant
  authentication.factor:    100%  → 100%   (no change)
  source.geo.country_name:  98.1% → 97.9%  (no change)

Diagnosis (LLM-generated):
  user.name population dropped 6.2pp on 2026-04-15. Two possible causes:
  (a) Okta released a new event_type ("policy.evaluated") on 2026-04-14 that does
      not include user.name in its payload (verified in vendor docs).
      → 4.8pp of the drop is attributable to this new event type.
  (b) An additional 1.4pp drop is unexplained. Recommend investigating
      whether a parser regression affected user.name extraction for an
      existing event type.

Affected detection rules (downstream):
  - okta-impossible-travel (depends on user.name) — currently functional but
    will silently miss events where user.name is null.
  - okta-mfa-fatigue (depends on user.name) — same.

Recommended action:
  1. Update parser to extract actor.alternateId as fallback for user.name
     when primary field is null on policy.evaluated events.
  2. Investigate the 1.4pp residual drop separately.
```

## Implementation Notes

- **Test against held-out samples.** The samples used to draft the parser must be different from the samples used to validate it. Otherwise you measure overfitting, not parser quality.
- **Vendor documentation lies.** Common patterns: documented fields that aren't in real logs, undocumented fields that are, type mismatches (doc says int, actual is string), enum values not in the docs. The validation pass against real samples is the ground truth, not the docs.
- **Chunk vendor docs for long sources.** Some vendor docs are 100+ pages. Identify the relevant subsection (using a relevance pass) before passing to the parser-generation prompt.
- **Don't ship parsers without a human merge.** Generated parsers are starting points. Production deployment requires human review of the schema mapping decisions and the validation report. Use the PR-with-tests pattern from Panther's AI Detection Builder.
- **Use prompt caching for system prompts.** Each onboarding has a stable system prompt (platform-specific parser conventions, schema spec) and a variable user prompt (vendor docs + samples). Cache the system prompt for cost efficiency.
- **Map drift detection to the rule dependency map.** Field-population drift is interesting on its own but actionable when joined with "this drift breaks N rules." Always present drift alerts with downstream impact.
- **Acknowledge that this overlaps with vendor capabilities.** SentinelOne's Observo AI integration filters/enriches/normalizes upstream of the SIEM. Microsoft Sentinel's AI Migration Experience auto-recommends connectors. Axoflow ships AI-classified ingest pipelines. For most environments, vendor-native is the cheaper path; this use case applies for environments needing portable / multi-platform / self-hosted parser generation.

## Dependencies

- **Prerequisite — Pillar 1 (Data Foundations)**: This use case *is* the Pillar 1 acceleration story. But you must already have the underlying capability to deploy parsers as code.
- **Prerequisite — Pillar 4 (Technology Stack)**: Programmatic ingest pipeline configuration (Elastic Fleet, Splunk Cloud REST, Sentinel API, etc.).
- [UC-04: Detection Drift Monitoring](../alert-analysis/04-detection-drift-monitoring.md) — Drift in field population is a leading indicator of detection drift.
- [UC-29: SIEM Cost & Data Tiering Optimization](29-siem-cost-data-tiering.md) — Cost estimation pre-ingest pairs with tiering decisions.
- [UC-26: Continuous Detection Validation](26-continuous-detection-validation.md) — A parser change is a great moment to re-validate downstream rules.

## Complexity Assessment

| Dimension | Rating | Notes |
|---|---|---|
| Data engineering | Medium-High | Parser generation across 4+ platform formats with field-mapping rigor is substantial. Validation pipeline against held-out samples requires careful test data management. |
| AI/ML complexity | Medium | LLM prompting with structured outputs. Drift detection blends statistical baselines with LLM diagnosis. No fine-tuning. |
| Integration effort | Medium-High | Requires CI integration with the SIEM's parser deployment pipeline, dependency map maintenance, and field-population monitoring. |
| Overall | **Medium-High** | High operational value (unblocks every other use case), but substantial up-front investment per platform. |

## Real-World Considerations

- **Onboarding speed is a strategic capability, not a tactical one.** A SOC that can onboard a new source in 2 days is fundamentally different from one that takes 2 months. Detection coverage *is* time-to-onboard. This use case targets that lever directly.
- **The AI-generated parser is a draft, not a deployable artifact.** Schema mapping decisions encode opinions (what is "user.name" for this source — the email? the SAM account? the SaaS user UUID?). Humans must review.
- **Field-population monitoring is the under-appreciated half.** Onboarding correctly is necessary but not sufficient — parsers degrade silently as vendors evolve their log formats. The drift detection capability is at least as valuable as the initial parser generation.
- **Some sources defy generation.** Highly proprietary log formats with no documentation, formats that change every release, formats that mix structured and unstructured payloads in unpredictable ways — these need manual parsing. Recognize this and don't waste cycles forcing AI on hard cases.
- **Privacy implications at the ingest layer.** Logs may contain credentials, session tokens, PII. The redaction patterns from [privacy-and-data-handling.md](../../docs/privacy-and-data-handling.md) apply at the ingest pipeline, not just at the LLM-call layer. The parser is the last opportunity to redact before data hits the index.
- **Vendor-side vs. SIEM-side ingest.** Some vendors (Cribl, Edge Delta, Axoflow, Observo) intercept logs *before* the SIEM and offer parsing/filtering/routing. Others (Sentinel data lake, Splunk Federated) route data based on tier. The AI-driven onboarding capability has to know where in the pipeline it operates.

## Related Use Cases

- [UC-04: Detection Drift Monitoring](../alert-analysis/04-detection-drift-monitoring.md) — Drift in field population is the upstream cause of drift in detection.
- [UC-29: SIEM Cost & Data Tiering Optimization](29-siem-cost-data-tiering.md) — Onboarding decisions are tiering decisions.
- [UC-26: Continuous Detection Validation](26-continuous-detection-validation.md) — Validates that parser changes don't silently break detection.
- [UC-24: Cross-SIEM Rule Migration](24-cross-siem-rule-migration.md) — Migration projects often require parallel onboarding of the same sources to the new platform.
- [UC-06: MITRE ATT&CK Posture Scoring](../posture-assessment/06-mitre-attack-posture-scoring.md) — Telemetry availability is the floor under all posture scoring; new sources unlock new technique coverage.

## References

- Elastic, [Ingest Pipelines Reference](https://www.elastic.co/guide/en/elasticsearch/reference/current/ingest.html)
- Elastic, [Common Schema (ECS) Reference](https://www.elastic.co/guide/en/ecs/current/index.html)
- Splunk, [Common Information Model (CIM)](https://docs.splunk.com/Documentation/CIM/latest/User/Overview)
- Splunk, [Add-On Builder](https://docs.splunk.com/Documentation/AddonBuilder/latest/UserGuide/Overview)
- Microsoft, [ASIM Schema Reference](https://learn.microsoft.com/en-us/azure/sentinel/normalization)
- Google Chronicle, [Parser Reference](https://cloud.google.com/chronicle/docs/data-ingestion-flow)
- SentinelOne / Observo AI, [Singularity AI SIEM Pipeline](https://www.sentinelone.com/press/sentinelone-unveils-new-ai-security-offerings/)
- Axoflow, [How Axoflow Really Uses AI](https://axoflow.com/how-axoflow-really-uses-ai) — AI-classified ingest pipeline reference
- Bronto, [Log Parsing with AI](https://www.bronto.io/blog/log-parsing-with-ai)
- Cribl, [Cribl Stream Documentation](https://docs.cribl.io/) — Vendor-side ingest routing
- Microsoft Sentinel, [AI-Powered SIEM Migration with Connector Recommendations](https://techcommunity.microsoft.com/blog/microsoftsentinelblog/accelerate-your-move-to-microsoft-sentinel-with-the-new-ai-powered-siem-migratio/4488505)
