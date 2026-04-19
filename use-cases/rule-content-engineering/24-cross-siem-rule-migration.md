# UC-24: Cross-SIEM Rule Migration & Semantic Translation

## Category

Rule Content Engineering

## Summary

Migrates an existing detection rule corpus from one SIEM platform to another by combining semantic embedding search against the target platform's prebuilt rule library with LLM-based translation of the unmatched residual. Distinct from from-scratch rule generation (UC-19) — this is bulk corpus migration anchored on existing native content, with the AI's job being to *avoid* re-translating rules that already exist on the target. Distinct from mechanical syntax conversion (pySigma) — this is intent-aware translation that handles macros, lookups, and platform-specific semantics that static converters cannot.

## Problem Statement

SIEM migration is one of the largest and most under-discussed projects in detection engineering. A migration from Splunk to Sentinel, ArcSight to Chronicle, or QRadar to Elastic typically involves:

- 2,000–10,000 detection rules in the source SIEM
- A target platform that ships with its own native rule library (Sentinel: ~1,200 analytics rules; Elastic: 1,300+ prebuilt detections; Chronicle: hundreds of YARA-L curated rules)
- Subtle semantic differences between query languages (SPL pipes vs. KQL operators vs. ES|QL vs. YARA-L) that mechanical converters mishandle
- Platform-specific abstractions (Splunk macros, Elastic exception lists, Sentinel watchlists, Chronicle data tables) that don't translate one-to-one
- A team that does not have 18 person-months to rewrite each rule by hand

Done badly, migration produces a few thousand mechanically-translated queries that nobody trusts, all firing 10× the expected volume because nuances were lost. Done well, migration leverages the target platform's existing curated content for everything possible and only translates the genuinely-unique organizational rules.

The deterministic part — converting `eval x = case(...)` to `case(condition_a, value_a, ...)` — is rule conversion as pySigma already does it. The hard, AI-shaped part is two-fold:

1. **Semantic deduplication against the target's library**: "We have a rule called `T1059.001 — Suspicious PowerShell Encoded Command`. Sentinel ships `Suspicious PowerShell Activity Detected` and `PowerShell Empire Cmdlets`. Are any of these semantically equivalent? Should we adopt the native rule and retire ours, port ours alongside, or merge?"
2. **Intent-aware translation of the residual**: For rules with no native equivalent, generate the target query with awareness of macros, lookups, schema differences (CIM vs. ECS vs. ASIM), and platform-specific operators that mechanical converters miss.

## Prerequisites (What Your SIEM/SOAR Should Already Handle)

- **Source rule corpus accessible programmatically.** Splunk REST API for searches, savedsearches.conf, ES app content; Elastic Detection Rules API; Sentinel ARM templates or Analytics Rules API; QRadar AQL Rule API; ArcSight CCE rule export. If you cannot enumerate your source rules via API, fix that first — this is a tooling problem, not an AI problem.
- **Target platform's prebuilt rule library accessible programmatically.** Sentinel's GitHub Analytics Rules repo, Elastic's `elastic/detection-rules` repo, Chronicle's curated YARA-L library, Splunk's ESCU. Required for the embedding-based dedup pass.
- **Target platform's data source mapping.** What target data sources / connectors / parsers correspond to your source SIEM's data? `windows:security:eventlog` (Splunk) maps to `windows.security.*` (ECS) maps to `SecurityEvent` (ASIM). This is a normalized-schema mapping problem the SIEM ingest team owns, not the AI.
- **Macro / lookup / abstraction inventory.** A list of every macro, lookup, watchlist, or named function used by your source rules. The AI cannot translate `\`my_critical_assets\`` correctly without knowing what it expands to.
- **A staging / validation environment in the target SIEM.** Migrated rules must be deployed to staging, fired against historical data (UC-26), and validated before they reach production. Migration is not "translate then ship."

## Where AI Adds Value

### 1. Semantic Deduplication Against the Target's Native Library

Embed every source rule and every target-platform native rule into the same vector space. For each source rule, retrieve the top-K nearest target rules. An LLM then judges whether each candidate is a semantic match, a partial match (covers some but not all observables), or unrelated. Output: a per-source-rule decision — adopt native, port custom, merge, or retire.

This is the single highest-value step. A 4,000-rule corpus often deduplicates to 1,500–2,500 unique rules requiring custom translation; the rest are covered by the target's native library. Skipping this step means re-translating content the target already ships, which is pure waste.

### 2. Intent-Aware Translation Beyond Syntax

For the residual, the LLM translates the source query into the target language with awareness of:

- **Schema mapping** — ECS `process.command_line` ↔ CIM `process` ↔ ASIM `Process.CommandLine`
- **Macro expansion** — replace Splunk macros with their definitions before translation, or carry them across as named functions where the target supports them
- **Lookup table conversion** — Splunk lookups → Sentinel watchlists / Elastic value lists / Chronicle data tables
- **Operator semantics** — Splunk `| stats count by user host` is *not* the same as KQL `| summarize count() by user, host` if `count` is computed differently in window-aware contexts
- **Time-window semantics** — `earliest=-24h` vs. `| where TimeGenerated > ago(24h)` vs. `| WHERE @timestamp > NOW() - 24 HOURS`
- **Building-block / correlation idioms** — Splunk's notable-then-correlation-search pattern vs. Sentinel's analytic-rule-then-incident pattern vs. Elastic's building-block-rule pattern (see [correlation rule catalog](../../correlation-rules/correlation-rule-catalog.md))

### 3. Translation Validation and Self-Correction

Every translated query is run through the target SIEM's parser (deterministic) and against a sample dataset (deterministic). If the target rejects the syntax or the rule fires at unexpected volume, an LLM self-correction loop (capped at N retries) refines the query. Elastic has shipped exactly this pattern for ES|QL; the principle generalizes.

### 4. Translation Auditability

The output is not just a translated query — it's a translation record: source query, semantic-match candidates considered and rejected, translation decisions, schema mappings applied, validation results. Auditable migration is what separates a successful project from a 12-month forensic dig of why production alerts dropped 40%.

## AI Approach

**Hybrid pipeline: embeddings + LLM + deterministic validation.**

1. **Embedding pass (deterministic)**: Embed source rules and target-library rules using a security-domain embedding model (or any general embedding model — quality differences are modest). Compute cosine similarity. Retain top-10 candidates per source rule.

2. **Semantic deduplication (LLM)**: For each source rule and its top-10 candidates, the LLM produces a decision:
   - `adopt_native` — target's rule covers this; retire source
   - `port_custom_alongside` — keep ours because we add organizational specificity (e.g., asset criticality logic)
   - `merge` — adopt target rule + port specific exception logic
   - `port_custom_only` — no semantic equivalent; full translation required

3. **Translation pass (LLM)**: For `port_custom_*` rules, the LLM generates the target query using the source query, the source rule's metadata, and the target schema mapping as input.

4. **Validation pass (deterministic + LLM)**:
   - Submit to target SIEM's parser → reject if syntax invalid
   - Run against sample data → measure fire rate
   - If fire rate is >5× source baseline → LLM refinement pass
   - If parser rejection or 5+ refinement loops → escalate to human

5. **Audit record (deterministic)**: Every decision and translation is logged with full provenance.

## Data Requirements

### Inputs

| Input | Format | Key Fields Used |
|---|---|---|
| Source rule corpus | Platform-native (SPL .conf, KQL ARM, EQL TOML, AQL XML) | Rule body, name, description, MITRE tags, severity, data source, exceptions |
| Target platform's prebuilt rule library | Platform-native (Sentinel ARM/YAML, Elastic TOML, Chronicle YARA-L) | Same as above |
| Macro / lookup inventory | Source-platform metadata | Macro name, expansion, lookup table contents |
| Schema mapping (source → target) | YAML/JSON config | Field-by-field mapping with type information |
| Sample dataset for validation | Target SIEM index | Recent telemetry from migrated data sources |
| Embedding model | Hosted or self-hosted | Used for similarity computation only |

> **Note:** Alert data follows the SIEM's standard alert schema with normalized source event fields. Rule files follow their format's defined schema (Elastic TOML, Sigma YAML, Splunk YAML, etc.). These are structured, documented formats — see [data-requirements/](../../data-requirements/) for platform-specific field references.

### Outputs

**Per-rule migration decision record (one per source rule):**

```json
{
  "source_rule_id": "splunk-saved-search-00421",
  "source_rule_name": "T1059.001 - Suspicious PowerShell Encoded Command",
  "decision": "merge",
  "decision_rationale": "Target Sentinel rule 'PowerShell Empire Cmdlets' covers process-name and command-line patterns we detect, but our rule includes asset-criticality-aware severity scaling using a custom lookup. Recommend adopting native rule, porting our severity logic as a Sentinel watchlist, and adding a custom rule extension for the asset weighting.",
  "candidates_considered": [
    {"target_rule_id": "Sentinel/PowerShellEmpireCmdlets", "similarity": 0.91, "decision": "primary_match"},
    {"target_rule_id": "Sentinel/SuspiciousPowerShellActivity", "similarity": 0.84, "decision": "partial_overlap"},
    {"target_rule_id": "Sentinel/EncodedPowerShellCommand", "similarity": 0.79, "decision": "narrower_scope"}
  ],
  "translated_artifact": {
    "type": "watchlist + analytic_rule_extension",
    "target_query": "...",
    "schema_mappings_applied": [
      {"source_field": "user", "target_field": "TargetUserName"},
      {"source_field": "host", "target_field": "Computer"},
      {"source_field": "CommandLine", "target_field": "ProcessCommandLine"}
    ],
    "macros_resolved": [
      {"macro": "$$critical_assets$$", "expansion": "asset_tier IN ('crown_jewel', 'tier_0')"}
    ]
  },
  "validation": {
    "parser_status": "valid",
    "fire_rate_24h_sample": {"source_baseline": 47, "target_observed": 51, "delta_pct": 8.5},
    "refinement_iterations": 0,
    "human_review_required": false
  }
}
```

**Migration project dashboard:**

```
============================================================================
MIGRATION: Splunk Enterprise Security → Microsoft Sentinel
Generated: 2026-04-18
============================================================================

Total source rules:                 4,217
  ├─ adopt_native:                  1,683 (39.9%) — covered by Sentinel library
  ├─ merge:                           421 (10.0%) — adopt + port custom logic
  ├─ port_custom_alongside:         1,109 (26.3%) — keep ours, add native too
  ├─ port_custom_only:                834 (19.8%) — no native equivalent
  └─ retire:                          170 ( 4.0%) — duplicate / deprecated

Translation pipeline status:
  ├─ Translated successfully:       2,108
  ├─ Validation passed (auto):      1,892
  ├─ Validation passed (1 refine):    176
  ├─ Validation passed (2-5 refine):   40
  └─ Escalated to human:                0  (none yet)

Effort saved:
  Without dedup:    4,217 rules × 2h avg = 8,434 person-hours
  With dedup:       2,364 rules × 2h avg = 4,728 person-hours
  Savings:          ~3,706 person-hours (44%)
```

## Implementation Notes

- **Run dedup first, translation second.** Translating 4,000 rules and *then* discovering that 1,700 had native equivalents is the most expensive mistake possible. The embedding pass costs almost nothing relative to LLM translation.
- **Use a domain-tuned embedding model where possible.** Generic embeddings work, but security-specific models reduce false-positive matches between rules that share generic vocabulary (e.g., "suspicious," "outbound," "exfiltration") but detect different things.
- **Cap LLM self-correction loops.** Three is a reasonable default. Escalate to human after that. Without a cap, rare malformed source rules drive runaway loops and runaway costs.
- **Validate fire rates against historical data, not synthetic.** If the source rule fired 100×/day in production, the translated rule should fire approximately 100×/day on the same time window of historical telemetry replayed into the target. A 10× delta is a problem; a 0.5× delta may be a legitimate environmental difference but warrants review.
- **Schema mapping is the silent killer.** Most translation failures trace to schema-mapping errors that the LLM made plausibly but incorrectly. Build a canonical mapping document and pass it as constrained context — do not let the model invent mappings.
- **Macro expansion before translation.** Resolve all macros to literal expressions before the LLM sees the query. Otherwise the model treats the macro name as an unknown function and either skips or fabricates its meaning.
- **Migrate exceptions and watchlists alongside rules.** A rule without its exception list will produce an alert flood on day one. Exception lists are first-class migration artifacts.
- **Cutover strategy is operational, not technical.** Big-bang cutover is risky. Recommend running source and target in parallel for 30+ days, comparing alert volumes per rule per day, and reconciling differences before disabling the source.

## Dependencies

- **Prerequisite — Pillar 1 (Data Foundations)**: Target platform must already be ingesting all data sources the source rules depend on. No translation will save you from missing telemetry.
- **Prerequisite — Pillar 4 (Technology Stack)**: Both source and target platforms must expose APIs for rule enumeration and deployment.
- [UC-17: Rule Comparison & Gap Analysis](17-rule-comparison-and-gap-analysis.md) — Provides the semantic comparison foundation. UC-24 is essentially UC-17 applied at corpus scale across SIEMs.
- [UC-19: Detection Rule Generation](19-detection-rule-generation.md) — For source rules with no native equivalent, the translation step shares prompt engineering with rule generation.
- [UC-26: Continuous Detection Validation](26-continuous-detection-validation.md) — Migrated rules must be validated via Atomic Red Team or equivalent before production cutover.

## Complexity Assessment

| Dimension | Rating | Notes |
|---|---|---|
| Data engineering | High | Requires programmatic access to source corpus, target library, schema mappings, macro/lookup inventory, validation telemetry. Often blocked on source-side API access. |
| AI/ML complexity | Medium-High | Embedding similarity + multi-stage LLM prompting + self-correction. No fine-tuning required, but pipeline orchestration is non-trivial. |
| Integration effort | High | Touches source SIEM, target SIEM, version control, validation environment, ticketing for human escalations. Multi-team project. |
| Overall | **High** | Most-shipped vendor capability of 2026 for a reason — high ROI, but only on a project with the prerequisite tooling in place. |

## Real-World Considerations

- **Migration is a project, not a feature.** Even with strong AI tooling, expect 6–12 months for a large migration. The AI accelerates translation; it does not eliminate the need for SOC analysts to validate that the new platform fires on real attacks the way the old one did.
- **Native library coverage varies by domain.** Sentinel's library is strong on cloud and identity, weaker on legacy on-prem. Elastic's library is strong on endpoint and cloud, growing on identity. Chronicle's curated YARA-L library is narrower but high-quality. Expect different `adopt_native` rates across rule categories.
- **Translation quality varies by source language.** Splunk SPL → KQL is well-traveled (Microsoft, Uncoder, multiple papers). KQL → ES|QL and SPL → ES|QL are newer territory. ArcSight CCL and IBM AQL → anything-modern are the hardest because the source languages have many platform-specific quirks.
- **Don't migrate dead rules.** Use UC-04 (Drift Monitoring) or simple silence detection on the source corpus to identify rules that haven't fired in 90+ days. These are usually candidates for `retire`, not migration. Migration is an opportunity to clean house.
- **Adversaries notice migration windows.** Periods of dual-running and validation are operational risk windows. Have explicit incident-response coverage for the migration period — the SOC must know which rules are authoritative on which date.
- **MITRE ATT&CK v18 schema differences.** v18's Detection Strategies + Analytics replace the legacy Detections + Data Sources schema (see UC-06 update). Migrating rules also presents the opportunity to re-tag against v18 — bundle the schema migration with the platform migration where possible.
- **Vendor-native versions exist for some pairs.** Microsoft Sentinel's AI-Powered SIEM Migration (Splunk, QRadar → Sentinel) and Elastic's Automatic Migration (Splunk → Elastic) and SOC Prime Uncoder AI v2 (10+ source / 21+ target) are commercial implementations of this use case. Build-vs-buy depends on direction (vendor-supported pairs cheaper to buy) and whether you need cross-vendor neutrality.

## Related Use Cases

- [UC-17: Rule Comparison & Gap Analysis](17-rule-comparison-and-gap-analysis.md) — Foundational semantic comparison capability scaled here to corpus level
- [UC-19: Detection Rule Generation](19-detection-rule-generation.md) — Translation step shares prompting techniques with rule generation
- [UC-26: Continuous Detection Validation](26-continuous-detection-validation.md) — Validates migrated rules against simulated attacks before production
- [UC-31: Detection Content Provenance](31-detection-content-provenance.md) — Migration is a major rule-authorship-attribution event; signing/provenance applies
- [UC-04: Detection Drift Monitoring](../alert-analysis/04-detection-drift-monitoring.md) — Identifies dead source rules to retire rather than migrate
- [UC-06: MITRE ATT&CK Posture Scoring](../posture-assessment/06-mitre-attack-posture-scoring.md) — Use migration as opportunity to re-tag for ATT&CK v18 schema

## References

- Microsoft, [AI-Powered SIEM Migration Experience (Splunk + QRadar → Sentinel)](https://techcommunity.microsoft.com/blog/microsoftsentinelblog/accelerate-your-move-to-microsoft-sentinel-with-the-new-ai-powered-siem-migratio/4488505) — Reference vendor implementation, 2026
- Elastic, [Automatic Migration with AI Rule Translation](https://www.elastic.co/blog/automatic-migration-ai-rule-translation) — Splunk → Elastic with ELSER semantic search + GenAI translation
- SOC Prime, [Uncoder AI Hybrid Rule Translation](https://socprime.com/blog/uncoder-ai-automates-cross-language-rule-translation-with-hybrid-ai/) — 10+ source / 21+ target languages, intent-aware translation
- Microsoft Security Blog, [CTI-REALM: Benchmark for Detection Rule Generation with AI Agents](https://www.microsoft.com/en-us/security/blog/2026/03/20/cti-realm-a-new-benchmark-for-end-to-end-detection-rule-generation-with-ai-agents/) — Public eval methodology applicable to translation quality
- arXiv, [RulePilot — LLM Agent for Cross-Platform Rule Writing and Conversion](https://arxiv.org/html/2511.12224)
- pySigma, [SigmaHQ/pySigma](https://github.com/SigmaHQ/pySigma) — Deterministic Sigma → backend converter; floor that any AI translation must beat
- Elastic Common Schema, [ECS Reference](https://www.elastic.co/guide/en/ecs/current/index.html)
- Microsoft Sentinel, [ASIM Schema Reference](https://learn.microsoft.com/en-us/azure/sentinel/normalization)
- Splunk CIM, [Common Information Model Documentation](https://docs.splunk.com/Documentation/CIM/latest/User/Overview)
