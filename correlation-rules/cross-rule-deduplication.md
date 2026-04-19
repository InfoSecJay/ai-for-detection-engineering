# Cross-Rule Deduplication Guidance

The 55-rule [correlation rule catalog](correlation-rule-catalog.md) is intentionally layered. A single entity can trigger Tier 1, Tier 2, Tier 3, and Tier 6 rules simultaneously and that is **correct behavior** — each tier evaluates a different question. But every downstream consumer (analysts, AI triage tools UC-11/UC-12/UC-14, ticketing systems) must decide how to merge or prioritize those overlapping fires. This document is the spec for that.

---

## Why Overlap Happens by Design

The tiers ask different questions:

- **Tier 1 (entity-centric)**: "Is this user/host/IP active across multiple domains?"
- **Tier 2 (kill chain)**: "Is this entity progressing through attack stages?"
- **Tier 3 (risk accumulation)**: "Has this entity accumulated enough risk to warrant attention?"
- **Tier 4 (meta-correlation)**: "Are multiple entities exhibiting coordinated behavior?"
- **Tier 5 (domain-specific)**: "Is this a known cross-domain attack chain?"
- **Tier 6 (novelty/anomaly)**: "Is this behavior new for this entity?"

A real intrusion will affirmatively answer several of these at once. Suppressing the overlap by design (e.g., "if Tier 3 fires, suppress Tier 1") loses information. The correct pattern is **emit all fires, deduplicate downstream**.

---

## Expected Overlap Patterns

These overlaps are the most common and should be treated as a single incident downstream, not multiple.

| Pattern | Description | Recommended Treatment |
|---|---|---|
| **Entity Activity Burst** | CORR-1A/1B + CORR-3A on the same entity in the same window | One incident; CORR-3A's risk score is the headline; CORR-1A's domain breakdown is supporting evidence |
| **Kill Chain with Risk** | CORR-2A + CORR-3A on the same entity | One incident; CORR-2A's tactic progression is the headline; CORR-3A's score is severity scaling |
| **Novel Risky Behavior** | CORR-6A + CORR-3A on the same entity | One incident; CORR-6A's novelty drives investigation priority; CORR-3A scales severity |
| **Domain Chain with Risk** | CORR-5A–5O + CORR-3A on the same entity | One incident; CORR-5x's specific chain (e.g., phishing→endpoint) is the headline |
| **Campaign Across Entities** | CORR-4A + multiple Tier 1/3 fires for different entities sharing an IOC | One *campaign-level* incident; per-entity Tier 1/3 fires become children |
| **Coordinated Activity** | CORR-4B + multiple Tier 2 fires across entities | One coordinated-activity incident; per-entity Tier 2 fires become children |

When you see these in production, downstream tools should consolidate, not enumerate.

---

## Deduplication Algorithm

The recommended dedup pattern is **time-windowed entity grouping with tier priority**:

```
INPUT: Stream of correlation rule fires from CORR-1A through CORR-6J
OUTPUT: Consolidated incident clusters

For each fire:
  1. Extract (entity_type, entity_value, fire_timestamp, tier, rule_id, severity)
  2. Lookup any open cluster matching (entity_type, entity_value) within last 4 hours
  3. If a cluster exists:
       - Append this fire to the cluster
       - Recompute cluster headline rule (highest-tier rule wins; ties broken by severity)
       - Recompute cluster severity (max of constituent severities, capped by tier weighting)
  4. If no cluster exists:
       - Create a new cluster keyed by (entity_type, entity_value, window_start)
       - Set headline to this fire
  5. If this fire is a Tier 4 meta-correlation:
       - Look for child clusters whose entities appear in this fire's affected_entities
       - Mark those clusters as children of this Tier 4 cluster (campaign / coordination)
```

**Window**: 4 hours by default. Aligns with the lookback used by most Tier 1/2/5 rules. Tune longer (8h–24h) for slow-moving threats; shorter (1h) for high-velocity environments.

**Entity key**: Use the typed entity key (`entity_type + entity_value`) emitted by Tier 4/6 rules. For Tier 1/2/3/5 rules that emit a single entity field, derive the type from the rule's join key (e.g., CORR-1A → `user`, CORR-1B → `host`). This prevents the COALESCE namespace collision called out in the [catalog](correlation-rule-catalog.md).

---

## Tier Priority for Headline Selection

When multiple rules fire on the same entity in the same window, the **headline** (the rule that frames the incident in the analyst's queue) is selected by tier priority. The remaining fires become **supporting evidence**, displayed but not duplicated.

| Priority | Tier(s) | Why |
|---|---|---|
| 1 (highest) | Tier 4 — Meta-correlation | Campaign / coordinated activity overrides per-entity stories |
| 2 | Tier 5 — Domain-specific chain | Specific known-bad chains carry the most actionable signal |
| 3 | Tier 2 — Kill chain progression | Multi-stage progression is more actionable than entity activity alone |
| 4 | Tier 6 — Novelty | Novel behavior demands explanation; pairs well with another tier |
| 5 | Tier 3 — Risk accumulation | Risk score is best as severity scaling, not the headline |
| 6 (lowest) | Tier 1 — Entity-centric | Useful as supporting evidence; rarely the right headline alone |

**Severity scaling**: When Tier 3 fires alongside any other tier, use Tier 3's risk score to **scale** the headline rule's severity, not to replace it. A CORR-2A (kill chain progression) headline with a CORR-3A risk score of 180 → escalate severity to critical even if CORR-2A alone would have rated high.

---

## When NOT to Deduplicate

Some overlaps are *separate incidents* that happen to share an entity. Do not merge:

- **Same entity, different time windows** (gap >4h or your tuned window): two distinct incidents
- **CORR-4F (cross-tenant correlation)** with single-tenant fires: keep CORR-4F as a tenancy-spanning incident, but per-tenant fires remain individually visible to per-tenant analysts
- **CORR-6A (novel rule firing)** when the novel rule itself is unrelated to other firing rules: the novelty is its own observation, even if the entity is concurrently elsewhere
- **CORR-4D (alert surge by rule)**: this is a rule-health observation, not an entity observation — keep it on the rule-tuning queue, not the analyst queue

---

## Consumption by AI Use Cases

The dedup output feeds three AI use cases. Each consumes the consolidated cluster differently.

### UC-11 (LLM Triage Verdicts)

**Input**: One cluster per analyst-facing item. Pass:
- The headline rule's name, description, severity, MITRE mapping
- All supporting fires (rule names, severities, timestamps) as a list
- The entity (typed) and its enrichment (CMDB, identity, asset criticality)
- The shared field values across fires (hosts, IPs, processes, hashes)

**Do not** pass each fire as a separate triage item. The model will produce N inconsistent verdicts.

### UC-12 (Alert Cluster Narrative Synthesis)

**Input**: The full cluster, including all fires, as a structured record. UC-12 specifically narrates *across* fires; deduplication should preserve, not collapse, the per-fire detail. Pass:
- Cluster ID, window, primary entity
- Ordered list of fires (rule, timestamp, tactic, severity, supporting fields)
- Tier 4 parent reference if this cluster is a child of a campaign

UC-12's job is to tell the story; dedup gives it the chapter list.

### UC-14 (Agentic Investigation)

**Input**: One investigation per cluster, with the cluster's headline and supporting fires as the starting context. The agent then pivots into deterministic enrichment and SIEM queries. Tool-call budgets should be set per cluster, not per fire.

---

## Implementation Reference

A reference implementation lives outside this catalog (it depends on your stream-processing platform — Kafka Streams, Flink, Logstash, Lambda, etc.). The minimum viable implementation is a 50-line stateful aggregator keyed on `(entity_type, entity_value, window_bucket)`.

**Pseudocode reference**:

```python
# Pseudocode — adapt to your stream processor
WINDOW_HOURS = 4

def cluster_fires(fires):
    clusters = {}
    for fire in sorted(fires, key=lambda f: f.timestamp):
        key = (fire.entity_type, fire.entity_value, bucket(fire.timestamp, WINDOW_HOURS))
        if key in clusters:
            clusters[key].append(fire)
        else:
            clusters[key] = [fire]
    return [build_cluster(fires) for fires in clusters.values()]

def build_cluster(fires):
    headline = max(fires, key=lambda f: (TIER_PRIORITY[f.tier], SEVERITY_RANK[f.severity]))
    risk_scaling = max((f.risk_score for f in fires if f.tier == 3), default=None)
    severity = scale_severity(headline.severity, risk_scaling)
    return Cluster(
        id=hash((headline.entity_type, headline.entity_value, headline.window_start)),
        headline=headline,
        supporting=[f for f in fires if f != headline],
        severity=severity,
        entities={(f.entity_type, f.entity_value) for f in fires},
    )
```

---

## Open Questions

These are deliberately not answered here because they're environment-specific:

1. **Cross-entity merging**: When CORR-1A fires for a user AND CORR-1B fires for the same user's primary host, should those be one cluster or two? Answer depends on the strength of your identity-host binding (see [identity-resolution-pattern.md](identity-resolution-pattern.md)).
2. **Tier 4 child window**: How far back should a CORR-4A campaign fire look for matching child Tier 1/3 clusters? 24h is a reasonable default; longer for slow campaigns.
3. **Suppression after-action**: Should a closed cluster suppress new fires on the same entity for a cool-down period? Recommend no — suppression hides re-attack — but flag re-fires within 24h as "recurrence" in the analyst UI.

Document your local answers in your operations runbook, not here.

## Vendor Implementations (2026)

Cross-rule deduplication is increasingly a built-in capability rather than an exercise the SOC team writes from scratch. Reference implementations:

- **Microsoft Sentinel graph (preview, 2026)** — graph-based entity correlation across alerts, with shared-entity grouping built in. Pairs with Sentinel MCP for agentic consumption.
- **Microsoft Defender XDR Incident clustering** — automatic correlation of related alerts into incidents, with the Sentinel-into-Defender consolidation (deadline July 1, 2026) making this the default for unified deployments.
- **Splunk Risk-Based Alerting (RBA)** — the original two-layer pattern (risk index + Risk Notable) effectively performs cross-rule consolidation by entity risk score.
- **Elastic Attack Discovery** — produces named "threat scenarios" that bundle multiple alerts into a single narrative, conceptually similar to the cluster output here.
- **Anvilogic Threat Scenarios** — visual cross-SIEM correlation with cluster-level outputs.

If your environment uses one of these natively, the cross-rule dedup spec here is the *contract* between the correlation rule layer and the AI consumer layer (UC-11/UC-12/UC-14). The implementation can be either custom (per the algorithm above) or vendor-native — what matters is that downstream AI consumers receive consolidated clusters, not raw fires.

---

## Validation

Before deploying dedup logic to production:

1. **Replay 30 days of historical fires** through the algorithm. Compare cluster count to fire count — expect a 3–10× reduction depending on your environment.
2. **Sample 50 clusters** and have a senior DE confirm the headline selection makes sense.
3. **Check Tier 4 parenting**: ensure campaign-level clusters correctly absorb their constituent per-entity clusters.
4. **Stress-test**: simulate a realistic intrusion chain (red-team replay or Caldera scenario) — confirm the resulting cluster contains all relevant fires with correct headline and severity.

If any of those fail, fix the dedup logic before exposing it to UC-11/UC-12/UC-14.
