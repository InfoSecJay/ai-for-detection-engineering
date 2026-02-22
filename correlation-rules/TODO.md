# Correlation Rules - TODO

Remaining work items for the 55-rule ES|QL correlation rule catalog.

---

## Open Items

### 1. Domain Categorization Standardization

~10 rules use abbreviated or non-standard `domain_category` CASE patterns (missing `proxy`, `dns`, `email` categories, or using merged categories like `"web_network"`). The full 8-domain pattern from the catalog conventions should be applied consistently.

**Affected rules**: Primarily Tier 5 domain-specific rules and select Tier 2/6 rules with simplified domain patterns.

**Canonical domains**: `endpoint`, `identity`, `cloud`, `network_fw`, `network_ndr`, `proxy`, `dns`, `email` (planned additions: `vpn`, `waf`, `dlp`).

### 2. Cross-Rule Deduplication Guidance

When multiple correlation rules fire for the same entity in the same time window, downstream consumers (analysts, AI triage tools) need deduplication guidance. Requires a dedicated catalog section covering:

- Expected overlap between tiers (e.g., a user triggering CORR-1A + CORR-2B + CORR-3A simultaneously is correct behavior, not a bug)
- How AI tools (UC-11, UC-12) should deduplicate and merge correlated clusters
- Priority ordering when the same entity has alerts from multiple tiers

### 3. CORR-5K Container Dataset Filters

CORR-5K (Container Escape Chain) has incorrect `event.dataset` filters for container-based detections. Needs review and correction of dataset patterns for container runtime environments (Docker, Kubernetes, containerd).

### 4. CORR-6I Transform Typed Entity Key

The CORR-6I Elasticsearch Transform uses COALESCE-style Painless logic (`u != null ? u : h`) to produce a single `entity` field. Should be updated to emit both `entity_type` and `entity_value` fields to align with the typed entity key pattern used in all other Tier 4/6 ES|QL rules.

### 5. Catalog Consolidation into Single Document

The 55 individual rule files and the master catalog (`correlation-rule-catalog.md`) contain overlapping content. Evaluate whether to consolidate into a single authoritative document or maintain the current split structure with cross-references.

---

## Known Limitations (Documented, No Fix Available)

- **CORR-6C Timezone Handling**: ES|QL lacks timezone conversion functions. Off-hours detection uses UTC-based hour extraction. Guidance for single-timezone, multi-timezone, and large enterprise deployments is documented in the rule file.
- **CORR-3D Z-Score Window**: Peer group deviation uses weekly average baseline compared against a 24-hour measurement window. The statistical comparison is valid but the time windows differ.

---

## Completed (Reference)

All P0/P1/P2 audit findings have been remediated:

- Tactic/technique field paths standardized across 19 files
- LOOKUP JOIN key mismatches fixed across 23 files
- `Esql.correlation_severity` standardized across 33 files
- `Esql.total_risk_score` standardized across 25 files
- Comma-separated IN operator bugs fixed in CORR-6B, 6H
- Entity resolution implemented across 16 rules (Pattern A dual-track for Tier 3, Pattern B typed entity key for Tiers 4/6)
- Optional LOOKUP JOIN enrichment added to all 18 Tier 1-2 rules
- CORR-6I redesigned as Transform + `new_terms` architecture
- CORR-1H service account patterns expanded
- Documentation accuracy fixes across ~8 files
- Unreachable severity branches cleaned up
