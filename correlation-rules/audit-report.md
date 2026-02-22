# Correlation Rule Catalog - Audit Report

**Date**: 2026-02-21
**Scope**: All 55 ES|QL correlation rules vs. 3 framework documents
**Audited by**: 7 parallel analysis agents (1 framework analyzer + 6 tier auditors)

---

## Executive Summary

The 55-rule correlation rule catalog was audited against the Correlation Rule Framework, Domain-Aware Entity Framework, and Catalog conventions. **~180 findings** were identified, with systemic issues affecting multiple tiers.

### Overall Grades

| Tier | Grade | Rules | Critical | High | Medium | Low |
|------|-------|-------|----------|------|--------|-----|
| Tier 1: Entity-Centric | A- | 8 | 3 | 8 | 19 | 12 |
| Tier 2: Kill Chain & Behavioral | B+ | 10 | 10 | 6 | 12 | 16 |
| Tier 3: Risk Accumulation | B+ | 5 | 3 | 6 | 8 | 6 |
| Tier 4: Meta-Correlation | B | 7 | 2 | 7 | 12 | 6 |
| Tier 5: Domain-Specific | B- | 15 | 3 | 10 | 29 | 25 |
| Tier 6: Novelty & Anomaly | B- | 10 | 8 | 10 | 13 | 7 |
| **Total** | | **55** | **31** | **49** | **93** | **72** |

---

## Top 10 Systemic Issues

### 1. Tactic Field Path Inconsistency (CRITICAL - P0)

**Affected**: 19 files across Tiers 2, 4, 5

Rules use `kibana.alert.rule.parameters.threat.tactic.name` instead of the framework-canonical `kibana.alert.rule.threat.tactic.name`. The `parameters` variant references the raw rule definition JSON, not the alert document schema. If this field is not populated in the alert index, tactic-based classification (kill chain stages, severity escalation, technique counting) is completely broken.

**Fix**: Replace `kibana.alert.rule.parameters.threat` with `kibana.alert.rule.threat` in all 19 files.

**Status**: FIXED in remediation pass.

### 2. LOOKUP JOIN Key Mismatches (CRITICAL - P0)

**Affected**: 23 files across Tiers 3-6

Multiple rules use LOOKUP JOIN with field names that don't match the catalog's lookup index schemas:
- `entity_name` vs `host.name` or `entity_value`
- `kibana.alert.rule.name` vs `rule_name`
- `user.name` vs `department`
- `destination.port` vs schema that uses `host.name`
- `Esql.tactic_combination` (post-aggregation field used as join key)

**Fix**: Add RENAME steps before LOOKUP JOINs, or align query field names with lookup schemas.

**Status**: FIXED in remediation pass.

### 3. Esql.severity vs Esql.correlation_severity (HIGH - P1)

**Affected**: 33 files (all Tiers 4-6 + catalog)

Tiers 1-3 use the framework-canonical `Esql.correlation_severity`. Tiers 4-6 use `Esql.severity`. This inconsistency breaks cross-tier field expectations for Tier 4 meta-correlation and AI integration layers.

**Fix**: Standardize all files to `Esql.correlation_severity`.

**Status**: FIXED in remediation pass.

### 4. Esql.total_risk vs Esql.total_risk_score (HIGH - P1)

**Affected**: 25 files (Tiers 2 + 5)

Tier 1 and the framework use `Esql.total_risk_score`. Tiers 2 and 5 use `Esql.total_risk`. Same cross-tier inconsistency.

**Fix**: Standardize all files to `Esql.total_risk_score`.

**Status**: FIXED in remediation pass.

### 5. Comma-Separated IN Operator Misuse (CRITICAL - P0)

**Affected**: CORR-6B, CORR-6H

Rules use `NOT field IN (lookup_keyword)` where the lookup field contains comma-separated values stored as a single string. ES|QL's IN operator doesn't parse comma-separated strings as lists. Every value appears as "new/novel" regardless of baseline.

**Fix**: Use `NOT LIKE` pattern matching or document that lookup fields must be stored as multi-valued keyword arrays.

**Status**: FIXED in remediation pass.

### 6. Domain Categorization Drift (MEDIUM - P2)

**Affected**: ~10 files with incomplete or non-standard domain CASE patterns

Some rules use abbreviated domain patterns (missing proxy, dns, email categories). Some rules create non-standard merged categories (e.g., "web_network"). The full 8-domain pattern from the catalog should be used consistently.

**Status**: Documented for future cleanup.

### 7. ~~Tier 4 Identity Crisis~~ — RESOLVED (Not an Issue)

All Tier 4 rules correctly query raw alert logs (`.internal.alerts-security.alerts-default`). This is the intended design: the framework assumes all alerts — vendor prebuilt rules, Sigma/LOLRMM imports, building block rules, and indicator alerts — are present in the alerts index. Tier 4 rules perform "meta-correlation" by analyzing patterns across the full alert population (campaigns via shared IOCs, coordinated TTP usage, alert surges, silent rule reactivation). CORR-4D and 4E specifically analyze detection system behavior. CORR-4A, 4B, 4C, 4F, and 4G analyze cross-entity alert patterns. Both are valid meta-correlation approaches.

**Status**: Confirmed correct by design. No changes needed.

### 8. Missing LOOKUP JOINs in Tiers 1-2 (LOW - P3)

**Affected**: All Tier 1 and Tier 2 rules

Despite listing `lookup-critical-assets` and `lookup-service-accounts` as optional dependencies, no Tier 1-2 rule actually uses LOOKUP JOIN. These enrichments would add asset criticality weighting and better service account handling.

**Fix**: Added optional LOOKUP JOIN blocks to all 18 Tier 1-2 rules (CORR-1A through 1G, CORR-2A through 2J). Each block uses the standard RENAME bridge pattern with clear comment delimiters for easy removal if the lookup index is unavailable. IP-based rules (1C, 1D) include notes about lookup index needing IP entries. Hash-based rule (1E) includes note about uncommon use case.

**Status**: FIXED in entity resolution pass.

### 9. Unreachable Severity Branches (LOW - P2)

**Affected**: CORR-2A, 2F, 2J, 3E, 6F + others

WHERE clause guarantees make the "medium" fallback in severity CASE statements unreachable. Not functionally harmful but indicates logic that doesn't match intent.

**Status**: FIXED where possible in remediation pass.

### 10. Documentation Accuracy (LOW - P3)

**Affected**: CORR-2B, 2D, 2F, 2J + others

Strategy sections reference "INLINE STATS" when queries use regular STATS. Strategy sections describe features (user.roles, Windows SIDs) not present in queries. Metadata lists join keys not used in GROUP BY.

**Status**: FIXED in remediation pass.

---

## Remediation Priority Table

| Priority | Issue | Files | Effort | Status |
|----------|-------|-------|--------|--------|
| P0 | Fix tactic/technique field paths | 19 | Low | FIXED |
| P0 | Fix LOOKUP JOIN key mismatches | 23 | Medium | FIXED |
| P0 | Fix comma-separated IN operator | 2 | Low | FIXED |
| P1 | Standardize Esql.correlation_severity | 33 | Low | FIXED |
| P1 | Standardize Esql.total_risk_score | 25 | Low | FIXED |
| P2 | Fix unreachable severity branches | ~6 | Low | FIXED |
| P2 | Fix documentation accuracy | ~8 | Low | FIXED |
| P2 | Standardize domain categorization | ~10 | Medium | Deferred |
| P3 | Add LOOKUP JOINs to Tiers 1-2 | 18 | High | FIXED |
| ~~P3~~ | ~~Resolve Tier 4 identity~~ | ~~5~~ | - | Resolved — correct by design |
| P3 | Create lookup index population guidance | 1 | Medium | Deferred |

---

## Per-Tier Summaries

### Tier 1: Entity-Centric (Grade: A-)

**Strengths**: Consistent structure, comprehensive ADS documentation, correct risk scoring weights, good domain categorization. All 8 rules now have optional LOOKUP JOIN enrichment blocks with criticality multipliers.

**Key Issues**: CORR-1G join key uses COALESCE that may produce mismatches. Service account patterns expanded in CORR-1H (FIXED). LOOKUP JOINs added to all rules (FIXED).

### Tier 2: Kill Chain & Behavioral (Grade: B+)

**Strengths**: Well-designed detection patterns, intentional overlaps provide defense-in-depth, consistent risk scoring. All 10 rules now have optional LOOKUP JOIN enrichment blocks.

**Key Issues**: All 10 rules had wrong tactic field path (FIXED). Framework-to-catalog drift in lookback windows. Documentation references INLINE STATS incorrectly (FIXED). LOOKUP JOINs added to all rules (FIXED).

### Tier 3: Risk Accumulation (Grade: B+)

**Strengths**: Mathematically sound risk scoring, comprehensive domain categorization, thoughtful severity assignment. CORR-3A, 3B, 3C, 3E now use dual-track pattern (separate user-risk and host-risk variants) eliminating entity conflation.

**Key Issues**: LOOKUP JOIN key mismatches in 3 of 5 rules (FIXED). CORR-3D z-score uses weekly average vs 24h measurement (documented). COALESCE entity conflation (FIXED — dual-track rewrite).

### Tier 4: Meta-Correlation (Grade: B)

**Strengths**: All 7 rules correctly operate on the full alert population. CORR-4D and 4E analyze detection system behavior (rule surges, silent reactivation). CORR-4A/4B/4C/4F/4G analyze cross-entity alert patterns (campaigns, coordination, TTP diversity). TTP diversity concept is sound.

**Key Issues**: COALESCE entity conflation (FIXED — typed entity key pattern applied to all 7 rules). LOOKUP JOIN syntax issues (FIXED).

### Tier 5: Domain-Specific (Grade: B-)

**Strengths**: Comprehensive domain coverage across 15 rules, good cross-domain correlation patterns, detailed ADS documentation.

**Key Issues**: Wrong technique field path in CORR-5A/5K (FIXED). CORR-5K has wrong dataset filters for containers. Several join key concerns for cross-domain rules. Non-standard risk score field names (FIXED).

### Tier 6: Novelty & Anomaly (Grade: B-)

**Strengths**: Complete ADS sections, innovative detection concepts, good use of lookup-based baselines. Typed entity key pattern applied to 5 affected rules (6A, 6G, 6H, 6I, 6J).

**Key Issues**: Every rule depends on externally maintained lookup indices with no population guidance. Pervasive LOOKUP JOIN key mismatches (FIXED). Comma-separated IN operator bugs (FIXED). CORR-6I redesigned as Transform + `new_terms` architecture (FIXED). Timezone handling in CORR-6C documented as known limitation. COALESCE entity conflation (FIXED — typed entity key).

---

## Deferred Issues (Require Architectural Decisions)

1. ~~**Tier 4 identity**~~: Resolved — all Tier 4 rules correctly correlate raw alert data. This is the intended design.
2. ~~**CORR-6I feasibility**~~: Resolved — redesigned as multi-component architecture: Elasticsearch Transform (computes per-entity tactic combinations via `scripted_metric`) + `new_terms` detection rule (60-day baseline, detects novel combinations). See CORR-6I documentation.
3. **CORR-6C timezone**: ES|QL lacks timezone conversion. Documented as known limitation with guidance for single-timezone, multi-timezone, and large enterprise deployments. See CORR-6C rule file.
4. **Lookup index population**: Added best practices and population guidance to catalog. No step-by-step build instructions (intentional — implementations vary by environment).
5. **Cross-rule deduplication**: Planned enhancement documented in catalog. Requires a dedicated section covering expected overlap, AI deduplication, and priority ordering.
6. ~~**COALESCE entity conflation**~~: Resolved — implemented across all 16 affected rules:
   - **Tier 3** (CORR-3A, 3B, 3C, 3E): Pattern A (Dual-track) — each rule split into Variant A (User Risk) and Variant B (Host Risk), deployed as separate Elastic Security rules.
   - **Tier 4** (CORR-4A–4G): Pattern B (Typed entity key) — `entity_type + entity_value` composite key replaces `COALESCE(user.name, host.name)`.
   - **Tier 6** (CORR-6A, 6G, 6H, 6I, 6J): Pattern B (Typed entity key) — same approach. CORR-6I metadata updated; transform architecture noted for future typed entity alignment.

---

## Validation Queries

Run these on your Elastic cluster to validate field paths before deployment:

```esql
// Test 1: Verify tactic field path
FROM .internal.alerts-security.alerts-default
| STATS tactic_count = COUNT_DISTINCT(kibana.alert.rule.threat.tactic.name)
| LIMIT 1

// Test 2: Verify technique field path
FROM .internal.alerts-security.alerts-default
| STATS technique_count = COUNT_DISTINCT(kibana.alert.rule.threat.technique.name)
| LIMIT 1

// Test 3: Verify severity field
FROM .internal.alerts-security.alerts-default
| STATS sev_count = COUNT_DISTINCT(signal.rule.severity)
| LIMIT 1
```
