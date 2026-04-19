# Deployment Roadmap

A phased adoption plan for the 23 use cases in this repository, organized by SOC size archetype, dependency order, and expected time-to-value. Read this **after** the [Prerequisites](../prerequisites/) section. If you do not pass the [readiness checklist](../prerequisites/readiness-checklist.md) at ≥60% per pillar, fix the foundations first — every roadmap below assumes the pillars are in place.

---

## How to Use This Document

1. **Pick your archetype** (Small / Medium / Large SOC) below.
2. **Look at the dependency DAG** to confirm what feeds what. You cannot start UC-07 without UC-06 producing scores.
3. **Use the milestone table** to set quarterly goals.
4. **Use the per-use-case "go / no-go" criteria** before promoting a use case from pilot to production.
5. **Apply the build-vs-buy guidance** below to decide which use cases warrant in-house development vs. vendor adoption.

This is a recommended sequence, not a mandate. Local constraints (vendor contracts, regulatory scope, available data sources) will reorder some steps.

The roadmap covers all **31 use cases** in the catalog.

---

## SOC Size Archetypes

| Archetype | Headcount | Detection Rules | Alert Volume / Day | Typical Maturity |
|---|---|---|---|---|
| **Small** | 3–8 (incl. analysts + 1 DE) | <500 | <2,000 | Often single-platform SIEM, partial DaC, no SOAR |
| **Medium** | 10–25 (analysts + 2–4 DEs + IR) | 500–2,000 | 2,000–20,000 | Multi-platform, partial DaC + CI/CD, SOAR rolling out |
| **Large / Enterprise** | 30+ (tiered ops + dedicated DE team + IR + threat research) | 2,000+ | 20,000+ | Full DaC, SOAR mature, multi-tenant or multi-business-unit |

Match yourself honestly. Most teams overestimate maturity by one tier.

---

## Use Case Dependency DAG

The `→` denotes "produces output consumed by." Use cases without an inbound arrow can be started independently once prerequisites are met.

```
PREREQUISITES (Pillars 1-5)
        │
        ▼
[Correlation Rule Catalog] ── feeds ──┐
        │                              │
        ▼                              ▼
UC-01 ─┬→ UC-03 ─→ UC-04             UC-12 (Alert Cluster Narrative)
       │     │       ▲                  ▲
UC-02 ─┘     │       │                  │
       │     ▼       │                  │
       │  [tuning    │                  │
       │   tickets]  │                  │
       ▼             │                  │
UC-05 (Temporal) ────┘                  │
                                        │
UC-06 (Posture Scoring) ─┬→ UC-07 ──────┤
        │                ├→ UC-08       │
        │                ├→ UC-09       │
        │                └→ UC-10       │
        │                                │
UC-11 (Triage Verdicts) ────────────────┤
        ▲                                │
        │                                │
[enrichment + correlation output] ───────┘
        │
        ▼
UC-13 (NL Alert Query)  ──── independent of others; consumes alert index
        │
        ▼
UC-14 (Agentic Investigation) ── highest dependency:
        ├ requires UC-11 quality bar
        ├ requires UC-15 (investigation guides as input)
        ├ requires correlation rule catalog
        └ requires API maturity (Pillar 4)

UC-15 (Investigation Guide Generation) ─→ feeds UC-14, UC-11
UC-16 (Observable Extraction) ─────→ feeds UC-15, UC-17, UC-18
UC-17 (Rule Comparison & Gap Analysis) ─→ feeds UC-07, UC-19
UC-18 (Rule Quality Assessment) ─→ feeds UC-06, UC-19
UC-19 (Rule Generation) ─→ feeds detection backlog
UC-23 (Synthetic Test Data) ─→ feeds UC-18, UC-19 validation

UC-20 (Workflow Optimization) ─ consumes triage telemetry from UC-11/UC-14
UC-21 (CTI Synthesis) ────── consumes UC-06 + UC-17 outputs
UC-22 (Program Health Reporting) ─ consumes everything

═══════════════════════════════════════════════════════════════════════════
2026 ADDITIONS (UC-24 through UC-31)
═══════════════════════════════════════════════════════════════════════════

UC-24 (Cross-SIEM Migration) ─ standalone project; depends on UC-17 patterns
                                ├─ requires programmatic source rule access
                                └─ requires target prebuilt-rule library access

UC-25 (AI Agent Detection) ─ depends on agent telemetry availability
                              └─ feeds posture scoring (UC-06 methodology applied to ATLAS)

UC-26 (Continuous Detection Validation) ─ becomes CI gate for UC-19, UC-30
                                          ├─ depends on isolated test environment
                                          └─ enhances UC-23 (synthetic data)

UC-27 (Log Source Onboarding) ─ accelerates Pillar 1; unblocks all other UCs
                                 └─ produces dependency map consumed by UC-29

UC-28 (Compliance Detection Mapping) ─ companion to UC-06 (different taxonomy)
                                        └─ consumes UC-06 + UC-26 + UC-31 outputs

UC-29 (SIEM Cost & Tiering) ─ consumes UC-27 dependency map + UC-06 quality scores
                               └─ informs ingest decisions feeding all other UCs

UC-30 (Self-Optimizing Tuning) ─ closed-loop variant of UC-03
                                  ├─ DEPENDS ON UC-03 maturity
                                  ├─ DEPENDS ON UC-26 CI gates
                                  └─ DEPENDS ON UC-23 validation tests

UC-31 (Detection Content Provenance) ─ cross-cutting governance layer
                                        ├─ consumed by UC-19, UC-24, UC-30 (AI generation tracking)
                                        └─ produces audit evidence for UC-28
```

Read the DAG as a partial order. **Anything left of an arrow must be in production (not pilot) before the right-side use case is reliable.**

---

## Phased Roadmap by Archetype

Each phase lists: **goal**, **use cases to deploy**, **prerequisites that must be satisfied**, and **exit criteria** (what must be true to move on).

### Small SOC (3–8 people)

A small SOC should adopt a minimum viable AI footprint. Focus on use cases that reduce one analyst's workload in ways the analyst can directly verify. Skip agentic patterns entirely until you grow.

| Phase | Months | Goal | Use Cases | Exit Criteria |
|---|---|---|---|---|
| 0 | -3 to 0 | Pillar foundations | None — fix Pillars 1, 4 | ECS/CIM/ASIM normalization ≥90%; rules in Git with CI; basic SOAR enrichment for IP/hash/user |
| 1 | 0–3 | Visibility | UC-01, UC-02 | Weekly portfolio narrative reviewed by DE; 5+ tuning items raised per cycle |
| 2 | 3–6 | Tuning velocity | UC-03, UC-04 | ≥20 rules tuned via AI-suggested exclusions; drift on top-50 rules monitored weekly |
| 3 | 6–12 | Rule content quality | UC-15, UC-16, UC-18 | Investigation guides generated for top-100 rules; quality assessment integrated into PR review |
| 4 | 12–18 | Triage assist (shadow only) | UC-13 (NL query), UC-12 (cluster narratives — read-only) | Analysts use NL query daily; cluster narratives reviewed but not auto-actioned |
| 5 | 12–18 | Compliance evidence + provenance | UC-28 (lite — single framework only) + UC-31 (signing pipeline) | Audit-ready evidence package for at least one compliance framework; rule signing in CI |
| 6 | 18+ | New attack surface coverage | UC-25 (AI Agent Detection — defensive content for any AI tools the org runs) | Detection content for OWASP Agentic Top 10 if applicable |

**Do not attempt** UC-06, UC-07, UC-08, UC-09, UC-10, UC-11, UC-14, UC-19, UC-20, UC-21, UC-22, UC-24, UC-26, UC-27, UC-29, UC-30 at this size. The ROI does not justify the engineering, and you lack the validation capacity. UC-24 (migration) becomes relevant only if you're actively migrating SIEMs.

### Medium SOC (10–25 people)

The sweet spot for this repository. Most use cases are achievable in 18–24 months with realistic engineering investment.

| Phase | Months | Goal | Use Cases | Exit Criteria |
|---|---|---|---|---|
| 0 | -3 to 0 | Pillar foundations + correlation catalog | None — deploy [correlation rules](../correlation-rules/) Tiers 1–3 | Correlation rules in production for ≥60 days; lookups populated; Pillar 1, 4 ≥80% |
| 1 | 0–3 | Visibility + tuning loop | UC-01, UC-02, UC-03 | Tuning recommendations applied via PR workflow; rollback procedure exercised once |
| 2 | 3–9 | Drift + rule content engineering | UC-04, UC-15, UC-16, UC-18 | Drift caught within 7 days of source change; ≥80% of new PRs include AI-assisted investigation guide |
| 3 | 9–15 | Posture and prioritization | UC-06, UC-07 | Posture scores reviewed monthly; CTI-driven backlog feeds DE prioritization |
| 4 | 12–18 | Triage shadow → assist | UC-13, UC-12, UC-11 (shadow) | UC-11 shadow-mode agreement with analysts ≥85%; documented escalation criteria |
| 5 | 18–24 | Triage assist → assisted close | UC-11 (assisted) | Top-quartile-confidence verdicts auto-close low-severity rules with weekly QA sample |
| 6 | 24+ | Strategic reporting | UC-08, UC-09, UC-10, UC-21, UC-22 | Quarterly board-level posture report generated; CTI synthesis integrated with TI feed |
| 7 | 6–18 (parallel) | Onboarding acceleration | UC-27 (log source onboarding) | New source onboarding TTM cut by 50%+; field-population drift monitoring active |
| 8 | 12–24 (parallel) | CI validation maturity | UC-26 (continuous detection validation) | Atomic Red Team CI gate on all rule changes; coverage metrics in monthly review |
| 9 | 12–24 (parallel) | Cost optimization | UC-29 (SIEM cost & data tiering) | Field-level filtering Phase 1 deployed; documented annual savings |
| 10 | 18–30 | Compliance + provenance | UC-28 (compliance mapping), UC-31 (provenance) | Audit packages for primary frameworks; cosign-based signing in CI |
| 11 | 24+ | AI agent detection | UC-25 (when agent telemetry is ingested) | Detection content for org's agent surface; OWASP Agentic Top 10 coverage |
| 12 | 24+ | Closed-loop tuning | UC-30 (only after UC-03 + UC-26 mature) | Auto-eligibility policy approved; first 10 closed-loop tunings deployed and monitored |
| 13 | Project-driven | Cross-SIEM migration | UC-24 (only if migrating SIEMs) | Bulk migration project, semantic dedup against target library |

**Defer or skip** UC-05 (limited ROI without dedicated data scientist), UC-14 (skip until UC-11 mature), UC-19 (treat as research project), UC-20 (skip — needs telemetry not yet present), UC-30 (skip until UC-03 demonstrably mature).

### Large / Enterprise SOC (30+ people)

Full catalog adoption is realistic over 24–36 months. Run multiple workstreams in parallel. Treat this as a program, not a project.

| Phase | Months | Goal | Workstreams | Exit Criteria |
|---|---|---|---|---|
| 0 | -6 to 0 | Pillar foundations + correlation catalog Tiers 1–6 | Pillar audit; correlation rules; lookup index population | All 11 lookup indices populated; correlation Tiers 1–4 in production |
| 1 | 0–6 | Parallel kickoff | A: UC-01/02/03/04; B: UC-15/16/18; C: UC-06 measurement only | Each workstream owned by a DE squad; weekly demos |
| 2 | 6–12 | Posture and content engineering | UC-06 narrative gen; UC-07; UC-17; UC-23 (test data) | Posture scoring published; CTI-driven gap backlog operational |
| 3 | 12–18 | Triage shadow | UC-11 shadow; UC-12; UC-13 | Shadow agreement ≥90% sustained over 60 days |
| 4 | 18–24 | Triage assisted close + agentic evidence gathering | UC-11 assisted; UC-14 (read-only) | UC-11 closes ≥30% of low-severity alerts with documented error budget burn-down |
| 5 | 24–30 | Strategic + program | UC-08, UC-09, UC-10, UC-20, UC-21, UC-22 | Quarterly leadership packet automated; analyst workflow optimization producing measurable MTTR change |
| 6 | 30+ | Rule generation + autonomous experiments | UC-19; UC-14 expanded scope | UC-19 producing ≥1 production-grade rule per sprint after human review; UC-14 trusted for evidence collection on Tier 2 alerts |
| Parallel: A | 0–12 | Onboarding & cost foundation | UC-27, UC-29 | New source onboarding standardized; field-filter cost optimization deployed |
| Parallel: B | 6–18 | Validation backbone | UC-26 (Continuous Detection Validation) | Atomic Red Team CI on all rule families; coverage dashboard in DE weekly review |
| Parallel: C | 6–18 | Compliance + provenance | UC-28, UC-31 | Audit-ready evidence for primary frameworks; cosign in CI; provenance metadata schema enforced |
| Parallel: D | 12–24 | New attack surface | UC-25 (AI Agent Detection) | Detection content for agent telemetry; OWASP Agentic Top 10 + ATLAS v5.4.0 coverage |
| Parallel: E | 18–30 | Closed-loop tuning | UC-30 | Auto-eligibility policy approved; rollback infrastructure exercised; first quarter of closed-loop deployments measured |
| Project: F | As needed | Cross-SIEM migration | UC-24 | Triggered by SIEM migration project; semantic dedup against target library; phased cutover |

---

## Per-Use-Case Pilot → Production Promotion Criteria

Use these as gates before any use case moves from pilot to production. They map to the [validation harness](../concepts/validation-harness.md) framework.

| Use Case | Pilot Exit Criteria | Production Exit Criteria | Rollback Trigger |
|---|---|---|---|
| UC-01 | Narratives reviewed weekly for 4 weeks; ≥3 actionable findings per cycle | Narratives drive ≥5 tuning items per month | Narratives consistently miss obvious issues humans catch |
| UC-02 | Entity analysis matches DE intuition on 10 sample rules | Drives tuning recommendations on ≥20 rules per quarter | False entity classification on >10% of sampled rules |
| UC-03 | Tuning proposals reviewed; ≥80% accepted by DE | Auto-PR'd to detection-as-code repo with mandatory human merge | Accepted tuning later reverted on >15% of cases |
| UC-04 | Drift correctly diagnosed on a manufactured silence event | Drift alerts route to DE backlog with ≤7-day median time-to-diagnose | False drift alerts >5/week |
| UC-05 | Identifies ≥1 known business-cycle pattern | Detects new patterns DE didn't know existed | High false-pattern rate; analyst trust erodes |
| UC-06 | Per-rule scores correlate with DE intuition on 50-rule sample | Scores published monthly; technique-level confidence drives roadmap | Score volatility >20 points week-over-week without rule changes |
| UC-07 | Gap prioritization reproduces DE manual ranking on a control CTI report | CTI feed → backlog automation; gaps closed measurable | Recommendations consistently misprioritize known critical TTPs |
| UC-08 | Kill-chain analysis matches red-team report findings | Quarterly kill-chain assessment included in posture report | Material mis-mapping of detections to tactics |
| UC-09 | Cross-domain analysis identifies ≥1 known coverage gap | Drives data-source prioritization for security data lake | Recommendations conflict with TI-team assessment without explanation |
| UC-10 | Executive draft requires <30 min DE editing | Quarterly report auto-generated, reviewed by SOC lead, sent to CISO | Leadership flags factual errors |
| UC-11 | Shadow-mode agreement ≥85% over 60 days; documented disagreement reasons | Auto-close on top-confidence-band low-severity alerts only | Analyst override rate >20% in any week, OR a missed TP traced to AI verdict |
| UC-12 | Narratives match analyst summary on 30 historical incidents | Routed to triage queue with verdict + recommended next action | Hallucinated entities or events found in narratives |
| UC-13 | NL → query accuracy ≥90% on 50-question test set | Embedded in analyst console; logged for query-quality review | Query injection or scope-violation incident |
| UC-14 | Investigation report on 20 historical alerts matches senior analyst conclusion ≥80% | Read-only evidence gathering on selected rule families | Any unauthorized query, scope drift, or hallucinated tool call |
| UC-15 | Generated guides accepted by DE without major edits on ≥80% of rules | Auto-attached to all new rule PRs | Guides reference nonexistent fields or telemetry |
| UC-16 | Extracted observables match human extraction on a 30-rule sample | Feeds UC-17, UC-18 automatically | Misclassification rate >10% |
| UC-17 | Identifies known overlaps in a control rule set | Comparison report runs per release; fed to DE team | False "duplicate" findings cause rule retirement errors |
| UC-18 | Quality findings reproduce known rule issues from DE backlog | Integrated into PR check; quality score visible per rule | Quality score gives high marks to rules with known evasion gaps |
| UC-19 | Generated rules pass syntax + a curated test set on ≥70% of attempts | Used as drafting aid; 100% human review before merge | Generated rules cause production false positives |
| UC-20 | Workflow analysis identifies ≥3 documented inefficiencies | Coaching recommendations adopted by SOC lead | Recommendations conflict with analyst experience without justification |
| UC-21 | Synthesis matches CTI team's manual triage on 10 reports | Drives DE backlog with traceable lineage to source report | TTP misclassification or actor misattribution |
| UC-22 | Quarterly draft reviewed by leadership; required edits documented | Auto-generated, signed off by SOC lead | Leadership rejects narrative for material errors |
| UC-23 | Generated test events trigger target rules at expected rate; do not trigger control rules | Used in CI for new and modified rules | Generated events confused with real attacks in production telemetry |
| UC-24 | Migration tested on rule subset (50–100 rules); semantic dedup hit rate ≥30%; all migrated rules validated via UC-26 | Bulk migration with auditable per-rule decision records; dual-running in source and target for ≥30 days | Translated rule fires at >5× source baseline without environmental explanation |
| UC-25 | Detection content for top-10 OWASP Agentic Top 10 categories deployed; agent telemetry ingested ≥95% completeness | Continuous content development cadence; goal-hijack verdicts on critical agent invocations | Coverage gap discovered post-incident on agent-targeted attack |
| UC-26 | Test-to-rule mapping covers ≥80% of catalog; CI gate on PRs touching detection rules | All rule changes pass UC-26 gate before merge; weekly coverage reports to DE leadership | UC-26 gate consistently false-positives or blocks legitimate changes |
| UC-27 | Reduces median onboarding time by ≥50% on representative new sources | Onboarding pipeline handles new sources with <3 days median TTM; field-population drift monitored continuously | Generated parsers produce field-extraction rate <90% on validation samples |
| UC-28 | Coverage assessment for at least one primary framework (NIST 800-53, ISO 27001, PCI DSS, or sector regime) | Audit-ready evidence packages for all in-scope frameworks; quarterly review cadence | Auditor identifies material discrepancy between assessed satisfaction and actual rule operating effectiveness |
| UC-29 | Field-level filtering Phase 1 deployed without detection impact; documented Phase 1 savings | Continuous tier-optimization recommendations; finance-side reporting integrated | Phase 2+ tiering change causes detection regression discovered post-incident |
| UC-30 | Closed-loop on one rule family for 60 days with ≥95% accurate auto-tunings | Auto-eligibility policy CISO-approved; rollback exercised in staging | Rollback trigger fires on ≥3 deployments in any 30-day window |
| UC-31 | Cosign in CI for new rules; provenance metadata schema deployed; legacy provenance inference run on existing corpus | All deployed rules signed; modification anomaly alerts routed to DE on-call; AI-generated rule audit ≥95% complete | Modification anomaly detected with high composite score (insider threat suspected) |

---

## When to Stop or Roll Back

Healthy programs roll back. If any of these are true, pause the use case, do an after-action, and either remediate or retire it:

- **Analyst trust collapse**: Analysts begin ignoring AI output entirely or work around it
- **Error budget burn-down**: AI-generated false negatives or false positives exceed CISO-approved threshold for the quarter
- **Cost overrun**: Token spend ≥2× modelled estimate over a billing cycle (see [cost-models.md](cost-models.md))
- **Adversarial signal**: Detected attempt to manipulate AI behavior via crafted alerts, threat-intel poisoning, or feedback loops (see [adversarial-ai-considerations.md](../concepts/adversarial-ai-considerations.md))
- **Regulatory finding**: Audit identifies undocumented automated decisions or PII handling violations (see [privacy-and-data-handling.md](privacy-and-data-handling.md))

---

## Build vs. Buy Per Use Case

The 2026 vendor landscape ([vendor-landscape.md](../references/vendor-landscape.md)) means many of these use cases now have credible commercial alternatives. The build-vs-buy decision is per-use-case, not all-or-nothing. Use this matrix to decide:

| Use Case | Buy if... | Build (use this repo) if... | Notable vendor commoditization (2026) |
|---|---|---|---|
| UC-01 Performance Analytics | n/a | Multi-platform analytics | Largely build territory; vendor versions are dashboards |
| UC-02 Entity Cardinality | n/a | Domain-aware entity framework needed | Build — uncommon vendor coverage |
| UC-03 Rule Tuning | Single SIEM + accept vendor's auto-eligibility policy | Multi-platform; need transparent recommend-with-reasoning | Hunters Pathfinder (closed-loop), Prophet, Intezer |
| UC-04 Drift Monitoring | n/a | Most vendor coverage is shallow | Build — unique discipline |
| UC-05 Temporal Patterns | n/a | Have a data scientist | Skip if no DS capacity |
| UC-06 ATT&CK Posture | Splunk Detection Studio (Splunk shop) or Sentinel MCP Graph (Sentinel shop) | Multi-platform; need vendor-neutral methodology | Splunk Detection Studio, Sentinel MCP Graph Tool |
| UC-07–UC-10 Posture Assessment | n/a | Strategic depth uncommon in vendors | Build — strategic differentiation |
| UC-11 Triage Verdicts | Single platform; vendor-aligned | Multi-platform; transparency required | Charlotte AI, Microsoft Security Analyst Agent, Google TIN, Hunters, Prophet, Datadog, every named startup |
| UC-12 Cluster Narratives | All major XDR vendors | Vendor-neutral / multi-platform | Elastic Attack Discovery, Microsoft, Splunk |
| UC-13 NL Alert Query | Vendor copilots | Federated query across platforms | Sentinel MCP, Sumo Mo Copilot, Elastic AI Assistant, Anvilogic Monte |
| UC-14 Agentic Investigation | Tier-1 SIEM + budget for agent | Need read-only / audit-heavy / multi-platform | Microsoft Security Analyst Agent, Google TIN, AgentiX Case Investigation, every startup |
| UC-15 Investigation Guides | Inline-in-console preference | Bulk backfill across rule corpus; version-controlled output | Splunk SOP Agent, Anvilogic Monte |
| UC-16 Observable Extraction | n/a | Cross-format parsing | Build — uncommon coverage |
| UC-17 Rule Comparison | n/a | Foundation for UC-24 | Build — uncommon coverage |
| UC-18 Rule Quality | n/a | Semantic quality vs. syntactic | Build — vendor versions are syntactic only |
| UC-19 Rule Generation | Single platform | Multi-platform output, rigorous validation harness | Splunk Detection Builder, Panther AI Detection Builder, Sublime ADÉ, CardinalOps TI-Ops, Uncoder AI |
| UC-20 Workflow Optimization | n/a | Have the workflow telemetry | Build — uncommon coverage |
| UC-21 CTI Synthesis | CardinalOps TI-Ops if in stack | Custom posture integration | CardinalOps, SOC Prime |
| UC-22 Program Health Reporting | n/a | Narrative reports beyond dashboards | Build — uncommon coverage |
| UC-23 Synthetic Test Data | Panther bundles tests with rules | Multi-platform test data generation | Panther AI Detection Builder |
| **UC-24 Cross-SIEM Migration** | **Vendor-supported pair (Splunk→Sentinel via MS, Splunk→Elastic via Elastic)** | Direction not vendor-supported, or need cross-vendor neutrality | **Microsoft Sentinel SIEM Migration, Elastic Automatic Migration, SOC Prime Uncoder AI v2** |
| **UC-25 AI Agent Detection** | Exabeam ABA / SentinelOne Prompt AI Agent Security in stack | Custom agent surface; multi-platform; on-prem | **Exabeam ABA, SentinelOne, Microsoft Agent 365** |
| **UC-26 Continuous Detection Validation** | AttackIQ / Picus / Cymulate / SafeBreach | Custom test environment; tight SIEM-native CI integration | **AttackIQ, Picus, Cymulate, AiStrike, LimaCharlie** |
| **UC-27 Log Source Onboarding** | SentinelOne Observo, Axoflow, Cribl AI | Multi-platform parser generation | **SentinelOne Observo AI, Axoflow, Bronto** |
| **UC-28 Compliance Mapping** | n/a | All compliance regimes | **Build — uncommon vendor coverage** |
| **UC-29 SIEM Cost & Tiering** | Cribl, Edge Delta, Axoflow if in stack | Cross-vendor analysis | **Cribl Stream, Edge Delta, Axoflow, ReliaQuest reference** |
| **UC-30 Self-Optimizing Tuning** | Hunters Pathfinder, Prophet, Intezer if in stack and you accept their policies | Custom auto-eligibility policy; full audit-trail control | **Hunters Pathfinder, Prophet, Intezer, LimaCharlie** |
| **UC-31 Detection Content Provenance** | n/a | All environments | **Build — no vendor offers full detection-content signing today** |

**Key build-vs-buy principles**:

1. **Vendor capability ≠ vendor obligation.** Even if a vendor ships a similar capability, you may still build for transparency, multi-platform, or governance reasons.
2. **Build the validation harness even when buying.** Vendor outputs need eval against your environment's golden set. The [validation-harness.md](../concepts/validation-harness.md) framework applies regardless of who built the AI.
3. **Hybrid is normal.** A medium SOC may buy UC-11 (vendor-native) and build UC-04, UC-22, UC-28, UC-31. There's no consistency requirement.
4. **Re-evaluate annually.** The vendor landscape moves fast. Today's "build" decision may be tomorrow's "buy."

## What This Roadmap Does Not Cover

This repository is scoped to **detection engineering** use cases. The following adjacent AI categories are deliberately deferred to future companion repositories:

- **AI for Threat Intelligence** (IOC extraction, actor profiling, infrastructure pivoting, victimology)
- **AI for Threat Hunting** (hypothesis generation, iterative hunt-loop agents, anomaly explanation)
- **AI for Incident Response** (containment scoping, exec comms drafting, post-mortem synthesis)
- **AI for Adversary Emulation** (scenario generation, atomic-test selection, purple-team retro)
- **AI for Malware & Forensics** (RE assistance, sandbox synthesis, YARA/Snort/Suricata generation)

UC-21 (CTI Synthesis) gestures at the first; UC-23 gestures at the fourth. Treat them as bridges to those future repos rather than full coverage.
