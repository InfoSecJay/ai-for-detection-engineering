# Governance Mapping for Detection Engineering

What a Detection Engineering team actually needs to do to satisfy the AI-governance asks they will receive from CISO, Privacy, Legal, Internal Audit, and (depending on jurisdiction) regulators. Scoped to detection engineering — broader enterprise AI governance is the CISO/Privacy team's domain. This document tells you what to produce so you don't get blocked by a governance review.

The framework with the broadest applicability is NIST's AI Risk Management Framework (AI RMF 1.0). It is voluntary, vendor-neutral, and the most-cited reference for organizations operationalizing AI governance. Use it as the spine; map your local regulatory regime onto it.

---

## NIST AI RMF in One Page

NIST AI RMF organizes work into four functions:

| Function | What it Means | What DE Owns |
|---|---|---|
| **GOVERN** | Policies, roles, accountability | Use-case approval, error budgets, escalation |
| **MAP** | Context, scope, risk identification | Use case definition, data flow, threat model |
| **MEASURE** | Quantitative + qualitative assessment | Validation harness, metrics, audit trail |
| **MANAGE** | Risk response, monitoring, change | Deployment gates, monitoring, rollback procedures |

Each AI use case in this repository should produce evidence of all four functions before going to production. The artifacts are concrete and finite — not "write a 200-page risk assessment."

---

## Per-Use-Case Governance Artifact Set

For each AI use case in production, maintain six artifacts. These satisfy the bulk of governance asks across NIST AI RMF, EU AI Act high-risk system requirements, ISO 42001 management-system requirements, and most internal-audit checklists.

### 1. Use Case Charter (MAP)

A one-page document covering:

- Use case ID and name
- Owner (named individual or team)
- Problem solved and intended benefit
- Decisions the AI makes or influences (this drives risk classification)
- Inputs (data categories, sources)
- Outputs (consumers, downstream actions)
- Out-of-scope items (what this use case does NOT do)
- Risk classification (low / medium / high blast radius)

Most of this is already in the use case markdown files — pull it into a single charter format your governance team can review. The classification matters: high-blast-radius use cases (UC-11 auto-close, UC-14 with response actions) need more rigor than low-blast-radius ones (UC-01 narratives, UC-22 reports).

### 2. Data Handling Record (MAP, GOVERN)

Per use case, what data leaves your environment and why. See [privacy-and-data-handling.md](privacy-and-data-handling.md) for the full template. Required fields:

- Data categories sent
- Field allow-list
- Redaction transforms applied
- Vendor + region + retention
- Legal basis for processing (where relevant: GDPR Art. 6, PIPEDA, state privacy law)

### 3. Validation Evidence (MEASURE)

Per use case, the most recent evaluation report from the [validation harness](../concepts/validation-harness.md):

- Golden set version + size
- Metrics achieved per category (accuracy, calibration, hallucination rate, etc.)
- Comparison against documented gates
- Date of last run
- Outstanding regressions or known issues

This is not a one-time artifact. Refresh on every prompt or model change and at least quarterly.

### 4. Failure Mode Register (MAP, MANAGE)

The failure modes from [where-ai-fails.md](../concepts/where-ai-fails.md) and [adversarial-ai-considerations.md](../concepts/adversarial-ai-considerations.md) that apply to this use case, with the controls in place. Per-use-case mapping is already in `where-ai-fails.md` — your job is to confirm controls are actually implemented and tested.

### 5. Monitoring + Rollback Plan (MANAGE)

- Production metrics tracked (from `validation-harness.md` § Continuous Production Monitoring)
- Alert thresholds + on-call routing
- Documented rollback procedure (how do you turn the use case off in <1 hour if needed)
- Last rollback test date

If you have not exercised the rollback at least once, you do not have a rollback procedure — you have a hope.

### 6. Change Log (GOVERN, MANAGE)

A version-controlled record of every:

- Prompt change (with diff + validation result)
- Model version change (with parallel-run results)
- Schema change to inputs (from upstream pipelines)
- Threshold or guardrail change

Keeping this in git alongside the use case is sufficient. Do not invent a separate document store.

---

## NIST AI RMF Mapping (Detailed)

For audits that require explicit NIST AI RMF traceability:

### GOVERN

| Subcategory | DE Evidence |
|---|---|
| GV-1.1 Legal/regulatory requirements understood | Charter section "Risk classification" + Data Handling Record "Legal basis" |
| GV-1.2 Trustworthy AI characteristics integrated | This repository's prerequisites + concept docs constitute the integration |
| GV-2.1 Roles, responsibilities documented | Use Case Charter "Owner"; SOC RACI |
| GV-3.2 Workforce trained | Analyst training records (from Pillar 3) |
| GV-4.1 Diverse perspectives in design | DE + analyst + IR + privacy review of charter before approval |
| GV-4.3 Periodic review | Quarterly governance review of artifact set |
| GV-6.1 AI lifecycle policies | This repository's deployment-roadmap defines lifecycle gates |

### MAP

| Subcategory | DE Evidence |
|---|---|
| MP-1.1 Context established | Use Case Charter |
| MP-2.1 Categorization of AI system | Charter "Risk classification" |
| MP-2.3 System scope, goals documented | Charter |
| MP-3.1 Benefits assessed | Charter "Intended benefit" + cost-models.md ROI |
| MP-3.4 Risks identified | Failure Mode Register + Adversarial AI Considerations |
| MP-4.1 Impacts on individuals/groups | Privacy Data Handling Record |
| MP-5.1 Likelihood and impact of risks | Failure Mode Register with explicit ratings |

### MEASURE

| Subcategory | DE Evidence |
|---|---|
| MS-1.1 Approach to measurement identified | Validation Harness spec for the use case |
| MS-2.1 Test sets representative | Golden Set composition documented |
| MS-2.5 AI system valid and reliable | Validation Evidence (latest harness run) |
| MS-2.7 AI system secure and resilient | Adversarial AI controls implemented + tested |
| MS-2.8 AI system safe | Rollback procedure exercised |
| MS-2.9 AI system explainable | Cite-and-verify pattern + reasoning chain captured |
| MS-2.10 AI system privacy-enhanced | Data Handling Record + redaction transforms |
| MS-2.13 Effectiveness measured continuously | Production monitoring metrics |
| MS-3.2 Risk tracking | Change log + production monitoring |
| MS-4.2 Measurement results integrated | Validation gates enforce results |

### MANAGE

| Subcategory | DE Evidence |
|---|---|
| MG-1.1 Risk responses documented | Failure Mode Register includes mitigation |
| MG-2.1 Resources allocated | Cost model + headcount allocation |
| MG-2.2 Mechanisms to sustain value | Quarterly review cadence |
| MG-3.1 Risks treated, transferred, accepted | Risk-acceptance decisions in change log |
| MG-4.1 Post-deployment monitoring | Production monitoring metrics + alerts |
| MG-4.2 Continuous improvement | Override capture, feedback-loop hardening |
| MG-4.3 Regular incident response | Rollback procedure tested |

You do not need to map every subcategory. Focus on the ones your auditor or risk team asks about.

---

## EU AI Act — Aug 2, 2026 Enforcement (Hard Deadline)

For organizations within scope of the EU AI Act:

- **Article 15 enforcement is Aug 2, 2026.** Annex III high-risk AI obligations become enforceable. Article 15 (accuracy, robustness, cybersecurity) and **automatic logging** requirements are mandatory; penalties up to €15M or 3% of global turnover.
- **Most SOC AI use cases are not high-risk** under Annex III categorization. Detection engineering AI is generally not "biometric identification," "education," "employment," or "essential services" use cases as defined.
- **Use cases approaching high-risk territory**:
  - **UC-20 (Workflow Optimization)** if used for analyst performance evaluation could implicate "employment, workers management" — handle with HR/Legal involvement.
  - **UC-25 (AI Agent & MCP Activity Detection)** intersects Article 15 logging requirements when applied to monitor high-risk AI systems in your environment. Treat agent telemetry as a compliance artifact.
  - **UC-30 (Self-Optimizing Closed-Loop Tuning)** if it makes consequential autonomous decisions affecting individuals (rare but possible if tuning affects user-facing detections).
- **AI agent logging requirements** are particularly sharp. Help Net Security (Apr 16, 2026) detailed the logging mandate: structured, tamper-evident, retained for the period the high-risk AI is in service. Pair UC-25 with UC-31 (provenance) to satisfy.
- **General-purpose AI (GPAI) provider obligations** fall on the LLM vendor, not on you as a deployer. You inherit deployer obligations: transparency to users about AI involvement, human oversight, monitoring.
- **Documentation is the practical hammer**: the Use Case Charter + Data Handling Record + Validation Evidence cover most deployer documentation expectations.

If you are not in EU AI Act scope, you still benefit from these documentation patterns — most other emerging AI regulations (Canada's AIDA, US executive orders, state-level AI laws, AU/UK voluntary frameworks) ask for similar evidence.

## NIST IR 8596 — Cyber AI Profile (Newly Material)

The Preliminary Draft (Dec 2025 / Jan 2026) introduces three Focus Areas relevant to detection engineering:

- **Secure** — protecting your AI systems (covers UC-25, UC-31)
- **Defend** — using AI in cyber defense (covers most of this catalog: UC-01–UC-30)
- **Thwart** — defending against adversarial AI (covers controls in [adversarial-ai-considerations.md](../concepts/adversarial-ai-considerations.md))

The "Defend" focus area is the first US standards body framing of detection-engineering AI as a controllable domain. Map your use cases to it explicitly in the Use Case Charter.

NIST followed up on April 7, 2026 with a concept note for an **AI RMF Profile on Trustworthy AI in Critical Infrastructure** (Energy, Water, Healthcare, Financial Services). If your environment is in critical infrastructure scope, this profile will become an additional alignment target later in 2026.

## NIST 800-53 COSAiS Overlays (Q3 2026 Drafts)

The Control Overlays for Securing AI Systems are the operationalization of 800-53 controls for AI. First overlay drafts due Q3 2026, Predictive AI first, generative AI to follow. If your environment runs federal or federal-adjacent compliance (FedRAMP, FISMA, CMMC), these overlays will become the substrate for AI-system control assessments.

Action: track NIST publications. When overlay drafts publish, map them through [UC-28 (Detection Coverage Mapping for Compliance)](../use-cases/posture-assessment/28-compliance-detection-mapping.md) into your existing 800-53 coverage.

## CSA AI Controls Matrix (AICM)

2026 CSO Award winner (Mar 10, 2026). Foundation for the upcoming **STAR for AI** certification. CSA also announced the **CSAI Foundation** (Mar 23, 2026) for "Securing the Agentic Control Plane."

For detection engineering specifically, AICM controls map cleanly to:

- Model-signing verification events → [UC-31](../use-cases/rule-content-engineering/31-detection-content-provenance.md) (parallel pattern)
- Training-data lineage events → not directly DE; flag for AI/ML platform team
- Agent activity audit → [UC-25](../use-cases/rule-content-engineering/25-ai-agent-mcp-detection.md)
- Pipeline integrity → covers ingest pipelines, applies to [UC-27](../use-cases/rule-content-engineering/27-log-source-onboarding.md)

If your organization is in CSA STAR scope or pursuing STAR for AI, AICM mapping is now table-stakes evidence.

---

## ISO/IEC 42001 — When It Applies

ISO 42001 is the AI management system standard (analogous to ISO 27001 for information security). If your organization is pursuing certification:

- DE owns the operational evidence; the certification effort is led by your management-systems team
- Your contribution: the artifact set above, kept current
- Pay attention to ISO 42001 Annex A controls A.6 (AI system lifecycle), A.7 (data for AI), A.9 (information for interested parties) — the artifacts above cover the bulk

If certification is not on the roadmap, do not adopt ISO 42001 voluntarily for DE alone — it's a heavy framework for a single team.

---

## Practical Workflow

A workable cadence:

| Cadence | Action |
|---|---|
| Per new use case | Produce Charter, Data Handling Record, Failure Mode Register, Monitoring Plan before pilot |
| Per pilot exit | Produce initial Validation Evidence; review artifact set with Privacy + Security |
| Per production change | Update Validation Evidence + Change Log; re-run regression gates |
| Monthly | Review production monitoring metrics; update Change Log |
| Quarterly | Refresh Validation Evidence; review Failure Mode Register against incidents; exercise rollback |
| Annually | Full artifact-set review with Internal Audit |

This is real work but it is bounded. A team running 8 use cases in production can manage the artifact set with ~0.2 FTE of effort.

---

## What This Document Does Not Cover

- **Model card and system card publication** — relevant if you build foundation models; not for SOC use cases consuming them
- **Algorithmic impact assessment** — relevant in some public-sector regimes (e.g., Canada's Directive on Automated Decision-Making for federal departments); covered by the Use Case Charter pattern with minor extensions
- **AI Bill of Materials (AIBOM)** — emerging concept; track but no concrete recommendation yet for SOC use cases
- **Watermarking/provenance** — relevant for content-generation use cases; not for triage/posture/correlation

If your governance team asks for one of these by name, route to the broader enterprise AI governance program rather than building it inside DE.

---

## Common Mistakes

1. **Building governance artifacts as a one-time exercise** — they decay quickly; bake refresh into the cadence
2. **Producing artifacts only when asked by audit** — at that point you're behind; produce them as part of normal use case development
3. **Treating AI governance as separate from existing change management** — it isn't; reuse your existing change-control process and add AI-specific evidence
4. **Skipping rollback testing** — every governance framework expects you can turn the system off; few teams have actually exercised it
5. **Letting validation evidence go stale** — quarterly refresh is the floor, not the ceiling
