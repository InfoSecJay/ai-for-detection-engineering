# UC-28: Detection Coverage Mapping for Compliance Frameworks

## Category

Posture Assessment

## Summary

Maps existing detection content to compliance control libraries (NIST 800-53 / COSAiS overlays, CSA AI Controls Matrix, ISO 27001 Annex A, PCI DSS 4.0, HIPAA Security Rule, EU AI Act Article 15 logging requirements, sector-specific) and identifies coverage gaps that translate to audit findings or regulatory exposure. Distinct from UC-06 (MITRE ATT&CK posture) — this is regulatory/compliance-mapped, not adversary-mapped. Same scoring methodology, different control library. Produces audit-ready evidence packages and prioritizes detection-engineering work that satisfies multiple regulatory regimes simultaneously.

## Problem Statement

Compliance and detection engineering historically operate in different spreadsheets. The compliance team maintains a list of controls (NIST 800-53 AC-2, AC-7, AU-2, etc.) and asks "do we satisfy these?" The detection engineering team maintains a list of rules and asks "do they fire?" Almost no one connects the two with rigor.

The 2026 regulatory environment makes this gap actionable in three ways:

1. **NIST IR 8596 Cyber AI Profile** (preliminary draft Dec 2025 / Jan 2026) — explicit "Defend" focus area calling out AI-enabled detection engineering as a controllable domain
2. **NIST 800-53 COSAiS overlays** (annotated outline Jan 8, 2026; first overlay drafts due Q3 2026) — explicit AI-system control overlays mapped to existing 800-53 controls
3. **EU AI Act Article 15 enforcement Aug 2, 2026** — mandatory cybersecurity controls and logging for high-risk AI systems, with penalties up to €15M or 3% of global turnover

Plus longstanding regimes that increasingly require evidence not just of policy but of *operational detection*:

- PCI DSS 4.0 (effective March 2025): explicit detection requirements (Req 10, 11.5, 12.10) with audit-of-evidence
- HIPAA Security Rule § 164.312: technical safeguards including audit controls and integrity monitoring
- ISO 27001 Annex A controls (notably A.8.16 — monitoring activities; A.8.15 — logging)
- SOC 2 Type II Common Criteria: continuous-control-monitoring evidence
- Sector regimes: NERC CIP for utilities, FFIEC IT Examination Handbook for finance, HITRUST CSF for healthcare

The deterministic part — *cataloging* what each framework requires, *querying* whether a rule exists — is structured-data work. The AI-shaped parts are: (a) *interpreting* the natural-language control text to identify the implied detection capability, (b) *judging* whether existing detection content actually satisfies the control intent (not just keyword-matches the description), (c) *prioritizing* detection-engineering work where one new rule satisfies multiple regimes simultaneously, and (d) *generating* audit-ready evidence packages with traceability.

## Prerequisites (What Your SIEM/SOAR Should Already Handle)

- **Detection rule inventory accessible programmatically** with metadata (name, description, MITRE mapping, severity, data source, enabled state).
- **Compliance control libraries in machine-readable format.** NIST 800-53 (OSCAL/JSON available from NIST), CSA AICM (downloadable), ISO 27001 controls (proprietary — usually internally normalized to a YAML/JSON), PCI DSS 4.0 (PCI Council), EU AI Act Annex III/Article 15 (text). For frameworks not natively machine-readable, build a normalized internal control library.
- **Regulatory scope definition.** Which controls actually apply to your environment? PCI applies if you process cardholder data; HIPAA if PHI; EU AI Act if you deploy high-risk AI in scope. Without scope clarity, the compliance posture is meaningless.
- **MITRE ATT&CK to compliance crosswalks** where they exist. NIST has published partial mappings; CIS Controls has extensive ATT&CK mappings. These crosswalks reduce the AI's reasoning load.
- **[UC-06](06-mitre-attack-posture-scoring.md) per-rule signal quality scores.** Compliance evidence isn't just "rule exists" — it's "rule operates with measured quality." A compliance auditor accepts a Functional rule; an Abandoned rule is a finding.
- **Audit log retention sufficient to demonstrate operating effectiveness.** Most regulators want evidence over time, not point-in-time snapshots.

## Where AI Adds Value

### 1. Control-Text-to-Detection-Capability Interpretation

NIST 800-53 SI-4(2) says: *"The information system employs automated tools to support near real-time analysis of events."* What does this mean for detection content? An LLM reads the control, identifies the implied detection capability (anomaly detection, real-time correlation, automated alerting on defined event categories), and maps to specific detection categories in your inventory.

This is *not* a simple keyword match. The same intent appears in different language across frameworks, and identifying the operative requirement requires reasoning.

### 2. Coverage Judgment (Not Just Existence)

Given a control's interpreted requirement and a candidate rule, the AI judges whether the rule satisfies the control intent: full, partial, or no satisfaction. Examples:

- Control requires *"detection of anomalous user authentication patterns"*; rule detects *"failed logon thresholds"*. The AI judges this as **partial** — failed-logon detection is one form of anomaly detection but does not cover impossible travel, unusual hours, or compromised-credential indicators.
- Control requires *"audit logging for privileged account use"*; rule fires on *"new domain admin group membership"*. The AI judges this as **no satisfaction** — group membership detection is not the same as privileged use logging.

The judgment must be auditable: every assessment cites the specific control text, the rule's logic, and the reasoning chain.

### 3. Cross-Regime Optimization

A new detection rule may satisfy NIST 800-53, ISO 27001, and PCI requirements simultaneously. The AI prioritizes detection-engineering backlog by counting cross-regime impact: "Building a privileged-session-recording detection satisfies 7 controls across 4 frameworks. Building a USB-device-mount detection satisfies 2 controls across 2 frameworks." Pure regulatory ROI.

### 4. Audit Evidence Package Generation

For each control, the AI generates an audit-ready evidence package: control text, organizational interpretation, detection rules satisfying the control, signal quality scores, sample alert records (redacted), validation status from [UC-26](../rule-content-engineering/26-continuous-detection-validation.md), gap analysis. Auditors can read it; auditors can challenge it; you have the evidence to defend it.

### 5. Continuous Compliance Drift Monitoring

When a rule is retired, modified, or its quality degrades, the AI surfaces compliance impact: "Rule `windows-priv-account-use` was disabled on 2026-04-12. This rule satisfied NIST 800-53 AU-2(3), AU-12(1), CIS 8.5, and PCI 10.2.1. No replacement detection has been deployed. Compliance gap as of 2026-04-12."

## AI Approach

**Multi-stage reasoning with full citation chain.**

1. **Control interpretation pass (LLM)** — Per control, LLM produces structured "what detection capability does this require" record with citation back to control text.

2. **Mapping pass (LLM)** — Per control, find candidate rules from inventory by semantic embedding + LLM judgment. Output: control → [matching rules] with confidence and full/partial/no satisfaction labels.

3. **Coverage gap analysis (deterministic)** — Identify controls with no matching rule; controls with only partial coverage; controls satisfied only by Abandoned/Degraded rules.

4. **Cross-regime prioritization (deterministic + LLM)** — Score proposed new detections by count of controls they would satisfy across regimes.

5. **Evidence package generation (LLM)** — Per control or per audit cycle, generate the package with citations and current state.

6. **Drift monitoring (deterministic + LLM)** — Detect rule changes that affect compliance coverage; LLM produces narrative explaining impact.

## Data Requirements

### Inputs

| Input | Format | Key Fields Used |
|---|---|---|
| Detection rule inventory | Platform-native | rule_id, name, description, query, MITRE tags, severity, data source, enabled |
| NIST 800-53 control library | OSCAL JSON (from NIST) | control_id, control_text, related_controls, withdrawn flag |
| NIST IR 8596 Cyber AI Profile | NIST publication | Focus areas, subcategory mappings |
| NIST 800-53 COSAiS overlays | NIST overlay JSON (when published Q3 2026) | Overlay scope, AI-specific control modifications |
| CSA AI Controls Matrix (AICM) | CSA download | Control IDs, control text, mapping to ISO/NIST/CCM |
| ISO 27001:2022 Annex A | Internally normalized YAML/JSON | Control IDs (A.5.x – A.8.x), descriptions |
| PCI DSS 4.0 controls | PCI Council JSON | Requirement IDs, sub-requirements, testing procedures |
| EU AI Act articles | Text (with internally derived control structure) | Article 15 logging requirements, Annex III scope |
| Sector frameworks | Various | NERC CIP, FFIEC, HITRUST, etc. as applicable |
| Signal quality scores | UC-06 output | rule_id → SQS, confidence_tier |
| Validation status | UC-26 output | rule_id → last_validated, fire_rate, evasion_status |
| Regulatory scope definition | Internal config | Which frameworks apply to your environment |
| MITRE ATT&CK ↔ compliance crosswalks | NIST + CIS public mappings | Reduces inference load |

### Outputs

**Per-control coverage assessment:**

```json
{
  "framework": "NIST_SP_800-53_R5",
  "control_id": "AU-2(3)",
  "control_text": "Review and update the events selected for logging and what events are logged at organization-defined frequency.",
  "interpreted_capability": "Periodic review process for which event categories are logged with documented decision rationale; alerting on events that are configured for logging but stop being logged (drift detection).",
  "satisfaction_assessment": "partial",
  "satisfying_rules": [
    {
      "rule_id": "drift-monitor-source-silence",
      "rule_name": "Data Source Silence Detection",
      "satisfaction_level": "partial",
      "signal_quality_score": 78,
      "validation_status": "PASS_2026_04_15",
      "rationale": "Rule detects when a data source stops emitting events, satisfying the drift-detection portion of AU-2(3). Does not satisfy the periodic-review-and-update portion."
    }
  ],
  "gap": "No rule or process satisfies the periodic-review-and-update portion. This is a procedural control requirement; recommend documenting an annual log-source review process owned by detection engineering with evidence captured in the SIEM-config-as-code repo.",
  "cross_regime_impact": [
    {"framework": "ISO_27001_2022", "control": "A.8.16", "satisfaction_level_inherited": "partial"},
    {"framework": "PCI_DSS_4_0", "control": "10.4.2", "satisfaction_level_inherited": "partial"},
    {"framework": "CSA_AICM", "control": "LOG-04", "satisfaction_level_inherited": "partial"}
  ],
  "evidence_package_path": "compliance/AU-2-3/evidence-2026-Q2.md"
}
```

**Cross-regime work prioritization:**

```
=============================================================================
COMPLIANCE BACKLOG — Q2 2026 PRIORITIZATION
=============================================================================

Top 10 detection work items by cross-regime impact:

1. Privileged-Session-Recording Detection
   Satisfies: NIST AU-12(1), AU-12(3); ISO A.8.15, A.8.16; PCI 10.2.1, 10.2.2; HIPAA § 164.312(b); CSA AICM AUD-02
   Frameworks satisfied: 4
   Total controls satisfied: 8
   Estimated effort: 5 days
   Compliance debt cleared: 2 audit findings (Q1 2026)

2. AI-Agent-Tool-Call Logging (UC-25 dependency)
   Satisfies: EU AI Act Article 15(1); NIST IR 8596 D-2; CSA AICM AGT-01, AGT-02; ISO 27001:2026 update (when ratified)
   Frameworks satisfied: 4
   Total controls satisfied: 5
   Regulatory deadline: EU AI Act Aug 2, 2026
   Estimated effort: 8 days (depends on UC-25 telemetry availability)

[continued for top 10]
```

**Audit evidence package (per control):**

```markdown
# Compliance Evidence: NIST 800-53 AU-12(1)

**Framework:** NIST SP 800-53 R5
**Control:** AU-12(1) — Audit Record Generation, System-Wide / Time-Correlated Audit Trail
**Control Text:** "Compile audit records from organization-defined system components into a system-wide (logical or physical) audit trail that is time-correlated to within organization-defined level of tolerance for the relationship between time stamps of individual records in the audit trail."

## Organizational Interpretation
Detection-engineering operates a SIEM with normalized timestamps (NTP-synchronized to ±100ms), centralized indexing, and cross-source correlation rules. The control is satisfied through (a) deterministic SIEM ingest behavior and (b) the correlation rule catalog.

## Implementing Detection Content
- [`correlation-rules/tier1-entity-centric/corr_1a_*`](../correlation-rules/tier1-entity-centric/) — Cross-domain entity correlation
- [`correlation-rules/tier4-meta-correlation/corr_4a_campaign_detection.md`](../correlation-rules/tier4-meta-correlation/corr_4a_campaign_detection.md) — Cross-tenant correlation

## Operating Effectiveness Evidence
- 47 correlation rules deployed and active as of 2026-04-18
- Rules generated 2,341 cross-source correlation alerts in past 90 days
- Last validation pass (UC-26): 2026-04-15 — all rules PASS
- Signal Quality Score range: 64-92 (all Functional or Strong tier)

## Gaps
None identified for this control as of 2026-04-18.

## Audit Trail
- Compliance assessment: 2026-04-18
- Assessor: Detection Engineering Team
- Next review: 2026-07-18 (quarterly cadence)
- Reviewer: Internal Audit
```

## Implementation Notes

- **Compliance is a structured-text problem.** The hard part is normalizing dozens of frameworks into a single control library. Once normalized, the AI mapping work is mechanical. Invest in the control library structure first.
- **Don't trust LLM compliance interpretation without legal sign-off.** Mapping a control to a detection capability is a legal/regulatory interpretation. Treat the AI output as a draft. Compliance and legal teams own final interpretations. The AI accelerates; it does not replace.
- **Auditors care about evidence over claims.** Every assessment must trace back to specific rule IDs, specific control text, specific reasoning. The AI's output is the artifact the auditor reads. Make it complete.
- **The ATT&CK ↔ compliance crosswalks are starting points, not finished products.** Use them to seed the mapping and reduce LLM workload. Validate against your specific environment.
- **Cross-regime optimization is the most-overlooked benefit.** Most teams build detections framework-by-framework, repeating work. The cross-regime view exposes that one well-designed detection often satisfies 5+ controls across 3+ frameworks. This is the ROI argument for the use case.
- **Compliance drift is real.** A rule retired today affects compliance posture today. Wire UC-28 into your detection-as-code lifecycle so disabling a rule triggers a compliance impact check.
- **EU AI Act Article 15 specifically requires logging.** If your environment includes high-risk AI systems under Annex III, the EU AI Act enforcement deadline (Aug 2, 2026) is a hard date. Combine this use case with [UC-25](../rule-content-engineering/25-ai-agent-mcp-detection.md) for the AI-agent telemetry side.

## Dependencies

- **Prerequisite — Pillar 1 (Data Foundations)**: Compliance evidence requires telemetry. Missing log sources are missing evidence.
- **Prerequisite — Pillar 5 (Metrics & Feedback)**: Per-rule signal quality scores from UC-06 are required for "operating effectiveness" claims.
- [UC-06: MITRE ATT&CK Posture Scoring](06-mitre-attack-posture-scoring.md) — Same scoring methodology applied to a different control taxonomy.
- [UC-26: Continuous Detection Validation](../rule-content-engineering/26-continuous-detection-validation.md) — Validation evidence is the strongest audit evidence.
- [UC-25: AI Agent & MCP Activity Detection](../rule-content-engineering/25-ai-agent-mcp-detection.md) — EU AI Act Article 15 logging requires agent telemetry.
- [UC-31: Detection Content Provenance](../rule-content-engineering/31-detection-content-provenance.md) — Audit evidence depends on rule provenance and integrity.

## Complexity Assessment

| Dimension | Rating | Notes |
|---|---|---|
| Data engineering | Medium | Normalizing control libraries is the bulk of the work. Once done, integration with rule inventory is straightforward. |
| AI/ML complexity | Medium | LLM prompting with structured outputs and citation requirements. No fine-tuning. |
| Integration effort | Medium-High | Touches detection-as-code repo, SIEM rule inventory, GRC tooling, audit workflow. Multi-team. |
| Overall | **Medium-High** | The AI part is straightforward; the organizational integration with compliance and audit is where most teams stall. |

## Real-World Considerations

- **Compliance teams have not heard of MITRE ATT&CK** — and detection engineering teams have not heard of NIST AU-12(1). The bridge between the two languages is the single highest-value soft outcome of this use case. Run shared workshops between DE and compliance to validate the AI mappings.
- **GRC platforms (ServiceNow IRM, MetricStream, LogicGate, OneTrust) are the consumers of the evidence packages.** Output should be deployable into the GRC tool's structure. Plan integration up front.
- **Audit cycles are slow but binding.** A finding written into an audit report in March affects budget and headcount in October. Detection-engineering teams that ignore compliance findings create operational risk. The cross-regime view helps prioritize.
- **EU AI Act is the most consequential 2026 milestone for SOC compliance.** If your organization deploys AI systems classified as high-risk under Annex III (and many SOC AI deployments may approach this category), the Article 15 cybersecurity and logging controls are enforceable Aug 2, 2026. The penalties are large enough to be material.
- **Sector regulators are catching up to AI.** Financial services (OCC, FRB), healthcare (HHS), critical infrastructure (CISA) are all publishing AI-specific guidance in 2026. The framework library will grow; design for that.
- **Avoid compliance theater.** A detection rule that satisfies a control on paper but doesn't fire in practice is worse than no rule, because it gives false assurance. Tie compliance evidence to UC-26 validation results — a control is satisfied only by rules that actually function.

## Related Use Cases

- [UC-06: MITRE ATT&CK Posture Scoring](06-mitre-attack-posture-scoring.md) — Same methodology, different taxonomy
- [UC-26: Continuous Detection Validation](../rule-content-engineering/26-continuous-detection-validation.md) — Validation evidence underpins audit defensibility
- [UC-25: AI Agent & MCP Activity Detection](../rule-content-engineering/25-ai-agent-mcp-detection.md) — Source of evidence for EU AI Act Article 15 logging
- [UC-31: Detection Content Provenance](../rule-content-engineering/31-detection-content-provenance.md) — Auditors care about who authored, signed, and modified each control-satisfying detection
- [UC-22: Detection Program Health Reporting](../strategic/22-detection-program-health-reporting.md) — Compliance posture rolls up into program health narrative

## References

- NIST, [SP 800-53 Rev. 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final) — Control library
- NIST, [IR 8596 Cybersecurity Framework Profile for AI (Preliminary Draft)](https://csrc.nist.gov/pubs/ir/8596/iprd) — Cyber AI Profile
- NIST, [Control Overlays for Securing AI Systems (COSAiS)](https://csrc.nist.gov/projects/cosais) — 800-53 AI overlays
- Cloud Security Alliance, [AI Controls Matrix (AICM)](https://cloudsecurityalliance.org/artifacts/ai-controls-matrix) — 2026 CSO Award winner
- ISO/IEC, [27001:2022](https://www.iso.org/standard/27001) — Information security management systems
- ISO/IEC, [42001:2023](https://www.iso.org/standard/42001) — AI management systems (CrowdStrike Charlotte AI 2026 certification reference)
- PCI Security Standards Council, [PCI DSS 4.0](https://www.pcisecuritystandards.org/document_library/) — Payment card industry
- HHS, [HIPAA Security Rule](https://www.hhs.gov/hipaa/for-professionals/security/index.html) — Healthcare
- European Union, [AI Act (Regulation 2024/1689)](https://artificialintelligenceact.eu/) — Article 15, Annex III
- Help Net Security, [EU AI Act AI agent logging requirements (April 2026)](https://www.helpnetsecurity.com/2026/04/16/eu-ai-act-logging-requirements/)
- CIS, [Critical Security Controls v8 — ATT&CK Mapping](https://www.cisecurity.org/controls/cis-controls-list)
- NIST, [OSCAL — Open Security Controls Assessment Language](https://pages.nist.gov/OSCAL/) — Machine-readable control format
