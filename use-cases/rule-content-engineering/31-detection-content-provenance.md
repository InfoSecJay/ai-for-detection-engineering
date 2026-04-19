# UC-31: Detection Content Provenance & Supply Chain Integrity

## Category

Rule Content Engineering

## Summary

Manages the detection-content lifecycle with cryptographic signing of authored rules, attribution chains for rules sourced from CTI vendors, the open-source community, or AI generation, and verification that rules in production match signed source. Detects unauthorized rule modifications, rules sourced from untrusted authors, and AI-generated rules that bypassed required human review. Parallels AI model supply-chain integrity (NSA AI Supply Chain Guidance March 2026, OpenSSF Model Signing Specification) but applied to the detection-content supply chain — your rules are now an attack surface in their own right.

## Problem Statement

Detection content has historically been treated as configuration. Configuration that, in many environments:

- Lives in a Git repo with PR workflows, but the PRs may have varying degrees of review rigor
- Is supplemented by content from vendors, partners, AI generation, the SigmaHQ community, and threat intel feeds — with attribution often lost in translation
- Is occasionally modified directly via SIEM GUI by analysts during investigations, with no commit trail
- Is exported, imported, copy-pasted across teams and platforms, often losing the original author's identity
- Has no cryptographic verification that what's running in production matches what was authored

In 2026, this becomes a problem for three converging reasons:

1. **Attackers can modify detection logic.** A detection rule that has been quietly modified to suppress alerts on the attacker's tools is the perfect persistence mechanism. The MITRE ATT&CK technique T1562 (Impair Defenses) covers this; detection-content tampering is its more sophisticated cousin.
2. **AI-generated rules bypass human review at scale.** [UC-19](19-detection-rule-generation.md) and [UC-30](../alert-analysis/30-self-optimizing-tuning.md) generate rules and tuning automatically. Without provenance tracking, "AI-authored, human-approved" rules become indistinguishable from "AI-authored, no review" rules.
3. **Regulators care about provenance.** NSA AI Supply Chain Guidance (March 2026) calls for cryptographic signing across the AI lifecycle. CSA AI Controls Matrix includes supply-chain controls. EU AI Act high-risk-AI requirements imply auditable change history. The compliance lens demands provenance for AI-influenced security tooling, and detection content qualifies.

The deterministic part — *signing* a rule, *verifying* a signature, *recording* a Git commit — is well-understood cryptography and version control. The AI-shaped parts are: (a) *attributing* rules to original authors when provenance is incomplete (heuristic source identification), (b) *detecting* anomalous modification patterns (rules changed by unusual actors, at unusual times, with unusual content), (c) *generating* the audit trail in human-readable form for review, and (d) *flagging* AI-generated content that bypassed required human review.

## Prerequisites (What Your SIEM/SOAR Should Already Handle)

- **Detection-as-code repository with full Git history.** Pre-existing git-tracked rule corpus. If rules are still being authored directly in the SIEM GUI, fix that first.
- **CI/CD pipeline for detection deployment.** Rules deploy to SIEM via pipeline, not by hand. The pipeline is where signing happens.
- **Identity infrastructure for rule authors.** Authors authenticate to Git with verified identities (GPG-signed commits, verified GitHub/GitLab accounts, SSH key registry). Anonymous commits are not provenance.
- **PR review enforcement.** Required-review settings on the detection-as-code repo. Without enforced review, "human-approved" provenance is a fiction.
- **A signing infrastructure.** Either OpenSSF Sigstore (recommended — keyless signing with OIDC), traditional code-signing certificates, or a dedicated signing service. The choice depends on your existing PKI and developer workflows.
- **A signed-content registry.** A trusted index of signed rule artifacts that the SIEM deployment can verify against. OCI registries with cosign signatures, custom artifact registry, or platform-native (some commercial detection content marketplaces are evolving toward signed distribution).
- **External-source intake process.** When you adopt a SigmaHQ rule, vendor TI rule, or community rule, who reviews it, who signs the local copy, who maintains the attribution? Without an intake process, externally-sourced rules quietly become unattributed local rules.

## Where AI Adds Value

### 1. Provenance Inference for Legacy Content

Most existing rule corpora have incomplete attribution. The original authors of rules from 2018 may have left the company. Rules copy-pasted from blog posts have no record of origin. The AI reads the rule body, compares against known SigmaHQ public rules, vendor content packs, public CTI reports, and community sources, and produces an attribution inference: "This rule's structure and field choices match the SigmaHQ rule `proc_creation_win_susp_ds_get_default_logon_provider.yml` — likely sourced from SigmaHQ community in 2022, locally modified."

Output is structured: confident attribution, candidate sources, modification analysis. Humans validate.

### 2. Anomalous Modification Detection

Cross-references each rule modification against historical patterns: who authors what, when, with what review depth. Flags anomalies for review:

- Rules modified by an actor who has never modified rules in that category before
- Modifications outside business hours by an unusual actor
- Modifications that materially weaken detection logic (loosen thresholds, expand exclusions, narrow conditions) without corresponding analyst-disposition trigger
- Rules with metadata stripped (descriptions removed, MITRE tags emptied)
- Bulk modifications across many rules in a single commit (unusual scope)

Each flag includes the modification diff, the actor, the historical baseline, and a reasoning narrative.

### 3. AI-Generated Content Tracking

Every AI-generated rule (from UC-19, UC-24, UC-30) must carry metadata identifying it as AI-generated, the model used, the prompt version, the human reviewer, and the validation harness pass. The AI cross-references SIEM-deployed rules against this metadata and identifies any AI-generated rule that lacks the required human-review signature. These are gap candidates — either they bypassed the workflow (incident) or the metadata is missing (process gap).

### 4. Audit Trail Narration

For audit and incident-response purposes, generate human-readable change history per rule: who created it, what was the original signing, what modifications occurred over time, who approved each change, and what's the current signature status. This is what an auditor reads when assessing rule integrity.

### 5. Supply-Chain Risk Scoring of External Sources

When ingesting from vendor TI feeds, SigmaHQ, community marketplaces, or partner sharing, the AI scores the source reputation: how stable, how reviewed, how often modified, how often retracted. Sources with poor reputation feed rules that require additional internal review before adoption.

## AI Approach

**Layered: cryptographic deterministic + LLM provenance reasoning + LLM anomaly explanation.**

1. **Signing pipeline (deterministic — Sigstore / cosign / equivalent)** — Every rule deployed to production is signed in CI. Signature includes commit hash, author identity, reviewer identities, validation harness version, model identity (if AI-generated).

2. **Verification at deploy (deterministic)** — SIEM deploy step verifies signature. Unsigned or invalidly-signed rules are rejected.

3. **Provenance metadata schema (deterministic standard)** — Every rule carries structured provenance metadata in its repository file: original_source, original_author, current_owner, ai_generated (bool), model_id (if AI), prompt_version (if AI), human_reviewers, last_signed.

4. **Provenance inference (LLM)** — For legacy rules with incomplete metadata, LLM produces attribution inference with confidence and citations.

5. **Modification anomaly detection (statistical baseline + LLM)** — Per-actor, per-rule-category modification baseline. Anomalies surface to LLM for narrative explanation and triage routing.

6. **AI-generated content audit (deterministic + LLM)** — Cross-reference deployed rules against AI-generation metadata. LLM produces audit summary.

7. **External source scoring (LLM, periodic)** — Score each external source by stability, review depth, retraction rate, alignment with internal standards.

## Data Requirements

### Inputs

| Input | Format | Key Fields Used |
|---|---|---|
| Detection-as-code Git repo | Git history | Commit hashes, authors, signatures, file diffs, review records |
| Signing infrastructure | Sigstore / cosign / x.509 | Verified identities, signing logs |
| AI-generation metadata | Structured logs from UC-19, UC-24, UC-30 | rule_id, model_id, prompt_version, human_reviewer, generation_timestamp |
| External source registry | Internal config | Vendor TI feeds, SigmaHQ adoption history, community sources, partner shares |
| Per-actor modification baseline | Time series, derived from Git | Per author: rules touched, categories, review depth, modification times |
| Rule body (for provenance inference) | Rule file | Full body for similarity comparison |
| SIEM deployed rules | SIEM API | Currently-running rule definitions for signature verification |
| Public rule corpora (for inference) | SigmaHQ, vendor, blog posts | Reference content for similarity matching |

### Outputs

**Per-rule provenance record:**

```yaml
rule_id: siem-rule-00421
rule_name: "Suspicious PowerShell Encoded Command"
provenance:
  origin:
    type: "ai_generated_from_cti"
    source: "UC-19 generation 2026-01-12 from Mandiant report MAN-2025-1142"
    original_author: "claude-opus-4-7@anthropic via UC-19 pipeline v3.2"
  current_state:
    current_owner: "detection-eng-team"
    file_path: "rules/windows/process_creation/proc_creation_win_powershell_encoded.yml"
    last_modified_commit: "a4f3e9c..."
    last_modified_by: "human-msmith"
    last_modified_at: "2026-04-15T14:23:11Z"
  modification_history:
    - commit: "a4f3e9c..."
      author: "human-msmith"
      reviewer: "human-tjones"
      timestamp: "2026-04-15T14:23:11Z"
      change_type: "exception_list_addition"
      ai_assisted: false
      change_summary: "Add exception for SVC-DEPLOY service account on BUILD-SVR-* hosts"
    - commit: "9b2e1a8..."
      author: "uc30-auto-tuning-pipeline"
      reviewer: "automated"
      timestamp: "2026-03-22T09:15:33Z"
      change_type: "exception_list_addition"
      ai_assisted: true
      ai_metadata:
        action_id: "UC30-2026-03-22-0915-7d4e"
        triggered_by_dispositions: 5
        blast_radius: "LOW"
        validation_passed: true
      change_summary: "Auto-tuned exception for SVC-INTUNE service account"
    - commit: "3a1c8d2..."
      author: "uc19-pipeline"
      reviewer: "human-jdoe"
      timestamp: "2026-01-12T11:42:08Z"
      change_type: "rule_creation"
      ai_assisted: true
      ai_metadata:
        model: "claude-opus-4-7"
        prompt_version: "v3.2"
        cti_source: "Mandiant MAN-2025-1142"
        validation_passed: true
      change_summary: "Initial rule created from CTI"
  signing_status:
    last_signed: "2026-04-15T14:25:08Z"
    signed_by: "ci-pipeline (cosign keyless via OIDC)"
    signature_valid: true
    deployed_signature_matches: true
  ai_generation_audit:
    is_ai_generated: true
    has_required_human_review: true
    review_compliant: true
```

**Anomalous modification flag:**

```
=============================================================================
ANOMALOUS RULE MODIFICATION DETECTED
Generated: 2026-04-18 02:14:33 UTC
=============================================================================

Rule modified: siem-rule-00892 (Critical Asset Privilege Escalation)
Modified by:   contractor-jdoe (first rule modification by this actor)
Modified at:   2026-04-18 02:11:08 UTC (outside business hours)
Change:        Exclusion added: user.name = "svc_attacker_test"

Anomaly factors (composite anomaly score 0.91 / 1.00):
  ┌──────────────────────────────────────────────────────────┬──────────┐
  │ Actor unfamiliarity with rule category                   │ +0.35    │
  │ Off-hours modification                                   │ +0.25    │
  │ Modification weakens critical-severity rule              │ +0.20    │
  │ Service account name pattern not in inventory            │ +0.15    │
  │ Single-rule rapid modification (no related context)      │ +0.10    │
  │ User has no historical disposition activity on this rule │ +0.05    │
  └──────────────────────────────────────────────────────────┴──────────┘

Human-readable assessment:
  This modification has multiple unusual characteristics. The actor
  (contractor-jdoe) has never modified detection rules before. The change
  was made at 02:11 UTC (well outside business hours for this team). The
  change weakens a CRITICAL-severity privilege escalation rule by adding
  an exclusion for a service account ("svc_attacker_test") that does not
  appear in the authorized service account inventory. The combination
  warrants immediate review.

Recommended actions:
  1. ROLLBACK the modification immediately (auto-rollback PR generated: PR-9981)
  2. Verify contractor-jdoe's identity and authorization to modify detection rules
  3. Audit all other recent activity by this actor across the detection-as-code repo
  4. Investigate the "svc_attacker_test" name as a potential adversary indicator
  5. Notify on-call DE and Insider Threat team

Status: ROLLBACK PR CREATED, ON-CALL PAGED
```

## Implementation Notes

- **Sigstore is the practical default for signing.** OIDC-based keyless signing eliminates the operational burden of long-lived signing keys. Integrates with GitHub Actions, GitLab CI, and most CI systems. Use cosign for the signature operations.
- **Sign at the rule artifact level, not just commit.** A signed Git commit proves "this commit was made by an authorized actor." A signed deployable artifact (the actual KQL/Sigma/SPL file as it lands in the SIEM) proves "this is what was deployed." Both are valuable; the artifact signature is what matters at deploy verification.
- **Provenance metadata in the rule file itself.** Rather than maintaining a separate metadata store, embed provenance fields in the rule's frontmatter or comments. The rule file becomes self-describing. Compatible with Sigma, Elastic TOML, Splunk YAML.
- **AI-generation tracking must be enforced at the source pipeline.** UC-19, UC-24, UC-30 must emit provenance metadata. If the upstream pipeline doesn't emit, downstream tracking can't compensate. Make this a CI-enforced requirement.
- **Modification anomaly thresholds are environment-specific.** A 5-person SOC where everyone touches everything will have different anomaly baselines than a 50-person SOC with role separation. Calibrate per environment.
- **Don't surface every anomaly as critical.** Most are false positives — a junior DE's first commit is "anomalous" by the actor-unfamiliarity factor. Use composite scoring; only escalate the high-composite cases.
- **External source intake should be a structured workflow.** When ingesting from SigmaHQ or vendor TI: clone the source, log the original URL, sign the local copy, attribute the original author, document the local modifications. This is rule-supply-chain hygiene.
- **The audit trail is also incident-response evidence.** When investigating a possible compromise, the rule provenance history shows whether attackers may have tampered with detection content. Make this trail accessible to IR.

## Dependencies

- **Prerequisite — Pillar 4 (Technology Stack)**: Detection-as-code with CI/CD and signing infrastructure.
- **Prerequisite — Pillar 5 (Metrics & Feedback)**: Per-actor modification telemetry.
- [UC-19: Detection Rule Generation](19-detection-rule-generation.md) — AI-generation must emit provenance metadata.
- [UC-24: Cross-SIEM Rule Migration](24-cross-siem-rule-migration.md) — Migration is a major rule-attribution event; provenance must transfer.
- [UC-30: Self-Optimizing Closed-Loop Tuning](../alert-analysis/30-self-optimizing-tuning.md) — Auto-applied changes must carry full provenance.
- [UC-28: Detection Coverage Mapping for Compliance](../posture-assessment/28-compliance-detection-mapping.md) — Audit evidence depends on provenance integrity.

## Complexity Assessment

| Dimension | Rating | Notes |
|---|---|---|
| Data engineering | Medium | Signing infrastructure setup is well-understood. Provenance metadata schema is standardization work. |
| AI/ML complexity | Medium | LLM for provenance inference and anomaly narration. No fine-tuning. |
| Integration effort | Medium-High | Touches detection-as-code repo, CI/CD, SIEM deployment, identity infrastructure, audit/IR workflows. |
| Overall | **Medium-High** | The cryptographic plumbing is the up-front cost. Once in place, the AI components are modest. |

## Real-World Considerations

- **The detection-as-code supply chain attack is theoretical today but trending toward inevitable.** As detection engineering matures, attackers will start targeting the detection content itself. The earliest evidence is anecdotal — 2025 saw a few public reports of attackers modifying SIEM rules during persistence. By 2027–2028 this is likely to be a meaningful attack pattern. Building provenance now means having defenses when the attack becomes common.
- **Compliance demand is the strongest lever.** Most teams will not invest in detection-content signing for the security benefit alone. NIST IR 8596, CSA AICM, EU AI Act, and FedRAMP audits will increasingly ask for it. Build the case on regulatory rationale.
- **External-source attribution is a recurring pain.** SigmaHQ, vendor packs, blog posts — the original authorship chain is fragile and easily lost. Establish an explicit intake workflow that captures attribution at the moment of adoption; retroactive attribution is much harder.
- **AI-generation traceability is the new dimension.** "Generated by Claude Opus 4.7 via UC-19 prompt v3.2 on 2026-01-12, reviewed by human-jdoe in PR-1234, validation harness 7.4.1 passed" — this is the level of detail audit trails will require for AI-influenced detection content. Bake it in.
- **The anomaly detection has insider-threat applications.** Detecting "an authorized user is modifying rules in unusual ways" is conceptually the same as detecting any insider threat. The signal is high-fidelity because rule modifications are rare events with high consequence.
- **Vendor capabilities are nascent.** No major vendor ships full detection-content signing today. SigmaHQ has explored signed rule distribution; commercial detection-content marketplaces (SOC Prime, Anvilogic) are best-positioned to add signing in the next 12–24 months. This use case is currently a build-only proposition.

## Related Use Cases

- [UC-19: Detection Rule Generation](19-detection-rule-generation.md) — Source of AI-generation metadata
- [UC-24: Cross-SIEM Rule Migration](24-cross-siem-rule-migration.md) — Migration is a provenance event
- [UC-30: Self-Optimizing Closed-Loop Tuning](../alert-analysis/30-self-optimizing-tuning.md) — Auto-applied changes carry provenance
- [UC-18: Rule Quality Assessment](18-rule-quality-assessment.md) — Quality assessment can include provenance signals
- [UC-28: Detection Coverage Mapping for Compliance](../posture-assessment/28-compliance-detection-mapping.md) — Audit evidence underpinning
- [Adversarial AI Considerations](../../concepts/adversarial-ai-considerations.md) — Specifically, defending against detection-content tampering

## References

- NSA, [AI Supply Chain Guidance (March 2026)](https://www.logistics-concepts.com/news/digital-supply-chain-nsa-warns-ai-risks-executive-summary-action-plan/)
- OpenSSF, [Model Signing (OMS) Specification](https://openssf.org/blog/2025/06/25/an-introduction-to-the-openssf-model-signing-oms-specification/)
- OpenSSF, [Sigstore](https://www.sigstore.dev/) — Keyless signing infrastructure
- OpenSSF, [cosign](https://github.com/sigstore/cosign) — Container and artifact signing tool
- OWASP, [Top 10 for Agentic Applications 2026 — ASI03 Identity & Privilege Abuse](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- Cloud Security Alliance, [AI Controls Matrix — Supply Chain Controls](https://cloudsecurityalliance.org/artifacts/ai-controls-matrix)
- MITRE ATT&CK, [T1562 Impair Defenses](https://attack.mitre.org/techniques/T1562/) — Adversary tampering with security tooling
- SigmaHQ, [Sigma Rule Specification — proposed signing extensions](https://sigmahq.io/) — Community discussion of signed rule distribution
- NIST, [SP 800-218 SSDF — Secure Software Development Framework](https://csrc.nist.gov/Projects/ssdf) — Applies to detection-as-code
- Chainguard, [Chainguard Actions — Trusted CI/CD Workflows](https://www.prnewswire.com/news-releases/introducing-chainguard-actions-trusted-cicd-workflows-for-developers-and-ai-coding-agents-302715401.html) — Reference for AI-aware CI security
