# UC-30: Self-Optimizing Closed-Loop Tuning

## Category

Alert Analysis

## Summary

The closed-loop variant of [UC-03 (Automated Rule Tuning Recommendations)](03-automated-rule-tuning-recommendations.md). UC-03 generates tuning proposals that humans review and apply; UC-30 closes the loop — analyst dispositions automatically generate, validate, deploy (via mandatory PR review for production), and monitor tuning changes, with guardrails for rollback and blast-radius prediction. Reflects the productized pattern shipped in 2026 by Hunters Pathfinder, Prophet Security, Intezer, and LimaCharlie. The defining characteristic is *autonomy with safety rails*, not "AI auto-applies whatever it thinks."

## Problem Statement

Manual tuning workflows from UC-03 produce a recommendation, queue it for human review, ship to a PR, and deploy. The cycle takes days to weeks per recommendation, and bottlenecks at human reviewer capacity. For a portfolio of 1,000+ rules with continuous noise sources, the bottleneck is not the AI — it's the human. The result is a chronic tuning backlog: rules stay noisy long after the tuning fix is identified, analysts mute their pages and ignore the noise, and the SOC's signal quality degrades.

The 2026 productized response: close the loop. Analyst dispositions on alerts (FP-confirmed, with reason) become the input to an AI that generates the tuning, validates it (in staging, against historical data, against UC-26 atomic tests), commits via mandatory-review PR for production rule changes, deploys, and monitors. Rollback is automatic if predefined safety thresholds trigger. Human review is required for production rule changes; the loop runs autonomously for the *low-blast-radius* parts of tuning (exception-list updates, threshold adjustments within bounds).

The deterministic part — *running* the SIEM analysis, *validating* the tuning condition, *deploying* via the SIEM API — is the same as UC-03. The AI-shaped parts are: (a) *deciding* what to tune, when, with what confidence, given the analyst disposition stream as the trigger, (b) *predicting* the blast radius of a proposed change before deployment, (c) *monitoring* post-deployment for signs the tuning was wrong (recurrence patterns, related-rule degradation, missed-detection signals), and (d) *rolling back* automatically when monitoring trips a threshold.

## Prerequisites (What Your SIEM/SOAR Should Already Handle)

- **All UC-03 prerequisites.** UC-30 builds on UC-03's foundation. If UC-03 is not operating, UC-30 is premature.
- **Analyst disposition data.** A reliable stream of analyst decisions (TP, FP-confirmed, FP-tunable, escalate, insufficient data) with structured reason codes. Without this, UC-30 has no trigger signal. This is Pillar 2 (Process Maturity) work.
- **Detection-as-code with PR-based deployment.** UC-30 commits via PR. If your detections deploy by GUI clicks, you cannot run UC-30. Pillar 4.
- **CI validation gates.** PRs must pass automated checks: syntax validation, [UC-26](../rule-content-engineering/26-continuous-detection-validation.md) atomic tests for the affected rule, [UC-23](../rule-content-engineering/23-synthetic-detection-testing-data.md) synthetic-data fire/no-fire tests, and a validation harness regression check ([validation-harness.md](../../concepts/validation-harness.md)).
- **Rollback infrastructure.** Either reverse-PR + redeploy or feature-flag toggle for rapid rule disable. Recovery within minutes, not hours.
- **Post-deployment monitoring.** Per-rule fire rate, per-entity recurrence, downstream rule co-occurrence patterns, analyst override on previously-auto-closed alerts. These are the rollback triggers.
- **Defined automation scope.** A policy stating which tuning categories are eligible for closed-loop (e.g., exception-list additions for low-severity rules below a certain blast radius) vs. which always require human approval (e.g., rule retirement, query logic changes, critical-severity rule modifications). Without this scope definition, you don't have automation — you have abdication.

## Where AI Adds Value

### 1. Trigger Decision (When to Act)

When an analyst marks an alert as FP-tunable with a reason code, that's a candidate trigger. Not every disposition warrants action — single-event dispositions on novel patterns shouldn't auto-tune. The AI evaluates: how many similar dispositions in the past N days, does the dispositioner have history of accurate dispositions, is the rule already known-degraded, would tuning here create cascading effects.

### 2. Blast-Radius Prediction

Before any deployment, the AI predicts the impact of the proposed change:

- Rules that share the proposed exclusion entity (could cascade)
- Historical alerts that would have been excluded (any TP among them?)
- Adjacent rules that depend on the same data source / parser logic
- Future-attack patterns the exclusion would mask (reasoning over MITRE technique knowledge)

A prediction with concerning radius routes to human review; a low-radius prediction proceeds within the closed loop.

### 3. Confidence-Banded Routing

Borrowed from [UC-11](../ai-assisted-triage/11-llm-triage-verdicts.md): high-confidence + low-blast-radius proposals → auto-PR with auto-approve gates passing → deploy. Medium-confidence → auto-PR with mandatory human review. Low-confidence → no PR; surface as recommendation only (UC-03 mode).

### 4. Post-Deployment Monitoring & Rollback

For each closed-loop deployment, the AI monitors for N days:

- Per-rule fire rate vs. pre-deployment baseline (should drop, not crater)
- Recurrence of similar alerts on different entities (suggests the noise pattern wasn't actually limited to the tuning condition)
- Adjacent rule fire rate changes (cascading effects)
- Analyst overrides on alerts that previously would have been excluded (suggests the exclusion is wrong)

If thresholds trip, the AI generates a rollback PR and pages the on-call DE.

### 5. Cumulative Health Tracking

A rule that's been auto-tuned 12 times in a quarter has a deeper problem than tuning. The AI surfaces these patterns to the human DE: "Rule X has accumulated 14 exception-list entries via UC-30 in 90 days. Total alert volume reduction: 89%. Residual signal: low diversity. Recommend human review for rule retirement or rewrite."

## AI Approach

**Layered: deterministic triggers + LLM judgment + deterministic deployment + deterministic monitoring + LLM diagnosis on rollback.**

1. **Disposition aggregator (deterministic)** — Streams analyst dispositions. Aggregates by rule + reason code + entity pattern.

2. **Trigger evaluation (LLM)** — Per candidate trigger, judge whether to proceed and what confidence band.

3. **Tuning generation (LLM, UC-03 reuse)** — Generate the exception condition with safety analysis, exclusion syntax, residual signal characterization.

4. **Blast-radius prediction (LLM + deterministic)** — Cross-reference proposed change against rule corpus, historical alerts, MITRE technique adjacency.

5. **Confidence-banded routing (deterministic policy)** — Map confidence + blast radius to action: auto-deploy / mandatory-review-PR / recommendation-only.

6. **PR creation + CI validation (deterministic)** — Create PR with proposed change. CI runs syntax validation, UC-26 atomic test on the rule, UC-23 synthetic-data tests, validation harness regression.

7. **Auto-merge gate (deterministic)** — If CI passes AND blast radius is low AND change is in the auto-eligible policy scope, auto-merge. Else queue for human review.

8. **Post-deployment monitoring (deterministic + LLM)** — Watch for N days. LLM produces narrative if rollback triggers fire.

9. **Rollback (deterministic)** — Auto-create rollback PR. Page on-call DE.

10. **Cumulative health surfacing (LLM, periodic)** — Identify rules with chronic auto-tuning patterns; recommend human-led review.

## Data Requirements

### Inputs

| Input | Format | Key Fields Used |
|---|---|---|
| Analyst dispositions | Structured stream | alert_id, rule_id, disposition (TP/FP/etc.), reason_code, dispositioner_id, timestamp |
| Dispositioner reliability data | Per-analyst profile | history of disposition correctness on golden set |
| All UC-03 inputs | Per UC-03 | Rule corpus, entity metrics, target platform syntax |
| Auto-eligibility policy | YAML config | Per rule severity / category / data source: which actions are auto-eligible |
| Historical alerts | SIEM index | For blast-radius backtesting and rollback monitoring |
| Adjacent-rule map | Generated from UC-17 | Rules sharing data sources, fields, MITRE techniques |
| Validation harness golden set | UC-23 + UC-26 outputs | For pre-deployment regression check |
| Rollback policy thresholds | Config | Fire-rate floor, recurrence threshold, override-rate threshold |

### Outputs

**Auto-tuning audit record (one per closed-loop action):**

```json
{
  "action_id": "UC30-2026-04-18-1432-09ab",
  "trigger": {
    "type": "analyst_disposition_aggregate",
    "rule_id": "siem-rule-00421",
    "rule_name": "Suspicious PowerShell Encoded Command",
    "dispositions_in_window": [
      {"alert_id": "alert-2026-04-15-1024", "disposition": "FP-tunable", "reason": "service_account_legitimate", "dispositioner": "analyst-msmith"},
      {"alert_id": "alert-2026-04-16-0913", "disposition": "FP-tunable", "reason": "service_account_legitimate", "dispositioner": "analyst-tjones"},
      {"alert_id": "alert-2026-04-17-1402", "disposition": "FP-tunable", "reason": "service_account_legitimate", "dispositioner": "analyst-msmith"}
    ],
    "trigger_confidence": "high"
  },
  "proposed_change": {
    "type": "exception_list_addition",
    "exclusion_condition": "user.name:\"svc_intune\" AND process.parent.name:\"Microsoft.Management.Services.IntuneWindowsAgent.exe\"",
    "projected_volume_reduction": 1400,
    "projected_volume_reduction_pct": 12.3
  },
  "blast_radius_prediction": {
    "rules_potentially_affected": 1,
    "historical_tps_in_excluded_set_30d": 0,
    "adjacent_rule_co_occurrence_concerns": "none",
    "mitre_technique_evasion_risk": "low",
    "blast_radius_score": "LOW"
  },
  "confidence_band": "high",
  "routing_decision": "auto_pr_with_required_ci_gates",
  "ci_validation": {
    "syntax_check": "PASS",
    "uc26_atomic_test": "PASS",
    "uc23_synthetic_data_tests": "PASS",
    "validation_harness_regression": "PASS"
  },
  "deployment": {
    "pr_url": "https://github.com/org/detection-as-code/pull/4321",
    "merged_at": "2026-04-18T15:12:33Z",
    "deployed_at": "2026-04-18T15:18:21Z",
    "human_reviewer": "automated"
  },
  "post_deployment_monitoring": {
    "watch_window_days": 14,
    "watch_until": "2026-05-02T15:18:21Z",
    "rollback_triggers": [
      {"metric": "rule_fire_rate", "threshold": "drop_below_5pct_of_baseline", "current": "67pct_of_baseline", "status": "OK"},
      {"metric": "recurrence_on_unrelated_entities", "threshold": "more_than_10_distinct_entities_in_24h", "current": "2_entities", "status": "OK"},
      {"metric": "adjacent_rule_silence", "threshold": "any_adjacent_rule_silent_3_consecutive_days", "current": "no_silence", "status": "OK"},
      {"metric": "analyst_override_on_excluded", "threshold": "any_analyst_marks_excluded_as_TP", "current": "no_overrides", "status": "OK"}
    ],
    "status": "MONITORING"
  }
}
```

**Cumulative health alert (when chronic auto-tuning detected):**

```
=============================================================================
CUMULATIVE TUNING ALERT — Human Review Required
Rule: siem-rule-00421 (Suspicious PowerShell Encoded Command)
Generated: 2026-04-18
=============================================================================

Closed-loop tuning history (90 days):
  Auto-tuning actions:           14
  Total volume reduction:        89% (from 12,847/30d to 1,425/30d)
  Exception list size:           14 entries (started at 0)
  Rule effectively detects:      4 users, 12 hosts, 23 command-line clusters

Concerns:
  - Exception-list growth rate exceeds threshold (14 in 90 days)
  - Each tuning addressed a specific service account or admin pattern
  - Cumulative effect: rule now detects ~5% of original surface
  - Residual signal cardinality is moderate, not high
  - 6 of the 14 exclusions could potentially be consolidated into broader patterns

Recommendation: Human review for rule rewrite or retirement.
  Option A: Rewrite rule with positive criteria (what behavior IS interesting)
            rather than progressive exclusions of what isn't.
  Option B: Retire and replace with two narrower rules (one for service-account
            patterns, one for interactive-user patterns).
  Option C: Accept current state and stop further auto-tuning on this rule.

Suggested next action: Schedule rule review meeting with detection engineering.
```

## Implementation Notes

- **Define the auto-eligibility policy in writing.** The single most important artifact in this use case is the policy that defines what UC-30 may do without human approval. Get CISO sign-off. Update quarterly. A team that runs UC-30 without an explicit policy is performing auto-tuning by accident.
- **Auto-eligible categories should be a small subset.** Suggested defaults: exception-list additions on low-and-medium-severity rules where blast radius is LOW and dispositioner reliability is high. Everything else routes to human PR.
- **Mandatory CI gates are non-negotiable.** Skipping the validation harness because "the model said it was fine" is exactly the failure mode this use case is meant to prevent.
- **Tier human reviewers.** Not every PR needs the senior DE's review. Low-impact PRs can route to junior DEs as a learning queue; high-impact to senior. Separate-track human review prevents reviewer burnout.
- **Watch the dispositioner-reliability axis carefully.** A junior analyst's dispositions should not bias the AI toward tuning patterns the senior team would reject. Weight dispositions by analyst reliability on the validation harness golden set.
- **Rollback monitoring duration matters.** 14 days is a reasonable default. Long enough to catch slow-burn issues; short enough to not hold up the lifecycle. Adjust by rule criticality.
- **The escalation to human happens twice.** First, at PR creation for medium-confidence proposals. Second, at cumulative-health alert when a rule has been auto-tuned too often. The second is often more valuable than the first.
- **Adjacent-rule monitoring catches cascading damage.** When a tuning on Rule A silently affects Rule B's fire rate (because they share parser logic, data sources, or correlation flows), this is exactly the failure mode hard to catch at deploy time. Post-deployment monitoring catches it.
- **Vendor implementations exist.** Hunters Pathfinder ships closed-loop self-optimizing detections. Prophet Security advertises detection-engineering feedback from triage. Intezer's "AI-Driven Detection Engineering" capability is the same pattern. LimaCharlie's daily MDR pipeline includes tuning-from-disposition. These are productized; build-vs-buy decision applies.

## Dependencies

- **Prerequisite — Pillar 2 (Process Maturity)**: Structured analyst disposition with reason codes is required.
- **Prerequisite — Pillar 3 (Human Element)**: Leadership must approve an "AI Error Budget" for closed-loop tuning errors. Without this approval, the use case cannot run.
- **Prerequisite — Pillar 4 (Technology Stack)**: Detection-as-code with PR workflow.
- **Prerequisite — Pillar 5 (Metrics & Feedback)**: Continuous monitoring infrastructure for rollback triggers.
- [UC-03: Automated Rule Tuning Recommendations](03-automated-rule-tuning-recommendations.md) — The recommendation-generation pattern UC-30 builds on.
- [UC-23: Synthetic Detection Testing Data Generation](../rule-content-engineering/23-synthetic-detection-testing-data.md) — Pre-deployment validation tests.
- [UC-26: Continuous Detection Validation](../rule-content-engineering/26-continuous-detection-validation.md) — Atomic tests in CI before merge.
- [Validation Harness](../../concepts/validation-harness.md) — Per-use-case golden set and regression gates.
- [Adversarial AI Considerations](../../concepts/adversarial-ai-considerations.md) — Specifically the feedback poisoning attack.

## Complexity Assessment

| Dimension | Rating | Notes |
|---|---|---|
| Data engineering | High | Disposition stream, dispositioner profiles, adjacent-rule map, blast-radius modeling, post-deployment monitoring all require integration. |
| AI/ML complexity | Medium-High | Trigger judgment + blast-radius reasoning + cumulative-health pattern recognition. Calibration matters. |
| Integration effort | High | Touches SOAR (disposition capture), detection-as-code repo (PR creation, merge), CI (validation gates), SIEM (deployment, monitoring), ticketing (cumulative health alerts). |
| Overall | **Very High** | The most operationally-impactful and operationally-risky use case in the alert-analysis category. Build only after UC-03 is mature. |

## Real-World Considerations

- **The "AI Error Budget" framing is the change-management foundation.** Leadership must explicitly accept that closed-loop tuning will sometimes be wrong, at a measured rate. Without this, the first wrong tuning creates an incident that ends the program. With it, the conversation becomes "how much error is acceptable for the time savings" — a tractable question.
- **Adversaries can exploit the closed loop.** An attacker who knows your SOC runs UC-30 can craft activity that mimics common FP patterns, hoping to seed an auto-tune that masks future malicious activity. Protect with: dispositioner-reliability weighting, blast-radius prediction including future-attack reasoning, periodic random sampling of auto-closed alerts for human review. See [adversarial-ai-considerations.md](../../concepts/adversarial-ai-considerations.md) Attack 4 (Feedback Loop Poisoning).
- **Audit trail is non-negotiable.** Every closed-loop action must be reconstructable: trigger, proposed change, blast-radius prediction, CI validation result, PR, deployment, monitoring outcomes. Auditors will ask why a specific exception was added. The answer must be in writing.
- **Cumulative health alerts are often the most valuable output.** The AI catches "this rule has been tuned to death" before a human notices. Acting on these alerts (rule rewrite, retirement, or accepting the current state) is detection-engineering hygiene.
- **Roll out narrowly first.** Start UC-30 on one rule family with low blast radius (e.g., specific noisy SaaS audit rules). Measure 60 days. Expand. Don't enable across the corpus on day one.
- **Track dispositioner-reliability over time.** A reliable dispositioner today may become unreliable after burnout, role change, or compromise. Continuous tracking is required, not a one-time profile.
- **Closed-loop tuning is what the vendor "self-optimizing detection" claims actually mean.** Customers asking "why don't you do what Hunters Pathfinder does?" are asking for UC-30. The build-vs-buy decision rests on whether the vendor's auto-eligibility policy and rollback safety match your risk appetite.

## Related Use Cases

- [UC-03: Automated Rule Tuning Recommendations](03-automated-rule-tuning-recommendations.md) — UC-30 closes the loop on UC-03's recommendations.
- [UC-23: Synthetic Detection Testing Data Generation](../rule-content-engineering/23-synthetic-detection-testing-data.md) — Pre-deployment validation
- [UC-26: Continuous Detection Validation](../rule-content-engineering/26-continuous-detection-validation.md) — CI gate for atomic tests
- [UC-04: Detection Drift Monitoring](04-detection-drift-monitoring.md) — Post-deployment drift is one of the rollback triggers
- [UC-31: Detection Content Provenance](../rule-content-engineering/31-detection-content-provenance.md) — Auto-applied changes must carry full provenance
- [UC-11: LLM Triage Verdicts](../ai-assisted-triage/11-llm-triage-verdicts.md) — Confidence-banded routing pattern shared

## References

- Hunters Security, [Pathfinder AI](https://www.hunters.security/pathfinder-ai) — Reference vendor implementation of self-optimizing detections
- Hunters Security, [Pathfinder AI Part 2 — Autonomous Investigation](https://www.hunters.security/en/blog/pathfinder-ai-part-2)
- Prophet Security, [Platform — closed-loop detection from triage data](https://www.prophetsecurity.ai/platform)
- Intezer, [AI-Driven Detection Engineering capability](https://intezer.com/forensic-ai-soc/)
- LimaCharlie, [Agentic MDR Pipeline](https://limacharlie.io/blog/agentic-mdr-pipeline-detection-engineering-at-scale) — Daily auto-tuning across customer tenants
- AiStrike, [Continuous Detection Engineering at RSAC 2026](https://ai-techpark.com/aistrike-launches-continuous-detection-engineering-at-rsa-2026/)
- Anton Chuvakin, ["Beyond 'Is Your SOC AI Ready?'"](https://medium.com/anton-on-security/beyond-is-your-soc-ai-ready-plan-the-journey-c9654a9ee175) — Defines AI Error Budget concept underpinning closed-loop policy
