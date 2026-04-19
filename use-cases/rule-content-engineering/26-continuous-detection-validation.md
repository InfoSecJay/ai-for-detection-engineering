# UC-26: Continuous Detection Validation (Atomic Test CI Loop)

## Category

Rule Content Engineering

## Summary

Closes the long-standing "did the rule actually fire?" gap by orchestrating real attack execution against detection content on a continuous basis. For each detection rule, AI selects appropriate Atomic Red Team / Caldera / Stratus / custom tests, schedules execution against a test environment, evaluates whether the rule fired with the expected severity and entities, and produces a coverage report with remediation suggestions for non-firing rules. Distinguishes from UC-23 (synthetic test data — generated logs without execution) by orchestrating real attack execution and observing the full ingest-to-alert pipeline.

## Problem Statement

The most common detection-engineering myth is that a rule's existence implies its function. In reality:

- A rule may fail because the data source isn't ingested in the test environment
- A rule may fail because a parser change silently dropped a field
- A rule may fail because a tuning exclusion grew to swallow the entire detection surface
- A rule may fail because the upstream EDR was changed and now reports events differently
- A rule may fire but with wrong severity, wrong entities, or wrong tactic mapping
- A rule may fire on the simulated attack but be silently bypassed by trivial variants the simulator doesn't model

Continuous detection validation is the discipline of running real attacks against your detection stack on a schedule — daily, weekly, or per-deploy — and measuring fire rates, severities, entity completeness, and time-to-detect. It is the only way to know, with evidence, whether your rule library functions as advertised.

The deterministic part — *executing* an Atomic Red Team test, *querying* the SIEM for the resulting alert, *recording* fire/no-fire — is straightforward orchestration. The AI-shaped parts are: (a) selecting which tests apply to a given rule (test-to-rule mapping at scale across thousands of tests and rules), (b) generating new tests for rules that lack coverage, (c) reasoning about *why* a rule failed (data missing? parser broken? exception too broad? evasion?), and (d) producing remediation work orders that are specific enough for a DE to act on.

## Prerequisites (What Your SIEM/SOAR Should Already Handle)

- **A safe, isolated test environment** that mirrors production telemetry pipelines. Hosts with EDR enabled, identity provider with test accounts, network with the same logging path. The environment must be safe to attack — no production data, no production credentials, no impact on production systems.
- **Atomic test execution infrastructure.** Atomic Red Team (PowerShell + invoke-atomicredteam), Caldera, Stratus Red Team for cloud, custom emulation tools. Orchestrated via CI runner (GitHub Actions, GitLab CI, Jenkins) or dedicated runners (Sliver, Mythic for command-and-control simulation).
- **SIEM API access for alert queries.** After executing a test, the validation pipeline queries the SIEM for matching alerts — by rule ID, by host, by time window. Standard SIEM API capability.
- **Test-to-rule mapping inventory.** A database mapping each Atomic test to the rule(s) it should trigger. This starts as manual mapping; UC-26 grows it via AI.
- **Detection rule corpus accessible programmatically.** Same prerequisite as UC-17, UC-19, UC-24.
- **Telemetry latency baseline.** Know how long it takes for a real event to traverse ingest → parse → enrich → match. Validation must wait the appropriate window before declaring no-fire.

## Where AI Adds Value

### 1. Test-to-Rule Mapping at Scale

Atomic Red Team has 1,000+ tests across 200+ ATT&CK techniques. Detection rule libraries have thousands of rules across the same techniques. The N×M mapping is intractable to maintain by hand. The AI reads each rule's logic and each test's procedure, scores semantic match, and produces:

- **Coverage matrix**: which rules should fire for which tests, ranked by confidence
- **Coverage gaps**: techniques where Atomic tests exist but no rules map (or vice versa)
- **Redundancy**: rules that should detect the same test (defense-in-depth or unintended duplication)

### 2. Test Synthesis for Rule Gaps

Some rules have no Atomic equivalent. The AI proposes new test specifications: command sequences, expected log signatures, MITRE technique mappings, target environments. Output is a test specification (PowerShell script for Atomic Red Team format, Caldera ability YAML, Stratus configuration) that a human reviews and adds to the test library.

### 3. Failure Diagnosis (Why Didn't the Rule Fire?)

When a test runs and the expected rule doesn't fire, the AI receives:
- The test execution log (what commands ran, what files were created, what network traffic was sent)
- The SIEM query results around the test window (what alerts *did* fire)
- The expected rule's query
- The rule's recent change history and exception list
- Telemetry inventory for the data sources the rule depends on

It produces a diagnosis: data source not ingested, parser dropped field X, exception list now matches the test, query semantically broken by recent change, evasion. The diagnosis is structured and references specific evidence — not a guess.

### 4. Remediation Work Order Generation

Given the diagnosis, the AI generates a remediation work order: tune the exception list, restore the parser, ingest the missing data source, retire-and-rewrite the rule, accept-the-gap with rationale. Pairs with [UC-03](../alert-analysis/03-automated-rule-tuning-recommendations.md) and feeds the detection-engineering backlog.

### 5. Adversarial Test Variant Generation

A rule that fires on `Atomic Test #1 — Mimikatz Lsadump` may be bypassed by trivial variants — different process name, syscall-based dumper, hash-only credential access. The AI generates variant tests that exercise the rule's evasion surface, then reports rules that detect the canonical test but miss the variants. This is the "Continuous Detection Validation" framing in 2026: validation that includes evasion, not just canonical detection.

## AI Approach

**Pipeline: orchestration + LLM mapping + LLM diagnosis + LLM variant generation.**

1. **Mapping pass (LLM)** — Embed rule queries and Atomic test procedures into shared vector space. LLM judges semantic match and produces test-to-rule mapping with confidence.

2. **Test scheduler (deterministic)** — For each rule, schedule its mapped tests at appropriate cadence (daily for critical, weekly for medium, per-deploy on rule change).

3. **Test executor (deterministic)** — Run the test in the isolated environment. Capture execution log.

4. **Validation pass (deterministic)** — Wait for telemetry latency window. Query SIEM for alerts matching expected rule. Record fire/no-fire/wrong-severity/wrong-entities.

5. **Diagnosis pass (LLM)** — For each failure, LLM produces structured diagnosis with citations.

6. **Variant generation (LLM, periodic)** — For high-criticality rules, generate evasion variants. Re-run validation with variants.

7. **Reporting (deterministic + LLM)** — Coverage dashboard (deterministic). Per-rule narrative on validation status (LLM, similar to UC-01 portfolio narrative).

## Data Requirements

### Inputs

| Input | Format | Key Fields Used |
|---|---|---|
| Detection rule corpus | Platform-native | Rule body, name, MITRE tags, severity, data source |
| Atomic Red Team test library | YAML | Test name, technique ID, executor, command, prerequisites, cleanup |
| Caldera ability library | YAML | Ability ID, technique, command, payload |
| Stratus Red Team techniques | Go module | Technique ID, attack, detonate, revert |
| Test-to-rule mapping | YAML/JSON (grown by AI, validated by human) | `test_id`, `expected_rules[]`, `confidence`, `verified_by_human` |
| Test execution environment manifest | YAML | Hosts available, EDR deployed, identity test accounts, network path |
| SIEM alert index | Platform-native | Standard alert schema |
| Rule change history | Git log on detection-as-code repo | Commit history per rule, exception list changes |
| Data source ingest health | Pipeline metrics | Per-source ingest rate, parser error rate |

### Outputs

**Per-rule validation record:**

```json
{
  "rule_id": "siem-rule-00421",
  "rule_name": "Suspicious PowerShell Encoded Command",
  "validation_window": {"start": "2026-04-15T00:00:00Z", "end": "2026-04-22T00:00:00Z"},
  "tests_executed": [
    {
      "test_id": "atomic-T1059.001-001",
      "test_name": "Run Encoded PowerShell Command",
      "executions": 7,
      "fires": 7,
      "expected_severity": "medium",
      "observed_severity": "medium",
      "expected_entities": ["host.name", "user.name", "process.command_line"],
      "observed_entities": ["host.name", "user.name", "process.command_line"],
      "median_time_to_detect_seconds": 45,
      "status": "PASS"
    },
    {
      "test_id": "atomic-T1059.001-013-variant-syscall-loader",
      "test_name": "PowerShell Encoded Command via Direct Syscall Loader",
      "executions": 7,
      "fires": 0,
      "status": "FAIL",
      "diagnosis": {
        "category": "evasion",
        "reasoning": "The variant uses a custom EXE loader that executes encoded PowerShell via direct syscalls without spawning powershell.exe. The rule's primary condition `process.name: powershell.exe` is bypassed. The encoded payload exists in the loader's command-line args but the process.name match fails.",
        "evidence": [
          {"claim": "rule requires process.name == powershell.exe",
           "source": "rule_query",
           "excerpt": "process.name:\"powershell.exe\" AND process.command_line:(*-enc* OR *-EncodedCommand*)"},
          {"claim": "test variant uses custom loader",
           "source": "test_specification",
           "excerpt": "loader.exe -enc <base64>"}
        ],
        "remediation_work_order": {
          "type": "rule_enhancement",
          "title": "Detect encoded PowerShell loaded via non-powershell.exe processes",
          "approach": "Add a secondary detection that matches encoded command-line patterns regardless of process name, scoped to non-system processes with -enc/-EncodedCommand flags.",
          "estimated_effort": "1-2 days",
          "priority": "medium"
        }
      }
    }
  ],
  "coverage_summary": {
    "tests_passed": 1,
    "tests_failed_evasion": 1,
    "tests_failed_data_gap": 0,
    "tests_failed_parser": 0,
    "tests_failed_rule_logic": 0
  }
}
```

**Validation dashboard (portfolio-level):**

```
=============================================================================
DETECTION VALIDATION REPORT — Week of 2026-04-15 to 2026-04-22
=============================================================================

Rules in scope:                    1,847
Rules with at least one test:      1,612 (87.3%)
Rules with no test coverage:         235 (12.7%)  ← gap

Tests executed (with variants):    14,221
Tests passed:                      11,089 (78.0%)
Tests failed:                       3,132 (22.0%)

Failure breakdown:
  ├─ Evasion (variant bypassed rule):       1,887 (60.3% of failures)
  ├─ Data source gap:                         741 (23.7%)
  ├─ Parser regression:                       312 (10.0%)
  ├─ Rule logic broken:                       128 ( 4.1%)
  ├─ Exception list too broad:                 64 ( 2.0%)

Top 10 critical-severity rules failing validation:
  1. T1003.001 LSASS Memory — 4 of 6 variants bypassed
  2. T1078.004 Cloud Account Abuse — data source gap (CloudTrail not in test env)
  ...

Work orders generated:                       412
  Auto-applied (low-risk):                    87
  Queued for review:                         325
```

## Implementation Notes

- **Isolation is non-negotiable.** Atomic tests execute real attacker behavior. A test that escapes the isolation environment is a self-inflicted incident. Use dedicated VLAN, dedicated test accounts, dedicated EDR instance, no production data, no production cred. Reset between runs.
- **Telemetry latency tolerance must be tuned.** A rule may fire 30 seconds after the test in one environment and 5 minutes in another. The validation pipeline must wait the longer window. Calibrate per data source.
- **Test mapping accuracy is gradient, not binary.** A test may be a perfect, partial, or tangential match for a rule. The AI's mapping confidence should drive how the result is interpreted. Low-confidence mappings need human verification before becoming fixtures.
- **Generate variant tests sparingly.** A rule with 1 canonical test passing is fine. A rule with 1 canonical + 5 variants where the variants always pass adds little. Focus variant generation on critical-severity rules and rules with known evasion vectors.
- **Diagnosis quality depends on input completeness.** Without the rule change history and ingest health data, the AI cannot distinguish "rule logic broken" from "parser regression." Bring all signals into the diagnosis prompt.
- **Wire into CI on rule changes.** Every rule modification should re-run its mapped tests before merge. This is the most valuable trigger — catch regressions at the source.
- **Don't auto-apply remediation work orders for critical rules.** AI-generated tuning suggestions can quietly disable detection. Critical-severity rule changes require human review, always.

## Dependencies

- **Prerequisite — Pillar 1 (Data Foundations)**: Test environment must replicate production telemetry pipelines.
- **Prerequisite — Pillar 4 (Technology Stack)**: CI infrastructure capable of running attack simulations.
- **Prerequisite — Pillar 5 (Metrics & Feedback)**: Validation results must route to detection-engineering backlog as work orders.
- [UC-23: Synthetic Detection Testing Data Generation](23-synthetic-detection-testing-data.md) — UC-23 generates logs synthetically; UC-26 orchestrates real execution. Complementary, not redundant.
- [UC-03: Automated Rule Tuning Recommendations](../alert-analysis/03-automated-rule-tuning-recommendations.md) — Diagnosis-driven remediation pairs with tuning recommendations.
- [UC-04: Detection Drift Monitoring](../alert-analysis/04-detection-drift-monitoring.md) — A rule that's silent in production AND failing validation has a different problem than a rule that's silent in production but passing validation.

## Complexity Assessment

| Dimension | Rating | Notes |
|---|---|---|
| Data engineering | High | Requires test execution environment, telemetry parity with production, mapping inventory, change history, ingest health. Significant up-front investment. |
| AI/ML complexity | Medium | Mapping (embedding + LLM) is tractable. Diagnosis prompting is more nuanced — must reason across rule, test, and environmental data. |
| Integration effort | High | Touches detection-as-code repo, CI pipelines, attack simulation tools, SIEM, ticketing. Multi-team. |
| Overall | **High** | The single most operationally impactful capability in this catalog — and proportionally the heaviest to build. |

## Real-World Considerations

- **Validation environments lag production.** A new SaaS app gets ingested into production on day 1 and into the test environment on day 47. Until parity is achieved, validation results have asterisks. Acknowledge this explicitly in reporting; don't pretend the test environment is production.
- **Atomic Red Team coverage is uneven.** Endpoint techniques are well-covered. Cloud techniques (handled by Stratus) are growing. Identity / SaaS techniques are sparse. Network and OT techniques have very thin libraries. Coverage gaps in the test corpus are worth tracking explicitly.
- **Validation telemetry can pollute production analytics.** UC-01 portfolio metrics will see unusual spikes from validation runs. Tag validation traffic at ingest (via dedicated account/host/source IP) and exclude from production analytics.
- **Continuous validation changes the threat model.** Once an attacker knows you validate continuously, they can theoretically time activity around validation runs. Mitigate by randomizing validation schedules and including out-of-band human-led red team on top of automated validation.
- **Detection coverage isn't binary, even after validation.** A passing validation says "the rule fires on this specific test in this specific environment." It does not say "the rule will catch every attacker who attempts this technique." Treat continuous validation as a tripwire for regressions, not a guarantee of detection.
- **Vendor capabilities exist.** AttackIQ, Picus, Cymulate, SafeBreach offer breach-and-attack simulation; SANS SEC598 productizes the agentic CDV pattern; Skyhawk and others are pushing autonomous red team. AiStrike's "Continuous Detection Engineering" framing at RSAC 2026 productized this loop. LimaCharlie's daily MDR pipeline runs the same pattern. For most environments, vendor-native is faster; this use case applies for environments needing customization or self-hosted.

## Related Use Cases

- [UC-23: Synthetic Detection Testing Data Generation](23-synthetic-detection-testing-data.md) — Synthetic logs (without execution) for testing parsing-side logic; UC-26 is real-execution-side
- [UC-03: Automated Rule Tuning Recommendations](../alert-analysis/03-automated-rule-tuning-recommendations.md) — Validation failures often produce tuning work orders
- [UC-04: Detection Drift Monitoring](../alert-analysis/04-detection-drift-monitoring.md) — Validation distinguishes "rule silent because no attacks" from "rule silent because broken"
- [UC-06: MITRE ATT&CK Posture Scoring](../posture-assessment/06-mitre-attack-posture-scoring.md) — Validation results feed posture scoring (a passing-validation rule scores higher than an unvalidated rule)
- [UC-19: Detection Rule Generation](19-detection-rule-generation.md) — Generated rules should be validated before deployment

## References

- Red Canary, [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) — The canonical test library
- MITRE, [CALDERA](https://github.com/mitre/caldera) — Adversary emulation platform
- DataDog, [Stratus Red Team](https://github.com/DataDog/stratus-red-team) — Cloud-native attack simulation
- SANS, [SEC598: AI and Security Automation for Red, Blue, Purple Teams](https://www.sans.org/cyber-security-courses/ai-security-automation) — Continuous detection engineering pedagogy
- SANS, ["Always-On Purple Team / Detection CI/CD" webcast](https://www.sans.org/webcasts/always-purple-team-automated-ci-cd-detection-engineering)
- AttackIQ, [Continuous Security Validation](https://www.attackiq.com/) — Commercial BAS reference
- Picus Security, [Security Validation Platform](https://www.picussecurity.com/) — Commercial BAS reference
- Cymulate, [Continuous Security Validation](https://cymulate.com/) — Commercial BAS reference
- AiStrike, [Continuous Detection Engineering at RSAC 2026](https://ai-techpark.com/aistrike-launches-continuous-detection-engineering-at-rsa-2026/) — Productized framing
- LimaCharlie, [Agentic MDR Pipeline](https://limacharlie.io/blog/agentic-mdr-pipeline-detection-engineering-at-scale) — Reference implementation of daily auto-validation
- Skyhawk Security, [Autonomous Red Team with Agentic AI](https://www.globenewswire.com/news-release/2025/12/02/3197994/0/en/Skyhawk-Security-Strengthens-Autonomous-Red-Team-with-Agentic-AI-Enabling-Continuous-Security-Control-Validation.html)
- arXiv, [CTI-REALM: Detection Rule Generation Benchmark](https://www.microsoft.com/en-us/research/publication/cti-realm-benchmark-to-evaluate-agent-performance-on-security-detection-rule-generation-capabilities/) — Methodology applies to validation eval
