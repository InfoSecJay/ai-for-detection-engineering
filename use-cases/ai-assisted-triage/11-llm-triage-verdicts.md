# UC-11: LLM Triage Verdicts

## Category

AI-Assisted Triage

## Summary

After SOAR playbooks assemble a complete enrichment package for an alert — threat intel lookups, asset context, identity data, historical activity — an LLM evaluates all of that context together and produces a structured triage verdict with reasoning. This is the step that sits between "gather all the facts" (deterministic) and "decide what this means" (requires judgment). The LLM produces a verdict (true positive, false positive, or escalate), a confidence level, cited reasoning, and recommended next steps.

## Problem Statement

SOAR playbooks are excellent at gathering context: look up the IP in threat intel, pull the CMDB record for the host, check the user's AD group membership, query for prior alerts on the same entity. But after all that enrichment is assembled, the playbook hits a wall. The decision logic for whether an alert is a true positive or false positive requires weighing multiple signals together — and those signals are frequently ambiguous.

A playbook can encode simple decision trees: "if threat intel match AND host is critical, escalate." But real triage decisions involve weighing combinations of weak signals, accounting for context that changes the meaning of an indicator, and recognizing patterns that are collectively suspicious even when each individual data point is benign. Writing deterministic branching logic for every possible combination of enrichment results across thousands of detection rules is not feasible. This is a reasoning problem, and it is where LLMs provide genuine value.

Without this capability, analysts spend the majority of their triage time doing what the LLM can do: reading through the enrichment data, mentally weighing the signals, and forming a judgment. The enrichment is already done — the bottleneck is the reasoning step.

## Prerequisites (What Your SIEM/SOAR Should Already Handle)

Before an LLM can produce a meaningful triage verdict, the following must be in place and working reliably:

- **Alert enrichment via SOAR playbooks:** Threat intelligence lookups (IP, domain, hash reputation), asset/CMDB context (host criticality, owner, business unit, OS, role), identity/AD context (user role, group membership, privileged account status, recent activity), vulnerability scan data (host exposure, patch status), geolocation/ASN data for IPs. These are API calls in playbook steps — not AI.
- **Alert grouping by entity:** The SIEM should already correlate related alerts by shared entities (same user, same host, same source IP) within a time window. This is a correlation rule, not an AI task.
- **Historical alert context:** The SOAR playbook should query for prior alerts involving the same entities — "has this user triggered this rule before? How many times in the last 30 days?" This is a SIEM query.
- **Structured alert data:** Alert records must contain normalized fields (rule name, severity, MITRE ATT&CK mapping, source event fields) in a consistent schema. If alerts are unstructured or inconsistently formatted, fix the SIEM ingest pipeline first.
- **Basic automated response actions:** Auto-closing known benign patterns, auto-escalating known critical patterns — these are SOAR playbook conditions that should already be handling the easy cases before any alert reaches the LLM.

The LLM should only see alerts that survive deterministic filtering — the ambiguous middle ground that playbook logic cannot resolve.

## Where AI Adds Value

The LLM performs the reasoning step that deterministic tooling cannot: evaluating all enrichment context together and forming a judgment about the alert's significance. Specifically:

1. **Weighing ambiguous signals.** A single indicator is rarely conclusive. The LLM considers: the IP has a low threat intel score (not blocklisted, but recently registered), the user is a service account with admin privileges, the activity occurred outside business hours, and the host is a domain controller. No single fact is damning, but together they warrant escalation. A SOAR playbook would need explicit branching logic for this exact combination — which doesn't scale across thousands of rule types.

2. **Recognizing collectively suspicious patterns.** Individual enrichment results may each appear benign in isolation. The LLM can recognize that the combination is unusual: "This service account has never connected from this source IP before, and the destination is a file share that this account has never accessed — while each fact alone is not malicious, the behavioral deviation is significant."

3. **Explaining the reasoning.** The LLM doesn't just output TP/FP — it produces a written explanation citing specific evidence from the enrichment data. This is immediately useful for the analyst reviewing the verdict and for downstream incident documentation.

4. **Contextualizing against rule intent.** The LLM considers what the detection rule is designed to catch and evaluates whether the observed activity matches that intent, not just whether the technical indicators match the rule's query.

## AI Approach

**LLM prompting with structured context package.**

The approach is straightforward prompt engineering, not fine-tuning or custom model training. The SOAR playbook assembles a structured context package (JSON or structured text) containing the alert data and all enrichment results. This package is submitted to an LLM with a system prompt that defines the expected output format, evaluation criteria, and constraints.

Key architectural elements:

- **System prompt** defines the analyst persona, verdict format, confidence scale, and rules for evidence citation. The prompt should include few-shot examples of correctly reasoned verdicts.
- **Context package** is assembled by the SOAR playbook in a structured format. The LLM does not query any systems directly — all data is pre-fetched and included in the prompt.
- **Output schema** is enforced via structured output (JSON mode or function calling) to ensure consistent parsing of verdicts by downstream automation.
- **Confidence calibration** — the system prompt defines what "high," "medium," and "low" confidence mean in terms of the evidence threshold required, not just the model's self-assessed certainty.

This is a single-turn LLM call, not an agentic loop. The LLM receives a complete context package and returns a verdict. No tool use, no multi-step reasoning chains, no external queries.

## Data Requirements

### Inputs

| Input | Format | Key Fields Used |
|---|---|---|
| Alert record | SIEM alert JSON | `rule.name`, `rule.id`, `kibana.alert.severity`, `kibana.alert.rule.threat` (MITRE mapping), `host.name`, `user.name`, `process.name`, `process.command_line`, `source.ip`, `destination.ip`, `event.action`, `@timestamp` |
| Threat intel enrichment | SOAR enrichment output (JSON) | IP/domain/hash reputation scores, threat feed matches, first/last seen dates, associated malware families |
| Asset/CMDB context | SOAR enrichment output (JSON) | Host criticality tier, business unit, asset owner, OS version, role (server/workstation/DC), network zone |
| Identity/AD context | SOAR enrichment output (JSON) | User role, group memberships, privileged account flag, department, manager, employment status, last password change |
| Vulnerability context | SOAR enrichment output (JSON) | Critical/high vulnerability count on host, patch compliance status, days since last scan |
| Historical alert context | SIEM query results (JSON) | Prior alert count for same entity (7/30/90 days), prior rule triggers, prior verdicts if available |
| Geolocation/ASN | SOAR enrichment output (JSON) | Source IP country, city, ASN name, VPN/proxy/Tor flag |

> **Note:** Alert data follows the SIEM's standard alert schema with normalized source event fields. Rule files follow their format's defined schema (Elastic TOML, Sigma YAML, Splunk YAML, etc.). These are structured, documented formats — see [data-requirements/](../../data-requirements/) for platform-specific field references.

### Outputs

The LLM produces a structured triage verdict containing:

- **Verdict:** True Positive, False Positive, or Escalate (requires human review)
- **Confidence:** High (>85%), Medium (60-85%), Low (<60%)
- **Reasoning:** 2-5 sentences citing specific evidence from the enrichment data
- **Key evidence:** Bulleted list of the most significant data points supporting the verdict
- **Recommended next steps:** Specific actions for the analyst or SOAR playbook
- **MITRE context:** Whether the observed activity aligns with the mapped technique

**Concrete output example:**

```json
{
  "verdict": "escalate",
  "confidence": "medium",
  "confidence_score": 0.72,
  "reasoning": "The alert fired on encoded PowerShell execution (rule: 'Suspicious Encoded PowerShell Command') on host DC-PROD-03, a Tier-1 domain controller. The executing user SVC-SCCM is a privileged service account. While SVC-SCCM has triggered this rule 14 times in the past 30 days — typically from SCCM deployment tasks — this instance differs in two ways: (1) the encoded payload decodes to an Invoke-WebRequest to an external IP (185.220.101.34) that has a medium-confidence threat intel hit associated with Cobalt Strike C2 infrastructure, and (2) this is the first time SVC-SCCM has triggered this rule on a domain controller rather than on member servers in the SCCM deployment scope. The combination of a known-noisy service account operating outside its normal scope on a critical asset, contacting a suspicious external IP, warrants analyst review.",
  "key_evidence": [
    "Host DC-PROD-03 is a Tier-1 domain controller (asset criticality: critical)",
    "SVC-SCCM has 14 prior triggers in 30 days — but all on member servers, never on domain controllers",
    "Decoded payload contains Invoke-WebRequest to 185.220.101.34",
    "185.220.101.34 flagged by 2/6 threat intel feeds as Cobalt Strike C2 (medium confidence)",
    "Activity occurred at 02:47 UTC — outside the SCCM maintenance window (typically 06:00-08:00 UTC)"
  ],
  "recommended_next_steps": [
    "Verify with SCCM team whether any deployment task targeted DC-PROD-03",
    "Query EDR for full process tree on DC-PROD-03 from SVC-SCCM in the last 4 hours",
    "Check network logs for any successful connection to 185.220.101.34",
    "If no legitimate SCCM activity confirmed, escalate to incident response"
  ],
  "mitre_alignment": "T1059.001 (Command and Scripting Interpreter: PowerShell) — activity is consistent with technique. Encoded payload with external download is higher fidelity than typical SVC-SCCM noise."
}
```

This example illustrates the core value: the LLM recognized that a historically noisy alert (14 prior triggers from SVC-SCCM) was different *this time* because of contextual factors (wrong host, wrong time, suspicious destination) that a simple "suppress SVC-SCCM" exclusion would have missed.

## Implementation Notes

**Prompt engineering is the primary technical work.** The quality of triage verdicts depends almost entirely on:

1. **Context package quality.** Garbage in, garbage out. If the SOAR playbook delivers incomplete or stale enrichment data, the LLM will produce unreliable verdicts. Invest in enrichment reliability before investing in prompt tuning.

2. **System prompt design.** The system prompt must clearly define:
   - What constitutes sufficient evidence for each verdict (TP/FP/escalate)
   - How to handle missing enrichment data (e.g., "if threat intel lookup failed, note this as a gap and reduce confidence")
   - The expected output schema with field descriptions
   - Few-shot examples covering common alert types and edge cases
   - Instructions to cite specific data points, not make generic statements

3. **Output parsing and validation.** Use structured output (JSON mode) to ensure the verdict can be parsed by downstream automation. Validate that required fields are present and values are within expected ranges. Reject and retry malformed outputs.

4. **Latency considerations.** Adding an LLM call to the triage pipeline adds 2-10 seconds per alert depending on the model and context size. This is acceptable for medium/high severity alerts but may not be appropriate for high-volume, low-severity alert streams. Implement severity-based routing: low-severity alerts go through deterministic triage only; medium/high go through LLM triage.

5. **Cost management.** Each triage verdict consumes LLM tokens. A context package with full enrichment can be 2,000-4,000 tokens input plus 500-1,000 tokens output. At scale (hundreds of alerts per day), this is a meaningful operational cost. Monitor token usage and optimize context packages to include only relevant fields.

6. **Model selection.** Larger models (Claude Sonnet/Opus, GPT-4) produce significantly better reasoning than smaller models. The marginal cost of a better model is trivial compared to the cost of analyst time reviewing bad verdicts. Do not optimize for the cheapest model — optimize for verdict quality.

7. **Feedback loop.** Capture analyst overrides of LLM verdicts. When an analyst changes a verdict from FP to TP (or vice versa), log the full context package, the LLM verdict, and the analyst's correction. This data is invaluable for prompt refinement and eventual fine-tuning.

**Architecture pattern:**

```
Alert fires → SOAR playbook runs enrichment steps → context package assembled (JSON)
→ deterministic filters applied (auto-close known benign, auto-escalate critical)
→ remaining alerts sent to LLM with context package → structured verdict returned
→ verdict routed: FP auto-closed | TP auto-escalated | Escalate → analyst queue
→ analyst reviews, confirms/overrides → feedback captured
```

## Dependencies

- **Prerequisite — Pillar 1 (Data Foundations):** Enrichment data sources (CMDB, AD, threat intel, vuln scans) must be queryable via API with acceptable reliability and latency.
- **Prerequisite — Pillar 2 (Process Maturity):** Investigation workflows must be sufficiently documented to define what constitutes a TP vs. FP for each alert type.
- **Prerequisite — Pillar 3 (Human Element):** Leadership must accept an AI error budget — the LLM will make incorrect triage decisions at a measurable rate.
- **Prerequisite — Pillar 4 (Technology Stack):** SOAR platform must support calling external APIs (LLM endpoint) as a playbook step and parsing structured JSON responses.
- [UC-15: LLM Investigation Guide Generation](../rule-content-engineering/15-llm-investigation-guide-generation.md) — Investigation guides can be included in the context package to give the LLM rule-specific triage criteria.

## Complexity Assessment

| Dimension | Rating | Notes |
|---|---|---|
| Data engineering | High | Assembling a complete, reliable enrichment package across 5-7 data sources is the hardest part. Every enrichment source is a potential point of failure (API timeout, stale data, missing records). |
| AI/ML complexity | Medium | Single-turn LLM prompting with structured output. No fine-tuning, no custom models, no training pipelines. Prompt engineering is iterative but not technically complex. |
| Integration effort | High | Requires SOAR playbook modifications, LLM API integration, output parsing, feedback capture pipeline, and routing logic. Touches multiple teams (SOAR engineering, detection engineering, SOC operations). |
| Overall | **High** | The AI part is medium complexity. The hard part is building the enrichment pipeline that feeds it and the organizational trust to act on its verdicts. |

## Real-World Considerations

**Enrichment reliability is the bottleneck, not LLM quality.** In production, the most common failure mode is not "the LLM reasoned poorly" but "the threat intel lookup timed out, the CMDB returned stale data, and the AD query returned nothing because the service account password expired." Build robust error handling and teach the LLM to explicitly flag missing data rather than reasoning confidently without it.

**Verdict accuracy varies dramatically by alert type.** LLM verdicts on well-enriched, common alert types (brute force, suspicious logon, known malware hash) will be significantly more accurate than verdicts on novel or ambiguous detections. Start with alert types where you have high enrichment coverage and clear TP/FP criteria. Expand gradually.

**Analyst trust must be earned incrementally.** Do not deploy LLM verdicts as auto-close decisions on day one. Start in shadow mode: the LLM produces verdicts, analysts triage normally, and you compare. Once accuracy exceeds an agreed threshold (e.g., 90% agreement with analyst decisions on a validation set), move to a "suggest and confirm" model where analysts see the LLM verdict and approve/override. Only after sustained accuracy do you move to auto-action on high-confidence verdicts.

**Hallucination risk is real but manageable.** The LLM may cite evidence that doesn't exist in the context package or misinterpret field values. Mitigations: (1) instruct the LLM to only cite data present in the provided context, (2) validate that cited evidence actually appears in the input, (3) use structured output to constrain the verdict format. Accept that occasional hallucinations will occur and build human review into the workflow.

**Scale considerations.** If you process 1,000 alerts per day and 40% survive deterministic filtering, you're making 400 LLM calls per day. At $0.01-0.03 per call, that's $4-12/day or $120-360/month — trivial compared to analyst salary. The cost concern is overblown for most SOCs. The latency concern (2-10 seconds per call) is more relevant for time-sensitive alerts.

**Regulatory and compliance.** Sending alert data (which may contain PII, hostnames, user identifiers) to external LLM APIs may violate data residency or privacy requirements. Evaluate self-hosted LLM deployment (e.g., vLLM, Ollama) or cloud provider AI services that keep data within your compliance boundary.

## Related Use Cases

- [UC-12: Alert Cluster Narrative Synthesis](12-alert-cluster-narrative-synthesis.md) — Applies similar LLM reasoning to clusters of related alerts rather than individual alerts.
- [UC-13: Natural Language Alert Query](13-natural-language-alert-query.md) — Analysts can ask follow-up questions about alerts in natural language after reviewing triage verdicts.
- [UC-14: Agentic Investigation Execution](14-agentic-investigation-execution.md) — Extends beyond single-turn verdicts to multi-step investigations where the LLM actively gathers additional data.
- [UC-15: LLM Investigation Guide Generation](../rule-content-engineering/15-llm-investigation-guide-generation.md) — Generates the investigation guides that can be included in the triage context package.
- [UC-03: Automated Rule Tuning Recommendations](../alert-analysis/03-automated-rule-tuning-recommendations.md) — FP patterns identified during triage should feed back into tuning recommendations.

## References

- Anthropic, "Claude Structured Output" — Using JSON mode and tool use for consistent LLM output parsing
- OWASP, "Agentic AI Threats and Mitigations" (2025) — Security considerations for LLM-integrated workflows
- Anton Chuvakin, "Simple to Ask: Is Your SOC AI Ready? Not Simple to Answer!" (October 2025) — Framework for evaluating SOC readiness for AI triage
- Dropzone AI, "Autonomous SOC Analysis" — Commercial implementation of LLM-based alert triage
- Prophet Security, "Agentic AI for SOC" — Commercial implementation of LLM triage with enrichment integration
- Prompt Engineering Guide (promptingguide.ai) — Techniques for structured LLM prompting applicable to triage verdict generation
