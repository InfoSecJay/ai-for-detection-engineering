# UC-13: Natural Language Alert Query

## Category

AI-Assisted Triage

## Summary

Analysts ask questions about alerts in plain English — "has this user triggered any credential access alerts in the last week?" — and an LLM translates the question into the appropriate SIEM query language (KQL, ESQL, SPL, KQL for Sentinel), executes it via the SIEM API, and summarizes the results in natural language. This is a RAG (Retrieval-Augmented Generation) pattern: the retrieval (query execution) is deterministic, and the generation (query translation + result summarization) is where the LLM adds value.

## Problem Statement

During triage, analysts frequently need to look up contextual information: prior alerts for the same user, similar alerts across the environment, historical activity on a specific host, or alerts matching a particular MITRE technique. Each of these lookups requires writing a query in the SIEM's query language, which creates two problems:

1. **Query language barrier.** Not every analyst is fluent in KQL, ESQL, EQL, or SPL. Junior analysts may struggle to write correct queries for anything beyond basic searches. Even experienced analysts slow down when constructing complex queries with time ranges, aggregations, field filters, and boolean logic. The query language is a barrier between the analyst's question and the answer.

2. **Result interpretation overhead.** SIEM query results are returned as tables or JSON — rows of alert records with dozens of fields. The analyst must scan the results, identify patterns, and mentally synthesize a summary. For a query returning 47 alerts, this is tedious. The analyst doesn't want 47 rows — they want: "Yes, this user triggered 47 credential access alerts across 3 rules in the past week, mostly from brute force detection on the VPN gateway. 44 were auto-closed as FP by the SOAR playbook. The remaining 3 were from a different rule detecting pass-the-hash activity and are still open."

Natural language query capability eliminates both barriers: the analyst asks a question in plain language, and the system returns a plain language answer backed by actual SIEM data.

## Prerequisites (What Your SIEM/SOAR Should Already Handle)

- **Query execution infrastructure:** The SIEM must expose a query API that accepts queries in its native language and returns structured results. This is standard for every major SIEM:
  - Elastic: `_search` API, `_esql` API, or `_eql/search` API
  - Splunk: REST API search endpoint (`/services/search/jobs`)
  - Sentinel: Log Analytics API with KQL queries
- **Alert index/table access:** The alert data must be queryable via the same API. Alert indices (e.g., `.internal.alerts-security.alerts-default-*` in Elastic, `notable` index in Splunk, `SecurityAlert` table in Sentinel) must be accessible to the service account running queries.
- **Field documentation:** The LLM needs to know which fields exist in the alert schema to generate valid queries. This is documented per platform (ECS field reference, CIM data model reference, ASIM schema reference) and should be provided to the LLM as reference context.
- **Access controls:** The service account executing LLM-generated queries must have appropriate read permissions scoped to alert indices. Do not give the LLM write access or administrative access to the SIEM.
- **Query validation and sanitization:** A middleware layer should validate that LLM-generated queries only target approved indices and do not contain destructive operations. This is a safety control, not an AI task.

## Where AI Adds Value

The LLM provides two distinct capabilities that deterministic tooling cannot:

1. **Natural language to query translation (text-to-KQL/ESQL/SPL).** The analyst's question is ambiguous, uses natural language conventions, and may reference concepts rather than field names. "Has this user triggered any credential access alerts?" requires the LLM to:
   - Identify that "this user" refers to a specific `user.name` value from the current alert context
   - Map "credential access" to MITRE tactic `TA0006` and know that the relevant field is `kibana.alert.rule.threat.tactic.name` or `kibana.alert.rule.threat.tactic.id`
   - Determine the appropriate time range ("last week" = last 7 days)
   - Construct a syntactically valid query in the target language

   A deterministic system could handle a few canned queries ("show me prior alerts for this user"), but it cannot handle the infinite variety of analyst questions. The LLM's ability to parse intent from natural language and map it to structured query constructs is the core value.

2. **Result summarization.** Raw query results are tabular data. The LLM reads the results and produces a natural language summary that answers the analyst's original question, highlights patterns, and surfaces actionable information. This is synthesis over structured data — the same capability that makes UC-11 and UC-12 valuable.

## AI Approach

**RAG (Retrieval-Augmented Generation) — LLM for query generation + summarization.**

This is a two-phase RAG pattern:

**Phase 1 — Query Generation:**
- The analyst's natural language question is sent to the LLM along with:
  - The SIEM's query language reference (field names, syntax, functions)
  - The current alert context (so "this user" and "this host" can be resolved)
  - Schema documentation for the alert index (available fields, field types)
- The LLM generates a query in the target language (KQL, ESQL, SPL)
- The query is validated by a middleware layer (syntax check, index scope check, safety check)
- The validated query is executed against the SIEM API

**Phase 2 — Result Summarization:**
- The query results (JSON/tabular) are returned to the LLM
- The LLM generates a natural language summary that directly answers the analyst's question
- The summary includes key data points, patterns, and counts from the results
- The original query is shown alongside the summary for transparency and analyst verification

**Key architectural elements:**

- **Schema context window:** Include a condensed schema reference in the system prompt — field names, types, and descriptions for the alert index. This is typically 500-1,000 tokens. Keep it focused on commonly queried fields rather than the full schema.
- **Query language examples:** Include 10-20 few-shot examples mapping natural language questions to correct queries. Cover common patterns: filtering by entity, filtering by MITRE technique, time range queries, aggregations, top-N queries.
- **Error handling:** If the generated query fails (syntax error, field not found), capture the error, pass it back to the LLM with the failed query, and ask for a corrected query. Allow up to 2 retries before reporting failure to the analyst.
- **Current context injection:** The analyst's question is interpreted in the context of the alert they're currently triaging. "This user," "this host," "this IP" are resolved from the current alert's entity fields before the LLM generates the query.

## Data Requirements

### Inputs

| Input | Format | Key Fields Used |
|---|---|---|
| Analyst question | Natural language text | Free-form question about alerts or activity |
| Current alert context | Alert JSON | `user.name`, `host.name`, `source.ip`, `destination.ip`, `process.name`, `rule.name` — used to resolve references like "this user" |
| Alert index schema | Schema documentation (JSON/text) | Field names, field types, descriptions for the alert index. Used by LLM to generate valid queries |
| Query language reference | Few-shot examples (text) | 10-20 examples mapping natural language questions to valid queries in the target SIEM language |
| SIEM query results | JSON array of alert records | Full alert records returned by the executed query, used by LLM for summarization |

> **Note:** Alert data follows the SIEM's standard alert schema with normalized source event fields. Rule files follow their format's defined schema (Elastic TOML, Sigma YAML, Splunk YAML, etc.). These are structured, documented formats — see [data-requirements/](../../data-requirements/) for platform-specific field references.

### Outputs

The system produces two outputs per interaction:

1. **Generated SIEM query** — shown to the analyst for transparency
2. **Natural language answer** — summarizing the query results

**Concrete example interaction:**

**Analyst asks:** "Has this user triggered any credential access alerts in the last week?"

**Context:** Analyst is triaging an alert for `user.name: jsmith`

**Generated query (Elastic ESQL):**

```esql
FROM .internal.alerts-security.alerts-default-*
| WHERE user.name == "jsmith"
  AND kibana.alert.rule.threat.tactic.name == "Credential Access"
  AND @timestamp >= NOW() - 7 days
| STATS alert_count = COUNT(*), rules_triggered = COUNT_DISTINCT(kibana.alert.rule.name),
  earliest = MIN(@timestamp), latest = MAX(@timestamp)
  BY kibana.alert.rule.name, kibana.alert.workflow_status
| SORT alert_count DESC
```

**Query results (raw):**

| kibana.alert.rule.name | kibana.alert.workflow_status | alert_count | earliest | latest |
|---|---|---|---|---|
| Brute Force Authentication Attempts | closed | 44 | 2025-03-08T14:22:00Z | 2025-03-14T09:11:00Z |
| Pass-the-Hash Activity Detected | open | 3 | 2025-03-13T22:41:00Z | 2025-03-14T01:15:00Z |

**Natural language answer:**

> Yes, **jsmith** has triggered **47 credential access alerts** across **2 rules** in the past 7 days:
>
> - **Brute Force Authentication Attempts** — 44 alerts between March 8-14, all closed (likely auto-closed by SOAR playbook as known VPN brute force noise)
> - **Pass-the-Hash Activity Detected** — 3 alerts on March 13-14, **still open**. These are from a different detection focused on lateral movement credential reuse, not the VPN brute force pattern.
>
> **Notable:** The 3 open Pass-the-Hash alerts are recent (last 2 days) and are a different detection pattern than the closed brute force alerts. These may warrant investigation in the context of the current alert.

---

**More complex example:**

**Analyst asks:** "Show me all alerts on this host in the last 24 hours grouped by MITRE tactic"

**Generated query (Elastic ESQL):**

```esql
FROM .internal.alerts-security.alerts-default-*
| WHERE host.name == "WKSTN-4421"
  AND @timestamp >= NOW() - 1 day
| STATS alert_count = COUNT(*), rules = COUNT_DISTINCT(kibana.alert.rule.name)
  BY kibana.alert.rule.threat.tactic.name
| SORT alert_count DESC
```

**Natural language answer:**

> **WKSTN-4421** generated **14 alerts** across **4 MITRE tactics** in the last 24 hours:
>
> | Tactic | Alerts | Distinct Rules |
> |---|---|---|
> | Execution | 6 | 2 |
> | Credential Access | 4 | 1 |
> | Defense Evasion | 3 | 2 |
> | Persistence | 1 | 1 |
>
> This host has activity across multiple tactics in a short window, which may indicate a multi-stage attack or an active compromise. The combination of execution, credential access, and defense evasion is particularly notable. Consider reviewing these alerts as a cluster (see UC-12) or escalating for investigation.

## Implementation Notes

**Query validation is critical.** Never execute an LLM-generated query without validation. Implement a middleware layer that:

1. **Parses the generated query** to verify syntactic correctness before execution
2. **Checks index scope** — the query must only target approved alert indices, not arbitrary data indices
3. **Blocks destructive operations** — no `DELETE`, no index modifications, no write operations
4. **Enforces time range limits** — reject queries without a time bound or with excessively long ranges (e.g., "all alerts ever")
5. **Enforces result size limits** — cap results at a reasonable number (e.g., 1,000 records) to prevent memory issues

**Multi-SIEM support.** If your organization runs multiple SIEMs, the query generation layer must target the correct query language. Approach options:
- Separate system prompts per SIEM, selected based on context
- A single system prompt with platform-specific few-shot examples, using a platform parameter to select the target language
- Query generation in a platform-agnostic intermediate format, then mechanical translation to the target language (though this reintroduces the format conversion problem)

**Conversational context.** Analysts often ask follow-up questions: "Now show me the same thing but for the last 30 days" or "What about the same rules but for a different user?" The system should maintain conversation history within a triage session so the LLM can resolve references to prior questions and results. Implement a session-scoped conversation context that persists across the triage session but does not carry over between sessions.

**Latency budget.** The full cycle — LLM generates query (2-5 seconds), query executes against SIEM (0.5-5 seconds), LLM summarizes results (2-5 seconds) — takes 5-15 seconds end-to-end. This is acceptable for interactive use but not for bulk processing. Design the UX for interactive, analyst-initiated queries, not automated pipelines.

**Query language coverage.** The LLM will be more accurate for simple queries (filters, aggregations, time ranges) than for complex queries (nested sub-queries, statistical functions, joins). Set expectations with analysts: this tool handles 80% of common lookup queries well, but complex analytical queries may need manual refinement. Show the generated query so analysts can verify and edit it.

**Schema drift.** Alert schemas change when SIEM versions are upgraded, new integrations are added, or field mappings change. The schema reference provided to the LLM must be kept current. Automate schema extraction from the SIEM and refresh the LLM's schema context on a regular schedule (weekly or on deployment).

## Dependencies

- **Prerequisite — Pillar 1 (Data Foundations):** Alert indices must be queryable via API with a documented field schema. Field names must be consistent and populated.
- **Prerequisite — Pillar 4 (Technology Stack):** SIEM query API must be accessible to the service running the LLM integration. API rate limits must accommodate interactive query volumes.
- [UC-11: LLM Triage Verdicts](11-llm-triage-verdicts.md) — Natural language query is most useful during or after triage. The analyst reviews a triage verdict and then asks follow-up questions.
- [UC-12: Alert Cluster Narrative Synthesis](12-alert-cluster-narrative-synthesis.md) — Natural language queries can supplement cluster narratives by answering analyst questions about related activity not included in the original cluster.

## Complexity Assessment

| Dimension | Rating | Notes |
|---|---|---|
| Data engineering | Low-Medium | The alert data already exists and is queryable. The main data engineering work is creating and maintaining the schema reference document provided to the LLM. |
| AI/ML complexity | Medium | Two-phase RAG pattern (generation + summarization) is well-established. Query generation accuracy depends heavily on few-shot example quality and schema documentation. No custom model training required. |
| Integration effort | Medium | Requires: LLM API integration, SIEM query API integration, query validation middleware, and a user interface for analyst interaction. The SIEM API integration is straightforward; the UX is the bigger effort. |
| Overall | **Medium** | This is one of the more approachable AI use cases. The RAG pattern is well-understood, the data is already available, and the value proposition is clear. The main challenge is query generation accuracy across the full range of analyst questions. |

## Real-World Considerations

**Query accuracy varies by question complexity.** Simple lookups ("show me alerts for this user") will have near-perfect accuracy. Complex analytical questions ("which rules have the highest false positive rate for service accounts in the finance department over the last quarter") will frequently produce incorrect or incomplete queries. Be transparent about these limitations — this is an analyst productivity tool for common lookups, not a replacement for query language expertise.

**Field name hallucination.** The most common failure mode is the LLM generating queries with field names that don't exist in the schema. Mitigations: (1) include the explicit field list in the system prompt, (2) validate field names in the generated query against the schema before execution, (3) return a clear error message when a field doesn't exist rather than silently failing.

**Security of LLM-generated queries.** A malicious or confused analyst could attempt prompt injection via their question to make the LLM generate queries against unauthorized indices or extract sensitive data. Mitigations: (1) query validation middleware with strict index allowlisting, (2) service account with read-only access scoped to alert indices only, (3) audit logging of all generated and executed queries. The LLM should never have access beyond what the analyst would have through direct SIEM query access.

**Adoption depends on UX.** If the natural language query interface is buried in a separate tool or requires context switching, analysts will revert to writing queries directly. The interface must be integrated into the analyst's existing triage workflow — ideally as a chat panel alongside the alert detail view in the SIEM or SOAR console. Integration with platforms that support embedded chatbots (e.g., SOAR case management, ticketing systems) is the most practical deployment path.

**Training data for few-shot examples.** The best few-shot examples come from your own SOC: take the 20 most common queries your analysts run during triage, pair them with the natural language version of the question, and use those as examples. Generic few-shot examples from documentation will work for basic queries but will not cover your environment-specific field usage patterns.

**This is NOT a replacement for query language skills.** Natural language query is a convenience tool that accelerates common lookups. Analysts still need to understand the SIEM query language for complex investigations, rule development, and cases where the LLM's generated query is incorrect. Position this as a productivity enhancement, not a skill replacement.

## Related Use Cases

- [UC-11: LLM Triage Verdicts](11-llm-triage-verdicts.md) — Triage verdicts often trigger follow-up questions that natural language query can answer.
- [UC-12: Alert Cluster Narrative Synthesis](12-alert-cluster-narrative-synthesis.md) — After reading a cluster narrative, analysts can drill into specific details via natural language queries.
- [UC-14: Agentic Investigation Execution](14-agentic-investigation-execution.md) — Agentic investigation uses the same text-to-query capability as one of its tools, but in an automated multi-step loop rather than an interactive analyst-initiated mode.
- [UC-01: Detection Performance Analytics](../alert-analysis/01-detection-performance-analytics.md) — Analysts can query alert performance data in natural language ("which rules have the highest volume this month?").

## References

- Anthropic, "Tool Use (Function Calling)" — Structured output patterns for query generation
- LangChain, "SQL Agent" — Reference architecture for text-to-SQL that applies to text-to-KQL/ESQL/SPL
- Elastic, "ES|QL Reference" — Query language documentation used as schema context for Elastic deployments
- Splunk, "SPL2 Reference" — Query language documentation for Splunk deployments
- Microsoft, "KQL Reference" — Query language documentation for Sentinel deployments
- Vanna AI — Open source text-to-SQL framework adaptable to SIEM query languages
- Andrew Ng, "Building Systems with the ChatGPT API" — RAG pattern fundamentals applicable to this use case
