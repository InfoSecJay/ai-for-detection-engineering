# UC-XX: [Use Case Name]

## Category

[Alert Analysis | Posture Assessment | AI-Assisted Triage | Rule Content Engineering | Strategic]

## Summary

[2-3 sentence description of what this does and why it matters]

## Problem Statement

[What operational problem does this solve? Why can't it be solved with SIEM/SOAR/deterministic tooling alone?]

## Prerequisites (What Your SIEM/SOAR Should Already Handle)

[Explicitly list what should be done by deterministic tooling BEFORE AI is applied. Be honest — if enrichment, correlation, or parsing is involved, state that those are SIEM/SOAR responsibilities.]

## Where AI Adds Value

[Precisely describe what the AI/LLM does that deterministic tooling cannot. This is the core of each use case — be specific about why reasoning, synthesis, or generation is needed.]

## AI Approach

[Specific AI/ML technique: LLM prompting, classification, clustering, agentic tool use, RAG, statistical analysis, etc.]

## Data Requirements

### Inputs

| Input | Format | Key Fields Used |
|---|---|---|
| | | |

> **Note:** Alert data follows the SIEM's standard alert schema with normalized source event fields. Rule files follow their format's defined schema (Elastic TOML, Sigma YAML, Splunk YAML, etc.). These are structured, documented formats — see [data-requirements/](../data-requirements/) for platform-specific field references.

### Outputs

[What does this produce? Include concrete examples.]

## Implementation Notes

[Technical considerations, architecture, libraries/tools, known challenges.]

## Dependencies

[Other use cases or prerequisites required first.]

## Complexity Assessment

| Dimension | Rating | Notes |
|---|---|---|
| Data engineering | [Low/Med/High] | |
| AI/ML complexity | [Low/Med/High] | |
| Integration effort | [Low/Med/High] | |
| Overall | [Low/Med/High] | |

## Real-World Considerations

[Production SOC challenges: data quality, scale, organizational adoption, trust/validation.]

## Related Use Cases

[Links to complementary use cases in this repo.]

## References

[External links to tools, papers, vendor implementations.]
