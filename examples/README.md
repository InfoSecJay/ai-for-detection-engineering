# Examples

Working artifacts for the use cases in this repository: production-shaped prompts, golden eval sets, and evaluation scaffolding.

This directory exists to fix the most common gap in AI-for-DE knowledge bases — that they describe what to do without showing what the actual prompts and evals look like. The examples here are designed to be **copy-modify starting points**, not finished systems. Treat them like reference architecture diagrams: they show the shape, you build the local instance.

---

## What's Here

```
examples/
├── README.md                    ← this file
├── TEMPLATE/                    ← starting template for new use case examples
│   ├── prompt.md
│   ├── golden-set.yaml
│   ├── eval-runner.md
│   └── README.md
├── uc-01-detection-performance/ ← portfolio narrative generation
├── uc-11-triage-verdicts/       ← LLM triage verdict (highest-stakes)
└── uc-15-investigation-guides/  ← investigation guide generation
```

Three use cases are exemplified now. They were chosen deliberately:

- **UC-15** is the simplest end-to-end example — bounded scope, low risk, easy to validate. Recommended starting point if you've never built an AI use case for DE.
- **UC-01** is the workhorse — moderate complexity, batches well, demonstrates prompt caching. Most teams ship this first in production.
- **UC-11** is the highest-stakes — calibration matters, hallucination matters, adversarial input matters. Demonstrates schema-constrained outputs and the cite-and-verify pattern.

The remaining 20 use cases follow the same pattern. Add them as you build them — the [TEMPLATE/](TEMPLATE/) directory is the starting point.

---

## How to Use These

For each example use case directory, you'll find:

| File | Purpose |
|---|---|
| `README.md` | Use case context, what this example demonstrates, how to run it |
| `prompt.md` | The system prompt + user prompt template |
| `golden-set.yaml` | Hand-curated input/expected-output pairs |
| `eval-runner.md` | Pseudocode + scoring logic for the eval harness |

The prompts are written for Anthropic's Claude API (Sonnet 4.6 default; UC-19-style use cases should use Opus 4.7). Translation to OpenAI / open-weight model APIs is mechanical — message structure differs, the prompt content does not.

Eval runners are **pseudocode**, not runnable code, by design. Production-quality eval frameworks (`promptfoo`, `LangSmith`, `Braintrust`, `Inspect AI`) handle the mechanics; the value of these examples is the *scoring logic*, which is use-case-specific. See [validation-harness.md](../concepts/validation-harness.md) for the spec these examples implement.

---

## Quality Bar

These examples demonstrate the engineering patterns the rest of the repository advocates:

- **Cite-and-verify pattern** — model output references input spans
- **Schema-constrained outputs** — JSON Schema for any field a downstream system parses
- **Two-pass extract-then-reason** for use cases with anchoring risk
- **Per-use-case golden set** with explicit `must_cite` and `must_not_invent` lists
- **Prompt caching** indicated where it matters

If you copy these and skip these patterns, you've got a demo, not a production system. See [where-ai-fails.md](../concepts/where-ai-fails.md) for why.

---

## Bringing Your Own Data

The golden sets here use anonymized examples representative of typical SOC environments. Before deploying any of these prompts in your environment:

1. Replace the golden set with examples from **your** data (your rule families, your environment's typical entities, your historical alerts)
2. Re-validate against your golden set — pass rates may differ materially
3. Apply the redaction patterns from [privacy-and-data-handling.md](../docs/privacy-and-data-handling.md) before sending real data
4. Add the failure-mode controls from [where-ai-fails.md](../concepts/where-ai-fails.md) appropriate to your blast radius

The examples are starting points. Production deployment is your engineering work.
