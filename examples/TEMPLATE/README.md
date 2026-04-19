# UC-XX: [Use Case Name] — Example Implementation

A starting template for building an example for a new use case. Copy this directory, rename, and fill in the four files.

## What This Example Demonstrates

[1-2 sentences on what the reader should learn from this specific example. Be concrete. "Demonstrates JSON-Schema-constrained verdict output with confidence-banded routing" beats "Shows how to do triage with AI."]

## Use Case Reference

Source use case: [link to the use-case markdown file in `../../use-cases/`]

## What's in This Directory

| File | Purpose |
|---|---|
| `README.md` | This file |
| `prompt.md` | System + user prompt template |
| `golden-set.yaml` | Hand-curated input/expected-output pairs for evaluation |
| `eval-runner.md` | Pseudocode for the eval scoring logic |

## Engineering Patterns Used

List which of the patterns from [where-ai-fails.md](../../concepts/where-ai-fails.md) this example demonstrates:

- [ ] Cite-and-verify
- [ ] Two-pass extract → reason
- [ ] Schema-constrained outputs
- [ ] Confidence-banded routing
- [ ] Prompt caching
- [ ] Tool-use with allow-list
- [ ] Untrusted-content delimiting

## Model Choice

Default: Claude Sonnet 4.6.
Why: [justify the model tier. Cheaper for extraction tasks (Haiku); frontier for hard reasoning (Opus); workhorse for narrative (Sonnet).]

## Cost Estimate

Per invocation:
- Input tokens (cached): ~X K
- Input tokens (fresh): ~Y K
- Output tokens: ~Z K
- Estimated cost: $$$

See [cost-models.md](../../docs/cost-models.md) for context.

## How to Run

1. Set your API key.
2. Use any eval framework (`promptfoo`, `LangSmith`, etc.) and load `golden-set.yaml`.
3. Render `prompt.md` with each golden input, call the model, score per `eval-runner.md`.
4. Compare against gates in the source use case's promotion criteria.

## Known Limitations

[What this example does NOT do. Common items: doesn't handle multi-language input, doesn't include the production redaction layer, doesn't include retry logic.]
