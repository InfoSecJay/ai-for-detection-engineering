# Contributing to AI for Detection Engineering

Thank you for your interest in contributing to this knowledge repo. This is a practitioner-maintained reference — contributions should reflect real-world experience with detection engineering, SOC operations, and applied AI/ML.

## What We're Looking For

- **New use cases** that follow the [use case template](use-cases/TEMPLATE.md) and honestly separate SIEM/SOAR work from AI work
- **Improvements to existing use cases** — better examples, corrections, additional platform references
- **Concept documents** that explain frameworks or methodologies relevant to AI in detection engineering
- **Tool and project references** — open source tools, research papers, vendor evaluations
- **Real-world implementation notes** — if you've built something described here, share what worked and what didn't

## Guidelines

### Be Honest About the AI Boundary

This repo's credibility depends on drawing a clear line between what is an AI problem and what is a SIEM/SOAR/data engineering problem. Every contribution must:

- Include a **"Prerequisites (What Your SIEM/SOAR Should Already Handle)"** section for any use case
- Include a **"Where AI Adds Value"** section that precisely describes the AI contribution
- Not claim AI is needed for: field parsing, log normalization, enrichment lookups, IOC matching, alert correlation by shared fields, rule format conversion, basic aggregation metrics, SOAR playbook execution, or threshold alerting

### Be Vendor-Agnostic

Use cases, concepts, and frameworks should apply regardless of SIEM/SOAR platform. Where concrete examples help, reference Elastic, Splunk, or Microsoft Sentinel as illustrative implementations — not requirements.

### Be Specific and Operational

- No vendor marketing language
- No generic security theory
- Include concrete examples and output samples
- Reference real tools, schemas, and query languages

## How to Contribute

1. **Fork** the repository
2. **Create a branch** for your contribution (`git checkout -b add-use-case-XX`)
3. **Follow the templates** — use [TEMPLATE.md](use-cases/TEMPLATE.md) for new use cases
4. **Submit a pull request** with a clear description of what you're adding or changing

## Use Case Numbering

Use cases are numbered sequentially (UC-01 through UC-XX). If adding a new use case, use the next available number and add it to the appropriate category directory.

## Code of Conduct

Be respectful, constructive, and focused on making this resource better for the detection engineering community. Disagreements about technical approaches are welcome — keep them professional and evidence-based.

## Questions?

Open an issue or reach out to [Jay Tymchuk](https://github.com/InfoSecJay).
