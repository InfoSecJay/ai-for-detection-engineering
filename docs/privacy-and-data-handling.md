# Privacy and Data Handling

When alert payloads, log lines, and rule contents leave your environment to reach a hosted LLM API, you have made a data-egress decision — whether or not you've documented it. This guide covers what to consider, what to redact, and when to insource inference. Scoped to detection engineering — broader enterprise AI governance is the CISO/Privacy team's domain.

---

## What Actually Leaves Your Environment

Per use case, here is what enters the LLM context (and therefore is processed by the API vendor). Most teams underestimate this list.

| Use Case | Data Sent to LLM | Sensitivity |
|---|---|---|
| UC-01 Detection Performance Analytics | Rule names, descriptions, aggregated metrics, top-N entity names (truncated/hashed if configured) | Medium — rule content reveals detection strategy; entity names may include staff |
| UC-02 Entity Cardinality Noise | Entity values (usernames, hostnames, IPs, command lines) for top-N concentration | High — direct PII and infrastructure detail |
| UC-03 Rule Tuning | Rule content + offending entity values | High — same as UC-02 plus exclusion logic |
| UC-04 Drift Monitoring | Rule metadata + statistical summary; minimal raw entities | Low–Medium |
| UC-05 Temporal Patterns | Time-bucketed counts; entity names if explaining a pattern | Medium |
| UC-06 Posture Scoring (narrative) | Rule metadata, scores, technique mappings; minimal entity data | Low |
| UC-07 Threat-Informed Gap Prioritization | CTI report text + your detection metadata | Medium — CTI may itself be sensitive (vendor licensing) |
| UC-08 Kill Chain | Rule metadata + tactic mappings | Low |
| UC-09 Cross-Domain Coverage | Rule metadata + data-source inventory | Low–Medium — data-source inventory reveals security posture |
| UC-10 Executive Posture Reporting | Aggregated metrics; minimal entity data | Low |
| UC-11 LLM Triage Verdicts | **Full alert payload** including raw event fields, enrichment, identity context | **Critical** — every field in the alert leaves |
| UC-12 Cluster Narrative | Multiple alert payloads in cluster | **Critical** |
| UC-13 NL Alert Query | Analyst question + retrieved alert results | High — analyst questions may include sensitive context |
| UC-14 Agentic Investigation | Alert payload + iterative tool results (SIEM queries, EDR results, identity records) | **Critical** — broadest exposure |
| UC-15 Investigation Guide Generation | Rule content + sample telemetry for context | Medium |
| UC-16 Observable Extraction | Rule query syntax | Medium |
| UC-17 Rule Comparison | Multiple rule contents | Medium |
| UC-18 Rule Quality Assessment | Rule content + metadata | Medium |
| UC-19 Rule Generation | CTI / technique description + your existing rule corpus for context | Medium |
| UC-23 Synthetic Test Data | Rule content + schema | Medium |
| UC-20 Workflow Optimization | Triage telemetry, may include analyst names | High — staff PII |
| UC-21 CTI Synthesis | CTI report text + your posture data | Medium |
| UC-22 Program Health Reporting | Aggregated metrics | Low |

**Rule of thumb**: any use case touching alert payloads (UC-11/12/13/14) is your highest-risk egress. Use cases working only on metadata and aggregates (UC-06/08/10/22) are lowest-risk.

---

## Categories of Sensitive Content in Alert Payloads

What is actually inside the things you're sending out? In a typical enterprise alert, expect:

- **Identity**: usernames, email addresses, employee IDs, manager chains, group memberships
- **Endpoint context**: hostnames, OS versions, installed software, file paths revealing user profile names
- **Network**: internal IP addresses (revealing topology), internal hostnames, cloud account IDs, region/zone
- **Process detail**: command lines (often containing credentials, tokens, or sensitive paths), parent processes, working directories
- **Authentication artifacts**: session IDs, MFA factor types, login locations, device fingerprints
- **Business context**: from CMDB enrichment — application owners, business unit, project codes, criticality
- **Sometimes secrets**: command lines invoking `--password`, environment variables echoed in process trees, API keys in URL parameters, connection strings

The last category is the worst. A misconfigured application that logs credentials gets those credentials exfiltrated to your LLM vendor every time UC-11 triages an alert from that source.

---

## Redaction Patterns

Five redaction strategies, ordered by complexity:

### 1. Field allow-list (simplest, recommended baseline)

For each use case, define the explicit set of fields that may be sent. Drop everything else. Default-deny.

Example for UC-11:
```yaml
fields_allowed_uc11:
  - "@timestamp"
  - "event.action"
  - "event.outcome"
  - "rule.name"
  - "rule.description"
  - "rule.severity"
  - "host.name"
  - "user.name"
  - "process.name"
  - "process.command_line"  # with secret-pattern redaction (see #3)
  - "source.ip"
  - "destination.ip"
  - "kibana.alert.workflow_status"
  - "threat.tactic.name"
```

Anything outside this list never reaches the LLM. New fields require a review.

### 2. Hash or tokenize identifiers (preserves correlation, removes content)

Replace usernames, hostnames, IPs with deterministic hashes. The model can still reason about "the same user appears in two alerts" without ever seeing the actual username.

```
Before: user.name = "jane.smith"
After:  user.name_hash = "u_7c4f3a91"
```

Trade-off: the LLM cannot use semantic features of the username (e.g., recognizing service-account naming conventions). For UC-02 this matters; for UC-04/06 it does not.

### 3. Pattern-based secret redaction (essential for command lines)

Run command lines, environment variables, URLs, and file paths through a redaction pass before sending. Replace matches:

| Pattern | Replacement |
|---|---|
| `--password\s+\S+` | `--password [REDACTED]` |
| `aws_secret_access_key=\S+` | `aws_secret_access_key=[REDACTED]` |
| `Bearer\s+[A-Za-z0-9-_=]{20,}` | `Bearer [REDACTED]` |
| Connection strings with `pwd=` or `password=` | replaced with `[REDACTED]` |
| Private IPs with credentials in URLs | URL credentials stripped |

Tools: `detect-secrets`, `gitleaks` patterns adapted to log content, or your DLP product's regex set.

### 4. Differential summarization (advanced)

Pre-summarize sensitive sections deterministically before sending. Instead of sending the full process command line, send `"PowerShell command, 412 chars, contains -EncodedCommand flag, 2 base64-decoded URLs reference {domain1, domain2}"`. The LLM gets the relevant signal without the raw content.

Trade-off: information loss. Suitable for high-volume use cases where the LLM needs the gist, not the detail.

### 5. Local pre-processing with on-prem inference (most thorough)

Run a local model (Llama, Qwen) to extract or classify the sensitive parts. Send only the extracted features to the hosted frontier model. This combines on-prem privacy with hosted-frontier capability.

Trade-off: complexity. Worth it for regulated environments and high-volume Tier-1 alert processing (UC-11).

---

## Vendor / Region Considerations

When evaluating an LLM vendor for SOC use:

| Question | Why it matters |
|---|---|
| Does the vendor train on customer inputs by default? | Anthropic, OpenAI, and most enterprise tiers say no — but verify in the contract, not the marketing page |
| What is the data retention policy? | 30 days is common for abuse monitoring; ensure this matches your retention policy and incident-response needs |
| Where is inference physically performed? | Region matters for data-residency regulations (GDPR, PIPEDA, Quebec Law 25, US state privacy laws) |
| Is there a zero-data-retention option? | Available from major vendors at enterprise tier; required for some compliance regimes |
| Is the vendor SOC 2 / ISO 27001 / FedRAMP / IRAP attested as appropriate to your regulatory regime? | Required for many enterprise procurement processes |
| Subprocessor list and notification policy? | LLM vendors use cloud subprocessors (typically AWS, GCP, Azure); ensure these are also approved |
| Logging on the vendor side — is your prompt content visible to their staff? | Some vendors offer customer-managed encryption keys; many do not |
| What is the breach notification SLA? | Typical: 72 hours; ensure it matches your regulatory requirements |

Negotiate. Default vendor terms are written for marketing departments, not SOCs handling sensitive operational telemetry.

---

## When to Insource Inference

Default to hosted inference. Move on-prem when one or more of these is true:

1. **Regulatory requirement** — your data classification or regulatory regime forbids egress (some financial, government, health, or critical infrastructure environments). Air-gapped or sovereign-cloud requirements.
2. **Cost crossover** — sustained spend exceeds the breakeven for dedicated GPU infrastructure. See [cost-models.md](cost-models.md). Approximate threshold: $8K–$15K/month of API spend.
3. **Latency requirement** — UC-11 at very high alert volumes hits hosted-API rate limits or latency floors. On-prem inference can be lower-latency at peak.
4. **Operational sensitivity** — your detection logic or incident telemetry is itself a competitive or operational secret you don't want a vendor to log even temporarily.

What "on-prem" means in 2026:
- **Open-weight models** (Llama 3.1+, Qwen 2.5+, Mistral, DeepSeek): adequate for UC-01/02/03/06/15/16/18 quality bar; insufficient for UC-19 rule generation and weaker than frontier models for UC-14 complex agentic reasoning
- **Self-hosted closed-weight via vendor agreement**: some vendors (Microsoft via Azure OpenAI in some regions, AWS Bedrock with provisioned throughput) offer in-region or in-VPC deployment
- **Hybrid**: on-prem for volume + sensitivity (UC-11 Haiku-class triage); hosted frontier for hard cases (UC-14 escalations, UC-19 rule generation)

---

## Per-Use-Case Recommended Posture

| Use Case | Recommended Posture | Reason |
|---|---|---|
| UC-01, UC-04, UC-06, UC-08, UC-09, UC-10, UC-22 | Hosted API, field allow-list, no PII redaction needed | Metadata-heavy, low entity exposure |
| UC-02, UC-03, UC-05 | Hosted API, field allow-list + hash entities | Entities used but exact values not needed for narrative |
| UC-15, UC-16, UC-17, UC-18, UC-23 | Hosted API, rule content only | Rule files don't contain runtime PII |
| UC-19 | Hosted frontier (quality matters), rule + CTI input | Output reviewed before deployment |
| UC-11, UC-12 | Hosted with field allow-list + secret-pattern redaction; consider on-prem for high-volume environments | Highest-volume PII exposure |
| UC-13 | Hosted with NL query logging and scope allow-list | Analyst questions may be sensitive |
| UC-14 | Hosted for hard cases; on-prem for routine if available | Broadest data exposure of any use case |
| UC-07, UC-21 | Hosted with vendor allow-list on CTI sources | Some CTI is licensed and cannot be re-distributed |
| UC-20 | Hosted with analyst-name hashing | Staff PII |

---

## Documentation You Need

For each use case in production, maintain a one-page **Data Handling Record** containing:

- Use case ID and owner
- Data categories sent to the LLM
- Field allow-list
- Redaction transforms applied
- Vendor + region + retention policy
- Legal basis for processing (relevant for GDPR / state privacy regimes)
- Date of last review

This is not a paperwork exercise. When the privacy team or auditor asks "what does our SOC send to OpenAI?" — and they will — you need an answer in writing. See [governance-mapping.md](governance-mapping.md) for how this fits into broader frameworks.

---

## Common Mistakes

1. **Sending the full alert document because it was easy** — most fields are unread by the prompt. Allow-list what you actually use.
2. **Forgetting that command lines contain secrets** — every command-line containing `--password`, `connection string`, or a base64 token leaves your environment unredacted by default.
3. **Treating CTI as non-sensitive** — vendor TI is usually licensed; redistributing report content via LLM may violate license terms. Read the TOS.
4. **Logging prompts and responses to a non-restricted log store** — your prompt logs contain everything you sent to the LLM. Apply the same access controls as you would to the source data.
5. **Assuming "enterprise tier = compliant"** — verify the specific provisions for your regulatory regime. Defaults vary.
6. **Skipping the redaction step in pilot, then forgetting to add it for production** — pilot data is often the same data as production data. Redact from day one.
