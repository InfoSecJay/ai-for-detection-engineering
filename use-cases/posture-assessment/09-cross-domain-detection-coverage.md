# UC-09: Cross-Domain Detection Coverage

## Category

Posture Assessment

## Summary

Evaluates detection coverage for ATT&CK techniques across multiple data source domains — endpoint, network, identity, cloud, email — to assess whether your detection for a given technique provides genuine multi-layered visibility or relies on a single telemetry source. Deterministic tooling counts which techniques have rules spanning multiple domains. AI adds value by assessing the quality and complementarity of cross-domain coverage, evaluating whether entity overlap enables cross-domain correlation, and identifying where adding detection in an additional domain would provide the most defensive value.

## Problem Statement

A technique detected by rules in three data source domains is more resilient than a technique detected in only one. If your only detection for T1078 (Valid Accounts) is in Okta identity logs and that data source experiences a parsing regression or collection gap, you go Blind. If you also have rules in AWS CloudTrail (detecting assumed role usage) and Windows Security logs (detecting logon events), the telemetry loss in one domain degrades but does not eliminate your detection.

Counting cross-domain coverage is trivial — group rules by technique, count distinct domains. The harder question is whether the rules in different domains actually detect complementary aspects of the technique. Two rules in two domains that both look for the same narrow artifact (a specific username pattern) provide redundancy but not diversity. Two rules that detect different observable stages of the same technique — the identity rule catches the initial authentication anomaly, the endpoint rule catches the post-authentication behavior — provide genuine defense-in-depth.

Assessing this complementarity requires understanding what each rule detects at a semantic level and reasoning about how the observables relate to each other. This is the gap between counting domains (deterministic) and evaluating cross-domain detection quality (requires reasoning).

## Prerequisites (What Your SIEM/SOAR Should Already Handle)

- **Rules with data source domain classification.** Each rule must be tagged with its data source domain (endpoint, network, identity, cloud, email, DNS, proxy, etc.). In Elastic, this is often derivable from the `index` patterns in the rule query or from explicit `data_source` metadata. In Sigma, the `logsource` block specifies `product` and `service`. In Splunk, the `datamodel` or `source` fields in the search. If your rules do not have domain classification, add it — this is a metadata enrichment task, not an AI problem.
- **Rules with MITRE ATT&CK technique mappings.** The cross-domain analysis groups rules by technique. Without technique mappings, there is no grouping key.
- **Detection Confidence Scores from UC-06.** Per-rule Signal Quality Scores allow the analysis to distinguish between "this technique has rules in 3 domains" and "this technique has healthy rules in 2 domains and a broken rule in the third." Without scores, you get a domain count; with scores, you get a quality-weighted domain assessment.
- **Entity field mapping per domain.** The [Domain-Aware Entity Framework](../../concepts/domain-aware-entity-framework.md) defines which entity fields are meaningful per domain. Cross-domain correlation depends on shared entity fields — hostname, username, IP address — that appear in alerts from different domains. If entity fields are not normalized across domains (e.g., endpoint uses `host.name` while network uses `observer.hostname` for different concepts), cross-domain correlation will fail. This normalization is a SIEM/data engineering prerequisite.
- **Correlation rules for cross-domain entity matching (optional but valuable).** If your SIEM already has correlation rules that join alerts by shared entities across domains (e.g., "same user in identity alert and endpoint alert within 15 minutes"), those correlations provide empirical evidence of cross-domain coverage working in practice. These are SIEM queries — not AI.

## Where AI Adds Value

### 1. Complementarity Assessment

An LLM reads the query logic of rules covering the same technique across different domains and assesses whether they detect genuinely different observable aspects:

> **Cross-Domain Assessment for T1078 — Valid Accounts:**
>
> **Domain: Identity (Okta)**
> - Rule: "Okta Sign-In from Unusual Location" — detects authentication events where the source IP geolocation deviates from the user's historical pattern. Observable: authentication metadata (source IP, geo, device fingerprint).
> - Rule: "Okta MFA Fatigue — Repeated Push Denials" — detects repeated MFA push notifications followed by an eventual acceptance. Observable: MFA challenge/response sequence.
>
> **Domain: Cloud (AWS CloudTrail)**
> - Rule: "AssumeRole from Unusual Source Account" — detects cross-account role assumption from accounts that have not previously used this role. Observable: API call metadata (source account, role ARN, source IP).
> - Rule: "Console Login Without MFA" — detects AWS console logins where MFA was not used. Observable: authentication method metadata.
>
> **Domain: Windows Endpoint (Security Events)**
> - Rule: "Logon Type 10 from Unusual Source" — detects RDP logon events from source IPs not in the historical baseline. Observable: logon event metadata (source IP, logon type, target host).
>
> **Complementarity Assessment:**
> These rules detect T1078 at three distinct points in the attack surface:
> 1. **Identity layer** — catches the initial credential use and authentication anomalies at the identity provider.
> 2. **Cloud layer** — catches post-authentication abuse of cloud-specific privileges (role assumption, console access).
> 3. **Endpoint layer** — catches the downstream effect of credential use on target systems.
>
> **Entity overlap for correlation:** All three domains share `user.name` as a common entity field. The identity rules and endpoint rules share `source.ip`. This means a cross-domain correlation rule could link: Okta unusual sign-in + AWS AssumeRole from same user + RDP logon on endpoint = high-confidence valid account abuse chain.
>
> **Gap identified:** No rules detect T1078 in the **email domain** (compromised account sending phishing emails) or the **network domain** (VPN authentication from unusual location). Adding email-domain detection would catch account takeover used for internal phishing — a common objective of valid account abuse.

### 2. Entity Overlap Analysis for Correlation Readiness

The LLM evaluates whether rules across domains share entity fields that would enable cross-domain alert correlation:

> **Entity Overlap Matrix for T1078:**
>
> | Domain Pair | Shared Entity Fields | Correlation Feasibility |
> |---|---|---|
> | Identity + Cloud | `user.name`, `source.ip` | Strong — same user identity, same source IP in both domains |
> | Identity + Endpoint | `user.name`, `source.ip` | Strong — user identity maps directly; source IP may differ if VPN terminates differently |
> | Cloud + Endpoint | `user.name` | Moderate — user maps but IP context differs (cloud API source IP vs. RDP source IP) |
> | Identity + Network | `source.ip`, `user.name` | Moderate — depends on whether network logs include authenticated user identity |
>
> **Correlation recommendation:** Deploy a cross-domain correlation rule: "Same user triggers identity anomaly alert AND cloud privilege abuse alert AND endpoint logon alert within 60 minutes." This correlation is a SIEM query — the entity fields are available and normalized. The AI contribution was assessing which entity fields overlap meaningfully and whether the correlation is operationally sound.

### 3. Investment Prioritization for Domain Expansion

The LLM identifies where adding detection in an additional domain would provide the most value:

> **Cross-Domain Investment Priorities:**
>
> **Highest value additions:**
>
> 1. **T1059.001 (PowerShell) — Add network domain detection.**
>    Currently covered by 6 rules, all in Windows Endpoint domain. No network-level detection of PowerShell C2 communication patterns. Adding a network rule that detects PowerShell download cradle HTTP patterns (specific User-Agent strings, URI patterns) would provide detection even if endpoint-level script block logging is evaded or disabled. Correlation potential: endpoint PowerShell execution alert + network suspicious HTTP pattern from same host = high confidence.
>
> 2. **T1003 (Credential Dumping) — Add identity domain detection.**
>    Currently covered by 4 endpoint rules (LSASS access, SAM registry access). No identity-domain detection of credential use anomalies *after* credentials are harvested. Adding an identity rule that detects "user authenticates from a new device immediately after LSASS access alert on their primary workstation" creates a detection-to-impact chain. Correlation potential: endpoint credential access alert + identity authentication from new device for same user within 30 minutes.
>
> 3. **T1048 (Exfiltration) — Add DNS domain detection.**
>    Currently covered by 3 network rules (large transfers, unusual protocols). No DNS-domain detection of DNS-based exfiltration (high-entropy subdomain queries, abnormal query volumes). Adding DNS exfiltration rules covers an evasion path that bypasses network-layer rules monitoring standard protocols.
>
> **Low value additions (avoid):**
>
> - T1566.001 (Spearphishing Attachment) — already covered in email (3 rules) and endpoint (4 rules) domains. Adding network-domain detection provides marginal value given strong existing coverage.

## AI Approach

**Deterministic aggregation + LLM qualitative analysis:**

1. **Deterministic domain counting:** Group rules by ATT&CK technique. For each technique, count distinct data source domains. Tag techniques as single-domain, dual-domain, or multi-domain. Overlay per-rule Signal Quality Scores to produce quality-weighted domain counts (a Blind rule in a domain does not count as meaningful coverage). This is a grouped aggregation — no AI required.

2. **LLM complementarity assessment:** For each technique with multi-domain coverage (or high-priority single-domain techniques), the LLM reads the query logic of all contributing rules and assesses:
   - Do rules detect different observable aspects of the technique?
   - Are the rules redundant (same observable, different domain) or complementary (different observable, different domain)?
   - Which combination of rules provides the strongest detection when correlated?

3. **LLM entity overlap analysis:** For rules covering the same technique across domains, the LLM identifies which entity fields are shared and evaluates whether those shared fields enable meaningful cross-domain correlation. This requires understanding that `user.name` in Okta and `user.name` in Windows Security events refer to the same logical entity, while `source.ip` in cloud and `source.ip` in endpoint may refer to different network contexts.

4. **LLM investment prioritization:** The LLM combines single-domain technique identification, posture scores, and threat relevance to recommend where adding a detection in a new domain would have the highest defensive impact.

**Caching strategy:** Complementarity assessments change only when rules change. Cache assessments per technique and invalidate only when rules mapped to that technique are added, modified, or removed. This minimizes LLM invocations for what is fundamentally a slow-changing analysis.

## Data Requirements

### Inputs

| Input | Format | Key Fields Used |
|---|---|---|
| Detection rule inventory | Elastic TOML / Sigma YAML / Splunk YAML | Rule ID, technique/tactic mappings, data source domain, query logic, index patterns / logsource / datamodel |
| Signal Quality Scores (from UC-06) | JSON | Rule ID, Signal Quality Score, tier |
| Detection Confidence Scores (from UC-06) | JSON | Technique ID, confidence score, tier, contributing rule list |
| Domain-Aware Entity Framework config | YAML | Per-domain entity field definitions (primary, secondary, supporting fields) |
| MITRE ATT&CK data sources | STIX 2.1 JSON | Technique-to-data-source mappings (ATT&CK v13+ includes formal data source objects) |
| Cross-domain correlation rules (optional) | SIEM rule format | Existing correlation rules that join alerts across domains — evidence of working cross-domain detection |

> **Note:** Alert data follows the SIEM's standard alert schema with normalized source event fields. Rule files follow their format's defined schema (Elastic TOML, Sigma YAML, Splunk YAML, etc.). These are structured, documented formats — see [data-requirements/](../../data-requirements/) for platform-specific field references.

### Outputs

**Primary output: Cross-Domain Coverage Report**

```
Cross-Domain Detection Coverage Summary
Analysis Date: 2026-02-14
Total Techniques Assessed: 187

Domain Distribution:
  Single-domain coverage:  104 techniques (55.6%)
  Dual-domain coverage:     58 techniques (31.0%)
  Multi-domain (3+):        25 techniques (13.4%)

Quality-Weighted Distribution (counting only Functional+ rules):
  Single-domain coverage:  121 techniques (64.7%)
  Dual-domain coverage:     46 techniques (24.6%)
  Multi-domain (3+):        20 techniques (10.7%)

  Note: 17 techniques shift to lower domain count when Degraded/Abandoned
  rules are excluded, exposing false cross-domain coverage.

Domain Participation:
  Domain              | Techniques Covered | Avg SQ Score | Unique Contribution
  --------------------|-------------------|--------------|---------------------
  Windows Endpoint    |       142         |     56       | 28 techniques covered ONLY here
  Network Firewall    |        67         |     48       | 8 techniques covered ONLY here
  Cloud (AWS)         |        54         |     62       | 12 techniques covered ONLY here
  Identity (Okta)     |        38         |     71       | 6 techniques covered ONLY here
  Linux Endpoint      |        31         |     44       | 4 techniques covered ONLY here
  Email (O365)        |        22         |     68       | 3 techniques covered ONLY here
  NDR (ExtraHop)      |        18         |     51       | 2 techniques covered ONLY here
  DNS                 |        11         |     53       | 1 technique covered ONLY here
  Proxy/Web Gateway   |        14         |     47       | 0 techniques (all overlap with network)

Top 10 Single-Domain Techniques at Highest Risk:
  Technique                              | Domain           | Confidence | Risk Factor
  ---------------------------------------|------------------|------------|------------------
  T1021.002 — SMB Admin Shares           | Win Endpoint     | 8 (Blind)  | Lateral movement, single domain
  T1055.001 — Process Injection (DLL)    | Win Endpoint     | 22 (Aband) | Defense evasion, single domain
  T1087.002 — Domain Account Discovery   | Win Endpoint     | 18 (Blind) | Discovery, no identity-domain rule
  T1071.001 — Web Protocols (C2)         | Network          | 34 (Degrad)| C2, no endpoint-domain rule
  ...
```

**Secondary output: Per-technique complementarity assessment** (see examples in "Where AI Adds Value" section above).

**Tertiary output: Domain expansion recommendations** with projected impact on Detection Confidence Scores.

## Implementation Notes

**Domain classification must be consistent.** The biggest data quality issue in this use case is inconsistent domain tagging. A rule that queries `logs-endpoint.events.process-*` in Elastic is clearly an endpoint rule, but a rule that queries `logs-*` with a filter on `event.dataset: aws.cloudtrail` could be misclassified if the domain is inferred from the index pattern rather than the filter. Implement a canonical domain taxonomy and validate rule-to-domain mappings.

**ATT&CK data sources provide a reference framework.** MITRE ATT&CK v13+ includes formal data source objects that map techniques to the telemetry types needed to detect them. Use this as a reference to identify *expected* domains per technique and flag techniques where your coverage is narrower than the ATT&CK data source mapping suggests. For example, if ATT&CK says T1078 is detectable via "Logon Session," "User Account Authentication," and "Cloud Service Modification," and your coverage is only in the identity domain, the reference mapping highlights missing cloud and endpoint domain coverage.

**Quality-weighted domain counting is essential.** A technique with rules in 3 domains where 2 of those rules are Blind does not have meaningful tri-domain coverage. Always present both raw domain counts and quality-weighted counts. The gap between them reveals "phantom coverage" — techniques that appear well-covered by domain breadth but are actually single-domain in practice.

**Entity normalization across domains is a SIEM prerequisite, but verify it.** The cross-domain entity overlap analysis depends on entity fields being consistently named and semantically equivalent across domains. If Okta logs use `actor.alternateId` and Windows logs use `winlog.event_data.TargetUserName` for the same logical user, the fields must be normalized to a common schema (e.g., `user.name` in ECS) before cross-domain correlation can work. Verify normalization rather than assuming it.

**Cross-domain correlation rules are the ultimate validation.** If you have SIEM correlation rules that successfully join alerts across domains (e.g., "same user triggers Okta alert and endpoint alert within 15 minutes"), those rules are empirical evidence that cross-domain coverage is operational, not just theoretical. Inventory existing correlation rules and include them in the analysis as "proven cross-domain links."

## Dependencies

- [UC-06: MITRE ATT&CK Posture Scoring](06-mitre-attack-posture-scoring.md) — provides Signal Quality Scores and Detection Confidence Scores that distinguish healthy from broken cross-domain coverage. Hard dependency.
- [Domain-Aware Entity Framework](../../concepts/domain-aware-entity-framework.md) — defines entity fields per domain, which drives the entity overlap analysis. Hard dependency.
- [UC-07: Threat-Informed Gap Prioritization](07-threat-informed-gap-prioritization.md) — provides threat relevance context for prioritizing domain expansion investments.
- [UC-08: Kill Chain Completeness Analysis](08-kill-chain-completeness-analysis.md) — kill chain breakpoints often occur where single-domain detection fails. The two analyses are complementary.

## Complexity Assessment

| Dimension | Rating | Notes |
|---|---|---|
| Data engineering | Medium | Domain classification of rules, cross-domain entity field mapping, and quality-weighted aggregation require a well-structured data pipeline. The domain taxonomy must be maintained as new data sources are onboarded. |
| AI/ML complexity | Medium | LLM must read and compare rule queries across different query languages (KQL, EQL, SPL, Sigma) and assess whether they detect complementary observables. This is a semantic reasoning task similar to UC-06's observable diversity assessment but scoped to cross-domain comparison. |
| Integration effort | Low-Medium | Consumes UC-06 output and rule metadata. Output is primarily analytical reports and recommendations. No real-time SIEM integration required. Optional integration: generate suggested cross-domain correlation rules as SIEM query templates. |
| Overall | **Medium** | The deterministic foundation (domain counting, entity mapping) is straightforward. The AI value-add (complementarity assessment, investment prioritization) requires competent prompt engineering but not complex model architecture. The hardest part is maintaining accurate domain classification across a large rule inventory. |

## Real-World Considerations

**Single-domain dependency is common and underappreciated.** In most enterprise SOCs, 50-60% of ATT&CK techniques are covered by rules in only one data source domain — typically Windows Endpoint. This means a single telemetry collection failure (EDR agent misconfiguration, log shipping outage, ingestion pipeline error) can eliminate detection for over half your covered techniques. The cross-domain analysis makes this risk visible.

**Domain expansion is often cheaper than rule tuning.** A Degraded endpoint rule for T1078 (SQ: 38 due to service account noise) might take 8 hours to tune properly. Writing a new identity-domain rule for T1078 that detects Okta authentication anomalies might take 4 hours and immediately provides cross-domain coverage. The investment analysis should compare domain expansion vs. existing rule improvement for each technique.

**Not every technique needs multi-domain coverage.** Some techniques are inherently single-domain. T1059.006 (Python) is primarily an endpoint observable. T1114.003 (Email Forwarding Rule) is inherently an email-domain detection. Do not set a goal of "every technique in 3+ domains" — set a goal of "critical techniques have coverage in every domain where the technique produces observable artifacts."

**Cross-domain correlation rules are high-value but high-maintenance.** Correlation rules that join alerts across domains require careful tuning — too broad and they generate combinatorial explosion of correlated alerts, too narrow and they miss legitimate correlations. The entity overlap analysis from this use case helps identify where correlation is feasible, but building and maintaining those correlation rules is an ongoing SIEM engineering effort.

**Vendor lock-in risk.** Heavy reliance on a single vendor's telemetry (e.g., all endpoint detection via SentinelOne) creates a "domain within a domain" concentration risk. If your endpoint coverage comes from two different sources (SentinelOne + Sysmon), losing one still leaves partial endpoint coverage. Consider sub-domain diversity for critical detection areas.

## Related Use Cases

- [UC-06: MITRE ATT&CK Posture Scoring](06-mitre-attack-posture-scoring.md) — provides the scored posture data that distinguishes healthy from phantom cross-domain coverage.
- [UC-07: Threat-Informed Gap Prioritization](07-threat-informed-gap-prioritization.md) — threat relevance context drives which techniques most need cross-domain investment.
- [UC-08: Kill Chain Completeness Analysis](08-kill-chain-completeness-analysis.md) — kill chain breakpoints often correlate with single-domain dependency points.
- [UC-10: Executive Posture Reporting](10-executive-posture-reporting.md) — cross-domain coverage metrics are a key component of executive posture narratives.
- [UC-04: Detection Drift Monitoring](../alert-analysis/04-detection-drift-monitoring.md) — detects when a data source domain experiences collection failures, immediately flagging single-domain techniques at risk.
- [UC-02: Entity Cardinality Noise Analysis](../alert-analysis/02-entity-cardinality-noise-analysis.md) — entity distribution analysis per domain feeds into the entity overlap assessment.

## References

- [MITRE ATT&CK Data Sources](https://attack.mitre.org/datasources/) — formal mapping of techniques to data sources. The authoritative reference for "which domains should cover which techniques."
- [DeTT&CT](https://github.com/rabobank-cdc/DeTTECT) — includes data source quality scoring and visibility coverage per technique.
- [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) — layer visualization supports multi-layer overlays, allowing side-by-side domain coverage comparison.
- [Elastic Common Schema (ECS)](https://www.elastic.co/guide/en/ecs/current/index.html) — cross-domain field normalization schema. Example of how entity fields are standardized across data sources.
- [Splunk Common Information Model (CIM)](https://docs.splunk.com/Documentation/CIM/latest/User/Overview) — Splunk's cross-domain normalization schema.
- [Microsoft Sentinel ASIM](https://learn.microsoft.com/en-us/azure/sentinel/normalization) — Sentinel's Advanced Security Information Model for cross-domain normalization.
- [Domain-Aware Entity Framework](../../concepts/domain-aware-entity-framework.md) — this repo's framework for domain-specific entity field definitions.
