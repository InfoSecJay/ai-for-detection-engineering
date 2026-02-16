# Pillar 1: SOC Data Foundations

> **Core principle:** "Security context and data are available and can be queried by machines (API, MCP, etc) in a scalable and reliable manner."

This is the pillar that kills most AI initiatives before they start. If an AI agent can't reliably query your data, get consistent field values, and access enrichment context, it doesn't matter how good the model is. Garbage in, garbage out — and LLMs are remarkably good at making garbage sound convincing.

---

## 1.1 Log Parsing and Normalization

### The Rule: Field Extraction Belongs to Your SIEM Ingest Pipeline, Not AI

Every log source entering your SIEM must be parsed into structured fields using your platform's normalized schema. This is not an AI problem. This is a data engineering problem with known, deterministic solutions.

**Platform-specific schemas:**

| Platform | Normalization Schema | Key Documentation |
|----------|---------------------|-------------------|
| Elastic Security | [Elastic Common Schema (ECS)](https://www.elastic.co/guide/en/ecs/current/index.html) | Field reference, mapping guides |
| Splunk Enterprise Security | [Common Information Model (CIM)](https://docs.splunk.com/Documentation/CIM/latest/User/Overview) | Data model reference, CIM add-ons |
| Microsoft Sentinel | [Advanced Security Information Model (ASIM)](https://learn.microsoft.com/en-us/azure/sentinel/normalization) | Schema reference, parsers |

### What "Normalized" Actually Means

Normalization is not just "logs are in the SIEM." It means:

1. **Common entity fields are reliably populated across sources.** Every authentication event — whether from Okta, Azure AD, on-prem AD, or a Linux PAM module — populates the same `user.name`, `source.ip`, and `event.outcome` fields (or your schema's equivalent).

2. **Field values are consistent.** If one source logs usernames as `DOMAIN\user` and another logs `user@domain.com`, your ingest pipeline resolves this before the data hits the index. Not after. Not "sometimes."

3. **Timestamps are parsed and timezone-normalized.** Every event has a parsed `@timestamp` (or equivalent) in UTC. If your timestamp parsing is broken, your correlation rules are broken, and any AI agent reasoning about event sequences will draw wrong conclusions.

### Platform Examples

**Elastic — Ingest Pipelines and Integrations:**
```yaml
# Example: Ingest pipeline for custom application logs
processors:
  - grok:
      field: message
      patterns:
        - "%{TIMESTAMP_ISO8601:event.created} %{LOGLEVEL:log.level} %{GREEDYDATA:event.reason}"
  - set:
      field: event.kind
      value: event
  - set:
      field: event.category
      value: authentication
      if: "ctx.event?.reason?.contains('login')"
```
Elastic Fleet integrations handle this for supported sources. For custom sources, you write ingest pipelines with grok, dissect, or scripted processors. This is deterministic, testable, and version-controlled.

**Splunk — Props/Transforms and CIM Mapping:**
```ini
# props.conf
[custom:application:auth]
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%3N%Z
SHOULD_LINEMERGE = false
TRANSFORMS-cim = auth_action_lookup, auth_user_extract

# transforms.conf
[auth_user_extract]
REGEX = user=(\S+)
FORMAT = user AS $1
```
Splunk CIM add-ons and TA (Technology Add-ons) map raw fields to CIM-compliant data model fields. If you're writing detection rules against CIM data models (`Authentication`, `Network_Traffic`, `Endpoint`), every source feeding that model must conform.

**Sentinel — ASIM Parsers:**
```kql
// ASIM Authentication parser - unifying multiple sources
let DisabledParsers = materialize(_GetWatchlist('ASimDisabledParsers')
    | where SearchKey in ('Any') | project SourceSpecificParser);
let BuiltInDisabled = toscalar(DisabledParsers | where SourceSpecificParser == '_Im_Authentication_AAD');
union isfuzzy=true
    vimAuthenticationEmpty,
    _Im_Authentication_AAD(disabled=(BuiltInDisabled == 'true')),
    _Im_Authentication_WindowsSecurityEvent(disabled=false)
```
ASIM unifying parsers normalize across sources. Each source gets a source-specific parser that maps its raw fields to ASIM schema fields.

### The Key Requirement

**Common entity fields must be reliably populated across all sources:**

- `user.name` / `user.id` — Who did it
- `source.ip` / `destination.ip` — Network context
- `host.name` / `host.id` — Where it happened
- `event.action` / `event.outcome` — What happened and did it succeed
- `process.name` / `process.pid` — What ran (endpoint telemetry)
- `file.path` / `file.hash` — What was touched (file telemetry)

If an AI agent asks "show me all failed logins for user jsmith in the last 24 hours" and three of your five authentication sources don't populate `user.name` consistently, the agent gets an incomplete answer and doesn't know it. That's worse than no AI at all.

---

## 1.2 Enrichment with Security Context

### The Rule: Alert Enrichment Is a SIEM/SOAR Function, Not AI

When an alert fires, the triage analyst needs context: Is this a crown jewel asset? Is the user a privileged admin? Is the source IP a known threat? Is the host missing critical patches?

All of this is enrichment via structured lookups. It is an API call, a lookup table, or a SOAR playbook step. It is not an AI problem.

**If your SOAR can look up a hostname in ServiceNow, that's an API call, not AI.**

### Enrichment Sources You Must Have Wired Up

| Source | What It Provides | How It's Accessed |
|--------|-----------------|-------------------|
| **Asset inventory / CMDB** | Asset criticality, business owner, OS version, asset group | ServiceNow API, custom CMDB, Splunk Asset & Identity framework |
| **Active Directory / Identity Provider** | Group memberships, privileged account flags, account status, last password change | LDAP queries, Azure AD Graph API, Okta API |
| **Vulnerability scan data** | Open CVEs on the host, severity scores, patch status | Tenable/Qualys/Rapid7 API, SIEM lookup tables |
| **Threat intelligence** | IoC matches (IP, domain, hash), threat actor attribution, TTP mapping | MISP, ThreatConnect, Anomali, SIEM TI integrations |
| **HR / Identity data** | Employment status, department, manager, recent role changes, termination date | HR system API, IAM platform |
| **Geo-IP / ASN data** | Geographic location, ISP, ASN ownership for IP addresses | MaxMind, SIEM built-in geo lookup |

### How Enrichment Should Work

**At ingest time (where possible):**
- Geo-IP enrichment on every event with a public IP
- Threat intel matching against known IoCs during ingest
- Asset criticality tags appended based on hostname/IP lookup

**At alert time (via SOAR playbook):**
- CMDB lookup for the affected host: business criticality, owner, environment (prod/dev)
- AD/IdP lookup for the user: privileged account? recently created? terminated?
- Vulnerability data for the host: any unpatched critical CVEs relevant to the attack technique?
- Reputation check for any external IPs/domains in the alert

**Example SOAR enrichment step (pseudocode):**
```python
# This is what a SOAR playbook does. It's not AI. It's an API call.
def enrich_alert(alert):
    host = cmdb_client.get_asset(alert.host_name)
    alert.asset_criticality = host.criticality  # "crown_jewel", "standard", "dev"
    alert.asset_owner = host.business_owner

    user = ad_client.get_user(alert.user_name)
    alert.is_privileged = user.is_member_of("Domain Admins")
    alert.account_age_days = (now() - user.created_date).days

    vulns = tenable_client.get_host_vulns(alert.host_ip)
    alert.critical_cves = [v for v in vulns if v.severity == "critical"]

    ti_match = tip_client.check_indicator(alert.source_ip)
    alert.threat_intel_hit = ti_match is not None
    alert.threat_actor = ti_match.actor if ti_match else None

    return alert  # Now the analyst (or AI agent) has context
```

The AI agent's job starts **after** enrichment — reasoning over the enriched alert, not performing the lookups. If you hand an LLM a raw alert with no context and ask "is this malicious?", you'll get a coin flip dressed up in confident prose.

---

## 1.3 Machine-Queryable Data Access

### The "API or Die" Audit

For AI agents to function, they need programmatic access to your security data. Run an audit of every data source and tool your SOC uses. For each one, answer:

1. **Does it have an API?** If not, it's a dead end for AI integration.
2. **Is the API documented and stable?** Undocumented internal APIs break without warning.
3. **What are the rate limits?** An AI agent making 100 queries per minute will hit rate limits that a human analyst never would.
4. **What authentication is required?** Service accounts, API keys, OAuth tokens — all need to be managed.
5. **What data can the API return?** Some APIs give you summaries but not raw events. That matters.

### Federated Data Access

In most SOCs, data lives in multiple systems:

- **SIEM** — Event logs, alerts, detection rule metadata
- **SOAR** — Case data, playbook execution history, enrichment results
- **Ticketing system** — Incident records, analyst notes, resolution details
- **Threat intel platform** — IoC databases, threat reports
- **EDR** — Endpoint telemetry, process trees, file analysis
- **Cloud security** — Cloud audit logs, configuration findings

An AI agent that can only query the SIEM has a partial view. You need a data access layer — whether that's an MCP server, a custom API gateway, or a SOAR platform that federates queries — that gives agents access to the data they need without requiring separate integrations for each tool.

### Past Incident Data: The Hard Problem

AI agents that help with triage, detection tuning, or threat hunting need access to past incident data: how were similar alerts resolved? What was the final disposition? What investigation steps did analysts take?

This data is often:
- **Trapped in freeform text** — Analyst notes in a ticketing system with no structured fields
- **Inconsistently recorded** — Some analysts write detailed notes; others close tickets with "false positive"
- **Siloed in a tool that predates your current stack** — Migration from a legacy SIEM left years of case data behind

If your past incident data is not machine-queryable and structured, AI agents cannot learn from organizational history. This is one of the highest-value and hardest-to-fix data foundation gaps.

**Practical steps:**
- Mandate structured closure fields on every alert: disposition (true positive, false positive, benign true positive), MITRE ATT&CK technique, affected assets, root cause
- Back-fill structured data from at least the last 12 months of incidents, even if it requires manual tagging
- Store case data in a system with an API, not a shared drive full of Word documents

---

## 1.4 Data Quality and Governance

### Field Population Rates

You need to measure and track the population rate of key fields across your data sources. The target: **>95% population rate for critical fields.**

What this looks like in practice:

**Elastic — Field population audit:**
```esql
FROM logs-*
| STATS
    total = COUNT(*),
    has_user = COUNT(user.name),
    has_source_ip = COUNT(source.ip),
    has_host = COUNT(host.name)
| EVAL
    user_pct = ROUND(has_user * 100.0 / total, 2),
    source_ip_pct = ROUND(has_source_ip * 100.0 / total, 2),
    host_pct = ROUND(has_host * 100.0 / total, 2)
```

**Splunk — Field population audit:**
```spl
index=* earliest=-24h
| fieldsummary
| where field IN ("user", "src_ip", "dest", "action", "app")
| eval population_pct = round((count / distinct_count) * 100, 2)
| table field count distinct_count population_pct
```

**Sentinel — Field population audit:**
```kql
CommonSecurityLog
| where TimeGenerated > ago(24h)
| summarize
    Total = count(),
    HasSourceIP = countif(isnotempty(SourceIP)),
    HasDestIP = countif(isnotempty(DestinationIP)),
    HasUser = countif(isnotempty(SourceUserName))
| extend
    SourceIP_Pct = round(100.0 * HasSourceIP / Total, 2),
    DestIP_Pct = round(100.0 * HasDestIP / Total, 2),
    User_Pct = round(100.0 * HasUser / Total, 2)
```

### Data Retention

- **Minimum 90 days** of hot/searchable data for alert investigation
- **12+ months** for threat hunting and trend analysis
- If your AI agent needs to answer "has this user ever done this before?", 30 days of retention gives you a pinhole view

### Tracking Data Quality Issues

Data quality degrades silently. A source stops sending logs, a field mapping breaks after an upgrade, a new log source arrives with non-compliant field names. You need:

1. **Automated data quality monitors** — Scheduled queries that check for unexpected drops in event volume, field population rate changes, new unmapped sources
2. **A data quality dashboard** — Visible to the detection engineering team, reviewed weekly
3. **An intake process for new log sources** — No source goes into production without field mapping validation against your normalization schema

If you don't track data quality, you won't know when your AI agent starts getting wrong answers because the data changed underneath it.

---

## 1.5 Self-Assessment Questions

Use these questions (adapted from Chuvakin's framework) to evaluate your data foundations:

1. **Can a machine query all your key security data sources via API?** List every source. For each one that requires manual export, screen scraping, or human intervention to access, you have a gap.

2. **Are your logs parsed into a normalized schema with >95% field population on critical fields?** Run the field population queries above. If critical fields are below 95%, fix the ingest pipelines before deploying AI.

3. **Is your enrichment automated?** When an alert fires, does context (asset criticality, user privilege level, threat intel matches) arrive automatically, or does an analyst have to manually look it up?

4. **Do you have machine-queryable past incident data?** Can you programmatically answer "how did we resolve the last 10 alerts of this type?" If the answer is in freeform ticket notes, that's not machine-queryable.

5. **Do you monitor data quality?** If a log source stops sending events or a field mapping breaks, how long until you notice? Hours? Days? Never?

6. **Is your data retention sufficient?** Can you query 90+ days of security events for investigation? 12+ months for hunting and trend analysis?

7. **Can you access threat intelligence programmatically?** Is your TIP integrated with your SIEM/SOAR, or is it a standalone portal that analysts check manually?

**Scoring guidance:**
- **5-7 "yes" answers:** Your data foundations are likely ready for AI use cases. Proceed to Pillar 2.
- **3-4 "yes" answers:** You have gaps that will limit AI effectiveness. Prioritize closing them.
- **0-2 "yes" answers:** Stop here. Fix your data foundations before investing in AI. The returns won't be there.

---

## Key Takeaway

Data foundations are not glamorous. Fixing field mappings, wiring up enrichment APIs, and running data quality audits is ungrateful work. But every AI use case in this repo — triage assistance, detection gap analysis, rule quality scoring, hunt hypothesis generation — depends on the assumption that the data is structured, complete, accessible, and correct.

If that assumption is wrong, AI doesn't help. It makes things worse by generating confident-sounding answers from broken data.

Fix the pipes before you install the AI faucet.
