# Where AI Fits (And Doesn't)

## Why This Document Exists

The security industry is saturated with claims about AI. Vendors claim AI detects threats. Analysts hear AI will replace them. Executives are told AI will solve the alert fatigue problem. Most of these claims are imprecise at best, misleading at worst.

This document draws a clear, specific line between problems that AI should solve and problems that AI should not solve in the context of detection engineering and SOC operations. The distinction is not about AI capability -- modern LLMs can do many of these tasks. The distinction is about **whether AI is the right tool**, considering reliability, auditability, cost, and failure modes.

The guiding principle: **Use deterministic methods for deterministic problems. Use AI for problems that require judgment, synthesis, or natural language understanding.** When in doubt, err toward deterministic. AI should earn its place by solving problems that deterministic approaches cannot.

---

## NOT an AI Problem

These tasks have deterministic, reliable solutions. Using AI here adds cost, latency, non-determinism, and failure modes without meaningful benefit.

### Field Parsing and Log Normalization

**What it is**: Converting raw log formats (syslog, JSON, CEF, LEEF, Windows Event XML) into a normalized schema (ECS, OCSF, or custom).

**Why AI is wrong here**: Log formats are structured. A Sysmon Event ID 1 always has the same XML schema. A Palo Alto traffic log always has the same CSV column order. Parsing rules are write-once-run-forever. A regex or Grok pattern that parses a Palo Alto log today will parse the same format in two years.

**What to use instead**: Logstash/Filebeat pipelines, Cribl packs, SIEM-native parsers, custom regex. These are deterministic, fast, and verifiable.

**Concrete example**: Parsing a Sysmon Event ID 1 (Process Create) log entry:
- Deterministic: XPath expression extracts `CommandLine`, `ParentImage`, `User` fields. Runs in microseconds. Never hallucinates a field value. Testable with unit tests.
- AI: Send the raw XML to an LLM, ask it to extract fields. Takes 500ms+, costs money per call, might occasionally misparse an unusual field, cannot be unit tested for correctness.

The deterministic approach is superior in every dimension.

---

### Enrichment Lookups (CMDB, AD, Threat Intel, Vulnerability Data)

**What it is**: Taking an entity from an alert (IP address, hostname, username, file hash) and looking up contextual information from reference databases.

**Why AI is wrong here**: This is a key-value lookup. "Is this IP in our threat intel feed?" is answered by a database query, not reasoning. "What department does this user belong to?" is an LDAP/AD query.

**What to use instead**: API calls to enrichment sources, SIEM lookup tables, SOAR enrichment playbook steps, direct database queries.

**Concrete example**: Enriching a source IP from a firewall alert:
- Deterministic: Query threat intel API (VirusTotal, AbuseIPDB) with the IP. Query CMDB for the hostname mapped to that IP. Query vulnerability scanner for open findings on that host. Three API calls, three definitive answers.
- AI: Ask an LLM "what do you know about IP 10.2.3.4?" It knows nothing -- it has no access to your internal CMDB, and its training data about public IPs is stale. Even with tool use, the AI is just calling the same APIs with extra overhead.

---

### IOC Matching

**What it is**: Checking whether an observable (hash, domain, IP, URL) matches a known indicator of compromise from threat intelligence feeds.

**Why AI is wrong here**: This is a set membership test. Either the hash is in the blocklist or it isn't. There is no ambiguity, no judgment, no context dependency.

**What to use instead**: Hash lookups against threat intel platforms (MISP, OpenCTI, commercial feeds), SIEM-native IOC matching, YARA rules for file-level matching.

**Concrete example**: Checking if a file hash from an email attachment matches known malware:
- Deterministic: SHA256 lookup against VirusTotal, internal malware repository, and MISP instance. Binary answer: match or no match, with metadata about the match.
- AI: Would need to be given the same lookup results to be useful. Adds nothing to the matching step itself.

---

### Alert Correlation by Shared Fields

**What it is**: Grouping alerts that share common entity values (same host, same user, same source IP) within a time window.

**Why AI is wrong here**: Correlation by shared fields is a join operation. "Find all alerts in the last 15 minutes where host.name = SERVER01" is a database query. It requires no reasoning about whether the alerts are related -- they are related by definition because they share the specified field value.

**What to use instead**: SIEM correlation rules, SPL/KQL/Lucene queries with aggregation, SOAR incident grouping logic.

**Concrete example**: Grouping alerts for the same host within a time window:
- Deterministic: `SELECT * FROM alerts WHERE host_name = 'SERVER01' AND timestamp BETWEEN '2024-01-15T10:00:00' AND '2024-01-15T10:15:00'` -- fast, complete, correct.
- AI: Not needed for the grouping itself. AI may add value in interpreting what the grouped alerts mean together (see "IS an AI problem" section below).

---

### Rule Format Conversion (pySigma)

**What it is**: Converting detection rule logic from one query language or format to another (Sigma to KQL, Sigma to SPL, YARA-L to custom format).

**Why AI is wrong here**: Query language conversion is a formal translation problem. The semantics of detection logic are well-defined. `process.name = "powershell.exe" AND process.command_line contains "-enc"` has an exact, unambiguous translation in every SIEM query language. pySigma handles this deterministically with backend plugins.

**What to use instead**: pySigma with appropriate backend plugins, custom transpilers for non-Sigma formats.

**Concrete example**: Converting a Sigma rule to Splunk SPL:
- Deterministic (pySigma): Parses the YAML, maps field names using a field mapping config, applies backend-specific syntax rules. Output is correct by construction. Can be validated by running the query.
- AI: Ask an LLM to rewrite the Sigma YAML as SPL. It will produce something that looks right but may have subtle field mapping errors, incorrect escaping, or wrong boolean logic grouping. These bugs are hard to catch and can cause missed detections in production.

For rule conversion, deterministic translation is not just equivalent to AI -- it is categorically better. A hallucinated query that runs without errors but misses 10% of matches is worse than a query that fails loudly.

---

### Basic Aggregation Metrics (Volume, Cardinality, Time Series)

**What it is**: Computing alert volume, distinct entity counts, time-series patterns, and other statistical measures.

**Why AI is wrong here**: These are SQL aggregation queries. `COUNT(*)`, `COUNT(DISTINCT host_name)`, `GROUP BY date_trunc('day', timestamp)`. The results are exact numbers, not estimates or interpretations.

**What to use instead**: SIEM queries, database aggregations, pandas/numpy for offline analysis.

**Concrete example**: Computing Signal Quality Score inputs:
- Deterministic: Run the queries defined in the Signal Quality Scoring methodology. Get exact numbers. Feed them through the scoring formula.
- AI: Asking an LLM to estimate these values from raw data would be slower, less accurate, and non-reproducible.

---

### SOAR Playbook Execution (Fixed-Sequence Actions)

**What it is**: Running a predefined sequence of actions in response to an alert: enrich IP, check reputation, query EDR for process tree, create ticket, notify analyst.

**Why AI is wrong here**: SOAR playbooks are deterministic workflows. Each step has a defined input, a defined action, and a defined output. There is no judgment involved in executing the sequence. The judgment was applied when the playbook was designed.

**What to use instead**: SOAR platforms (Palo Alto XSOAR, Splunk SOAR, Tines, Shuffle), workflow automation tools.

**Concrete example**: Running an initial triage playbook for a phishing alert:
- Deterministic: Step 1: Extract sender domain. Step 2: Check domain age via WHOIS. Step 3: Check URL reputation. Step 4: Detonate attachments in sandbox. Step 5: Compile results into ticket. Each step is an API call with deterministic logic.
- AI: Not needed for execution. AI may add value in deciding which playbook to run (dynamic routing) or interpreting the combined results (see next section).

---

### Threshold Alerting

**What it is**: Firing an alert when a metric crosses a predefined threshold (e.g., more than 50 failed logins in 5 minutes, more than 1GB egress to a single external IP in an hour).

**Why AI is wrong here**: Threshold comparison is arithmetic. If count > 50, alert. No interpretation needed. The hard part is choosing the right threshold, not evaluating it.

**What to use instead**: SIEM alert rules, monitoring platform thresholds (Prometheus alerting rules, CloudWatch alarms).

**Note**: AI may add value in dynamically adjusting thresholds based on historical baselines (adaptive thresholds), but the basic threshold evaluation itself is deterministic.

---

## IS an AI Problem

These tasks require judgment, synthesis, natural language understanding, or reasoning over ambiguous inputs. Deterministic approaches either cannot solve them or produce brittle, incomplete solutions.

### Narrative Synthesis Over Multiple Data Points

**What it is**: Taking a collection of structured data (alert details, enrichment results, entity context, historical patterns) and producing a coherent, human-readable summary that explains what happened and why it matters.

**Why AI is right here**: Narrative synthesis requires understanding which data points are relevant, how they relate to each other, and how to communicate the synthesis in a way that is useful to a human analyst. This is a natural language generation task that deterministic templates handle poorly. Templates produce formulaic, repetitive narratives that analysts learn to ignore. AI-generated narratives can adapt to the specific combination of data points.

**Concrete example**: Generating an alert summary from enrichment data:
- Template-based (deterministic): "Alert: Suspicious PowerShell on SERVER01. User: jsmith. Command: [raw command line]. Host risk: Medium. User department: Finance." -- Technically accurate but flat. Analyst must mentally reconstruct the context.
- AI-generated: "PowerShell executed a download cradle on SERVER01, a Finance department workstation assigned to John Smith. The downloaded URL (hxxp://evil[.]com/payload) resolves to an IP flagged in 3 threat intel feeds as Cobalt Strike infrastructure. Smith has no history of PowerShell usage in the last 90 days, and this host has no software deployment tools that would explain this pattern. This appears to be initial access via a phishing payload." -- Synthesizes multiple data points into an actionable narrative.

The AI version is more useful because it connects dots that a template cannot. It reasons about what is abnormal for this specific user and host.

---

### Semantic Reasoning About Detection Logic

**What it is**: Understanding what a detection rule actually detects, identifying logical gaps, suggesting improvements, or explaining the rule to someone unfamiliar with the query language.

**Why AI is right here**: Detection rules are written in query languages (SPL, KQL, Sigma YAML) that encode logic. Understanding the intent behind the logic -- what attack technique it targets, what evasion methods it misses, how it could be improved -- requires domain knowledge and reasoning that goes beyond syntax parsing.

**Concrete example**: Reviewing a detection rule for gaps:
- Deterministic: A linter can check syntax, validate field names, and flag performance issues. But it cannot tell you that the rule misses PowerShell invoked via `pwsh.exe` (PowerShell Core) because the rule only checks for `powershell.exe`.
- AI: "This rule detects PowerShell download cradles by matching on `process.name = powershell.exe` with specific command-line patterns. However, it misses: (1) PowerShell Core (`pwsh.exe`), (2) PowerShell invoked via `System.Management.Automation.dll` directly, (3) obfuscated command lines using string concatenation or variable substitution. Consider adding `pwsh.exe` to the process name filter and adding obfuscation-aware patterns for the command-line match."

This requires understanding both the query syntax and the threat landscape it targets.

---

### Contextual Triage Decisions with Ambiguous Signals

**What it is**: Deciding what action to take on an alert when the available evidence is inconclusive -- not clearly malicious, not clearly benign.

**Why AI is right here**: Most alerts fall in the ambiguous middle ground. The enrichment data does not give a definitive answer. The host is not known-compromised, but the behavior is unusual. The user is not on a watchlist, but the activity is outside their normal pattern. Making a judgment call about whether this warrants escalation requires weighing multiple factors with imperfect information.

**Concrete example**: Triaging an alert for unusual outbound DNS activity:
- Deterministic: DNS query to `abc123.suspicious-domain.com`. Domain is 3 days old. Not in any threat intel feed. 47 DNS queries in the last hour from one host. No other alerts on this host.
- AI triage reasoning: "The domain is newly registered (3 days old) and the query pattern (47 requests in 60 minutes with incrementing subdomains) is consistent with DNS tunneling or DGA beaconing. While the domain is not in threat intel feeds, the behavioral pattern combined with domain age warrants investigation. Recommend: isolate the host from the network, collect a full process tree from EDR, and submit the domain to sandbox analysis. Priority: High."

The AI is not hallucinating -- it is applying security domain knowledge to ambiguous evidence. A deterministic rule could flag "new domain + high query volume" but cannot articulate why this specific combination is concerning or recommend specific next steps tailored to the situation.

---

### Natural Language Generation for Reports

**What it is**: Producing human-readable reports, executive summaries, incident timelines, or detection posture assessments from structured data.

**Why AI is right here**: Report writing requires adapting tone, detail level, and focus to the audience. An executive summary of detection coverage gaps reads differently from a technical rundown for the detection engineering team. Templates are rigid and produce reports that all look the same regardless of what the data shows.

**Concrete example**: Generating a weekly detection posture report:
- Template-based: "This week: 12,847 alerts. Top rule: 'Failed Login' (4,231 alerts). 3 rules had 0 alerts." -- Accurate but uninformative. Provides no insight into whether anything changed or what to do about it.
- AI-generated: "Detection posture declined this week. The 'Failed Login' rule generated 4,231 alerts (up 340% from last week's baseline of 960), driven entirely by brute-force attempts against the VPN gateway from a /24 block in Eastern Europe. This is likely a credential stuffing campaign and should be addressed with IP-based rate limiting at the VPN concentrator. Separately, three cloud detection rules went silent after the CloudTrail logging configuration was modified on Tuesday -- this appears to be a logging gap, not an absence of activity. Recommend immediate investigation of the CloudTrail configuration change."

The AI version tells a story. It identifies what changed, why it matters, and what to do about it.

---

### Query Language Translation from Natural Language

**What it is**: Converting a human's description of what they want to detect into a working query in a specific SIEM query language.

**Why AI is right here**: Natural language is ambiguous. "Show me all failed logins from outside the US in the last week" requires understanding the intent, mapping it to available fields, knowing the data model, and producing syntactically correct query language. This is a many-to-one mapping (many natural language phrasings, one correct query) that deterministic approaches handle poorly.

**Concrete example**: An analyst wants to hunt for lateral movement:
- Analyst says: "Find any cases where a user authenticated to more than 5 unique hosts in under 10 minutes using RDP"
- AI translates to KQL:
```kql
SecurityEvent
| where EventID == 4624
| where LogonType == 10
| summarize DistinctHosts = dcount(Computer),
            HostList = make_set(Computer)
    by Account, bin(TimeGenerated, 10m)
| where DistinctHosts > 5
```

This requires understanding that "RDP" maps to LogonType 10 in Windows Security Event 4624, that "5 unique hosts" means `dcount(Computer) > 5`, and that "10 minutes" translates to `bin(TimeGenerated, 10m)`. A deterministic translator would need a comprehensive mapping of natural language security concepts to query constructs -- which is effectively what an LLM has learned.

**Important caveat**: The AI-generated query should always be reviewed by a human before production use. LLMs can produce syntactically valid queries with semantic errors (wrong field names, incorrect logic grouping). AI is the right tool for the initial translation, not for unsupervised query deployment.

---

### Dynamic Investigation Path Planning

**What it is**: Deciding what to investigate next during an incident or threat hunt based on what has been found so far.

**Why AI is right here**: Investigation is a branching decision tree. What you look at next depends on what you found in the previous step. If the endpoint shows a malicious process, you pivot to network logs to find C2 traffic. If the network logs show connections to a known-bad IP, you search for other hosts connecting to the same IP. The decision about which pivot to make is context-dependent and requires security domain knowledge.

**Concrete example**: During a phishing investigation:
- Step 1: Email alert shows malicious attachment. AI decides: "Check if user opened the attachment -- query EDR for process creation events on the user's endpoint within 10 minutes of email delivery."
- Step 2: EDR shows `winword.exe` spawned `powershell.exe`. AI decides: "This is a macro-enabled document dropping a payload. Get the PowerShell command line and check for network connections from this process."
- Step 3: PowerShell connected to `evil.com`. AI decides: "Search all network logs for any host connecting to `evil.com` in the last 30 days to identify other potential victims."

Each step's direction depends on the previous step's results. A SOAR playbook could handle a linear investigation path, but cannot adapt when the evidence leads somewhere unexpected. AI can.

---

### Threat Report Analysis and TTP Extraction

**What it is**: Reading threat intelligence reports (blog posts, PDF reports, STIX bundles in prose) and extracting structured TTP information: what techniques were used, what indicators were observed, what detection opportunities exist.

**Why AI is right here**: Threat reports are written in natural language with varying formats, styles, and levels of detail. Extracting structured data from unstructured text is a core NLP task. Deterministic approaches (regex, keyword matching) miss context-dependent references ("the adversary then moved laterally" -- the specific technique is not named, but the behavior implies T1021).

**Concrete example**: Processing a threat intelligence blog post about a new ransomware campaign:
- Deterministic: Regex extracts IOCs (hashes, IPs, domains) from the text. Keyword matching finds "PowerShell" and "Cobalt Strike." But misses: "The operators leveraged a legitimate remote access tool to maintain persistence" -- this is T1219 (Remote Access Software) but the specific tool name is not mentioned in a way regex can match.
- AI: Extracts IOCs AND behavioral TTPs: "The report describes initial access via spearphishing (T1566.001), execution via macro-enabled documents (T1204.002), persistence via a legitimate remote access tool (T1219), lateral movement via RDP (T1021.001), and data exfiltration via HTTPS to cloud storage (T1567.002). The report does not name the remote access tool, but the described behavior is consistent with AnyDesk or TeamViewer based on the installation path mentioned."

AI understands the implicit mappings between described behaviors and formal technique classifications.

---

### Quality Assessment Requiring Security Domain Judgment

**What it is**: Evaluating whether a detection rule, a set of alert triage actions, or a security configuration is "good" -- not just syntactically correct, but operationally effective.

**Why AI is right here**: Quality assessment requires understanding the intent behind the artifact, the operational context it exists in, and the tradeoffs involved. "Is this detection rule good?" cannot be answered by a linter. It requires reasoning about: Does the rule catch the technique it claims to detect? Does it produce actionable alerts? Are the field mappings correct for the target SIEM? Is the threshold appropriate for the environment size?

**Concrete example**: Evaluating a new Sigma rule submitted by a junior analyst:
- Deterministic: Validate YAML syntax, check that referenced fields exist in the schema, verify the rule compiles to valid backend queries. All pass.
- AI review: "This rule detects `certutil.exe` downloading files by matching on `process.command_line contains 'urlcache'`. The rule is syntactically correct but has gaps: (1) It misses the `-split` flag variation commonly used in attacks. (2) The field `process.command_line` is case-sensitive in the target SIEM -- an attacker using `CertUtil.exe` would evade detection. (3) The rule would benefit from a parent process filter to exclude legitimate certificate operations triggered by Windows Update. Recommend adding case-insensitive matching and expanding the command-line patterns."

---

## The Gray Zone

Some tasks sit on the boundary. Today's best practice may shift as AI capabilities and reliability improve.

### Adaptive Thresholds
Currently: Statistical methods (z-scores, MAD, percentile-based) work well for simple time-series anomalies. AI adds value when the baseline itself is complex (multi-seasonal, event-driven shifts).

### Alert Deduplication
Currently: Field-based deduplication is deterministic. But identifying that two syntactically different alerts describe the same underlying incident requires some semantic understanding. Hybrid approaches (deterministic grouping + AI dedup validation) are emerging.

### Rule Tuning Suggestions
Currently: If tuning means "add this host to the exclusion list because it generates 80% of FPs," that is a deterministic recommendation from cardinality analysis. If tuning means "restructure this rule's logic to reduce false positives while maintaining detection of the target technique," that requires AI reasoning.

---

## Decision Framework

When deciding whether to use AI for a specific task, ask:

1. **Is the input structured and well-defined?** If yes, deterministic approach first.
2. **Is the output a fixed format with exact values?** If yes, deterministic approach first.
3. **Would a wrong answer be silently dangerous?** If yes, deterministic approach (or AI with mandatory human review).
4. **Does the task require synthesizing multiple heterogeneous inputs?** If yes, consider AI.
5. **Does the task require natural language understanding or generation?** If yes, AI is likely the right tool.
6. **Does the task require domain expertise applied to ambiguous evidence?** If yes, AI with human oversight.

The goal is not to minimize AI usage -- it is to maximize reliability. Use AI where it provides genuine value. Use deterministic methods where they provide guaranteed correctness. The combination is more powerful than either alone.
