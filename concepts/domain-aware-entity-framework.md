# Domain-Aware Entity Framework

## Why Data-Source-Specific Entity Fields Matter

Generic alert analysis fails because it treats all data sources the same. A firewall log and an endpoint process event share almost no meaningful fields, yet most alert pipelines flatten them into the same structure and lose the signal that matters.

The Domain-Aware Entity Framework defines **which fields carry meaning** for each data source domain, organized into three tiers:

- **Primary entities**: The fields that uniquely identify what happened and to whom. These are the fields you group by, correlate on, and use to determine if two alerts describe the same activity.
- **Secondary entities**: Fields that add critical context to the primary entities. These distinguish benign from malicious activity within the same primary grouping.
- **Supporting entities**: Fields that provide forensic depth. Useful during investigation but rarely sufficient for triage decisions on their own.

The tier assignment is not arbitrary. It reflects how SOC analysts actually triage alerts in each domain. A firewall analyst looks at source IP, destination IP, and port first. An endpoint analyst looks at hostname, username, and process name first. The framework encodes this operational reality.

---

## Entity Definitions by Domain

### Windows Endpoint (SentinelOne, Sysmon, Windows Security)

**Primary observable differentiator**: Process execution context -- the combination of who ran what on which machine tells you most of what you need for initial triage.

| Tier | Field | Description |
|------|-------|-------------|
| Primary | `host.name` | The endpoint where the activity occurred |
| Primary | `user.name` | The account context executing the process |
| Primary | `process.name` | The executable name (e.g., `powershell.exe`, `cmd.exe`) |
| Secondary | `process.command_line` | Full command line arguments -- this is where malicious intent becomes visible |
| Secondary | `process.parent.name` | Parent process -- critical for detecting LOLBin chains |
| Secondary | `file.path` | File system paths involved (created, modified, accessed) |
| Supporting | `process.pid` | Process identifier for correlation within a single host |
| Supporting | `process.hash` | SHA256/MD5 of the executable for reputation lookups |
| Supporting | `registry.path` | Registry keys modified (persistence, config changes) |

**Domain-specific signal quality indicators**:
- Command line diversity: High cardinality in `process.command_line` for the same `process.name` suggests the rule is catching varied behaviors (potentially noisy). Low cardinality suggests consistent, specific detection.
- Parent-child consistency: If `process.parent.name` is always the same value (e.g., `explorer.exe`), the rule may be detecting normal user-initiated activity.
- Host concentration: If 80% of alerts come from 3 hosts out of 10,000, investigate those hosts -- they are either compromised or generating false positives.

**Example YAML config**:

```yaml
domain: windows_endpoint
data_sources:
  - sentinelone
  - sysmon
  - windows_security

entities:
  primary:
    - field: host.name
      description: Endpoint hostname
      cardinality_baseline: medium  # expect hundreds to low thousands
    - field: user.name
      description: Executing user account
      cardinality_baseline: medium
    - field: process.name
      description: Executable filename
      cardinality_baseline: low  # most rules target specific processes

  secondary:
    - field: process.command_line
      description: Full command line with arguments
      cardinality_baseline: high  # nearly unique per execution
    - field: process.parent.name
      description: Parent process executable
      cardinality_baseline: low
    - field: file.path
      description: File system path involved
      cardinality_baseline: high

  supporting:
    - field: process.pid
      description: Process ID
      cardinality_baseline: high
    - field: process.hash
      description: SHA256 hash of executable
      cardinality_baseline: low_to_medium
    - field: registry.path
      description: Registry key path
      cardinality_baseline: medium

signal_quality_weights:
  command_line_diversity: 0.30
  host_concentration: 0.25
  user_concentration: 0.20
  parent_process_consistency: 0.15
  volume_stability: 0.10
```

---

### Linux Endpoint (Auditd, syslog, EDR)

**Primary observable differentiator**: Process execution with user context. Linux environments tend to have more service accounts and cron-driven activity, making user-to-process mapping especially important for separating automation noise from interactive threats.

| Tier | Field | Description |
|------|-------|-------------|
| Primary | `host.name` | The Linux host |
| Primary | `user.name` | The executing user (including effective UID) |
| Primary | `process.name` | The binary name |
| Secondary | `process.command_line` | Full command with arguments |
| Secondary | `file.path` | Files read, written, or executed |
| Supporting | `process.pid` | Process ID |
| Supporting | `process.working_directory` | CWD at execution time -- reveals context (e.g., `/tmp` is suspicious for most binaries) |

**Domain-specific signal quality indicators**:
- Cron noise ratio: Percentage of alerts attributable to scheduled tasks. High ratio degrades signal quality.
- Root vs. unprivileged: Rules that only fire under root may be detecting legitimate admin activity or may be catching privilege escalation -- context from `process.working_directory` helps distinguish.
- Container vs. host: If `host.name` values are container IDs (ephemeral), entity cardinality metrics must account for pod churn.

**Example YAML config**:

```yaml
domain: linux_endpoint
data_sources:
  - auditd
  - syslog
  - edr_linux

entities:
  primary:
    - field: host.name
      description: Linux hostname or container ID
      cardinality_baseline: medium
    - field: user.name
      description: Executing user (effective UID)
      cardinality_baseline: low_to_medium
    - field: process.name
      description: Binary name
      cardinality_baseline: low

  secondary:
    - field: process.command_line
      description: Full command with arguments
      cardinality_baseline: high
    - field: file.path
      description: File paths involved
      cardinality_baseline: high

  supporting:
    - field: process.pid
      description: Process identifier
      cardinality_baseline: high
    - field: process.working_directory
      description: Working directory at execution time
      cardinality_baseline: medium

signal_quality_weights:
  command_line_diversity: 0.30
  host_concentration: 0.25
  user_concentration: 0.20
  cron_noise_ratio: 0.15
  volume_stability: 0.10
```

---

### Network Firewall (Palo Alto, Fortigate)

**Primary observable differentiator**: Network tuple -- source, destination, and port define the conversation. Application identification (from NGFW) adds a layer that raw netflow cannot provide.

| Tier | Field | Description |
|------|-------|-------------|
| Primary | `source.ip` | Source IP address of the connection |
| Primary | `destination.ip` | Destination IP address |
| Primary | `destination.port` | Destination port |
| Secondary | `network.application` | NGFW-identified application (e.g., `ssl`, `web-browsing`, `dns`) |
| Secondary | `rule.name` | Firewall policy rule that matched |
| Supporting | `source.nat.ip` | NAT'd source IP (for tracing internal origin behind NAT) |
| Supporting | `network.bytes` | Total bytes transferred |

**Domain-specific signal quality indicators**:
- IP concentration: A rule triggering on thousands of unique source IPs is likely matching broad scanning or a misconfigured policy. A rule triggering on 5 specific destination IPs may be detecting C2 beaconing.
- Port diversity: If `destination.port` has high cardinality for the same rule, the rule is probably too broad (matching general traffic patterns rather than specific threats).
- Bytes outlier detection: Anomalous `network.bytes` values within a rule's alert population can indicate data exfiltration hidden among normal matches.

**Example YAML config**:

```yaml
domain: network_firewall
data_sources:
  - palo_alto
  - fortigate

entities:
  primary:
    - field: source.ip
      description: Source IP address
      cardinality_baseline: high
    - field: destination.ip
      description: Destination IP address
      cardinality_baseline: medium_to_high
    - field: destination.port
      description: Destination port number
      cardinality_baseline: low

  secondary:
    - field: network.application
      description: Application identified by NGFW
      cardinality_baseline: low
    - field: rule.name
      description: Matched firewall policy rule
      cardinality_baseline: low

  supporting:
    - field: source.nat.ip
      description: NAT translated source IP
      cardinality_baseline: low_to_medium
    - field: network.bytes
      description: Total bytes in session
      cardinality_baseline: high

signal_quality_weights:
  source_ip_concentration: 0.30
  destination_ip_concentration: 0.25
  port_diversity: 0.20
  application_consistency: 0.15
  volume_stability: 0.10
```

---

### Network Detection / NDR (ExtraHop)

**Primary observable differentiator**: Network conversations with protocol-level context. NDR differs from firewall logs because it provides deeper protocol inspection and behavioral baselines, making the protocol and application fields more meaningful.

| Tier | Field | Description |
|------|-------|-------------|
| Primary | `source.ip` | Internal or external source |
| Primary | `destination.ip` | Target of the network activity |
| Secondary | `network.protocol` | Protocol (TCP, UDP, ICMP, etc.) |
| Secondary | `network.application` | Application-layer protocol (HTTP, DNS, SMB, etc.) |
| Supporting | `network.bytes` | Data volume for anomaly context |
| Supporting | `event.duration` | Connection duration (long-lived connections may indicate tunneling) |

**Domain-specific signal quality indicators**:
- Protocol anomaly rate: Detections on unusual protocol/port combinations (e.g., DNS over port 443) carry higher signal quality than detections on standard protocol/port mappings.
- Duration distribution: Tight clustering of `event.duration` values may indicate automated beaconing. Wide variance suggests diverse traffic types caught by an overly broad rule.
- Internal-to-internal ratio: NDR rules that primarily trigger on east-west traffic have different baselines than north-south rules.

**Example YAML config**:

```yaml
domain: ndr
data_sources:
  - extrahop

entities:
  primary:
    - field: source.ip
      description: Source IP address
      cardinality_baseline: medium_to_high
    - field: destination.ip
      description: Destination IP address
      cardinality_baseline: medium

  secondary:
    - field: network.protocol
      description: Transport-layer protocol
      cardinality_baseline: very_low
    - field: network.application
      description: Application-layer protocol identification
      cardinality_baseline: low

  supporting:
    - field: network.bytes
      description: Bytes transferred in session
      cardinality_baseline: high
    - field: event.duration
      description: Connection duration in milliseconds
      cardinality_baseline: high

signal_quality_weights:
  source_ip_concentration: 0.25
  destination_ip_concentration: 0.25
  protocol_anomaly_rate: 0.20
  duration_distribution: 0.15
  volume_stability: 0.15
```

---

### Cloud AWS (CloudTrail)

**Primary observable differentiator**: API action performed by a specific identity within a specific account. Cloud detection is identity-centric -- the "who did what in which account" triple is the foundation of every triage decision.

| Tier | Field | Description |
|------|-------|-------------|
| Primary | `cloud.account.id` | AWS account where the action occurred |
| Primary | `user.name` / `user_identity.arn` | The IAM principal (user, role, or service) |
| Primary | `event.action` | The API call (e.g., `RunInstances`, `PutBucketPolicy`) |
| Secondary | `source.ip` | IP address of the caller (useful for detecting compromised credentials) |
| Secondary | `aws.cloudtrail.request_parameters` | The parameters passed to the API call (the "how" of the action) |
| Supporting | `aws.cloudtrail.user_identity.type` | Identity type: `IAMUser`, `AssumedRole`, `AWSService`, `Root` |
| Supporting | `cloud.region` | AWS region where the action was performed |

**Domain-specific signal quality indicators**:
- Identity type distribution: Rules that fire only on `AssumedRole` identities behave differently from those firing on `IAMUser`. Service-linked roles generate noise in many detection rules.
- Account concentration: A rule triggering across many accounts may indicate a systemic misconfiguration. A rule triggering in one account may indicate targeted activity.
- Request parameter specificity: High diversity in `request_parameters` for the same `event.action` suggests the rule is catching varied legitimate usage.

**Example YAML config**:

```yaml
domain: cloud_aws
data_sources:
  - cloudtrail

entities:
  primary:
    - field: cloud.account.id
      description: AWS account identifier
      cardinality_baseline: low  # most orgs have tens to low hundreds
    - field: user.name
      description: IAM principal name or ARN
      cardinality_baseline: medium
    - field: event.action
      description: CloudTrail API action name
      cardinality_baseline: low  # rules typically target specific actions

  secondary:
    - field: source.ip
      description: Caller IP address
      cardinality_baseline: medium_to_high
    - field: aws.cloudtrail.request_parameters
      description: API call parameters (JSON)
      cardinality_baseline: high

  supporting:
    - field: aws.cloudtrail.user_identity.type
      description: Type of IAM identity
      cardinality_baseline: very_low
    - field: cloud.region
      description: AWS region
      cardinality_baseline: low

signal_quality_weights:
  identity_concentration: 0.30
  account_concentration: 0.20
  source_ip_diversity: 0.20
  request_parameter_specificity: 0.15
  volume_stability: 0.15
```

---

### Identity (Okta)

**Primary observable differentiator**: User action outcome -- who did what, and did it succeed or fail. Identity detection is centered on behavioral anomalies in authentication and authorization patterns.

| Tier | Field | Description |
|------|-------|-------------|
| Primary | `user.name` / `actor.alternateId` | The Okta user performing the action |
| Primary | `event.action` | The Okta event type (e.g., `user.session.start`, `user.account.lock`) |
| Secondary | `source.ip` | IP address of the request |
| Secondary | `okta.client.user_agent` | Client user agent string |
| Supporting | `okta.outcome.result` | Success, failure, or other outcome |
| Supporting | `okta.target` | Target resources of the action |

**Domain-specific signal quality indicators**:
- Failure-to-success ratio: Rules detecting authentication failures should track whether failures are followed by successes (credential stuffing with hits) or are purely failed (noise or lockout scenarios).
- Geographic diversity of `source.ip`: Same user authenticating from multiple geolocations in a short window is high-signal.
- User agent consistency: A single user with many different `okta.client.user_agent` values may indicate credential theft or token replay.

**Example YAML config**:

```yaml
domain: identity_okta
data_sources:
  - okta

entities:
  primary:
    - field: user.name
      description: Okta actor (alternateId)
      cardinality_baseline: medium
    - field: event.action
      description: Okta event type
      cardinality_baseline: low

  secondary:
    - field: source.ip
      description: Request source IP
      cardinality_baseline: medium_to_high
    - field: okta.client.user_agent
      description: Client user agent string
      cardinality_baseline: medium

  supporting:
    - field: okta.outcome.result
      description: Action outcome (SUCCESS, FAILURE, etc.)
      cardinality_baseline: very_low
    - field: okta.target
      description: Target resource identifiers
      cardinality_baseline: medium

signal_quality_weights:
  user_concentration: 0.30
  source_ip_diversity: 0.25
  failure_success_ratio: 0.20
  user_agent_consistency: 0.15
  volume_stability: 0.10
```

---

### Email (O365, Proofpoint)

**Primary observable differentiator**: Sender-to-recipient relationship with content indicators. Email detection hinges on whether the sender, content, and delivery characteristics match known malicious patterns.

| Tier | Field | Description |
|------|-------|-------------|
| Primary | `email.from.address` | Sender email address (envelope or header) |
| Primary | `email.to.address` | Recipient email address |
| Secondary | `email.subject` | Subject line (useful for campaign correlation) |
| Secondary | `email.attachments.hash` | Hash of attachments (SHA256) |
| Supporting | `source.ip` | Sending mail server IP |
| Supporting | `email.delivery_action` | What happened: delivered, quarantined, blocked |

**Domain-specific signal quality indicators**:
- Sender domain diversity: A rule triggering on many different sender domains suggests a phishing campaign using varied infrastructure. A rule triggering on one sender domain may be a miscategorized legitimate sender.
- Recipient concentration: If the same 5 users receive all flagged emails, they may be targeted (spearphishing) or may be on public-facing distribution lists (noise).
- Attachment hash uniqueness: Low cardinality in `email.attachments.hash` means the same file is being sent repeatedly -- likely a known-bad indicator or a campaign.

**Example YAML config**:

```yaml
domain: email
data_sources:
  - office365
  - proofpoint

entities:
  primary:
    - field: email.from.address
      description: Sender email address
      cardinality_baseline: medium_to_high
    - field: email.to.address
      description: Recipient email address
      cardinality_baseline: medium

  secondary:
    - field: email.subject
      description: Email subject line
      cardinality_baseline: high
    - field: email.attachments.hash
      description: SHA256 hash of attachments
      cardinality_baseline: low_to_medium

  supporting:
    - field: source.ip
      description: Sending mail server IP
      cardinality_baseline: medium
    - field: email.delivery_action
      description: Delivery disposition (delivered, blocked, quarantined)
      cardinality_baseline: very_low

signal_quality_weights:
  sender_domain_diversity: 0.25
  recipient_concentration: 0.25
  attachment_hash_uniqueness: 0.20
  delivery_action_distribution: 0.15
  volume_stability: 0.15
```

---

### DNS

**Primary observable differentiator**: Query name and the requesting client. DNS detection is about identifying malicious domains being resolved, and which internal hosts are resolving them.

| Tier | Field | Description |
|------|-------|-------------|
| Primary | `dns.question.name` | The domain name being queried |
| Primary | `source.ip` | The internal host making the query |
| Secondary | `dns.answers.data` | The resolved IP address(es) |
| Secondary | `dns.question.type` | Record type (A, AAAA, TXT, MX, CNAME) |
| Supporting | `dns.response_code` | Response code (NOERROR, NXDOMAIN, SERVFAIL) |

**Domain-specific signal quality indicators**:
- Query name entropy: High entropy in `dns.question.name` values (e.g., `a8f3k2.evil.com`, `b9d1m7.evil.com`) strongly suggests DGA or DNS tunneling.
- TXT record ratio: An elevated proportion of TXT queries indicates possible DNS-based data exfiltration or C2.
- NXDOMAIN rate: High NXDOMAIN responses for a rule's alerts suggest DGA activity (many generated domains, few resolving).
- Client concentration: A single internal host making all the flagged queries is a strong indicator of compromise on that specific host.

**Example YAML config**:

```yaml
domain: dns
data_sources:
  - dns_logs
  - passive_dns

entities:
  primary:
    - field: dns.question.name
      description: Queried domain name
      cardinality_baseline: high
    - field: source.ip
      description: Internal client IP making the query
      cardinality_baseline: medium

  secondary:
    - field: dns.answers.data
      description: Resolved IP address(es)
      cardinality_baseline: medium_to_high
    - field: dns.question.type
      description: DNS record type
      cardinality_baseline: very_low

  supporting:
    - field: dns.response_code
      description: DNS response code
      cardinality_baseline: very_low

signal_quality_weights:
  query_name_entropy: 0.30
  client_concentration: 0.25
  record_type_distribution: 0.15
  response_code_distribution: 0.15
  volume_stability: 0.15
```

---

### Proxy / Web Gateway (Zscaler, BlueCoat)

**Primary observable differentiator**: User-to-destination mapping with URL context. Proxy detection combines identity (who is browsing) with destination (where they are going) in a way that raw network logs cannot.

| Tier | Field | Description |
|------|-------|-------------|
| Primary | `source.ip` | Internal client IP |
| Primary | `url.domain` | Destination domain |
| Primary | `user.name` | Authenticated user (if proxy authenticates) |
| Secondary | `url.path` | URL path (reveals specific resource accessed) |
| Secondary | `http.response.status_code` | HTTP response code |
| Supporting | `http.request.method` | HTTP method (GET, POST, PUT, etc.) |
| Supporting | `url.category` | Proxy-assigned URL category |

**Domain-specific signal quality indicators**:
- Domain reputation correlation: Alerts on domains with known-bad reputation are higher signal than alerts on uncategorized domains.
- POST method concentration: High ratio of POST requests to an unusual domain suggests data exfiltration or C2 communication.
- Category override rate: If a significant portion of flagged URLs are in "allowed" categories, the rule may need category-based exclusions.
- User-to-domain mapping: A single user repeatedly hitting the same flagged domain is different from many users hitting it once (widespread campaign vs. targeted compromise).

**Example YAML config**:

```yaml
domain: proxy_web_gateway
data_sources:
  - zscaler
  - bluecoat

entities:
  primary:
    - field: source.ip
      description: Internal client IP
      cardinality_baseline: high
    - field: url.domain
      description: Destination domain
      cardinality_baseline: medium_to_high
    - field: user.name
      description: Authenticated proxy user
      cardinality_baseline: medium

  secondary:
    - field: url.path
      description: URL path component
      cardinality_baseline: high
    - field: http.response.status_code
      description: HTTP response status code
      cardinality_baseline: low

  supporting:
    - field: http.request.method
      description: HTTP request method
      cardinality_baseline: very_low
    - field: url.category
      description: URL category assigned by proxy
      cardinality_baseline: low

signal_quality_weights:
  domain_concentration: 0.25
  user_concentration: 0.25
  url_path_diversity: 0.20
  http_method_distribution: 0.15
  volume_stability: 0.15
```

---

## Cross-Domain Considerations

### Field Mapping Conflicts

The same logical concept maps to different field names across domains. `source.ip` in a firewall log is the connection initiator. `source.ip` in an email log is the sending mail server. `source.ip` in an Okta log is the user's client IP. These are semantically different and must not be blindly correlated.

The entity framework handles this by keeping entity definitions domain-scoped. Cross-domain correlation happens at a higher layer that understands the semantic mapping:

```
Firewall source.ip  -->  "internal client IP"  <--  Proxy source.ip
CloudTrail source.ip --> "API caller IP"        <--  Okta source.ip
Email source.ip      --> "mail server IP"       (no direct equivalent in other domains)
```

### Cardinality Baseline Calibration

The `cardinality_baseline` values in each config are starting points. They must be calibrated per environment:

- An organization with 500 employees will have different `user.name` cardinality than one with 50,000.
- A cloud-native company may have 200 AWS accounts; a traditional enterprise may have 5.
- Container-heavy Linux environments will have extremely high `host.name` cardinality due to ephemeral pod IDs.

Calibration process:
1. Run a 30-day baseline query for each primary entity field per domain.
2. Record the distinct count and the distribution (top-10 values and their percentages).
3. Set the baseline to the observed cardinality tier.
4. Re-calibrate quarterly or after major infrastructure changes.

### Using the Framework

This framework feeds directly into two downstream systems:

1. **Signal Quality Scoring**: Entity diversity, concentration, and entropy are calculated using the primary and secondary fields defined here. The tier assignments determine which fields receive the highest weights in the composite score.

2. **Detection Confidence Scoring**: Observable diversity across rules for the same technique is measured by comparing entity field coverage. A technique with rules covering `process.command_line` (endpoint), `source.ip` (network), and `user.name` (identity) has higher observable diversity than a technique with three rules all keying on `process.name`.

The framework is not a normalization schema (that is ECS or OCSF's job). It is a **triage prioritization schema** -- it tells the scoring system which fields matter most for determining whether a rule is producing meaningful alerts.
