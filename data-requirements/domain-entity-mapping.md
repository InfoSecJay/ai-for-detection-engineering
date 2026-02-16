# Domain Entity Mapping

Quick reference mapping which normalized and vendor-specific fields are meaningful entity fields per data source domain. Entity concepts — host, user, process, network tuple, cloud API action — are universal across platforms even though field names differ.

This document is a companion to the [Domain-Aware Entity Framework](../concepts/domain-aware-entity-framework.md) concept doc, which explains the reasoning behind domain-specific entity analysis. This page focuses on the practical field mappings.

---

## Windows Endpoint

| Attribute | Value |
|---|---|
| **Primary Entities** | Process, User, Host, File |
| **What makes this domain unique** | Deep process lineage (parent-child chains), command-line visibility, registry and service manipulation, lateral movement artifacts. Process tree context is critical — a process in isolation tells you little. |

**Key Normalized Fields (ECS):**
- `process.name`, `process.command_line`, `process.pid`, `process.executable`
- `process.parent.name`, `process.parent.command_line`, `process.parent.pid`
- `user.name`, `user.domain`, `user.id`
- `host.name`, `host.os.name`, `host.os.version`
- `file.path`, `file.name`, `file.hash.sha256`, `file.hash.md5`
- `registry.path`, `registry.value`, `registry.data.strings`
- `event.action`, `event.category`, `event.provider`

**Key Vendor-Specific Fields:**
- Sysmon: `winlog.event_id`, `winlog.event_data.TargetFilename`, `winlog.event_data.GrantedAccess`
- CrowdStrike: `crowdstrike.event.GrandparentCommandLine`, `crowdstrike.event.PatternDispositionDescription`
- Defender for Endpoint: `DeviceProcessEvents.InitiatingProcessCommandLine`, `DeviceProcessEvents.AccountName`

---

## Linux Endpoint

| Attribute | Value |
|---|---|
| **Primary Entities** | Process, User, Host, File |
| **What makes this domain unique** | Shell-centric execution (bash, sh, python interpreters), cron/systemd persistence, SSH-based access, container/pod context when containerized. User context often maps to service accounts. |

**Key Normalized Fields (ECS):**
- `process.name`, `process.command_line`, `process.executable`, `process.working_directory`
- `process.parent.name`, `process.parent.command_line`
- `user.name`, `user.id`, `user.effective.id`
- `host.name`, `host.os.type` (`linux`), `host.os.platform`
- `file.path`, `file.owner`, `file.mode`
- `event.action`, `event.module`

**Key Vendor-Specific Fields:**
- Auditd: `auditd.log.syscall`, `auditd.log.key`, `auditd.log.exe`
- CrowdStrike (Linux sensor): `crowdstrike.event.CommandLine`
- Container context: `container.id`, `container.name`, `container.image.name`, `orchestrator.namespace`

---

## Network Firewall

| Attribute | Value |
|---|---|
| **Primary Entities** | Network Tuple (src/dst IP + port + protocol), Zone |
| **What makes this domain unique** | No process or user context — analysis is purely network-level. Entity analysis centers on traffic patterns, connection volumes, blocked vs. allowed actions, and zone-to-zone flows. |

**Key Normalized Fields (ECS):**
- `source.ip`, `source.port`, `source.nat.ip`
- `destination.ip`, `destination.port`, `destination.nat.ip`
- `network.transport` (tcp, udp), `network.protocol`, `network.direction`
- `event.action` (allowed, denied, dropped)
- `observer.name` (firewall hostname), `observer.type` (`firewall`)
- `rule.name` (firewall rule that matched)

**Key Vendor-Specific Fields:**
- Palo Alto: `panw.panos.action`, `panw.panos.rule_name`, `panw.panos.source_zone`, `panw.panos.destination_zone`, `panw.panos.app`
- Fortinet: `fortinet.firewall.action`, `fortinet.firewall.policyid`
- Cisco ASA: `cisco.asa.message_id`, `cisco.asa.connection_id`

---

## NDR (Network Detection & Response)

| Attribute | Value |
|---|---|
| **Primary Entities** | Network Tuple, DNS Query, TLS Certificate, HTTP Transaction |
| **What makes this domain unique** | Deep packet metadata (not just flow). Provides protocol-level context: DNS queries, TLS certificate details, HTTP headers, JA3/JA4 fingerprints. Entity analysis focuses on behavioral patterns in protocol usage. |

**Key Normalized Fields (ECS):**
- `source.ip`, `destination.ip`, `destination.port`
- `dns.question.name`, `dns.answers.data`, `dns.response_code`
- `tls.server.subject`, `tls.server.ja3s`, `tls.client.ja3`
- `http.request.method`, `http.request.body.content`, `url.full`
- `network.bytes`, `network.packets`

**Key Vendor-Specific Fields:**
- Zeek: `zeek.connection.uid`, `zeek.dns.query`, `zeek.ssl.server_name`, `zeek.http.uri`
- Corelight: `corelight.conn.community_id`
- Vectra: `vectra.detection.category`, `vectra.detection.score`

---

## Cloud — AWS

| Attribute | Value |
|---|---|
| **Primary Entities** | IAM Principal, API Action, Resource ARN, Region |
| **What makes this domain unique** | No host/process context — everything is API-driven. Entity analysis centers on who (principal) did what (API action) to which resource, from where (source IP, user agent). Role assumption chains add complexity. |

**Key Normalized Fields (ECS):**
- `cloud.provider` (`aws`), `cloud.region`, `cloud.account.id`
- `event.action` (API call name), `event.outcome` (success/failure)
- `user.name`, `user.id`
- `source.ip`, `user_agent.original`

**Key Vendor-Specific Fields:**
- CloudTrail: `aws.cloudtrail.user_identity.type` (Root, IAMUser, AssumedRole, AWSService)
- `aws.cloudtrail.user_identity.arn`, `aws.cloudtrail.user_identity.session_context.session_issuer.arn`
- `aws.cloudtrail.request_parameters`, `aws.cloudtrail.response_elements`
- `aws.cloudtrail.event_type`, `aws.cloudtrail.error_code`, `aws.cloudtrail.error_message`
- `aws.cloudtrail.resources.arn`, `aws.cloudtrail.resources.type`

---

## Identity — Okta

| Attribute | Value |
|---|---|
| **Primary Entities** | User, Application, Authentication Factor, Client Device |
| **What makes this domain unique** | Identity-centric — every event maps to a user action. Entity analysis focuses on authentication patterns, factor usage, application access, and geographic/device anomalies. Session context (IP, device, geo) is key. |

**Key Normalized Fields (ECS):**
- `user.name`, `user.email`, `user.full_name`
- `event.action` (e.g., `user.session.start`, `user.authentication.sso`)
- `event.outcome` (success/failure)
- `source.ip`, `source.geo.country_name`, `source.geo.city_name`
- `user_agent.original`, `user_agent.os.name`

**Key Vendor-Specific Fields:**
- `okta.actor.display_name`, `okta.actor.alternate_id`
- `okta.client.device`, `okta.client.zone`
- `okta.outcome.reason`, `okta.outcome.result`
- `okta.authentication_context.credential_type` (PASSWORD, MFA, etc.)
- `okta.authentication_context.authentication_provider`
- `okta.target` (array of target objects: user, app, policy affected)
- `okta.security_context.as_org`, `okta.security_context.isp`

---

## Email

| Attribute | Value |
|---|---|
| **Primary Entities** | Sender, Recipient, Attachment, URL, Message-ID |
| **What makes this domain unique** | Content-oriented — entity analysis involves sender reputation, header analysis, attachment characteristics, embedded URLs, and delivery patterns. Phishing detection relies on combining multiple weak signals. |

**Key Normalized Fields (ECS):**
- `email.from.address`, `email.to.address`, `email.cc.address`
- `email.subject`, `email.message_id`
- `email.attachments.file.name`, `email.attachments.file.hash.sha256`, `email.attachments.file.mime_type`
- `url.full`, `url.domain` (extracted from email body)
- `source.ip` (sending MTA IP)
- `event.action` (delivered, quarantined, blocked)

**Key Vendor-Specific Fields:**
- Microsoft 365/Defender for Office: `EmailEvents.SenderFromAddress`, `EmailEvents.DeliveryAction`, `EmailAttachmentInfo.FileName`
- Proofpoint: `proofpoint.message.spamScore`, `proofpoint.message.phishScore`, `proofpoint.message.clickTime`
- Mimecast: `mimecast.direction`, `mimecast.act`

---

## DNS

| Attribute | Value |
|---|---|
| **Primary Entities** | Queried Domain, Query Type, Resolver Client, Response Data |
| **What makes this domain unique** | High-volume, low-fidelity signal individually — value comes from patterns. Entity analysis focuses on domain reputation, query volume anomalies, record type distribution (TXT for exfiltration), and NXDomain rates. |

**Key Normalized Fields (ECS):**
- `dns.question.name`, `dns.question.type` (A, AAAA, TXT, MX, CNAME)
- `dns.answers.data`, `dns.answers.type`, `dns.answers.ttl`
- `dns.response_code` (NOERROR, NXDOMAIN, SERVFAIL)
- `source.ip` (client requesting resolution)
- `destination.ip` (DNS resolver)

**Key Vendor-Specific Fields:**
- Infoblox: `infoblox.dns.query`, `infoblox.dns.response`
- Windows DNS: `winlog.event_data.QueryName`, `winlog.event_data.QueryType`
- Route 53 (AWS): logged via CloudTrail or VPC DNS query logs

---

## Proxy / Web Gateway

| Attribute | Value |
|---|---|
| **Primary Entities** | User, URL/Domain, HTTP Method, Content Category, Action |
| **What makes this domain unique** | User-to-URL mapping with content categorization. Entity analysis links users to their web activity patterns, identifies uncategorized or newly-registered domains, and tracks data transfer volumes per destination. |

**Key Normalized Fields (ECS):**
- `url.full`, `url.domain`, `url.path`, `url.query`
- `http.request.method`, `http.response.status_code`
- `http.request.bytes`, `http.response.bytes`
- `user.name` (from proxy authentication)
- `source.ip` (client IP), `destination.ip` (resolved server IP)
- `event.action` (allowed, blocked, warned)
- `tls.server.subject`, `tls.version`

**Key Vendor-Specific Fields:**
- Zscaler: `zscaler.action`, `zscaler.urlcategory`, `zscaler.department`, `zscaler.dlpengine`
- Symantec ProxySG: `symantec.proxy.categories`, `symantec.proxy.filter_result`
- Squid: `squid.code`, `squid.hierarchy_code`

---

## Cross-Domain Entity Summary

| Domain | Primary Entity | Core Question |
|---|---|---|
| Windows Endpoint | Process + User + Host | What ran, who ran it, what's the process tree? |
| Linux Endpoint | Process + User + Host | What executed, under which account, in what context (container/host)? |
| Network Firewall | Network Tuple | What connected to what, was it allowed or blocked? |
| NDR | Network Tuple + Protocol | What protocols and behaviors were observed at the network level? |
| Cloud AWS | IAM Principal + API Action | Who called which API on what resource? |
| Identity (Okta) | User + Auth Factor | How did this user authenticate, from where, to what app? |
| Email | Sender + Recipient + Content | Who sent what to whom, with what attachments/links? |
| DNS | Domain + Query Type | What domains are being resolved, by whom, how often? |
| Proxy / Web Gateway | User + URL + Action | What web resources are users accessing, and what was blocked? |

These mappings are reference data. They inform how AI systems should interpret and correlate entities when analyzing alerts from different domains.
