# Alert Log Fields

Reference for SIEM detection alert schemas. Every major SIEM stores alerts in a structured, documented format. Understanding these schemas is a prerequisite for any AI-assisted analysis — the fields already exist, parsed and normalized by the SIEM. AI consumes them; it does not create them.

## What an Alert Record Contains

Every SIEM alert record has two layers:

1. **Alert metadata** — fields the SIEM adds when a rule fires: rule ID, rule name, severity, risk score, MITRE ATT&CK mapping, timestamp, workflow status.
2. **Source event fields** — the original event data that triggered the rule, parsed into the platform's normalized schema plus any vendor-specific fields that survived ingestion.

Field availability depends on the SIEM doing its parsing job — not on any AI processing.

---

## Elastic Security

### Alert Index

```
.internal.alerts-security.alerts-default-*
```

### Alert Metadata Fields

| Field | Description |
|---|---|
| `kibana.alert.rule.name` | Detection rule name |
| `kibana.alert.rule.uuid` | Unique rule identifier |
| `kibana.alert.severity` | Rule severity: low, medium, high, critical |
| `kibana.alert.risk_score` | Numeric risk score (0-100) |
| `kibana.alert.rule.threat` | MITRE ATT&CK mapping (tactic, technique, subtechnique) |
| `@timestamp` | Alert creation timestamp |
| `kibana.alert.workflow_status` | Alert status: open, acknowledged, closed |
| `kibana.alert.rule.type` | Rule type: query, eql, threshold, machine_learning, etc. |
| `kibana.alert.rule.description` | Rule description text |
| `kibana.alert.rule.tags` | Rule tags including MITRE references |

### ECS-Normalized Source Fields

These fields follow the [Elastic Common Schema (ECS)](https://www.elastic.co/guide/en/ecs/current/index.html) and appear in alert documents when the triggering event contained the relevant data.

| Field | Description | Example |
|---|---|---|
| `host.name` | Hostname of the source system | `WORKSTATION-01` |
| `host.os.name` | Operating system name | `Windows 11` |
| `user.name` | Username associated with the event | `jsmith` |
| `user.domain` | User domain | `CORP` |
| `process.name` | Process name | `powershell.exe` |
| `process.command_line` | Full command line | `powershell.exe -enc SQBFAFgA...` |
| `process.pid` | Process ID | `4528` |
| `process.parent.name` | Parent process name | `cmd.exe` |
| `process.parent.command_line` | Parent command line | `cmd.exe /c start powershell` |
| `source.ip` | Source IP address | `10.1.5.22` |
| `destination.ip` | Destination IP address | `203.0.113.50` |
| `destination.port` | Destination port | `443` |
| `file.path` | File path | `C:\Users\jsmith\malware.exe` |
| `file.hash.sha256` | File SHA-256 hash | `a1b2c3d4...` |
| `event.action` | Action taken | `connection_attempted` |
| `event.category` | Event category | `process`, `network`, `authentication` |
| `event.outcome` | Event outcome | `success`, `failure` |

### Vendor-Specific Fields

When data sources are ingested via integrations, vendor-specific fields are preserved under their namespace:

| Namespace | Source | Example Fields |
|---|---|---|
| `aws.cloudtrail.*` | AWS CloudTrail | `aws.cloudtrail.user_identity.type`, `aws.cloudtrail.request_parameters` |
| `okta.*` | Okta Identity | `okta.actor.display_name`, `okta.outcome.reason` |
| `panw.*` | Palo Alto Networks | `panw.panos.action`, `panw.panos.rule_name` |
| `crowdstrike.*` | CrowdStrike Falcon | `crowdstrike.event.PatternDispositionDescription` |
| `azure.*` | Microsoft Azure | `azure.signinlogs.properties.conditional_access_status` |

---

## Splunk (Enterprise Security)

### Notable Events Index

```
index=notable
```

### Standard Notable Event Fields

| Field | Description |
|---|---|
| `source` | Correlation search that generated the notable |
| `search_name` | Name of the correlation search |
| `dest` | Destination host or IP |
| `src` | Source host or IP |
| `user` | Username associated with the event |
| `signature` | Detection signature name |
| `severity` | Severity: informational, low, medium, high, critical |
| `urgency` | Calculated urgency combining severity and asset/identity priority |
| `status` | Workflow status |
| `owner` | Assigned analyst |
| `rule_name` | Detection rule name |
| `security_domain` | Domain: access, endpoint, network, threat, identity, audit |

### CIM-Normalized Fields

Splunk uses the [Common Information Model (CIM)](https://docs.splunk.com/Documentation/CIM/latest/User/Overview) to normalize fields per data model:

- **Authentication**: `action`, `app`, `src`, `dest`, `user`, `authentication_method`
- **Endpoint (Processes)**: `process`, `process_name`, `parent_process`, `parent_process_name`, `process_id`, `user`, `dest`
- **Network Traffic**: `src_ip`, `dest_ip`, `dest_port`, `transport`, `action`, `bytes_in`, `bytes_out`
- **Malware**: `file_name`, `file_path`, `file_hash`, `action`, `signature`

Field availability depends on the data source having a matching CIM-compatible Technology Add-on (TA) installed.

---

## Microsoft Sentinel

### Alert and Incident Tables

| Table | Description |
|---|---|
| `SecurityAlert` | Individual alerts from analytics rules and connected products |
| `SecurityIncident` | Incidents (grouped alerts) with status and assignment |
| `AlertEvidence` | Entities and evidence linked to alerts (Defender-sourced) |

### Key SecurityAlert Fields

| Field | Description |
|---|---|
| `AlertName` | Detection rule name |
| `AlertSeverity` | Severity: Informational, Low, Medium, High |
| `Description` | Alert description |
| `Tactics` | MITRE ATT&CK tactics (comma-separated) |
| `Techniques` | MITRE ATT&CK technique IDs |
| `ProviderName` | Source product (e.g., `Microsoft Defender for Endpoint`) |
| `Entities` | JSON array of extracted entities (account, host, IP, file, process) |
| `TimeGenerated` | Alert creation timestamp |
| `Status` | Alert status |

### Standardized Entity Schema

Sentinel extracts entities into a structured JSON format within the `Entities` field:

- **Account**: `Name`, `UPNSuffix`, `AadUserId`, `Sid`
- **Host**: `HostName`, `DnsDomain`, `OSFamily`, `OSVersion`
- **IP**: `Address`
- **File**: `Name`, `Directory`
- **Process**: `ProcessId`, `CommandLine`, `ImageFile`

### ASIM-Normalized Source Data

Sentinel uses the [Advanced Security Information Model (ASIM)](https://learn.microsoft.com/en-us/azure/sentinel/normalization) to normalize ingested data across sources. ASIM-normalized tables use a common schema per event type (authentication, DNS, network session, process, file, etc.) regardless of the original data source.

---

## Key Takeaway

These field schemas are what any AI-based analysis operates on. The fields are already structured, normalized, and queryable. When building AI-assisted triage or investigation workflows, the starting point is always: what fields does this alert already contain, and what do they tell us?
