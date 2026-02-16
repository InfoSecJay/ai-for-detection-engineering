# Rule File Formats

Structure reference for common detection rule formats used in detection engineering. These are the file formats that detection rules are authored, stored, and managed in — distinct from the runtime alert schemas covered in [Alert Log Fields](alert-log-fields.md).

---

## Elastic Security TOML

Elastic detection rules are stored as TOML files in the [elastic/detection-rules](https://github.com/elastic/detection-rules) repository.

### Structure

The `[rule]` block contains all rule metadata and logic:

| Field | Description |
|---|---|
| `name` | Rule name |
| `description` | Rule description |
| `severity` | low, medium, high, critical |
| `risk_score` | Numeric risk score (0-100) |
| `type` | Rule type: `query`, `eql`, `threshold`, `esql`, `machine_learning`, `new_terms` |
| `query` | Detection query in KQL, EQL, or ES|QL |
| `index` | Index patterns to query |
| `tags` | Array of tags including MITRE references |
| `language` | Query language: `kuery`, `eql`, `esql` |

MITRE ATT&CK mappings use `[[rule.threat]]` blocks. Threshold rules add `[rule.threshold]`.

### Example

```toml
[metadata]
creation_date = "2025/01/15"
integration = ["endpoint"]
maturity = "production"

[rule]
name = "Suspicious PowerShell Encoded Command"
description = """
Detects execution of PowerShell with encoded command line arguments,
a technique commonly used by attackers to obfuscate malicious commands.
"""
severity = "medium"
risk_score = 47
type = "eql"
language = "eql"
query = '''
process where host.os.type == "windows" and event.type == "start" and
  process.name : "powershell.exe" and
  process.command_line : ("*-enc*", "*-EncodedCommand*", "*-ec *")
'''
index = ["logs-endpoint.events.process-*", "winlogbeat-*"]
tags = [
    "Domain: Endpoint",
    "OS: Windows",
    "Use Case: Threat Detection",
    "Tactic: Execution",
    "Data Source: Elastic Defend"
]

[[rule.threat]]
framework = "MITRE ATT&CK"

[[rule.threat.technique]]
id = "T1059"
name = "Command and Scripting Interpreter"

[[rule.threat.technique.subtechnique]]
id = "T1059.001"
name = "PowerShell"

[rule.threat.tactic]
id = "TA0002"
name = "Execution"
```

---

## Sigma YAML

[Sigma](https://github.com/SigmaHQ/sigma) is a platform-agnostic detection rule format. Rules are written in YAML and converted to platform-specific queries using [pySigma](https://github.com/SigmaHQ/pySigma) backends.

### Structure

| Field | Description |
|---|---|
| `title` | Rule title |
| `id` | Unique UUID |
| `status` | test, experimental, stable, deprecated, unsupported |
| `description` | Rule description |
| `author` | Rule author |
| `date` | Creation date |
| `modified` | Last modification date |
| `logsource` | Log source definition: `category`, `product`, `service` |
| `detection` | Detection logic: selection conditions, filters, condition expression |
| `tags` | MITRE ATT&CK tags (format: `attack.t1059.001`) |
| `level` | Severity: informational, low, medium, high, critical |
| `falsepositives` | Known false positive scenarios |

### Detection Logic

The `detection` block uses named selection and filter conditions combined with a `condition` expression:

- **Selection**: field-value mappings that define what to match
- **Filter**: field-value mappings that define what to exclude
- **Condition**: Boolean logic combining selections and filters (`selection and not filter`)

### Example

```yaml
title: Suspicious PowerShell Encoded Command
id: f3a1b2c4-5d6e-7f8a-9b0c-1d2e3f4a5b6c
status: stable
description: |
    Detects execution of PowerShell with encoded command line arguments,
    commonly used to obfuscate malicious commands.
author: Detection Engineering Team
date: 2025/01/15
modified: 2025/06/01
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\powershell.exe'
        CommandLine|contains:
            - '-enc'
            - '-EncodedCommand'
            - '-ec '
    filter_admin_scripts:
        ParentImage|endswith:
            - '\sccm.exe'
            - '\configmgr.exe'
        User|contains: 'SYSTEM'
    condition: selection and not filter_admin_scripts
falsepositives:
    - Legitimate administrative scripts using encoded commands
    - Configuration management tools
tags:
    - attack.execution
    - attack.t1059.001
level: medium
```

### Platform Conversion

Sigma rules are converted to platform-specific queries via pySigma:

```bash
# Convert to Elastic query
sigma convert -t elasticsearch rules/suspicious_powershell_encoded.yml

# Convert to Splunk SPL
sigma convert -t splunk rules/suspicious_powershell_encoded.yml

# Convert to Microsoft Sentinel KQL
sigma convert -t microsoft365defender rules/suspicious_powershell_encoded.yml
```

---

## Splunk Security Content YAML

[Splunk Security Content](https://github.com/splunk/security_content) stores detection rules as YAML files with SPL queries.

### Structure

| Field | Description |
|---|---|
| `name` | Detection name |
| `id` | Unique UUID |
| `description` | Detection description |
| `search` | SPL query |
| `type` | Detection type: `TTP`, `Anomaly`, `Hunting`, `Correlation` |
| `how_to_implement` | Implementation requirements |
| `known_false_positives` | Known false positive scenarios |
| `tags` | Metadata block containing MITRE mappings, analytic story, kill chain phases |

### Tags Block

The `tags` sub-block contains structured metadata:

- `mitre_attack_id`: List of MITRE technique IDs
- `kill_chain_phases`: Lockheed Martin kill chain phase mappings
- `analytic_story`: Associated Splunk analytic stories
- `asset_type`: Target asset type (Endpoint, Network, Cloud)
- `security_domain`: Security domain (endpoint, network, access, threat)
- `confidence`, `impact`: Numeric scores used to calculate risk

### Example

```yaml
name: Suspicious PowerShell Encoded Command
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
version: 2
date: '2025-01-15'
description: >
  Detects execution of PowerShell with encoded command line arguments,
  a common technique for obfuscating malicious commands.
search: >
  | tstats `security_content_summariesonly` count min(_time) as firstTime
  max(_time) as lastTime from datamodel=Endpoint.Processes where
  Processes.process_name=powershell.exe
  (Processes.process=*-enc* OR Processes.process=*-EncodedCommand* OR Processes.process=*-ec\ *)
  by Processes.dest Processes.user Processes.parent_process_name
  Processes.process_name Processes.process Processes.process_id
  Processes.parent_process_id
  | `drop_dm_object_name(Processes)`
  | `security_content_ctime(firstTime)`
  | `security_content_ctime(lastTime)`
type: TTP
how_to_implement: >
  You must be ingesting endpoint data that populates the Endpoint.Processes
  data model. This is typically collected via Sysmon, CrowdStrike, or
  Carbon Black with appropriate Splunk TAs installed.
known_false_positives: >
  Legitimate administrative scripts using encoded commands for
  deployment or configuration management.
tags:
  analytic_story:
    - Malicious PowerShell
  mitre_attack_id:
    - T1059.001
  kill_chain_phases:
    - exploitation
  asset_type: Endpoint
  security_domain: endpoint
  confidence: 70
  impact: 60
```

---

## Format Comparison

| Attribute | Elastic TOML | Sigma YAML | Splunk YAML |
|---|---|---|---|
| Query language | KQL, EQL, ES\|QL | Platform-agnostic (Sigma syntax) | SPL |
| Platform binding | Elastic Security | None (converted via pySigma) | Splunk Enterprise Security |
| MITRE mapping format | Nested TOML blocks | Tags (`attack.t1059.001`) | Tags (`mitre_attack_id`) |
| Severity representation | `severity` + `risk_score` | `level` | `confidence` + `impact` = risk |
| False positives | In description or notes | Dedicated `falsepositives` field | Dedicated `known_false_positives` field |
| Detection type taxonomy | Rule `type` (query, eql, threshold) | Implicit in logsource + detection | Explicit `type` (TTP, Anomaly, Hunting) |

Understanding these formats is necessary for any workflow that reads, validates, converts, or enriches detection rules — whether manually or with AI assistance.
