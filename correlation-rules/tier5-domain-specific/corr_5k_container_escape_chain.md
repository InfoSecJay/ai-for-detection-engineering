# Container Escape Chain

---

## Metadata

- **Rule ID:** `CORR-5K`
- **Tier:** 5 — Domain-Specific Correlation
- **Author:** Detection Engineering
- **Description:** Detect container-related alert patterns that indicate a container escape attempt or successful breakout to the host. The chain typically involves a privileged container alert, followed by host filesystem mount or namespace access, followed by host-level resource access. Container escapes are high-impact because they allow an attacker to break out of the container isolation boundary and compromise the underlying host and potentially all other containers on that host.
- **Join Key(s):** `cloud.instance.id` OR `container.id`
- **Lookback:** 2 hours
- **Schedule:** Every 10 minutes
- **Priority:** P2
- **Integration:** [alerts](https://www.elastic.co/guide/en/security/current/alerts-ui-manage.html)
- **Language:** `[ES|QL]`

## Query

```esql
FROM .internal.alerts-security.alerts-default
| WHERE @timestamp > NOW() - 2 HOURS
    AND kibana.alert.workflow_status == "open"
    AND (container.id IS NOT NULL OR cloud.instance.id IS NOT NULL)
    AND (
        event.dataset LIKE "cloud*" OR event.dataset LIKE "aws*"
        OR event.dataset LIKE "gcp*" OR event.dataset LIKE "azure*"
        OR event.dataset LIKE "endpoint*" OR event.dataset LIKE "sentinelone*"
        OR event.dataset LIKE "windows*" OR event.dataset LIKE "sysmon*"
    )
| EVAL
    Esql.container_key = COALESCE(container.id, cloud.instance.id),
    severity_weight = CASE(
        signal.rule.severity == "critical", 25,
        signal.rule.severity == "high", 15,
        signal.rule.severity == "medium", 8,
        signal.rule.severity == "low", 3, 1
    ),
    bbr_factor = CASE(kibana.alert.rule.building_block_type == "default", 0.3, 1.0),
    alert_risk = ROUND(severity_weight * bbr_factor),
    is_priv_escalation = CASE(
        kibana.alert.rule.threat.tactic.name == "Privilege Escalation"
            OR kibana.alert.rule.name LIKE "*Privileged*Container*"
            OR kibana.alert.rule.name LIKE "*Capabilities*"
            OR kibana.alert.rule.name LIKE "*Privilege*Escalat*"
            OR kibana.alert.rule.name LIKE "*Root*Container*",
            1, 0
    ),
    is_host_access = CASE(
        kibana.alert.rule.name LIKE "*Host*Mount*"
            OR kibana.alert.rule.name LIKE "*Host*Namespace*"
            OR kibana.alert.rule.name LIKE "*Host*PID*"
            OR kibana.alert.rule.name LIKE "*Host*Network*"
            OR kibana.alert.rule.name LIKE "*Container*Escape*"
            OR kibana.alert.rule.name LIKE "*Breakout*"
            OR kibana.alert.rule.name LIKE "*chroot*"
            OR kibana.alert.rule.name LIKE "*nsenter*",
            1, 0
    )
| STATS
    Esql.alert_count = COUNT(*),
    Esql.first_seen = MIN(@timestamp),
    Esql.last_seen = MAX(@timestamp),
    Esql.total_risk = SUM(alert_risk),
    Esql.technique_count = COUNT_DISTINCT(kibana.alert.rule.parameters.threat.technique.id),
    Esql.has_priv_escalation = MAX(is_priv_escalation),
    Esql.has_host_access = MAX(is_host_access),
    Esql.unique_rules = COUNT_DISTINCT(kibana.alert.rule.name),
    Esql.rule_names = VALUES(kibana.alert.rule.name),
    Esql.tactic_values = VALUES(kibana.alert.rule.threat.tactic.name),
    Esql.host_values = VALUES(host.name),
    Esql.user_values = VALUES(user.name),
    Esql.container_names = VALUES(container.name),
    Esql.container_images = VALUES(container.image.name)
  BY Esql.container_key
| WHERE Esql.technique_count >= 2
| EVAL
    Esql.risk_score = Esql.total_risk,
    Esql.severity = CASE(
        Esql.has_priv_escalation == 1 AND Esql.has_host_access == 1, "critical",
        Esql.has_priv_escalation == 1, "high",
        Esql.technique_count >= 2, "medium",
        "low"
    ),
    Esql.description = CONCAT(
        "Container escape chain on ", Esql.container_key,
        " | Privilege escalation: ", TO_STRING(Esql.has_priv_escalation),
        " | Host access: ", TO_STRING(Esql.has_host_access),
        " | ", TO_STRING(Esql.technique_count), " techniques",
        " | ", TO_STRING(Esql.unique_rules), " rules",
        " | Risk Score: ", TO_STRING(Esql.risk_score),
        " | Window: ", TO_STRING(Esql.first_seen), " to ", TO_STRING(Esql.last_seen)
    )
| SORT Esql.risk_score DESC
| LIMIT 50
```

## Strategy

Filters to container-related alerts by matching on container and cloud datasets. Uses the compound join key of `COALESCE(container.id, cloud.instance.id)` to correlate alerts at the container or instance level. Classifies alerts into privilege escalation and host access categories. Requires at least 2 distinct techniques to fire, ensuring the rule captures multi-step escape attempts rather than single misconfigurations.

## Severity Logic

| Condition | Severity |
|-----------|----------|
| Container escape + host access | Critical |
| Privilege escalation in container | High |
| 2+ container techniques | Medium |

## Notes

- **Blind Spots:**
  - Serverless container environments (AWS Fargate, Azure Container Instances) where container IDs may not be preserved in alerts
  - Container escapes via kernel exploits that bypass userspace detection entirely
  - Ephemeral containers that are destroyed before alert processing completes
  - Container runtime environments without EDR agent coverage inside containers

- **False Positives:**
  - **Privileged containers for infrastructure**: Some legitimate workloads require privileged containers (monitoring agents, storage drivers). Mitigation: maintain a list of expected privileged container images.
  - **Container orchestration operations**: Kubernetes system containers that mount host paths for kubelet, kube-proxy, etc. Mitigation: exclude known system namespace containers.
  - **CI/CD build containers**: Docker-in-Docker builds that require host Docker socket access. Mitigation: exclude known CI/CD runner container images.

- **Tuning:**
  1. Customize the `is_priv_escalation` and `is_host_access` CASE patterns for your container security detection rule names
  2. Add container image name filtering -- exclude known infrastructure container images that legitimately run privileged
  3. `technique_count` threshold (default: 2) -- keep at 2 because container escape chains typically involve exactly 2-3 steps
  4. Consider adding Kubernetes namespace filtering if available -- system namespaces (kube-system, monitoring) generate expected privileged activity

## Data Requirements

- **Index**: `.internal.alerts-security.alerts-default`
- **Required fields**: `container.id`, `cloud.instance.id`, `event.dataset`, `signal.rule.severity`, `kibana.alert.rule.name`, `kibana.alert.rule.building_block_type`, `kibana.alert.rule.parameters.threat.technique.id`, `kibana.alert.rule.threat.tactic.name`, `@timestamp`, `host.name`, `user.name`, `container.name`, `container.image.name`
- **Minimum data sources**: At least one container security or cloud workload protection integration with container-aware detection rules
- **Minimum volume**: 2+ container-related alerts with distinct techniques for same container/instance within 2h

## Dependencies

None required.

## Validation

In a test container environment:
1. Run a privileged container (triggers privileged container alert)
2. Mount the host filesystem from within the container (triggers host mount alert)
3. Access host resources through the mount point (triggers host access or escape alert)

Expected result: Container/instance appears with `Esql.has_priv_escalation == 1`, `Esql.has_host_access == 1`, severity of critical.

## Elastic Comparison

Elastic ships individual container security rules (e.g., "Kubernetes Pod Created with HostPID", "Privileged Docker Container Creation") but does not correlate them into an escape chain for the same container. CORR-5K detects the multi-step container escape pattern that individual rules cannot identify.
