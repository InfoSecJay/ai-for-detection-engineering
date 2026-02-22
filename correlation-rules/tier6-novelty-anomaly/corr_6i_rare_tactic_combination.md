# Rare Tactic Combination

---

## Metadata

- **Rule ID:** `CORR-6I`
- **Tier:** 6 — Novelty and Anomaly Detection
- **Author:** Detection Engineering
- **Description:** Detect entities exhibiting combinations of MITRE ATT&CK tactics that have rarely or never been observed together in the environment's alert history. Most attacks follow predictable tactic sequences (Initial Access, Execution, Persistence). An entity exhibiting Reconnaissance + Impact (unusual pairing) or Collection + Defense Evasion + Exfiltration (rare triple) stands out because the combination itself is anomalous, even if individual alerts are medium severity.
- **Join Key(s):** `entity_type + entity_value (typed composite key)`
- **Lookback:** 24 hours (transform), 60 days (baseline)
- **Schedule:** Every 1 hour (transform), continuous (`new_terms` rule)
- **Priority:** P2
- **Integration:** [alerts](https://www.elastic.co/guide/en/security/current/alerts-ui-manage.html)
- **Language:** Multi-component: Elasticsearch Transform + `new_terms` detection rule

## Architecture

> **Why not a single ES|QL rule?** The original design attempted a `LOOKUP JOIN` on a post-aggregation computed field (`Esql.tactic_combination`), which is not supported in ES|QL. The detection requires two operations that cannot be combined in a single query: (1) aggregate tactics per entity across multiple alerts, and (2) compare the resulting combination against a historical baseline of known combinations. The recommended architecture separates these concerns.

```
.internal.alerts-security.alerts-default
           |
           | Continuous Transform (every 1h)
           | Computes per-entity tactic combinations
           v
transform-tactic-combinations
  - entity: "john.doe"
  - tactic_combo_key: "credential-access|execution|impact"
  - tactic_count: 3
  - alert_count: 5
           |
           | new_terms rule (every 1h, 60d history)
           | Detects novel tactic_combo_key values
           v
Alert: "CORR-6I: Rare Tactic Combination"
  - building_block_type: "default"
  - Feeds Tier 4 meta-correlation (CORR-4G)
```

## Component 1: Destination Index

Create the destination index before starting the transform:

```json
PUT transform-tactic-combinations
{
  "mappings": {
    "properties": {
      "entity": { "type": "keyword" },
      "entity_type": { "type": "keyword" },
      "alert_count": { "type": "long" },
      "tactic_count": { "type": "long" },
      "max_severity_weight": { "type": "long" },
      "tactic_combinations": {
        "properties": {
          "all_tactics": { "type": "keyword" },
          "tactic_pairs": { "type": "keyword" },
          "tactic_combo_key": { "type": "keyword" }
        }
      },
      "@timestamp": { "type": "date" }
    }
  }
}
```

## Component 2: Continuous Transform

The transform aggregates alerts per entity and computes sorted tactic combination strings using `scripted_metric`:

> **// TODO: Update transform to output entity_type alongside entity for typed entity key support.** The current Painless script uses COALESCE-style logic (`u != null ? u : h`) to produce a single `entity` field. To align with the typed entity key pattern used in ES|QL correlation rules, the transform should be updated to emit both `entity_type` ("user" or "host") and `entity_value` fields instead of a single conflated `entity` field.

```json
PUT _transform/corr-6i-tactic-combinations
{
  "source": {
    "index": [".internal.alerts-security.alerts-default"],
    "query": {
      "bool": {
        "filter": [
          { "range": { "@timestamp": { "gte": "now-24h" } } },
          { "term": { "kibana.alert.workflow_status": "open" } },
          { "exists": { "field": "kibana.alert.rule.threat.tactic.name" } }
        ]
      }
    }
  },
  "dest": {
    "index": "transform-tactic-combinations"
  },
  "frequency": "1h",
  "sync": {
    "time": {
      "field": "@timestamp",
      "delay": "60s"
    }
  },
  "pivot": {
    "group_by": {
      "entity": {
        "terms": {
          "script": {
            "source": "def u = doc['user.name'].size() > 0 ? doc['user.name'].value : null; def h = doc['host.name'].size() > 0 ? doc['host.name'].value : null; return u != null ? u : (h != null ? h : 'unknown');",
            "lang": "painless"
          }
        }
      }
    },
    "aggregations": {
      "alert_count": { "value_count": { "field": "@timestamp" } },
      "tactic_count": { "cardinality": { "field": "kibana.alert.rule.threat.tactic.name" } },
      "max_severity_weight": {
        "max": {
          "script": {
            "source": "def sev = doc.containsKey('signal.rule.severity') && doc['signal.rule.severity'].size() > 0 ? doc['signal.rule.severity'].value : 'low'; if (sev == 'critical') return 25; if (sev == 'high') return 15; if (sev == 'medium') return 8; if (sev == 'low') return 3; return 1;"
          }
        }
      },
      "tactic_combinations": {
        "scripted_metric": {
          "init_script": "state.tactics = new HashSet()",
          "map_script": "if (doc['kibana.alert.rule.threat.tactic.name'].size() > 0) { for (def t : doc['kibana.alert.rule.threat.tactic.name']) { state.tactics.add(t); } }",
          "combine_script": "return state.tactics.toArray()",
          "reduce_script": "def all_tactics = new TreeSet(); for (s in states) { for (t in s) { all_tactics.add(t); } } def tactic_list = new ArrayList(all_tactics); def pairs = new ArrayList(); for (int i = 0; i < tactic_list.size(); i++) { for (int j = i + 1; j < tactic_list.size(); j++) { pairs.add(tactic_list.get(i) + '+' + tactic_list.get(j)); } } def result = new HashMap(); result.put('all_tactics', tactic_list); result.put('tactic_pairs', pairs); result.put('tactic_combo_key', String.join('|', tactic_list)); return result;"
        }
      }
    }
  }
}
```

## Component 3: `new_terms` Detection Rule

The detection rule monitors the transform output for never-before-seen tactic combinations:

```json
POST api/detection_engine/rules
{
  "type": "new_terms",
  "name": "CORR-6I: Rare Tactic Combination",
  "description": "Detects entities exhibiting MITRE ATT&CK tactic combinations not observed in the past 60 days.",
  "severity": "medium",
  "risk_score": 47,
  "index": ["transform-tactic-combinations"],
  "new_terms_fields": ["tactic_combinations.tactic_combo_key"],
  "history_window_start": "now-60d",
  "query": "tactic_count >= 2 AND alert_count >= 3",
  "filters": [],
  "interval": "1h",
  "from": "now-2h",
  "language": "kuery",
  "building_block_type": "default",
  "tags": ["CORR-6I", "Tier 6", "Novelty", "MITRE ATT&CK"],
  "threat": [
    {
      "framework": "MITRE ATT&CK",
      "tactic": {
        "id": "TA0001",
        "name": "Initial Access",
        "reference": "https://attack.mitre.org/tactics/TA0001/"
      },
      "technique": []
    }
  ]
}
```

## Simplified Alternative (No `scripted_metric`)

If `scripted_metric` is unavailable (e.g., Elasticsearch Serverless), use a simpler transform that groups by `(entity, tactic)` pairs and a `new_terms` rule with composite fields:

```json
PUT _transform/corr-6i-entity-tactic-pairs
{
  "source": {
    "index": [".internal.alerts-security.alerts-default"],
    "query": {
      "bool": {
        "filter": [
          { "range": { "@timestamp": { "gte": "now-24h" } } },
          { "term": { "kibana.alert.workflow_status": "open" } },
          { "exists": { "field": "kibana.alert.rule.threat.tactic.name" } }
        ]
      }
    }
  },
  "dest": { "index": "transform-entity-tactic-pairs" },
  "frequency": "1h",
  "sync": { "time": { "field": "@timestamp", "delay": "60s" } },
  "pivot": {
    "group_by": {
      "entity": {
        "terms": {
          "script": {
            "source": "def u = doc['user.name'].size() > 0 ? doc['user.name'].value : null; def h = doc['host.name'].size() > 0 ? doc['host.name'].value : null; return u != null ? u : (h != null ? h : 'unknown');"
          }
        }
      },
      "tactic": {
        "terms": { "field": "kibana.alert.rule.threat.tactic.name" }
      }
    },
    "aggregations": {
      "alert_count": { "value_count": { "field": "@timestamp" } },
      "last_seen": { "max": { "field": "@timestamp" } }
    }
  }
}
```

Then use a `new_terms` rule with `new_terms_fields: ["entity", "tactic"]` to detect when an entity is associated with a tactic for the first time. This detects **new entity-tactic pairs** rather than **new tactic combinations** — a simpler but still valuable signal.

## Strategy

The primary approach uses an Elasticsearch continuous transform to compute per-entity tactic combination strings (sorted, concatenated) every hour from 24h of alert data. The `scripted_metric` aggregation collects all unique tactics per entity, sorts them alphabetically, and produces both a full combo key (`credential-access|execution|impact`) and individual pairs (`credential-access+execution`). The transform destination index is monitored by an Elastic Security `new_terms` rule with a 60-day history window. When a tactic combination appears that has never been seen in the past 60 days, the rule fires. The `new_terms` engine handles baseline maintenance natively — no external lookup index required.

## Severity Logic

| Condition | Severity |
|-----------|----------|
| Novel tactic combination with 3+ tactics and high/critical alerts | High (escalated via Tier 4) |
| Novel tactic combination with 2 tactics | Medium |

> **Note**: The `new_terms` rule fires at medium severity. Severity escalation for high-impact combinations should be handled by Tier 4 rules (CORR-4G: TTP Diversity Score) that consume CORR-6I building block output.

## Notes

- **Blind Spots:**
  - **Limited tactic metadata**: Many detection rules do not have MITRE ATT&CK tactic mappings populated. Alerts without tactic metadata are invisible to this rule.
  - **Small alert corpus**: In environments with low alert volume, all tactic combinations may appear "rare" because the baseline has insufficient data to establish common patterns. Requires 60+ days of data to build meaningful baselines.
  - **Multi-valued tactics**: A single alert may map to multiple tactics, creating combinations within a single alert that are not actually distinct attack steps.

- **False Positives:**
  - **Purple team exercises**: Red team operators deliberately execute unusual tactic combinations. Mitigation: tag purple team accounts and suppress during exercises.
  - **Detection rule testing**: Detection engineers testing rules covering unusual tactic combinations. Mitigation: exclude test accounts and lab environments.
  - **Incomplete tactic mappings**: Rules incorrectly mapped to unusual tactic combinations produce artificial rarity. Mitigation: audit MITRE mappings for accuracy.

- **Tuning:**
  1. The 60-day history window is the recommended minimum. Increase to 90 days if your environment sees seasonal variation in alert patterns.
  2. Set `alert_count >= 3` in the `new_terms` query filter to avoid flagging entities with too few alerts for meaningful tactic analysis.
  3. Exclude specific tactic pairs known to co-occur by adding them to the `new_terms` rule's exception list.
  4. Weight certain tactic pairs higher via Tier 4 rules (Reconnaissance + Impact is more suspicious than Execution + Persistence).

## Data Requirements

- **Index**: `.internal.alerts-security.alerts-default` (source for transform)
- **Transform destination index**: `transform-tactic-combinations` (created per Component 1)
- **Required fields**: `user.name`, `host.name`, `kibana.alert.rule.threat.tactic.name`, `signal.rule.severity`, `kibana.alert.workflow_status`, `@timestamp`
- **Minimum volume**: 60+ days of alert data with tactic mappings to build a meaningful baseline via `new_terms` history window.

## Dependencies

- **Required**: Elasticsearch Transform capability (for continuous tactic combination computation)
- **Required**: `new_terms` rule type (available in Elastic Security 8.6+)
- **Optional**: MITRE ATT&CK mapping validation for detection rules

## Validation

1. Create the destination index and start the transform
2. Generate alerts combining Reconnaissance + Impact tactics for the same entity (unusual pairing in most environments)
3. Wait for the transform to process (up to 1 hour)
4. Verify the `new_terms` rule fires for the novel tactic combination
5. Generate alerts combining Execution + Persistence (common pairing) and confirm the rule does NOT fire (assuming this combination exists in the 60-day baseline)

## Elastic Comparison

Elastic does not ship a tactic-combination rarity rule. Elastic's MITRE ATT&CK coverage dashboard shows tactic distribution but does not flag unusual combinations. The `new_terms` rule type can detect new individual field values but requires the transform pre-processing step to reason about cross-alert tactic combinations per entity. CORR-6I provides a unique capability to detect attack patterns that are novel at the tactic-sequence level.
