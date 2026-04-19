# Identity Resolution Pattern

A reference design for the `lookup-identity-resolution` index that powers cross-domain correlation when entities use different naming conventions across data sources. This document fixes the **CORR-5E blind spot** called out in [TODO.md](TODO.md): email and endpoint domains use incompatible `user.name` formats and the rule produces silent false negatives without normalization.

The pattern generalizes beyond CORR-5E. Any cross-domain rule joining on `user.name`, `user.email`, or `user.id` benefits from a shared identity-resolution lookup.

---

## The Problem

Most enterprises do not normalize user identity at SIEM ingest. A single human user named "Jane Smith" appears as:

| Source Domain | Field | Example Value |
|---|---|---|
| Email security (Proofpoint, Mimecast) | `user.email` / `user.name` | `jane.smith@corp.com` |
| Endpoint EDR (SentinelOne, Defender) | `user.name` | `CORP\jsmith` |
| Identity (Okta, Azure AD) | `user.name` / `user.id` | `jsmith` / `00u4abcd1234` |
| Cloud (AWS CloudTrail) | `user.name` / `user.id` | `arn:aws:iam::123:user/jane.smith` |
| HR / CMDB | `user.id` / `user.name` | `EMP-104872` / `Jane Smith` |

CORR-5E joins email-domain alerts to endpoint-domain alerts on `user.name`. With the values above, the join silently fails. The rule appears to be working but emits zero correlations for valid phishing chains.

This is a data-engineering problem, not an AI problem. The fix is a deterministic lookup index that maps every observed identity form to a canonical user ID.

---

## The Index

### Index name
`lookup-identity-resolution`

### Mapping

```json
{
  "mappings": {
    "properties": {
      "canonical_user_id":     { "type": "keyword" },
      "primary_email":         { "type": "keyword" },
      "samaccountname":        { "type": "keyword" },
      "upn":                   { "type": "keyword" },
      "okta_user_id":          { "type": "keyword" },
      "azure_object_id":       { "type": "keyword" },
      "aws_user_arn":          { "type": "keyword" },
      "hr_employee_id":        { "type": "keyword" },
      "display_name":          { "type": "text", "fields": { "raw": { "type": "keyword" } } },
      "department":            { "type": "keyword" },
      "manager_canonical_id":  { "type": "keyword" },
      "is_active":             { "type": "boolean" },
      "is_privileged":         { "type": "boolean" },
      "account_type":          { "type": "keyword" },
      "last_updated":          { "type": "date" }
    }
  }
}
```

### Required fields

| Field | Source | Why |
|---|---|---|
| `canonical_user_id` | Derived (UUID or HR employee ID) | The single ID downstream rules join on |
| `primary_email` | HR / Identity | Joins email-domain alerts |
| `samaccountname` | Active Directory | Joins legacy Windows endpoint alerts (`DOMAIN\jsmith` → `jsmith`) |
| `upn` | Azure AD | Joins modern endpoint and Azure alerts |
| `okta_user_id` | Okta | Joins Okta auth alerts |
| `azure_object_id` | Azure AD | Joins Azure / M365 alerts |
| `aws_user_arn` | AWS IAM | Joins CloudTrail (where applicable) |
| `is_active` | HR / Identity | Filter terminated accounts |
| `is_privileged` | AD / Identity / PAM | Severity scaling |
| `account_type` | Identity | Distinguish `human`, `service`, `system`, `shared` |

`canonical_user_id` should be **stable across the user's lifetime**. HR employee ID is the most common choice; UUIDs work if HR ID is unavailable. Email is a poor canonical ID — it changes on name change.

---

## Population

This is an **ETL responsibility**, not a SIEM responsibility. Recommended pipeline:

1. **Source of record**: HR / Identity Governance system (Workday, BambooHR, Saviynt) is the authoritative source for `canonical_user_id`, employment status, department, manager.
2. **Identity directory**: Active Directory + Azure AD provide `samaccountname`, `upn`, `azure_object_id`, group membership for privilege classification.
3. **SaaS identity**: Okta, AWS IAM, GCP IAM provide service-specific IDs.
4. **Reconciliation**: A scheduled job joins these sources by best-effort matching (email → UPN → samaccountname) and writes the consolidated record to `lookup-identity-resolution`.

Cadence:
- **Hourly** for `is_active`, `account_type`, group membership changes (catch terminations and privilege changes quickly)
- **Daily** for non-time-critical fields (department, display name)
- **Real-time** if you have an identity event bus (Okta event hooks, Azure AD audit logs streamed)

A user in HR but without identity records appears with `is_active=true` and missing IDs — flag this as a data-quality issue.

---

## Usage in Correlation Rules

### CORR-5E (the original motivating case)

The current CORR-5E joins on `user.name`. The fixed pattern uses a normalized `canonical_user_id`:

**Pre-correlation normalization step** (run as an Elastic ingest pipeline or transform on `.internal.alerts-security.alerts-default`):

```
For each alert, derive Esql.canonical_user_id by lookup:
  - If user.email is set:                lookup by primary_email
  - Else if user.name matches DOMAIN\X:  strip domain prefix → lookup by samaccountname
  - Else if user.name matches X@Y:       lookup by upn
  - Else if okta event:                  lookup by okta_user_id
  - Else if cloudtrail event:            lookup by aws_user_arn
  - Else: NULL (cannot resolve — flag for data-quality follow-up)
```

CORR-5E (revised) then joins on `Esql.canonical_user_id` instead of `user.name`. The phishing-to-endpoint chain catches Jane Smith regardless of whether the email shows `jane.smith@corp.com` or the endpoint shows `CORP\jsmith` — both resolve to the same `canonical_user_id`.

### Other rules that benefit

| Rule | Current Join | Recommended Join | Why |
|---|---|---|---|
| CORR-1A (Multi-Domain by User) | `user.name` | `Esql.canonical_user_id` | Picks up cross-domain activity even with naming mismatches |
| CORR-1G (by Email) | `user.email` | `Esql.canonical_user_id` | Works when only some sources populate email |
| CORR-2B (Identity → Endpoint) | `user.name` | `Esql.canonical_user_id` | Identity events use UPN, endpoint uses samaccountname |
| CORR-2D (Privilege Escalation) | `user.name` | `Esql.canonical_user_id` | Service-account adoption tracking |
| CORR-3A (24h Risk Score, User) | `user.name` | `Esql.canonical_user_id` | Risk score correctly accumulates across all identity forms |
| CORR-5J (Impossible Travel) | varies | `Esql.canonical_user_id` | Catches travel even when SSO and SaaS log different identifiers |
| CORR-5L (Insider Threat Composite) | `user.name` | `Esql.canonical_user_id` | Composite needs unified identity |

The shift is mechanical: replace the join key, keep the rule logic.

---

## Deployment Sequence

To avoid breaking running rules, deploy in three phases:

1. **Phase 1 — Build the lookup**: stand up `lookup-identity-resolution`, populate from HR + AD + Identity + SaaS sources, validate coverage (target: ≥98% of recently-active users have a complete record).
2. **Phase 2 — Enrich at ingest**: add a pipeline that derives `Esql.canonical_user_id` on every alert. Run this **alongside** existing rules without changing them. Verify enrichment hit rate ≥95%.
3. **Phase 3 — Switch rule joins**: migrate rules to join on `Esql.canonical_user_id` one tier at a time. Compare before/after fire rates — expect Tier 1/2/5 cross-domain rules to fire **more often**, not less, because the previously-silent false negatives now surface.

Do **not** delete the original `user.name` field after enrichment — analysts still use it for display, and other tooling may depend on it.

---

## Failure Modes

| Failure | Symptom | Mitigation |
|---|---|---|
| HR data stale | Terminated user still appears as `is_active=true` | Reconcile within 24h of HR change; alert on age of last_updated > 7d |
| Multiple users with same email | Aliasing in shared mailboxes | Mark `account_type=shared`; do not generate canonical_user_id; rely on session context |
| Service account misclassified as human | False positive rate spike on user-centric rules | Maintain service-account naming convention or PAM-sourced flag; classify on ingest |
| Identity sync gap | New employee triggers alerts before record propagates | Acceptable for first 24h; flag as data-quality but do not block correlation |
| External user (contractor, vendor) | No HR record | Create canonical_user_id from identity provider; flag `account_type=external` |
| User with no canonical ID | Lookup returns NULL; rule joins fail silently again | Track unresolved-identity rate as a data-quality metric; alert when >2% sustained |

---

## Validation

Before declaring identity resolution operational:

1. **Coverage check**: ≥98% of active human users have records with email + samaccountname + upn populated
2. **Enrichment check**: ≥95% of recent alerts on user-bearing data sources have `Esql.canonical_user_id` populated
3. **Round-trip test**: select 20 random users, generate test alerts in email + endpoint + identity domains, confirm CORR-5E and CORR-1A correctly correlate them all to the same canonical ID
4. **Termination test**: schedule an identity-resolution sync after a known termination, confirm `is_active=false` propagates within the SLA you've committed to
5. **Privileged-user test**: confirm `is_privileged=true` users trigger Tier 3 critical-asset multipliers correctly

Document the validation results in your detection-engineering runbook before flipping rules to use the new join key.

---

## Why This Is in Scope for the Catalog

A reasonable objection: identity resolution is an enterprise IAM problem, not a detection-engineering one. True. But the catalog cannot pretend the problem doesn't exist when it directly causes silent false negatives in CORR-5E, CORR-1A, CORR-2B, CORR-3A, and others. The minimum specification of what the lookup must contain — not the implementation of how to populate it — belongs here so that DE teams have a concrete artifact to demand from their identity team.

If your identity team cannot deliver this lookup, the cross-domain rules in this catalog will under-perform their advertised value. That is a fact worth surfacing in the architecture-review stage, not after deployment.
