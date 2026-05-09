# identity-context-engine

> Cross-layer context engine for post-intrusion detection — correlating identity, behavior, and runtime signals across HRIS, Cloud IAM, code, and Kubernetes.

---

## Concept

Most detection systems ask: **"What happened?"**

This project asks: **"Who did it, what were they supposed to be doing, and does this make sense given everything we know about them?"**

The core insight is that security events without organizational context are just noise. A Kubernetes pod executing a shell is suspicious. The same event from a pod deployed by someone who resigned last week is a different risk entirely.

`identity-context-engine` is a modular platform that builds a continuous, enriched context layer by correlating signals across organizational data sources — and feeds that context into runtime detection pipelines.

---

## The Problem

Zero Trust architectures verify identity at authentication time. But **authentication is a single moment**. What happens after — lateral movement, data exfiltration, privilege escalation — happens in a context that authentication alone cannot see.

Existing detection tools operate in silos:
- **SIEM** sees logs, but not who the user is organizationally
- **HRIS** knows the employee lifecycle, but has no visibility into technical behavior
- **k8s runtime tools** (Falco, Tetragon) see syscalls and process trees, but not the human behind the workload
- **Cloud IAM / k8s RBAC** defines what service accounts can do, but not who owns them or whether that ownership is still valid

The gap between these layers is where attackers live.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Data Sources                                 │
│                                                                     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐               │
│  │     HRIS     │  │  Cloud IAM   │  │  SCM / CI    │               │
│  │  (Workday    │  │  (AWS IAM,   │  │  (GitHub     │               │
│  │  or other)   │  │  GCP IAM,    │  │  or other)   │               │
│  │              │  │  or other)   │  │              │               │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘               │
│         │                 │                  │                      │
└─────────┼─────────────────┼──────────────────┼──────────────────────┘
          │                 │                  │
          ▼                 ▼                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     Identity Anchor Layer                           │
│                                                                     │
│  [Human]                                                            │
│   employee_id  ──►  idp_user_id  ──►  github_username               │
│                          │                   │                      │
│                          └──────────────────►│                      │
│                                              ▼                      │
│                                    k8s user / OIDC subject          │
│                                                                     │
│  [Non-Human]                                                        │
│   k8s ServiceAccount  ──►  manifest annotations (owner, team)       │
│          │                          │                               │
│          ├──►  AWS IAM Role (IRSA)         ──►  owning team         │
│          └──►  GCP SA (Workload Identity)  ──►  owning team         │
│                                                                     │
│   Ownership gap (no annotation, no IAM binding) = risk indicator    │
└────────────────────────────┬────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      Context Engine Core                            │
│                                                                     │
│  ┌────────────────────────────────────────────────────────────┐     │
│  │  Lifecycle Context     │  Behavioral Baseline              │     │
│  │  - Employment status   │  - Normal working hours           │     │
│  │  - Days until offboard │  - Typical namespace access       │     │
│  │  - Role changes        │  - Deploy frequency               │     │
│  │  - Access tier         │  - Resource access patterns       │     │
│  └────────────────────────┴───────────────────────────────────┘     │
│                                                                     │
│  ┌────────────────────────────────────────────────────────────┐     │
│  │               Anomaly Scoring                              │     │
│  │  event + identity context + behavioral baseline            │     │
│  │  → enriched alert with organizational risk score           │     │
│  └────────────────────────────────────────────────────────────┘     │
└────────────────────────────┬────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     Runtime Detection Layer                         │
│                                                                     │
│  k8s-detection-pipeline (Falco + Tetragon + Audit Logs)             │
│  → events enriched with identity context before SIEM ingestion      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Identity Anchor

The hardest problem in cross-layer correlation is **identity resolution** — the same person or service appears under different identifiers in every system.

The engine covers two identity types:

### Human Identity

Resolution strategy (in order of preference):

| Priority | Method | Example |
|---|---|---|
| 1 | IdP as canonical anchor | e.g. SSO provider → GitHub → k8s OIDC |
| 2 | HRIS custom fields | Workday `github_username` field |
| 3 | Reference mapping table | CSV/DB mapping employee_id ↔ accounts |

The engine resolves to a single `identity_anchor_id` per person, used as the join key across all context layers.

### Non-Human Identity (Service Accounts)

Service accounts are first-class identities in this engine. They appear in two places:

- **k8s manifests** — `ServiceAccount` resources with `owner` or `team` annotations define organizational ownership
- **IdP / cloud IAM machine accounts** — service accounts registered in AWS IAM, GCP IAM, or Google Workspace carry ownership and access tier metadata

Resolution chain:

```
k8s ServiceAccount
    → manifest annotations (owner, team, purpose)
    → cloud IAM / Google Workspace machine account (if registered)
    → owning team's human identities
```

**Why this matters for detection:** A service account accessing resources outside its declared scope, or a SA with no ownership annotation touching sensitive namespaces, is a high-signal anomaly — independent of any human actor. Ownership gaps (SA exists in k8s but has no registered owner) are themselves a risk indicator.

---

## Modules (Planned)

### `hris-connector/`
Pulls employee lifecycle events from HRIS systems.

| Source | Status |
|---|---|
| Workday | Planned |

Key events: `employee.offboarding_scheduled`, `role.changed`, `access_tier.modified`

### `idp-connector/`
Resolves identity anchors and pulls authentication context.

| Source | Status |
|---|---|
| AWS IAM | Planned |
| GCP IAM | Planned |
| Google Workspace | Planned |

### `scm-connector/`
Attributes code and deployments to identities.

| Source | Status |
|---|---|
| GitHub | Planned |

Key signal: `commit → CI/CD → k8s pod` attribution chain

### `context-engine/`
Core correlation and enrichment engine. Receives events from runtime detection layer, joins with identity context, computes anomaly scores, emits enriched events.

### `k8s-runtime/`
Integration with [k8s-detection-pipeline](https://github.com/jaypark81/k8s-detection-pipeline) — Falco, Tetragon, audit log events as the runtime signal source.

---

## Detection Philosophy

This engine is **not** a top-down threat model.

It starts from observability — "what can we see?" — and layers organizational context on top until anomalies become visible naturally. A suspicious technical event becomes a high-priority alert when context reveals:

- The actor is **7 days from their last day**
- The accessed resource is **outside their normal namespace**
- The action was taken **outside normal working hours**
- The pod was deployed from a **branch with no peer review**

No single signal is conclusive. The context engine makes the combination visible.

---

## Relationship to k8s-detection-pipeline

[k8s-detection-pipeline](https://github.com/jaypark81/k8s-detection-pipeline) is the **runtime signal layer** — collecting and normalizing Falco, Tetragon, and Kubernetes audit log events into Elasticsearch.

`identity-context-engine` sits above it, consuming those events and enriching them with organizational context before or after SIEM ingestion.

```
k8s-detection-pipeline  →  raw runtime events
identity-context-engine →  runtime events + who + why + how anomalous
```

---

## Privacy & Legal Considerations

This engine correlates employee identity with behavioral and runtime signals. Deploying it in any organization involves processing personal data and monitoring employee activity — both of which carry significant legal obligations depending on jurisdiction.

Before deployment, legal review is strongly recommended, covering at minimum: applicable data protection law (e.g. GDPR), employee notification requirements, works council or labor representation obligations, and data retention limits.

This engine is intended for **security anomaly detection**, not employee performance monitoring or surveillance.

---

Early design phase. This repository documents the architectural concept and module plan.
Implementation will proceed module by module, starting with the identity anchor layer.

---

## License

Apache License 2.0
