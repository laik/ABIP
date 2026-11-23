# ABIP Architecture (POC v0.1)

ABIP (Agent Behavioral Intelligence Platform): a runtime behavioral intelligence and decision
platform for Kubernetes workloads. This document is the POC implementation of the v1.0 design:
**the target architecture is unchanged; the first round implements only the core loop.**

Core loop: Observe → Understand → Predict → Decide → Evaluate → Learn

中文版本: [architecture.zh.md](architecture.zh.md)

## 1. Target architecture (v1.0, unchanged)

```
Tetragon (the only runtime behavior entry point)
   ↓
Rust Collector (validation / dedup / metadata enrichment / tenant binding)
   ↓
Redpanda (event stream)
   ↓
Process Tree Engine + Feature Engine ──→ Redis (realtime state)
   ↓                                        ↓
LSTM Inference (next-event + anomaly)   Training Pipeline (Replay Buffer → incremental training)
   ↓                                        ↓
Risk Context                            Model Validation → Registry → Promotion
   ↓
Jev Decision (/v1/systemone, Choice/Score/Noul)
   ↓
Decision Controller (Rust; deterministic policy first, confidence thresholds, fallback)
   ↓
Alert / Approval / Enforcement Recommendation → Audit / Feedback
```

Inviolable responsibility boundaries:

- Tetragon only observes. Pre-emptive blocking goes through pre-deployed TracingPolicies (path A);
  asynchronous LSTM/Jev decisions are post-hoc risk response only (path B).
- Jev does not control the kernel; its output never maps directly to enforcement actions.
  Deterministic deny rules take precedence over model judgment.
- Training and inference share **one** model definition, feature schema, category vocabulary
  and normalization parameters.
- Online training only produces Challengers; after validation passes, the Champion is switched
  atomically. After a switch, old hidden states must be rebuilt by replaying through the new model.
- Phase 1 runs entirely in Monitoring Mode; no model-driven dynamic enforcement.

## 2. POC scope (what this repo implements)

Per the v1.0 design's own final recommendation, the first round proves this chain:

```
Tetragon JSON events (real capture, replay, or synthetic)
   ↓
Rust Collector: schema validation → dedup → process tree reconstruction → unified events
   ↓
LSTM online inference: per-event next-event prediction vs actual, anomaly = -log P(actual)
   ↓
Online incremental training: self-supervised samples + Replay Buffer + micro-batches
   ↓
Champion/Challenger: validation → atomic promotion → live swap + state rebuild in inference
```

**Process tree reconstruction is the first technical milestone** (process identity, parent/child
links, event ordering, state lifecycle). If it is wrong, the LSTM just learns wrong sequences.
The Collector's tests focus here.

### POC simplifications and upgrade paths (explicitly recorded deviations)

| v1.0 component | POC substitute | Upgrade path |
|---|---|---|
| Redpanda event stream | JSONL files (append-only) | Swap the Collector's output for a producer; interface unchanged |
| Redis state store | Inference-process memory (per-exec_id state + ring buffer of last 64 events) | Replace state_manager with a Redis implementation using v1.0 §4.3 key layout |
| Postgres metadata/audit | Prediction/decision JSONL + registry meta.json | Persist audit to DB |
| Jev Adapter / Decision Controller | Not implemented; anomaly score + threshold report instead | P3; question templates in v1.0 §7.3 |
| Multi-tenancy | Events carry tenant_id (= namespace); single-tenant run | Per-tenant streams/models/thresholds |
| OTEL / Helm / RBAC | Not implemented; Makefile + kind scripts | P4 |
| ONNX export | Direct PyTorch CPU inference (model is tiny) | Export to ONNX when throughput demands it |

Contracts kept for later consumers: prediction/decision output schemas in `contracts/`;
Jev/Controller can consume them directly.

## 3. Data contracts

- `contracts/behavior-event.schema.json` — unified event format (v1.0 §3.3); Collector output,
  training/inference input.
- `contracts/feature-schema.json` — **feature-schema-v1**: category vocabularies + normalization
  parameters, versioned. Python `lstm/features.py` is the only encoding implementation, used by
  both training and inference; the Rust side does no feature logic.

Process identity: `exec_id` (unique) + `parent_exec_id` + pid + start_time + container_id + pod_uid.
PID-reuse protection: state closes on process exit; a new exec_id starts fresh state and never
reuses an old sequence.

Ordering: the Collector tracks last_ts per exec_id; events later than the max out-of-order window
(5s) are flagged `late: true`. Inference **records late events but never updates hidden state**
(v1.0 §6.4: no unconditional overwrite).

## 4. Model design (v1.0 §6, same parameters)

One shared LSTM encoder + Next Event Head (Head B, the anomaly score, is a function of the
predictive distribution, -log P(actual); it needs no separate network):

- Categorical features via embeddings (16 dims per field); continuous features log/clip-normalized;
  unknown → UNK (index 0).
- LSTM 2 layers, hidden 128, sequence window 64, batch 128, AdamW lr 1e-4, CrossEntropy.
- Anomaly score = -log P(actual event category). An anomaly signal, not a maliciousness probability.
- Self-supervised samples: E1..E63 → predict E2..E64. Model predictions are never used as labels.
- Process tree context (v1.0 §4): a new child process inherits its parent's current hidden state
  and pending prediction, so the first event of a derived chain (python→sh→nc) is scoreable —
  attack-chain detection has no blind spot at process birth.

### Champion / Challenger

```
models/registry/
  v1/{model.pt, meta.json}      # meta: metrics, sample count, feature schema version, parent
  v2/...
  champion.json                 # atomic pointer, written via os.replace
```

- Every 512 new samples triggers a round: initialize the Challenger from Champion weights,
  train on recent data + Replay Buffer (capacity 8192, reservoir sampling), validate on an
  independent time-based holdout (no leakage).
- Promotion gate: validation CE improves AND Top-3 accuracy does not drop; otherwise discard.
- Inference polls champion.json; on version change it loads the new weights and rebuilds every
  exec_id's hidden state by replaying its last-64-event buffer.
- Rollback = point champion.json back at an older version (atomic).

## 5. Modules and layout

```
ABIP/
├── docs/                         # architecture + POC report (English primary, .zh.md Chinese)
├── contracts/                    # event schema + feature-schema-v1
├── collector/                    # Rust: Tetragon JSONL → unified events + process tree
│   └── src/{main.rs, normalize.rs, tree.rs}
├── lstm/                         # Python: one model & feature implementation for train + infer
│   ├── features.py               # the only Feature Engine (reads feature-schema.json)
│   ├── model.py                  # the only model definition
│   ├── data.py                   # JSONL → per-exec sequences → window samples + Replay Buffer
│   ├── registry.py               # Champion/Challenger atomic switch
│   ├── train.py                  # incremental training + validation + promotion
│   ├── infer.py                  # streaming inference + anomaly + state rebuild + report
│   └── selfcheck.py              # assert-based selfchecks (train/infer consistency etc.)
├── scripts/gen_workload.py       # synthetic Tetragon-shaped events (normal profiles + anomalies)
├── deployment/tetragon/          # TracingPolicy (file/network/security) + kind config
├── scripts/{kind-up.sh, capture-events.sh}
├── tests/fixtures/               # realistically shaped Tetragon event fixtures
└── Makefile                      # demo: gen → collect → train → infer → report
```

## 6. Real capture (P0, requires a Linux cluster)

Tetragon emits process lifecycle events by default; **file/network/security behavior requires
explicit TracingPolicies**:

- `deployment/tetragon/file-network-security.yaml`:
  - `sys_openat` → file_open (path from the string arg)
  - `tcp_connect` → network_connect
  - `commit_creds` / `sys_setuid` → capability_change (credential changes)
- `scripts/kind-up.sh`: kind cluster + Tetragon via Helm + apply TracingPolicy.
- `scripts/capture-events.sh`: `tetra getevents -o json` to JSONL, feed the Collector.

macOS dev machines cannot run eBPF; local development/acceptance uses replay and synthetic events
(`make demo`). The TracingPolicy was verified on a real Tetragon v1.8.0 / k8s v1.37 cluster
(2026-11-23, see poc-report.md §7); scope it with `matchWorkloads.podSelector` on pod labels —
labels must exist at pod creation. kind scripts remain unexercised.

## 7. POC acceptance (executable subset of v1.0 §15)

`make demo` produces `data/report.json`:

| Metric | Acceptance method |
|---|---|
| Process tree correctness | cargo test: parent/child, exit closes state, PID reuse, dedup, late flag |
| Train/infer schema consistency | selfcheck: same event encodes bit-identically through both paths; single model definition |
| Top-1 / Top-3 accuracy | Baseline on synthetic normal profiles; improves over the initial model after training |
| Anomaly recall | Two layers: LSTM surprise for category-level anomalies (capability_change); sensitive files / anomalous external connections are normal at category level and covered by deterministic Risk Context flags (sensitive_resource / external_destination / capability_change) — the Risk Context → Jev trigger signal in v1.0; deterministic rules take precedence over model judgment |
| Promotion / rollback | Training produces new versions with atomic switch; inference uninterrupted, state rebuilt; pointer can roll back |
| Event loss / ordering | Collector counters: received / deduped / late / emitted |

No preset accuracy targets; Jev cost, throughput stress tests and Redis state sizing are
pre-production work.

## 8. Phase roadmap (maps to v1.0 P0–P4)

- **P0 (this repo)**: Collector + process tree + TracingPolicy + kind scripts.
- **P1 (this repo)**: Feature Schema v1 + LSTM inference + anomaly score + state management.
- **P2 (this repo)**: Replay Buffer + micro-batch incremental training + Champion/Challenger + state rebuild.
- P3: Jev Adapter (risk-triggered, not per-event), confidence calibration, low-confidence fallback, decision audit.
- P4: Tenant isolation, policy integration, alerting/approval, enforcement policy release control, failure fallback, OTEL/Helm/RBAC.