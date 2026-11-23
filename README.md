# ABIP — Agent Behavioral Intelligence Platform (POC)

Runtime behavioral intelligence and decision platform for Kubernetes workloads.
Tetragon (observe) → Rust Collector (process tree) → LSTM (predict / anomaly) → incremental training → Champion/Challenger model promotion.

Architecture and boundaries: [docs/architecture.md](docs/architecture.md) · POC results: [docs/poc-report.md](docs/poc-report.md) · 中文: [README.zh.md](README.zh.md)

This repo implements the first-round core loop (P0–P2) of the v1.0 design. Jev decisioning and the Decision Controller are P3 and not implemented yet.

## Quick start (macOS/Linux, no cluster needed)

```bash
make setup      # venv + torch (skip if already installed)
make demo       # synthetic events → Collector → training/promotion → inference → data/report.json
make test       # cargo test + Python selfchecks (consistency / hot-swap / rollback / ordering / dedup)
```

Real cluster capture (requires Linux + kind + helm):

```bash
make kind-up    # kind + Tetragon + TracingPolicy
make capture    # tetra getevents -o json → data/raw-events.jsonl (Ctrl-C to stop)
make collect train infer
```

## Artifacts

| File | Content |
|---|---|
| `data/tree.json` | Process tree snapshot (exec_id parent/child links, liveness, event counts) |
| `data/events.jsonl` | Unified event format (contracts/behavior-event.schema.json) |
| `data/training-log.json` | Per-round Challenger validation metrics and promote/discard decisions |
| `models/registry/` | Versioned models + champion.json atomic pointer |
| `data/predictions.jsonl` | Per event: predicted vs actual, Top-3, anomaly score, deterministic Risk Context flags, model version |
| `data/report.json` | Top-1/Top-3 accuracy, CE, LSTM-surprise recall by anomaly type, Risk Context coverage, hot-swap/rebuild counters |

Anomaly detection has two layers (as in the v1.0 design): LSTM surprise `-log P(actual)` catches
**event-category-level** surprises (e.g. capability_change); sensitive file access and anomalous
external connections are normal at the category level and are flagged by deterministic Risk Context
(`sensitive_resource` / `external_destination` / `capability_change`) — the risk-trigger signal that
feeds Jev in P3. Deterministic rules take precedence over model judgment.

## Status

| Component | Status |
|---|---|
| Rust Collector (normalize / dedup / process tree / ordering) | ✅ 11 unit tests |
| Feature Engine v1 (single implementation for training & inference) | ✅ selfcheck |
| LSTM training / inference / incremental / Champion-Challenger | ✅ selfcheck + demo |
| Hot-swap + state rebuild + rollback | ✅ selfcheck |
| TracingPolicy (real Tetragon v1.8.0 / k8s v1.37 cluster) | ✅ verified 2026-11-23, real-stream Top-1 0.813 / Top-3 0.948 |
| OpenShell agent scenarios (RFC 0001/0002: coding/data/ops/supply/persist/lateral + release-pipeline interception) | ✅ all passed, Top-3 0.90+, attack coverage 1.0, transfer publish BLOCKED |
| Mutation coverage engine (RFC 0002: 8 deviation dims + blind, 7 real profiles) | ✅ deterministic dims 1.00, blind 1.0; timing/sequence gaps documented |
| kind scripts | ⚠️ provided, unexercised (real cluster already existed) |
| Jev / Decision Controller / multi-tenancy / OTEL | ⏭ P3/P4, not implemented |

## Layout

```
contracts/   Event schema + feature-schema-v1 (the single feature contract)
collector/   Rust: Tetragon JSONL → unified events + process tree
lstm/        Python: features / model / data / registry / train / infer / selfcheck
scripts/     Synthetic workload, kind setup, event capture
deployment/  TracingPolicy, kind config
tests/       Tetragon event fixtures
docs/        Architecture, POC report (English primary, .zh.md Chinese)
```