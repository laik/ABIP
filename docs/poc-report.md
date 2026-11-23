# ABIP POC Acceptance Report (First-Round Core Loop)

Date: 2026-11-22 · Environment: macOS arm64, CPU · Data: synthetic Tetragon-shaped events (seed=42, reproducible)
Reproduce: `make demo && make test` · 中文版本: [poc-report.zh.md](poc-report.zh.md)

## 1. Pipeline and scale

```
gen (20015 events, 95 injected anomalies) → Rust Collector → 20005 unified events
→ 8 incremental training rounds (v1 cold start + 7 micro-batch rounds) → Champion v8
→ streaming inference over 15271 scoreable events
```

Collector counters: received=20015, invalid=0, **deduped=10** (all injected duplicates removed),
**late=5** (all injected out-of-order events flagged), emitted=20005. No loss.

## 2. Process tree (the first milestone)

- All 11 Rust unit tests pass: parent/child depth, late-arriving parent still links, exit closes
  state, **PID-reuse isolation** (same pid, new exec_id → independent sequence), dedup,
  out-of-order window (5s), time parsing.
- `data/tree.json`: python3 → bash → curl chain correct; curl depth=2, parent_binary=bash.

## 3. Training / model management

| Round | val CE | val Top-3 | Outcome |
|---|---|---|---|
| v1 cold start | 1.949 | 0.444 | promote |
| v2–v5 | 1.901→1.572 | 0.766→0.811 | promote |
| v6 | 1.457 | 0.805 (< champ 0.811) | **discard** (Top-3 regression rejected) |
| v7–v8 | 1.450→1.390 | 0.907→0.934 | promote |

- CE dropped from 1.949 (≈ln7, uniform) to 1.390; Top-3 rose from 0.444 to 0.934.
- The promotion gate (CE improves AND Top-3 does not drop) genuinely rejected one regression (v6).
- Switching is an atomic os.replace of champion.json; selfchecks cover promote/rollback/old-version retention.

## 4. Inference and anomaly detection

| Metric | Value |
|---|---|
| Top-1 accuracy (full stream, incl. early untrained phase) | 0.499 |
| Top-3 accuracy | **0.933** |
| Mean CE / anomaly score | 1.361 |
| LSTM-surprise Recall@p90: capability_change | **0.643** |
| LSTM-surprise Recall@p90: sensitive file_open / external connect | 0.0 (see below) |
| **Deterministic Risk Context coverage (all injected anomalies)** | **1.000** |
| Late events skipped for state updates | 5/5 |

Consistent with the v1.0 design: **category-level surprises** (capability_change) are caught by
LSTM surprise; sensitive files / anomalous external connections are normal at the category level,
so surprise is ineffective there — deterministic Risk Context
(sensitive_resource / external_destination / capability_change) covers 100% of them. This is
exactly the Risk Context → Jev risk-trigger signal in P3: deterministic rules take precedence
over model judgment.

## 5. Hot-swap and state rebuild (selfcheck)

Promoting a new Champion mid-inference: the inferencer detects the switch (v2→v3), rebuilds all
live states by replaying their event buffers, all subsequent records use the new version, no
interruption. Late events are counted but never update hidden state; state closes on process_exit.

## 6. Train/infer consistency (selfcheck)

Same FeatureEngine code path, deterministic encoding, UNK→index 0, normalization ∈ [0,1],
bit-identical model save/load, single-step `step` matches batched `forward`, anomaly formula verified.

## 7. Unverified / known limitations

- TracingPolicy / kind scripts not verified on real Linux (no eBPF on macOS); real Tetragon kprobe
  payload shapes follow the fixtures and docs — normalize may need minor adjustments at integration.
- file_write not captured (sys_write's arg is a buffer, not a path; needs fd→path resolution;
  marked with a `shortcut:` comment).
- Synthetic behavior patterns are strong; metrics do not represent real workloads. Re-baseline
  after real data integration.
- Dedup set clears wholesale at the 200k cap (a few duplicates may slip through at extreme
  throughput; marked with a `shortcut:` comment).
- Jev / Decision Controller / multi-tenancy / OTEL / Helm are P3/P4, not implemented.