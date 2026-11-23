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

## 7. Real-cluster verification (2026-11-23)

Environment: existing k8s v1.37.2 cluster (Debian 12, kernel 6.12), Tetragon v1.8.0 already
installed; dev host Ubuntu 24.04. ABIP TracingPolicy scoped by pod label (`abip.io/observe=true`),
demo workload pod (alpine sh/cat/ls/wget) on the worker node.

- Capture (merged runs): 2533 raw events → **invalid=0, deduped=689** (same exec observed by two
  policies), emitted=1844 unified events covering all four categories:
  process_exec/exit, file_open (110 in the final window), network_connect, capability_change.
- Training: cold-start v1 val CE 2.93 / Top-1 0.549 → v2 **promoted** (CE 2.64, Top-3 0.932).
- Inference on the real stream: **Top-1 0.813, Top-3 0.948**, mean CE 1.078.
  An exec-only capture scored Top-1 0.960 (short exec→exit chains are highly predictable);
  these are baselines, not claims about complex workloads.

Integration findings fixed along the way (all covered by tests now):

1. Real kprobe `function_name` carries arch prefixes (`__x64_sys_openat`) — stripped in normalize.
2. Tracepoint exec events use `subsys`/`event` fields, not `function_name` — now ingested.
3. Real payloads nest container under `pod.container` — both layouts accepted.
4. Exec/exit dedup must key on `exec_id`, not `event_id` (policies timestamp the same exec differently).
5. `matchWorkloads.podSelector` matches **pod labels**, and labels must exist at pod creation;
   `matchNamespaces` selects Linux namespaces, not k8s namespaces.
6. Small captures need scaled cold-start epochs (~200 gradient steps minimum) or the model
   stays at its initialization.
7. **`syscall: true` kprobes produce no events when combined with `matchWorkloads` selectors**
   on Tetragon v1.8.0 / kernel 6.12. Use kernel functions with `syscall: false`
   (`do_sys_openat2` instead of `sys_openat`); the repo policy is updated accordingly.
8. `commit_creds` fires on **every execve** (normal kernel credential setup) with a
   **transient exec_id** distinct from the resulting process_exec, creating phantom
   single-event processes. The Collector filters this noise (unknown exec_id + known
   same-binary parent); genuine in-lifetime credential changes are kept.
9. OpenShell agent scenario validation (RFC 0001, 4 scenarios incl. a 3-role release
   pipeline with a compromised-AI interception loop) all passed on the real cluster:
   baseline Top-3 0.940/0.966/0.945, two-layer attack coverage 1.0, zero false blocks,
   transfer-service publish BLOCKED. See [rfc/0001](rfc/0001-openshell-agent-behavior-scenarios.md).

## 8. Unverified / known limitations

- kind scripts not exercised (the real cluster already existed); Docker Hub pulls fail on this
  network (DNS poisoning) — use node-cached images or a reachable registry.
- file_write not captured (sys_write's arg is a buffer, not a path; needs fd→path resolution;
  marked with a `shortcut:` comment).
- Synthetic behavior patterns are strong; metrics do not represent real workloads. Re-baseline
  after real data integration.
- Dedup set clears wholesale at the 200k cap (a few duplicates may slip through at extreme
  throughput; marked with a `shortcut:` comment).
- Jev / Decision Controller / multi-tenancy / OTEL / Helm are P3/P4, not implemented.