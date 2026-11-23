#!/usr/bin/env bash
# 从 kind 集群的 Tetragon 采集 JSON 事件到 data/raw-events.jsonl(Ctrl-C 停止)。
# 之后: make collect train infer
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p data
kubectl exec -n kube-system ds/tetragon -c tetragon -- \
  tetra getevents -o json > data/raw-events.jsonl