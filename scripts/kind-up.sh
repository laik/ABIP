#!/usr/bin/env bash
# P0:kind 集群 + Tetragon + ABIP TracingPolicy。需要 Linux(或 macOS 上的 Docker Desktop)、
# kind、helm、kubectl。未在 Linux 真机验证(见 README 状态表)。
set -euo pipefail
cd "$(dirname "$0")/.."

kind create cluster --name abip --config deployment/kind-config.yaml
helm repo add cilium https://helm.cilium.io >/dev/null
helm repo update >/dev/null
helm install tetragon cilium/tetragon -n kube-system \
  --set tetragon.enableProcessCred=true \
  --set tetragon.enableProcessNs=true
kubectl -n kube-system rollout status ds/tetragon --timeout=300s
kubectl apply -f deployment/tetragon/file-network-security.yaml
echo "Tetragon ready. 采集: make capture"