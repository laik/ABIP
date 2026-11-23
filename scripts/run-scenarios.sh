#!/usr/bin/env bash
# RFC 0001 验证执行器:3 个 OpenShell Agent 场景 × (baseline + attack)。
# 在已配置集群访问的主机(如 192.168.5.190)运行;约 6 分钟。
set -uo pipefail
cd "$(dirname "$0")/.."
NS=openshell
PY=.venv/bin/python
COLLECTOR=collector/target/release/abip-collector
mkdir -p data

TPOD=$(kubectl -n kube-system get pods -l app.kubernetes.io/name=tetragon \
  -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.spec.nodeName}{"\n"}{end}' \
  | awk '$2=="vm02"{print $1}')
[ -n "$TPOD" ] || { echo "no tetragon pod on vm02"; exit 1; }

kubectl apply -f deployment/openshell/scenario-scripts.yaml

run_one() {
  local S=$1 MODE=$2 NAME=abip-$1-$2
  kubectl -n $NS delete sandbox "$NAME" --ignore-not-found --wait=true --timeout=60s >/dev/null 2>&1
  sleep 2
  timeout 150 kubectl -n kube-system exec "$TPOD" -c tetragon -- tetra getevents -o json \
    > "data/raw-$S-$MODE.jsonl" 2>/dev/null &
  local CAP=$!
  kubectl apply -f - <<EOF
apiVersion: agents.x-k8s.io/v1beta1
kind: Sandbox
metadata:
  name: $NAME
  namespace: $NS
  labels: {abip.io/observe: "true", abip.io/scenario: "$S"}
spec:
  podTemplate:
    metadata:
      labels: {abip.io/observe: "true", abip.io/scenario: "$S"}
    spec:
      restartPolicy: Never
      nodeName: vm02
      containers:
        - name: agent
          image: nginx:1.27-alpine
          imagePullPolicy: IfNotPresent
          command: ["sh", "-c", "sh /scenarios/$S.sh $MODE"]
          volumeMounts: [{name: scripts, mountPath: /scenarios}]
      volumes:
        - name: scripts
          configMap: {name: abip-scenario-scripts}
EOF
  kubectl -n $NS wait --for=jsonpath='{.status.phase}'=Succeeded "pod/$NAME" --timeout=150s \
    || echo "WARN: $NAME did not succeed: $(kubectl -n $NS get pod $NAME -o jsonpath='{.status.phase}' 2>/dev/null)"
  kill $CAP 2>/dev/null; wait $CAP 2>/dev/null
  $PY - "$NAME" "data/raw-$S-$MODE.jsonl" "data/events-$S-$MODE.jsonl" <<'PY'
import json, sys
name, src, dst = sys.argv[1:4]
n = 0
with open(src) as f, open(dst, "w") as out:
    for line in f:
        e = json.loads(line)
        for k in ("process_exec", "process_exit", "process_kprobe", "process_tracepoint"):
            p = e.get(k)
            if p and (p.get("process", {}).get("pod") or {}).get("name") == name:
                out.write(line); n += 1
                break
print(f"{name}: {n} events")
PY
  $COLLECTOR --input "data/events-$S-$MODE.jsonl" --output "data/norm-$S-$MODE.jsonl"
  kubectl -n $NS delete sandbox "$NAME" --wait=false >/dev/null 2>&1
}

for S in ${SCENARIOS:-coding data ops}; do
  echo "=== scenario: $S ==="
  run_one "$S" baseline
  run_one "$S" attack
  rm -rf "models/scenario-$S"
  $PY scripts/verify_scenarios.py \
    --baseline "data/norm-$S-baseline.jsonl" --attack "data/norm-$S-attack.jsonl" \
    --registry "models/scenario-$S" --scenario "$S" --out "data/scenario-$S-report.json" > "data/scenario-$S-verify.log" 2>&1 \
    || { echo "verify failed, see data/scenario-$S-verify.log"; tail -5 "data/scenario-$S-verify.log"; }
done

$PY - <<'PY'
import json
summary = {}
import glob, os
for f in sorted(glob.glob("data/scenario-*-report.json")):
    s = os.path.basename(f)[len("scenario-"):-len("-report.json")]
    try:
        r = json.load(open(f))
        summary[s] = {"passed": r["passed"], "gates": r["gates"],
                      "baseline_top3": round(r["baseline"]["top3"], 3),
                      "risk_coverage": r["attack"]["risk_context_coverage"],
                      "chain_exec_anomaly": round(r["attack"].get("chain_exec_anomaly",
                                                          r["attack"].get("nc_exec_anomaly", 0)), 3),
                      "baseline_p90": round(r["baseline"]["anomaly_p90"], 3)}
    except (KeyError, ValueError):
        summary[s] = {"passed": False, "error": "bad report"}
json.dump(summary, open("data/scenario-report.json", "w"), indent=2)
print(json.dumps(summary, indent=2))
print("ALL PASSED" if all(v.get("passed") for v in summary.values()) else "SOME GATES FAILED")
PY