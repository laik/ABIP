#!/usr/bin/env bash
# S8 db-lock 验证(RFC 0003):被劫持 agent 勒索链 → ABIP 决策 → 门禁拦截破坏阶段。
# 核心门槛:attack 后数据库文件必须完整(零损失,不只是检测到)。
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

run_ransom() {
  local MODE=$1 NAME=abip-ransom-$1
  kubectl -n $NS delete sandbox "$NAME" --ignore-not-found --wait=true --timeout=60s >/dev/null 2>&1
  sleep 2
  timeout 120 kubectl -n kube-system exec "$TPOD" -c tetragon -- tetra getevents -o json \
    > "data/raw-ransom-$MODE.jsonl" 2>/dev/null &
  local CAP=$!
  kubectl apply -f - <<EOF
apiVersion: agents.x-k8s.io/v1beta1
kind: Sandbox
metadata:
  name: $NAME
  namespace: $NS
  labels: {abip.io/observe: "true", abip.io/scenario: ransom}
spec:
  podTemplate:
    metadata:
      labels: {abip.io/observe: "true", abip.io/scenario: ransom}
    spec:
      restartPolicy: Never
      nodeName: vm02
      containers:
        - name: agent
          image: nginx:1.27-alpine
          imagePullPolicy: IfNotPresent
          command: ["sh", "-c", "sh /scenarios/ransom.sh $MODE"]
          volumeMounts: [{name: scripts, mountPath: /scenarios}]
      volumes:
        - name: scripts
          configMap: {name: abip-scenario-scripts}
EOF
  kubectl -n $NS wait --for=condition=Ready "pod/$NAME" --timeout=90s || return 1
  sleep 38   # 基线循环 + 备份;attack:侦察/归档/加锁完成,进入决策等待
  kill $CAP 2>/dev/null; wait $CAP 2>/dev/null
  $PY - "$NAME" "data/raw-ransom-$MODE.jsonl" "data/events-ransom-$MODE.jsonl" <<'PY'
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
  $COLLECTOR --input "data/events-ransom-$MODE.jsonl" --output "data/norm-ransom-$MODE.jsonl"
  if [ "$MODE" = baseline ]; then
    rm -rf models/ransom
    $PY -m lstm.train --events "data/norm-ransom-baseline.jsonl" --registry models/ransom \
      > data/ransom-training.log 2>&1
  fi
  $PY scripts/release_decision.py --events "data/norm-ransom-$MODE.jsonl" \
    --registry models/ransom --decision "data/decision-ransom-$MODE.json" \
    --evidence "data/evidence-ransom-$MODE.json"
  kubectl -n $NS exec -i "$NAME" -- sh -c 'cat > /workspace/decision.json' \
    < "data/decision-ransom-$MODE.json"
  kubectl -n $NS exec "$NAME" -- cat /workspace/decision.json | grep -q action \
    || echo "WARN: decision not delivered to $NAME"
  sleep 5
  # 数据完整性验证(block 路径 pod 保持存活 20s)
  if [ "$MODE" = attack ]; then
    if kubectl -n $NS exec "$NAME" -- test -f /var/lib/db/data/users.csv; then
      echo "DATA_INTACT=true" > data/ransom-integrity.txt
    else
      echo "DATA_INTACT=false" > data/ransom-integrity.txt
    fi
    if kubectl -n $NS exec "$NAME" -- test -f /workspace/README_RESTORE.txt; then
      echo "RANSOM_NOTE=true" >> data/ransom-integrity.txt
    else
      echo "RANSOM_NOTE=false" >> data/ransom-integrity.txt
    fi
    cat data/ransom-integrity.txt
  fi
  local i=0 phase=Running
  while [ $i -lt 60 ]; do
    phase=$(kubectl -n $NS get pod "$NAME" -o jsonpath='{.status.phase}' 2>/dev/null)
    [ "$phase" != Running ] && [ "$phase" != Pending ] && break
    sleep 2; i=$((i+1))
  done
  kubectl -n $NS logs "$NAME" > "data/ransom-$MODE.log" 2>/dev/null
  echo "ransom-$MODE: phase=$phase log=$(tail -1 "data/ransom-$MODE.log")"
  kubectl -n $NS delete sandbox "$NAME" --wait=false >/dev/null 2>&1
}

run_ransom baseline
run_ransom attack

$PY - <<'PY'
import json
base_log = open("data/ransom-baseline.log").read()
atk_log = open("data/ransom-attack.log").read()
ev = json.load(open("data/evidence-ransom-attack.json"))
integ = dict(l.strip().split("=") for l in open("data/ransom-integrity.txt"))
report = {
    "baseline": {"maintained": "MAINTAINED" in base_log,
                 "decision": json.load(open("data/decision-ransom-baseline.json"))},
    "attack": {"blocked": "BLOCKED" in atk_log,
               "decision": json.load(open("data/decision-ransom-attack.json")),
               "risk_flags": ev["risk_flags"],
               "data_intact": integ.get("DATA_INTACT") == "true",
               "ransom_note_written": integ.get("RANSOM_NOTE") == "true"},
    "gates": {
        "baseline_maintained_no_false_block": "MAINTAINED" in base_log,
        "attack_blocked": "BLOCKED" in atk_log,
        "data_intact_zero_loss": integ.get("DATA_INTACT") == "true",
        "destruction_prevented": integ.get("RANSOM_NOTE") == "false",
        "sensitive_flagged": ev["risk_flags"].get("sensitive_resource", 0) > 0,
    },
}
report["passed"] = all(report["gates"].values())
json.dump(report, open("data/ransom-report.json", "w"), indent=2)
print(json.dumps(report, indent=2))
print("RANSOM SCENARIO PASSED" if report["passed"] else "RANSOM SCENARIO FAILED")
PY