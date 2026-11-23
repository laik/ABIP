"""合成 Tetragon 格式事件流(POC 本地验收用;真实数据走 scripts/capture-events.sh)。

两个 workload profile(coding-agent / web-server),行为有可学习的模式;
注入 ~2% 异常(权限变化 / 敏感文件 / 异常外联 / 可疑派生链),输出 ground truth。
另注入少量重复事件和乱序事件,验证 Collector 的去重与 late 标记。

用法:python scripts/gen_workload.py --count 20000 --events data/raw-events.jsonl \
        --truth data/anomaly-truth.jsonl [--seed 42]
"""

import argparse
import json
import random
from datetime import datetime, timedelta, timezone

BASE = datetime(2026, 11, 22, 10, 0, 0, tzinfo=timezone.utc)


def iso(t: datetime) -> str:
    return t.isoformat(timespec="milliseconds").replace("+00:00", "Z")


class Gen:
    def __init__(self, seed=42):
        self.rng = random.Random(seed)
        self.n = 0
        self.events = []
        self.truth = []

    def exec_id(self):
        self.n += 1
        return f"exec-{self.n:06d}"

    def proc(self, eid, parent, pid, binary, pod, cid, uid, t):
        return {
            "exec_id": eid, "parent_exec_id": parent, "pid": pid,
            "uid": uid, "cwd": "/workspace", "binary": binary,
            "start_time": iso(t),
            "pod": {"namespace": "tenant-a", "name": pod},
            "container": {"id": f"docker://{cid}"},
        }

    def emit(self, t, payload, p):
        # process 必须在内层 payload(process_exec/process_exit/process_kprobe)里
        inner = next(iter(payload))
        payload[inner]["process"] = p
        self.events.append({"time": iso(t), "node_name": "kind-worker", **payload})

    def kprobe(self, t, p, func, args, anomaly=False):
        self.emit(t, {"process_kprobe": {
            "function_name": func, "args": args, "policy_name": "abip-file-network-security",
        }}, p)
        if anomaly:
            kind = {"sys_openat": "file_open", "tcp_connect": "network_connect",
                    "commit_creds": "capability_change", "sys_setuid": "capability_change",
                    "sys_write": "file_write"}[func]
            self.truth.append({"exec_id": p["exec_id"], "event_time": iso(t), "type": kind})

    def child_behavior(self, t, p, binary, anomalous):
        """每种 binary 有固定倾向的行为序列(LSTM 可学习);返回结束时间。"""
        r = self.rng
        if anomalous:
            if binary == "nc":
                self.kprobe(t, p, "tcp_connect",
                            [{"sock_arg": {"daddr": "203.0.113.9", "dport": 4444}}], anomaly=True)
            else:
                choice = r.randrange(3)
                if choice == 0:
                    self.kprobe(t, p, "sys_openat", [{"int_arg": -100}, {"string_arg": r.choice(
                        ["/etc/shadow", "/root/.ssh/id_rsa", "/var/run/secrets/token"])}],
                        anomaly=True)
                elif choice == 1:
                    self.kprobe(t, p, "tcp_connect",
                                [{"sock_arg": {"daddr": "203.0.113.9", "dport": 4444}}],
                                anomaly=True)
                else:
                    self.kprobe(t, p, "commit_creds", [], anomaly=True)
            t += timedelta(seconds=r.uniform(0.1, 1))
            self.emit(t, {"process_exit": {}}, p)
            return t

        actions = {
            "bash": [("sys_openat", "/workspace/run.sh"), ("sys_write", "/tmp/out.log")],
            "sh": [("sys_openat", "/workspace/entry.sh")],
            "cat": [("sys_openat", r.choice(["/workspace/main.py", "/etc/nginx/nginx.conf",
                                             "/app/config.yaml"]))],
            "ls": [("sys_openat", "/workspace")],
            "curl": [("tcp_connect", None), ("sys_write", "/tmp/download")],
            "gcc": [("sys_openat", "/workspace/main.c"), ("sys_write", "/tmp/a.out")],
            "tar": [("sys_openat", "/workspace/dist.tar"), ("sys_write", "/tmp/dist.tar")],
            "nc": [("tcp_connect", None)],
        }[binary]
        for func, res in actions:
            t += timedelta(seconds=r.uniform(0.05, 0.5))
            if func == "tcp_connect":
                args = [{"sock_arg": {"daddr": r.choice(["10.96.0.10", "192.168.1.5"]),
                                       "dport": r.choice([80, 443, 8080])}}]
            elif func == "sys_openat":
                args = [{"int_arg": -100}, {"string_arg": res}]
            else:
                args = [{"string_arg": res}]
            self.kprobe(t, p, func, args)
        t += timedelta(seconds=r.uniform(0.05, 0.5))
        self.emit(t, {"process_exit": {}}, p)
        return t

    def spawn(self, t, parent_p, pod, cid, uid, binary, anomalous=False):
        p = self.proc(self.exec_id(), parent_p["exec_id"], self.rng.randrange(1000, 60000),
                      f"/usr/bin/{binary}", pod, cid, uid, t)
        self.emit(t, {"process_exec": {}}, p)
        end = self.child_behavior(t + timedelta(seconds=0.05), p, binary, anomalous)
        return end, p

    def run(self, count):
        r = self.rng
        roots = []
        for pod, cid, binary, uid in [("coding-agent-0", "c0de01", "/usr/bin/python3", 1000),
                                      ("nginx-0", "cafe02", "/usr/sbin/nginx", 0)]:
            p = self.proc(self.exec_id(), "", r.randrange(100, 999), binary, pod, cid, uid, BASE)
            self.emit(BASE, {"process_exec": {}}, p)
            roots.append([p, pod, cid, uid, BASE + timedelta(seconds=1)])

        while len(self.events) < count:
            root = r.choice(roots)
            p, pod, cid, uid, t = root
            t += timedelta(seconds=r.uniform(0.2, 2.0))
            if r.random() < 0.45:
                # 长驻进程自身行为:读工作区/配置,偶发内部连接
                if r.random() < 0.25:
                    self.kprobe(t, p, "tcp_connect",
                                [{"sock_arg": {"daddr": "10.96.0.10", "dport": 443}}])
                else:
                    self.kprobe(t, p, "sys_openat", [{"int_arg": -100}, {"string_arg": r.choice(
                        ["/workspace/main.py", "/workspace/util.py", "/app/config.yaml",
                         "/etc/hosts"])}])
                root[4] = t
            else:
                binary = (r.choice(["bash", "sh", "cat", "ls", "gcc", "tar", "curl"])
                          if pod == "coding-agent-0" else r.choice(["sh", "cat", "ls", "curl"]))
                if r.random() < 0.02:
                    if binary in ("bash", "sh"):
                        # 可疑派生链:python3 → bash → nc 外联
                        end, bash_p = self.spawn(t, p, pod, cid, uid, binary)
                        end, _ = self.spawn(end, bash_p, pod, cid, uid, "nc", anomalous=True)
                    else:
                        end, _ = self.spawn(t, p, pod, cid, uid, binary, anomalous=True)
                else:
                    end, _ = self.spawn(t, p, pod, cid, uid, binary)
                root[4] = max(t, end)

        # 注入完全重复事件(验证去重)
        for _ in range(max(1, count // 2000)):
            self.events.append(r.choice(self.events))
        # 注入乱序:时间回拨 6s 且放到文件更后位置(验证 late 标记)
        for _ in range(max(1, count // 4000)):
            i = r.randrange(len(self.events) // 2, len(self.events) - 10)
            ev = json.loads(json.dumps(self.events[i]))
            t = datetime.fromisoformat(ev["time"].replace("Z", "+00:00")) - timedelta(seconds=6)
            ev["time"] = iso(t)
            self.events.append(ev)
        return self.events, self.truth


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--count", type=int, default=20000)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--events", required=True)
    ap.add_argument("--truth", required=True)
    args = ap.parse_args()
    events, truth = Gen(args.seed).run(args.count)
    with open(args.events, "w") as f:
        for ev in events:
            f.write(json.dumps(ev) + "\n")
    with open(args.truth, "w") as f:
        for t in truth:
            f.write(json.dumps(t) + "\n")
    print(f"generated {len(events)} tetragon-shaped events, {len(truth)} injected anomalies")


if __name__ == "__main__":
    main()