//! 进程树重建 + 去重 + 乱序标记。第一个技术里程碑:身份/父子/排序/生命周期。

use crate::normalize::{parse_time, Event};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};

/// 与 contracts/feature-schema.json ordering.max_out_of_order_seconds 一致。
const MAX_OUT_OF_ORDER_SECONDS: f64 = 5.0;
const DEDUP_CAP: usize = 200_000;

#[derive(Default)]
pub struct Counters {
    pub received: u64,
    pub invalid: u64,
    pub deduped: u64,
    pub late: u64,
    pub emitted: u64,
    pub exec_cred_noise: u64,
}

struct Node {
    parent_exec_id: String,
    binary: String,
    pid: i64,
    container_id: String,
    pod_uid: String,
    tenant_id: String,
    alive: bool,
    children: Vec<String>,
    last_ts: f64,
    event_count: u64,
}

#[derive(Default)]
pub struct Tree {
    nodes: HashMap<String, Node>,
    seen: HashSet<String>,
    pub counters: Counters,
}

impl Tree {
    /// 去重、补全树上下文(parent_binary/depth)、标记迟到事件。
    /// 返回 false 表示重复事件,调用方应丢弃。
    pub fn observe(&mut self, ev: &mut Event) -> bool {
        self.counters.received += 1;
        // execve 期间的 commit_creds 带瞬态 exec_id(与 process_exec 不同),
        // 是内核标准凭据安装的良性噪声,不是真正的权限变化;过滤。
        // 进程生存期内 exec_id 已存在的 capability_change(setuid 等)保留。
        if ev.event.kind == "capability_change" && !self.nodes.contains_key(&ev.process.exec_id) {
            if let Some(p) = self.nodes.get(&ev.process.parent_exec_id) {
                if !p.binary.is_empty() && p.binary == ev.process.binary {
                    self.counters.exec_cred_noise += 1;
                    return false;
                }
            }
        }
        // shortcut: 去重集到上限整体清空,极端吞吐下可能放过少量重复;升级换 LRU/bloom filter。
        if self.seen.len() >= DEDUP_CAP {
            self.seen.clear();
        }
        // exec/exit 按 exec_id 去重:一个进程实例只执行/退出一次,
        // 多个 policy(默认 + tracepoint)观测同一 exec 时时间戳略有差异,不能用 event_id。
        let dedup_key = match ev.event.kind.as_str() {
            "process_exec" | "process_exit" => format!("{}:{}", ev.event.kind, ev.process.exec_id),
            _ => ev.event_id.clone(),
        };
        if !self.seen.insert(dedup_key) {
            self.counters.deduped += 1;
            return false;
        }

        let exec_id = ev.process.exec_id.clone();
        let ts = parse_time(&ev.event_time).unwrap_or(0.0);
        let is_exec = ev.event.kind == "process_exec";
        let is_exit = ev.event.kind == "process_exit";

        let node = self.nodes.entry(exec_id.clone()).or_insert_with(|| Node {
            parent_exec_id: ev.process.parent_exec_id.clone(),
            binary: ev.process.binary.clone(),
            pid: ev.process.pid,
            container_id: ev.container_id.clone(),
            pod_uid: ev.pod_uid.clone(),
            tenant_id: ev.tenant_id.clone(),
            alive: true,
            children: Vec::new(),
            last_ts: ts,
            event_count: 0,
        });
        if is_exec {
            node.alive = true;
        }
        if is_exit {
            // exit 关闭状态;节点保留用于树上下文,PID 重用走新 exec_id,不污染旧序列。
            node.alive = false;
        }
        node.event_count += 1;
        if ts < node.last_ts - MAX_OUT_OF_ORDER_SECONDS {
            ev.late = true;
            self.counters.late += 1;
        } else {
            node.last_ts = node.last_ts.max(ts);
        }

        // 父节点后到时也能挂上:children 挂在 parent 条目上,exec 时登记。
        if is_exec && !ev.process.parent_exec_id.is_empty() {
            let parent_id = ev.process.parent_exec_id.clone();
            let child_id = exec_id.clone();
            self.nodes
                .entry(parent_id)
                .or_insert_with(|| Node {
                    parent_exec_id: String::new(),
                    binary: String::new(),
                    pid: 0,
                    container_id: String::new(),
                    pod_uid: String::new(),
                    tenant_id: String::new(),
                    alive: false,
                    children: Vec::new(),
                    last_ts: 0.0,
                    event_count: 0,
                })
                .children
                .push(child_id);
        }

        ev.process.parent_binary = self
            .nodes
            .get(&ev.process.parent_exec_id)
            .map(|n| n.binary.clone())
            .filter(|b| !b.is_empty())
            .unwrap_or_else(|| "unknown".into());
        ev.process.depth = self.depth(&exec_id);
        self.counters.emitted += 1;
        true
    }

    /// 树深,带环/超长保护。
    fn depth(&self, exec_id: &str) -> i64 {
        let mut d = 0;
        let mut cur = exec_id;
        while d < 64 {
            match self.nodes.get(cur) {
                Some(n) if !n.parent_exec_id.is_empty() => {
                    cur = &n.parent_exec_id;
                    d += 1;
                }
                _ => break,
            }
        }
        d
    }

    /// 进程树快照(审计/验收用)。
    pub fn snapshot(&self) -> Value {
        let nodes: Vec<Value> = self
            .nodes
            .iter()
            .filter(|(_, n)| !n.binary.is_empty())
            .map(|(id, n)| {
                json!({
                    "exec_id": id, "parent_exec_id": n.parent_exec_id,
                    "binary": n.binary, "pid": n.pid, "alive": n.alive,
                    "container_id": n.container_id, "pod_uid": n.pod_uid,
                    "tenant_id": n.tenant_id, "children": n.children,
                    "event_count": n.event_count,
                })
            })
            .collect();
        json!({ "processes": nodes })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::normalize::normalize;
    use serde_json::json;

    fn exec(id: &str, parent: &str, pid: i64, binary: &str, time: &str) -> Event {
        let raw = json!({"process_exec": {"process": {
            "exec_id": id, "parent_exec_id": parent, "pid": pid,
            "binary": binary, "pod": {"namespace": "t", "name": "p"}
        }}, "time": time});
        normalize(&raw, "c").unwrap()
    }

    fn kprobe(id: &str, func: &str, arg: &str, time: &str) -> Event {
        let raw = json!({"process_kprobe": {
            "process": {"exec_id": id, "binary": "/usr/bin/curl", "pid": 3},
            "function_name": func, "args": [{"string_arg": arg}]
        }, "time": time});
        normalize(&raw, "c").unwrap()
    }

    #[test]
    fn builds_parent_child_chain() {
        let mut tree = Tree::default();
        let mut a = exec("e1", "", 1, "/usr/bin/python3", "2026-11-22T10:00:00Z");
        let mut b = exec("e2", "e1", 2, "/bin/bash", "2026-11-22T10:00:01Z");
        let mut c = exec("e3", "e2", 3, "/usr/bin/curl", "2026-11-22T10:00:02Z");
        assert!(tree.observe(&mut a));
        assert!(tree.observe(&mut b));
        assert!(tree.observe(&mut c));
        assert_eq!(a.process.depth, 0);
        assert_eq!(b.process.depth, 1);
        assert_eq!(c.process.depth, 2);
        assert_eq!(c.process.parent_binary, "bash");
        assert_eq!(b.process.parent_binary, "python3");
        assert_eq!(a.process.parent_binary, "unknown");
    }

    #[test]
    fn dedups_identical_events() {
        let mut tree = Tree::default();
        let mut a = exec("e1", "", 1, "/bin/bash", "2026-11-22T10:00:00Z");
        let mut dup = a.clone();
        assert!(tree.observe(&mut a));
        assert!(!tree.observe(&mut dup));
        assert_eq!(tree.counters.deduped, 1);
        assert_eq!(tree.counters.emitted, 1);
    }

    #[test]
    fn filters_execve_credential_noise_but_keeps_real_changes() {
        let mut tree = Tree::default();
        let mut parent = exec("e1", "", 1, "/usr/bin/tar", "2026-11-22T10:00:00Z");
        tree.observe(&mut parent);
        // 瞬态 exec_id 的 commit_creds(parent 已知、同 binary)→ 噪声过滤
        let mut noise = {
            let raw = json!({"process_kprobe": {
                "process": {"exec_id": "e-transient", "parent_exec_id": "e1",
                            "pid": 2, "binary": "/usr/bin/tar"},
                "function_name": "commit_creds", "args": []
            }, "time": "2026-11-22T10:00:00.001Z"});
            normalize(&raw, "c").unwrap()
        };
        assert!(!tree.observe(&mut noise));
        assert_eq!(tree.counters.exec_cred_noise, 1);
        // 进程生存期内的 capability_change(exec_id 已知)→ 保留
        let mut real = {
            let raw = json!({"process_kprobe": {
                "process": {"exec_id": "e1", "parent_exec_id": "",
                            "pid": 1, "binary": "/usr/bin/tar"},
                "function_name": "commit_creds", "args": []
            }, "time": "2026-11-22T10:00:05Z"});
            normalize(&raw, "c").unwrap()
        };
        assert!(tree.observe(&mut real));
    }

    #[test]
    fn dedups_same_exec_across_policies_with_different_timestamps() {
        let mut tree = Tree::default();
        let mut a = exec("e1", "", 1, "/bin/bash", "2026-11-22T10:00:00.000Z");
        // 同一 exec 被另一个 policy 观测,时间戳差 50µs,event_id 不同
        let mut b = exec("e1", "", 1, "/bin/bash", "2026-11-22T10:00:00.00005Z");
        assert_ne!(a.event_id, b.event_id);
        assert!(tree.observe(&mut a));
        assert!(!tree.observe(&mut b));
        assert_eq!(tree.counters.deduped, 1);
    }

    #[test]
    fn exit_closes_state_and_pid_reuse_is_isolated() {
        let mut tree = Tree::default();
        let mut a = exec("e1", "", 42, "/bin/bash", "2026-11-22T10:00:00Z");
        tree.observe(&mut a);
        let mut exit = {
            let raw = json!({"process_exit": {"process": {
                "exec_id": "e1", "parent_exec_id": "", "pid": 42, "binary": "/bin/bash"
            }}, "time": "2026-11-22T10:00:10Z"});
            normalize(&raw, "c").unwrap()
        };
        tree.observe(&mut exit);
        assert!(!tree.nodes.get("e1").unwrap().alive);
        // PID 重用:同 pid 新 exec_id,独立节点、独立序列。
        let mut b = exec("e2", "", 42, "/bin/sh", "2026-11-22T10:00:11Z");
        tree.observe(&mut b);
        assert!(tree.nodes.get("e2").unwrap().alive);
        assert_eq!(tree.nodes.get("e1").unwrap().event_count, 2);
        assert_eq!(tree.nodes.get("e2").unwrap().event_count, 1);
    }

    #[test]
    fn flags_late_events_beyond_window() {
        let mut tree = Tree::default();
        let mut a = exec("e1", "", 1, "/bin/bash", "2026-11-22T10:00:00Z");
        tree.observe(&mut a);
        let mut on_time = kprobe("e1", "sys_openat", "/app/x", "2026-11-22T10:00:10Z");
        tree.observe(&mut on_time);
        assert!(!on_time.late);
        // 比 last_ts 早 6s > 5s 窗口 → late;早 3s 在窗口内 → 不标。
        let mut late = kprobe("e1", "sys_openat", "/app/y", "2026-11-22T10:00:04Z");
        tree.observe(&mut late);
        assert!(late.late);
        let mut within = kprobe("e1", "sys_openat", "/app/z", "2026-11-22T10:00:07.5Z");
        tree.observe(&mut within);
        assert!(!within.late);
        assert_eq!(tree.counters.late, 1);
    }

    #[test]
    fn parent_arriving_later_still_links() {
        let mut tree = Tree::default();
        let mut child = exec("e2", "e1", 2, "/bin/bash", "2026-11-22T10:00:01Z");
        tree.observe(&mut child);
        let mut parent = exec("e1", "", 1, "/usr/bin/python3", "2026-11-22T10:00:00Z");
        tree.observe(&mut parent);
        assert_eq!(tree.depth("e2"), 1);
        assert!(tree.nodes.get("e1").unwrap().children.contains(&"e2".to_string()));
    }
}