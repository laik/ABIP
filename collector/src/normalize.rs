//! Tetragon 原始 JSON → 统一事件格式(contracts/behavior-event.schema.json)。
//! 只做身份/类别/资源提取;模型特征类别化统一在 Python Feature Engine,这里不做。

use serde::Serialize;
use serde_json::Value;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

#[derive(Serialize, Clone, Debug)]
pub struct ProcessInfo {
    pub exec_id: String,
    pub parent_exec_id: String,
    pub pid: i64,
    pub binary: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub parent_binary: String,
    pub depth: i64,
    pub uid: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub cwd: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub start_time: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct EventInfo {
    pub category: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub operation: String,
    pub resource_type: String,
    pub resource: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct Event {
    pub event_id: String,
    pub event_time: String,
    pub cluster_id: String,
    pub tenant_id: String,
    pub namespace: String,
    pub pod_uid: String,
    pub container_id: String,
    pub process: ProcessInfo,
    pub event: EventInfo,
    pub late: bool,
    pub raw: Value,
}

fn s(v: &Value, key: &str) -> String {
    v.get(key).and_then(Value::as_str).unwrap_or("").to_string()
}

fn basename(path: &str) -> String {
    path.rsplit('/').next().unwrap_or(path).to_string()
}

/// Tetragon kprobe args 里找第一个 string_arg(如 sys_openat 的 filename)。
fn first_string_arg(args: &Value) -> String {
    if let Some(arr) = args.as_array() {
        for a in arr {
            if let Some(v) = a.get("string_arg").and_then(Value::as_str) {
                return v.to_string();
            }
        }
    }
    String::new()
}

/// tcp_connect 的 sock_arg → "daddr:dport"。
fn sock_dest(args: &Value) -> String {
    if let Some(arr) = args.as_array() {
        for a in arr {
            if let Some(sock) = a.get("sock_arg") {
                let daddr = s(sock, "daddr");
                if !daddr.is_empty() {
                    let dport = sock.get("dport").and_then(Value::as_i64).unwrap_or(0);
                    return format!("{daddr}:{dport}");
                }
            }
        }
    }
    String::new()
}

fn kprobe_mapping(function: &str, args: &Value) -> EventInfo {
    let (category, kind, operation, resource_type, resource) = match function {
        "sys_openat" | "do_sys_openat2" | "security_file_open" => {
            ("file", "file_open", "open", "path", first_string_arg(args))
        }
        "sys_write" | "vfs_write" => ("file", "file_write", "write", "path", first_string_arg(args)),
        "tcp_connect" | "inet_stream_connect" | "sys_connect" => {
            let mut dest = sock_dest(args);
            if dest.is_empty() {
                dest = first_string_arg(args);
            }
            ("network", "network_connect", "connect", "socket", dest)
        }
        "commit_creds" | "sys_setuid" | "sys_setreuid" => {
            ("security", "capability_change", "credential_change", "credential", String::new())
        }
        _ => ("process", "unknown", "unknown", "unknown", String::new()),
    };
    EventInfo {
        category: category.into(),
        kind: kind.into(),
        operation: operation.into(),
        resource_type: resource_type.into(),
        resource,
    }
}

/// 规范化一条 Tetragon JSON 事件;无法识别的 payload 返回 None。
pub fn normalize(raw: &Value, cluster_id: &str) -> Option<Event> {
    let (payload, event_info) = if let Some(p) = raw.get("process_exec") {
        let binary = s(p.get("process")?, "binary");
        (
            p,
            EventInfo {
                category: "process".into(),
                kind: "process_exec".into(),
                operation: "execute".into(),
                resource_type: "binary".into(),
                resource: binary,
            },
        )
    } else if let Some(p) = raw.get("process_exit") {
        (
            p,
            EventInfo {
                category: "process".into(),
                kind: "process_exit".into(),
                operation: "exit".into(),
                resource_type: "none".into(),
                resource: String::new(),
            },
        )
    } else if let Some(p) = raw.get("process_kprobe") {
        let fname = s(p, "function_name");
        // 真实 Tetragon 上报解析后的符号名,如 __x64_sys_openat / __arm64_sys_openat。
        let function = fname
            .strip_prefix("__x64_")
            .or_else(|| fname.strip_prefix("__arm64_"))
            .or_else(|| fname.strip_prefix("__ia32_"))
            .unwrap_or(&fname);
        let args = p.get("args").cloned().unwrap_or(Value::Null);
        (p, kprobe_mapping(function, &args))
    } else {
        return None;
    };

    let proc = payload.get("process")?;
    let exec_id = s(proc, "exec_id");
    if exec_id.is_empty() {
        return None;
    }
    let pod = proc.get("pod").cloned().unwrap_or(Value::Null);
    let namespace = s(&pod, "namespace");
    // Tetragon pod 对象不一定带 uid;缺失时用 namespace/name 作为稳定身份。
    let pod_uid = {
        let uid = s(&pod, "uid");
        if uid.is_empty() {
            format!("{}/{}", namespace, s(&pod, "name"))
        } else {
            uid
        }
    };
    let container_id = {
        let id = s(&proc.get("container").cloned().unwrap_or(Value::Null), "id");
        id.split("://").last().unwrap_or("").to_string()
    };
    let event_time = s(raw, "time");
    let binary_full = s(proc, "binary");

    let mut hasher = DefaultHasher::new();
    (
        &exec_id,
        &event_info.kind,
        &event_time,
        &event_info.resource,
    )
        .hash(&mut hasher);
    let event_id = format!("evt-{:016x}", hasher.finish());

    Some(Event {
        event_id,
        event_time,
        cluster_id: cluster_id.into(),
        tenant_id: if namespace.is_empty() { "default".into() } else { namespace.clone() },
        namespace,
        pod_uid,
        container_id,
        process: ProcessInfo {
            exec_id,
            parent_exec_id: s(proc, "parent_exec_id"),
            pid: proc.get("pid").and_then(Value::as_i64).unwrap_or(0),
            binary: basename(&binary_full),
            parent_binary: String::new(),
            depth: 0,
            uid: proc.get("uid").and_then(Value::as_i64).unwrap_or(-1),
            cwd: s(proc, "cwd"),
            start_time: s(proc, "start_time"),
        },
        event: event_info,
        late: false,
        raw: raw.clone(),
    })
}

/// 解析 RFC3339(Tetragon 输出 UTC "Z",兼容 ±HH:MM 偏移)为 epoch 秒。
pub fn parse_time(t: &str) -> Option<f64> {
    let b = t.as_bytes();
    if b.len() < 19 {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<i64> { t.get(r)?.parse().ok() };
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, sec) = (num(11..13)?, num(14..16)?, num(17..19)?);
    let mut frac = 0.0;
    let mut rest = &t[19..];
    if let Some(stripped) = rest.strip_prefix('.') {
        let digits: String = stripped.chars().take_while(|c| c.is_ascii_digit()).collect();
        frac = format!("0.{digits}").parse().unwrap_or(0.0);
        rest = &stripped[digits.len()..];
    }
    let offset = match rest {
        "Z" | "" => 0,
        _ if rest.len() == 6 && (rest.starts_with('+') || rest.starts_with('-')) => {
            let oh: i64 = rest[1..3].parse().ok()?;
            let om: i64 = rest[4..6].parse().ok()?;
            let sign = if rest.starts_with('-') { -1 } else { 1 };
            sign * (oh * 3600 + om * 60)
        }
        _ => return None,
    };
    // days from civil (Howard Hinnant 算法),避免引入 chrono。
    let y = if mo <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    Some((days * 86400 + h * 3600 + mi * 60 + sec - offset) as f64 + frac)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn exec_event() -> Value {
        json!({
            "process_exec": {
                "process": {
                    "exec_id": "exec-001", "parent_exec_id": "exec-000", "pid": 1234,
                    "uid": 1000, "cwd": "/workspace", "binary": "/usr/bin/python3",
                    "start_time": "2026-11-22T10:00:00Z",
                    "pod": {"namespace": "tenant-a", "name": "agent-1"},
                    "container": {"id": "docker://abc123"}
                }
            },
            "time": "2026-11-22T10:00:00.5Z", "node_name": "n1"
        })
    }

    #[test]
    fn normalizes_exec() {
        let ev = normalize(&exec_event(), "c1").unwrap();
        assert_eq!(ev.process.binary, "python3");
        assert_eq!(ev.tenant_id, "tenant-a");
        assert_eq!(ev.container_id, "abc123");
        assert_eq!(ev.pod_uid, "tenant-a/agent-1");
        assert_eq!(ev.event.kind, "process_exec");
        assert_eq!(ev.event.resource, "/usr/bin/python3");
    }

    #[test]
    fn normalizes_openat_kprobe() {
        let raw = json!({"process_kprobe": {
            "process": {"exec_id": "e1", "binary": "/bin/cat", "pid": 1},
            "function_name": "sys_openat",
            "args": [{"int_arg": -100}, {"string_arg": "/etc/shadow"}, {"int_arg": 0}]
        }, "time": "2026-11-22T10:00:01Z"});
        let ev = normalize(&raw, "c1").unwrap();
        assert_eq!(ev.event.kind, "file_open");
        assert_eq!(ev.event.category, "file");
        assert_eq!(ev.event.resource, "/etc/shadow");
    }

    #[test]
    fn normalizes_tcp_connect() {
        let raw = json!({"process_kprobe": {
            "process": {"exec_id": "e1", "binary": "/usr/bin/curl", "pid": 1},
            "function_name": "tcp_connect",
            "args": [{"sock_arg": {"daddr": "203.0.113.9", "dport": 443}}]
        }, "time": "2026-11-22T10:00:01Z"});
        let ev = normalize(&raw, "c1").unwrap();
        assert_eq!(ev.event.kind, "network_connect");
        assert_eq!(ev.event.resource, "203.0.113.9:443");
    }

    #[test]
    fn strips_arch_prefix_from_real_tetragon_symbols() {
        let raw = json!({"process_kprobe": {
            "process": {"exec_id": "e1", "binary": "/bin/cat", "pid": 1},
            "function_name": "__x64_sys_openat",
            "args": [{"string_arg": "/etc/hostname"}]
        }, "time": "2026-11-22T10:00:01Z"});
        let ev = normalize(&raw, "c1").unwrap();
        assert_eq!(ev.event.kind, "file_open");
        assert_eq!(ev.event.resource, "/etc/hostname");
    }

    #[test]
    fn unknown_function_maps_to_unknown() {
        let raw = json!({"process_kprobe": {
            "process": {"exec_id": "e1", "binary": "/bin/x", "pid": 1},
            "function_name": "some_other_hook", "args": []
        }, "time": "2026-11-22T10:00:01Z"});
        assert_eq!(normalize(&raw, "c1").unwrap().event.kind, "unknown");
    }

    #[test]
    fn rejects_garbage() {
        assert!(normalize(&json!({"foo": 1}), "c1").is_none());
        assert!(normalize(&json!({"process_exec": {"process": {}}}), "c1").is_none());
    }

    #[test]
    fn parses_times() {
        let t = parse_time("2026-11-22T10:00:00Z").unwrap();
        assert_eq!(parse_time("2026-11-22T10:00:00.5Z").unwrap(), t + 0.5);
        assert_eq!(parse_time("2026-11-22T11:00:00+01:00").unwrap(), t);
        assert_eq!(parse_time("2026-11-22T09:00:00-01:00").unwrap(), t);
        assert!(parse_time("garbage").is_none());
        // 与已知 epoch 对照:2026-11-22T10:00:00Z
        assert_eq!(t, 1795341600.0);
    }
}