//! ABIP Rust Collector:Tetragon JSONL → 统一事件 JSONL + 进程树快照。
//! POC 用文件/stdin 回放;接真实 Tetragon 时 `tetra getevents -o json` 直接管道进来。

mod normalize;
mod tree;

use std::env;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut input = "-".to_string();
    let mut output = "-".to_string();
    let mut tree_out = String::new();
    let mut cluster_id = "cluster-01".to_string();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--input" => { input = args[i + 1].clone(); i += 2; }
            "--output" => { output = args[i + 1].clone(); i += 2; }
            "--tree-out" => { tree_out = args[i + 1].clone(); i += 2; }
            "--cluster-id" => { cluster_id = args[i + 1].clone(); i += 2; }
            other => { eprintln!("unknown arg: {other}"); std::process::exit(2); }
        }
    }

    let reader: Box<dyn BufRead> = if input == "-" {
        Box::new(BufReader::new(io::stdin()))
    } else {
        Box::new(BufReader::new(File::open(&input).unwrap_or_else(|e| {
            eprintln!("cannot open input {input}: {e}");
            std::process::exit(1);
        })))
    };
    let mut writer: Box<dyn Write> = if output == "-" {
        Box::new(io::stdout())
    } else {
        Box::new(File::create(&output).unwrap_or_else(|e| {
            eprintln!("cannot create output {output}: {e}");
            std::process::exit(1);
        }))
    };

    let mut tree = tree::Tree::default();
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => { eprintln!("read error: {e}"); break; }
        };
        if line.trim().is_empty() {
            continue;
        }
        let raw: serde_json::Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => { tree.counters.invalid += 1; continue; }
        };
        let mut ev = match normalize::normalize(&raw, &cluster_id) {
            Some(ev) => ev,
            None => { tree.counters.invalid += 1; continue; }
        };
        if !tree.observe(&mut ev) {
            continue;
        }
        if let Err(e) = writeln!(writer, "{}", serde_json::to_string(&ev).unwrap()) {
            eprintln!("write error: {e}");
            std::process::exit(1);
        }
    }

    if !tree_out.is_empty() {
        let snap = serde_json::to_string_pretty(&tree.snapshot()).unwrap();
        if let Err(e) = std::fs::write(&tree_out, snap) {
            eprintln!("cannot write tree snapshot: {e}");
        }
    }
    let c = &tree.counters;
    eprintln!(
        "collector: received={} invalid={} deduped={} late={} emitted={}",
        c.received, c.invalid, c.deduped, c.late, c.emitted
    );
}