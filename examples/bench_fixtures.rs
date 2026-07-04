//! Score the generated fixture corpus and report precision / recall.
//!
//! Run: `cargo run --example bench_fixtures -- ./fixtures`
//!
//! Reads `<dir>/labels.jsonl`, runs `analyze_image` on each, and treats
//! `should_flag()` as the positive prediction. Prints a confusion matrix and
//! P/R/F1 — the same scoring shape the split-brain-harness benches use.

use deobfuscate_vision::analyze_image;
use std::fs;
use std::path::PathBuf;

fn main() {
    let dir = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("fixtures"));
    let labels = fs::read_to_string(dir.join("labels.jsonl")).expect("run gen_fixtures first");

    // Two honest metrics, matching the crate's documented scope:
    //   flag detection  — obfuscated attacks the crate detects on its own.
    //   extraction cover — plain attacks it surfaces (as a channel) for Stage-1.
    let (mut flag_tp, mut flag_fn) = (0, 0); // expect=flag
    let (mut extract_ok, mut extract_miss) = (0, 0); // expect=extract
    let (mut clean_ok, mut clean_fp) = (0, 0); // expect=clean
    let mut errors = 0;

    for line in labels.lines().filter(|l| !l.trim().is_empty()) {
        let path = field(line, "path");
        let expect = field(line, "expect");

        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(_) => {
                errors += 1;
                continue;
            }
        };
        let report = match analyze_image(&bytes) {
            Ok(r) => r,
            Err(_) => {
                errors += 1;
                continue;
            }
        };

        match expect.as_str() {
            "flag" => {
                if report.should_flag() {
                    flag_tp += 1;
                } else {
                    flag_fn += 1;
                    println!("  MISS (obfuscated attack not flagged): {path}");
                }
            }
            "extract" => {
                // Success = the payload was surfaced as a channel for Stage-1,
                // even though it is (correctly) not flagged as obfuscated.
                if report.has_findings() {
                    extract_ok += 1;
                } else {
                    extract_miss += 1;
                    println!("  MISS (plain injection not extracted): {path}");
                }
            }
            "clean" => {
                if report.should_flag() {
                    clean_fp += 1;
                    println!("  FP (benign flagged): {path}  [{}]", report.summary());
                } else {
                    clean_ok += 1;
                }
            }
            other => println!("  ?? unknown expect={other} for {path}"),
        }
    }

    let flag_recall = ratio(flag_tp, flag_tp + flag_fn);
    let extract_cover = ratio(extract_ok, extract_ok + extract_miss);
    let clean_rate = ratio(clean_ok, clean_ok + clean_fp);

    println!("\n─── deobfuscate-vision fixture bench ───");
    println!("obfuscation detection : {flag_tp}/{}  (recall {flag_recall:.2})", flag_tp + flag_fn);
    println!("extraction coverage   : {extract_ok}/{}  (cover  {extract_cover:.2})", extract_ok + extract_miss);
    println!("benign specificity    : {clean_ok}/{}  (clean  {clean_rate:.2})", clean_ok + clean_fp);
    println!("errors={errors}");
}

fn ratio(num: usize, den: usize) -> f32 {
    if den == 0 {
        0.0
    } else {
        num as f32 / den as f32
    }
}

/// Minimal JSON string-field extractor (fixtures are flat, ASCII-keyed).
fn field(line: &str, key: &str) -> String {
    let pat = format!("\"{key}\":\"");
    let Some(start) = line.find(&pat) else {
        return String::new();
    };
    let rest = &line[start + pat.len()..];
    let end = rest.find('"').unwrap_or(rest.len());
    rest[..end].to_string()
}
