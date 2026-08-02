//! Turns the JSONL evidence of a synthetic soak run into the Gate C verdict.
//!
//! Exit codes: 0 passed, 1 evidence unreadable, 2 invariant violated, 3 clean
//! but shorter than the required 72 hours.
use onelayer_pilot_pipeline::soak::{evaluate, parse_records, Verdict, REQUIRED_RUN_SECONDS};
use std::{env, fs, process::ExitCode};

fn main() -> ExitCode {
    let path = match env::args().nth(1) {
        Some(path) => path,
        None => {
            eprintln!("usage: soak_report <evidence.jsonl>");
            return ExitCode::from(1);
        }
    };
    let contents = match fs::read_to_string(&path) {
        Ok(contents) => contents,
        Err(error) => {
            eprintln!("cannot read {path}: {error}");
            return ExitCode::from(1);
        }
    };
    let records = match parse_records(&contents) {
        Ok(records) => records,
        Err(error) => {
            eprintln!("evidence is malformed: {error}");
            return ExitCode::from(1);
        }
    };
    let report = evaluate(&records);
    println!(
        "{}",
        serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".into())
    );
    match report.verdict {
        Verdict::Passed => ExitCode::SUCCESS,
        Verdict::Failed => {
            eprintln!("Gate C soak failed: {} finding(s)", report.findings.len());
            ExitCode::from(2)
        }
        Verdict::Incomplete { observed_seconds } => {
            eprintln!(
                "Gate C soak is clean but covers {observed_seconds}s of the required {REQUIRED_RUN_SECONDS}s"
            );
            ExitCode::from(3)
        }
    }
}
