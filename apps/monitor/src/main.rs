//! CLI: `onelayer-monitor once|run --config <file>` и `verify-evidence --dir <dir>`.

use onelayer_monitor::chain::RpcChain;
use onelayer_monitor::evidence::replay;
use onelayer_monitor::monitor::{load_keys, Config, Monitor};
use onelayer_monitor::source::PgSource;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

fn usage() -> ExitCode {
    eprintln!("usage: onelayer-monitor once|run --config <file> [--cycles N]\n       onelayer-monitor verify-evidence --dir <dir>");
    ExitCode::from(64)
}

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn start(config_path: &str) -> Result<(Config, Monitor<RpcChain, PgSource>), String> {
    let config = Config::load(&PathBuf::from(config_path))?;
    let trust = config.trust()?;
    let keys = load_keys(&config.keys_file)?;
    let chain = RpcChain::new(&config.rpc_url)?;
    let source = PgSource::connect(&config.source_dsn)?;
    let monitor = Monitor::new(
        trust,
        keys,
        config.policy.clone(),
        chain,
        source,
        &config.evidence_dir,
    )?;
    Ok((config, monitor))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(command) = args.first().cloned() else {
        return usage();
    };
    match command.as_str() {
        "verify-evidence" => {
            let Some(dir) = arg(&args, "--dir") else {
                return usage();
            };
            match replay(&PathBuf::from(dir).join("evidence.jsonl")) {
                Ok(r) => {
                    println!(
                        "{}",
                        serde_json::json!({"ok": true, "entries": r.entries, "head": r.head, "activeFindings": r.active.len()})
                    );
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    println!("{}", serde_json::json!({"ok": false, "error": e}));
                    ExitCode::from(2)
                }
            }
        }
        "once" | "run" => {
            let Some(path) = arg(&args, "--config") else {
                return usage();
            };
            let (config, mut monitor) = match start(&path) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("monitor start refused: {e}");
                    return ExitCode::from(1);
                }
            };
            let cycles: Option<u64> = if command == "once" {
                Some(1)
            } else {
                arg(&args, "--cycles").and_then(|c| c.parse().ok())
            };
            let mut done = 0u64;
            let mut last_active;
            loop {
                match monitor.cycle() {
                    Ok(report) => {
                        last_active = report.active;
                        println!(
                            "{}",
                            serde_json::json!({
                                "cycle": done + 1, "chainSlot": report.chain_slot, "verifiedBatches": report.verified_batches,
                                "newFindings": report.new_findings.iter().map(|f| f.kind).collect::<Vec<_>>(),
                                "active": report.active, "cleared": report.cleared, "durationMs": report.duration_ms,
                            })
                        );
                    }
                    Err(e) => {
                        eprintln!("monitor cycle failed (evidence write): {e}");
                        return ExitCode::from(1);
                    }
                }
                done += 1;
                if cycles.is_some_and(|n| done >= n) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(config.poll_interval_ms));
            }
            if last_active > 0 {
                ExitCode::from(3)
            } else {
                ExitCode::SUCCESS
            }
        }
        _ => usage(),
    }
}
