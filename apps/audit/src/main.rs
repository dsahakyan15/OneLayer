//! CLI: `onelayer-audit serve|issue-capability|verify-sink|rebuild`.

use onelayer_audit::capability::{CapOp, CapabilityKey, CapabilityPayload};
use onelayer_audit::config::AuditConfig;
use onelayer_audit::server;
use onelayer_audit::sink::ProtectedSink;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::process::ExitCode;

fn usage() -> ExitCode {
    eprintln!(
        "usage:\n  onelayer-audit serve --config <file>\n  onelayer-audit issue-capability --config <file> --op append|read|export|rebuild|status --subject <s> [--source <s>]... [--registry <r>]... [--device <d>] [--expires-ms <n>] [--out <file>]\n  onelayer-audit verify-sink --config <file>\n  onelayer-audit rebuild --config <file> --source <s>"
    );
    ExitCode::from(64)
}

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn args_all(args: &[String], name: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == name {
            if let Some(value) = args.get(i + 1) {
                out.push(value.clone());
            }
        }
        i += 1;
    }
    out
}

fn now_unix_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(command) = args.first().cloned() else {
        return usage();
    };
    let Some(config_path) = arg(&args, "--config") else {
        return usage();
    };
    let config = match AuditConfig::load(&PathBuf::from(&config_path)) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("audit config refused: {e}");
            return ExitCode::from(1);
        }
    };
    match command.as_str() {
        "serve" => match server::serve(config) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("audit serve failed: {e}");
                ExitCode::from(1)
            }
        },
        "issue-capability" => {
            let (Some(op), Some(subject)) = (arg(&args, "--op"), arg(&args, "--subject")) else {
                return usage();
            };
            let op = match CapOp::parse(&op) {
                Ok(op) => op,
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::from(1);
                }
            };
            let key = match CapabilityKey::load(&config.capability_key_file) {
                Ok(key) => key,
                Err(e) => {
                    eprintln!("capability key refused: {e}");
                    return ExitCode::from(1);
                }
            };
            let expires_ms: i64 = arg(&args, "--expires-ms")
                .and_then(|v| v.parse().ok())
                .unwrap_or(86_400_000);
            let payload = CapabilityPayload {
                v: 1,
                op,
                sources: args_all(&args, "--source"),
                registries: args_all(&args, "--registry"),
                subject,
                device: arg(&args, "--device").unwrap_or_default(),
                expires_at_ms: now_unix_ms() + expires_ms,
                nonce: format!("{}-{}", now_unix_ms(), std::process::id()),
            };
            let token = key.issue(&payload);
            match arg(&args, "--out") {
                Some(path) => {
                    let path = PathBuf::from(path);
                    let mut file = match std::fs::OpenOptions::new()
                        .create(true)
                        .write(true)
                        .truncate(true)
                        .mode(0o600)
                        .open(&path)
                    {
                        Ok(file) => file,
                        Err(e) => {
                            eprintln!("capability out {}: {e}", path.display());
                            return ExitCode::from(1);
                        }
                    };
                    if let Err(e) = writeln!(file, "{token}") {
                        eprintln!("capability out: {e}");
                        return ExitCode::from(1);
                    }
                    println!(
                        "{}",
                        serde_json::json!({"ok": true, "out": path.display().to_string()})
                    );
                }
                None => println!("{token}"),
            }
            ExitCode::SUCCESS
        }
        "verify-sink" => match ProtectedSink::open(&config.state_dir) {
            Ok(sink) => {
                let status = sink.status();
                let ok = status.tail_rollback.is_none();
                println!("{}", serde_json::json!({"ok": ok, "destination": status}));
                if ok {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::from(2)
                }
            }
            Err(e) => {
                println!("{}", serde_json::json!({"ok": false, "error": e}));
                ExitCode::from(2)
            }
        },
        "rebuild" => {
            let Some(source) = arg(&args, "--source") else {
                return usage();
            };
            match server::rebuild_blocking(config, &source) {
                Ok(state) => {
                    println!("{}", serde_json::json!({"ok": true, "rebuild": state}));
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    println!("{}", serde_json::json!({"ok": false, "error": e}));
                    ExitCode::from(2)
                }
            }
        }
        _ => usage(),
    }
}
