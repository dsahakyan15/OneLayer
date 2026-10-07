//! HTTP API audit-сервиса (loopback, JSON). Capability обязательна на каждом
//! endpoint (default deny); scope проверяется по источнику и реестру. Rebuild
//! идёт только из проверенного destination и durable-состояния в PG.

use crate::capability::{authorize, CapOp, CapabilityKey};
use crate::config::AuditConfig;
use crate::event::AuditEvent;
use crate::projection::{Projector, RebuildState, RebuildStatus};
use crate::sink::{Checkpoint, ProtectedSink, SearchQuery};
use serde_json::{json, Value as Json};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_BODY_BYTES: usize = 1024 * 1024;

pub struct AppState {
    pub sink: Mutex<ProtectedSink>,
    pub key: CapabilityKey,
    pub config: AuditConfig,
    pub rebuild: Mutex<RebuildState>,
    pub rebuild_running: AtomicBool,
}

impl AppState {
    pub fn new(config: AuditConfig) -> Result<Arc<Self>, String> {
        let sink = ProtectedSink::open(&config.state_dir)?;
        let key = CapabilityKey::load(&config.capability_key_file)?;
        let rebuild = match &config.projection_dsn {
            Some(dsn) => match Projector::connect(dsn) {
                Ok(mut projector) => projector
                    .state()
                    .unwrap_or_else(|_| RebuildState::unknown()),
                Err(_) => RebuildState::unknown(),
            },
            None => RebuildState::unknown(),
        };
        Ok(Arc::new(Self {
            sink: Mutex::new(sink),
            key,
            config,
            rebuild: Mutex::new(rebuild),
            rebuild_running: AtomicBool::new(false),
        }))
    }
}

pub fn now_unix_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

struct Request {
    method: String,
    path: String,
    body: Vec<u8>,
    bearer: Option<String>,
}

fn read_request<R: Read>(stream: &mut R) -> Result<Request, String> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        let n = stream.read(&mut chunk).map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            return Err("connection closed before headers".into());
        }
        buffer.extend_from_slice(&chunk[..n]);
        if let Some(pos) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos;
        }
        if buffer.len() > MAX_HEADER_BYTES {
            return Err("headers too large".into());
        }
    };
    let head = String::from_utf8(buffer[..header_end].to_vec())
        .map_err(|_| "non-UTF-8 headers".to_string())?;
    let mut lines = head.split("\r\n");
    let request_line = lines.next().ok_or("empty request line")?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().ok_or("no method")?.to_string();
    let path = parts.next().ok_or("no path")?.to_string();
    let mut content_length: Option<usize> = None;
    let mut bearer = None;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim().to_ascii_lowercase();
            let value = value.trim();
            if name == "content-length" {
                content_length = Some(value.parse().map_err(|_| "bad content-length")?);
            } else if name == "authorization" {
                bearer = value
                    .strip_prefix("Bearer ")
                    .map(|token| token.trim().to_string());
            }
        }
    }
    let length = content_length.unwrap_or(0);
    if length > MAX_BODY_BYTES {
        return Err("body too large".into());
    }
    let mut body = buffer[header_end + 4..].to_vec();
    while body.len() < length {
        let n = stream
            .read(&mut chunk)
            .map_err(|e| format!("read body: {e}"))?;
        if n == 0 {
            return Err("truncated body".into());
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(length);
    Ok(Request {
        method,
        path,
        body,
        bearer,
    })
}

fn write_response(stream: &mut TcpStream, status: u16, body: &Json) -> Result<(), String> {
    let bytes = serde_json::to_vec(body).expect("serializable");
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        422 => "Unprocessable Entity",
        500 => "Internal Server Error",
        _ => "Error",
    };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        bytes.len()
    );
    stream
        .write_all(head.as_bytes())
        .and_then(|_| stream.write_all(&bytes))
        .map_err(|e| format!("write: {e}"))
}

fn error(status: u16, message: &str) -> (u16, Json) {
    let (code, detail) = match message.split_once(": ") {
        Some((code, detail)) => (code, detail),
        None => (message, ""),
    };
    (
        status,
        json!({"ok": false, "error": code, "detail": detail}),
    )
}

fn parse_json(body: &[u8]) -> Result<Json, String> {
    if body.is_empty() {
        return Err("AUDIT_EVENT_INVALID: empty body".into());
    }
    serde_json::from_slice(body).map_err(|e| format!("AUDIT_EVENT_INVALID: {e}"))
}

fn require_token(
    state: &AppState,
    request: &Request,
) -> Result<crate::capability::CapabilityPayload, (u16, Json)> {
    let Some(token) = request.bearer.as_deref() else {
        return Err(error(
            401,
            "AUDIT_CAPABILITY_REQUIRED: missing bearer token",
        ));
    };
    state.key.verify(token).map_err(|e| error(401, &e))
}

fn scope_error(e: String) -> (u16, Json) {
    if e.starts_with("AUDIT_CAPABILITY_SCOPE") {
        error(403, &e)
    } else {
        error(401, &e)
    }
}

fn require_cap(
    state: &AppState,
    request: &Request,
    op: CapOp,
    source: Option<&str>,
    registry: Option<&str>,
) -> Result<crate::capability::CapabilityPayload, (u16, Json)> {
    let payload = require_token(state, request)?;
    authorize(&payload, op, source, registry, now_unix_ms()).map_err(scope_error)?;
    Ok(payload)
}

fn config_allows(config: &AuditConfig, source: &str, registry: &str) -> Result<(), String> {
    if !config.sources.is_empty() && !config.sources.iter().any(|s| s == source) {
        return Err(format!(
            "AUDIT_CAPABILITY_SCOPE: source {source} is not enabled for this service"
        ));
    }
    if !config.registries.is_empty() && !config.registries.iter().any(|r| r == registry) {
        return Err(format!(
            "AUDIT_CAPABILITY_SCOPE: registry {registry} is not enabled for this service"
        ));
    }
    Ok(())
}

fn dispatch(state: &Arc<AppState>, request: &Request) -> (u16, Json) {
    let result = match (request.method.as_str(), request.path.as_str()) {
        ("POST", "/v1/append") => handle_append(state, request),
        ("GET", "/v1/status") => handle_status(state, request),
        ("POST", "/v1/search") => handle_search(state, request),
        ("POST", "/v1/export") => handle_export(state, request),
        ("POST", "/v1/bundle/verify") => handle_bundle_verify(state, request),
        ("POST", "/v1/rebuild") => handle_rebuild(state, request),
        ("GET", "/v1/rebuild/status") => handle_rebuild_status(state, request),
        _ => Err(error(404, "AUDIT_ROUTE_NOT_FOUND: unknown route")),
    };
    result.unwrap_or_else(|e| e)
}

fn handle_append(state: &Arc<AppState>, request: &Request) -> Result<(u16, Json), (u16, Json)> {
    // Default deny first: unauthenticated requests never reach event parsing.
    let capability = require_token(state, request)?;
    let body = parse_json(&request.body).map_err(|e| error(422, &e))?;
    let event: AuditEvent = serde_json::from_value(body["event"].clone())
        .map_err(|e| error(422, &format!("AUDIT_EVENT_INVALID: {e}")))?;
    authorize(
        &capability,
        CapOp::Append,
        Some(&event.source),
        Some(&event.registry_id),
        now_unix_ms(),
    )
    .map_err(scope_error)?;
    config_allows(&state.config, &event.source, &event.registry_id).map_err(|e| error(403, &e))?;
    let mut sink = state.sink.lock().expect("sink lock");
    let digest = event.digest();
    match sink.append(event) {
        Ok(outcome) => Ok((
            200,
            json!({
                "ok": true,
                "status": outcome.status,
                "deliverySeq": outcome.delivery_seq,
                "destinationHash": outcome.destination_hash,
                "sourceSequence": outcome.source_sequence,
                "eventDigest": digest,
            }),
        )),
        Err(e) => {
            let status = if e.contains("TAIL_ROLLBACK")
                || e.contains("SEQUENCE_GAP")
                || e.contains("SEQUENCE_CONFLICT")
                || e.contains("EVENT_CONFLICT")
            {
                409
            } else {
                422
            };
            Err(error(status, &e))
        }
    }
}

fn rebuild_json(state: &AppState, sink_head: u64, tail_rollback: bool) -> Json {
    let rebuild = state.rebuild.lock().expect("rebuild lock");
    json!({
        "status": rebuild.status.as_str(),
        "sourceIdentity": rebuild.source_identity,
        "cursorSequence": rebuild.cursor_sequence,
        "headSequence": rebuild.head_sequence,
        "headHash": rebuild.head_hash,
        "floorSequence": rebuild.floor_sequence,
        "error": rebuild.error,
        "projectionStatus": if tail_rollback { "UNKNOWN" } else { rebuild.projection_status(sink_head) },
    })
}

fn handle_status(state: &Arc<AppState>, request: &Request) -> Result<(u16, Json), (u16, Json)> {
    require_cap(state, request, CapOp::Status, None, None)?;
    let sink = state.sink.lock().expect("sink lock");
    let status = sink.status();
    let tail_rollback = status.tail_rollback.is_some();
    let (rebuilding, projection) = {
        let rebuild = state.rebuild.lock().expect("rebuild lock");
        (
            rebuild.status == RebuildStatus::Rebuilding,
            if tail_rollback {
                "UNKNOWN".to_string()
            } else {
                rebuild.projection_status(status.head_seq).to_string()
            },
        )
    };
    let overall = if tail_rollback {
        "TAIL_ROLLBACK"
    } else if rebuilding {
        "REBUILDING"
    } else if state.config.projection_dsn.is_none() {
        // Без projection destination сам является current-источником.
        "CURRENT"
    } else {
        projection.as_str()
    };
    Ok((
        200,
        json!({
            "ok": true,
            "status": overall,
            "destination": status,
            "rebuild": rebuild_json(state, status.head_seq, tail_rollback),
        }),
    ))
}

fn handle_search(state: &Arc<AppState>, request: &Request) -> Result<(u16, Json), (u16, Json)> {
    let capability = require_token(state, request)?;
    let body = parse_json(&request.body).map_err(|e| error(422, &e))?;
    let query = SearchQuery {
        source: body["source"].as_str().map(str::to_string),
        registry_id: body["registryId"].as_str().map(str::to_string),
        action: body["action"].as_str().map(str::to_string),
        actor: body["actor"].as_str().map(str::to_string),
        from_sequence: body["fromSequence"].as_u64(),
        to_sequence: body["toSequence"].as_u64(),
        limit: body["limit"].as_u64().map(|n| n as usize),
    };
    authorize(
        &capability,
        CapOp::Read,
        query.source.as_deref(),
        query.registry_id.as_deref(),
        now_unix_ms(),
    )
    .map_err(scope_error)?;
    if !capability.registries.is_empty() && query.registry_id.is_none() {
        return Err(error(
            403,
            "AUDIT_CAPABILITY_SCOPE: this capability requires an explicit registryId",
        ));
    }
    if !capability.sources.is_empty() && query.source.is_none() {
        return Err(error(
            403,
            "AUDIT_CAPABILITY_SCOPE: this capability requires an explicit source",
        ));
    }
    let sink = state.sink.lock().expect("sink lock");
    if let Some(reason) = sink.tail_rollback() {
        return Err(error(409, reason));
    }
    let events: Vec<Json> = sink
        .search(&query)
        .into_iter()
        .map(|entry| {
            json!({
                "deliverySeq": entry.delivery_seq,
                "destinationHash": entry.hash,
                "eventDigest": entry.event.digest(),
                "event": entry.event,
            })
        })
        .collect();
    let status = sink.status();
    let tail_rollback = status.tail_rollback.is_some();
    Ok((
        200,
        json!({
            "ok": true,
            "events": events,
            "destinationHead": status,
            "rebuild": rebuild_json(state, status.head_seq, tail_rollback),
        }),
    ))
}

fn handle_export(state: &Arc<AppState>, request: &Request) -> Result<(u16, Json), (u16, Json)> {
    let capability = require_token(state, request)?;
    let body = parse_json(&request.body).map_err(|e| error(422, &e))?;
    let registry = body["registryId"]
        .as_str()
        .ok_or_else(|| error(422, "AUDIT_EXPORT_FORBIDDEN: registryId is required"))?
        .to_string();
    authorize(
        &capability,
        CapOp::Export,
        None,
        Some(&registry),
        now_unix_ms(),
    )
    .map_err(scope_error)?;
    let from = body["fromSequence"].as_u64().unwrap_or(1);
    let to = body["toSequence"].as_u64().unwrap_or(u64::MAX);
    let sink = state.sink.lock().expect("sink lock");
    if sink.tail_rollback().is_some() {
        return Err(error(
            409,
            sink.tail_rollback().unwrap_or("AUDIT_SINK_TAIL_ROLLBACK"),
        ));
    }
    let bundle = sink.export(&registry, from, to, &capability.sources);
    Ok((200, json!({"ok": true, "bundle": bundle})))
}

fn handle_bundle_verify(
    state: &Arc<AppState>,
    request: &Request,
) -> Result<(u16, Json), (u16, Json)> {
    let capability = require_token(state, request)?;
    let body = parse_json(&request.body).map_err(|e| error(422, &e))?;
    let bundle: crate::sink::EvidenceBundle = serde_json::from_value(body["bundle"].clone())
        .map_err(|e| error(422, &format!("AUDIT_EVENT_INVALID: {e}")))?;
    authorize(
        &capability,
        CapOp::Read,
        None,
        Some(&bundle.registry_id),
        now_unix_ms(),
    )
    .map_err(scope_error)?;
    let verification = ProtectedSink::verify_bundle(&bundle);
    Ok((
        200,
        json!({"ok": true, "verified": verification.verified, "errors": verification.errors}),
    ))
}

fn handle_rebuild(state: &Arc<AppState>, request: &Request) -> Result<(u16, Json), (u16, Json)> {
    let capability = require_token(state, request)?;
    let body = parse_json(&request.body).map_err(|e| error(422, &e))?;
    let source = body["source"]
        .as_str()
        .ok_or_else(|| error(422, "AUDIT_REBUILD_INVALID: source is required"))?
        .to_string();
    authorize(
        &capability,
        CapOp::Rebuild,
        Some(&source),
        None,
        now_unix_ms(),
    )
    .map_err(scope_error)?;
    if state.config.projection_dsn.is_none() {
        return Err(error(
            409,
            "AUDIT_REBUILD_UNCONFIGURED: projectionDsn is not configured",
        ));
    }
    if state
        .rebuild_running
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
    {
        let thread_state = Arc::clone(state);
        std::thread::spawn(move || run_rebuild(thread_state, source));
    }
    let sink = state.sink.lock().expect("sink lock");
    let status = sink.status();
    let head = status.head_seq;
    let tail_rollback = status.tail_rollback.is_some();
    Ok((
        200,
        json!({"ok": true, "rebuild": rebuild_json(state, head, tail_rollback)}),
    ))
}

fn handle_rebuild_status(
    state: &Arc<AppState>,
    request: &Request,
) -> Result<(u16, Json), (u16, Json)> {
    require_cap(state, request, CapOp::Read, None, None)?;
    if state.config.projection_dsn.is_none() {
        return Err(error(
            409,
            "AUDIT_REBUILD_UNCONFIGURED: projectionDsn is not configured",
        ));
    }
    let durable = match &state.config.projection_dsn {
        Some(dsn) => Projector::connect(dsn)
            .and_then(|mut projector| projector.state())
            .map_err(|e| error(500, &e))?,
        None => RebuildState::unknown(),
    };
    let sink = state.sink.lock().expect("sink lock");
    let status = sink.status();
    let head = status.head_seq;
    let tail_rollback = status.tail_rollback.is_some();
    Ok((
        200,
        json!({
            "ok": true,
            "rebuild": rebuild_json(state, head, tail_rollback),
            "durable": {
                "status": durable.status.as_str(),
                "cursorSequence": durable.cursor_sequence,
                "headSequence": durable.head_sequence,
                "headHash": durable.head_hash,
                "floorSequence": durable.floor_sequence,
                "error": durable.error,
                "projectionStatus": durable.projection_status(head),
            },
        }),
    ))
}

/// Rebuild из проверенного destination: resume с durable cursor, идемпотентные
/// insert, завершение только когда cursor догнал текущий destination head
/// (доставка во время rebuild не даёт false current).
fn run_rebuild(state: Arc<AppState>, source: String) {
    let outcome = run_rebuild_inner(&state, &source);
    if let Err(e) = &outcome {
        if let Some(dsn) = &state.config.projection_dsn {
            if let Ok(mut projector) = Projector::connect(dsn) {
                let _ = projector.fail(e);
            }
        }
        if let Ok(mut mirror) = state.rebuild.lock() {
            mirror.status = RebuildStatus::Failed;
            mirror.error = Some(e.clone());
        }
    }
    state.rebuild_running.store(false, Ordering::SeqCst);
}

fn run_rebuild_inner(state: &Arc<AppState>, source: &str) -> Result<(), String> {
    let dsn = state
        .config
        .projection_dsn
        .clone()
        .ok_or("AUDIT_REBUILD_UNCONFIGURED")?;
    let mut projector = Projector::connect(&dsn)?;
    let snapshot =
        |state: &Arc<AppState>| -> Result<(Vec<crate::sink::SinkEntry>, u64, String, u64), String> {
            let sink = state.sink.lock().expect("sink lock");
            let entries: Vec<crate::sink::SinkEntry> = sink
                .stream_for_source(source)?
                .into_iter()
                .cloned()
                .collect();
            let pin = sink
                .status()
                .sources
                .into_iter()
                .find(|p| p.identity == source)
                .ok_or_else(|| format!("AUDIT_REBUILD_INVALID: source {source} has no events"))?;
            Ok((entries, pin.head_seq, pin.head_hash, pin.floor_sequence))
        };

    let (entries, head_seq, head_hash, floor_seq) = snapshot(state)?;
    let current = projector.state()?;
    let resume = current.status == RebuildStatus::Rebuilding
        && current.source_identity.as_deref() == Some(source);
    let mut cursor = if resume { current.cursor_sequence } else { 0 };
    projector.begin(source, head_seq, &head_hash, floor_seq, resume)?;
    {
        let mut mirror = state.rebuild.lock().expect("rebuild lock");
        *mirror = projector.state()?;
    }
    for entry in entries.iter() {
        if entry.event.sequence <= cursor {
            continue;
        }
        if state.config.rebuild_delay_ms > 0 {
            std::thread::sleep(std::time::Duration::from_millis(
                state.config.rebuild_delay_ms,
            ));
        }
        projector.project_entry(entry)?;
        cursor = entry.event.sequence;
    }
    // Доставка могла продолжиться во время rebuild: догоняем до стабильного head.
    for _ in 0..10_000 {
        let (fresh, fresh_head_seq, fresh_head_hash, _) = snapshot(state)?;
        if cursor >= fresh_head_seq {
            projector.complete(source, fresh_head_seq, &fresh_head_hash)?;
            let state_now = projector.state()?;
            {
                let mut mirror = state.rebuild.lock().expect("rebuild lock");
                *mirror = state_now.clone();
            }
            let mut sink = state.sink.lock().expect("sink lock");
            sink.append_checkpoint(&Checkpoint {
                at_unix_ms: now_unix_ms(),
                status: "COMPLETE".into(),
                source: source.to_string(),
                cursor_sequence: state_now.cursor_sequence,
                head_seq: fresh_head_seq,
                head_hash: fresh_head_hash,
            })?;
            return Ok(());
        }
        for entry in fresh.iter() {
            if entry.event.sequence <= cursor {
                continue;
            }
            if state.config.rebuild_delay_ms > 0 {
                std::thread::sleep(std::time::Duration::from_millis(
                    state.config.rebuild_delay_ms,
                ));
            }
            projector.project_entry(entry)?;
            cursor = entry.event.sequence;
        }
    }
    Err("AUDIT_REBUILD_INVALID: delivery never settled".into())
}

/// Синхронный rebuild (CLI): запускается и дожидается завершения.
pub fn rebuild_blocking(config: AuditConfig, source: &str) -> Result<RebuildState, String> {
    let state = AppState::new(config)?;
    run_rebuild_inner(&state, source)?;
    let dsn = state
        .config
        .projection_dsn
        .clone()
        .ok_or("AUDIT_REBUILD_UNCONFIGURED")?;
    Projector::connect(&dsn)?.state()
}

pub fn serve(config: AuditConfig) -> Result<(), String> {
    let state = AppState::new(config)?;
    let listener = TcpListener::bind(&state.config.listen)
        .map_err(|e| format!("audit listen {}: {e}", state.config.listen))?;
    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                let state = Arc::clone(&state);
                std::thread::spawn(move || {
                    let response = match read_request(&mut stream) {
                        Ok(request) => dispatch(&state, &request),
                        Err(e) => error(400, &format!("AUDIT_REQUEST_INVALID: {e}")),
                    };
                    let _ = write_response(&mut stream, response.0, &response.1);
                });
            }
            Err(e) => eprintln!("audit accept: {e}"),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn request_bytes(method: &str, path: &str, body: &str, bearer: Option<&str>) -> Vec<u8> {
        let auth = bearer
            .map(|t| format!("Authorization: Bearer {t}\r\n"))
            .unwrap_or_default();
        format!(
            "{method} {path} HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n{auth}\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    #[test]
    fn parses_requests_with_body_and_bearer() {
        let raw = request_bytes("POST", "/v1/append", "{\"a\":1}", Some("tok"));
        let mut cursor = Cursor::new(raw);
        let request = read_request(&mut cursor).unwrap();
        assert_eq!(
            (request.method.as_str(), request.path.as_str()),
            ("POST", "/v1/append")
        );
        assert_eq!(request.body, b"{\"a\":1}");
        assert_eq!(request.bearer.as_deref(), Some("tok"));
    }

    #[test]
    fn rejects_oversized_body_and_maps_error_codes() {
        let raw = format!(
            "POST /v1/append HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY_BYTES + 1
        );
        assert!(read_request(&mut Cursor::new(raw.into_bytes())).is_err());
        let (status, body) = error(422, "AUDIT_REDACTION_FORBIDDEN_KEY: payload.token");
        assert_eq!(status, 422);
        assert_eq!(body["error"], "AUDIT_REDACTION_FORBIDDEN_KEY");
        assert_eq!(body["detail"], "payload.token");
    }
}
