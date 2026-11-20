//! HTTP API (docs/api.md) and static UI.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::body::to_bytes;
use axum::extract::{DefaultBodyLimit, Multipart, Path as UrlPath, Query, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use mail_parser::{Message, MessageParser, MimeHeaders};
use md5::Md5;
use serde::Deserialize;
use serde_json::json;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use tokio::io::AsyncWriteExt;
use tokio::sync::Semaphore;
use tower_http::services::{ServeDir, ServeFile};

use crate::engines::{ENGINES, Engines};
use crate::model::{Category, EngineResult, FileInfo, ResultStatus, ResultVerdict, Verdict};
use crate::search::Index;
use crate::store::{ScanFilter, Store, Submission};

pub const MAX_UPLOAD: usize = 256 * 1024 * 1024;

pub(crate) const MAX_MAIL: usize = 25 * 1024 * 1024;
const MAX_ATTACHMENTS: usize = 32;

pub struct AppState {
    pub store: Store,
    pub index: Index,
    pub engines: Engines,
    pub samples_dir: PathBuf,
    pub scan_slots: Semaphore,
    pub token: Option<String>,
    pub ingest_tokens: std::collections::BTreeMap<String, String>,
    pub admission: Arc<Semaphore>,
    pub notifications: crate::notify::Notifications,
}

type St = State<Arc<AppState>>;

pub struct ApiError(pub(crate) StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

impl<E: std::fmt::Display> From<E> for ApiError {
    fn from(e: E) -> Self {
        tracing::error!("{e:#}");
        ApiError(StatusCode::INTERNAL_SERVER_ERROR, "internal error".into())
    }
}

type ApiResult<T> = Result<T, ApiError>;

pub fn router(state: Arc<AppState>, web_dir: &Path) -> Router {
    let api = Router::new()
        .route("/health", get(health))
        .route("/stats", get(stats))
        .route("/engines", get(engines))
        .route("/scans", get(list_scans).post(upload).layer(DefaultBodyLimit::max(MAX_UPLOAD + 64 * 1024)))
        .route("/scans/{id}", get(get_scan))
        .route("/mail", post(upload_mail))
        .fallback(|| async { ApiError(StatusCode::NOT_FOUND, "not found".into()) })
        .route_layer(middleware::from_fn_with_state(state.clone(), auth))
        .with_state(state);
    let ui = ServeDir::new(web_dir).fallback(ServeFile::new(web_dir.join("index.html")));
    Router::new().nest("/api", api).fallback_service(ui).layer(middleware::from_fn(security_headers))
}

async fn security_headers(req: Request, next: Next) -> Response {
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'self'; img-src 'self' data:; font-src 'self' data:; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'"),
    );
    res
}

async fn auth(State(s): St, req: Request, next: Next) -> Response {
    let given = bearer(req.headers());
    let ingest = integration(&s, req.headers()).is_some();
    if ingest && req.method() == axum::http::Method::POST && matches!(req.uri().path(), "/mail" | "/scans") {
        return next.run(req).await;
    }
    if ingest {
        return ApiError(StatusCode::UNAUTHORIZED, "submit-only token".into()).into_response();
    }
    if let Some(token) = &s.token {
        if !given.is_some_and(|g| constant_time_eq(g.as_bytes(), token.as_bytes())) {
            return ApiError(StatusCode::UNAUTHORIZED, "token required".into()).into_response();
        }
    }
    next.run(req).await
}

fn integration<'a>(s: &'a AppState, headers: &HeaderMap) -> Option<&'a str> {
    let given = bearer(headers)?;
    s.ingest_tokens.iter().find_map(|(name, token)|
        constant_time_eq(given.as_bytes(), token.as_bytes()).then_some(name.as_str()))
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers.get(header::AUTHORIZATION)?.to_str().ok()?.strip_prefix("Bearer ")
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

async fn health(State(s): St) -> Json<serde_json::Value> {
    let info = s.engines.info().await;
    Json(json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
        "engines_ready": info.iter().filter(|e| e.ready).count(),
        "engines_total": info.len(),
    }))
}

async fn stats(State(s): St) -> ApiResult<impl IntoResponse> {
    Ok(Json(s.store.stats()?))
}

async fn engines(State(s): St) -> Json<serde_json::Value> {
    Json(json!({ "engines": s.engines.info().await }))
}

#[derive(Deserialize)]
struct ListQuery {
    #[serde(default)]
    from: usize,
    size: Option<usize>,
    q: Option<String>,
    verdict: Option<String>,
    status: Option<String>,
    since_hours: Option<u32>,
}

async fn list_scans(State(s): St, Query(p): Query<ListQuery>) -> ApiResult<impl IntoResponse> {
    let size = p.size.unwrap_or(20).clamp(1, 100);
    let hits = match p.q.as_deref().map(str::trim).filter(|q| !q.is_empty()) {
        Some(q) => {
            let mut ids = s.index.search(q, 1000)?;
            ids.extend(s.store.ids_by_hash_prefix(q)?);
            ids.sort();
            ids.dedup();
            Some(ids)
        }
        None => None,
    };
    let filter = ScanFilter {
        verdict: match p.verdict.as_deref() {
            None | Some("") | Some("all") => None,
            Some("threat") => Some(Verdict::Threat),
            Some("clean") => Some(Verdict::Clean),
            Some("pending") => Some(Verdict::Pending),
            Some("incomplete") => Some(Verdict::Incomplete),
            Some(_) => return Err(ApiError(StatusCode::BAD_REQUEST, "verdict must be threat, clean, pending or incomplete".into())),
        },
        running: match p.status.as_deref() {
            None | Some("") | Some("all") => false,
            Some("running") => true,
            Some(_) => return Err(ApiError(StatusCode::BAD_REQUEST, "status must be running".into())),
        },
        since_hours: p.since_hours,
    };
    let (total, scans) = s.store.list(hits.as_deref(), &filter, p.from, size)?;
    Ok(Json(json!({ "total": total, "scans": scans })))
}

async fn get_scan(State(s): St, UrlPath(id): UrlPath<String>) -> ApiResult<impl IntoResponse> {
    match s.store.get_scan(&id)? {
        Some(d) => {
            let mut value = serde_json::to_value(d)?;
            if let serde_json::Value::Object(fields) = s.store.submission_details(&id)? {
                value.as_object_mut().expect("scan detail is an object").extend(fields);
            }
            Ok(Json(value))
        },
        None => Err(ApiError(StatusCode::NOT_FOUND, "scan not found".into())),
    }
}

pub(crate) fn capacity(s: &AppState) -> ApiResult<tokio::sync::OwnedSemaphorePermit> {
    s.admission.clone().try_acquire_owned()
        .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "scan queue is full; retry later".into()))
}

struct TempUpload(PathBuf);

impl Drop for TempUpload {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

async fn upload(State(s): St, headers: HeaderMap, mut form: Multipart) -> ApiResult<impl IntoResponse> {
    let permit = capacity(&s)?;
    let source = integration(&s, &headers).unwrap_or("upload").to_owned();
    let bad = |m: &str| ApiError(StatusCode::BAD_REQUEST, m.into());
    let multipart_err = |e: axum::extract::multipart::MultipartError| {
        let status = e.status();
        let msg = if status == StatusCode::PAYLOAD_TOO_LARGE { "file is larger than 256 MiB".into() } else { e.body_text() };
        ApiError(status, msg)
    };
    while let Some(mut field) = form.next_field().await.map_err(multipart_err)? {
        if field.name() != Some("file") {
            continue;
        }
        let name = sanitize_name(field.file_name().unwrap_or("upload"));
        let is_mail = name.to_ascii_lowercase().ends_with(".eml");
        let tmp = TempUpload(s.samples_dir.join(format!(".upload-{}", uuid::Uuid::new_v4())));
        let mut out = tokio::fs::File::create(&tmp.0).await?;
        let (mut md5, mut sha1, mut sha256, mut sha512) = (Md5::new(), Sha1::new(), Sha256::new(), Sha512::new());
        let mut size = 0u64;
        let mut head = Vec::with_capacity(512);
        let copied: ApiResult<()> = async {
            while let Some(chunk) = field.chunk().await.map_err(multipart_err)? {
                size += chunk.len() as u64;
                if size > if is_mail { MAX_MAIL } else { MAX_UPLOAD } as u64 {
                    return Err(ApiError(StatusCode::PAYLOAD_TOO_LARGE, "file exceeds upload limit".into()));
                }
                if head.len() < 512 {
                    head.extend_from_slice(&chunk[..chunk.len().min(512 - head.len())]);
                }
                md5.update(&chunk);
                sha1.update(&chunk);
                sha256.update(&chunk);
                sha512.update(&chunk);
                out.write_all(&chunk).await?;
            }
            out.flush().await?;
            Ok(())
        }
        .await;
        drop(out);
        copied?;
        if size == 0 {
            return Err(bad("file is empty"));
        }
        let file = FileInfo {
            name,
            size,
            mime: sniff_mime(&head).into(),
            md5: hex::encode(md5.finalize()),
            sha1: hex::encode(sha1.finalize()),
            sha256: hex::encode(sha256.finalize()),
            sha512: hex::encode(sha512.finalize()),
        };
        if is_mail {
            let bytes = tokio::fs::read(&tmp.0).await?;
            return submit_mail(s, permit, &headers, &source, file.name, &bytes).await;
        }
        // Samples are stored under their hash, never under the uploaded name.
        let path = s.samples_dir.join(&file.sha256);
        tokio::fs::rename(&tmp.0, &path).await?;

        return submit(s, permit, &headers, &source, file, None, Vec::new()).await;
    }
    Err(bad("missing multipart field 'file'"))
}

async fn upload_mail(State(s): St, req: Request) -> ApiResult<(StatusCode, Json<serde_json::Value>)> {
    let permit = capacity(&s)?;
    let (parts, body) = req.into_parts();
    if parts.headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next()) != Some("message/rfc822") {
        return Err(ApiError(StatusCode::UNSUPPORTED_MEDIA_TYPE, "expected message/rfc822".into()));
    }
    let bytes = to_bytes(body, MAX_MAIL).await
        .map_err(|_| ApiError(StatusCode::PAYLOAD_TOO_LARGE, "mail exceeds 25 MiB or transfer failed".into()))?;
    let source = integration(&s, &parts.headers).unwrap_or("upload").to_owned();
    submit_mail(s, permit, &parts.headers, &source, "message.eml".into(), &bytes).await
}

fn mail_parts<'a>(message: &'a Message<'a>, attachments: &mut Vec<(String, &'a [u8])>) -> ApiResult<()> {
    if message.parts.iter().any(|part| part.is_encoding_problem) {
        return Err(ApiError(StatusCode::UNPROCESSABLE_ENTITY, "mail contains malformed MIME parts".into()));
    }
    for part in message.attachments() {
        let bytes = part.contents();
        if attachments.len() >= MAX_ATTACHMENTS {
            return Err(ApiError(StatusCode::UNPROCESSABLE_ENTITY, "mail exceeds 32 attachments".into()));
        }
        if bytes.is_empty() {
            return Err(ApiError(StatusCode::UNPROCESSABLE_ENTITY, "mail contains an empty or unsupported attachment".into()));
        }
        let name = sanitize_name(part.attachment_name().unwrap_or("attachment"));
        attachments.push((name, bytes));
        if let Some(nested) = part.message() {
            mail_parts(nested, attachments)?;
        }
    }
    Ok(())
}

async fn save_bytes(s: &AppState, name: String, bytes: &[u8]) -> ApiResult<FileInfo> {
    let file = FileInfo {
        name,
        size: bytes.len() as u64,
        mime: sniff_mime(bytes).into(),
        md5: hex::encode(Md5::digest(bytes)),
        sha1: hex::encode(Sha1::digest(bytes)),
        sha256: hex::encode(Sha256::digest(bytes)),
        sha512: hex::encode(Sha512::digest(bytes)),
    };
    let tmp = TempUpload(s.samples_dir.join(format!(".upload-{}", uuid::Uuid::new_v4())));
    tokio::fs::write(&tmp.0, bytes).await?;
    tokio::fs::rename(&tmp.0, s.samples_dir.join(&file.sha256)).await?;
    Ok(file)
}

pub(crate) async fn submit_mail(
    s: Arc<AppState>, permit: tokio::sync::OwnedSemaphorePermit, headers: &HeaderMap, source: &str, name: String, bytes: &[u8],
) -> ApiResult<(StatusCode, Json<serde_json::Value>)> {
    let message = MessageParser::default().parse(bytes)
        .filter(|message| message.from().is_some() || message.subject().is_some())
        .ok_or_else(|| ApiError(StatusCode::UNPROCESSABLE_ENTITY, "invalid RFC 5322 mail".into()))?;
    let mut parts = Vec::new();
    mail_parts(&message, &mut parts)?;
    let mut forwarded = message.attachments().filter_map(|part| part.message());
    let original = match (forwarded.next(), forwarded.next()) {
        (Some(original), None) => original,
        _ => &message,
    };
    let body = original.body_text(0).unwrap_or_default();
    let preview: String = body.chars().take(12000).collect();
    let mail = json!({
        "subject": original.subject().unwrap_or("(no subject)").chars().take(512).collect::<String>(),
        "from": original.from().and_then(|v| v.first()).and_then(|v| v.address()).map(|v| v.chars().take(512).collect::<String>()),
        "body": preview,
        "body_truncated": preview.len() < body.len(),
    });
    if parts.iter().map(|(_, content)| content.len()).sum::<usize>() > MAX_MAIL * 2 {
        return Err(ApiError(StatusCode::UNPROCESSABLE_ENTITY, "decoded attachments exceed 50 MiB".into()));
    }
    let mut attachments = Vec::new();
    for (name, content) in parts {
        attachments.push(save_bytes(&s, name, content).await?);
    }
    let mut file = save_bytes(&s, name, bytes).await?;
    file.mime = "message/rfc822".into();
    submit(s, permit, headers, source, file, Some(mail), attachments).await
}

fn submission_header<'a>(headers: &'a HeaderMap, name: &'static str) -> ApiResult<Option<&'a str>> {
    headers.get(name).map(|value| {
        value.to_str().ok().filter(|value| !value.trim().is_empty() && value.len() <= 200)
            .ok_or_else(|| ApiError(StatusCode::BAD_REQUEST, format!("invalid {name}")))
    }).transpose()
}

async fn submit(
    s: Arc<AppState>, permit: tokio::sync::OwnedSemaphorePermit, headers: &HeaderMap,
    source: &str, file: FileInfo, mail: Option<serde_json::Value>, attachments: Vec<FileInfo>,
) -> ApiResult<(StatusCode, Json<serde_json::Value>)> {
    let channels = s.notifications.channels(mail.is_some());
    let Some((id, children)) = s.store.submit(Submission {
        file: &file, source, reference: submission_header(headers, "x-scan-reference")?,
        key: submission_header(headers, "idempotency-key")?, mail: mail.as_ref(), attachments: &attachments,
        channels: &channels,
    })? else {
        return Err(ApiError(StatusCode::CONFLICT, "idempotency key already used for a different submission".into()));
    };
    let receipt = json!({ "id": id, "sha256": file.sha256, "name": file.name, "report": format!("/scans/{id}"), "status": "running" });
    if let Some(children) = children {
        let job_id = id;
        tokio::spawn(async move {
            let _permit = permit;
            let Ok(_slot) = s.scan_slots.acquire().await else { return };
            run_engines(&s, &job_id, &file).await;
            if mail.is_some() {
                let mut threat = false;
                let mut incomplete = false;
                for (child, attachment) in children.iter().zip(&attachments) {
                    run_engines(&s, child, attachment).await;
                    match finish_scan(&s, child) {
                        Some(Verdict::Threat) => threat = true,
                        Some(Verdict::Clean) => {}
                        _ => incomplete = true,
                    }
                }
                let result = EngineResult {
                    engine: "mail-attachments".into(),
                    category: Category::Av,
                    status: if incomplete { ResultStatus::Error } else { ResultStatus::Ok },
                    verdict: if threat { Some(ResultVerdict::Threat) } else if incomplete { None } else { Some(ResultVerdict::Clean) },
                    signature: threat.then(|| "Threat in mail attachment".into()),
                    duration_ms: None,
                    error: incomplete.then(|| "At least one attachment was not fully scanned".into()),
                    data: json!({ "count": children.len() }),
                };
                if let Err(error) = s.store.put_result(&job_id, &result) {
                    tracing::error!(scan = %job_id, %error, "store attachment result");
                }
            }
            finish_scan(&s, &job_id);
        });
    }
    Ok((StatusCode::ACCEPTED, Json(receipt)))
}

async fn run_engines(s: &AppState, id: &str, file: &FileInfo) {
    let path = s.samples_dir.join(&file.sha256);
    let runs = ENGINES.iter().map(|engine| {
        let path = &path;
        async move {
            let r = s.engines.run(engine, path, file).await;
            if let Err(e) = s.store.put_result(id, &r) {
                tracing::error!(scan = %id, engine, "store result: {e:#}");
            }
        }
    });
    futures_util::future::join_all(runs).await;
}

fn finish_scan(s: &AppState, id: &str) -> Option<Verdict> {
    let scan = s.store.finish_scan(id).and_then(|_| s.store.get_scan(id));
    match scan {
        Ok(Some(detail)) => {
            if let Err(error) = s.index.put(&detail.summary) {
                tracing::error!(scan = %id, %error, "index scan");
            }
            Some(detail.summary.verdict)
        }
        Ok(None) => None,
        Err(error) => {
            tracing::error!(scan = %id, %error, "finish scan");
            None
        }
    }
}

fn sanitize_name(raw: &str) -> String {
    let base = raw.rsplit(['/', '\\']).next().unwrap_or_default();
    let clean: String = base.chars().filter(|c| !c.is_control()).take(255).collect();
    if clean.trim().is_empty() || clean == "." || clean == ".." { "upload".into() } else { clean }
}

/// Mime types from magic bytes; enough to tell the UI what kind of file it is.
fn sniff_mime(head: &[u8]) -> &'static str {
    const MAGIC: &[(&[u8], &str)] = &[
        (b"MZ", "application/x-dosexec"),
        (b"\x7fELF", "application/x-executable"),
        (b"\xcf\xfa\xed\xfe", "application/x-mach-binary"),
        (b"\xce\xfa\xed\xfe", "application/x-mach-binary"),
        (b"\xca\xfe\xba\xbe", "application/x-mach-binary"),
        (b"%PDF", "application/pdf"),
        (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "application/x-ole-storage"),
        (b"{\\rtf", "application/rtf"),
        (b"PK\x03\x04", "application/zip"),
        (b"Rar!", "application/x-rar"),
        (b"7z\xbc\xaf\x27\x1c", "application/x-7z-compressed"),
        (b"\x1f\x8b", "application/gzip"),
        (b"#!", "text/x-shellscript"),
    ];
    if let Some((_, m)) = MAGIC.iter().find(|(m, _)| head.starts_with(m)) {
        return m;
    }
    // The 512-byte head may cut a multi-byte character; that still counts as text.
    let utf8 = match std::str::from_utf8(head) {
        Ok(_) => true,
        Err(e) => e.error_len().is_none(),
    };
    if utf8 && !head.contains(&0) { "text/plain" } else { "application/octet-stream" }
}
