//! The scan engines: clamd over TCP, YARA-X in process, and three hash lookups.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use serde::Serialize;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::model::{Category, EngineResult, FileInfo, ResultStatus, ResultVerdict};

#[derive(Serialize)]
pub struct EngineInfo {
    pub name: &'static str,
    pub category: Category,
    pub kind: &'static str,
    pub description: &'static str,
    pub mime: [&'static str; 1],
    pub ready: bool,
    pub detail: Option<String>,
}

pub const ENGINES: [&str; 5] = ["clamav", "yara", "hashlookup", "shadowserver", "virustotal"];

pub fn category_of(engine: &str) -> Category {
    match engine {
        "hashlookup" | "shadowserver" | "virustotal" => Category::Intel,
        _ => Category::Av,
    }
}

const ENGINE_TIMEOUT: Duration = Duration::from_secs(120);

pub struct Engines {
    clamd_addr: String,
    rules: Option<Arc<yara_x::Rules>>,
    rule_count: usize,
    http: reqwest::Client,
    vt_key: Option<String>,
}

type Outcome = Result<(ResultStatus, Option<ResultVerdict>, Option<String>, Value)>;

impl Engines {
    pub fn new(clamd_addr: String, rules_dir: &Path, vt_key: Option<String>) -> Result<Self> {
        let (rules, rule_count) = match load_rules(rules_dir)? {
            Some(r) => {
                let n = r.iter().len();
                (Some(Arc::new(r)), n)
            }
            None => (None, 0),
        };
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .user_agent(concat!("malicenx/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self { clamd_addr, rules, rule_count, http, vt_key: vt_key.filter(|k| !k.is_empty()) })
    }

    pub async fn info(&self) -> Vec<EngineInfo> {
        let clamd = clamd_command(&self.clamd_addr, b"zVERSION\0").await;
        let e = |name, kind, description, mime, ready, detail: Option<String>| EngineInfo {
            name,
            category: category_of(name),
            kind,
            description,
            mime: [mime],
            ready,
            detail,
        };
        vec![
            e("clamav", "service", "ClamAV signatures, scanned by the clamd service", "*", clamd.is_ok(), Some(match clamd {
                Ok(v) => v,
                Err(err) => format!("clamd unreachable: {err:#}"),
            })),
            e("yara", "builtin", "YARA-X rule scan inside the server", "*", self.rule_count > 0, Some(format!("{} rule{}", self.rule_count, if self.rule_count == 1 { "" } else { "s" }))),
            e("hashlookup", "builtin", "CIRCL hashlookup: NSRL and other known-file sets", "hash", true, Some("online lookup".into())),
            e("shadowserver", "builtin", "Shadowserver known-software lookup", "hash", true, Some("online lookup".into())),
            e("virustotal", "builtin", "VirusTotal hash lookup", "hash", self.vt_key.is_some(), Some(
                if self.vt_key.is_some() { "API key set" } else { "VIRUSTOTAL_API_KEY not set" }.into(),
            )),
        ]
    }

    pub async fn run(&self, engine: &str, path: &Path, file: &FileInfo) -> EngineResult {
        let started = Instant::now();
        let outcome = match tokio::time::timeout(ENGINE_TIMEOUT, self.dispatch(engine, path, file)).await {
            Ok(o) => o,
            Err(_) => Err(anyhow!("timed out after {}s", ENGINE_TIMEOUT.as_secs())),
        };
        let (status, verdict, signature, data, error) = match outcome {
            Ok((status, verdict, signature, data)) => {
                let skip_reason = (status == ResultStatus::Skipped).then(|| data["reason"].as_str().unwrap_or("skipped").to_string());
                (status, verdict, signature, if skip_reason.is_some() { Value::Null } else { data }, skip_reason)
            }
            Err(e) => (ResultStatus::Error, None, None, Value::Null, Some(format!("{e:#}"))),
        };
        EngineResult {
            engine: engine.to_string(),
            category: category_of(engine),
            status,
            verdict,
            signature,
            duration_ms: Some(started.elapsed().as_millis() as u64),
            error,
            data,
        }
    }

    async fn dispatch(&self, engine: &str, path: &Path, file: &FileInfo) -> Outcome {
        match engine {
            "clamav" => {
                let reply = clamd_scan(&self.clamd_addr, path).await?;
                let (verdict, sig) = clamd_verdict(&reply)?;
                Ok((ResultStatus::Ok, Some(verdict), sig, json!({ "reply": reply })))
            }
            "yara" => {
                let Some(rules) = self.rules.clone() else {
                    return Ok((ResultStatus::Skipped, None, None, json!({"reason": "no YARA rules loaded"})));
                };
                let path = path.to_path_buf();
                let matches = tokio::task::spawn_blocking(move || yara_scan(&rules, &path)).await??;
                let sig = matches.first().map(|m| m["rule"].as_str().unwrap_or_default().to_string());
                let verdict = if sig.is_some() { ResultVerdict::Threat } else { ResultVerdict::Clean };
                Ok((ResultStatus::Ok, Some(verdict), sig, json!({ "matches": matches })))
            }
            "hashlookup" => {
                let url = format!("https://hashlookup.circl.lu/lookup/sha256/{}", file.sha256);
                let body = get_json(self.http.get(url)).await?;
                let (v, sig) = hashlookup_verdict(body.as_ref());
                Ok((ResultStatus::Ok, Some(v), sig, json!({ "found": body.is_some(), "record": body })))
            }
            "shadowserver" => {
                // Keyless known-software list. A match identifies the file, it does not clear it.
                let url = format!("http://bin-test.shadowserver.org/api?md5={}", file.md5);
                let text = self.http.get(url).send().await?.error_for_status()?.text().await?;
                let record = text.trim().split_once(' ').and_then(|(_, j)| serde_json::from_str::<Value>(j).ok());
                Ok((ResultStatus::Ok, Some(ResultVerdict::Info), None, json!({ "found": record.is_some(), "record": record })))
            }
            "virustotal" => {
                let Some(key) = &self.vt_key else {
                    return Ok((ResultStatus::Skipped, None, None, json!({"reason": "VIRUSTOTAL_API_KEY not set"})));
                };
                let url = format!("https://www.virustotal.com/api/v3/files/{}", file.sha256);
                let body = get_json(self.http.get(url).header("x-apikey", key)).await?;
                let (v, sig) = virustotal_verdict(body.as_ref());
                let attrs = body.as_ref().map(|b| &b["data"]["attributes"]);
                let data = json!({
                    "found": body.is_some(),
                    "stats": attrs.map(|a| a["last_analysis_stats"].clone()),
                    "threat_label": attrs.map(|a| a["popular_threat_classification"]["suggested_threat_label"].clone()),
                    "permalink": format!("https://www.virustotal.com/gui/file/{}", file.sha256),
                });
                Ok((ResultStatus::Ok, Some(v), sig, data))
            }
            other => bail!("unknown engine {other}"),
        }
    }
}

/// GET returning `None` on 404.
async fn get_json(req: reqwest::RequestBuilder) -> Result<Option<Value>> {
    let resp = req.send().await?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    Ok(Some(resp.error_for_status()?.json().await?))
}

pub fn clamd_verdict(reply: &str) -> Result<(ResultVerdict, Option<String>)> {
    let body = reply.trim_end_matches('\0').trim();
    let body = body.strip_prefix("stream:").map(str::trim).unwrap_or(body);
    if body == "OK" {
        return Ok((ResultVerdict::Clean, None));
    }
    if let Some(sig) = body.strip_suffix(" FOUND") {
        return Ok((ResultVerdict::Threat, Some(sig.trim().to_string())));
    }
    bail!("clamd: {body}")
}

pub fn hashlookup_verdict(record: Option<&Value>) -> (ResultVerdict, Option<String>) {
    match record {
        None => (ResultVerdict::Info, None),
        Some(r) => match r.get("KnownMalicious").and_then(Value::as_str) {
            Some(src) => (ResultVerdict::Threat, Some(format!("KnownMalicious: {src}"))),
            // Listed as a known file (NSRL etc.). That is not proof of harmlessness: EICAR is listed too.
            None => (ResultVerdict::Info, None),
        },
    }
}

pub fn virustotal_verdict(body: Option<&Value>) -> (ResultVerdict, Option<String>) {
    let Some(attrs) = body.map(|b| &b["data"]["attributes"]) else {
        return (ResultVerdict::Info, None);
    };
    let stats = &attrs["last_analysis_stats"];
    let n = |k: &str| stats[k].as_u64().unwrap_or(0);
    let malicious = n("malicious");
    if malicious == 0 {
        return (ResultVerdict::Clean, None);
    }
    let total = malicious + n("suspicious") + n("undetected") + n("harmless");
    let label = attrs["popular_threat_classification"]["suggested_threat_label"].as_str().unwrap_or("malicious");
    (ResultVerdict::Threat, Some(format!("{label} ({malicious}/{total})")))
}

async fn clamd_command(addr: &str, cmd: &[u8]) -> Result<String> {
    let mut s = tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(addr)).await??;
    s.write_all(cmd).await?;
    read_reply(&mut s).await
}

async fn read_reply(s: &mut TcpStream) -> Result<String> {
    let mut out = Vec::new();
    s.read_to_end(&mut out).await?;
    Ok(String::from_utf8_lossy(&out).trim_end_matches('\0').trim().to_string())
}

async fn clamd_scan(addr: &str, path: &Path) -> Result<String> {
    let mut s = TcpStream::connect(addr).await.with_context(|| format!("connect clamd at {addr}"))?;
    let mut f = tokio::fs::File::open(path).await?;
    s.write_all(b"zINSTREAM\0").await?;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        s.write_all(&(n as u32).to_be_bytes()).await?;
        if let Err(e) = s.write_all(&buf[..n]).await {
            // clamd closes the stream when StreamMaxLength is exceeded; its reply says why.
            return read_reply(&mut s).await.ok().filter(|r| !r.is_empty()).ok_or_else(|| e.into());
        }
    }
    s.write_all(&0u32.to_be_bytes()).await?;
    read_reply(&mut s).await
}

/// Compiles every .yar/.yara file under `dir`. A file that fails to compile is logged and skipped.
pub fn load_rules(dir: &Path) -> Result<Option<yara_x::Rules>> {
    let mut files = Vec::new();
    collect_rule_files(dir, &mut files);
    files.sort();
    let mut compiler = yara_x::Compiler::new();
    // Globals that common public rule sets (signature-base, THOR) reference.
    for g in ["filename", "filepath", "extension", "filetype", "owner"] {
        compiler.define_global(g, "")?;
    }
    let mut ok = 0;
    for f in &files {
        let src = match std::fs::read_to_string(f) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(file = %f.display(), "skip rule file: {e}");
                continue;
            }
        };
        compiler.new_namespace(&f.strip_prefix(dir).unwrap_or(f).display().to_string());
        match compiler.add_source(yara_x::SourceCode::from(src.as_str()).with_origin(f.display().to_string())) {
            Ok(_) => ok += 1,
            Err(e) => tracing::warn!(file = %f.display(), "skip rule file: {e}"),
        }
    }
    tracing::info!(files = files.len(), compiled = ok, dir = %dir.display(), "yara rules");
    if ok == 0 {
        return Ok(None);
    }
    Ok(Some(compiler.build()))
}

fn collect_rule_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(dir = %dir.display(), "cannot read rule directory: {e}");
            return;
        }
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            collect_rule_files(&p, out);
        } else if matches!(p.extension().and_then(|x| x.to_str()), Some("yar" | "yara")) {
            out.push(p);
        }
    }
}

fn yara_scan(rules: &yara_x::Rules, path: &Path) -> Result<Vec<Value>> {
    let mut scanner = yara_x::Scanner::new(rules);
    scanner.set_timeout(Duration::from_secs(60));
    let results = scanner.scan_file(path)?;
    Ok(results
        .matching_rules()
        .map(|r| {
            json!({
                "rule": r.identifier(),
                "namespace": r.namespace(),
                "tags": r.tags().map(|t| t.identifier().to_string()).collect::<Vec<_>>(),
            })
        })
        .collect())
}
