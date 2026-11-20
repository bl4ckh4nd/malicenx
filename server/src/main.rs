use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result, ensure};
use malicenx::api::{AppState, router};
use malicenx::engines::Engines;
use malicenx::search::Index;
use malicenx::store::Store;
use tokio::sync::Semaphore;

fn env(key: &str, default: &str) -> String {
    std::env::var(key).ok().filter(|v| !v.is_empty()).unwrap_or_else(|| default.to_string())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let data = PathBuf::from(env("MALICENX_DATA", "./data"));
    let samples_dir = data.join("samples");
    std::fs::create_dir_all(&samples_dir).with_context(|| format!("create {}", samples_dir.display()))?;

    let store = Store::open(data.join("malicenx.db").to_str().context("data path is not UTF-8")?)?;
    let max_scans: usize = env("MALICENX_MAX_SCANS", "4").parse().context("MALICENX_MAX_SCANS")?;
    let max_accepted: usize = env("MALICENX_MAX_ACCEPTED", "16").parse().context("MALICENX_MAX_ACCEPTED")?;
    ensure!((1..=1024).contains(&max_scans) && (max_scans..=1024).contains(&max_accepted),
        "require 1 <= MALICENX_MAX_SCANS <= MALICENX_MAX_ACCEPTED <= 1024");
    let token = malicenx::notify::setting("MALICENX_TOKEN");
    let mut ingest_tokens: std::collections::BTreeMap<String, String> =
        malicenx::notify::setting("MALICENX_INGEST_TOKENS")
            .map(|raw| serde_json::from_str(&raw).map_err(|_| anyhow::anyhow!("invalid MALICENX_INGEST_TOKENS JSON")))
            .transpose()?.unwrap_or_default();
    if let Some(ingest) = malicenx::notify::setting("MALICENX_INGEST_TOKEN") {
        ensure!(!ingest_tokens.contains_key("integration"), "duplicate integration name");
        ingest_tokens.insert("integration".into(), ingest);
    }
    if !ingest_tokens.is_empty() {
        ensure!(token.is_some(), "configure MALICENX_TOKEN before enabling integrations");
        let mut distinct = std::collections::HashSet::new();
        for (name, secret) in &ingest_tokens {
            ensure!(!name.is_empty() && name.len() <= 64 && !matches!(name.as_str(), "upload" | "smtp")
                && name.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'),
                "invalid integration name");
            ensure!(!secret.is_empty() && secret.bytes().all(|byte| byte.is_ascii_graphic())
                && token.as_ref() != Some(secret) && distinct.insert(secret), "invalid or duplicate integration token");
        }
    }
    let notifications = malicenx::notify::Notifications::from_env()?;
    let channels = notifications.channels(true);
    let retention = malicenx::notify::setting("MALICENX_SAMPLE_RETENTION_HOURS")
        .map(|value| value.parse::<u64>().context("MALICENX_SAMPLE_RETENTION_HOURS"))
        .transpose()?;
    ensure!(retention.is_none_or(|hours| (1..=87600).contains(&hours)),
        "MALICENX_SAMPLE_RETENTION_HOURS must be between 1 and 87600");
    let interrupted = store.recover_interrupted()?;
    if interrupted > 0 {
        tracing::warn!(interrupted, "closed scans left running by the previous process");
    }
    let state = Arc::new(AppState {
        store,
        index: Index::open(&data.join("index"))?,
        engines: Engines::new(
            env("CLAMD_ADDR", "127.0.0.1:3310"),
            &PathBuf::from(env("MALICENX_RULES", "./rules")),
            std::env::var("VIRUSTOTAL_API_KEY").ok(),
        )?,
        samples_dir,
        scan_slots: Semaphore::new(max_scans),
        admission: Arc::new(Semaphore::new(max_accepted)),
        token,
        ingest_tokens,
        notifications,
    });

    let listen = env("MALICENX_LISTEN", "127.0.0.1:3993");
    for channel in channels {
        tokio::spawn(malicenx::notify::Notifications::run(state.clone(), channel));
    }
    if let Some(hours) = retention {
        tokio::spawn(prune_samples(state.clone(), max_accepted as u32, hours));
    }
    let smtp = malicenx::notify::setting("MALICENX_SMTP_LISTEN").map(|listen| {
        let recipient = env("MALICENX_SMTP_INTAKE_RECIPIENT", "scan@malicenx.local");
        recipient.parse::<lettre::Address>().context("invalid MALICENX_SMTP_INTAKE_RECIPIENT")?;
        Ok::<_, anyhow::Error>(malicenx::smtp::serve(state.clone(), listen, recipient))
    }).transpose()?;
    let app = router(state, &PathBuf::from(env("MALICENX_WEB_DIR", "../web/dist")));
    let listener = tokio::net::TcpListener::bind(&listen).await.with_context(|| format!("bind {listen}"))?;
    tracing::info!("listening on http://{listen}");
    let http = axum::serve(listener, app)
        .with_graceful_shutdown(async {
            // Containers stop with SIGTERM; as PID 1 the default handler would ignore it.
            let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("SIGTERM handler");
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = term.recv() => {}
            }
        });
    if let Some(smtp) = smtp {
        tokio::select! {
            result = http => result?,
            result = smtp => result.context("SMTP intake listener")?,
        }
    } else {
        http.await?;
    }
    Ok(())
}

async fn prune_samples(state: Arc<AppState>, capacity: u32, hours: u64) {
    use std::time::Duration;

    let age = Duration::from_secs(hours * 3600);
    let mut ticks = tokio::time::interval(Duration::from_secs(3600));
    loop {
        ticks.tick().await;
        // The full permit set excludes uploads and scans that share a sample.
        if let Ok(_idle) = state.admission.try_acquire_many(capacity) {
            if let Err(error) = remove_expired_samples(&state.samples_dir, age).await {
                tracing::warn!(%error, "prune samples");
            }
        }
    }
}

async fn remove_expired_samples(dir: &std::path::Path, age: std::time::Duration) -> Result<()> {
    let mut entries = tokio::fs::read_dir(dir).await?;
    while let Some(entry) = entries.next_entry().await? {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let sample = name.len() == 64 && name.bytes().all(|byte| byte.is_ascii_hexdigit());
        let temp = name.strip_prefix(".upload-").is_some_and(|id| uuid::Uuid::parse_str(id).is_ok());
        if !(sample || temp) || !entry.file_type().await?.is_file() {
            continue;
        }
        if entry.metadata().await?.modified()?.elapsed().is_ok_and(|elapsed| elapsed >= age) {
            tokio::fs::remove_file(entry.path()).await?;
        }
    }
    Ok(())
}
