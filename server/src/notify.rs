use std::env;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use hmac::{Hmac, KeyInit, Mac};
use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{Certificate, Tls, TlsParameters};
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use serde_json::json;
use sha2::Sha256;

use crate::api::AppState;

struct Webhook {
    url: reqwest::Url,
    secret: String,
}

struct Email {
    relay: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
    to: Mailbox,
}

pub struct Notifications {
    public_url: Option<reqwest::Url>,
    webhook: Option<Webhook>,
    email: Option<Email>,
    http: reqwest::Client,
}

pub fn setting(key: &str) -> Option<String> {
    env::var(key).ok().filter(|value| !value.is_empty())
}

fn required(key: &str) -> Result<String> {
    setting(key).with_context(|| format!("{key} must be set"))
}

fn url(raw: &str) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(raw)?;
    let loopback = matches!(url.host_str(), Some("127.0.0.1" | "[::1]" | "localhost"));
    ensure!(url.scheme() == "https" || (url.scheme() == "http" && loopback), "use HTTPS for non-local notification URLs");
    ensure!(url.host().is_some() && url.username().is_empty() && url.password().is_none()
        && url.fragment().is_none(), "invalid notification URL");
    Ok(url)
}

impl Notifications {
    pub fn from_env() -> Result<Self> {
        let webhook = setting("MALICENX_WEBHOOK_URL").map(|address| -> Result<_> {
            let secret = required("MALICENX_WEBHOOK_SECRET")?;
            ensure!(secret.len() >= 32, "webhook secret must have at least 32 bytes");
            Ok(Webhook { url: url(&address)?, secret })
        }).transpose()?;
        let email = setting("MALICENX_SMTP_HOST").map(|host| -> Result<_> {
            let mut relay = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&host)?;
            if let Some(path) = setting("MALICENX_SMTP_CA_FILE") {
                let pem = std::fs::read(path).context("read SMTP CA file")?;
                let tls = TlsParameters::builder(host)
                    .add_root_certificate(Certificate::from_pem(&pem)?)
                    .build()?;
                relay = relay.tls(Tls::Required(tls));
            }
            if let Some(port) = setting("MALICENX_SMTP_PORT") {
                relay = relay.port(port.parse().context("MALICENX_SMTP_PORT")?);
            }
            if let Some(user) = setting("MALICENX_SMTP_USER") {
                relay = relay.credentials(Credentials::new(user, required("MALICENX_SMTP_PASSWORD")?));
            }
            Ok(Email {
                relay: relay.timeout(Some(Duration::from_secs(15))).build(),
                from: required("MALICENX_SMTP_FROM")?.parse()?,
                to: required("MALICENX_SMTP_TO")?.parse()?,
            })
        }).transpose()?;
        let public_url = setting("MALICENX_PUBLIC_URL").map(|address| url(&address)).transpose()?;
        ensure!(email.is_none() || public_url.is_some(), "MALICENX_PUBLIC_URL is required for SMTP");
        let http = reqwest::Client::builder().timeout(Duration::from_secs(15))
            .redirect(reqwest::redirect::Policy::none()).build()?;
        Ok(Self { public_url, webhook, email, http })
    }

    pub fn channels(&self, mail: bool) -> Vec<&'static str> {
        let mut channels = Vec::new();
        if self.webhook.is_some() {
            channels.push("webhook");
        }
        if mail && self.email.is_some() {
            channels.push("email");
        }
        channels
    }

    pub async fn run(s: Arc<AppState>, channel: &'static str) {
        loop {
            match s.store.next_notification(channel) {
                Ok(Some((id, attempts))) => {
                    let delivery = tokio::time::timeout(Duration::from_secs(30), s.notifications.deliver(&s, channel, &id)).await;
                    let delivered = matches!(delivery, Ok(Ok(())));
                    if !delivered {
                        tracing::warn!(scan = %id, channel, attempt = attempts + 1, "notification delivery failed");
                    }
                    if let Err(error) = s.store.record_delivery(&id, channel, attempts, delivered) {
                        tracing::error!(%error, "record notification delivery");
                        tokio::time::sleep(Duration::from_secs(2)).await;
                    }
                }
                Ok(None) => tokio::time::sleep(Duration::from_secs(2)).await,
                Err(error) => {
                    tracing::error!(%error, "read notification queue");
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            }
        }
    }

    async fn deliver(&self, s: &AppState, channel: &str, id: &str) -> Result<()> {
        let scan = s.store.get_scan(id)?.context("scan missing")?.summary;
        let path = format!("/scans/{id}");
        let link = self.public_url.as_ref().map(|base| base.join(&path)).transpose()?;
        if channel == "webhook" {
            let hook = self.webhook.as_ref().context("webhook disabled")?;
            let submission = s.store.submission_details(id)?;
            let body = serde_json::to_vec(&json!({
                "event": "scan.completed",
                "id": id,
                "sha256": scan.file.sha256,
                "verdict": scan.verdict,
                "finished_at": scan.finished_at,
                "source": submission["source"],
                "reference": submission["reference"],
                "report": link.as_ref().map(|url| url.as_str()).unwrap_or(&path)
            }))?;
            let time = chrono::Utc::now().timestamp().to_string();
            let mut mac = Hmac::<Sha256>::new_from_slice(hook.secret.as_bytes()).expect("HMAC accepts any key length");
            mac.update(time.as_bytes());
            mac.update(b".");
            mac.update(&body);
            let signature = hex::encode(mac.finalize().into_bytes());
            let response = self.http.post(hook.url.clone())
                .header("content-type", "application/json")
                .header("x-malicenx-timestamp", time)
                .header("x-malicenx-signature", format!("sha256={signature}"))
                .body(body).send().await?;
            ensure!(response.status().is_success(), "webhook receiver rejected the event");
        } else {
            let mail = self.email.as_ref().context("SMTP disabled")?;
            let verdict = match scan.verdict {
                crate::model::Verdict::Threat => "Threat detected",
                crate::model::Verdict::Clean => "No detections",
                _ => "Scan incomplete",
            };
            let message = Message::builder().from(mail.from.clone()).to(mail.to.clone())
                .subject(format!("MaliceNX: {verdict}"))
                .body(format!("{verdict}\n\nReport: {}\n", link.context("report URL missing")?))?;
            mail.relay.send(message).await?;
        }
        Ok(())
    }
}
