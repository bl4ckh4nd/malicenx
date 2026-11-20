use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use sha2::{Digest, Sha256};
use smtpd::{Error, Response, Session, SmtpConfig, SmtpHandler, SmtpHandlerFactory};
use tokio::sync::OwnedSemaphorePermit;

use crate::api::{AppState, MAX_MAIL, capacity, submit_mail};

struct Intake {
    state: Arc<AppState>,
    recipient: Arc<str>,
}

struct Connection {
    state: Arc<AppState>,
    recipient: Arc<str>,
    permit: Option<OwnedSemaphorePermit>,
}

pub async fn serve(state: Arc<AppState>, listen: String, recipient: String) -> std::io::Result<()> {
    let config = SmtpConfig {
        bind_addr: listen,
        hostname: "malicenx.local".into(),
        max_message_size: Some(MAX_MAIL),
        max_recipients: 1,
        timeout: Duration::from_secs(30),
        disable_reverse_dns: true,
        ..Default::default()
    };
    smtpd::start_server(config, Intake { state, recipient: recipient.into() }).await
}

impl SmtpHandlerFactory for Intake {
    type Handler = Connection;

    fn new_handler(&self, _: &Session) -> Connection {
        Connection { state: self.state.clone(), recipient: self.recipient.clone(), permit: None }
    }
}

#[smtpd::async_trait]
impl SmtpHandler for Connection {
    async fn handle_rcpt(&mut self, _: &Session, address: &str) -> smtpd::Result {
        if !self.recipient.eq_ignore_ascii_case(address) {
            return Err(reject(550, "Recipient unavailable", "5.1.1"));
        }
        if self.permit.is_none() {
            self.permit = Some(capacity(&self.state).map_err(|_| reject(452, "Scan queue is full", "4.3.1"))?);
        }
        Ok(Response::default())
    }

    async fn handle_email(&mut self, _: &Session, bytes: Vec<u8>) -> smtpd::Result {
        let permit = self.permit.take().ok_or_else(|| reject(451, "Retry submission", "4.3.0"))?;
        let mut headers = HeaderMap::new();
        let digest = hex::encode(Sha256::digest(&bytes));
        headers.insert("idempotency-key", HeaderValue::from_str(&digest).expect("hex is valid ASCII"));
        match submit_mail(self.state.clone(), permit, &headers, "smtp", "message.eml".into(), &bytes).await {
            Ok((_, Json(receipt))) => {
                let report = receipt["report"].as_str().expect("submission receipt includes its report path");
                Ok(Response::ok(format!("Accepted for scanning {report}")))
            }
            Err(error) if error.0 == StatusCode::UNPROCESSABLE_ENTITY => {
                Err(reject(554, "Invalid or unsupported MIME message", "5.6.0"))
            }
            Err(_) => Err(reject(451, "Scan submission failed; retry later", "4.3.0")),
        }
    }
}

fn reject(status: usize, message: &'static str, enhanced: &'static str) -> Error {
    Error::Response(Response::new(status, message, Some(enhanced.into())))
}
