//! SQLite store: one row per scan, one row per engine result.
//! Engines write their own row, so concurrent engines never contend on one document.

use std::sync::Mutex;

use anyhow::Result;
use chrono::{Duration, SecondsFormat, Utc};
use rusqlite::{Connection, OptionalExtension, Row, params, params_from_iter};

use crate::engines::category_of;
use crate::model::*;

#[derive(Default)]
pub struct ScanFilter {
    pub verdict: Option<Verdict>,
    /// Only scans that have not finished.
    pub running: bool,
    /// Only scans created in the last N hours.
    pub since_hours: Option<u32>,
}

pub struct Store {
    db: Mutex<Connection>,
}

const SCHEMA: &str = "
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS scans (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL, size INTEGER NOT NULL, mime TEXT NOT NULL,
  md5 TEXT NOT NULL, sha1 TEXT NOT NULL, sha256 TEXT NOT NULL, sha512 TEXT NOT NULL,
  created_at TEXT NOT NULL, finished_at TEXT
);
CREATE INDEX IF NOT EXISTS scans_created ON scans(created_at);
CREATE TABLE IF NOT EXISTS results (
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  engine TEXT NOT NULL, category TEXT NOT NULL, status TEXT NOT NULL,
  verdict TEXT, signature TEXT, duration_ms INTEGER, error TEXT, data TEXT NOT NULL,
  PRIMARY KEY (scan_id, engine)
);
CREATE TABLE IF NOT EXISTS scan_interruptions (
  id TEXT PRIMARY KEY REFERENCES scans(id)
);
CREATE TABLE IF NOT EXISTS submissions (
  id TEXT PRIMARY KEY REFERENCES scans(id),
  source TEXT NOT NULL, reference TEXT, request_key TEXT,
  mail TEXT,
  UNIQUE(source, request_key)
);
CREATE TABLE IF NOT EXISTS attachments (
  parent TEXT NOT NULL REFERENCES submissions(id),
  child TEXT NOT NULL UNIQUE REFERENCES scans(id)
);
CREATE TABLE IF NOT EXISTS notifications (
  scan_id TEXT NOT NULL REFERENCES submissions(id),
  channel TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  next_attempt INTEGER NOT NULL DEFAULT 0,
  delivered INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (scan_id, channel)
);
";

pub fn now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn day_ago() -> String {
    (Utc::now() - Duration::hours(24)).to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn text<T: serde::Serialize>(v: T) -> String {
    serde_json::to_value(v).ok().and_then(|v| v.as_str().map(String::from)).unwrap_or_default()
}

fn status_of(s: &str) -> ResultStatus {
    match s {
        "ok" => ResultStatus::Ok,
        "error" => ResultStatus::Error,
        "skipped" => ResultStatus::Skipped,
        _ => ResultStatus::Running,
    }
}

fn verdict_of(s: Option<String>) -> Option<ResultVerdict> {
    match s.as_deref() {
        Some("threat") => Some(ResultVerdict::Threat),
        Some("clean") => Some(ResultVerdict::Clean),
        Some("info") => Some(ResultVerdict::Info),
        _ => None,
    }
}

const SCAN_COLS: &str = "id, name, size, mime, md5, sha1, sha256, sha512, created_at, finished_at";

fn scan_row(r: &Row) -> rusqlite::Result<(String, FileInfo, String, Option<String>)> {
    Ok((
        r.get(0)?,
        FileInfo {
            name: r.get(1)?,
            size: r.get(2)?,
            mime: r.get(3)?,
            md5: r.get(4)?,
            sha1: r.get(5)?,
            sha256: r.get(6)?,
            sha512: r.get(7)?,
        },
        r.get(8)?,
        r.get(9)?,
    ))
}

pub struct Submission<'a> {
    pub file: &'a FileInfo,
    pub source: &'a str,
    pub reference: Option<&'a str>,
    pub key: Option<&'a str>,
    pub mail: Option<&'a serde_json::Value>,
    pub attachments: &'a [FileInfo],
    pub channels: &'a [&'a str],
}

fn insert_scan(db: &Connection, file: &FileInfo, engines: &[&str]) -> Result<String> {
    let id = uuid::Uuid::new_v4().to_string();
    db.execute(
        &format!("INSERT INTO scans ({SCAN_COLS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL)"),
        params![id, file.name, file.size, file.mime, file.md5, file.sha1, file.sha256, file.sha512, now()],
    )?;
    for e in engines {
        db.execute(
            "INSERT INTO results (scan_id, engine, category, status, data) VALUES (?1, ?2, ?3, 'running', 'null')",
            params![id, e, text(category_of(e))],
        )?;
    }
    Ok(id)
}

impl Store {
    pub fn open(path: &str) -> Result<Self> {
        let db = Connection::open(path)?;
        db.execute_batch(SCHEMA)?;
        Ok(Self { db: Mutex::new(db) })
    }

    /// Creates the scan with a `running` row per engine and returns its id.
    pub fn create_scan(&self, file: &FileInfo, engines: &[&str]) -> Result<String> {
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction()?;
        let id = insert_scan(&tx, file, engines)?;
        tx.commit()?;
        Ok(id)
    }

    pub fn submit(&self, submission: Submission<'_>) -> Result<Option<(String, Option<Vec<String>>)>> {
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction()?;
        if let Some(key) = submission.key {
            let existing: Option<(String, String, Option<String>, bool)> = tx.query_row(
                "SELECT s.id, s.sha256, p.reference, p.mail IS NOT NULL
                 FROM submissions p JOIN scans s ON s.id = p.id WHERE source = ?1 AND request_key = ?2",
                params![submission.source, key],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            ).optional()?;
            if let Some((id, sha, reference, mail)) = existing {
                return Ok((sha == submission.file.sha256 && reference.as_deref() == submission.reference
                    && mail == submission.mail.is_some()).then_some((id, None)));
            }
        }

        let mut engines = crate::engines::ENGINES.to_vec();
        if submission.mail.is_some() {
            engines.push("mail-attachments");
        }
        let id = insert_scan(&tx, submission.file, &engines)?;
        tx.execute(
            "INSERT INTO submissions (id, source, reference, request_key, mail) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![id, submission.source, submission.reference, submission.key, submission.mail.map(serde_json::Value::to_string)],
        )?;
        let mut children = Vec::new();
        for file in submission.attachments {
            let child = insert_scan(&tx, file, &crate::engines::ENGINES)?;
            tx.execute("INSERT INTO attachments VALUES (?1, ?2)", params![id, child])?;
            children.push(child);
        }
        for channel in submission.channels {
            tx.execute("INSERT INTO notifications (scan_id, channel) VALUES (?1, ?2)", params![id, channel])?;
        }
        tx.commit()?;
        Ok(Some((id, Some(children))))
    }

    pub fn next_notification(&self, channel: &str) -> Result<Option<(String, u32)>> {
        Ok(self.db.lock().unwrap().query_row(
            "SELECT n.scan_id, n.attempts FROM notifications n JOIN scans s ON s.id = n.scan_id
             WHERE n.channel = ?1 AND n.delivered = 0 AND n.attempts < 5
               AND n.next_attempt <= unixepoch() AND s.finished_at IS NOT NULL
             ORDER BY n.next_attempt, s.finished_at LIMIT 1",
            [channel], |r| Ok((r.get(0)?, r.get(1)?)),
        ).optional()?)
    }

    pub fn record_delivery(&self, id: &str, channel: &str, attempts: u32, delivered: bool) -> Result<()> {
        self.db.lock().unwrap().execute(
            "UPDATE notifications SET attempts = ?3, delivered = ?4, next_attempt = unixepoch() + ?5
             WHERE scan_id = ?1 AND channel = ?2",
            params![id, channel, attempts + 1, delivered, 10_i64 << attempts],
        )?;
        Ok(())
    }

    pub fn put_result(&self, scan_id: &str, r: &EngineResult) -> Result<()> {
        self.db.lock().unwrap().execute(
            "INSERT OR REPLACE INTO results (scan_id, engine, category, status, verdict, signature, duration_ms, error, data)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                scan_id,
                r.engine,
                text(r.category),
                text(r.status),
                r.verdict.map(text),
                r.signature,
                r.duration_ms,
                r.error,
                r.data.to_string()
            ],
        )?;
        Ok(())
    }

    pub fn finish_scan(&self, scan_id: &str) -> Result<()> {
        self.db.lock().unwrap().execute("UPDATE scans SET finished_at = ?2 WHERE id = ?1", params![scan_id, now()])?;
        Ok(())
    }

    /// Scans left running by a previous process can never finish; close them.
    pub fn recover_interrupted(&self) -> Result<usize> {
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction()?;
        tx.execute(
            "INSERT OR IGNORE INTO scan_interruptions
             SELECT id FROM scans WHERE finished_at IS NULL
             UNION SELECT scan_id FROM results WHERE error = 'server restarted during scan'",
            [],
        )?;
        tx.execute(
            "UPDATE results SET status = 'error', error = 'server restarted during scan'
             WHERE status = 'running'",
            [],
        )?;
        tx.execute(
            "UPDATE results SET verdict = 'threat', signature = 'Threat in mail attachment'
             WHERE engine = 'mail-attachments' AND status = 'error'
               AND EXISTS (SELECT 1 FROM attachments a JOIN results child ON child.scan_id = a.child
                           WHERE a.parent = results.scan_id AND child.verdict = 'threat')",
            [],
        )?;
        let count = tx.execute("UPDATE scans SET finished_at = ?1 WHERE finished_at IS NULL", params![now()])?;
        tx.commit()?;
        Ok(count)
    }

    pub fn get_scan(&self, id: &str) -> Result<Option<ScanDetail>> {
        let db = self.db.lock().unwrap();
        let Some(row) = db
            .query_row(&format!("SELECT {SCAN_COLS} FROM scans WHERE id = ?1"), [id], scan_row)
            .optional()?
        else {
            return Ok(None);
        };
        Ok(Some(detail(&db, row)?))
    }

    pub fn submission_details(&self, id: &str) -> Result<serde_json::Value> {
        let db = self.db.lock().unwrap();
        let info: Option<(String, Option<String>, Option<String>)> = db.query_row(
            "SELECT source, reference, mail FROM submissions WHERE id = ?1",
            [id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        ).optional()?;
        let Some((source, reference, mail)) = info else { return Ok(serde_json::Value::Null) };
        let mail = if let Some(mail) = mail {
            let mut mail: serde_json::Value = serde_json::from_str(&mail)?;
            let cols = SCAN_COLS.split(", ").map(|col| format!("s.{col}")).collect::<Vec<_>>().join(", ");
            let mut stmt = db.prepare(&format!(
                "SELECT {cols} FROM attachments a JOIN scans s ON s.id = a.child WHERE a.parent = ?1 ORDER BY a.rowid"
            ))?;
            let rows = stmt.query_map([id], scan_row)?.collect::<rusqlite::Result<Vec<_>>>()?;
            let children = rows.into_iter().map(|row| detail(&db, row).map(|d| d.summary)).collect::<Result<Vec<_>>>()?;
            mail["attachments"] = serde_json::to_value(children)?;
            mail
        } else {
            serde_json::Value::Null
        };
        let mut stmt = db.prepare("SELECT channel, delivered, attempts FROM notifications WHERE scan_id = ?1 ORDER BY channel")?;
        let notifications = stmt.query_map([id], |r| {
            let channel: String = r.get(0)?;
            let delivered: bool = r.get(1)?;
            let attempts: u32 = r.get(2)?;
            let status = if delivered { "delivered" } else if attempts >= 5 { "failed" } else { "pending" };
            Ok(serde_json::json!({ "channel": channel, "status": status, "attempts": attempts }))
        })?.collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(serde_json::json!({ "source": source, "reference": reference, "mail": mail, "notifications": notifications }))
    }

    /// Newest first. `ids` restricts the page to those scans (search hits); `Some(&[])` means no hits.
    pub fn list(&self, ids: Option<&[String]>, filter: &ScanFilter, from: usize, size: usize) -> Result<(usize, Vec<ScanSummary>)> {
        let db = self.db.lock().unwrap();
        let mut clauses: Vec<String> = Vec::new();
        let mut args: Vec<String> = Vec::new();
        match ids {
            Some([]) => return Ok((0, vec![])),
            Some(ids) => {
                clauses.push(format!("id IN ({})", vec!["?"; ids.len()].join(",")));
                args.extend(ids.iter().cloned());
            }
            None => {}
        }
        const HAS_THREAT: &str = "EXISTS (SELECT 1 FROM results r WHERE r.scan_id = scans.id AND r.verdict = 'threat')";
        const COVERED: &str = "(EXISTS (SELECT 1 FROM results r WHERE r.scan_id = scans.id AND r.category = 'av') AND NOT EXISTS (SELECT 1 FROM results r WHERE r.scan_id = scans.id AND r.category = 'av' AND r.status <> 'ok') AND NOT EXISTS (SELECT 1 FROM scan_interruptions i WHERE i.id = scans.id))";
        match filter.verdict {
            Some(Verdict::Threat) => clauses.push(HAS_THREAT.into()),
            Some(Verdict::Clean) => clauses.push(format!("finished_at IS NOT NULL AND NOT {HAS_THREAT} AND {COVERED}")),
            Some(Verdict::Incomplete) => clauses.push(format!("finished_at IS NOT NULL AND NOT {HAS_THREAT} AND NOT {COVERED}")),
            Some(Verdict::Pending) => clauses.push(format!("finished_at IS NULL AND NOT {HAS_THREAT}")),
            None => {}
        }
        if filter.running {
            clauses.push("finished_at IS NULL".into());
        }
        if let Some(h) = filter.since_hours {
            clauses.push("created_at >= ?".into());
            args.push((Utc::now() - Duration::hours(h as i64)).to_rfc3339_opts(SecondsFormat::Millis, true));
        }
        let filter = if clauses.is_empty() { String::new() } else { format!("WHERE {}", clauses.join(" AND ")) };
        let total: usize = db.query_row(&format!("SELECT COUNT(*) FROM scans {filter}"), params_from_iter(&args), |r| r.get(0))?;
        let mut stmt = db.prepare(&format!(
            "SELECT {SCAN_COLS} FROM scans {filter} ORDER BY created_at DESC, rowid DESC LIMIT {size} OFFSET {from}"
        ))?;
        let rows = stmt.query_map(params_from_iter(&args), scan_row)?.collect::<rusqlite::Result<Vec<_>>>()?;
        let scans = rows.into_iter().map(|row| detail(&db, row).map(|d| d.summary)).collect::<Result<_>>()?;
        Ok((total, scans))
    }

    /// Scans whose MD5, SHA-1, SHA-256 or SHA-512 starts with `q`. Only for hex input of 8+ characters;
    /// the full-text index cannot hold hashes longer than its 40-character token limit.
    pub fn ids_by_hash_prefix(&self, q: &str) -> Result<Vec<String>> {
        if q.len() < 8 || q.len() > 128 || !q.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Ok(vec![]);
        }
        let like = format!("{}%", q.to_ascii_lowercase());
        let db = self.db.lock().unwrap();
        let mut stmt = db.prepare_cached(
            "SELECT id FROM scans WHERE md5 LIKE ?1 OR sha1 LIKE ?1 OR sha256 LIKE ?1 OR sha512 LIKE ?1 LIMIT 1000",
        )?;
        let ids = stmt.query_map([like], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?;
        Ok(ids)
    }

    pub fn stats(&self) -> Result<Stats> {
        let db = self.db.lock().unwrap();
        let since = day_ago();
        let count = |sql: &str| -> Result<u64> { Ok(db.query_row(sql, [&since], |r| r.get(0))?) };
        Ok(Stats {
            scans_total: db.query_row("SELECT COUNT(*) FROM scans", [], |r| r.get(0))?,
            scans_24h: count("SELECT COUNT(*) FROM scans WHERE created_at >= ?1")?,
            threats_24h: count(
                "SELECT COUNT(DISTINCT s.id) FROM scans s JOIN results r ON r.scan_id = s.id
                 WHERE s.created_at >= ?1 AND r.verdict = 'threat'",
            )?,
            running: db.query_row("SELECT COUNT(*) FROM scans WHERE finished_at IS NULL", [], |r| r.get(0))?,
            avg_duration_ms: db.query_row(
                "SELECT CAST(AVG((julianday(finished_at) - julianday(created_at)) * 86400000) AS INTEGER)
                 FROM scans WHERE finished_at IS NOT NULL AND created_at >= ?1",
                [&since],
                |r| r.get(0),
            )?,
        })
    }
}

fn detail(db: &Connection, (id, file, created_at, finished_at): (String, FileInfo, String, Option<String>)) -> Result<ScanDetail> {
    let mut stmt = db.prepare_cached(
        "SELECT engine, category, status, verdict, signature, duration_ms, error, data
         FROM results WHERE scan_id = ?1 ORDER BY category, engine",
    )?;
    let results = stmt
        .query_map([&id], |r| {
            Ok(EngineResult {
                engine: r.get(0)?,
                category: if r.get::<_, String>(1)? == "intel" { Category::Intel } else { Category::Av },
                status: status_of(&r.get::<_, String>(2)?),
                verdict: verdict_of(r.get(3)?),
                signature: r.get(4)?,
                duration_ms: r.get(5)?,
                error: r.get(6)?,
                data: serde_json::from_str(&r.get::<_, String>(7)?).unwrap_or_default(),
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    let detections: Vec<Detection> = results
        .iter()
        .filter(|r| r.verdict == Some(ResultVerdict::Threat))
        .map(|r| Detection { engine: r.engine.clone(), name: r.signature.clone().unwrap_or_else(|| "detected".into()) })
        .collect();
    let done = finished_at.is_some();
    let interrupted: bool = db.query_row(
        "SELECT EXISTS (SELECT 1 FROM scan_interruptions WHERE id = ?1)", [&id], |row| row.get(0),
    )?;
    let verdict = match (detections.is_empty(), done) {
        (false, _) => Verdict::Threat,
        (true, true) if !interrupted && results.iter().any(|r| r.category == Category::Av)
            && results.iter().filter(|r| r.category == Category::Av).all(|r| r.status == ResultStatus::Ok) => Verdict::Clean,
        (true, true) => Verdict::Incomplete,
        (true, false) => Verdict::Pending,
    };
    Ok(ScanDetail {
        summary: ScanSummary {
            id,
            file,
            created_at,
            finished_at,
            status: if done { "done" } else { "running" },
            verdict,
            engines_expected: results.len(),
            engines_reported: results.iter().filter(|r| r.status != ResultStatus::Running).count(),
            detections,
        },
        results,
    })
}
