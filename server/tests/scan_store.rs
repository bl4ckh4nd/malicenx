//! In-process checks of the store, verdict rules, search and engine reply parsing.
//! No network, no clamd, no browser.

use malicenx::engines::{clamd_verdict, hashlookup_verdict, virustotal_verdict};
use malicenx::model::{Category, EngineResult, FileInfo, ResultStatus, ResultVerdict, Verdict};
use malicenx::search::Index;
use malicenx::store::{ScanFilter, Store};
use serde_json::json;

fn eicar() -> FileInfo {
    FileInfo {
        name: "eicar.com".into(),
        size: 68,
        mime: "text/plain".into(),
        md5: "44d88612fea8a8f36de82e1278abb02f".into(),
        sha1: "3395856ce81f2b7382dee72602f798b642f14140".into(),
        sha256: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f".into(),
        sha512: "cc80".into(),
    }
}

fn result(engine: &str, status: ResultStatus, verdict: Option<ResultVerdict>, sig: Option<&str>) -> EngineResult {
    EngineResult {
        engine: engine.into(),
        category: Category::Av,
        status,
        verdict,
        signature: sig.map(Into::into),
        duration_ms: Some(5),
        error: None,
        data: json!({}),
    }
}

#[test]
fn scan_moves_from_pending_to_threat_and_is_searchable() {
    let store = Store::open(":memory:").unwrap();
    let id = store.create_scan(&eicar(), &["clamav", "yara", "virustotal"]).unwrap();

    let s = store.get_scan(&id).unwrap().unwrap();
    assert_eq!(s.summary.verdict, Verdict::Pending);
    assert_eq!(s.summary.engines_expected, 3);
    assert_eq!(s.summary.engines_reported, 0);
    assert!(s.results.iter().all(|r| r.status == ResultStatus::Running));

    store.put_result(&id, &result("clamav", ResultStatus::Ok, Some(ResultVerdict::Threat), Some("Eicar-Signature"))).unwrap();
    // A threat shows up before the scan is done.
    let s = store.get_scan(&id).unwrap().unwrap();
    assert_eq!(s.summary.verdict, Verdict::Threat);
    assert_eq!(s.summary.engines_reported, 1);

    store.put_result(&id, &result("yara", ResultStatus::Ok, Some(ResultVerdict::Clean), None)).unwrap();
    let mut skipped = result("virustotal", ResultStatus::Skipped, None, None);
    skipped.error = Some("VIRUSTOTAL_API_KEY not set".into());
    store.put_result(&id, &skipped).unwrap();
    store.finish_scan(&id).unwrap();

    let s = store.get_scan(&id).unwrap().unwrap();
    assert_eq!(s.summary.status, "done");
    assert!(s.summary.finished_at.is_some());
    assert_eq!(s.summary.engines_reported, 3);
    assert_eq!(s.summary.detections.len(), 1);
    assert_eq!(s.summary.detections[0].name, "Eicar-Signature");

    let stats = store.stats().unwrap();
    assert_eq!((stats.scans_total, stats.scans_24h, stats.threats_24h, stats.running), (1, 1, 1, 0));

    let index = Index::in_memory().unwrap();
    index.put(&s.summary).unwrap();
    for q in ["eicar", "Eicar-Signature", "44d88612fea8a8f36de82e1278abb02f"] {
        assert_eq!(index.search(q, 100).unwrap(), vec![id.clone()], "query {q}");
    }
    assert!(index.search("nothing-like-this", 100).unwrap().is_empty());
    // Typing in the search box: word prefixes match.
    assert_eq!(index.search("eica", 100).unwrap(), vec![id.clone()]);

    // Long hashes exceed the tokenizer's token limit; the store answers hex queries by prefix.
    let f = eicar();
    for q in [f.sha256.as_str(), &f.sha1, &f.md5, "275a021b", "3395856CE81F"] {
        assert_eq!(store.ids_by_hash_prefix(q).unwrap(), vec![id.clone()], "hash query {q}");
    }
    assert!(store.ids_by_hash_prefix("275a0").unwrap().is_empty(), "too short to be a hash");
    assert!(store.ids_by_hash_prefix("eicar").unwrap().is_empty(), "not hex");

    let all = ScanFilter::default();
    let (total, page) = store.list(None, &all, 0, 20).unwrap();
    assert_eq!((total, page.len()), (1, 1));
    let (total, page) = store.list(Some(&[]), &all, 0, 20).unwrap();
    assert_eq!((total, page.len()), (0, 0));
}

#[test]
fn list_filters_by_verdict_status_and_age() {
    let store = Store::open(":memory:").unwrap();
    let threat_running = store.create_scan(&eicar(), &["clamav", "yara"]).unwrap();
    store.put_result(&threat_running, &result("clamav", ResultStatus::Ok, Some(ResultVerdict::Threat), Some("X"))).unwrap();
    let pending = store.create_scan(&eicar(), &["clamav"]).unwrap();
    let clean = store.create_scan(&eicar(), &["clamav"]).unwrap();
    store.put_result(&clean, &result("clamav", ResultStatus::Ok, Some(ResultVerdict::Clean), None)).unwrap();
    store.finish_scan(&clean).unwrap();

    let ids = |f: ScanFilter| -> Vec<String> { store.list(None, &f, 0, 20).unwrap().1.into_iter().map(|s| s.id).collect() };
    assert_eq!(ids(ScanFilter { verdict: Some(Verdict::Threat), ..Default::default() }), vec![threat_running.clone()]);
    assert_eq!(ids(ScanFilter { verdict: Some(Verdict::Pending), ..Default::default() }), vec![pending.clone()]);
    assert_eq!(ids(ScanFilter { verdict: Some(Verdict::Clean), ..Default::default() }), vec![clean.clone()]);
    // "Running" includes a running scan that already has a detection.
    let mut running = ids(ScanFilter { running: true, ..Default::default() });
    running.sort();
    let mut expected = vec![threat_running, pending];
    expected.sort();
    assert_eq!(running, expected);
    assert_eq!(ids(ScanFilter { since_hours: Some(24), ..Default::default() }).len(), 3);
}

#[test]
fn clean_scan_without_detections_is_clean_once_done() {
    let store = Store::open(":memory:").unwrap();
    let id = store.create_scan(&eicar(), &["clamav"]).unwrap();
    store.put_result(&id, &result("clamav", ResultStatus::Ok, Some(ResultVerdict::Clean), None)).unwrap();
    assert_eq!(store.get_scan(&id).unwrap().unwrap().summary.verdict, Verdict::Pending);
    store.finish_scan(&id).unwrap();
    assert_eq!(store.get_scan(&id).unwrap().unwrap().summary.verdict, Verdict::Clean);
}

#[test]
fn engine_replies_map_to_verdicts() {
    assert_eq!(clamd_verdict("stream: Eicar-Signature FOUND").unwrap(), (ResultVerdict::Threat, Some("Eicar-Signature".into())));
    assert_eq!(clamd_verdict("stream: OK").unwrap(), (ResultVerdict::Clean, None));
    assert!(clamd_verdict("INSTREAM size limit exceeded. ERROR").is_err());

    // CIRCL hashlookup: a KnownMalicious source is a threat; listed or unknown files are only info.
    assert_eq!(hashlookup_verdict(Some(&json!({"FileName": "ls"}))), (ResultVerdict::Info, None));
    assert_eq!(
        hashlookup_verdict(Some(&json!({"KnownMalicious": "malshare.com"}))),
        (ResultVerdict::Threat, Some("KnownMalicious: malshare.com".into()))
    );
    assert_eq!(hashlookup_verdict(None), (ResultVerdict::Info, None));

    let vt = json!({"data": {"attributes": {"last_analysis_stats": {"malicious": 61, "suspicious": 0, "undetected": 10, "harmless": 0},
        "popular_threat_classification": {"suggested_threat_label": "virus.eicar/test"}}}});
    assert_eq!(virustotal_verdict(Some(&vt)), (ResultVerdict::Threat, Some("virus.eicar/test (61/71)".into())));
    let vt_clean = json!({"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "suspicious": 0, "undetected": 70, "harmless": 0}}}});
    assert_eq!(virustotal_verdict(Some(&vt_clean)), (ResultVerdict::Clean, None));
    assert_eq!(virustotal_verdict(None), (ResultVerdict::Info, None));
}

#[test]
fn broken_rule_file_is_skipped_and_the_rest_still_loads() {
    let dir = std::env::temp_dir().join(format!("malicenx-rules-{}", std::process::id()));
    std::fs::create_dir_all(dir.join("sub")).unwrap();
    std::fs::copy(concat!(env!("CARGO_MANIFEST_DIR"), "/../rules/eicar.yar"), dir.join("sub/eicar.yar")).unwrap();
    std::fs::write(dir.join("broken.yar"), "rule broken { condition: nope }").unwrap();
    std::fs::write(dir.join("notes.txt"), "not a rule").unwrap();
    let rules = malicenx::engines::load_rules(&dir).unwrap().expect("eicar rule compiles");
    assert_eq!(rules.iter().len(), 1);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn interrupted_or_failed_required_engine_never_produces_clean() {
    let store = Store::open(":memory:").unwrap();
    let interrupted = store.create_scan(&eicar(), &["clamav", "yara"]).unwrap();
    let optional_error = store.create_scan(&eicar(), &["clamav", "hashlookup"]).unwrap();
    store.put_result(&optional_error, &result("clamav", ResultStatus::Ok, Some(ResultVerdict::Clean), None)).unwrap();
    let mut lookup = result("hashlookup", ResultStatus::Error, None, None);
    lookup.category = Category::Intel;
    store.put_result(&optional_error, &lookup).unwrap();
    store.finish_scan(&optional_error).unwrap();
    assert_eq!(store.recover_interrupted().unwrap(), 1);
    let clean = ScanFilter { verdict: Some(Verdict::Clean), ..Default::default() };
    assert_eq!(store.list(None, &clean, 0, 20).unwrap().0, 1);
    assert_ne!(store.get_scan(&interrupted).unwrap().unwrap().summary.verdict, Verdict::Clean);
}
