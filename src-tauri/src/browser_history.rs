//! Local browser history IOC scan (Windows). Read-only: copies SQLite DBs before opening.

use crate::abuse_ch::{AbuseChIndex, AbuseChSource};
use crate::dev_infra::{parse_http_url, DevInfraIndex};
use crate::event_log::{log as log_event, EventKind};
use crate::ioc::IocIndex;
use crate::AppState;
use rusqlite::{Connection, OpenFlags};
use serde::Serialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

const CHROME_EPOCH_OFFSET_MICROS: i64 = 11_644_473_600_000_000;
const FOURTEEN_DAYS_SECS: i64 = 14 * 86_400;
const PER_BROWSER_CAP: usize = 5000;
const FINDINGS_CAP: usize = 5000;

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct HistoryFinding {
    pub id: i64,
    pub browser: String,
    pub profile: String,
    pub url: String,
    pub host: String,
    pub title: Option<String>,
    pub last_visit_at: String,
    pub matched_categories: Vec<String>,
    pub source_label: Option<String>,
    pub severity: String,
    pub score: i32,
}

pub struct HistoryFindingRow {
    pub browser: String,
    pub profile: String,
    pub url: String,
    pub host: String,
    pub title: Option<String>,
    pub last_visit_at: String,
    pub matched_categories: Vec<String>,
    pub source_label: Option<String>,
    pub severity: String,
    pub score: i32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserHistoryScanResult {
    pub scanned_at: String,
    pub browsers_scanned: Vec<String>,
    pub total_findings: u32,
    pub urls_scanned: u32,
    pub by_category: HashMap<String, u32>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DevInfraMeta {
    pub category_counts: HashMap<String, u32>,
    pub snapshot_date: String,
}

pub(crate) fn severity_rank(s: &str) -> u8 {
    match s {
        "high" => 3,
        "warn" => 2,
        "low" => 1,
        _ => 0,
    }
}

pub(crate) fn strongest_severity(a: &str, b: &str) -> String {
    if severity_rank(a) >= severity_rank(b) {
        a.to_string()
    } else {
        b.to_string()
    }
}

// internal helper; refactoring to a struct adds boilerplate without behavior change
#[allow(clippy::too_many_arguments)]
fn aggregate_matches(
    browser: String,
    profile: String,
    url: String,
    host: String,
    title: Option<String>,
    last_visit_at: String,
    ioc: &IocIndex,
    dev_matches: Vec<crate::dev_infra::DevInfraMatch>,
    abuse_ch: &AbuseChIndex,
) -> Option<HistoryFinding> {
    let stalk = ioc.host_matches_domain(&host);
    let mut categories: Vec<String> = Vec::new();
    let mut score: i32 = 0;
    let mut severity = "info".to_string();
    let mut source_label: Option<String> = None;

    if let Some(dom) = stalk {
        categories.push("stalkerware".into());
        score = score.saturating_add(45);
        severity = strongest_severity(&severity, "high");
        source_label = Some(dom);
    }

    for m in &dev_matches {
        if !categories.contains(&m.category) {
            categories.push(m.category.clone());
        }
        score = score.saturating_add(m.score_delta).min(100);
        severity = strongest_severity(&severity, m.severity);
    }

    if let Some(rec) = abuse_ch.match_url(&url) {
        let cat = match rec.source {
            AbuseChSource::UrlHaus => "abuse-ch-urlhaus",
            AbuseChSource::ThreatFox => "abuse-ch-threatfox",
            AbuseChSource::MalwareBazaar => "abuse-ch-threatfox",
        };
        if !categories.iter().any(|c| c == cat) {
            categories.push(cat.into());
        }
        score = score.saturating_add(35).min(100);
        severity = strongest_severity(&severity, "high");
        if source_label.is_none() {
            source_label = rec
                .family
                .clone()
                .or_else(|| Some(rec.source.label().into()));
        }
    }

    if categories.is_empty() {
        return None;
    }

    score = score.min(100);

    Some(HistoryFinding {
        id: 0,
        browser,
        profile,
        url,
        host,
        title,
        last_visit_at,
        matched_categories: categories,
        source_label,
        severity,
        score,
    })
}

pub(crate) fn unix_micros_to_rfc3339(us: i64) -> Option<String> {
    chrono::DateTime::from_timestamp_micros(us).map(|dt| dt.to_rfc3339())
}

pub(crate) fn chrome_micros_to_rfc3339(chrome_us: i64) -> Option<String> {
    let unix_us = chrome_us.checked_sub(CHROME_EPOCH_OFFSET_MICROS)?;
    unix_micros_to_rfc3339(unix_us)
}

fn cutoff_chrome_micros() -> i64 {
    let now = chrono::Utc::now().timestamp_micros();
    let cutoff_unix = now - FOURTEEN_DAYS_SECS * 1_000_000;
    cutoff_unix.saturating_add(CHROME_EPOCH_OFFSET_MICROS)
}

fn cutoff_firefox_micros() -> i64 {
    chrono::Utc::now().timestamp_micros() - FOURTEEN_DAYS_SECS * 1_000_000
}

fn copy_open_sqlite(src: &Path) -> Option<Connection> {
    let tmp = std::env::temp_dir().join(format!(
        "spy-detector-bh-{}-{}.sqlite",
        std::process::id(),
        chrono::Utc::now().timestamp_micros()
    ));
    if std::fs::copy(src, &tmp).is_err() {
        eprintln!(
            "spy-detector: browser history copy failed for {}",
            src.display()
        );
        return None;
    }
    Connection::open_with_flags(&tmp, OpenFlags::SQLITE_OPEN_READ_ONLY).ok()
}

fn chromium_history_paths(user_data: &Path) -> Vec<(String, PathBuf)> {
    let mut out: Vec<(String, PathBuf)> = Vec::new();
    let default_hist = user_data.join("Default").join("History");
    if default_hist.is_file() {
        out.push(("Default".into(), default_hist));
    }
    if let Ok(rd) = std::fs::read_dir(user_data) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if name == "Default" {
                continue;
            }
            if name.starts_with("Profile ") {
                let p = e.path().join("History");
                if p.is_file() {
                    out.push((name, p));
                }
            }
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

fn firefox_places_paths() -> Vec<(String, PathBuf)> {
    let mut out = Vec::new();
    let Ok(appdata) = std::env::var("APPDATA") else {
        return out;
    };
    let profiles_root = Path::new(&appdata)
        .join("Mozilla")
        .join("Firefox")
        .join("Profiles");
    let Ok(rd) = std::fs::read_dir(&profiles_root) else {
        return out;
    };
    for e in rd.flatten() {
        let p = e.path().join("places.sqlite");
        if p.is_file() {
            let label = e.file_name().to_string_lossy().into_owned();
            out.push((label, p));
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

fn scan_chromium_file(
    browser_label: &str,
    profile: &str,
    hist_path: &Path,
    cutoff: i64,
    ioc: &IocIndex,
    dev_infra: &DevInfraIndex,
    abuse_ch: &AbuseChIndex,
) -> (u32, Vec<HistoryFinding>) {
    let Some(conn) = copy_open_sqlite(hist_path) else {
        return (0, Vec::new());
    };
    let sql = "SELECT url, title, last_visit_time FROM urls WHERE last_visit_time >= ?1 ORDER BY last_visit_time DESC LIMIT ?2";
    let Ok(mut stmt) = conn.prepare(sql) else {
        return (0, Vec::new());
    };
    let rows = stmt.query_map(rusqlite::params![cutoff, PER_BROWSER_CAP as i64], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, Option<String>>(1)?,
            r.get::<_, i64>(2)?,
        ))
    });
    let Ok(rows) = rows else {
        return (0, Vec::new());
    };
    let mut n_urls = 0u32;
    let mut findings = Vec::new();
    for row in rows.flatten() {
        n_urls += 1;
        let (url, title, chrome_us) = row;
        let Some((host, path)) = parse_http_url(&url) else {
            continue;
        };
        let Some(last_visit_at) = chrome_micros_to_rfc3339(chrome_us) else {
            continue;
        };
        let dev_m = dev_infra.match_host_path(&host, &path);
        if let Some(f) = aggregate_matches(
            browser_label.into(),
            profile.into(),
            url,
            host,
            title,
            last_visit_at,
            ioc,
            dev_m,
            abuse_ch,
        ) {
            findings.push(f);
        }
    }
    (n_urls, findings)
}

fn scan_firefox_file(
    profile: &str,
    places_path: &Path,
    cutoff: i64,
    ioc: &IocIndex,
    dev_infra: &DevInfraIndex,
    abuse_ch: &AbuseChIndex,
) -> (u32, Vec<HistoryFinding>) {
    let Some(conn) = copy_open_sqlite(places_path) else {
        return (0, Vec::new());
    };
    let sql = "SELECT url, title, last_visit_date FROM moz_places WHERE last_visit_date IS NOT NULL AND last_visit_date >= ?1 ORDER BY last_visit_date DESC LIMIT ?2";
    let Ok(mut stmt) = conn.prepare(sql) else {
        return (0, Vec::new());
    };
    let rows = stmt.query_map(rusqlite::params![cutoff, PER_BROWSER_CAP as i64], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, Option<String>>(1)?,
            r.get::<_, i64>(2)?,
        ))
    });
    let Ok(rows) = rows else {
        return (0, Vec::new());
    };
    let mut n_urls = 0u32;
    let mut findings = Vec::new();
    for row in rows.flatten() {
        n_urls += 1;
        let (url, title, ff_us) = row;
        let Some((host, path)) = parse_http_url(&url) else {
            continue;
        };
        let Some(last_visit_at) = unix_micros_to_rfc3339(ff_us) else {
            continue;
        };
        let dev_m = dev_infra.match_host_path(&host, &path);
        if let Some(f) = aggregate_matches(
            "Firefox".into(),
            profile.into(),
            url,
            host,
            title,
            last_visit_at,
            ioc,
            dev_m,
            abuse_ch,
        ) {
            findings.push(f);
        }
    }
    (n_urls, findings)
}

pub fn scan_browser_history_disk(
    ioc: &IocIndex,
    dev_infra: &DevInfraIndex,
    abuse_ch: &AbuseChIndex,
) -> (BrowserHistoryScanResult, Vec<HistoryFinding>) {
    let mut browsers_scanned: Vec<String> = Vec::new();
    let mut urls_scanned = 0u32;
    let mut findings: Vec<HistoryFinding> = Vec::new();

    let cutoff_chrome = cutoff_chrome_micros();
    let cutoff_ff = cutoff_firefox_micros();

    let Ok(local) = std::env::var("LOCALAPPDATA") else {
        return (
            BrowserHistoryScanResult {
                scanned_at: chrono::Utc::now().to_rfc3339(),
                browsers_scanned,
                total_findings: 0,
                urls_scanned: 0,
                by_category: HashMap::new(),
            },
            findings,
        );
    };
    let local = Path::new(&local);

    let chrome_root = local.join("Google").join("Chrome").join("User Data");
    if chrome_root.is_dir() {
        browsers_scanned.push("Chrome".into());
        for (prof, p) in chromium_history_paths(&chrome_root) {
            let (n, mut f) =
                scan_chromium_file("Chrome", &prof, &p, cutoff_chrome, ioc, dev_infra, abuse_ch);
            urls_scanned = urls_scanned.saturating_add(n);
            findings.append(&mut f);
        }
    }

    let edge_root = local.join("Microsoft").join("Edge").join("User Data");
    if edge_root.is_dir() {
        browsers_scanned.push("Edge".into());
        for (prof, p) in chromium_history_paths(&edge_root) {
            let (n, mut f) =
                scan_chromium_file("Edge", &prof, &p, cutoff_chrome, ioc, dev_infra, abuse_ch);
            urls_scanned = urls_scanned.saturating_add(n);
            findings.append(&mut f);
        }
    }

    let brave_root = local
        .join("BraveSoftware")
        .join("Brave-Browser")
        .join("User Data");
    if brave_root.is_dir() {
        browsers_scanned.push("Brave".into());
        for (prof, p) in chromium_history_paths(&brave_root) {
            let (n, mut f) =
                scan_chromium_file("Brave", &prof, &p, cutoff_chrome, ioc, dev_infra, abuse_ch);
            urls_scanned = urls_scanned.saturating_add(n);
            findings.append(&mut f);
        }
    }

    if !firefox_places_paths().is_empty() {
        browsers_scanned.push("Firefox".into());
    }
    for (prof, p) in firefox_places_paths() {
        let (n, mut f) = scan_firefox_file(&prof, &p, cutoff_ff, ioc, dev_infra, abuse_ch);
        urls_scanned = urls_scanned.saturating_add(n);
        findings.append(&mut f);
    }

    findings.sort_by(|a, b| b.last_visit_at.cmp(&a.last_visit_at));
    findings.truncate(FINDINGS_CAP);

    let mut by_category: HashMap<String, u32> = HashMap::new();
    for f in &findings {
        for c in &f.matched_categories {
            *by_category.entry(c.clone()).or_insert(0) += 1;
        }
    }

    let scanned_at = chrono::Utc::now().to_rfc3339();
    (
        BrowserHistoryScanResult {
            scanned_at: scanned_at.clone(),
            browsers_scanned,
            total_findings: findings.len() as u32,
            urls_scanned,
            by_category,
        },
        findings,
    )
}

pub fn scan_and_persist(state: &AppState) -> Result<BrowserHistoryScanResult, String> {
    log_event(
        EventKind::ScanStarted,
        "info",
        None,
        None,
        None,
        Some(serde_json::json!({ "trigger": "browser_history" })),
        "Browser history scan started",
    );

    let ioc = state.ioc.read().map_err(|e| e.to_string())?;
    let abuse = state.abuse_ch.read().map_err(|e| e.to_string())?;
    let (summary, findings) = scan_browser_history_disk(&ioc, state.dev_infra.as_ref(), &abuse);

    let rows: Vec<HistoryFindingRow> = findings
        .iter()
        .map(|f| HistoryFindingRow {
            browser: f.browser.clone(),
            profile: f.profile.clone(),
            url: f.url.clone(),
            host: f.host.clone(),
            title: f.title.clone(),
            last_visit_at: f.last_visit_at.clone(),
            matched_categories: f.matched_categories.clone(),
            source_label: f.source_label.clone(),
            severity: f.severity.clone(),
            score: f.score,
        })
        .collect();

    {
        let mut db = state.db.lock().map_err(|e| e.to_string())?;
        replace_browser_history_findings(&mut db, &summary.scanned_at, &rows)?;
    }

    let by_cat_json: serde_json::Value =
        serde_json::to_value(&summary.by_category).map_err(|e| e.to_string())?;
    log_event(
        EventKind::ScanCompleted,
        "info",
        None,
        None,
        None,
        Some(serde_json::json!({
            "findingsCount": summary.total_findings,
            "byCategory": by_cat_json,
            "trigger": "browser_history",
            "urlsScanned": summary.urls_scanned,
        })),
        "Browser history scan completed",
    );

    for f in &findings {
        if f.severity == "high" {
            log_event(
                EventKind::FindingNew,
                "high",
                None,
                None,
                None,
                Some(serde_json::json!({
                    "url": f.url,
                    "browser": f.browser,
                    "categories": f.matched_categories,
                    "trigger": "browser_history",
                })),
                format!("Browser history match ({})", f.host),
            );
        }
    }

    Ok(summary)
}

pub fn dev_infra_meta(state: &AppState) -> DevInfraMeta {
    DevInfraMeta {
        category_counts: state.dev_infra.category_counts_cloned(),
        snapshot_date: state.dev_infra.snapshot_date.clone(),
    }
}

pub fn replace_browser_history_findings(
    conn: &mut Connection,
    scanned_at: &str,
    rows: &[HistoryFindingRow],
) -> Result<(), String> {
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    tx.execute("DELETE FROM browser_history_findings", [])
        .map_err(|e| e.to_string())?;
    for r in rows {
        let cats = serde_json::to_string(&r.matched_categories).map_err(|e| e.to_string())?;
        tx.execute(
            "INSERT INTO browser_history_findings (scanned_at, browser, profile, url, host, title, last_visit_at, matched_categories, source_label, severity, score)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            rusqlite::params![
                scanned_at,
                r.browser,
                r.profile,
                r.url,
                r.host,
                r.title,
                r.last_visit_at,
                cats,
                r.source_label,
                r.severity,
                r.score,
            ],
        )
        .map_err(|e| e.to_string())?;
    }
    tx.commit().map_err(|e| e.to_string())?;
    Ok(())
}

pub fn db_list_browser_history_findings(
    conn: &Connection,
    limit: u32,
    offset: u32,
    severity: Option<&str>,
) -> Result<Vec<HistoryFinding>, String> {
    let lim = (limit as i64).clamp(1, 5000);
    let off = (offset as i64).max(0);
    let map_row = |row: &rusqlite::Row<'_>| -> rusqlite::Result<HistoryFinding> {
        let cats_s: String = row.get(7)?;
        let cats: Vec<String> = serde_json::from_str(&cats_s).unwrap_or_default();
        Ok(HistoryFinding {
            id: row.get(0)?,
            browser: row.get(1)?,
            profile: row.get(2)?,
            url: row.get(3)?,
            host: row.get(4)?,
            title: row.get(5)?,
            last_visit_at: row.get(6)?,
            matched_categories: cats,
            source_label: row.get(8)?,
            severity: row.get(9)?,
            score: row.get::<_, i64>(10)? as i32,
        })
    };
    match severity {
        Some(sev) => {
            let mut stmt = conn
                .prepare(
                    "SELECT id, browser, profile, url, host, title, last_visit_at, matched_categories, source_label, severity, score
                     FROM browser_history_findings WHERE severity = ?1
                     ORDER BY last_visit_at DESC LIMIT ?2 OFFSET ?3",
                )
                .map_err(|e| e.to_string())?;
            let rows = stmt
                .query_map(rusqlite::params![sev, lim, off], map_row)
                .map_err(|e| e.to_string())?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|e| e.to_string())
        }
        None => {
            let mut stmt = conn
                .prepare(
                    "SELECT id, browser, profile, url, host, title, last_visit_at, matched_categories, source_label, severity, score
                     FROM browser_history_findings
                     ORDER BY last_visit_at DESC LIMIT ?1 OFFSET ?2",
                )
                .map_err(|e| e.to_string())?;
            let rows = stmt
                .query_map(rusqlite::params![lim, off], map_row)
                .map_err(|e| e.to_string())?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|e| e.to_string())
        }
    }
}

pub fn clear_browser_history_findings(conn: &Connection) -> Result<(), String> {
    conn.execute("DELETE FROM browser_history_findings", [])
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn severity_rank_orders_levels() {
        assert!(severity_rank("high") > severity_rank("warn"));
        assert!(severity_rank("warn") > severity_rank("low"));
        assert_eq!(severity_rank("unknown"), 0);
    }

    #[test]
    fn strongest_severity_prefers_higher_rank() {
        assert_eq!(strongest_severity("low", "high"), "high");
        assert_eq!(strongest_severity("warn", "low"), "warn");
    }

    #[test]
    fn unix_epoch_micros_round_trip() {
        let us = 1_609_459_200_000_000_i64;
        let s = unix_micros_to_rfc3339(us).expect("ts");
        assert!(s.starts_with("2021-01-01"));
    }

    #[test]
    fn chrome_epoch_maps_to_unix_time() {
        // Browser Chromium epoch offset (matches `CHROME_EPOCH_OFFSET_MICROS`).
        let chrome_us = 11_644_473_600_000_000_i64;
        let s = chrome_micros_to_rfc3339(chrome_us).expect("chrome epoch");
        assert!(s.starts_with("1970-01-01"));
    }
}
