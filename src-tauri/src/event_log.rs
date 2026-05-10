use crate::app_log;
use rusqlite::types::Value as SqlValue;
use rusqlite::{params_from_iter, Connection};
use serde::Serialize;
use serde_json::Value as JsonValue;
use std::sync::{Arc, Mutex, OnceLock};
use tauri::Emitter;

static APP_HANDLE: OnceLock<tauri::AppHandle> = OnceLock::new();
static DB: OnceLock<Arc<Mutex<Connection>>> = OnceLock::new();

pub fn init(app: tauri::AppHandle, db: Arc<Mutex<Connection>>) {
    let _ = APP_HANDLE.set(app);
    let _ = DB.set(db);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub enum EventKind {
    CameraAccess,
    MicrophoneAccess,
    KeyboardHook,
    ClipboardAccess,
    ProcessLaunch,
    ProcessExit,
    ThreadInjection,
    ThreadBurst,
    ScanStarted,
    ScanCompleted,
    FindingNew,
    AlertEmitted,
    ProcessKilled,
    ProcessQuarantined,
    Ignored,
    Unignored,
    AllowlistAdded,
    AllowlistRemoved,
    IocRefresh,
    IpFeedMatch,
    AutostartAdded,
    AutostartRemoved,
    SettingsChanged,
    ElevationRequested,
    EtwSubscriptionStateChanged,
    AppStarted,
    AppStopped,
    AmsiDetection,
    YaraMatch,
    AbuseChMatch,
    AutostartEntryEnabled,
    AutostartEntryDisabled,
    ServiceStartTypeChanged,
    ServiceStateChanged,
    BrowserHistoryUrlRemoved,
}

impl EventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            EventKind::CameraAccess => "camera-access",
            EventKind::MicrophoneAccess => "microphone-access",
            EventKind::KeyboardHook => "keyboard-hook",
            EventKind::ClipboardAccess => "clipboard-access",
            EventKind::ProcessLaunch => "process-launch",
            EventKind::ProcessExit => "process-exit",
            EventKind::ThreadInjection => "thread-injection",
            EventKind::ThreadBurst => "thread-burst",
            EventKind::ScanStarted => "scan-started",
            EventKind::ScanCompleted => "scan-completed",
            EventKind::FindingNew => "finding-new",
            EventKind::AlertEmitted => "alert-emitted",
            EventKind::ProcessKilled => "process-killed",
            EventKind::ProcessQuarantined => "process-quarantined",
            EventKind::Ignored => "ignored",
            EventKind::Unignored => "unignored",
            EventKind::AllowlistAdded => "allowlist-added",
            EventKind::AllowlistRemoved => "allowlist-removed",
            EventKind::IocRefresh => "ioc-refresh",
            EventKind::IpFeedMatch => "ip-feed-match",
            EventKind::AutostartAdded => "autostart-added",
            EventKind::AutostartRemoved => "autostart-removed",
            EventKind::SettingsChanged => "settings-changed",
            EventKind::ElevationRequested => "elevation-requested",
            EventKind::EtwSubscriptionStateChanged => "etw-subscription-state-changed",
            EventKind::AppStarted => "app-started",
            EventKind::AppStopped => "app-stopped",
            EventKind::AmsiDetection => "amsi-detection",
            EventKind::YaraMatch => "yara-match",
            EventKind::AbuseChMatch => "abuse-ch-match",
            EventKind::AutostartEntryEnabled => "autostart-entry-enabled",
            EventKind::AutostartEntryDisabled => "autostart-entry-disabled",
            EventKind::ServiceStartTypeChanged => "service-start-type-changed",
            EventKind::ServiceStateChanged => "service-state-changed",
            EventKind::BrowserHistoryUrlRemoved => "browser-history-url-removed",
        }
    }

    #[allow(dead_code)]
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.trim() {
            "camera-access" => EventKind::CameraAccess,
            "microphone-access" => EventKind::MicrophoneAccess,
            "keyboard-hook" => EventKind::KeyboardHook,
            "clipboard-access" => EventKind::ClipboardAccess,
            "process-launch" => EventKind::ProcessLaunch,
            "process-exit" => EventKind::ProcessExit,
            "thread-injection" => EventKind::ThreadInjection,
            "thread-burst" => EventKind::ThreadBurst,
            "scan-started" => EventKind::ScanStarted,
            "scan-completed" => EventKind::ScanCompleted,
            "finding-new" => EventKind::FindingNew,
            "alert-emitted" => EventKind::AlertEmitted,
            "process-killed" => EventKind::ProcessKilled,
            "process-quarantined" => EventKind::ProcessQuarantined,
            "ignored" => EventKind::Ignored,
            "unignored" => EventKind::Unignored,
            "allowlist-added" => EventKind::AllowlistAdded,
            "allowlist-removed" => EventKind::AllowlistRemoved,
            "ioc-refresh" => EventKind::IocRefresh,
            "ip-feed-match" => EventKind::IpFeedMatch,
            "autostart-added" => EventKind::AutostartAdded,
            "autostart-removed" => EventKind::AutostartRemoved,
            "settings-changed" => EventKind::SettingsChanged,
            "elevation-requested" => EventKind::ElevationRequested,
            "etw-subscription-state-changed" => EventKind::EtwSubscriptionStateChanged,
            "app-started" => EventKind::AppStarted,
            "app-stopped" => EventKind::AppStopped,
            "amsi-detection" => EventKind::AmsiDetection,
            "yara-match" => EventKind::YaraMatch,
            "abuse-ch-match" => EventKind::AbuseChMatch,
            "autostart-entry-enabled" => EventKind::AutostartEntryEnabled,
            "autostart-entry-disabled" => EventKind::AutostartEntryDisabled,
            "service-start-type-changed" => EventKind::ServiceStartTypeChanged,
            "service-state-changed" => EventKind::ServiceStateChanged,
            "browser-history-url-removed" => EventKind::BrowserHistoryUrlRemoved,
            _ => return None,
        })
    }
}

fn trim_to_cap(conn: &Connection) -> Result<(), rusqlite::Error> {
    conn.execute_batch(
        r"DELETE FROM event_log WHERE id IN (
            SELECT id FROM event_log ORDER BY id DESC LIMIT -1 OFFSET 10000
        );",
    )
}

// internal helper; refactoring to a struct adds boilerplate without behavior change
#[allow(clippy::too_many_arguments)]
fn insert_row(
    conn: &Connection,
    kind: &str,
    severity: &str,
    pid: Option<u32>,
    process_name: Option<&str>,
    image_path: Option<&str>,
    summary: &str,
    details_json: Option<&str>,
) -> Result<i64, rusqlite::Error> {
    let ts = chrono::Utc::now().to_rfc3339();
    let pid_i = pid.map(|p| p as i64);
    conn.execute(
        r"INSERT INTO event_log (ts, kind, severity, pid, process_name, image_path, summary, details)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        rusqlite::params![
            ts,
            kind,
            severity,
            pid_i,
            process_name,
            image_path,
            summary,
            details_json,
        ],
    )?;
    trim_to_cap(conn)?;
    Ok(conn.last_insert_rowid())
}

pub fn log(
    kind: EventKind,
    severity: &str,
    pid: Option<u32>,
    process_name: Option<String>,
    image_path: Option<String>,
    details: Option<JsonValue>,
    summary: impl AsRef<str>,
) {
    let Some(db) = DB.get().cloned() else {
        app_log::append_line(&format!(
            "event_log skipped (no db): {} {}",
            kind.as_str(),
            severity
        ));
        return;
    };
    let summary = summary.as_ref().to_string();
    let kind_s = kind.as_str().to_string();
    let sev = severity.to_string();
    let details_s = details.and_then(|v| serde_json::to_string(&v).ok());

    std::thread::spawn(move || {
        let insert_result = (|| -> Result<i64, String> {
            let g = db.lock().map_err(|e| e.to_string())?;
            insert_row(
                &g,
                &kind_s,
                &sev,
                pid,
                process_name.as_deref(),
                image_path.as_deref(),
                &summary,
                details_s.as_deref(),
            )
            .map_err(|e| e.to_string())
        })();

        match insert_result {
            Ok(id) => {
                if let Some(app) = APP_HANDLE.get() {
                    let _ = app.emit(
                        "event_logged",
                        &serde_json::json!({
                            "id": id,
                            "kind": kind_s,
                            "severity": sev,
                            "summary": summary,
                            "processName": process_name,
                            "pid": pid,
                        }),
                    );
                }
            }
            Err(e) => {
                app_log::append_line(&format!(
                    "event_log insert failed: {e} kind={kind_s} summary={summary}"
                ));
            }
        }
    });
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EventLogRow {
    pub id: i64,
    pub ts: String,
    pub kind: String,
    pub severity: String,
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_path: Option<String>,
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<JsonValue>,
}

fn filter_params(
    kinds: Option<&[String]>,
    search: Option<&str>,
    severities: Option<&[String]>,
) -> (String, Vec<SqlValue>) {
    let mut sql = String::new();
    let mut vals: Vec<SqlValue> = Vec::new();

    if let Some(klist) = kinds {
        if !klist.is_empty() {
            sql.push_str(" AND kind IN (");
            sql.push_str(&vec!["?"; klist.len()].join(","));
            sql.push(')');
            for k in klist {
                vals.push(SqlValue::Text(k.clone()));
            }
        }
    }

    if let Some(sev) = severities {
        if !sev.is_empty() {
            sql.push_str(" AND severity IN (");
            sql.push_str(&vec!["?"; sev.len()].join(","));
            sql.push(')');
            for s in sev {
                vals.push(SqlValue::Text(s.clone()));
            }
        }
    }

    if let Some(q) = search {
        let q = q.trim();
        if !q.is_empty() {
            let pat = format!("%{q}%");
            sql.push_str(
                " AND (summary LIKE ? OR COALESCE(process_name,'') LIKE ? OR kind LIKE ? OR COALESCE(image_path,'') LIKE ?)",
            );
            for _ in 0..4 {
                vals.push(SqlValue::Text(pat.clone()));
            }
        }
    }

    (sql, vals)
}

fn map_event_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<EventLogRow> {
    let details_s: Option<String> = r.get(8)?;
    let details = details_s.and_then(|s| serde_json::from_str(&s).ok());
    Ok(EventLogRow {
        id: r.get(0)?,
        ts: r.get(1)?,
        kind: r.get(2)?,
        severity: r.get(3)?,
        pid: r.get::<_, Option<i64>>(4)?.map(|p| p as u32),
        process_name: r.get(5)?,
        image_path: r.get(6)?,
        summary: r.get(7)?,
        details,
    })
}

pub fn list_rows(
    conn: &Connection,
    limit: u32,
    offset: u32,
    kinds: Option<&[String]>,
    search: Option<&str>,
    severities: Option<&[String]>,
) -> Result<Vec<EventLogRow>, String> {
    let lim = limit.clamp(1, 500) as i64;
    let off = offset as i64;
    let (filt_sql, mut vals) = filter_params(kinds, search, severities);
    let q = format!(
        "SELECT id, ts, kind, severity, pid, process_name, image_path, summary, details FROM event_log WHERE 1=1{filt_sql} ORDER BY id DESC LIMIT ? OFFSET ?"
    );
    vals.push(SqlValue::Integer(lim));
    vals.push(SqlValue::Integer(off));
    let mut stmt = conn.prepare(&q).map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map(params_from_iter(vals), map_event_row)
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|e| e.to_string())?);
    }
    Ok(out)
}

pub fn count_filtered(
    conn: &Connection,
    kinds: Option<&[String]>,
    search: Option<&str>,
    severities: Option<&[String]>,
) -> Result<u64, String> {
    let (filt_sql, vals) = filter_params(kinds, search, severities);
    let q = format!("SELECT COUNT(*) FROM event_log WHERE 1=1{filt_sql}");
    let mut stmt = conn.prepare(&q).map_err(|e| e.to_string())?;
    let total: i64 = stmt
        .query_row(params_from_iter(vals), |r| r.get(0))
        .map_err(|e| e.to_string())?;
    Ok(total as u64)
}

pub fn clear_table(conn: &Connection) -> Result<(), String> {
    conn.execute("DELETE FROM event_log", [])
        .map_err(|e| e.to_string())?;
    Ok(())
}

pub fn log_app_stopping_sync() {
    let Some(db) = DB.get() else {
        return;
    };
    let Ok(g) = db.lock() else {
        return;
    };
    let _ = insert_row(
        &g,
        EventKind::AppStopped.as_str(),
        "info",
        None,
        None,
        None,
        "Spy Detector exiting",
        None,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn event_kind_as_str_round_trip_all_variants() {
        let kinds = [
            EventKind::CameraAccess,
            EventKind::MicrophoneAccess,
            EventKind::KeyboardHook,
            EventKind::ClipboardAccess,
            EventKind::ProcessLaunch,
            EventKind::ProcessExit,
            EventKind::ThreadInjection,
            EventKind::ThreadBurst,
            EventKind::ScanStarted,
            EventKind::ScanCompleted,
            EventKind::FindingNew,
            EventKind::AlertEmitted,
            EventKind::ProcessKilled,
            EventKind::ProcessQuarantined,
            EventKind::Ignored,
            EventKind::Unignored,
            EventKind::AllowlistAdded,
            EventKind::AllowlistRemoved,
            EventKind::IocRefresh,
            EventKind::IpFeedMatch,
            EventKind::AutostartAdded,
            EventKind::AutostartRemoved,
            EventKind::SettingsChanged,
            EventKind::ElevationRequested,
            EventKind::EtwSubscriptionStateChanged,
            EventKind::AppStarted,
            EventKind::AppStopped,
            EventKind::AmsiDetection,
            EventKind::YaraMatch,
            EventKind::AbuseChMatch,
            EventKind::AutostartEntryEnabled,
            EventKind::AutostartEntryDisabled,
            EventKind::ServiceStartTypeChanged,
            EventKind::ServiceStateChanged,
            EventKind::BrowserHistoryUrlRemoved,
        ];
        for k in kinds {
            let s = k.as_str();
            assert_eq!(EventKind::parse(s), Some(k));
            assert!(!s.is_empty());
        }
    }

    #[test]
    fn event_kind_parse_unknown_returns_none() {
        assert_eq!(EventKind::parse("not-a-real-kind"), None);
        assert_eq!(EventKind::parse(""), None);
    }

    #[test]
    fn severity_tokens_used_in_app_are_non_empty() {
        for sev in ["info", "warn", "high", "low"] {
            assert!(!sev.trim().is_empty());
        }
    }

    #[test]
    fn list_rows_respects_limit_with_many_rows() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        crate::db::init_db(&conn).unwrap();
        for i in 0..150 {
            conn.execute(
                r"INSERT INTO event_log (ts, kind, severity, pid, process_name, image_path, summary, details)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                rusqlite::params![
                    format!("2026-01-01T{:02}:{:02}:00Z", i / 60, i % 60),
                    "app-started",
                    "info",
                    None::<i64>,
                    None::<String>,
                    None::<String>,
                    format!("summary-{i}"),
                    None::<String>,
                ],
            )
            .unwrap();
        }
        let rows = list_rows(&conn, 100, 0, None, None, None).unwrap();
        assert_eq!(rows.len(), 100);
        let rows_rest = list_rows(&conn, 100, 100, None, None, None).unwrap();
        assert_eq!(rows_rest.len(), 50);
    }
}
