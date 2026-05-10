use rusqlite::{params_from_iter, Connection};

pub fn open_db() -> Result<Connection, String> {
    let dir = dirs::data_dir()
        .ok_or_else(|| "could not resolve %APPDATA%".to_string())?
        .join("spy-detector");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let path = dir.join("db.sqlite");
    let conn = Connection::open(path).map_err(|e| e.to_string())?;
    init_db(&conn).map_err(|e| e.to_string())?;
    Ok(conn)
}

/// Applies schema DDL and migrations (idempotent). Used by `open_db` and tests.
pub fn init_db(conn: &Connection) -> rusqlite::Result<()> {
    init_schema(conn)
}

fn init_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        r"
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            started_at TEXT NOT NULL,
            finished_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            pid INTEGER NOT NULL,
            name TEXT NOT NULL,
            exe_path TEXT,
            score INTEGER NOT NULL,
            reasons TEXT NOT NULL,
            FOREIGN KEY(scan_id) REFERENCES scans(id)
        );
        CREATE TABLE IF NOT EXISTS trusted_paths (
            path_norm TEXT PRIMARY KEY,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS user_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS autostart_history (
            path_norm TEXT PRIMARY KEY,
            location TEXT NOT NULL,
            first_seen TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS security_action_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            at_utc TEXT NOT NULL,
            action TEXT NOT NULL,
            pid INTEGER,
            detail TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS thread_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            kind TEXT NOT NULL,
            source_pid INTEGER NOT NULL,
            source_name TEXT NOT NULL,
            source_path TEXT NOT NULL,
            target_pid INTEGER NOT NULL,
            target_name TEXT NOT NULL,
            target_path TEXT NOT NULL,
            suspicious INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS process_launches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            pid INTEGER NOT NULL,
            name TEXT NOT NULL,
            path TEXT NOT NULL,
            ppid INTEGER NOT NULL,
            parent_name TEXT NOT NULL,
            classification TEXT NOT NULL,
            signed INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS event_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            kind TEXT NOT NULL,
            severity TEXT NOT NULL,
            pid INTEGER,
            process_name TEXT,
            image_path TEXT,
            summary TEXT NOT NULL,
            details TEXT
        );
        CREATE INDEX IF NOT EXISTS event_log_ts_idx ON event_log(ts);
        CREATE INDEX IF NOT EXISTS event_log_kind_idx ON event_log(kind);
        CREATE TABLE IF NOT EXISTS browser_history_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scanned_at TEXT NOT NULL,
            browser TEXT NOT NULL,
            profile TEXT NOT NULL,
            url TEXT NOT NULL,
            host TEXT NOT NULL,
            title TEXT,
            last_visit_at TEXT NOT NULL,
            matched_categories TEXT NOT NULL,
            source_label TEXT,
            severity TEXT NOT NULL,
            score INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS bh_url_idx ON browser_history_findings(url);
        CREATE INDEX IF NOT EXISTS bh_visit_idx ON browser_history_findings(last_visit_at);
        CREATE TABLE IF NOT EXISTS startup_entries_state (
            id TEXT PRIMARY KEY,
            note TEXT,
            first_seen TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS disabled_startup_entries (
            source TEXT NOT NULL,
            scope TEXT NOT NULL,
            name TEXT NOT NULL,
            original_value TEXT NOT NULL,
            disabled_at TEXT NOT NULL,
            PRIMARY KEY (source, scope, name)
        );
        CREATE TABLE IF NOT EXISTS service_state (
            service_name TEXT PRIMARY KEY,
            note TEXT,
            last_observed_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS etw_ignore_list (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pattern TEXT NOT NULL COLLATE NOCASE UNIQUE,
            kind TEXT NOT NULL CHECK(kind IN ('basename', 'path')),
            note TEXT,
            created_at INTEGER NOT NULL
        );
        ",
    )?;
    migrate_findings_suspicious_column(conn)?;
    migrate_trusted_paths_columns(conn)?;
    seed_settings_defaults(conn)?;
    Ok(())
}

fn migrate_trusted_paths_columns(conn: &Connection) -> rusqlite::Result<()> {
    let mut stmt = conn.prepare("PRAGMA table_info(trusted_paths)")?;
    let cols: Vec<String> = stmt
        .query_map([], |row| row.get::<_, String>(1))?
        .filter_map(|r| r.ok())
        .collect();
    if !cols.iter().any(|c| c == "display_name") {
        conn.execute("ALTER TABLE trusted_paths ADD COLUMN display_name TEXT", [])?;
    }
    if !cols.iter().any(|c| c == "reason") {
        conn.execute("ALTER TABLE trusted_paths ADD COLUMN reason TEXT", [])?;
    }
    Ok(())
}

pub fn log_security_action(
    conn: &Connection,
    action: &str,
    pid: Option<u32>,
    detail: &str,
) -> Result<(), String> {
    let at = chrono::Utc::now().to_rfc3339();
    let pid_i = pid.map(|p| p as i64);
    conn.execute(
        "INSERT INTO security_action_log (at_utc, action, pid, detail) VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![at, action, pid_i, detail],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

fn migrate_findings_suspicious_column(conn: &Connection) -> rusqlite::Result<()> {
    let mut stmt = conn.prepare("PRAGMA table_info(findings)")?;
    let cols: Vec<String> = stmt
        .query_map([], |row| row.get::<_, String>(1))?
        .filter_map(|r| r.ok())
        .collect();
    if !cols.iter().any(|c| c == "suspicious_image_loads") {
        conn.execute(
            "ALTER TABLE findings ADD COLUMN suspicious_image_loads INTEGER NOT NULL DEFAULT 0",
            [],
        )?;
    }
    Ok(())
}

// internal helper; refactoring to a struct adds boilerplate without behavior change
#[allow(clippy::too_many_arguments)]
pub fn insert_process_launch(
    conn: &Connection,
    ts: &str,
    pid: u32,
    name: &str,
    path: &str,
    ppid: u32,
    parent_name: &str,
    classification: &str,
    signed: bool,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO process_launches (ts, pid, name, path, ppid, parent_name, classification, signed)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        rusqlite::params![
            ts,
            pid as i64,
            name,
            path,
            ppid as i64,
            parent_name,
            classification,
            if signed { 1 } else { 0 },
        ],
    )?;
    trim_process_launches(conn, 5000)?;
    Ok(())
}

fn trim_process_launches(conn: &Connection, cap: i64) -> rusqlite::Result<()> {
    let count: i64 = conn.query_row("SELECT COUNT(*) FROM process_launches", [], |r| r.get(0))?;
    if count <= cap {
        return Ok(());
    }
    let excess = count - cap;
    conn.execute(
        "DELETE FROM process_launches WHERE id IN (
            SELECT id FROM process_launches ORDER BY id ASC LIMIT ?1
        )",
        [excess],
    )?;
    Ok(())
}

// internal helper; refactoring to a struct adds boilerplate without behavior change
#[allow(clippy::too_many_arguments)]
pub fn insert_thread_event_row(
    conn: &Connection,
    ts: &str,
    kind: &str,
    source_pid: u32,
    source_name: &str,
    source_path: &str,
    target_pid: u32,
    target_name: &str,
    target_path: &str,
    suspicious: bool,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO thread_events (ts, kind, source_pid, source_name, source_path, target_pid, target_name, target_path, suspicious)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        rusqlite::params![
            ts,
            kind,
            source_pid as i64,
            source_name,
            source_path,
            target_pid as i64,
            target_name,
            target_path,
            if suspicious { 1 } else { 0 },
        ],
    )?;
    Ok(())
}

pub fn clear_process_launches(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute("DELETE FROM process_launches", [])?;
    Ok(())
}

pub fn clear_thread_events(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute("DELETE FROM thread_events", [])?;
    Ok(())
}

pub fn recent_process_launches(
    conn: &Connection,
    limit: u32,
) -> rusqlite::Result<Vec<crate::live_activity::ProcessLaunchRow>> {
    let mut stmt = conn.prepare(
        "SELECT id, ts, pid, name, path, ppid, parent_name, classification, signed
         FROM process_launches ORDER BY id DESC LIMIT ?1",
    )?;
    let rows = stmt.query_map([limit as i64], |r| {
        Ok(crate::live_activity::ProcessLaunchRow {
            id: r.get(0)?,
            ts: r.get(1)?,
            pid: r.get::<_, i64>(2)? as u32,
            name: r.get(3)?,
            path: r.get(4)?,
            ppid: r.get::<_, i64>(5)? as u32,
            parent_name: r.get(6)?,
            classification: r.get(7)?,
            signed: r.get::<_, i64>(8)? != 0,
        })
    })?;
    rows.collect()
}

pub fn recent_thread_events(
    conn: &Connection,
    limit: u32,
) -> rusqlite::Result<Vec<crate::live_activity::ThreadEventRow>> {
    let mut stmt = conn.prepare(
        "SELECT id, ts, kind, source_pid, source_name, source_path, target_pid, target_name, target_path, suspicious
         FROM thread_events ORDER BY id DESC LIMIT ?1",
    )?;
    let rows = stmt.query_map([limit as i64], |r| {
        Ok(crate::live_activity::ThreadEventRow {
            id: r.get(0)?,
            ts: r.get(1)?,
            kind: r.get(2)?,
            source_pid: r.get::<_, i64>(3)? as u32,
            source_name: r.get(4)?,
            source_path: r.get(5)?,
            target_pid: r.get::<_, i64>(6)? as u32,
            target_name: r.get(7)?,
            target_path: r.get(8)?,
            suspicious: r.get::<_, i64>(9)? != 0,
        })
    })?;
    rows.collect()
}

pub fn count_process_launches_since(conn: &Connection, since_iso: &str) -> rusqlite::Result<u32> {
    let n: i64 = conn.query_row(
        "SELECT COUNT(*) FROM process_launches WHERE ts >= ?1",
        [since_iso],
        |r| r.get(0),
    )?;
    Ok(n as u32)
}

pub fn count_thread_events_since(conn: &Connection, since_iso: &str) -> rusqlite::Result<u32> {
    let n: i64 = conn.query_row(
        "SELECT COUNT(*) FROM thread_events WHERE ts >= ?1",
        [since_iso],
        |r| r.get(0),
    )?;
    Ok(n as u32)
}

#[derive(Debug, Clone)]
pub struct BrowserHistoryFindingRecord {
    pub id: i64,
    pub browser: String,
    pub profile: String,
    pub url: String,
}

pub fn list_browser_history_findings_by_ids(
    conn: &Connection,
    ids: &[i64],
) -> rusqlite::Result<Vec<BrowserHistoryFindingRecord>> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let placeholders = ids.iter().map(|_| "?").collect::<Vec<_>>().join(",");
    let sql = format!(
        "SELECT id, browser, profile, url FROM browser_history_findings WHERE id IN ({placeholders})"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params_from_iter(ids.iter().copied()), |row| {
        Ok(BrowserHistoryFindingRecord {
            id: row.get(0)?,
            browser: row.get(1)?,
            profile: row.get(2)?,
            url: row.get(3)?,
        })
    })?;
    rows.collect()
}

pub fn delete_browser_history_findings_by_ids(
    conn: &Connection,
    ids: &[i64],
) -> rusqlite::Result<u64> {
    if ids.is_empty() {
        return Ok(0);
    }
    let placeholders = ids.iter().map(|_| "?").collect::<Vec<_>>().join(",");
    let sql = format!("DELETE FROM browser_history_findings WHERE id IN ({placeholders})");
    let n = conn.execute(&sql, params_from_iter(ids.iter().copied()))?;
    Ok(n as u64)
}

fn seed_settings_defaults(conn: &Connection) -> rusqlite::Result<()> {
    let defaults = [
        ("warn_threshold", "50"),
        ("alert_threshold", "75"),
        ("disabled_signature_tokens", "[]"),
        ("periodic_scan_interval_secs", "300"),
        ("amsi_enabled", "1"),
        ("yara_enabled", "1"),
        ("auto_scan_on_launch", "1"),
        ("tray_alerts_enabled", "1"),
        ("diagnostic_logging", "0"),
        ("thread_injection_scanner_enabled", "1"),
        ("process_etw_enabled", "0"),
        ("win32k_etw_enabled", "1"),
        ("dns_etw_enabled", "1"),
        ("camera_monitor_enabled", "1"),
        ("periodic_scan_enabled", "1"),
    ];
    for (k, v) in defaults {
        conn.execute(
            "INSERT OR IGNORE INTO user_settings (key, value) VALUES (?1, ?2)",
            [k, v],
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use rusqlite::params;

    fn table_names(conn: &Connection) -> rusqlite::Result<Vec<String>> {
        let mut stmt = conn.prepare(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
        )?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        rows.collect()
    }

    #[test]
    fn init_db_idempotent_and_creates_expected_tables() {
        let conn = Connection::open_in_memory().unwrap();
        init_db(&conn).unwrap();
        init_db(&conn).unwrap();

        let tables = table_names(&conn).unwrap();
        assert!(
            tables.contains(&"browser_history_findings".to_string()),
            "missing bh table: {tables:?}"
        );
        assert!(tables.contains(&"event_log".to_string()));
        assert!(tables.contains(&"findings".to_string()));
        assert!(tables.contains(&"process_launches".to_string()));
        assert!(tables.contains(&"scans".to_string()));
        assert!(tables.contains(&"trusted_paths".to_string()));

        conn.execute(
            "INSERT INTO event_log (ts, kind, severity, pid, process_name, image_path, summary, details)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                "2026-01-01T00:00:00Z",
                "app-started",
                "info",
                None::<i64>,
                None::<String>,
                None::<String>,
                "hello",
                None::<String>,
            ],
        )
        .unwrap();
        let n: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM event_log WHERE summary = 'hello'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1);

        conn.execute(
            "INSERT INTO trusted_paths (path_norm, created_at, display_name, reason)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                "c:\\windows\\notepad.exe",
                "2026-01-01T00:00:00Z",
                "Notepad",
                "test",
            ],
        )
        .unwrap();
        let tn: String = conn
            .query_row(
                "SELECT display_name FROM trusted_paths WHERE path_norm = ?1",
                ["c:\\windows\\notepad.exe"],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(tn, "Notepad");

        conn.execute(
            "INSERT INTO scans (started_at, finished_at) VALUES (?1, ?2)",
            params!["2026-01-01T00:00:00Z", "2026-01-01T00:01:00Z"],
        )
        .unwrap();
        let scan_id: i64 = conn.last_insert_rowid();

        conn.execute(
            "INSERT INTO findings (scan_id, pid, name, exe_path, score, reasons, suspicious_image_loads)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![scan_id, 42_i64, "evil", "C:\\e.exe", 90_i64, r#"["x"]"#, 0_i64],
        )
        .unwrap();
        let score: i64 = conn
            .query_row("SELECT score FROM findings WHERE pid = 42", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(score, 90);
    }
}
