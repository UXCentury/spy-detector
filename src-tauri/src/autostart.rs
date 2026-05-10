//! Enumerate autostart locations and resolve each entry to an exe path when possible.
//! `snapshot_and_diff` persists first-seen timestamps to detect entries added within the last 24h.

use crate::event_log::{log as log_event, EventKind};
use once_cell::sync::Lazy;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Mutex;

use rusqlite::Connection;
use winreg::enums::*;
use winreg::{RegKey, HKEY};

#[derive(Debug, Clone)]
pub struct AutostartEntry {
    #[allow(dead_code)]
    pub name: String,
    #[allow(dead_code)]
    pub command: String,
    pub resolved_path: Option<PathBuf>,
    pub location: String,
}

#[derive(Debug, Clone)]
pub struct AutostartDiff {
    pub existing: HashSet<String>,
    pub new_in_last_24h: HashSet<String>,
}

static PREV_AUTOSTART_PATHS: Lazy<Mutex<Option<HashSet<String>>>> = Lazy::new(|| Mutex::new(None));

pub fn snapshot_and_diff(conn: &mut Connection) -> Result<AutostartDiff, rusqlite::Error> {
    let entries = collect_entries();
    let now = chrono::Utc::now().to_rfc3339();
    for e in &entries {
        let Some(ref p) = e.resolved_path else {
            continue;
        };
        let Some(ps) = p.to_str() else {
            continue;
        };
        let path_norm = ps.to_lowercase();
        conn.execute(
            "INSERT OR IGNORE INTO autostart_history (path_norm, location, first_seen) VALUES (?1, ?2, ?3)",
            rusqlite::params![path_norm, &e.location, &now],
        )?;
    }

    let mut existing = HashSet::new();
    for e in &entries {
        if let Some(ref p) = e.resolved_path {
            if let Some(ps) = p.to_str() {
                existing.insert(ps.to_lowercase());
            }
        }
    }

    let cutoff = (chrono::Utc::now() - chrono::Duration::hours(24)).to_rfc3339();
    let mut new_in_last_24h = HashSet::new();
    let mut stmt = conn.prepare(
        "SELECT 1 FROM autostart_history WHERE path_norm = ?1 AND first_seen >= ?2 LIMIT 1",
    )?;
    for p in &existing {
        if stmt.exists(rusqlite::params![p, &cutoff])? {
            new_in_last_24h.insert(p.clone());
        }
    }

    if let Ok(mut g) = PREV_AUTOSTART_PATHS.lock() {
        let prev = g.replace(existing.clone());
        if let Some(prev) = prev {
            for p in existing.difference(&prev) {
                log_event(
                    EventKind::AutostartAdded,
                    "low",
                    None,
                    None,
                    Some(p.clone()),
                    None,
                    format!("Autostart entry: {p}"),
                );
            }
            for p in prev.difference(&existing) {
                log_event(
                    EventKind::AutostartRemoved,
                    "low",
                    None,
                    None,
                    Some(p.clone()),
                    None,
                    format!("Autostart entry removed: {p}"),
                );
            }
        }
    }

    Ok(AutostartDiff {
        existing,
        new_in_last_24h,
    })
}

fn fill_collect_entries(out: &mut Vec<AutostartEntry>) {
    read_run_key(
        HKEY_CURRENT_USER,
        RUN_PATH,
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        out,
    );
    read_run_key(
        HKEY_CURRENT_USER,
        RUNONCE_PATH,
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        out,
    );
    read_run_key(
        HKEY_LOCAL_MACHINE,
        RUN_PATH,
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
        out,
    );
    read_run_key(
        HKEY_LOCAL_MACHINE,
        RUNONCE_PATH,
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        out,
    );
    read_run_key(
        HKEY_LOCAL_MACHINE,
        WOW64_RUN_PATH,
        r"HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        out,
    );
    read_startup_dir(startup_dir_user(), "Startup (current user)", out);
    read_startup_dir(startup_dir_common(), "Startup (all users)", out);
}

pub(crate) fn collect_autostart_snapshot_entries() -> Vec<AutostartEntry> {
    let mut entries: Vec<AutostartEntry> = Vec::new();
    fill_collect_entries(&mut entries);
    entries
}

fn collect_entries() -> Vec<AutostartEntry> {
    collect_autostart_snapshot_entries()
}

const RUN_PATH: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const RUNONCE_PATH: &str = r"Software\Microsoft\Windows\CurrentVersion\RunOnce";
const WOW64_RUN_PATH: &str = r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run";

fn read_run_key(hive: HKEY, subpath: &str, location: &str, out: &mut Vec<AutostartEntry>) {
    let root = RegKey::predef(hive);
    let Ok(key) = root.open_subkey_with_flags(subpath, KEY_READ) else {
        return;
    };
    for r in key.enum_values() {
        let Ok((name, val)) = r else {
            continue;
        };
        let cmd = match val.vtype {
            REG_SZ | REG_EXPAND_SZ => val.to_string(),
            _ => continue,
        };
        let resolved = parse_command_to_exe(&cmd);
        out.push(AutostartEntry {
            name,
            command: cmd,
            resolved_path: resolved,
            location: location.to_string(),
        });
    }
}

fn read_startup_dir(dir: Option<PathBuf>, location: &str, out: &mut Vec<AutostartEntry>) {
    let Some(dir) = dir else {
        return;
    };
    let Ok(rd) = std::fs::read_dir(&dir) else {
        return;
    };
    for ent in rd.flatten() {
        let path = ent.path();
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string();
        let resolved = if path
            .extension()
            .and_then(|s| s.to_str())
            .map(|s| s.eq_ignore_ascii_case("lnk"))
            .unwrap_or(false)
        {
            None
        } else {
            Some(path.clone())
        };
        out.push(AutostartEntry {
            name,
            command: path.to_string_lossy().into_owned(),
            resolved_path: resolved,
            location: location.to_string(),
        });
    }
}

pub(crate) fn startup_dir_user() -> Option<PathBuf> {
    std::env::var_os("APPDATA")
        .map(|a| PathBuf::from(a).join(r"Microsoft\Windows\Start Menu\Programs\Startup"))
}

pub(crate) fn startup_dir_common() -> Option<PathBuf> {
    std::env::var_os("ProgramData")
        .map(|p| PathBuf::from(p).join(r"Microsoft\Windows\Start Menu\Programs\Startup"))
}

pub(crate) fn parse_command_to_exe(cmd: &str) -> Option<PathBuf> {
    let trimmed = cmd.trim();
    if trimmed.is_empty() {
        return None;
    }
    let candidate = if let Some(rest) = trimmed.strip_prefix('"') {
        let end = rest.find('"')?;
        rest[..end].to_string()
    } else {
        trimmed
            .split_whitespace()
            .next()
            .unwrap_or(trimmed)
            .to_string()
    };
    let expanded = expand_env(&candidate);
    Some(PathBuf::from(expanded))
}

pub(crate) fn expand_env(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if let Some(end_rel) = s[i + 1..].find('%') {
                let var = &s[i + 1..i + 1 + end_rel];
                if let Ok(v) = std::env::var(var) {
                    out.push_str(&v);
                    i += 2 + end_rel;
                    continue;
                }
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use rusqlite::Connection;

    fn setup_history(conn: &Connection) {
        conn.execute_batch(
            r"
            CREATE TABLE autostart_history (
                path_norm TEXT PRIMARY KEY,
                location TEXT NOT NULL,
                first_seen TEXT NOT NULL
            );
            ",
        )
        .expect("schema");
    }

    fn is_recent(conn: &Connection, path_norm: &str) -> bool {
        let cutoff = (chrono::Utc::now() - chrono::Duration::hours(24)).to_rfc3339();
        conn.query_row(
            "SELECT 1 FROM autostart_history WHERE path_norm = ?1 AND first_seen >= ?2",
            rusqlite::params![path_norm, cutoff],
            |_| Ok(()),
        )
        .is_ok()
    }

    #[test]
    fn brand_new_autostart_first_seen_is_recent() {
        let conn = Connection::open_in_memory().expect("db");
        setup_history(&conn);
        let path = "c:\\program files\\test\\app.exe".to_lowercase();
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO autostart_history (path_norm, location, first_seen) VALUES (?1, 'Run', ?2)",
            rusqlite::params![path, now],
        )
        .expect("insert");
        assert!(is_recent(&conn, &path));
    }

    #[test]
    fn autostart_first_seen_48h_ago_not_recent() {
        let conn = Connection::open_in_memory().expect("db");
        setup_history(&conn);
        let path = "c:\\program files\\test\\app.exe".to_lowercase();
        let old = (chrono::Utc::now() - chrono::Duration::hours(48)).to_rfc3339();
        conn.execute(
            "INSERT INTO autostart_history (path_norm, location, first_seen) VALUES (?1, 'Run', ?2)",
            rusqlite::params![path, old],
        )
        .expect("insert");
        assert!(!is_recent(&conn, &path));
    }
}
