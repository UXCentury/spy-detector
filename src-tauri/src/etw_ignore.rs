//! Per-user ignore list for Process ETW (kernel-process provider) paths and basenames.

use rusqlite::Connection;
use serde::Serialize;
use std::collections::HashSet;
use std::path::Path;
use std::sync::{OnceLock, RwLock};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum IgnoreKind {
    Basename,
    Path,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IgnoreEntry {
    pub id: i64,
    pub pattern: String,
    pub kind: IgnoreKind,
    pub note: Option<String>,
    pub created_at: i64,
}

#[derive(Default)]
struct IgnoreCache {
    basenames: HashSet<String>,
    paths: HashSet<String>,
}

static IGNORE_CACHE: OnceLock<RwLock<IgnoreCache>> = OnceLock::new();

fn cache_lock() -> &'static RwLock<IgnoreCache> {
    IGNORE_CACHE.get_or_init(|| RwLock::new(IgnoreCache::default()))
}

#[cfg(windows)]
fn normalize_etw_path(raw: &str) -> String {
    let s = raw.trim();
    let stripped = s
        .strip_prefix(r"\??\")
        .or_else(|| s.strip_prefix("\\??\\"))
        .unwrap_or(s);
    crate::authenticode::normalize_image_path(Path::new(stripped))
        .to_string_lossy()
        .to_lowercase()
        .replace('/', "\\")
}

#[cfg(not(windows))]
fn normalize_etw_path(raw: &str) -> String {
    raw.trim().to_lowercase().replace('/', "\\")
}

pub fn detect_kind(pattern: &str) -> IgnoreKind {
    let t = pattern.trim();
    if t.contains('\\') || t.contains('/') {
        IgnoreKind::Path
    } else {
        IgnoreKind::Basename
    }
}

pub fn reload_from_db(conn: &Connection) -> rusqlite::Result<()> {
    let mut basenames = HashSet::new();
    let mut paths = HashSet::new();
    let mut stmt = conn.prepare("SELECT pattern, kind FROM etw_ignore_list")?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    for r in rows {
        let (pattern, kind) = r?;
        match kind.as_str() {
            "basename" => {
                basenames.insert(pattern.trim().to_lowercase());
            }
            "path" => {
                paths.insert(normalize_etw_path(&pattern));
            }
            _ => {}
        }
    }
    let mut g = cache_lock().write().expect("etw_ignore cache poisoned");
    g.basenames = basenames;
    g.paths = paths;
    Ok(())
}

pub fn is_ignored(image_path: &str) -> bool {
    let s = image_path.trim();
    if s.is_empty() {
        return false;
    }
    let norm = normalize_etw_path(s);
    let cache = cache_lock().read().expect("etw_ignore cache poisoned");
    if cache.paths.contains(&norm) {
        return true;
    }
    if let Some(base) = Path::new(&norm)
        .file_name()
        .and_then(|x| x.to_str())
        .map(|x| x.to_lowercase())
    {
        if cache.basenames.contains(&base) {
            return true;
        }
    }
    if !s.contains('\\') && !s.contains('/') && cache.basenames.contains(&s.to_lowercase()) {
        return true;
    }
    false
}

pub fn add(
    conn: &mut Connection,
    pattern: &str,
    kind: IgnoreKind,
    note: Option<&str>,
) -> rusqlite::Result<()> {
    let trimmed = pattern.trim();
    let kind_str = match kind {
        IgnoreKind::Basename => "basename",
        IgnoreKind::Path => "path",
    };
    let created = chrono::Utc::now().timestamp();
    conn.execute(
        "INSERT INTO etw_ignore_list (pattern, kind, note, created_at) VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![trimmed, kind_str, note, created],
    )?;
    reload_from_db(conn)?;
    Ok(())
}

pub fn remove(conn: &mut Connection, id: i64) -> rusqlite::Result<()> {
    conn.execute("DELETE FROM etw_ignore_list WHERE id = ?1", [id])?;
    reload_from_db(conn)?;
    Ok(())
}

pub fn list(conn: &Connection) -> rusqlite::Result<Vec<IgnoreEntry>> {
    let mut stmt = conn.prepare(
        "SELECT id, pattern, kind, note, created_at FROM etw_ignore_list ORDER BY created_at DESC",
    )?;
    let rows = stmt.query_map([], |row| {
        let kind_s: String = row.get(2)?;
        let kind = match kind_s.as_str() {
            "basename" => IgnoreKind::Basename,
            "path" => IgnoreKind::Path,
            _ => IgnoreKind::Basename,
        };
        Ok(IgnoreEntry {
            id: row.get(0)?,
            pattern: row.get(1)?,
            kind,
            note: row.get(3)?,
            created_at: row.get(4)?,
        })
    })?;
    rows.collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn fresh_db() -> Connection {
        let conn = Connection::open_in_memory().expect("open in-memory db");
        crate::db::init_db(&conn).expect("init schema");
        conn
    }

    #[test]
    fn round_trip_add_list_remove() {
        let mut conn = fresh_db();
        reload_from_db(&conn).unwrap();
        assert!(!is_ignored(r"C:\Foo\bar.exe"));

        add(&mut conn, "bar.exe", IgnoreKind::Basename, Some("note a")).unwrap();
        let rows = list(&conn).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].pattern, "bar.exe");
        assert_eq!(rows[0].kind, IgnoreKind::Basename);
        assert_eq!(rows[0].note.as_deref(), Some("note a"));

        assert!(is_ignored(r"C:\Tools\bar.exe"));

        remove(&mut conn, rows[0].id).unwrap();
        assert!(list(&conn).unwrap().is_empty());
        assert!(!is_ignored(r"C:\Tools\bar.exe"));
    }

    #[test]
    fn basename_normalization() {
        let mut conn = fresh_db();
        reload_from_db(&conn).unwrap();
        add(&mut conn, "GIT.EXE", IgnoreKind::Basename, None).unwrap();
        assert!(is_ignored("git.exe"));
        assert!(is_ignored(r"C:\x\git.exe"));
        assert!(!is_ignored(r"C:\x\notgit.exe"));
    }

    #[test]
    fn path_match_requires_normalized_path() {
        let mut conn = fresh_db();
        reload_from_db(&conn).unwrap();
        add(&mut conn, r"C:\Tools\App\foo.exe", IgnoreKind::Path, None).unwrap();
        #[cfg(windows)]
        assert!(is_ignored(r"C:/Tools/App/foo.exe"));
        #[cfg(not(windows))]
        assert!(is_ignored(r"c:\tools\app\foo.exe"));
        assert!(!is_ignored(r"C:\Tools\App\bar.exe"));
    }

    #[cfg(windows)]
    #[test]
    fn device_path_matches_when_drive_mapping_known() {
        use windows::core::PCWSTR;
        use windows::Win32::Storage::FileSystem::QueryDosDeviceW;

        let Ok(sys_drive) = std::env::var("SystemDrive") else {
            return;
        };
        let drive = sys_drive.trim_end_matches('\\').to_string();
        if drive.len() != 2 || !drive.ends_with(':') {
            return;
        }
        let drive_wide: Vec<u16> = drive.encode_utf16().chain(std::iter::once(0)).collect();
        let mut buf = vec![0u16; 1024];
        let n = unsafe { QueryDosDeviceW(PCWSTR(drive_wide.as_ptr()), Some(&mut buf)) };
        if n == 0 {
            return;
        }
        let take = (n as usize).min(buf.len());
        let slice = &buf[..take];
        let first_end = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
        let device = String::from_utf16_lossy(&slice[..first_end]);
        let device = device.trim();
        if device.is_empty()
            || !device
                .to_lowercase()
                .starts_with("\\device\\harddiskvolume")
        {
            return;
        }
        let synthetic = format!(r"{device}\Windows\System32\notepad.exe");
        let win32_path = format!(r"{drive}\Windows\System32\notepad.exe");

        let mut conn = fresh_db();
        reload_from_db(&conn).unwrap();
        add(&mut conn, &win32_path, IgnoreKind::Path, None).unwrap();
        assert!(
            is_ignored(&synthetic),
            "expected ignore of device path {synthetic}"
        );
    }
}
