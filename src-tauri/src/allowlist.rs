use rusqlite::Connection;
use serde::Serialize;
use std::path::Path;

pub fn normalize_path(p: &str) -> String {
    p.trim().replace('/', "\\").to_lowercase()
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AllowlistEntry {
    pub image_path: String,
    pub name: String,
    pub created_at: String,
    pub reason: Option<String>,
}

pub fn is_trusted(conn: &Connection, exe_path: Option<&str>) -> rusqlite::Result<bool> {
    let Some(p) = exe_path else {
        return Ok(false);
    };
    let key = normalize_path(p);
    let n: i64 = conn.query_row(
        "SELECT COUNT(*) FROM trusted_paths WHERE path_norm = ?1",
        [&key],
        |row| row.get(0),
    )?;
    Ok(n > 0)
}

pub fn list_entries(conn: &Connection) -> rusqlite::Result<Vec<AllowlistEntry>> {
    let mut stmt = conn.prepare(
        "SELECT path_norm, display_name, created_at, reason FROM trusted_paths ORDER BY created_at DESC",
    )?;
    let rows = stmt.query_map([], |r| {
        let path_norm: String = r.get(0)?;
        let display_name: Option<String> = r.get(1)?;
        let created_at: String = r.get(2)?;
        let reason: Option<String> = r.get(3)?;
        let stem = Path::new(&path_norm)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(&path_norm)
            .to_string();
        let name = display_name
            .filter(|s| !s.trim().is_empty())
            .unwrap_or(stem);
        Ok(AllowlistEntry {
            image_path: path_norm,
            name,
            created_at,
            reason,
        })
    })?;
    rows.collect()
}

pub fn remove_entry(conn: &Connection, image_path: &str) -> rusqlite::Result<()> {
    let key = normalize_path(image_path);
    conn.execute("DELETE FROM trusted_paths WHERE path_norm = ?1", [&key])?;
    Ok(())
}

pub fn set_entry(
    conn: &Connection,
    image_path: &str,
    name: &str,
    trusted: bool,
    reason: Option<&str>,
) -> rusqlite::Result<()> {
    let key = normalize_path(image_path);
    if !trusted {
        conn.execute("DELETE FROM trusted_paths WHERE path_norm = ?1", [&key])?;
        return Ok(());
    }
    let now = chrono::Utc::now().to_rfc3339();
    let disp_raw = name.trim();
    let disp_store = if disp_raw.is_empty() {
        Path::new(image_path.trim())
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string()
    } else {
        disp_raw.to_string()
    };
    let reason_store = reason.and_then(|r| {
        let t = r.trim();
        if t.is_empty() {
            None
        } else {
            Some(t.to_string())
        }
    });
    conn.execute(
        "INSERT INTO trusted_paths (path_norm, created_at, display_name, reason) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(path_norm) DO UPDATE SET
           created_at = excluded.created_at,
           display_name = excluded.display_name,
           reason = excluded.reason",
        rusqlite::params![key, now, disp_store, reason_store],
    )?;
    Ok(())
}

pub fn set_trusted(conn: &Connection, path: &str, trusted: bool) -> rusqlite::Result<()> {
    set_entry(conn, path, "", trusted, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn normalize_path_slash_case_and_trim() {
        assert_eq!(normalize_path("C:\\Foo\\Bar.exe"), "c:\\foo\\bar.exe");
        assert_eq!(normalize_path("c:/foo/bar.exe"), "c:\\foo\\bar.exe");
        assert_eq!(normalize_path("  D:\\tools\\\\ "), "d:\\tools\\\\");
    }

    #[test]
    fn normalize_path_unc() {
        assert_eq!(
            normalize_path("//SERVER/Share/app.exe"),
            "\\\\server\\share\\app.exe"
        );
    }
}
