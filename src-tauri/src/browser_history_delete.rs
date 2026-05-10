//! Delete URLs from real browser history SQLite databases (Windows paths).

use crate::app_log;
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteOutcome {
    pub url: String,
    pub browser: String,
    pub success: bool,
    #[serde(default)]
    pub not_present: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeleteUrlOk {
    pub not_present: bool,
}

pub fn browser_slug(display_name: &str) -> String {
    match display_name.trim() {
        "Chrome" => "chrome".into(),
        "Edge" => "edge".into(),
        "Brave" => "brave".into(),
        "Firefox" => "firefox".into(),
        _ => display_name.trim().to_ascii_lowercase(),
    }
}

pub fn error_is_busy(msg: &str) -> bool {
    let m = msg.to_ascii_lowercase();
    m.contains("database is locked") || m.contains("busy")
}

pub fn resolve_history_sqlite_path(browser: &str, profile_label: &str) -> Result<PathBuf, String> {
    let as_path = Path::new(profile_label.trim());
    if as_path.is_file() {
        return Ok(as_path.to_path_buf());
    }

    match browser.trim() {
        "Chrome" => {
            let local =
                std::env::var("LOCALAPPDATA").map_err(|_| "LOCALAPPDATA not set".to_string())?;
            Ok(PathBuf::from(local)
                .join("Google")
                .join("Chrome")
                .join("User Data")
                .join(profile_label)
                .join("History"))
        }
        "Edge" => {
            let local =
                std::env::var("LOCALAPPDATA").map_err(|_| "LOCALAPPDATA not set".to_string())?;
            Ok(PathBuf::from(local)
                .join("Microsoft")
                .join("Edge")
                .join("User Data")
                .join(profile_label)
                .join("History"))
        }
        "Brave" => {
            let local =
                std::env::var("LOCALAPPDATA").map_err(|_| "LOCALAPPDATA not set".to_string())?;
            Ok(PathBuf::from(local)
                .join("BraveSoftware")
                .join("Brave-Browser")
                .join("User Data")
                .join(profile_label)
                .join("History"))
        }
        "Firefox" => {
            let appdata = std::env::var("APPDATA").map_err(|_| "APPDATA not set".to_string())?;
            Ok(PathBuf::from(appdata)
                .join("Mozilla")
                .join("Firefox")
                .join("Profiles")
                .join(profile_label)
                .join("places.sqlite"))
        }
        other => Err(format!("unknown browser: {other}")),
    }
    .and_then(|p| {
        if p.is_file() {
            Ok(p)
        } else {
            Err(format!("history database not found: {}", p.display()))
        }
    })
}

fn with_busy_retries<T, F: FnMut() -> Result<T, String>>(
    browser_display: &str,
    mut f: F,
) -> Result<T, String> {
    let started = Instant::now();
    let mut last = String::new();
    for attempt in 0..3 {
        app_log::append_line(&format!(
            "[browser-history-delete] busy_retry attempt={}/3 elapsed_ms={} browser={}",
            attempt + 1,
            started.elapsed().as_millis(),
            browser_display
        ));
        match f() {
            Ok(v) => return Ok(v),
            Err(e) => {
                last = e.clone();
                if error_is_busy(&last) && attempt < 2 {
                    app_log::append_line(&format!(
                        "[browser-history-delete] busy_retry backing_off_ms=500 browser={} err={}",
                        browser_display, last
                    ));
                    std::thread::sleep(Duration::from_millis(500));
                    continue;
                }
                if error_is_busy(&last) {
                    let locked = format!("locked:{}", browser_display);
                    app_log::append_line(&format!(
                        "[browser-history-delete] outcome=locked browser={} err={}",
                        browser_display, last
                    ));
                    return Err(locked);
                }
                return Err(last);
            }
        }
    }
    if error_is_busy(&last) {
        app_log::append_line(&format!(
            "[browser-history-delete] outcome=locked_exhausted browser={} err={}",
            browser_display, last
        ));
        return Err(format!("locked:{}", browser_display));
    }
    Err(last)
}

fn ignore_no_such_table_rows(res: rusqlite::Result<usize>) -> rusqlite::Result<usize> {
    match res {
        Ok(n) => Ok(n),
        Err(e) => {
            if e.to_string().contains("no such table") {
                Ok(0)
            } else {
                Err(e)
            }
        }
    }
}

pub(crate) fn delete_chromium(conn: &mut Connection, url: &str) -> rusqlite::Result<usize> {
    let ids: Vec<i64> = {
        let mut stmt = conn.prepare("SELECT id FROM urls WHERE url = ?1")?;
        let collected = stmt
            .query_map([url], |r| r.get(0))?
            .collect::<Result<Vec<_>, _>>()?;
        collected
    };

    let mut urls_removed = 0usize;
    for url_id in ids {
        let tx = conn.transaction()?;
        let n_vs = ignore_no_such_table_rows(tx.execute(
            "DELETE FROM visit_source WHERE id IN (SELECT id FROM visits WHERE url = ?1)",
            [url_id],
        ))?;
        app_log::append_line(&format!(
            "[browser-history-delete] chromium DELETE visit_source rows_affected={} url_id={}",
            n_vs, url_id
        ));
        let n_visits = tx.execute("DELETE FROM visits WHERE url = ?1", [url_id])?;
        app_log::append_line(&format!(
            "[browser-history-delete] chromium DELETE visits rows_affected={} url_id={}",
            n_visits, url_id
        ));
        let n_kw = ignore_no_such_table_rows(tx.execute(
            "DELETE FROM keyword_search_terms WHERE url_id = ?1",
            [url_id],
        ))?;
        app_log::append_line(&format!(
            "[browser-history-delete] chromium DELETE keyword_search_terms rows_affected={} url_id={}",
            n_kw, url_id
        ));
        let n_seg = ignore_no_such_table_rows(
            tx.execute("DELETE FROM segments WHERE url_id = ?1", [url_id]),
        )?;
        app_log::append_line(&format!(
            "[browser-history-delete] chromium DELETE segments rows_affected={} url_id={}",
            n_seg, url_id
        ));
        let n_urls = tx.execute("DELETE FROM urls WHERE id = ?1", [url_id])?;
        app_log::append_line(&format!(
            "[browser-history-delete] chromium DELETE urls rows_affected={} url_id={}",
            n_urls, url_id
        ));
        tx.commit()?;
        urls_removed += 1;
    }
    Ok(urls_removed)
}

pub(crate) fn delete_firefox(conn: &mut Connection, url: &str) -> rusqlite::Result<usize> {
    let place_ids: Vec<i64> = {
        let mut stmt = conn.prepare("SELECT id FROM moz_places WHERE url = ?1")?;
        let collected = stmt
            .query_map([url], |r| r.get(0))?
            .collect::<Result<Vec<_>, _>>()?;
        collected
    };

    let mut places_cleared = 0usize;
    for place_id in place_ids {
        let tx = conn.transaction()?;
        let bookmarked: bool = tx
            .query_row(
                "SELECT 1 FROM moz_bookmarks WHERE fk = ?1 LIMIT 1",
                [place_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some();

        let n_hv = tx.execute(
            "DELETE FROM moz_historyvisits WHERE place_id = ?1",
            [place_id],
        )?;
        app_log::append_line(&format!(
            "[browser-history-delete] firefox DELETE moz_historyvisits rows_affected={} place_id={}",
            n_hv, place_id
        ));
        let n_ih = ignore_no_such_table_rows(tx.execute(
            "DELETE FROM moz_inputhistory WHERE place_id = ?1",
            [place_id],
        ))?;
        app_log::append_line(&format!(
            "[browser-history-delete] firefox DELETE moz_inputhistory rows_affected={} place_id={}",
            n_ih, place_id
        ));

        let n_pl = if !bookmarked {
            tx.execute("DELETE FROM moz_places WHERE id = ?1", [place_id])?
        } else {
            0
        };
        app_log::append_line(&format!(
            "[browser-history-delete] firefox DELETE moz_places rows_affected={} place_id={} bookmarked={}",
            n_pl, place_id, bookmarked
        ));
        tx.commit()?;
        places_cleared += 1;
    }
    Ok(places_cleared)
}

pub fn delete_url_from_browser(
    browser_display: &str,
    profile_path: &Path,
    url: &str,
) -> Result<DeleteUrlOk, String> {
    let slug = browser_slug(browser_display);
    app_log::append_line(&format!(
        "[browser-history-delete] delete_url_from_browser enter browser={} slug={} profile_path={} url={}",
        browser_display,
        slug,
        profile_path.display(),
        url
    ));

    let is_firefox = slug == "firefox"
        || profile_path
            .file_name()
            .and_then(|s| s.to_str())
            .is_some_and(|n| n.eq_ignore_ascii_case("places.sqlite"));

    with_busy_retries(browser_display, || {
        let mut conn = Connection::open_with_flags(profile_path, OpenFlags::SQLITE_OPEN_READ_WRITE)
            .map_err(|e| e.to_string())?;
        conn.busy_timeout(Duration::from_millis(2000))
            .map_err(|e| e.to_string())?;

        let outline_res = if is_firefox {
            let place_ids: Vec<i64> = {
                let mut stmt = conn
                    .prepare("SELECT id FROM moz_places WHERE url = ?1")
                    .map_err(|e| e.to_string())?;
                let rows = stmt
                    .query_map([url], |r| r.get(0))
                    .map_err(|e| e.to_string())?;
                rows.collect::<Result<Vec<_>, _>>()
                    .map_err(|e| e.to_string())?
            };
            app_log::append_line(&format!(
                "[browser-history-delete] firefox SELECT moz_places id match count={} browser={}",
                place_ids.len(),
                browser_display
            ));
            if place_ids.is_empty() {
                app_log::append_line(&format!(
                    "[browser-history-delete] outcome=success_not_present browser={} url={}",
                    browser_display, url
                ));
                return Ok(DeleteUrlOk { not_present: true });
            }
            delete_firefox(&mut conn, url).map_err(|e| e.to_string())
        } else {
            let ids: Vec<i64> = {
                let mut stmt = conn
                    .prepare("SELECT id FROM urls WHERE url = ?1")
                    .map_err(|e| e.to_string())?;
                let rows = stmt
                    .query_map([url], |r| r.get(0))
                    .map_err(|e| e.to_string())?;
                rows.collect::<Result<Vec<_>, _>>()
                    .map_err(|e| e.to_string())?
            };
            app_log::append_line(&format!(
                "[browser-history-delete] chromium SELECT urls id match count={} browser={}",
                ids.len(),
                browser_display
            ));
            if ids.is_empty() {
                app_log::append_line(&format!(
                    "[browser-history-delete] outcome=success_not_present browser={} url={}",
                    browser_display, url
                ));
                return Ok(DeleteUrlOk { not_present: true });
            }
            delete_chromium(&mut conn, url).map_err(|e| e.to_string())
        };

        let removed = outline_res?;
        app_log::append_line(&format!(
            "[browser-history-delete] outcome=success_removed browser={} chains_removed={}",
            browser_display, removed
        ));
        Ok(DeleteUrlOk { not_present: false })
    })
    .map_err(|e| {
        app_log::append_line(&format!(
            "[browser-history-delete] outcome=error browser={} profile_path={} err={}",
            browser_display,
            profile_path.display(),
            e
        ));
        e
    })
}

#[allow(dead_code)]
pub fn delete_urls(items: &[(String, PathBuf, String)]) -> Vec<DeleteOutcome> {
    items
        .iter()
        .map(
            |(browser, path, url)| match delete_url_from_browser(browser, path, url) {
                Ok(ok) => DeleteOutcome {
                    url: url.clone(),
                    browser: browser_slug(browser),
                    success: true,
                    not_present: ok.not_present,
                    error: if ok.not_present {
                        Some("not-present-in-history".into())
                    } else {
                        None
                    },
                },
                Err(e) => DeleteOutcome {
                    url: url.clone(),
                    browser: browser_slug(browser),
                    success: false,
                    not_present: false,
                    error: Some(e),
                },
            },
        )
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::tempdir;

    #[test]
    fn delete_chromium_removes_url_chain() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("History");
        let conn = Connection::open(&db_path).unwrap();
        conn.execute_batch(
            r"
            CREATE TABLE urls (
                id INTEGER PRIMARY KEY,
                url TEXT,
                title TEXT,
                visit_count INT,
                typed_count INT,
                last_visit_time INT,
                hidden INT
            );
            CREATE TABLE visits (
                id INTEGER PRIMARY KEY,
                url INTEGER,
                visit_time INT,
                from_visit INT,
                transition INT
            );
            CREATE TABLE visit_source (
                id INTEGER PRIMARY KEY,
                source INT
            );
            CREATE TABLE keyword_search_terms (
                keyword_id INTEGER,
                url_id INTEGER,
                term TEXT,
                normalized_term TEXT
            );
            CREATE TABLE segments (
                id INTEGER PRIMARY KEY,
                name TEXT,
                url_id INTEGER,
                segment_usage_id INTEGER
            );
            ",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO urls (id, url, title, visit_count, typed_count, last_visit_time, hidden) VALUES (1, 'https://evil.example/', 't', 1, 0, 0, 0)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO visits (id, url, visit_time, from_visit, transition) VALUES (10, 1, 0, 0, 0)",
            [],
        )
        .unwrap();
        conn.execute("INSERT INTO visit_source (id, source) VALUES (10, 0)", [])
            .unwrap();
        conn.execute(
            "INSERT INTO keyword_search_terms (keyword_id, url_id, term, normalized_term) VALUES (1, 1, 'x', 'x')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO segments (id, name, url_id, segment_usage_id) VALUES (1, 's', 1, 1)",
            [],
        )
        .unwrap();
        drop(conn);

        let mut conn = Connection::open(&db_path).unwrap();
        delete_chromium(&mut conn, "https://evil.example/").unwrap();
        drop(conn);

        let conn = Connection::open(&db_path).unwrap();
        let urls_left: i64 = conn
            .query_row("SELECT COUNT(*) FROM urls", [], |r| r.get(0))
            .unwrap();
        let visits_left: i64 = conn
            .query_row("SELECT COUNT(*) FROM visits", [], |r| r.get(0))
            .unwrap();
        assert_eq!(urls_left, 0);
        assert_eq!(visits_left, 0);
    }

    #[test]
    fn delete_firefox_skips_place_when_bookmarked() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("places.sqlite");
        let conn = Connection::open(&db_path).unwrap();
        conn.execute_batch(
            r"
            CREATE TABLE moz_places (
                id INTEGER PRIMARY KEY,
                url TEXT,
                title TEXT,
                visit_count INTEGER,
                hidden INTEGER,
                typed INTEGER,
                favicon_id INTEGER,
                frecency INTEGER,
                last_visit_date INTEGER
            );
            CREATE TABLE moz_historyvisits (
                id INTEGER PRIMARY KEY,
                from_visit INTEGER,
                place_id INTEGER,
                visit_date INTEGER,
                visit_type INTEGER,
                session INTEGER,
                guid TEXT
            );
            CREATE TABLE moz_inputhistory (
                place_id INTEGER,
                input TEXT,
                use_count INTEGER,
                PRIMARY KEY (place_id, input)
            );
            CREATE TABLE moz_bookmarks (
                id INTEGER PRIMARY KEY,
                type INTEGER,
                fk INTEGER,
                parent INTEGER,
                position INTEGER,
                title TEXT,
                dateAdded INTEGER,
                lastModified INTEGER,
                guid TEXT
            );
            ",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO moz_places (id, url, title, visit_count, hidden, typed, favicon_id, frecency, last_visit_date)
             VALUES (1, 'https://keep.example/', 'x', 1, 0, 0, 0, 1, 1)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO moz_historyvisits (id, from_visit, place_id, visit_date, visit_type, session, guid)
             VALUES (1, 0, 1, 1, 1, 0, 'g')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO moz_inputhistory (place_id, input, use_count) VALUES (1, 'q', 1)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO moz_bookmarks (id, type, fk, parent, position, title, dateAdded, lastModified, guid)
             VALUES (1, 1, 1, 0, 0, 'b', 0, 0, 'bg')",
            [],
        )
        .unwrap();
        drop(conn);

        let mut conn = Connection::open(&db_path).unwrap();
        delete_firefox(&mut conn, "https://keep.example/").unwrap();
        drop(conn);

        let conn = Connection::open(&db_path).unwrap();
        let places_left: i64 = conn
            .query_row("SELECT COUNT(*) FROM moz_places WHERE id = 1", [], |r| {
                r.get(0)
            })
            .unwrap();
        let visits_left: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM moz_historyvisits WHERE place_id = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(places_left, 1);
        assert_eq!(visits_left, 0);
    }

    #[test]
    fn delete_chromium_url_absent_reports_success_not_present() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("History");
        let conn = Connection::open(&db_path).unwrap();
        conn.execute_batch(
            r"
            CREATE TABLE urls (
                id INTEGER PRIMARY KEY,
                url TEXT,
                title TEXT,
                visit_count INT,
                typed_count INT,
                last_visit_time INT,
                hidden INT
            );
            ",
        )
        .unwrap();
        drop(conn);

        let ok = delete_url_from_browser("Chrome", &db_path, "https://never-inserted.example/path")
            .expect("delete should succeed when URL is absent from Chromium history");
        assert!(ok.not_present);

        let conn = Connection::open(&db_path).unwrap();
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM urls", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0);
    }
}
