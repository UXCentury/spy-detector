//! Startup enumeration, scoring, enable/disable. Registry disables are stored in SQLite and the
//! value is removed from Run/RunOnce keys until re-enabled.

use crate::system_surfaces::{severity_from_score, StartupEntry, StartupScope, StartupSource};
use crate::AppState;
use rusqlite::{Connection, OptionalExtension};
use serde::Serialize;
use sha2::{Digest, Sha256};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

const PIPE_ESC: &str = "::pipe::";
pub(crate) const SPYDET_DISABLED_SUFFIX: &str = ".spydet-disabled";

#[derive(Debug, Clone, Serialize)]
pub struct ParsedSchtaskRow {
    pub task_path: String,
    pub command: String,
    pub hidden: bool,
    pub enabled: bool,
}

pub fn parse_schtasks_xml_for_logon_boot(xml: &str) -> Result<Vec<ParsedSchtaskRow>, String> {
    let doc = roxmltree::Document::parse(xml).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for node in doc.descendants().filter(|n| n.has_tag_name("Task")) {
        let has_logon = node
            .descendants()
            .any(|n| n.has_tag_name("LogonTrigger") || n.has_tag_name("BootTrigger"));
        if !has_logon {
            continue;
        }
        let mut task_path = String::new();
        for d in node.descendants() {
            if d.has_tag_name("URI")
                && d.parent()
                    .map(|p| p.has_tag_name("RegistrationInfo"))
                    .unwrap_or(false)
            {
                if let Some(t) = d.text() {
                    task_path = t.trim().to_string();
                }
                break;
            }
        }
        if task_path.is_empty() {
            continue;
        }
        let mut command = String::new();
        for d in node.descendants() {
            if d.has_tag_name("Command") && d.ancestors().any(|a| a.has_tag_name("Exec")) {
                if let Some(t) = d.text() {
                    command.push_str(t.trim());
                }
            }
        }
        if let Some(args) = node.descendants().find(|n| n.has_tag_name("Arguments")) {
            if let Some(t) = args.text() {
                let a = t.trim();
                if !a.is_empty() {
                    command.push(' ');
                    command.push_str(a);
                }
            }
        }
        let hidden = node.descendants().any(|n| {
            n.has_tag_name("Hidden")
                && n.text()
                    .map(|t| t.trim().eq_ignore_ascii_case("true"))
                    .unwrap_or(false)
        });
        let enabled = !node.descendants().any(|n| {
            n.has_tag_name("Enabled")
                && n.text()
                    .map(|t| t.trim().eq_ignore_ascii_case("false"))
                    .unwrap_or(false)
        });
        out.push(ParsedSchtaskRow {
            task_path,
            command,
            hidden,
            enabled,
        });
    }
    Ok(out)
}

fn hash_tail(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    format!("{:x}", h.finalize())[..12].to_string()
}

pub fn stable_startup_id(
    source: StartupSource,
    scope: StartupScope,
    name: &str,
    command: &str,
) -> String {
    format!(
        "{}|{}|{}|{}",
        source.as_db_key(),
        scope.as_db_key(),
        name.replace('|', PIPE_ESC),
        hash_tail(command)
    )
}

pub fn decode_stable_startup_id(id: &str) -> Option<(StartupSource, StartupScope, String)> {
    let (rest, tail) = id.rsplit_once('|')?;
    if tail.len() != 12 || !tail.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let mut it = rest.splitn(3, '|');
    let s = StartupSource::parse_db_key(it.next()?)?;
    let sc = StartupScope::parse_db_key(it.next()?)?;
    let n = it.next()?.replace(PIPE_ESC, "|");
    Some((s, sc, n))
}

#[cfg(windows)]
fn decode_schtasks_stdout(bytes: &[u8]) -> String {
    if bytes.len() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE {
        let u16s: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        return String::from_utf16_lossy(&u16s);
    }
    String::from_utf8_lossy(bytes).into_owned()
}

#[cfg(windows)]
fn collect_schtasks_rows() -> Result<Vec<ParsedSchtaskRow>, String> {
    let out = std::process::Command::new("schtasks")
        .args(["/Query", "/XML"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(format!(
            "schtasks failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    parse_schtasks_xml_for_logon_boot(&decode_schtasks_stdout(&out.stdout))
}

#[cfg(windows)]
fn map_location_to_source_scope(loc: &str) -> Option<(StartupSource, StartupScope)> {
    Some(match loc {
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run" => {
            (StartupSource::HkcuRun, StartupScope::CurrentUser)
        }
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce" => {
            (StartupSource::HkcuRunOnce, StartupScope::CurrentUser)
        }
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run" => {
            (StartupSource::HklmRun, StartupScope::AllUsers)
        }
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce" => {
            (StartupSource::HklmRunOnce, StartupScope::AllUsers)
        }
        r"HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" => {
            (StartupSource::HklmWow64Run, StartupScope::AllUsers)
        }
        "Startup (current user)" => (StartupSource::StartupFolderUser, StartupScope::CurrentUser),
        "Startup (all users)" => (StartupSource::StartupFolderAllUsers, StartupScope::AllUsers),
        _ => return None,
    })
}

#[cfg(windows)]
fn task_can_disable(uri: &str, elevated: bool) -> bool {
    if elevated {
        return true;
    }
    let u = uri.to_lowercase();
    !u.contains("\\microsoft\\windows\\")
}

#[cfg(windows)]
fn registry_subpath_and_hive(source: StartupSource) -> Option<(winreg::HKEY, &'static str)> {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::enums::HKEY_LOCAL_MACHINE;
    Some(match source {
        StartupSource::HkcuRun => (
            HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
        ),
        StartupSource::HkcuRunOnce => (
            HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        ),
        StartupSource::HklmRun => (
            HKEY_LOCAL_MACHINE,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
        ),
        StartupSource::HklmRunOnce => (
            HKEY_LOCAL_MACHINE,
            r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        ),
        StartupSource::HklmWow64Run => (
            HKEY_LOCAL_MACHINE,
            r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        ),
        _ => return None,
    })
}

#[cfg(windows)]
fn elevated() -> bool {
    crate::privilege::is_process_elevated()
}

#[cfg(windows)]
fn is_suspicious_localappdata_path(path: &std::path::Path) -> bool {
    let Ok(la) = std::env::var("LOCALAPPDATA") else {
        return false;
    };
    let Some(ps) = path.to_str() else {
        return false;
    };
    let pl = ps.to_lowercase();
    let ll = la.to_lowercase();
    if !pl.starts_with(&ll) {
        return false;
    }
    let rest = pl.strip_prefix(&ll).unwrap_or("");
    let rest = rest.trim_start_matches('\\');
    let first = rest.split('\\').next().unwrap_or("");
    if first.is_empty() {
        return false;
    }
    let safe = [
        "microsoft",
        "temp",
        "packages",
        "programs",
        "google",
        "mozilla",
    ];
    !safe.iter().any(|s| first.eq_ignore_ascii_case(s))
}

#[cfg(windows)]
// internal helper; refactoring to a struct adds boilerplate without behavior change
#[allow(clippy::too_many_arguments)]
fn score_and_reasons(
    source: StartupSource,
    scope: StartupScope,
    command: &str,
    image_path: Option<&std::path::Path>,
    signed: Option<bool>,
    task_hidden: bool,
    recent_24h: bool,
    ioc_index: &crate::ioc::IocIndex,
) -> (u32, Vec<String>, Option<String>) {
    let mut score: u32 = 0;
    let mut reasons = Vec::new();
    let cmd_l = command.to_lowercase();
    let path_l = image_path
        .and_then(|p| p.to_str())
        .map(|s| s.to_lowercase())
        .unwrap_or_default();
    let exe_stem = image_path
        .and_then(|p| p.file_stem())
        .and_then(|s| s.to_str())
        .map(crate::ioc::norm_token)
        .unwrap_or_default();
    let ioc_match = if !exe_stem.is_empty() || !path_l.is_empty() {
        ioc_index.startup_ioc_match(&exe_stem, &path_l, &cmd_l)
    } else {
        None
    };
    let ioc_label = ioc_match.clone();
    if let Some(ref lb) = ioc_label {
        score = score.saturating_add(40);
        reasons.push(format!("IOC match: {lb}"));
    }
    if let Some(false) = signed {
        score = score.saturating_add(20);
        reasons.push("Executable is not Authenticode-signed".into());
    }
    if let (Some(false), Some(p)) = (signed, image_path) {
        if crate::authenticode::is_in_user_writable_path(p) {
            score = score.saturating_add(35);
            reasons.push("Unsigned binary in a user-writable location".into());
        }
    }
    if let Some(p) = image_path {
        let pl = p.to_string_lossy().to_lowercase();
        if pl.contains("\\temp\\")
            || pl.contains("\\appdata\\local\\temp")
            || is_suspicious_localappdata_path(p)
        {
            score = score.saturating_add(20);
            reasons.push("Binary under temporary or suspicious AppData path".into());
        }
    }
    if matches!(source, StartupSource::HklmRun | StartupSource::HklmWow64Run)
        && matches!(scope, StartupScope::AllUsers)
        && signed == Some(false)
    {
        score = score.saturating_add(15);
        reasons.push("Machine-wide HKLM autostart with unsigned binary".into());
    }
    if task_hidden {
        score = score.saturating_add(25);
        reasons.push("Scheduled task is marked hidden".into());
    }
    if recent_24h {
        score = score.saturating_add(10);
        reasons.push("Newly observed in the last 24 hours".into());
    }
    (score.min(100), reasons, ioc_label)
}

#[cfg(windows)]
fn ensure_first_seen(conn: &Connection, id: &str) -> Result<String, String> {
    let now = chrono::Utc::now().to_rfc3339();
    conn.execute(
        "INSERT OR IGNORE INTO startup_entries_state (id, note, first_seen) VALUES (?1, NULL, ?2)",
        rusqlite::params![id, &now],
    )
    .map_err(|e| e.to_string())?;
    let fs: String = conn
        .query_row(
            "SELECT first_seen FROM startup_entries_state WHERE id = ?1",
            [id],
            |r| r.get(0),
        )
        .map_err(|e| e.to_string())?;
    Ok(fs)
}

#[cfg(windows)]
fn load_note(conn: &Connection, id: &str) -> Result<Option<String>, String> {
    conn.query_row(
        "SELECT note FROM startup_entries_state WHERE id = ?1",
        [id],
        |r| r.get::<_, Option<String>>(0),
    )
    .optional()
    .map(|opt| opt.flatten())
    .map_err(|e| e.to_string())
}

#[cfg(windows)]
struct RawStartupRow(
    String,
    String,
    StartupSource,
    StartupScope,
    bool,
    Option<std::path::PathBuf>,
    bool,
    String,
);

#[cfg(windows)]
pub fn list_all(state: &AppState) -> Result<Vec<StartupEntry>, String> {
    use crate::authenticode::{is_signed, SignatureStatus};
    use crate::autostart::collect_autostart_snapshot_entries;
    use std::collections::HashSet;

    let ioc = state.ioc.read().map_err(|e| e.to_string())?;
    let elevated = elevated();
    let conn = state.db.lock().map_err(|e| e.to_string())?;
    let cutoff = (chrono::Utc::now() - chrono::Duration::hours(24)).to_rfc3339();
    let mut recent_paths: HashSet<String> = HashSet::new();
    {
        let mut stmt = conn
            .prepare("SELECT path_norm FROM autostart_history WHERE first_seen >= ?1")
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([&cutoff], |r| r.get::<_, String>(0))
            .map_err(|e| e.to_string())?;
        for r in rows.flatten() {
            recent_paths.insert(r.to_lowercase());
        }
    }

    let mut live_keys: HashSet<(String, String, String)> = HashSet::new();
    let mut raw: Vec<RawStartupRow> = Vec::new();

    for e in collect_autostart_snapshot_entries() {
        let Some((src, sc)) = map_location_to_source_scope(&e.location) else {
            continue;
        };
        let enabled = !e.name.ends_with(SPYDET_DISABLED_SUFFIX);
        let display_name = if enabled {
            e.name.clone()
        } else {
            e.name
                .strip_suffix(SPYDET_DISABLED_SUFFIX)
                .unwrap_or(&e.name)
                .to_string()
        };
        let cmd = e.command.clone();
        let img = e.resolved_path.clone();
        let entry_name = if matches!(
            src,
            StartupSource::StartupFolderUser | StartupSource::StartupFolderAllUsers
        ) {
            let pth = std::path::Path::new(&e.command);
            let mut stem = pth
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or(&e.name)
                .to_string();
            if stem.to_lowercase().ends_with(".lnk") {
                stem = stem[..stem.len() - 4].to_string();
            }
            stem
        } else {
            display_name.clone()
        };
        live_keys.insert((
            src.as_db_key().to_string(),
            sc.as_db_key().to_string(),
            entry_name.clone(),
        ));
        raw.push(RawStartupRow(
            entry_name,
            cmd,
            src,
            sc,
            enabled,
            img,
            false,
            String::new(),
        ));
    }

    if let Ok(rows) = collect_schtasks_rows() {
        for t in rows {
            let name = t.task_path.clone();
            let cmd = t.command.clone();
            let img = crate::autostart::parse_command_to_exe(&cmd);
            live_keys.insert((
                StartupSource::TaskScheduler.as_db_key().to_string(),
                StartupScope::System.as_db_key().to_string(),
                name.clone(),
            ));
            raw.push(RawStartupRow(
                name,
                cmd,
                StartupSource::TaskScheduler,
                StartupScope::System,
                t.enabled,
                img,
                t.hidden,
                t.task_path,
            ));
        }
    }

    let mut disabled_rows: Vec<(String, String, String, String)> = Vec::new();
    {
        let mut stmt = conn
            .prepare("SELECT source, scope, name, original_value FROM disabled_startup_entries")
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |r| {
                Ok((r.get::<_, String>(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
            })
            .map_err(|e| e.to_string())?;
        for row in rows.flatten() {
            disabled_rows.push(row);
        }
    }
    for (src_s, sc_s, name, orig) in disabled_rows {
        let Some(src) = StartupSource::parse_db_key(&src_s) else {
            continue;
        };
        let Some(sc) = StartupScope::parse_db_key(&sc_s) else {
            continue;
        };
        let k = (src_s.clone(), sc_s.clone(), name.clone());
        if live_keys.contains(&k) {
            continue;
        }
        let img = crate::autostart::parse_command_to_exe(&orig);
        raw.push(RawStartupRow(
            name,
            orig,
            src,
            sc,
            false,
            img,
            false,
            String::new(),
        ));
    }

    let mut out: Vec<StartupEntry> = Vec::new();
    for RawStartupRow(name, command, source, scope, enabled, image_path, task_hidden, task_path) in
        raw
    {
        let id = stable_startup_id(source, scope, &name, &command);
        let first_seen = ensure_first_seen(&conn, &id)?;
        let note = load_note(&conn, &id)?;
        let path_norm = image_path
            .as_ref()
            .and_then(|p| p.to_str())
            .map(|s| s.to_lowercase());
        let recent = path_norm
            .as_ref()
            .map(|p| recent_paths.contains(p))
            .unwrap_or(false);
        let signed = if let Some(ref p) = image_path {
            if p.exists() {
                Some(matches!(is_signed(p), SignatureStatus::Signed))
            } else {
                None
            }
        } else {
            None
        };
        let (score, reasons, ioc_match) = score_and_reasons(
            source,
            scope,
            &command,
            image_path.as_deref(),
            signed,
            task_hidden,
            recent,
            &ioc,
        );
        let can_disable = match source {
            StartupSource::HkcuRun
            | StartupSource::HkcuRunOnce
            | StartupSource::StartupFolderUser => true,
            StartupSource::StartupFolderAllUsers => elevated,
            StartupSource::HklmRun | StartupSource::HklmRunOnce | StartupSource::HklmWow64Run => {
                elevated
            }
            StartupSource::TaskScheduler => task_can_disable(&task_path, elevated),
        };
        let severity = severity_from_score(score);
        let last_modified = image_path
            .as_ref()
            .filter(|p| p.exists())
            .and_then(|p| std::fs::metadata(p).ok())
            .and_then(|m| m.modified().ok())
            .map(|t| chrono::DateTime::<chrono::Utc>::from(t).to_rfc3339());
        out.push(StartupEntry {
            id,
            name,
            command,
            image_path: image_path
                .as_ref()
                .and_then(|p| p.to_str().map(String::from)),
            source,
            scope,
            first_seen,
            last_modified,
            signed,
            publisher: None,
            ioc_match,
            enabled,
            score,
            severity,
            reasons,
            can_disable,
            note,
        });
    }
    out.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.name.cmp(&b.name)));
    Ok(out)
}

#[cfg(not(windows))]
pub fn list_all(_state: &AppState) -> Result<Vec<StartupEntry>, String> {
    Ok(vec![])
}

#[cfg(windows)]
pub fn refresh(state: &AppState) -> Result<Vec<StartupEntry>, String> {
    list_all(state)
}

#[cfg(not(windows))]
pub fn refresh(_state: &AppState) -> Result<Vec<StartupEntry>, String> {
    Ok(vec![])
}

#[cfg(windows)]
pub fn set_note(state: &AppState, id: String, note: Option<String>) -> Result<(), String> {
    let conn = state.db.lock().map_err(|e| e.to_string())?;
    let now = chrono::Utc::now().to_rfc3339();
    conn.execute(
        "INSERT INTO startup_entries_state (id, note, first_seen) VALUES (?1, ?2, ?3)
         ON CONFLICT(id) DO UPDATE SET note = excluded.note",
        rusqlite::params![id, note, &now],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(not(windows))]
pub fn set_note(_state: &AppState, _id: String, _note: Option<String>) -> Result<(), String> {
    Ok(())
}

#[cfg(windows)]
pub fn set_enabled(state: &AppState, id: String, enabled: bool) -> Result<(), String> {
    use crate::event_log::{log as log_event, EventKind};
    use winreg::enums::{KEY_READ, KEY_WRITE};
    use winreg::RegKey;

    let (source, scope, name) =
        decode_stable_startup_id(&id).ok_or_else(|| "Invalid startup id".to_string())?;
    let elevated = elevated();
    let conn = state.db.lock().map_err(|e| e.to_string())?;

    match source {
        StartupSource::HkcuRun
        | StartupSource::HkcuRunOnce
        | StartupSource::HklmRun
        | StartupSource::HklmRunOnce
        | StartupSource::HklmWow64Run => {
            if !enabled {
                if matches!(
                    source,
                    StartupSource::HklmRun
                        | StartupSource::HklmRunOnce
                        | StartupSource::HklmWow64Run
                ) && !elevated
                {
                    return Err(
                        "Requires administrator. Use 'Restart as administrator' from the title bar."
                            .into(),
                    );
                }
                let Some((hive, sub)) = registry_subpath_and_hive(source) else {
                    return Err("Unsupported source".into());
                };
                let root = RegKey::predef(hive);
                let key = root
                    .open_subkey_with_flags(sub, KEY_READ | KEY_WRITE)
                    .map_err(|e| e.to_string())?;
                let val: String = match key.get_value::<String, &str>(name.as_str()) {
                    Ok(v) => v,
                    Err(_) => return Err("Registry value not found".into()),
                };
                let now = chrono::Utc::now().to_rfc3339();
                conn.execute(
                    "INSERT OR REPLACE INTO disabled_startup_entries (source, scope, name, original_value, disabled_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                    rusqlite::params![
                        source.as_db_key(),
                        scope.as_db_key(),
                        &name,
                        &val,
                        &now
                    ],
                )
                .map_err(|e| e.to_string())?;
                key.delete_value(&name).map_err(|e| e.to_string())?;
                log_event(
                    EventKind::AutostartEntryDisabled,
                    "low",
                    None,
                    None,
                    None,
                    None,
                    format!("Disabled startup registry entry {name}"),
                );
            } else {
                let row: Option<String> = conn
                    .query_row(
                        "SELECT original_value FROM disabled_startup_entries WHERE source = ?1 AND scope = ?2 AND name = ?3",
                        rusqlite::params![source.as_db_key(), scope.as_db_key(), &name],
                        |r| r.get(0),
                    )
                    .optional()
                    .map_err(|e| e.to_string())?;
                let Some(orig) = row else {
                    return Ok(());
                };
                if matches!(
                    source,
                    StartupSource::HklmRun
                        | StartupSource::HklmRunOnce
                        | StartupSource::HklmWow64Run
                ) && !elevated
                {
                    return Err(
                        "Requires administrator. Use 'Restart as administrator' from the title bar."
                            .into(),
                    );
                }
                let Some((hive, sub)) = registry_subpath_and_hive(source) else {
                    return Err("Unsupported source".into());
                };
                let root = RegKey::predef(hive);
                let (k, _) = root
                    .create_subkey_with_flags(sub, KEY_READ | KEY_WRITE)
                    .map_err(|e| e.to_string())?;
                k.set_value(&name, &orig).map_err(|e| e.to_string())?;
                conn.execute(
                    "DELETE FROM disabled_startup_entries WHERE source = ?1 AND scope = ?2 AND name = ?3",
                    rusqlite::params![source.as_db_key(), scope.as_db_key(), &name],
                )
                .map_err(|e| e.to_string())?;
                log_event(
                    EventKind::AutostartEntryEnabled,
                    "low",
                    None,
                    None,
                    None,
                    None,
                    format!("Enabled startup registry entry {name}"),
                );
            }
        }
        StartupSource::StartupFolderUser | StartupSource::StartupFolderAllUsers => {
            let dir = if matches!(source, StartupSource::StartupFolderUser) {
                crate::autostart::startup_dir_user()
            } else {
                crate::autostart::startup_dir_common()
            };
            let Some(dir) = dir else {
                return Err("Startup folder not found".into());
            };
            if matches!(source, StartupSource::StartupFolderAllUsers) && !elevated {
                return Err(
                    "Requires administrator. Use 'Restart as administrator' from the title bar."
                        .into(),
                );
            }
            if !enabled {
                let from = dir.join(format!("{name}.lnk"));
                let to = dir.join(format!("{name}.lnk{SPYDET_DISABLED_SUFFIX}"));
                std::fs::rename(&from, &to).map_err(|e| e.to_string())?;
                log_event(
                    EventKind::AutostartEntryDisabled,
                    "low",
                    None,
                    None,
                    None,
                    None,
                    format!("Disabled startup shortcut {name}"),
                );
            } else {
                let from = dir.join(format!("{name}.lnk{SPYDET_DISABLED_SUFFIX}"));
                let to = dir.join(format!("{name}.lnk"));
                std::fs::rename(&from, &to).map_err(|e| e.to_string())?;
                log_event(
                    EventKind::AutostartEntryEnabled,
                    "low",
                    None,
                    None,
                    None,
                    None,
                    format!("Enabled startup shortcut {name}"),
                );
            }
        }
        StartupSource::TaskScheduler => {
            if !elevated {
                return Err(
                    "Requires administrator. Use 'Restart as administrator' from the title bar."
                        .into(),
                );
            }
            let tn = &name;
            let arg = if enabled { "/Enable" } else { "/Disable" };
            let st = std::process::Command::new("schtasks")
                .args(["/Change", "/TN", tn, arg])
                .creation_flags(CREATE_NO_WINDOW)
                .status()
                .map_err(|e| e.to_string())?;
            if !st.success() {
                return Err(format!(
                    "schtasks /Change failed: {}",
                    st.code().map(|c| c.to_string()).unwrap_or_default()
                ));
            }
            log_event(
                if enabled {
                    EventKind::AutostartEntryEnabled
                } else {
                    EventKind::AutostartEntryDisabled
                },
                "low",
                None,
                None,
                None,
                None,
                format!("Task scheduler entry {tn}"),
            );
        }
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn set_enabled(_state: &AppState, _id: String, _enabled: bool) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sample_schtasks_xml_finds_logon_task() {
        let xml = include_str!("../tests/fixtures/schtasks_sample.xml");
        let rows = parse_schtasks_xml_for_logon_boot(xml).expect("parse");
        assert!(!rows.is_empty());
        assert!(rows.iter().any(|r| r.task_path.contains("SpyDetTestLogon")));
    }

    #[test]
    fn decode_round_trip_stable_startup_id() {
        let id = stable_startup_id(
            StartupSource::HkcuRun,
            StartupScope::CurrentUser,
            "My|App",
            "C:\\\\Windows\\\\System32\\\\notepad.exe",
        );
        let (s, sc, n) = decode_stable_startup_id(&id).unwrap();
        assert_eq!(s, StartupSource::HkcuRun);
        assert_eq!(sc, StartupScope::CurrentUser);
        assert_eq!(n, "My|App");
    }
}
