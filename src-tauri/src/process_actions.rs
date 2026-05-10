//! Kill / quarantine with PID+exe binding (`confirm_token`) and findings/sysinfo checks.

use crate::app_log;
use crate::db;
use crate::event_log::{log as log_event, EventKind};
use crate::scan::{self, Finding};
use crate::AppState;
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use sysinfo::{Pid, System};
use tauri::State;

const KILL_PREFIX: &str = "KILL";
const QUARANTINE_PREFIX: &str = "QUARANTINE";

pub fn confirm_token_hex(prefix: &str, pid: u32, exe_path: Option<&str>) -> String {
    let exe = exe_path.unwrap_or("");
    let payload = format!("{prefix}:{pid}:{exe}");
    let digest = Sha256::digest(payload.as_bytes());
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

fn paths_equivalent_win(a: &str, b: &str) -> bool {
    a.trim().eq_ignore_ascii_case(b.trim())
}

/// Latest-scan PID reuse guard: if the PID was reported in the last scan, the live image path must match.
fn verify_pid_not_reused(
    findings: &[Finding],
    pid: u32,
    live_exe: Option<&str>,
) -> Result<(), String> {
    if let Some(f) = findings.iter().find(|f| f.pid == pid) {
        if let (Some(stored), Some(live)) = (&f.exe_path, live_exe) {
            if !paths_equivalent_win(stored, live) {
                return Err(
                    "This PID no longer matches the executable from the latest scan (possible PID reuse)."
                        .into(),
                );
            }
        }
    }
    Ok(())
}

/// Target must be running now, and either appear in latest findings or in the live process list (always true if running).
pub fn process_eligible_for_action(
    conn: &Connection,
    pid: u32,
    live_exe: Option<&str>,
    live_name: &str,
) -> Result<bool, String> {
    let findings = scan::load_latest_findings(conn)?.unwrap_or_default();
    verify_pid_not_reused(&findings, pid, live_exe)?;

    let in_findings = findings.iter().any(|f| f.pid == pid);
    // Running process is always in the live list; findings OR process-list sources match spec.
    let _keep = live_name;
    Ok(in_findings || live_exe.is_some() || !live_name.is_empty())
}

pub fn resolve_live_process(pid: u32) -> Option<(String, Option<String>)> {
    let mut sys = System::new_all();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
    let proc = sys.process(Pid::from_u32(pid))?;
    let name = proc.name().to_string_lossy().into_owned();
    let exe_path = proc
        .exe()
        .map(|p| p.to_string_lossy().into_owned())
        .filter(|s| !s.is_empty());
    Some((name, exe_path))
}

fn verify_token(
    expected_prefix: &str,
    pid: u32,
    exe_path: Option<&str>,
    confirm_token: &str,
) -> Result<(), String> {
    let expect = confirm_token_hex(expected_prefix, pid, exe_path);
    if confirm_token.trim().eq_ignore_ascii_case(&expect) {
        Ok(())
    } else {
        Err("Confirmation token mismatch; prepare the action again.".into())
    }
}

fn quarantine_dir() -> Result<PathBuf, String> {
    let d = crate::app_log::app_data_dir()?.join("quarantine");
    std::fs::create_dir_all(&d).map_err(|e| e.to_string())?;
    Ok(d)
}

#[cfg(windows)]
fn move_file_copy_allowed(src: &Path, dest: &Path) -> Result<(), String> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_COPY_ALLOWED, MOVEFILE_REPLACE_EXISTING,
    };

    fn wide(s: &OsStr) -> Vec<u16> {
        s.encode_wide().chain(std::iter::once(0)).collect()
    }
    let old = wide(src.as_os_str());
    let new = wide(dest.as_os_str());
    let flags = MOVEFILE_COPY_ALLOWED | MOVEFILE_REPLACE_EXISTING;
    unsafe {
        MoveFileExW(PCWSTR(old.as_ptr()), PCWSTR(new.as_ptr()), flags)
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[cfg(not(windows))]
fn move_file_copy_allowed(_src: &Path, _dest: &Path) -> Result<(), String> {
    Err("Quarantine is only supported on Windows.".into())
}

#[cfg(windows)]
fn terminate_pid(pid: u32) -> Result<(), String> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};

    unsafe {
        let handle = OpenProcess(PROCESS_TERMINATE, false, pid)
            .map_err(|e| format!("OpenProcess failed ({e}); try running elevated."))?;
        let r = TerminateProcess(handle, 1);
        let _ = CloseHandle(handle);
        r.map_err(|e| format!("TerminateProcess failed ({e})."))?;
    }
    Ok(())
}

#[cfg(not(windows))]
fn terminate_pid(_pid: u32) -> Result<(), String> {
    Err("Process termination is only supported on Windows.".into())
}

// --- Tauri structs ---

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrepareProcessActionResult {
    pub exe_path: Option<String>,
    pub name: String,
    pub can_kill: bool,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuarantineProcessResult {
    pub quarantine_path: String,
}

#[tauri::command(rename_all = "camelCase")]
pub fn prepare_process_action(
    state: State<AppState>,
    pid: u32,
) -> Result<PrepareProcessActionResult, String> {
    let db = state.db.lock().map_err(|e| e.to_string())?;
    let Some((name, exe_path)) = resolve_live_process(pid) else {
        return Ok(PrepareProcessActionResult {
            exe_path: None,
            name: String::new(),
            can_kill: false,
        });
    };

    let blocked_self = exe_path
        .as_deref()
        .map(is_spy_detector_exe)
        .unwrap_or(false);

    let eligible = process_eligible_for_action(&db, pid, exe_path.as_deref(), &name)?;
    let can_kill =
        eligible && exe_path.as_deref().map(|p| !p.is_empty()).unwrap_or(true) && !blocked_self;

    Ok(PrepareProcessActionResult {
        exe_path,
        name,
        can_kill,
    })
}

#[tauri::command(rename_all = "camelCase")]
pub fn kill_process(state: State<AppState>, pid: u32, confirm_token: String) -> Result<(), String> {
    let (name, exe_path) = {
        let db = state.db.lock().map_err(|e| e.to_string())?;
        let Some((name, exe_path)) = resolve_live_process(pid) else {
            return Err("Process is not running.".into());
        };
        if !process_eligible_for_action(&db, pid, exe_path.as_deref(), &name)? {
            return Err("Process is not eligible for this action.".into());
        }
        verify_token(KILL_PREFIX, pid, exe_path.as_deref(), &confirm_token)?;
        if exe_path
            .as_deref()
            .map(is_spy_detector_exe)
            .unwrap_or(false)
        {
            return Err("Refusing to terminate Spy Detector itself.".into());
        }
        (name, exe_path)
    };

    match terminate_pid(pid) {
        Ok(()) => {
            let db = state.db.lock().map_err(|e| e.to_string())?;
            let detail = format!("name={name} exe={:?}", exe_path);
            db::log_security_action(&db, "kill_process", Some(pid), &detail)?;
            log_event(
                EventKind::ProcessKilled,
                "high",
                Some(pid),
                Some(name.clone()),
                exe_path.clone(),
                None,
                format!("Process terminated: {name} ({pid})"),
            );
            app_log::append_line(&format!("kill_process pid={pid} {detail}"));
            Ok(())
        }
        Err(e) => {
            log_event(
                EventKind::ProcessKilled,
                "warn",
                Some(pid),
                Some(name.clone()),
                exe_path.clone(),
                Some(serde_json::json!({ "error": e })),
                format!("Kill failed: {name} ({pid})"),
            );
            Err(e)
        }
    }
}

#[tauri::command(rename_all = "camelCase")]
pub fn quarantine_process(
    state: State<AppState>,
    pid: u32,
    confirm_token: String,
) -> Result<QuarantineProcessResult, String> {
    let (name, exe_path, src, dest) = {
        let db = state.db.lock().map_err(|e| e.to_string())?;
        let Some((name, exe_path)) = resolve_live_process(pid) else {
            return Err("Process is not running.".into());
        };
        if !process_eligible_for_action(&db, pid, exe_path.as_deref(), &name)? {
            return Err("Process is not eligible for this action.".into());
        }
        verify_token(QUARANTINE_PREFIX, pid, exe_path.as_deref(), &confirm_token)?;

        let exe_path_s = exe_path
            .as_deref()
            .filter(|p| !p.is_empty())
            .ok_or_else(|| "Executable path is unknown; cannot quarantine.".to_string())?;
        if is_spy_detector_exe(exe_path_s) {
            return Err("Refusing to quarantine Spy Detector itself.".into());
        }
        let src = PathBuf::from(exe_path_s);
        if !src.is_file() {
            return Err("Executable file is missing on disk; nothing to quarantine.".into());
        }

        let fname = src
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| "Could not read executable file name.".to_string())?;
        let ts = chrono::Utc::now().format("%Y%m%dT%H%M%SZ");
        let dest = quarantine_dir()?.join(format!("{ts}_{fname}"));
        (name, exe_path, src, dest)
    };

    // Move first so we fail fast when the image is locked; then terminate.
    // Race: another instance could respawn; operator may need a second attempt.
    move_file_copy_allowed(&src, &dest).map_err(|e| {
        let msg = format!("Could not move executable into quarantine (it may be in use): {e}");
        log_event(
            EventKind::ProcessQuarantined,
            "warn",
            Some(pid),
            Some(name.clone()),
            exe_path.clone(),
            Some(serde_json::json!({ "error": msg.clone() })),
            "Quarantine failed (move)",
        );
        msg
    })?;

    let _ = terminate_pid(pid);

    let dest_s = dest.to_string_lossy().into_owned();
    let detail = format!("name={name} moved_to={dest_s}");
    let db = state.db.lock().map_err(|e| e.to_string())?;
    db::log_security_action(&db, "quarantine_process", Some(pid), &detail)?;
    log_event(
        EventKind::ProcessQuarantined,
        "high",
        Some(pid),
        Some(name.clone()),
        exe_path.clone(),
        Some(serde_json::json!({ "quarantinePath": dest_s })),
        format!("Process quarantined: {name} ({pid})"),
    );
    app_log::append_line(&format!("quarantine_process pid={pid} {detail}"));

    Ok(QuarantineProcessResult {
        quarantine_path: dest_s,
    })
}

/// Optional second guard: reject quarantine/kill of our own EXE (always).
pub fn is_spy_detector_exe(path: &str) -> bool {
    if let Ok(cur) = std::env::current_exe() {
        if let Ok(cur_s) = cur.canonicalize() {
            if let Ok(p) = Path::new(path).canonicalize() {
                return cur_s == p;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn confirm_token_hex_kill_fixture() {
        let hex = confirm_token_hex("KILL", 1234, Some(r"C:\foo\bar.exe"));
        assert_eq!(
            hex,
            "76925ba37f9745f8e387d3dae5dc52da6b2647c8dfd769d499115b63fe69d3c6"
        );
    }

    #[test]
    fn confirm_token_hex_empty_path_treated_as_empty_string() {
        let with_none = confirm_token_hex("QUARANTINE", 99, None);
        let with_empty = confirm_token_hex("QUARANTINE", 99, Some(""));
        assert_eq!(with_none, with_empty);
    }

    #[test]
    fn is_spy_detector_exe_true_for_current_exe_path() {
        let exe = std::env::current_exe().expect("current_exe");
        let exe_s = exe.to_string_lossy();
        assert!(
            is_spy_detector_exe(exe_s.as_ref()),
            "canonical path of current test binary should match itself"
        );
    }
}
