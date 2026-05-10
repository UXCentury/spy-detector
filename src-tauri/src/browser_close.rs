//! Graceful / forced browser shutdown via WM_CLOSE and optional TerminateProcess (Windows).

use crate::app_log;
use serde::Serialize;
use std::collections::HashSet;
use std::thread;
use std::time::Duration;
use sysinfo::{Pid, ProcessesToUpdate, System};

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CloseBrowserResult {
    pub browser: String,
    pub closed_pids: Vec<u32>,
    pub remaining_pids: Vec<u32>,
    pub forced: bool,
    pub error: Option<String>,
}

pub fn browser_exe_name(browser: &str) -> Option<&'static str> {
    match browser.trim().to_ascii_lowercase().as_str() {
        "chrome" | "google chrome" => Some("chrome.exe"),
        "edge" | "microsoft edge" => Some("msedge.exe"),
        "brave" => Some("brave.exe"),
        "firefox" | "mozilla firefox" => Some("firefox.exe"),
        _ => None,
    }
}

pub fn list_browser_pids(exe_name: &str) -> Vec<u32> {
    let mut sys = System::new_all();
    sys.refresh_processes(ProcessesToUpdate::All, true);
    let target = exe_name.to_ascii_lowercase();
    let mut out: Vec<u32> = sys
        .processes()
        .iter()
        .filter(|(_, proc_)| proc_.name().to_string_lossy().to_ascii_lowercase() == target)
        .map(|(pid, _)| pid.as_u32())
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

fn remaining_target_pids(original: &[u32], sys: &System) -> Vec<u32> {
    original
        .iter()
        .copied()
        .filter(|p| sys.process(Pid::from_u32(*p)).is_some())
        .collect()
}

#[cfg(windows)]
fn post_wm_close_to_browser_windows(target_pids: &HashSet<u32>) -> u32 {
    use windows::core::BOOL;
    use windows::Win32::Foundation::{HWND, LPARAM, WPARAM};
    use windows::Win32::UI::WindowsAndMessaging::{
        EnumWindows, GetWindow, GetWindowThreadProcessId, IsWindowVisible, PostMessageW, GW_OWNER,
        WM_CLOSE,
    };

    struct EnumCtx {
        target_pids: HashSet<u32>,
        posts: u32,
    }

    unsafe extern "system" fn enum_proc(hwnd: HWND, lparam: LPARAM) -> BOOL {
        let ctx = &mut *(lparam.0 as *mut EnumCtx);
        if !IsWindowVisible(hwnd).as_bool() {
            return BOOL(1);
        }
        let owner = GetWindow(hwnd, GW_OWNER).unwrap_or_default();
        if !owner.is_invalid() {
            return BOOL(1);
        }
        let mut pid: u32 = 0;
        let _tid = GetWindowThreadProcessId(hwnd, Some(&mut pid));
        if ctx.target_pids.contains(&pid) {
            let _ = PostMessageW(Some(hwnd), WM_CLOSE, WPARAM(0), LPARAM(0));
            ctx.posts += 1;
        }
        BOOL(1)
    }

    let mut ctx = EnumCtx {
        target_pids: target_pids.clone(),
        posts: 0,
    };
    let lparam = LPARAM(&mut ctx as *mut EnumCtx as isize);
    unsafe {
        let _ = EnumWindows(Some(enum_proc), lparam);
    }
    ctx.posts
}

#[cfg(windows)]
fn terminate_pid_hard(pid: u32) -> Result<(), String> {
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
fn post_wm_close_to_browser_windows(_target_pids: &HashSet<u32>) -> u32 {
    0
}

#[cfg(not(windows))]
fn terminate_pid_hard(_pid: u32) -> Result<(), String> {
    Err("Process termination is only supported on Windows.".into())
}

pub fn close_browser_safely(browser: &str, force: bool) -> CloseBrowserResult {
    let browser_owned = browser.trim().to_string();
    app_log::append_line(&format!(
        "[browser-close] entry browser={} force={}",
        browser_owned, force
    ));

    let Some(exe_name) = browser_exe_name(&browser_owned) else {
        app_log::append_line("[browser-close] unknown browser label");
        return CloseBrowserResult {
            browser: browser_owned,
            closed_pids: Vec::new(),
            remaining_pids: Vec::new(),
            forced: force,
            error: Some("Unknown browser; cannot close.".into()),
        };
    };

    let original_pids = list_browser_pids(exe_name);
    app_log::append_line(&format!(
        "[browser-close] list_browser_pids exe={} pids={:?}",
        exe_name, original_pids
    ));

    if original_pids.is_empty() {
        app_log::append_line("[browser-close] no matching processes");
        return CloseBrowserResult {
            browser: browser_owned,
            closed_pids: Vec::new(),
            remaining_pids: Vec::new(),
            forced: force,
            error: None,
        };
    }

    #[cfg(not(windows))]
    {
        let _ = force;
        return CloseBrowserResult {
            browser: browser_owned,
            closed_pids: Vec::new(),
            remaining_pids: original_pids.clone(),
            forced: force,
            error: Some("Browser close is only supported on Windows.".into()),
        };
    }

    #[cfg(windows)]
    {
        close_browser_safely_windows(&browser_owned, &original_pids, force)
    }
}

#[cfg(windows)]
fn close_browser_safely_windows(
    browser_label: &str,
    original_pids: &[u32],
    force: bool,
) -> CloseBrowserResult {
    let target_set: HashSet<u32> = original_pids.iter().copied().collect();
    let posts = post_wm_close_to_browser_windows(&target_set);
    app_log::append_line(&format!("[browser-close] WM_CLOSE messages_sent={}", posts));

    let poll_deadline_ms = if force { 3000u64 } else { 8000u64 };
    let step = Duration::from_millis(250);
    let mut elapsed_ms: u64 = 0;
    let mut sys = System::new_all();

    loop {
        sys.refresh_processes(ProcessesToUpdate::All, true);
        let remaining = remaining_target_pids(original_pids, &sys);
        app_log::append_line(&format!(
            "[browser-close] poll elapsed_ms={} remaining_pids={:?}",
            elapsed_ms, remaining
        ));
        if remaining.is_empty() {
            let closed: Vec<u32> = original_pids.to_vec();
            app_log::append_line(&format!(
                "[browser-close] final ok closed_count={}",
                closed.len()
            ));
            return CloseBrowserResult {
                browser: browser_label.to_string(),
                closed_pids: closed,
                remaining_pids: Vec::new(),
                forced: force,
                error: None,
            };
        }
        if elapsed_ms >= poll_deadline_ms {
            break;
        }
        thread::sleep(step);
        elapsed_ms += step.as_millis() as u64;
    }

    let mut sys = System::new_all();
    sys.refresh_processes(ProcessesToUpdate::All, true);
    let mut remaining = remaining_target_pids(original_pids, &sys);

    if force && !remaining.is_empty() {
        app_log::append_line(&format!(
            "[browser-close] TerminateProcess batch count={}",
            remaining.len()
        ));
        for pid in &remaining {
            match terminate_pid_hard(*pid) {
                Ok(()) => app_log::append_line(&format!(
                    "[browser-close] TerminateProcess ok pid={}",
                    pid
                )),
                Err(e) => app_log::append_line(&format!(
                    "[browser-close] TerminateProcess failed pid={} err={}",
                    pid, e
                )),
            }
        }
        thread::sleep(Duration::from_millis(500));
        sys.refresh_processes(ProcessesToUpdate::All, true);
        remaining = remaining_target_pids(original_pids, &sys);
        app_log::append_line(&format!(
            "[browser-close] post-terminate remaining_pids={:?}",
            remaining
        ));
    }

    let closed: Vec<u32> = original_pids
        .iter()
        .copied()
        .filter(|p| !remaining.contains(p))
        .collect();

    let err = if remaining.is_empty() {
        None
    } else if force {
        Some(format!(
            "{} process(es) still running after force close.",
            remaining.len()
        ))
    } else {
        None
    };

    app_log::append_line(&format!(
        "[browser-close] final forced={} remaining={:?} closed_count={}",
        force,
        remaining,
        closed.len()
    ));

    CloseBrowserResult {
        browser: browser_label.to_string(),
        closed_pids: closed,
        remaining_pids: remaining,
        forced: force,
        error: err,
    }
}

#[cfg(test)]
mod tests {
    use super::browser_exe_name;

    #[test]
    fn browser_exe_name_maps_common_labels() {
        assert_eq!(browser_exe_name("Chrome"), Some("chrome.exe"));
        assert_eq!(browser_exe_name(" chrome "), Some("chrome.exe"));
        assert_eq!(browser_exe_name("Google Chrome"), Some("chrome.exe"));
        assert_eq!(browser_exe_name("Edge"), Some("msedge.exe"));
        assert_eq!(browser_exe_name("Microsoft Edge"), Some("msedge.exe"));
        assert_eq!(browser_exe_name("Brave"), Some("brave.exe"));
        assert_eq!(browser_exe_name("Firefox"), Some("firefox.exe"));
        assert_eq!(browser_exe_name("Mozilla Firefox"), Some("firefox.exe"));
    }

    #[test]
    fn browser_exe_name_unknown() {
        assert_eq!(browser_exe_name("Safari"), None);
        assert_eq!(browser_exe_name(""), None);
    }
}
