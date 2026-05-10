//! ETW consumer for `Microsoft-Windows-Win32k` (`{8c416c79-d49b-4f01-a467-e56d3aa8234c}`).
//!
//! ## Hook installs (Goal A)
//! Dedicated “Hook* task” events are not exposed as separate keywords in this provider’s manifest.
//! The smallest reliable signal we found is **`AuditApiCalls`** (keyword mask `0x400`), which emits
//! event **1002** (`task_01002`) when **`SetWindowsHookEx`** returns — fields include `FilterType`
//! (hook id), module path, and `ReturnValue` (non-zero `HHOOK` on success). We enable only event
//! **1002** and accept hook types **WH_KEYBOARD (2), WH_MOUSE (7), WH_KEYBOARD_LL (13),
//! WH_MOUSE_LL (14)** to approximate keyboard/mouse hook installation without `$kernel` sessions.
//!
//! **Fallback not used:** tracing **`NtUserSetWindowsHookEx`** via a hypothetical `SystemCall`
//! keyword would require much broader syscall tracing and was skipped as unnecessarily noisy.
//!
//! ## Screen capture (`PrintWindow`, DWM thumbnails)
//! The published `Microsoft-Windows-Win32k` manifest does **not** list a dedicated task/keyword for
//! **`NtUserPrintWindow`** or DWM thumbnail capture (no related task names; nothing analogous to
//! hook or clipboard keywords). **`AuditApiCalls`** only covers the audited APIs bundled into its
//! schema (we rely on it for **`SetWindowsHookEx`** above). Without a documented, capture-specific
//! keyword, enabling broader audit streams would add unclear noise and risk false positives, so
//! **no Win32k ETW signal is used for screen capture**; scans use the behavioral heuristic in
//! `screen_capture.rs` instead.
//!
//! ## Clipboard access
//! **`ReadClipboard`** (`0x80000000000`) event **463** carries `CallerPid` for read-side access;
//! **`WriteClipboard`** (`0x40000000000`) events **459–460** carry `Pid`. Together these approximate
//! `OpenClipboard` / `GetClipboardData` / `SetClipboardData` activity with per-caller attribution.

use crate::authenticode;
use crate::etw_win::EtwCallback;
use crate::event_log::{log as log_event, EventKind};
use crate::media_signals::maybe_log_clipboard_access;
use ferrisetw::native::EvntraceNativeError;
use ferrisetw::parser::Parser;
use ferrisetw::provider::{EventFilter, Provider};
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::{TraceError, UserTrace};
use ferrisetw::EventRecord;
use once_cell::sync::Lazy;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use sysinfo::{Pid, ProcessesToUpdate, System};

/// `{8c416c79-d49b-4f01-a467-e56d3aa8234c}`
pub const WIN32K_PROVIDER_GUID: &str = "8c416c79-d49b-4f01-a467-e56d3aa8234c";

const KW_AUDIT_API_CALLS: u64 = 0x400;
/// Keyword masks from `wevtutil gp Microsoft-Windows-Win32k /ge` (hex, no `0x` in tool output).
const KW_WRITE_CLIPBOARD: u64 = 0x40000000000;
const KW_READ_CLIPBOARD: u64 = 0x80000000000;

const EVT_SET_WINDOWS_HOOK_EX: u16 = 1002;
const EVT_WRITE_CLIPBOARD: u16 = 459;
const EVT_WRITE_CLIPBOARD_ALT: u16 = 460;
const EVT_READ_CLIPBOARD: u16 = 463;

const HOOK_RECENCY: Duration = Duration::from_secs(5 * 60);
const CLIPBOARD_WINDOW: Duration = Duration::from_secs(60);

/// WH_KEYBOARD, WH_MOUSE, WH_KEYBOARD_LL, WH_MOUSE_LL
const KEYBOARD_MOUSE_HOOK_TYPES: &[u32] = &[2, 7, 13, 14];

fn hook_type_label(id: u32) -> &'static str {
    match id {
        2 => "WH_KEYBOARD",
        7 => "WH_MOUSE",
        13 => "WH_KEYBOARD_LL",
        14 => "WH_MOUSE_LL",
        _ => "hook",
    }
}

fn pid_exe_hint(pid: u32) -> (String, Option<String>) {
    let mut sys = System::new_all();
    sys.refresh_processes(ProcessesToUpdate::Some(&[Pid::from_u32(pid)]), true);
    if let Some(p) = sys.process(Pid::from_u32(pid)) {
        let name = p.name().to_string_lossy().into_owned();
        let exe = p
            .exe()
            .map(|e| {
                authenticode::normalize_image_path(e)
                    .to_string_lossy()
                    .into_owned()
            })
            .filter(|s| !s.is_empty());
        return (name, exe);
    }
    (format!("pid {pid}"), None)
}

pub struct HookStats {
    pub install_count: u32,
    pub last_seen: Instant,
}

pub struct ClipboardStats {
    pub open_count_60s_window: usize,
    pub last_seen: Instant,
    opens: VecDeque<Instant>,
}

impl ClipboardStats {
    fn new() -> Self {
        Self {
            open_count_60s_window: 0,
            last_seen: Instant::now(),
            opens: VecDeque::new(),
        }
    }

    fn record_open(&mut self) {
        let now = Instant::now();
        self.last_seen = now;
        self.opens.push_back(now);
        self.prune(now);
    }

    fn prune(&mut self, now: Instant) {
        while let Some(t) = self.opens.front().copied() {
            if now.duration_since(t) > CLIPBOARD_WINDOW {
                self.opens.pop_front();
            } else {
                break;
            }
        }
        self.open_count_60s_window = self.opens.len();
    }
}

static HOOK_STATS: Lazy<Mutex<HashMap<u32, HookStats>>> = Lazy::new(|| Mutex::new(HashMap::new()));
static CLIPBOARD_STATS: Lazy<Mutex<HashMap<u32, ClipboardStats>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

static ETW_WIN32K_ACTIVE: AtomicBool = AtomicBool::new(false);

static WIN32K_ETW_ENABLED: AtomicBool = AtomicBool::new(true);

pub fn set_win32k_etw_enabled(enabled: bool) {
    WIN32K_ETW_ENABLED.store(enabled, Ordering::Relaxed);
}

pub fn is_win32k_etw_enabled() -> bool {
    WIN32K_ETW_ENABLED.load(Ordering::Relaxed)
}

pub fn is_running() -> bool {
    ETW_WIN32K_ACTIVE.load(Ordering::Relaxed)
}

pub fn spawn_win32k_monitor() {
    tauri::async_runtime::spawn(async move {
        let _ = tokio::task::spawn_blocking(run_win32k_loop).await;
    });
}

fn run_win32k_loop() {
    let session = format!("spy-detector-win32k-{}", std::process::id());

    let cb: EtwCallback = Arc::new(Mutex::new(Box::new(
        move |record: &EventRecord, locator: &SchemaLocator| {
            let Ok(schema) = locator.event_schema(record) else {
                return;
            };
            let id = record.event_id();
            match id {
                EVT_SET_WINDOWS_HOOK_EX => {
                    if !is_win32k_etw_enabled() {
                        return;
                    }
                    let parser = Parser::create(record, &schema);
                    let Ok(rv) = parser.try_parse::<u32>("ReturnValue") else {
                        return;
                    };
                    if rv == 0 {
                        return;
                    }
                    let Ok(filter_type) = parser.try_parse::<u32>("FilterType") else {
                        return;
                    };
                    if !KEYBOARD_MOUSE_HOOK_TYPES.contains(&filter_type) {
                        return;
                    }
                    let pid = record.process_id();
                    if pid == 0 {
                        return;
                    }
                    let now = Instant::now();
                    if let Ok(mut g) = HOOK_STATS.lock() {
                        let e = g.entry(pid).or_insert(HookStats {
                            install_count: 0,
                            last_seen: now,
                        });
                        e.install_count = e.install_count.saturating_add(1);
                        e.last_seen = now;
                    }
                    let (proc_name, image_path) = pid_exe_hint(pid);
                    log_event(
                        EventKind::KeyboardHook,
                        "warn",
                        Some(pid),
                        Some(proc_name.clone()),
                        image_path.clone(),
                        Some(serde_json::json!({
                            "hookType": filter_type,
                            "hookLabel": hook_type_label(filter_type),
                        })),
                        format!(
                            "Keyboard/mouse hook installed ({})",
                            hook_type_label(filter_type)
                        ),
                    );
                }
                EVT_READ_CLIPBOARD => {
                    if !is_win32k_etw_enabled() {
                        return;
                    }
                    let parser = Parser::create(record, &schema);
                    let pid = parser
                        .try_parse::<u32>("CallerPid")
                        .unwrap_or_else(|_| record.process_id());
                    if pid == 0 {
                        return;
                    }
                    if let Ok(mut g) = CLIPBOARD_STATS.lock() {
                        let e = g.entry(pid).or_insert_with(ClipboardStats::new);
                        e.record_open();
                    }
                    maybe_log_clipboard_access(pid, "read");
                }
                EVT_WRITE_CLIPBOARD | EVT_WRITE_CLIPBOARD_ALT => {
                    if !is_win32k_etw_enabled() {
                        return;
                    }
                    let parser = Parser::create(record, &schema);
                    let pid = parser
                        .try_parse::<u32>("Pid")
                        .unwrap_or_else(|_| record.process_id());
                    if pid == 0 {
                        return;
                    }
                    if let Ok(mut g) = CLIPBOARD_STATS.lock() {
                        let e = g.entry(pid).or_insert_with(ClipboardStats::new);
                        e.record_open();
                    }
                    maybe_log_clipboard_access(pid, "write");
                }
                _ => {}
            }
        },
    )));

    let win32k_any = KW_AUDIT_API_CALLS | KW_WRITE_CLIPBOARD | KW_READ_CLIPBOARD;
    let win32k_event_ids = vec![
        EVT_SET_WINDOWS_HOOK_EX,
        EVT_WRITE_CLIPBOARD,
        EVT_WRITE_CLIPBOARD_ALT,
        EVT_READ_CLIPBOARD,
    ];

    let mut attempt = 0_u32;
    let _session_handle = loop {
        let cb_dispatch = {
            let cb = Arc::clone(&cb);
            move |record: &EventRecord, locator: &SchemaLocator| {
                let mut inner = cb.lock().unwrap();
                (*inner)(record, locator);
            }
        };
        let provider = Provider::by_guid(WIN32K_PROVIDER_GUID)
            .any(win32k_any)
            .level(4)
            .add_filter(EventFilter::ByEventIds(win32k_event_ids.clone()))
            .add_callback(cb_dispatch)
            .build();

        match UserTrace::new()
            .named(session.clone())
            .enable(provider)
            .start_and_process()
        {
            Ok(t) => break Some(t),
            Err(e) => {
                if matches!(
                    &e,
                    TraceError::EtwNativeError(EvntraceNativeError::AlreadyExist)
                ) && attempt == 0
                {
                    let _ = crate::etw_cleanup::stop_session(&session);
                    std::thread::sleep(Duration::from_millis(150));
                    attempt += 1;
                    continue;
                }
                let hint = crate::etw_cleanup::format_etw_trace_start_failure(&e);
                ETW_WIN32K_ACTIVE.store(false, Ordering::Relaxed);
                log_event(
                    EventKind::EtwSubscriptionStateChanged,
                    "info",
                    None,
                    None,
                    None,
                    Some(serde_json::json!({ "provider": "Win32k", "active": false })),
                    "Win32k ETW unavailable",
                );
                eprintln!(
                    "spy-detector: Win32k ETW disabled (keyboard hook / clipboard telemetry unavailable): {hint} ({e:?})"
                );
                break None;
            }
        }
    };

    let Some(_session_handle) = _session_handle else {
        return;
    };

    ETW_WIN32K_ACTIVE.store(true, Ordering::Relaxed);
    log_event(
        EventKind::EtwSubscriptionStateChanged,
        "info",
        None,
        None,
        None,
        Some(serde_json::json!({ "provider": "Win32k", "active": true })),
        "Win32k ETW active",
    );

    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}

/// Successful keyboard/mouse hook install observed within the last 5 minutes.
pub fn recent_hook_install(pid: u32) -> bool {
    let Ok(g) = HOOK_STATS.lock() else {
        return false;
    };
    g.get(&pid)
        .is_some_and(|s| s.last_seen.elapsed() <= HOOK_RECENCY)
}

/// Clipboard read/write events in the rolling 60s window, after eviction (for scoring / UI).
pub fn clipboard_opens_last_60s(pid: u32) -> usize {
    let Ok(mut g) = CLIPBOARD_STATS.lock() else {
        return 0;
    };
    let Some(e) = g.get_mut(&pid) else {
        return 0;
    };
    let now = Instant::now();
    e.prune(now);
    e.open_count_60s_window
}
