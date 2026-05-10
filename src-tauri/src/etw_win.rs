//! Real-time ETW via `UserTrace` + `Microsoft-Windows-Kernel-Process`
//! (`{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}`).

use crate::allowlist;
use crate::authenticode::{self, SignatureStatus};
use crate::db;
use crate::event_log::{log as log_event, EventKind};
use crate::ioc::IocIndex;
use crate::live_activity::{ProcessLaunchedPayload, ThreadEventPayload};
use crate::privilege;
use crate::scan::Finding;
use crate::score;
use crate::thread_injection::{Severity, ThreadEvent, ThreadInjectionFilter};
use chrono::Utc;
use ferrisetw::native::EvntraceNativeError;
use ferrisetw::parser::Parser;
use ferrisetw::provider::{EventFilter, Provider};
use ferrisetw::schema::Schema;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::{TraceError, UserTrace};
use ferrisetw::EventRecord;
use once_cell::sync::Lazy;
use rusqlite::Connection;
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use sysinfo::{Pid, ProcessesToUpdate, System};
use tauri::Emitter;
use tauri_plugin_notification::NotificationExt;

pub(crate) type EtwCallback = Arc<Mutex<Box<dyn FnMut(&EventRecord, &SchemaLocator) + Send>>>;

const KERNEL_GUID: &str = "22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716";
const KW_PROCESS: u64 = 0x8000000000000010;
const KW_IMAGE: u64 = 0x8000000000000040;
const KW_THREAD: u64 = 0x8000000000000020;

const EVT_PROCESS_START: u16 = 1;
const EVT_PROCESS_STOP: u16 = 2;
const EVT_THREAD_START: u16 = 3;
const EVT_IMAGE_LOAD: u16 = 5;

const PRUNE_EVERY: Duration = Duration::from_secs(45);
const STALE_AFTER: Duration = Duration::from_secs(900);

const MS_CURATED_EXE: &[&str] = &[
    "svchost.exe",
    "csrss.exe",
    "services.exe",
    "lsass.exe",
    "wininit.exe",
    "smss.exe",
    "winlogon.exe",
    "fontdrvhost.exe",
    "dllhost.exe",
    "runtimebroker.exe",
    "sihost.exe",
    "taskhostw.exe",
    "ctfmon.exe",
    "explorer.exe",
    "dwm.exe",
];

struct PidImageState {
    start_time: Option<Instant>,
    main_exe_os: Option<PathBuf>,
    loaded_basenames: HashSet<String>,
    suspicious_loads: u32,
    trio_done: bool,
    last_event: Instant,
}

impl PidImageState {
    fn touch(&mut self) {
        self.last_event = Instant::now();
    }
}

static PID_IMAGE_TRACKER: Lazy<Mutex<HashMap<u32, PidImageState>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static LAST_PRUNE: Lazy<Mutex<Instant>> = Lazy::new(|| Mutex::new(Instant::now()));

static PID_EXE_CACHE: Lazy<Mutex<HashMap<u32, (String, String)>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static SYS_FOR_LOOKUP: Lazy<Mutex<System>> = Lazy::new(|| Mutex::new(System::new()));

static THREAD_BURST_WIN: Lazy<Mutex<HashMap<u32, VecDeque<Instant>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static THREAD_INJECTION_FILTER: Lazy<Mutex<ThreadInjectionFilter>> =
    Lazy::new(|| Mutex::new(ThreadInjectionFilter::default()));

static ETW_PROCESS_ACTIVE: AtomicBool = AtomicBool::new(false);

static PROCESS_ETW_ENABLED: AtomicBool = AtomicBool::new(true);

pub fn set_process_etw_enabled(enabled: bool) {
    PROCESS_ETW_ENABLED.store(enabled, Ordering::Relaxed);
}

pub fn is_process_etw_enabled() -> bool {
    PROCESS_ETW_ENABLED.load(Ordering::Relaxed)
}

pub fn is_running() -> bool {
    ETW_PROCESS_ACTIVE.load(Ordering::Relaxed)
}

pub fn spawn_etw_monitor(
    app: tauri::AppHandle,
    ioc: Arc<RwLock<IocIndex>>,
    db: Arc<Mutex<Connection>>,
    latest_alert_at: Arc<Mutex<Option<chrono::DateTime<Utc>>>>,
) {
    tauri::async_runtime::spawn(async move {
        let app_c = app.clone();
        let _ = tokio::task::spawn_blocking(move || run_etw_loop(app_c, ioc, db, latest_alert_at))
            .await;
    });
}

pub fn suspicious_image_loads(pid: u32) -> u32 {
    let Ok(g) = PID_IMAGE_TRACKER.lock() else {
        return 0;
    };
    g.get(&pid).map(|s| s.suspicious_loads).unwrap_or(0)
}

fn kernel_path_to_os_path(raw: &str) -> PathBuf {
    let s = raw.trim();
    let stripped = s
        .strip_prefix(r"\??\")
        .or_else(|| s.strip_prefix("\\??\\"))
        .unwrap_or(s);
    crate::authenticode::normalize_image_path(Path::new(stripped))
}

fn dll_basename(kernel_path: &str) -> Option<String> {
    let p = kernel_path_to_os_path(kernel_path);
    p.file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.to_lowercase())
}

fn maybe_prune_tracker() {
    let Ok(mut lp) = LAST_PRUNE.lock() else {
        return;
    };
    let now = Instant::now();
    if now.duration_since(*lp) < PRUNE_EVERY {
        return;
    }
    *lp = now;
    let Ok(mut g) = PID_IMAGE_TRACKER.lock() else {
        return;
    };
    g.retain(|_, v| now.duration_since(v.last_event) < STALE_AFTER);
}

fn non_microsoft_main_exe(state: &PidImageState) -> bool {
    let Some(ref main) = state.main_exe_os else {
        return false;
    };
    !authenticode::is_system_protected_path(main)
}

fn norm_path_lower(path: &Path) -> String {
    path.to_string_lossy().to_lowercase().replace('/', "\\")
}

fn path_under_windows_root(path: &Path) -> bool {
    let pl = norm_path_lower(path);
    let windir = std::env::var("WINDIR").unwrap_or_else(|_| "C:\\Windows".into());
    let wl = PathBuf::from(windir.trim())
        .to_string_lossy()
        .to_lowercase()
        .replace('/', "\\");
    pl.starts_with(&(wl.clone() + "\\")) || pl.starts_with("c:\\windows\\")
}

fn curated_system_executable(path: &Path) -> bool {
    let pl = norm_path_lower(path);
    if !(pl.contains("\\windows\\") || pl.contains("\\system32\\") || pl.contains("\\syswow64\\")) {
        return false;
    }
    let base = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_lowercase();
    MS_CURATED_EXE.contains(&base.as_str())
}

fn severity_for_classification(classification: &str) -> &'static str {
    match classification {
        "system" => "info",
        "signed-third-party" => "low",
        "unsigned" | "user-writable-path" => "warn",
        _ => "low",
    }
}

fn classify_launch(path: &Path) -> (&'static str, bool) {
    let signed_ok = matches!(authenticode::is_signed(path), SignatureStatus::Signed);
    if authenticode::is_in_user_writable_path(path) {
        return ("user-writable-path", signed_ok);
    }
    if !signed_ok {
        return ("unsigned", false);
    }
    let system_like = path_under_windows_root(path) || curated_system_executable(path);
    if system_like {
        ("system", true)
    } else {
        ("signed-third-party", true)
    }
}

fn lookup_pid_exe(pid: u32) -> (String, String) {
    if pid == 0 {
        return (String::new(), String::new());
    }
    if let Ok(cache) = PID_EXE_CACHE.lock() {
        if let Some((n, p)) = cache.get(&pid) {
            return (n.clone(), p.clone());
        }
    }
    let Ok(mut sys) = SYS_FOR_LOOKUP.lock() else {
        return (format!("pid {pid}"), String::new());
    };
    sys.refresh_processes(ProcessesToUpdate::Some(&[Pid::from_u32(pid)]), true);
    if let Some(p) = sys.process(Pid::from_u32(pid)) {
        let name = p.name().to_string_lossy().into_owned();
        let path = p
            .exe()
            .map(|x| {
                crate::authenticode::normalize_image_path(x)
                    .to_string_lossy()
                    .into_owned()
            })
            .unwrap_or_default();
        return (name, path);
    }
    (format!("pid {pid}"), String::new())
}

fn upsert_pid_exe_cache(pid: u32, kernel_image: &str) {
    let exe_os = kernel_path_to_os_path(kernel_image);
    let name = exe_os
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_string();
    let path_str = exe_os.to_string_lossy().into_owned();
    if let Ok(mut c) = PID_EXE_CACHE.lock() {
        c.insert(pid, (name, path_str));
    }
}

fn note_thread_burst(source_pid: u32) -> bool {
    let now = Instant::now();
    let Ok(mut map) = THREAD_BURST_WIN.lock() else {
        return false;
    };
    let dq = map.entry(source_pid).or_default();
    dq.push_back(now);
    while dq
        .front()
        .is_some_and(|t| now.duration_since(*t) > Duration::from_secs(5))
    {
        dq.pop_front();
    }
    dq.len() == 51
}

fn record_process_start(pid: u32, image_name: &str) {
    upsert_pid_exe_cache(pid, image_name);
    let exe_os = kernel_path_to_os_path(image_name);
    if let Ok(mut g) = PID_IMAGE_TRACKER.lock() {
        let e = g.entry(pid).or_insert(PidImageState {
            start_time: None,
            main_exe_os: None,
            loaded_basenames: HashSet::new(),
            suspicious_loads: 0,
            trio_done: false,
            last_event: Instant::now(),
        });
        if e.start_time.is_none() {
            e.start_time = Some(Instant::now());
        }
        if e.main_exe_os.is_none() {
            e.main_exe_os = Some(exe_os);
        }
        e.touch();
    }
}

fn record_image_load(pid: u32, image_kernel_path: &str) {
    let Some(base) = dll_basename(image_kernel_path) else {
        return;
    };
    let Ok(mut g) = PID_IMAGE_TRACKER.lock() else {
        return;
    };
    let st = g.entry(pid).or_insert(PidImageState {
        start_time: None,
        main_exe_os: None,
        loaded_basenames: HashSet::new(),
        suspicious_loads: 0,
        trio_done: false,
        last_event: Instant::now(),
    });
    st.loaded_basenames.insert(base.clone());
    st.touch();

    let non_ms = non_microsoft_main_exe(st);

    let has_wsock = st.loaded_basenames.contains("wsock32.dll");
    let has_wininet = st.loaded_basenames.contains("wininet.dll");
    let has_crypt = st.loaded_basenames.contains("crypt32.dll");
    if non_ms && has_wsock && has_wininet && has_crypt && !st.trio_done {
        st.trio_done = true;
        st.suspicious_loads = st.suspicious_loads.saturating_add(1);
    }

    if base == "user32.dll" {
        if let Some(started) = st.start_time {
            if started.elapsed() >= Duration::from_secs(60) {
                st.suspicious_loads = st.suspicious_loads.saturating_add(1);
            }
        }
    }

    if base == "vssapi.dll" && non_ms {
        st.suspicious_loads = st.suspicious_loads.saturating_add(1);
    }
}

fn emit_process_launch_and_persist(
    db: &Arc<Mutex<Connection>>,
    app: &tauri::AppHandle,
    pid: u32,
    image_name: &str,
    ppid: u32,
) {
    let exe_pb = kernel_path_to_os_path(image_name);
    let proc_name = exe_pb
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(image_name)
        .to_string();
    let path_str = exe_pb.to_string_lossy().into_owned();
    let (parent_name, _) = lookup_pid_exe(ppid);
    let (classification, signed_ok) = classify_launch(&exe_pb);
    let ts = Utc::now().to_rfc3339();
    let started_at = ts.clone();

    let payload = ProcessLaunchedPayload {
        ts: ts.clone(),
        pid,
        name: proc_name.clone(),
        path: path_str.clone(),
        ppid,
        parent_name: parent_name.clone(),
        classification: classification.to_string(),
        signed: signed_ok,
        started_at,
    };

    if let Ok(g) = db.lock() {
        let _ = db::insert_process_launch(
            &g,
            &ts,
            pid,
            &proc_name,
            &path_str,
            ppid,
            &parent_name,
            classification,
            signed_ok,
        );
    }

    log_event(
        EventKind::ProcessLaunch,
        severity_for_classification(classification),
        Some(pid),
        Some(proc_name.clone()),
        Some(path_str.clone()),
        Some(serde_json::json!({
            "classification": classification,
            "signed": signed_ok,
            "ppid": ppid,
            "parentName": parent_name,
        })),
        format!("{proc_name} ({pid}) launched by {parent_name}"),
    );

    let _ = app.emit("process_launched", &payload);
}

fn handle_thread_start(
    record: &EventRecord,
    schema: &Schema,
    app: &tauri::AppHandle,
    db: &Arc<Mutex<Connection>>,
    latest_alert_at_cb: &Arc<Mutex<Option<chrono::DateTime<Utc>>>>,
) {
    let parser = Parser::create(record, schema);
    let owner_pid: u32 = parser.try_parse("ProcessID").unwrap_or(0);
    if owner_pid == 0 {
        return;
    }

    let mut source_pid = owner_pid;
    match parser.try_parse::<u32>("CreateProcessID") {
        Ok(cp) if cp != 0 && cp != owner_pid => source_pid = cp,
        _ => {
            let header_pid = record.process_id();
            if header_pid != 0 && header_pid != owner_pid {
                source_pid = header_pid;
            }
        }
    }

    if note_thread_burst(source_pid) {
        let (src_name, src_path) = lookup_pid_exe(source_pid);
        let ts = Utc::now().to_rfc3339();
        let payload = ThreadEventPayload {
            ts: ts.clone(),
            kind: "thread_burst".into(),
            source_pid,
            source_name: src_name.clone(),
            source_path: src_path.clone(),
            target_pid: source_pid,
            target_name: src_name.clone(),
            target_path: src_path.clone(),
            suspicious: true,
            severity: "warn".into(),
        };
        let _ = app.emit("thread_event", &payload);
        if let Ok(g) = db.lock() {
            let _ = db::insert_thread_event_row(
                &g,
                &ts,
                "thread_burst",
                source_pid,
                &src_name,
                &src_path,
                source_pid,
                &src_name,
                &src_path,
                true,
            );
        }
        log_event(
            EventKind::ThreadBurst,
            "warn",
            Some(source_pid),
            Some(src_name.clone()),
            Some(src_path.clone()),
            None,
            format!("Thread burst heuristic (PID {source_pid})"),
        );
    }

    if source_pid == owner_pid {
        return;
    }

    if !crate::thread_injection::is_scanner_enabled() {
        return;
    }

    let (src_name, src_path) = lookup_pid_exe(source_pid);
    let (tgt_name, tgt_path) = lookup_pid_exe(owner_pid);

    let candidate = ThreadEvent {
        source_pid,
        source_name: src_name.clone(),
        source_path: src_path.clone(),
        target_pid: owner_pid,
        target_name: tgt_name.clone(),
        target_path: tgt_path.clone(),
    };
    let severity = {
        let Ok(mut sys) = SYS_FOR_LOOKUP.lock() else {
            return;
        };
        sys.refresh_processes(
            ProcessesToUpdate::Some(&[Pid::from_u32(source_pid), Pid::from_u32(owner_pid)]),
            true,
        );
        let Ok(mut filter) = THREAD_INJECTION_FILTER.lock() else {
            return;
        };
        filter.should_alert(&candidate, &sys)
    };
    let Some(severity) = severity else {
        return;
    };

    let ts = Utc::now().to_rfc3339();
    let payload = ThreadEventPayload {
        ts: ts.clone(),
        kind: "remote_thread".into(),
        source_pid,
        source_name: src_name.clone(),
        source_path: src_path.clone(),
        target_pid: owner_pid,
        target_name: tgt_name.clone(),
        target_path: tgt_path.clone(),
        suspicious: true,
        severity: severity.as_str().into(),
    };

    let _ = app.emit("thread_event", &payload);

    if let Ok(g) = db.lock() {
        let _ = db::insert_thread_event_row(
            &g,
            &ts,
            "remote_thread",
            source_pid,
            &src_name,
            &src_path,
            owner_pid,
            &tgt_name,
            &tgt_path,
            true,
        );
    }

    log_event(
        EventKind::ThreadInjection,
        severity.as_str(),
        Some(owner_pid),
        Some(tgt_name.clone()),
        Some(tgt_path.clone()),
        Some(serde_json::json!({
            "sourcePid": source_pid,
            "sourcePath": src_path.clone(),
            "targetPid": owner_pid,
            "severityReason": match severity {
                Severity::High => "unsigned target in user-writable path",
                Severity::Warn => "remote thread candidate after benign gates",
            },
        })),
        format!("Remote thread: {src_name} ({source_pid}) → {tgt_name} ({owner_pid})"),
    );

    if severity.is_high() {
        if let Ok(mut la) = latest_alert_at_cb.lock() {
            *la = Some(Utc::now());
        }

        let hint_path = if tgt_path.is_empty() {
            None
        } else {
            Some(tgt_path.clone())
        };
        let alert = Finding {
            pid: owner_pid,
            name: tgt_name.clone(),
            exe_path: hint_path,
            score: 92,
            reasons: vec![
                "[Real-time] Suspicious remote thread injection".into(),
                format!("Injector: {} (PID {}) — {}", src_name, source_pid, src_path),
            ],
            suspicious_image_loads: 0,
            ignored: false,
            authenticode_signed: None,
        };
        if let Ok(v) = serde_json::to_value(&alert) {
            log_event(
                EventKind::AlertEmitted,
                severity.as_str(),
                Some(owner_pid),
                Some(tgt_name.clone()),
                alert.exe_path.clone(),
                Some(v),
                format!("Alert: remote thread — {} ({owner_pid})", tgt_name),
            );
        }
        let _ = app.emit("alert", alert.clone());
        let tray_enabled = db
            .lock()
            .ok()
            .and_then(|g| crate::settings::read_tray_alerts_enabled(&g).ok())
            .unwrap_or(true);
        if tray_enabled {
            let _ = app
                .notification()
                .builder()
                .title("Spy Detector")
                .body(format!(
                    "Remote thread — {} ← {} (PID {})",
                    tgt_name, src_name, source_pid
                ))
                .show();
        }
    }
}

fn run_etw_loop(
    app: tauri::AppHandle,
    ioc: Arc<RwLock<IocIndex>>,
    db: Arc<Mutex<Connection>>,
    latest_alert_at: Arc<Mutex<Option<chrono::DateTime<Utc>>>>,
) {
    let session = format!("spy-detector-{}", std::process::id());
    let app_emit = app.clone();
    let latest_alert_at_cb = latest_alert_at.clone();

    let elevated = privilege::is_process_elevated();
    let mut any_mask = KW_PROCESS;
    let mut event_ids = vec![EVT_PROCESS_START, EVT_PROCESS_STOP];

    if elevated {
        any_mask |= KW_IMAGE | KW_THREAD;
        event_ids.push(EVT_IMAGE_LOAD);
        event_ids.push(EVT_THREAD_START);
    } else {
        eprintln!(
            "spy-detector: Kernel-Process image-load ETW disabled (not elevated); injection DLL heuristic unavailable."
        );
        eprintln!("spy-detector: thread monitor disabled (not elevated)");
    }

    let cb: EtwCallback = Arc::new(Mutex::new(Box::new(
        move |record: &EventRecord, locator: &SchemaLocator| {
            if !is_process_etw_enabled() {
                return;
            }

            maybe_prune_tracker();

            let Ok(schema) = locator.event_schema(record) else {
                return;
            };
            let id = record.event_id();

            match id {
                EVT_THREAD_START => {
                    if !elevated {
                        return;
                    }
                    handle_thread_start(
                        record,
                        schema.as_ref(),
                        &app_emit,
                        &db,
                        &latest_alert_at_cb,
                    );
                    return;
                }
                EVT_IMAGE_LOAD => {
                    let parser = Parser::create(record, schema.as_ref());
                    let pid: u32 = parser.try_parse("ProcessID").unwrap_or(0);
                    if pid == 0 {
                        return;
                    }
                    let image_name: String =
                        parser.try_parse::<String>("ImageName").unwrap_or_default();
                    if image_name.is_empty() {
                        return;
                    }
                    record_image_load(pid, &image_name);
                    return;
                }
                EVT_PROCESS_STOP => {
                    let parser = Parser::create(record, schema.as_ref());
                    let pid: u32 = parser.try_parse("ProcessID").unwrap_or(0);
                    if pid == 0 {
                        return;
                    }
                    let image_name: String = parser
                        .try_parse::<String>("ImageName")
                        .or_else(|_| parser.try_parse::<String>("ImageFileName"))
                        .unwrap_or_default();
                    let (mut proc_name, path_str) = lookup_pid_exe(pid);
                    if (proc_name.is_empty() || proc_name.starts_with("pid "))
                        && !image_name.is_empty()
                    {
                        proc_name = kernel_path_to_os_path(&image_name)
                            .file_name()
                            .and_then(|s| s.to_str())
                            .unwrap_or("")
                            .to_string();
                    }
                    let image_opt = (!path_str.is_empty()).then_some(path_str);
                    log_event(
                        EventKind::ProcessExit,
                        "info",
                        Some(pid),
                        Some(proc_name.clone()),
                        image_opt,
                        None,
                        format!("{proc_name} ({pid}) exited"),
                    );
                    return;
                }
                EVT_PROCESS_START => {}
                _ => return,
            }

            let parser = Parser::create(record, schema.as_ref());
            let pid: u32 = parser.try_parse("ProcessID").unwrap_or(0);
            if pid == 0 {
                return;
            }
            let image_name: String = parser
                .try_parse::<String>("ImageName")
                .or_else(|_| parser.try_parse::<String>("ImageFileName"))
                .unwrap_or_default();
            if image_name.is_empty() {
                return;
            }

            record_process_start(pid, &image_name);

            let ppid: u32 = parser.try_parse("ParentProcessID").unwrap_or(0);
            emit_process_launch_and_persist(&db, &app_emit, pid, &image_name, ppid);

            let exe_pb = kernel_path_to_os_path(&image_name);
            let exe_path_opt = exe_pb.to_str();
            let proc_name = exe_pb
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or_else(|| {
                    Path::new(&image_name)
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or(image_name.as_str())
                });

            let trusted = db
                .lock()
                .ok()
                .and_then(|g| allowlist::is_trusted(&g, exe_path_opt).ok())
                .unwrap_or(false);
            if trusted {
                return;
            }

            let Ok(ioc_read) = ioc.read() else {
                return;
            };
            let (score, reasons) =
                score::signature_signals(&ioc_read, proc_name, exe_path_opt, &HashSet::new());
            if score < 75 {
                return;
            }

            let payload = Finding {
                pid,
                name: proc_name.to_string(),
                exe_path: Some(exe_pb.to_string_lossy().into_owned()),
                score,
                reasons,
                suspicious_image_loads: 0,
                ignored: false,
                authenticode_signed: None,
            };

            if let Ok(mut la) = latest_alert_at_cb.lock() {
                *la = Some(Utc::now());
            }

            if let Ok(v) = serde_json::to_value(&payload) {
                let sev = if payload.score >= 75 { "high" } else { "warn" };
                log_event(
                    EventKind::AlertEmitted,
                    sev,
                    Some(payload.pid),
                    Some(payload.name.clone()),
                    payload.exe_path.clone(),
                    Some(v),
                    format!("Alert: {} score {}", payload.name, payload.score),
                );
            }

            let _ = app_emit.emit("alert", payload.clone());
            let _ = app_emit
                .notification()
                .builder()
                .title("Spy Detector")
                .body(format!(
                    "High score {} — {} (PID {})",
                    payload.score, payload.name, payload.pid
                ))
                .show();
        },
    )));

    let mut attempt = 0_u32;
    let _session_handle = loop {
        let cb_dispatch = {
            let cb = Arc::clone(&cb);
            move |record: &EventRecord, locator: &SchemaLocator| {
                let mut inner = cb.lock().unwrap();
                (*inner)(record, locator);
            }
        };
        let provider = Provider::by_guid(KERNEL_GUID)
            .any(any_mask)
            .level(4)
            .add_filter(EventFilter::ByEventIds(event_ids.clone()))
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
                    std::thread::sleep(std::time::Duration::from_millis(150));
                    attempt += 1;
                    continue;
                }
                let hint = crate::etw_cleanup::format_etw_trace_start_failure(&e);
                eprintln!(
                    "spy-detector: Kernel-Process ETW session '{}' disabled: {hint} ({e:?})",
                    session
                );
                ETW_PROCESS_ACTIVE.store(false, Ordering::Relaxed);
                log_event(
                    EventKind::EtwSubscriptionStateChanged,
                    "info",
                    None,
                    None,
                    None,
                    Some(serde_json::json!({ "provider": "Kernel-Process", "active": false })),
                    "Kernel-Process ETW unavailable",
                );
                break None;
            }
        }
    };

    let Some(_session_handle) = _session_handle else {
        return;
    };

    ETW_PROCESS_ACTIVE.store(true, Ordering::Relaxed);
    log_event(
        EventKind::EtwSubscriptionStateChanged,
        "info",
        None,
        None,
        None,
        Some(serde_json::json!({ "provider": "Kernel-Process", "active": true })),
        "Kernel-Process ETW active",
    );

    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}
