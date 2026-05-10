use crate::camera_win;
use crate::event_log::{log as log_event, EventKind};
use crate::mic_win;
use once_cell::sync::Lazy;
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use sysinfo::{Pid, ProcessesToUpdate, System};

static LAST_CAM: Lazy<Mutex<Option<HashSet<u32>>>> = Lazy::new(|| Mutex::new(None));
static LAST_MIC: Lazy<Mutex<Option<HashSet<String>>>> = Lazy::new(|| Mutex::new(None));

fn resolve_pid(pid: u32) -> (String, String) {
    let mut sys = System::new_all();
    sys.refresh_processes(ProcessesToUpdate::Some(&[Pid::from_u32(pid)]), true);
    if let Some(p) = sys.process(Pid::from_u32(pid)) {
        let name = p.name().to_string_lossy().into_owned();
        let path = p
            .exe()
            .map(|x| x.to_string_lossy().into_owned())
            .unwrap_or_default();
        return (name, path);
    }
    (format!("pid {pid}"), String::new())
}

pub fn poll_camera_mic() {
    let cur_cam: HashSet<u32> = camera_win::active_camera_pids().into_iter().collect();
    let cur_mic = mic_win::paths_with_active_microphone();

    if let Ok(mut g) = LAST_CAM.lock() {
        let prev = g.replace(cur_cam.clone());
        if let Some(prev) = prev {
            for &pid in cur_cam.difference(&prev) {
                let (name, path) = resolve_pid(pid);
                let image = (!path.is_empty()).then_some(path.clone());
                log_event(
                    EventKind::CameraAccess,
                    "warn",
                    Some(pid),
                    Some(name.clone()),
                    image,
                    None,
                    format!("Camera access: {name} ({pid})"),
                );
            }
        }
    }

    if let Ok(mut g) = LAST_MIC.lock() {
        let prev = g.replace(cur_mic.clone());
        if let Some(prev) = prev {
            for path in cur_mic.difference(&prev) {
                let mut sys = System::new_all();
                sys.refresh_processes(ProcessesToUpdate::All, true);
                let mut any = false;
                for (pid, proc_) in sys.processes() {
                    let exe = proc_
                        .exe()
                        .map(|p| p.to_string_lossy().to_lowercase())
                        .unwrap_or_default();
                    if exe == *path || (!path.is_empty() && exe.ends_with(path)) {
                        let pid_u = pid.as_u32();
                        let name = proc_.name().to_string_lossy().into_owned();
                        let img = proc_
                            .exe()
                            .map(|p| p.to_string_lossy().into_owned())
                            .filter(|s| !s.is_empty());
                        log_event(
                            EventKind::MicrophoneAccess,
                            "warn",
                            Some(pid_u),
                            Some(name),
                            img,
                            Some(serde_json::json!({ "consentPath": path })),
                            format!("Microphone consent active ({path})"),
                        );
                        any = true;
                    }
                }
                if !any {
                    log_event(
                        EventKind::MicrophoneAccess,
                        "warn",
                        None,
                        None,
                        Some(path.clone()),
                        Some(serde_json::json!({ "consentPath": path })),
                        format!("Microphone consent active ({path})"),
                    );
                }
            }
        }
    }
}

static LAST_CLIPBOARD_LOG: Lazy<Mutex<HashMap<u32, Instant>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

pub fn maybe_log_clipboard_access(pid: u32, access: &str) {
    if pid == 0 {
        return;
    }
    let now = Instant::now();
    if let Ok(mut g) = LAST_CLIPBOARD_LOG.lock() {
        if let Some(t) = g.get(&pid) {
            if now.duration_since(*t) < Duration::from_secs(30) {
                return;
            }
        }
        g.insert(pid, now);
    }
    let (name, path) = resolve_pid(pid);
    let image = (!path.is_empty()).then_some(path);
    log_event(
        EventKind::ClipboardAccess,
        "low",
        Some(pid),
        Some(name.clone()),
        image,
        Some(serde_json::json!({ "access": access })),
        format!("Clipboard {access}: {name} ({pid})"),
    );
}
