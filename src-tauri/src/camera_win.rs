//! Real-time camera activity tracking via Media Foundation's
//! `IMFSensorActivityMonitor`. The monitor invokes our
//! `IMFSensorActivitiesReportCallback` whenever the sensor activity state
//! changes; we read each report and remember which PIDs are currently
//! streaming from a sensor that looks like a camera (best signal MF gives
//! us; the monitor is documented as the camera-attribution surface).
//!
//! Threading: the monitor runs on a dedicated OS thread we initialize as
//! an STA (`COINIT_APARTMENTTHREADED`). MF marshals the callback to that
//! same apartment, which means a message pump must run on it; we keep a
//! plain `GetMessage` loop alive until the process exits. Failing fast
//! and degrading gracefully (returning an empty PID set) is preferable to
//! crashing the whole app, since this is one signal among many.
//!
//! `active_camera_pids()` reads a `Mutex<HashSet<u32>>` populated by the
//! callback and is safe to call from any thread.
//!
//! Note: `IMFSensorActivityReport` does not expose a sensor *type*; the
//! API is documented for camera attribution and the friendly name /
//! symbolic link routinely contain "camera" or the KS video category
//! GUID. We accept all reports the monitor produces — practical impact
//! is the same since MF's monitor primarily covers cameras.

use once_cell::sync::Lazy;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::thread;

use windows::core::{Interface, Ref, Result as WinResult};
use windows::Win32::Media::MediaFoundation::{
    IMFSensorActivitiesReport, IMFSensorActivitiesReportCallback,
    IMFSensorActivitiesReportCallback_Impl, IMFSensorActivityMonitor, IMFShutdown,
    MFCreateSensorActivityMonitor, MFShutdown, MFStartup, MFSTARTUP_FULL, MF_VERSION,
};
use windows::Win32::System::Com::{
    CoInitializeEx, CoUninitialize, COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE,
};
use windows::Win32::UI::WindowsAndMessaging::{
    DispatchMessageW, GetMessageW, TranslateMessage, MSG,
};
use windows_implement::implement;

static ACTIVE_PIDS: Lazy<Mutex<HashSet<u32>>> = Lazy::new(|| Mutex::new(HashSet::new()));

static CAMERA_MONITOR_ACTIVE: AtomicBool = AtomicBool::new(false);

static CAMERA_MONITOR_ENABLED: AtomicBool = AtomicBool::new(true);

pub fn set_camera_monitor_enabled(enabled: bool) {
    CAMERA_MONITOR_ENABLED.store(enabled, Ordering::Relaxed);
}

pub fn is_camera_monitor_enabled() -> bool {
    CAMERA_MONITOR_ENABLED.load(Ordering::Relaxed)
}

pub fn is_running() -> bool {
    CAMERA_MONITOR_ACTIVE.load(Ordering::Relaxed)
}

pub fn active_camera_pids() -> Vec<u32> {
    match ACTIVE_PIDS.lock() {
        Ok(g) => g.iter().copied().collect(),
        Err(_) => Vec::new(),
    }
}

#[implement(IMFSensorActivitiesReportCallback)]
struct CameraCallback;

impl IMFSensorActivitiesReportCallback_Impl for CameraCallback_Impl {
    fn OnActivitiesReport(&self, report: Ref<'_, IMFSensorActivitiesReport>) -> WinResult<()> {
        if !is_camera_monitor_enabled() {
            if let Ok(mut g) = ACTIVE_PIDS.lock() {
                g.clear();
            }
            return Ok(());
        }
        let Some(report) = report.as_ref() else {
            return Ok(());
        };
        let mut streaming: HashSet<u32> = HashSet::new();
        let count = unsafe { report.GetCount() }.unwrap_or(0);
        for i in 0..count {
            let activity = match unsafe { report.GetActivityReport(i) } {
                Ok(a) => a,
                Err(_) => continue,
            };
            let proc_count = unsafe { activity.GetProcessCount() }.unwrap_or(0);
            for j in 0..proc_count {
                let proc_act = match unsafe { activity.GetProcessActivity(j) } {
                    Ok(p) => p,
                    Err(_) => continue,
                };
                let pid = unsafe { proc_act.GetProcessId() }.unwrap_or(0);
                if pid == 0 {
                    continue;
                }
                let is_streaming = unsafe { proc_act.GetStreamingState() }
                    .map(|b| b.as_bool())
                    .unwrap_or(false);
                if is_streaming {
                    streaming.insert(pid);
                }
            }
        }

        if let Ok(mut g) = ACTIVE_PIDS.lock() {
            *g = streaming;
        }
        Ok(())
    }
}

pub fn spawn_monitor() {
    thread::Builder::new()
        .name("spy-detector-camera-mf".into())
        .spawn(|| {
            if let Err(e) = run_monitor() {
                eprintln!("camera monitor: MF init failed: {e:?}");
            }
        })
        .ok();
}

fn run_monitor() -> WinResult<()> {
    unsafe {
        let hr = CoInitializeEx(None, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
        if hr.is_err() {
            return Err(hr.into());
        }
    }

    let result = (|| -> WinResult<()> {
        unsafe { MFStartup(MF_VERSION, MFSTARTUP_FULL)? };

        let callback: IMFSensorActivitiesReportCallback = CameraCallback.into();
        let monitor: IMFSensorActivityMonitor =
            unsafe { MFCreateSensorActivityMonitor(&callback)? };
        unsafe { monitor.Start()? };
        CAMERA_MONITOR_ACTIVE.store(true, Ordering::Relaxed);

        unsafe {
            let mut msg = MSG::default();
            while GetMessageW(&mut msg, None, 0, 0).into() {
                let _ = TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }

        CAMERA_MONITOR_ACTIVE.store(false, Ordering::Relaxed);

        unsafe { monitor.Stop()? };
        if let Ok(shutdown) = monitor.cast::<IMFShutdown>() {
            unsafe { shutdown.Shutdown()? };
        }
        unsafe { MFShutdown()? };
        Ok(())
    })();

    unsafe { CoUninitialize() };
    result
}
