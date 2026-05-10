//! Periodic full scans and monitoring heartbeat (Windows runtime).

use crate::monitoring::ScanCompletedEvent;
use crate::monitoring::{build_monitoring_tick, MonitoringTick};
use crate::scan;
use crate::settings;
use crate::AppState;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tauri::Emitter;

static PERIODIC_SCAN_ENABLED: AtomicBool = AtomicBool::new(true);

pub fn set_periodic_scan_enabled(enabled: bool) {
    PERIODIC_SCAN_ENABLED.store(enabled, Ordering::Relaxed);
}

pub fn is_periodic_scan_enabled() -> bool {
    PERIODIC_SCAN_ENABLED.load(Ordering::Relaxed)
}

pub fn spawn_periodic_scan(app: tauri::AppHandle, state: AppState) {
    tauri::async_runtime::spawn(async move {
        loop {
            let interval_secs_opt = match state.db.lock() {
                Ok(db) => Some(settings::read_scan_interval_secs(&db).unwrap_or(300)),
                Err(_) => None,
            };
            let interval_secs = match interval_secs_opt {
                Some(s) => s,
                None => {
                    tokio::time::sleep(Duration::from_secs(300)).await;
                    continue;
                }
            };

            tokio::time::sleep(Duration::from_secs(interval_secs as u64)).await;

            if !is_periodic_scan_enabled() {
                continue;
            }

            let scan_result = {
                let mut db = match state.db.lock() {
                    Ok(g) => g,
                    Err(_) => continue,
                };
                let mut beacons = match state.beacons.lock() {
                    Ok(g) => g,
                    Err(_) => continue,
                };
                let ioc = match state.ioc.read() {
                    Ok(g) => g,
                    Err(_) => continue,
                };
                let feeds = match state.ip_feeds.read() {
                    Ok(g) => g,
                    Err(_) => continue,
                };
                let abuse = match state.abuse_ch.read() {
                    Ok(g) => g,
                    Err(_) => continue,
                };
                scan::execute_scan_with_state(
                    &ioc,
                    &feeds,
                    &abuse,
                    state.dev_infra.as_ref(),
                    &mut db,
                    &mut beacons,
                    &state.scan_state,
                    "periodic",
                )
            };

            match scan_result {
                Ok(findings) => {
                    let risk_relevant: Vec<_> = findings.iter().filter(|f| !f.ignored).collect();
                    let max_score = risk_relevant.iter().map(|f| f.score).max().unwrap_or(0);
                    let payload = ScanCompletedEvent {
                        at: chrono::Utc::now().to_rfc3339(),
                        findings_count: risk_relevant.len() as u32,
                        max_score,
                    };
                    let _ = app.emit("scan_completed", &payload);
                }
                Err(ref e) if e.as_str() == scan::SCAN_BUSY_ERR => {
                    eprintln!("spy-detector: periodic scan skipped (scan already in progress)");
                }
                Err(e) => {
                    eprintln!("spy-detector: periodic scan failed: {e}");
                }
            }

            let bh_state = state.clone();
            let _ = std::thread::spawn(move || {
                if let Err(e) = crate::browser_history::scan_and_persist(&bh_state) {
                    eprintln!("spy-detector: browser history scan failed: {e}");
                }
            });
        }
    });
}

/// One-shot full scan kicked off shortly after startup, gated by the
/// `auto_scan_on_launch` user setting. Errors are logged, never panicked on.
pub fn spawn_auto_scan_on_launch(app: tauri::AppHandle, state: AppState) {
    tauri::async_runtime::spawn(async move {
        let enabled = match state.db.lock() {
            Ok(db) => settings::read_auto_scan_on_launch(&db).unwrap_or(true),
            Err(e) => {
                eprintln!("[auto-scan] db lock poisoned: {e}");
                return;
            }
        };
        if !enabled {
            return;
        }

        // Give monitors / ETW sessions a few seconds to warm up first.
        tokio::time::sleep(Duration::from_secs(8)).await;

        let scan_state = state.clone();
        let scan_result = tokio::task::spawn_blocking(move || {
            let mut db = scan_state.db.lock().map_err(|e| e.to_string())?;
            let mut beacons = scan_state.beacons.lock().map_err(|e| e.to_string())?;
            let ioc = scan_state.ioc.read().map_err(|e| e.to_string())?;
            let feeds = scan_state.ip_feeds.read().map_err(|e| e.to_string())?;
            let abuse = scan_state.abuse_ch.read().map_err(|e| e.to_string())?;
            scan::execute_scan_with_state(
                &ioc,
                &feeds,
                &abuse,
                scan_state.dev_infra.as_ref(),
                &mut db,
                &mut beacons,
                &scan_state.scan_state,
                "auto_launch",
            )
        })
        .await;

        let scan_result = match scan_result {
            Ok(r) => r,
            Err(e) => {
                eprintln!("[auto-scan] join error: {e}");
                return;
            }
        };

        match scan_result {
            Ok(findings) => {
                let risk_relevant: Vec<_> = findings.iter().filter(|f| !f.ignored).collect();
                let max_score = risk_relevant.iter().map(|f| f.score).max().unwrap_or(0);
                let payload = ScanCompletedEvent {
                    at: chrono::Utc::now().to_rfc3339(),
                    findings_count: risk_relevant.len() as u32,
                    max_score,
                };
                let _ = app.emit("scan_completed", &payload);
            }
            Err(ref e) if e.as_str() == scan::SCAN_BUSY_ERR => {
                eprintln!("[auto-scan] skipped (scan already in progress)");
            }
            Err(e) => {
                eprintln!("[auto-scan] failed: {e}");
            }
        }
    });
}

pub fn spawn_monitoring_heartbeat(app: tauri::AppHandle, state: AppState) {
    tauri::async_runtime::spawn(async move {
        loop {
            let tick: Result<MonitoringTick, String> = build_monitoring_tick(&state);
            match tick {
                Ok(t) => {
                    let _ = app.emit("monitoring_tick", &t);
                    #[cfg(windows)]
                    crate::media_signals::poll_camera_mic();
                    let tip = if t.elevated {
                        "Spy Detector\nMonitoring active"
                    } else {
                        "Spy Detector\nLimited mode"
                    };
                    if let Some(tray) = app.tray_by_id("main-tray") {
                        let _ = tray.set_tooltip(Some(tip));
                    }
                }
                Err(e) => {
                    eprintln!("spy-detector: monitoring_tick build failed: {e}");
                }
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });
}
