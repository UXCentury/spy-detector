mod abuse_ch;
mod allowlist;
mod amsi;
mod app_log;
#[cfg(windows)]
mod authenticode;
#[cfg(windows)]
mod autostart;
mod beaconing;
mod browser_close;
mod browser_history;
mod browser_history_cmds;
mod browser_history_delete;
#[cfg(windows)]
mod camera_win;
#[cfg(windows)]
mod clipboard_win;
mod commands;
mod db;
mod dev_infra;
mod diagnostics;
mod etw_cleanup;
#[cfg(windows)]
mod etw_dns;
#[cfg(windows)]
mod etw_win;
#[cfg(windows)]
mod etw_win32k;
mod event_log;
mod export_reports;
mod ioc;
mod ioc_refresh;
mod ip_feeds;
mod live_activity;
#[cfg(windows)]
mod media_signals;
#[cfg(windows)]
mod mic_win;
mod monitoring;
mod privilege;
mod process_actions;
mod process_tree;
mod scan;
#[cfg(windows)]
mod scheduler;
mod score;
#[cfg(windows)]
mod screen_capture;
#[cfg(windows)]
mod services;
mod settings;
mod startup_items;
mod system_surfaces;
#[cfg(windows)]
mod thread_injection;
#[cfg(windows)]
mod window_enum;
mod yara_scan;

use abuse_ch::AbuseChIndex;
use beaconing::BeaconTracker;
use dev_infra::DevInfraIndex;
use ioc::IocIndex;
use ip_feeds::IpFeedIndex;
use rusqlite::Connection;
use serde::Serialize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use tauri::menu::{CheckMenuItemBuilder, Menu, MenuItemBuilder, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::Emitter;
use tauri::Manager;
use tauri::WindowEvent;
use tauri_plugin_autostart::{MacosLauncher, ManagerExt as AutostartManagerExt};
use tauri_plugin_notification::NotificationExt;

#[derive(Clone, Serialize)]
struct SplashProgress {
    step: &'static str,
    label: &'static str,
    done: u32,
    total: u32,
}

#[derive(Default)]
pub struct SetupState {
    pub frontend_task: bool,
    pub backend_task: bool,
}

fn restore_and_focus_primary_window(app: &tauri::AppHandle) {
    let target = app
        .get_webview_window("main")
        .or_else(|| app.get_webview_window("splash"));
    if let Some(win) = target {
        let _ = win.unminimize();
        let _ = win.show();
        let _ = win.set_focus();
    }
}

#[cfg(any(target_os = "windows", target_os = "linux"))]
static SECOND_LAUNCH_GUARD: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Default)]
pub struct ScanState {
    pub in_progress: bool,
    pub last_scan_at: Option<String>,
    pub last_max_score: Option<u8>,
}

#[derive(Clone)]
pub struct AppState {
    pub ioc: Arc<RwLock<IocIndex>>,
    pub ip_feeds: Arc<RwLock<IpFeedIndex>>,
    pub abuse_ch: Arc<RwLock<AbuseChIndex>>,
    pub dev_infra: Arc<DevInfraIndex>,
    pub db: Arc<Mutex<Connection>>,
    pub beacons: Arc<Mutex<BeaconTracker>>,
    pub latest_alert_at: Arc<Mutex<Option<chrono::DateTime<chrono::Utc>>>>,
    pub scan_state: Arc<Mutex<ScanState>>,
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let default_panic = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let payload = info.payload();
        let msg = if let Some(s) = payload.downcast_ref::<&str>() {
            (*s).to_string()
        } else if let Some(s) = payload.downcast_ref::<String>() {
            s.clone()
        } else {
            format!("{payload:?}")
        };
        let loc = info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "unknown".into());
        let bt = std::backtrace::Backtrace::capture();
        eprintln!("[panic] {msg}");
        eprintln!("[panic] at {loc}");
        eprintln!("{bt}");
        let one_line = format!("[panic] {msg} @ {loc}")
            .replace('\n', " ")
            .replace('\r', "");
        app_log::append_line(&one_line);
        default_panic(info);
    }));

    let mut builder = tauri::Builder::default();

    #[cfg(any(target_os = "windows", target_os = "linux"))]
    {
        builder = builder.plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            if !SECOND_LAUNCH_GUARD.load(Ordering::SeqCst) {
                eprintln!(
                    "[single-instance] second launch dropped — first instance still initializing"
                );
                crate::app_log::append_line("[single-instance] second launch dropped during setup");
                return;
            }
            let handle = app.app_handle().clone();
            let handle_inner = handle.clone();
            if let Err(e) =
                handle.run_on_main_thread(move || restore_and_focus_primary_window(&handle_inner))
            {
                eprintln!("[single-instance] run_on_main_thread failed: {e}");
                crate::app_log::append_line(&format!(
                    "[single-instance] run_on_main_thread failed: {e}"
                ));
            }
        }));
    }

    builder
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_autostart::init(
            MacosLauncher::LaunchAgent,
            Some(vec!["--minimized"]),
        ))
        .manage(Mutex::new(SetupState::default()))
        .on_window_event(|window, event| {
            if window.label() != "main" {
                return;
            }
            let WindowEvent::CloseRequested { api, .. } = event else {
                return;
            };
            api.prevent_close();
            let _ = window.hide();

            let app = window.app_handle().clone();
            let state = app.state::<AppState>().inner().clone();
            let notified = {
                let db_guard = match state.db.lock() {
                    Ok(g) => g,
                    Err(_) => return,
                };
                settings::read_tray_close_notified(&db_guard).unwrap_or(false)
            };

            if !notified {
                let _ = app
                    .notification()
                    .builder()
                    .title("Spy Detector is still running")
                    .body(
                        "Right-click the tray icon to fully exit. Open the window from the tray any time.",
                    )
                    .show();
                if let Ok(db_guard) = state.db.lock() {
                    let _ = settings::write_tray_close_notified(&db_guard, true);
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::set_language,
            commands::get_language,
            commands::accept_terms,
            commands::get_terms_accepted_at,
            commands::get_app_metadata,
            commands::quit_app,
            commands::list_processes,
            commands::get_runtime_status,
            commands::request_elevation_restart,
            commands::run_scan,
            commands::get_latest_findings,
            commands::get_scan_history,
            commands::list_network_connections,
            commands::list_allowlist,
            commands::set_allowlist_entry,
            commands::remove_allowlist_entry,
            commands::set_allowlist_trusted,
            commands::get_app_settings,
            commands::set_app_settings,
            commands::export_latest_scan_json,
            commands::export_latest_scan_markdown,
            commands::refresh_ioc,
            commands::list_ip_feeds,
            commands::set_ip_feed_enabled,
            commands::refresh_ip_feeds,
            commands::list_abusech_sources,
            commands::set_abusech_enabled,
            commands::refresh_abusech,
            commands::lookup_hash_malwarebazaar,
            commands::file_sha256_hex,
            commands::get_ioc_catalog_meta,
            commands::check_rules_update,
            commands::submit_bug_report,
            commands::list_ioc_entries,
            commands::set_signature_disabled,
            commands::get_scan_interval,
            commands::set_scan_interval,
            commands::get_monitoring_tick,
            commands::get_yara_status,
            commands::yara_scan_path,
            commands::get_dns_cache_stats,
            commands::clear_dns_cache,
            commands::get_recent_process_launches,
            commands::get_recent_thread_events,
            commands::clear_process_launches,
            commands::clear_thread_events,
            commands::list_event_log,
            commands::count_event_log,
            commands::clear_event_log,
            browser_history_cmds::scan_browser_history,
            browser_history_cmds::list_browser_history_findings,
            browser_history_cmds::clear_browser_history_findings,
            browser_history_cmds::get_dev_infra_meta,
            browser_history_cmds::delete_browser_history_findings,
            browser_history_cmds::delete_all_browser_history_findings,
            browser_history_cmds::preflight_browser_history_delete,
            browser_history_cmds::close_browser_safely_cmd,
            process_actions::prepare_process_action,
            process_actions::kill_process,
            process_actions::quarantine_process,
            commands::get_autostart_enabled,
            commands::set_autostart_enabled,
            commands::list_startup_entries,
            commands::refresh_startup_entries,
            commands::set_startup_entry_enabled,
            commands::set_startup_entry_note,
            commands::list_services,
            commands::open_diagnostic_log,
            commands::open_devtools,
            commands::set_service_enabled,
            commands::set_service_start_type,
            commands::start_service_cmd,
            commands::stop_service_cmd,
            commands::set_service_note,
            commands::set_complete,
        ])
        .setup(move |app| {
            let handle = app.handle().clone();

            #[cfg(windows)]
            const SPLASH_TOTAL: u32 = 11;
            #[cfg(not(windows))]
            const SPLASH_TOTAL: u32 = 6;

            let mut splash_done: u32 = 0;
            let mut splash_emit = |step: &'static str, label: &'static str| {
                splash_done += 1;
                let payload = SplashProgress {
                    step,
                    label,
                    done: splash_done,
                    total: SPLASH_TOTAL,
                };
                let _ = handle.emit("splash_progress", &payload);
            };

            splash_emit("ioc", "Loading IOC index");
            let ioc = Arc::new(RwLock::new(
                IocIndex::load_preferred().expect("bundled IOC YAML must be valid"),
            ));

            splash_emit("db", "Opening local database");
            let db = Arc::new(Mutex::new(
                db::open_db().expect("open application database under %APPDATA%/spy-detector"),
            ));

            splash_emit("diagnostics", "Reading diagnostics flag");
            {
                let db_guard = db
                    .lock()
                    .expect("database mutex poisoned during diagnostics flag init");
                crate::diagnostics::set_enabled(
                    crate::settings::read_diagnostic_logging(&db_guard).unwrap_or(false),
                );
                #[cfg(windows)]
                crate::thread_injection::set_scanner_enabled(
                    crate::settings::read_thread_injection_scanner_enabled(&db_guard)
                        .unwrap_or(true),
                );
                #[cfg(windows)]
                {
                    crate::etw_win::set_process_etw_enabled(
                        crate::settings::read_process_etw_enabled(&db_guard).unwrap_or(true),
                    );
                    crate::etw_win32k::set_win32k_etw_enabled(
                        crate::settings::read_win32k_etw_enabled(&db_guard).unwrap_or(true),
                    );
                    crate::etw_dns::set_dns_etw_enabled(
                        crate::settings::read_dns_etw_enabled(&db_guard).unwrap_or(true),
                    );
                    crate::camera_win::set_camera_monitor_enabled(
                        crate::settings::read_camera_monitor_enabled(&db_guard).unwrap_or(true),
                    );
                    crate::scheduler::set_periodic_scan_enabled(
                        crate::settings::read_periodic_scan_enabled(&db_guard).unwrap_or(true),
                    );
                }
            }

            splash_emit("ip_feeds", "Loading IP feeds");
            let ip_feeds = Arc::new(RwLock::new({
                let g = db
                    .lock()
                    .expect("database mutex poisoned during IP feed index init");
                IpFeedIndex::reload(&g).expect("IP feed index load")
            }));

            splash_emit("abuse_ch", "Loading abuse.ch indexes");
            let abuse_ch = Arc::new(RwLock::new({
                let g = db
                    .lock()
                    .expect("database mutex poisoned during abuse.ch index init");
                match AbuseChIndex::reload(&g) {
                    Ok(idx) => idx,
                    Err(e) => {
                        eprintln!("abuse.ch index load failed: {e}; using empty index");
                        crate::app_log::append_line(&format!(
                            "abuse.ch index load failed: {e}; using empty index"
                        ));
                        AbuseChIndex::default()
                    }
                }
            }));

            let dev_infra = Arc::new(
                DevInfraIndex::load_embedded().expect("bundled dev-infra YAML must be valid"),
            );

            app.manage(AppState {
                ioc,
                ip_feeds,
                abuse_ch,
                dev_infra,
                db,
                beacons: Arc::new(Mutex::new(BeaconTracker::new())),
                latest_alert_at: Arc::new(Mutex::new(None)),
                scan_state: Arc::new(Mutex::new(ScanState::default())),
            });

            let state: AppState = app.state::<AppState>().inner().clone();
            event_log::init(handle.clone(), state.db.clone());
            yara_scan::init_global_index();
            #[cfg(windows)]
            if let Ok(db_guard) = state.db.lock() {
                amsi::sync_enabled_from_db(&db_guard);
            }
            #[cfg(windows)]
            let _ = amsi::try_register_provider(handle.clone());
            event_log::log(
                event_log::EventKind::AppStarted,
                "info",
                None,
                None,
                None,
                None,
                "Spy Detector started",
            );

            #[cfg(windows)]
            {
                let win_state = state.clone();

                splash_emit("media", "Starting camera/microphone monitor");
                camera_win::spawn_monitor();

                splash_emit("etw_cleanup", "Cleaning up stale ETW sessions");
                etw_cleanup::cleanup_stale_sessions();

                splash_emit("etw_monitors", "Subscribing to kernel ETW providers");
                etw_win::spawn_etw_monitor(
                    handle.clone(),
                    win_state.ioc.clone(),
                    win_state.db.clone(),
                    win_state.latest_alert_at.clone(),
                );
                etw_win32k::spawn_win32k_monitor();

                splash_emit("dns_etw", "Starting DNS ETW monitor");
                etw_dns::spawn_dns_monitor(handle.clone());
            }

            // Pause / Resume is disabled (v1 stub). Native tray menus here do not support a
            // per-item tooltip; intended UX copy: tooltip "Coming soon".
            let show_i = MenuItemBuilder::with_id("show", "Show window").build(app)?;
            let initial_autostart_state = app.autolaunch().is_enabled().unwrap_or(false);
            let autostart_i = CheckMenuItemBuilder::with_id("autostart", "Run on system startup")
                .checked(initial_autostart_state)
                .build(app)?;
            let scan_i = MenuItemBuilder::with_id("scan_now", "Run scan now").build(app)?;
            let pause_i = MenuItemBuilder::with_id(
                "pause",
                "Pause / Resume monitoring",
            )
            .enabled(false)
            .build(app)?;
            let sep = PredefinedMenuItem::separator(app)?;
            let quit_i = MenuItemBuilder::with_id("quit", "Quit Spy Detector").build(app)?;
            let menu = Menu::with_items(
                app,
                &[&show_i, &autostart_i, &scan_i, &pause_i, &sep, &quit_i],
            )?;

            let icon = match app.default_window_icon() {
                Some(i) => i.clone(),
                None => return Err("missing default window icon".into()),
            };

            let app_handle = app.handle().clone();
            let autostart_for_menu = autostart_i.clone();
            TrayIconBuilder::with_id("main-tray")
                .icon(icon)
                .menu(&menu)
                .tooltip("Spy Detector\nLimited mode")
                .show_menu_on_left_click(false)
                .on_menu_event(move |app, event| match event.id.as_ref() {
                    "quit" => app.exit(0),
                    "show" => {
                        restore_and_focus_primary_window(app);
                    }
                    "autostart" => {
                        let manager = app.autolaunch();
                        let currently = manager.is_enabled().unwrap_or(false);
                        if currently {
                            let _ = manager.disable();
                        } else {
                            let _ = manager.enable();
                        }
                        let new_state = manager.is_enabled().unwrap_or(false);
                        let _ = autostart_for_menu.set_checked(new_state);
                        event_log::log(
                            event_log::EventKind::SettingsChanged,
                            "info",
                            None,
                            None,
                            None,
                            Some(serde_json::json!({ "key": "autostart", "value": new_state })),
                            if new_state {
                                "Auto-start on boot enabled"
                            } else {
                                "Auto-start on boot disabled"
                            },
                        );
                        let _ = app.emit("autostart_changed", new_state);
                    }
                    "scan_now" => {
                        let state = app.state::<AppState>().inner().clone();
                        let app_for_emit = app.clone();
                        tauri::async_runtime::spawn(async move {
                            let scan_result = tokio::task::spawn_blocking(move || {
                                let mut db = state.db.lock().map_err(|e| e.to_string())?;
                                let mut beacons = state.beacons.lock().map_err(|e| e.to_string())?;
                                let ioc = state.ioc.read().map_err(|e| e.to_string())?;
                                let feeds = state.ip_feeds.read().map_err(|e| e.to_string())?;
                                let abuse = state.abuse_ch.read().map_err(|e| e.to_string())?;
                                scan::execute_scan_with_state(
                                    &ioc,
                                    &feeds,
                                    &abuse,
                                    state.dev_infra.as_ref(),
                                    &mut db,
                                    &mut beacons,
                                    &state.scan_state,
                                    "manual",
                                )
                            })
                            .await;

                            let scan_result = match scan_result {
                                Ok(r) => r,
                                Err(e) => {
                                    eprintln!("spy-detector: tray scan join failed: {e}");
                                    return;
                                }
                            };

                            match scan_result {
                                Ok(findings) => {
                                    let risk_relevant: Vec<_> =
                                        findings.iter().filter(|f| !f.ignored).collect();
                                    let max_score = risk_relevant
                                        .iter()
                                        .map(|f| f.score)
                                        .max()
                                        .unwrap_or(0);
                                    let payload = monitoring::ScanCompletedEvent {
                                        at: chrono::Utc::now().to_rfc3339(),
                                        findings_count: risk_relevant.len() as u32,
                                        max_score,
                                    };
                                    let _ = app_for_emit.emit("scan_completed", &payload);
                                }
                                Err(ref e) if e.as_str() == scan::SCAN_BUSY_ERR => {
                                    eprintln!(
                                        "spy-detector: tray scan skipped (scan already in progress)"
                                    );
                                }
                                Err(e) => {
                                    eprintln!("spy-detector: tray scan failed: {e}");
                                }
                            }
                        });
                    }
                    _ => {}
                })
                .on_tray_icon_event(move |_tray, event| {
                    let TrayIconEvent::Click {
                        button,
                        button_state,
                        ..
                    } = event
                    else {
                        return;
                    };
                    if button != MouseButton::Left || button_state != MouseButtonState::Up {
                        return;
                    }
                    if let Some(w) = app_handle.get_webview_window("main") {
                        match w.is_visible() {
                            Ok(true) => {
                                let _ = w.hide();
                            }
                            Ok(false) => {
                                restore_and_focus_primary_window(&app_handle);
                            }
                            Err(_) => {
                                restore_and_focus_primary_window(&app_handle);
                            }
                        }
                    }
                })
                .build(app)?;

            #[cfg(windows)]
            {
                let sched_state = app.state::<AppState>().inner().clone();
                splash_emit("scheduler", "Starting schedulers");
                scheduler::spawn_auto_scan_on_launch(handle.clone(), sched_state.clone());
                scheduler::spawn_periodic_scan(handle.clone(), sched_state.clone());
                scheduler::spawn_monitoring_heartbeat(handle.clone(), sched_state);
                std::thread::sleep(std::time::Duration::from_millis(250));
            }

            splash_emit("ready", "Ready");

            let args: Vec<String> = std::env::args().collect();
            let start_minimized = args.iter().any(|a| a == "--minimized");
            if start_minimized {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.hide();
                }
            }

            let setup_app = app.handle().clone();
            let mutex = setup_app.state::<Mutex<SetupState>>();
            let _ = commands::complete_setup_task(&setup_app, mutex.inner(), "backend");

            #[cfg(any(target_os = "windows", target_os = "linux"))]
            SECOND_LAUNCH_GUARD.store(true, Ordering::SeqCst);

            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|_app_handle, event| {
            if let tauri::RunEvent::Exit = event {
                event_log::log_app_stopping_sync();
            }
        })
}
