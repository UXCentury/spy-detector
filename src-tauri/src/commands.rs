use crate::abuse_ch::{
    self, AbuseChIndex, AbuseChRefreshSummary, AbuseChSourceStatus, MbLookupResult,
};
use crate::app_log;
use crate::event_log::{log as log_event, EventKind};
use crate::export_reports;
use crate::ioc::{IocEntrySource, IocIndex};
use crate::ioc_refresh::{self, STALKERWARE_IOC_URL};
use crate::ip_feeds::{self, IpFeedIndex, IpFeedStatus};
use crate::monitoring::MonitoringTick;
use crate::privilege;
use crate::scan;
use crate::settings::{self, AppSettings};
use crate::AppState;
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use sysinfo::{Pid, System};
use tauri::Emitter;
use tauri::Manager;
use tauri::State;
use tauri_plugin_autostart::ManagerExt as AutostartManagerExt;

/// Locale codes persisted to `user_settings.language` (must match frontend `Lang`).
const ALLOWED_LANGUAGE_CODES: &[&str] = &[
    "hy-AM", "en-US", "en-GB", "es", "pt-BR", "fr", "de", "it", "nl", "pl", "ru", "uk", "tr", "ar",
    "he", "fa", "hi", "bn", "zh-CN", "zh-TW", "ja", "ko", "vi", "th", "id",
];

fn normalize_language_code(code: &str) -> Option<&'static str> {
    let code = code.trim();
    ALLOWED_LANGUAGE_CODES.iter().copied().find(|&c| c == code)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessRow {
    pub pid: u32,
    pub name: String,
    pub exe_path: Option<String>,
    pub ignored: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeStatus {
    pub elevated: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppMetadata {
    pub version: String,
    pub git_commit: String,
    pub build_date: String,
    pub tauri_version: String,
    pub target: String,
}

#[tauri::command]
pub fn get_app_metadata() -> AppMetadata {
    let secs: u64 = option_env!("SPY_BUILD_DATE_EPOCH")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let build_date = chrono::DateTime::<chrono::Utc>::from_timestamp(secs as i64, 0)
        .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        .unwrap_or_else(|| "unknown".into());
    AppMetadata {
        version: env!("CARGO_PKG_VERSION").to_string(),
        git_commit: option_env!("SPY_GIT_COMMIT")
            .unwrap_or("unknown")
            .to_string(),
        build_date,
        tauri_version: "2".to_string(),
        target: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
    }
}

#[tauri::command(rename_all = "camelCase")]
pub fn list_processes(state: State<AppState>) -> Result<Vec<ProcessRow>, String> {
    let t0 = std::time::Instant::now();
    crate::diagnostics::log("[ipc:list_processes] start");
    let result = (|| -> Result<Vec<ProcessRow>, String> {
        let lock_t0 = std::time::Instant::now();
        crate::diagnostics::log("[ipc:list_processes] acquiring db lock");
        let trusted_keys: HashSet<String> = {
            let db = state.db.lock().map_err(|e| e.to_string())?;
            crate::diagnostics::log(&format!(
                "[ipc:list_processes] db lock acquired in {}ms",
                lock_t0.elapsed().as_millis()
            ));
            let mut stmt = db
                .prepare("SELECT path_norm FROM trusted_paths")
                .map_err(|e| e.to_string())?;
            let rows = stmt
                .query_map([], |r| r.get::<_, String>(0))
                .map_err(|e| e.to_string())?;
            rows.filter_map(|r| r.ok()).collect()
        };
        let mut sys = System::new_all();
        sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
        let mut rows: Vec<ProcessRow> = sys
            .processes()
            .iter()
            .map(|(pid, proc_)| {
                let name = proc_.name().to_string_lossy().into_owned();
                let exe_path = proc_
                    .exe()
                    .map(|p| p.to_string_lossy().into_owned())
                    .filter(|s| !s.is_empty());
                let ignored = exe_path
                    .as_ref()
                    .map(|p| trusted_keys.contains(&crate::allowlist::normalize_path(p)))
                    .unwrap_or(false);
                ProcessRow {
                    pid: pid_as_u32(*pid),
                    name,
                    exe_path,
                    ignored,
                }
            })
            .collect();
        rows.sort_by_key(|a| a.name.to_lowercase());
        Ok(rows)
    })();
    let elapsed = t0.elapsed().as_millis();
    match &result {
        Ok(v) => crate::diagnostics::log(&format!(
            "[ipc:list_processes] ok in {elapsed}ms (rows={})",
            v.len()
        )),
        Err(e) => {
            crate::diagnostics::log(&format!("[ipc:list_processes] error in {elapsed}ms: {e}"))
        }
    }
    result
}

fn pid_as_u32(pid: Pid) -> u32 {
    pid.as_u32()
}

fn user_setting_get(conn: &rusqlite::Connection, key: &str) -> Result<Option<String>, String> {
    conn.query_row(
        "SELECT value FROM user_settings WHERE key = ?1",
        [key],
        |row| row.get::<_, String>(0),
    )
    .optional()
    .map_err(|e| e.to_string())
}

fn user_setting_put(conn: &rusqlite::Connection, key: &str, val: &str) -> Result<(), String> {
    conn.execute(
        "INSERT OR REPLACE INTO user_settings (key, value) VALUES (?1, ?2)",
        rusqlite::params![key, val],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command(rename_all = "camelCase")]
pub fn get_runtime_status() -> RuntimeStatus {
    let t0 = std::time::Instant::now();
    crate::diagnostics::log("[ipc:get_runtime_status] start");
    let result = RuntimeStatus {
        elevated: crate::privilege::is_process_elevated(),
    };
    let elapsed = t0.elapsed().as_millis();
    crate::diagnostics::log(&format!("[ipc:get_runtime_status] ok in {elapsed}ms"));
    result
}

#[tauri::command(rename_all = "camelCase")]
pub fn request_elevation_restart(app: tauri::AppHandle) -> Result<(), String> {
    if crate::privilege::is_process_elevated() {
        return Ok(());
    }
    log_event(
        EventKind::ElevationRequested,
        "info",
        None,
        None,
        None,
        None,
        "User requested elevated restart",
    );
    crate::privilege::shell_restart_elevated()?;
    app.exit(0);
    Ok(())
}

#[tauri::command(rename_all = "camelCase")]
pub fn run_scan(state: State<AppState>) -> Result<Vec<scan::Finding>, String> {
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
    .map_err(|e| {
        if e == scan::SCAN_BUSY_ERR {
            "A scan is already in progress.".into()
        } else {
            e
        }
    })
}

#[tauri::command(rename_all = "camelCase")]
pub fn get_scan_interval(state: State<AppState>) -> Result<u32, String> {
    let db = state.db.lock().map_err(|e| e.to_string())?;
    settings::read_scan_interval_secs(&db)
}

#[tauri::command(rename_all = "camelCase")]
pub fn set_scan_interval(state: State<AppState>, seconds: u32) -> Result<(), String> {
    let db = state.db.lock().map_err(|e| e.to_string())?;
    settings::write_scan_interval_secs(&db, seconds)
}

#[tauri::command(rename_all = "camelCase")]
pub fn get_monitoring_tick(state: State<AppState>) -> Result<MonitoringTick, String> {
    crate::monitoring::build_monitoring_tick(&state)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsCacheStats {
    pub active: bool,
    pub cached_count: u32,
}

#[tauri::command(rename_all = "camelCase")]
pub fn get_dns_cache_stats() -> Result<DnsCacheStats, String> {
    #[cfg(windows)]
    {
        Ok(DnsCacheStats {
            active: crate::etw_dns::is_running(),
            cached_count: crate::etw_dns::cached_count() as u32,
        })
    }
    #[cfg(not(windows))]
    {
        Ok(DnsCacheStats {
            active: false,
            cached_count: 0,
        })
    }
}

#[tauri::command]
pub fn clear_dns_cache() -> Result<(), String> {
    #[cfg(windows)]
    crate::etw_dns::clear_cache();
    Ok(())
}

fn get_recent_process_launches_inner(
    state: &AppState,
    limit: u32,
) -> Result<Vec<crate::live_activity::ProcessLaunchRow>, String> {
    let t0 = std::time::Instant::now();
    crate::diagnostics::log("[ipc:get_recent_process_launches] start");
    let result = (|| -> Result<Vec<crate::live_activity::ProcessLaunchRow>, String> {
        let db = state.db.lock().map_err(|e| e.to_string())?;
        crate::db::recent_process_launches(&db, limit).map_err(|e| e.to_string())
    })();
    let elapsed = t0.elapsed().as_millis();
    match &result {
        Ok(v) => crate::diagnostics::log(&format!(
            "[ipc:get_recent_process_launches] ok in {elapsed}ms (rows={})",
            v.len()
        )),
        Err(e) => crate::diagnostics::log(&format!(
            "[ipc:get_recent_process_launches] error in {elapsed}ms: {e}"
        )),
    }
    result
}

#[tauri::command(rename_all = "camelCase")]
pub async fn get_recent_process_launches(
    state: State<'_, AppState>,
    limit: u32,
) -> Result<Vec<crate::live_activity::ProcessLaunchRow>, String> {
    let st = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || get_recent_process_launches_inner(&st, limit))
        .await
        .map_err(|e| e.to_string())?
}

fn get_recent_thread_events_inner(
    state: &AppState,
    limit: u32,
) -> Result<Vec<crate::live_activity::ThreadEventRow>, String> {
    let t0 = std::time::Instant::now();
    crate::diagnostics::log("[ipc:get_recent_thread_events] start");
    let result = (|| -> Result<Vec<crate::live_activity::ThreadEventRow>, String> {
        let db = state.db.lock().map_err(|e| e.to_string())?;
        crate::db::recent_thread_events(&db, limit).map_err(|e| e.to_string())
    })();
    let elapsed = t0.elapsed().as_millis();
    match &result {
        Ok(v) => crate::diagnostics::log(&format!(
            "[ipc:get_recent_thread_events] ok in {elapsed}ms (rows={})",
            v.len()
        )),
        Err(e) => crate::diagnostics::log(&format!(
            "[ipc:get_recent_thread_events] error in {elapsed}ms: {e}"
        )),
    }
    result
}

#[tauri::command(rename_all = "camelCase")]
pub async fn get_recent_thread_events(
    state: State<'_, AppState>,
    limit: u32,
) -> Result<Vec<crate::live_activity::ThreadEventRow>, String> {
    let st = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || get_recent_thread_events_inner(&st, limit))
        .await
        .map_err(|e| e.to_string())?
}

fn clear_process_launches_inner(state: &AppState) -> Result<(), String> {
    let t0 = std::time::Instant::now();
    crate::diagnostics::log("[ipc:clear_process_launches] start");
    let result = (|| -> Result<(), String> {
        let db = state.db.lock().map_err(|e| e.to_string())?;
        crate::db::clear_process_launches(&db).map_err(|e| e.to_string())
    })();
    let elapsed = t0.elapsed().as_millis();
    match &result {
        Ok(()) => {
            crate::diagnostics::log(&format!("[ipc:clear_process_launches] ok in {elapsed}ms"))
        }
        Err(e) => crate::diagnostics::log(&format!(
            "[ipc:clear_process_launches] error in {elapsed}ms: {e}"
        )),
    }
    result
}

#[tauri::command(rename_all = "camelCase")]
pub async fn clear_process_launches(state: State<'_, AppState>) -> Result<(), String> {
    let st = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || clear_process_launches_inner(&st))
        .await
        .map_err(|e| e.to_string())?
}

fn clear_thread_events_inner(state: &AppState) -> Result<(), String> {
    let t0 = std::time::Instant::now();
    crate::diagnostics::log("[ipc:clear_thread_events] start");
    let result = (|| -> Result<(), String> {
        let db = state.db.lock().map_err(|e| e.to_string())?;
        crate::db::clear_thread_events(&db).map_err(|e| e.to_string())
    })();
    let elapsed = t0.elapsed().as_millis();
    match &result {
        Ok(()) => crate::diagnostics::log(&format!("[ipc:clear_thread_events] ok in {elapsed}ms")),
        Err(e) => crate::diagnostics::log(&format!(
            "[ipc:clear_thread_events] error in {elapsed}ms: {e}"
        )),
    }
    result
}

#[tauri::command(rename_all = "camelCase")]
pub async fn clear_thread_events(state: State<'_, AppState>) -> Result<(), String> {
    let st = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || clear_thread_events_inner(&st))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command(rename_all = "camelCase")]
pub fn get_latest_findings(state: State<AppState>) -> Result<Option<Vec<scan::Finding>>, String> {
    let t0 = std::time::Instant::now();
    crate::diagnostics::log("[ipc:get_latest_findings] start");
    let result = (|| -> Result<Option<Vec<scan::Finding>>, String> {
        let db = state.db.lock().map_err(|e| e.to_string())?;
        scan::load_latest_findings(&db)
    })();
    let elapsed = t0.elapsed().as_millis();
    match &result {
        Ok(Some(v)) => crate::diagnostics::log(&format!(
            "[ipc:get_latest_findings] ok in {elapsed}ms (rows={})",
            v.len()
        )),
        Ok(None) => crate::diagnostics::log(&format!(
            "[ipc:get_latest_findings] ok in {elapsed}ms (rows=0)"
        )),
        Err(e) => crate::diagnostics::log(&format!(
            "[ipc:get_latest_findings] error in {elapsed}ms: {e}"
        )),
    }
    result
}

#[tauri::command(rename_all = "camelCase")]
pub fn get_scan_history(
    state: State<AppState>,
    limit: u32,
) -> Result<Vec<scan::ScanHistoryRow>, String> {
    let db = state.db.lock().map_err(|e| e.to_string())?;
    scan::load_scan_history(&db, limit)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkConnectionRow {
    pub pid: u32,
    pub process_name: String,
    pub remote_ip: String,
    pub remote_port: u16,
    pub reverse_dns: Option<String>,
    #[serde(default)]
    pub resolved_via_dns_etw: bool,
    pub ioc_match: bool,
    pub ioc_source: Option<String>,
    pub ioc_category: Option<String>,
    #[serde(default)]
    pub abuse_ch_family: Option<String>,
    #[serde(default)]
    pub abuse_ch_tags: Option<Vec<String>>,
    pub beacon_suspect: bool,
}

fn abuse_ch_category_slug(src: crate::abuse_ch::AbuseChSource) -> &'static str {
    match src {
        crate::abuse_ch::AbuseChSource::ThreatFox => "abuse-ch-threatfox",
        crate::abuse_ch::AbuseChSource::UrlHaus => "abuse-ch-urlhaus",
        crate::abuse_ch::AbuseChSource::MalwareBazaar => "abuse-ch-malwarebazaar",
    }
}

#[tauri::command(rename_all = "camelCase")]
pub fn list_network_connections(
    state: State<AppState>,
) -> Result<Vec<NetworkConnectionRow>, String> {
    let t0 = std::time::Instant::now();
    crate::diagnostics::log("[ipc:list_network_connections] start");
    let result = (|| -> Result<Vec<NetworkConnectionRow>, String> {
        let ioc = state.ioc.read().map_err(|e| e.to_string())?;
        let feeds = state.ip_feeds.read().map_err(|e| e.to_string())?;
        let abuse = state.abuse_ch.read().map_err(|e| e.to_string())?;
        let db = state.db.lock().map_err(|e| e.to_string())?;
        let disabled = crate::settings::disabled_token_set(&db)?;
        let findings_opt = scan::load_latest_findings(&db)?;
        let findings = findings_opt.unwrap_or_default();
        let mut beacon_pids: HashSet<u32> = HashSet::new();
        for f in &findings {
            if f.reasons.iter().any(|r| r.contains("Beaconing")) {
                beacon_pids.insert(f.pid);
            }
        }

        let peers = scan::established_tcp_peers();
        let mut sys = System::new_all();
        sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);

        let unique_ips: HashSet<IpAddr> = peers.iter().map(|p| p.1).collect();
        let mut dns_map: HashMap<IpAddr, (Option<String>, Option<String>)> = HashMap::new();
        const MAX_DNS: usize = 96;
        for ip in unique_ips.iter().take(MAX_DNS) {
            #[cfg(windows)]
            let etw = crate::etw_dns::lookup_host_for_ip(ip);
            #[cfg(not(windows))]
            let etw = None;
            let rev = dns_lookup::lookup_addr(ip).ok().map(|s| s.to_lowercase());
            dns_map.insert(*ip, (etw, rev));
        }

        let mut feed_match_cache: HashMap<IpAddr, Option<crate::ip_feeds::IpFeedHit>> =
            HashMap::new();

        let mut out: Vec<NetworkConnectionRow> = Vec::with_capacity(peers.len());
        for (pid, ip, port) in peers {
            let process_name = sys
                .process(Pid::from_u32(pid))
                .map(|p| p.name().to_string_lossy().into_owned())
                .unwrap_or_else(|| format!("pid {pid}"));
            let remote_ip = ip.to_string();
            let (mut etw_host, mut rev_host) = dns_map.get(&ip).cloned().unwrap_or((None, None));
            #[cfg(windows)]
            if etw_host.is_none() {
                etw_host = crate::etw_dns::lookup_host_for_ip(&ip);
            }
            if rev_host.is_none() {
                rev_host = dns_lookup::lookup_addr(&ip).ok().map(|s| s.to_lowercase());
            }
            let rev = etw_host.clone().or(rev_host.clone());
            let resolved_via_dns_etw = etw_host.is_some();
            let ip_flag = format!("net:{}", remote_ip.to_lowercase());
            let ip_disabled = disabled.contains(&ip_flag);
            let mut ioc_match = false;
            let mut ioc_source: Option<String> = None;
            let mut ioc_category: Option<String> = None;
            let mut abuse_ch_family: Option<String> = None;
            let mut abuse_ch_tags: Option<Vec<String>> = None;

            if !ip_disabled && ioc.ips.contains(&ip) {
                ioc_match = true;
                ioc_source = Some("Stalkerware (ioc.yaml)".into());
                ioc_category = Some("stalkerware".into());
            } else if !ip_disabled {
                let mut matched = false;
                if let Some(ref eh) = etw_host {
                    if let Some(dom) = ioc.host_matches_domain(eh) {
                        let dom_flag = format!("net:{dom}").to_lowercase();
                        if !disabled.contains(&dom_flag) {
                            ioc_match = true;
                            matched = true;
                            ioc_source = Some("Stalkerware (ioc.yaml)".into());
                            ioc_category = Some("stalkerware".into());
                        }
                    }
                }
                if !matched {
                    if let Some(ref rh) = rev_host {
                        if let Some(dom) = ioc.host_matches_domain(rh) {
                            let dom_flag = format!("net:{dom}").to_lowercase();
                            if !disabled.contains(&dom_flag) {
                                ioc_match = true;
                                ioc_source = Some("Stalkerware (ioc.yaml)".into());
                                ioc_category = Some("stalkerware".into());
                            }
                        }
                    }
                }
            }

            if !ioc_match && !ip_disabled {
                let hit = feed_match_cache
                    .entry(ip)
                    .or_insert_with(|| feeds.match_ip(ip))
                    .clone();
                if let Some(h) = hit {
                    ioc_match = true;
                    ioc_source = Some(h.label.to_string());
                    ioc_category = Some(h.category_slug.to_string());
                }
            }

            if !ioc_match && !ip_disabled {
                if let Some(rec) = abuse.match_ip(&ip) {
                    ioc_match = true;
                    ioc_source = Some(format!("abuse.ch {}", rec.source.label()));
                    ioc_category = Some(abuse_ch_category_slug(rec.source).into());
                    abuse_ch_family = rec.family.clone();
                    abuse_ch_tags = Some(rec.tags.clone());
                }
            }

            if !ioc_match && !ip_disabled {
                for h in [&etw_host, &rev_host].into_iter().flatten() {
                    if let Some(rec) = abuse.match_host(h) {
                        ioc_match = true;
                        ioc_source = Some(format!("abuse.ch {}", rec.source.label()));
                        ioc_category = Some(abuse_ch_category_slug(rec.source).into());
                        abuse_ch_family = rec.family.clone();
                        abuse_ch_tags = Some(rec.tags.clone());
                        break;
                    }
                }
            }

            out.push(NetworkConnectionRow {
                pid,
                process_name,
                remote_ip,
                remote_port: port,
                reverse_dns: rev,
                resolved_via_dns_etw,
                ioc_match,
                ioc_source,
                ioc_category,
                abuse_ch_family,
                abuse_ch_tags,
                beacon_suspect: beacon_pids.contains(&pid),
            });
        }
        out.sort_by(|a, b| {
            a.remote_ip
                .cmp(&b.remote_ip)
                .then_with(|| a.remote_port.cmp(&b.remote_port))
                .then_with(|| a.pid.cmp(&b.pid))
        });
        Ok(out)
    })();
    let elapsed = t0.elapsed().as_millis();
    match &result {
        Ok(v) => crate::diagnostics::log(&format!(
            "[ipc:list_network_connections] ok in {elapsed}ms (rows={})",
            v.len()
        )),
        Err(e) => crate::diagnostics::log(&format!(
            "[ipc:list_network_connections] error in {elapsed}ms: {e}"
        )),
    }
    result
}

fn list_allowlist_inner(state: &AppState) -> Result<Vec<crate::allowlist::AllowlistEntry>, String> {
    let t0 = std::time::Instant::now();
    crate::diagnostics::log("[ipc:list_allowlist] start");
    let result = (|| -> Result<Vec<crate::allowlist::AllowlistEntry>, String> {
        let db = state.db.lock().map_err(|e| e.to_string())?;
        crate::allowlist::list_entries(&db).map_err(|e| e.to_string())
    })();
    let elapsed = t0.elapsed().as_millis();
    match &result {
        Ok(v) => crate::diagnostics::log(&format!(
            "[ipc:list_allowlist] ok in {elapsed}ms (rows={})",
            v.len()
        )),
        Err(e) => {
            crate::diagnostics::log(&format!("[ipc:list_allowlist] error in {elapsed}ms: {e}"))
        }
    }
    result
}

#[tauri::command(rename_all = "camelCase")]
pub async fn list_allowlist(
    state: State<'_, AppState>,
) -> Result<Vec<crate::allowlist::AllowlistEntry>, String> {
    let st = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || list_allowlist_inner(&st))
        .await
        .map_err(|e| e.to_string())?
}

fn list_etw_ignored_inner(state: &AppState) -> Result<Vec<crate::etw_ignore::IgnoreEntry>, String> {
    let db = state.db.lock().map_err(|e| e.to_string())?;
    crate::etw_ignore::list(&db).map_err(|e| e.to_string())
}

#[tauri::command(rename_all = "camelCase")]
pub async fn list_etw_ignored(
    state: State<'_, AppState>,
) -> Result<Vec<crate::etw_ignore::IgnoreEntry>, String> {
    let st = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || list_etw_ignored_inner(&st))
        .await
        .map_err(|e| e.to_string())?
}

fn add_etw_ignored_inner(
    state: &AppState,
    pattern: String,
    note: Option<String>,
) -> Result<(), String> {
    let trimmed = pattern.trim().to_string();
    if trimmed.is_empty() {
        return Err("Pattern cannot be empty.".into());
    }
    let kind = crate::etw_ignore::detect_kind(&trimmed);
    let mut db = state.db.lock().map_err(|e| e.to_string())?;
    crate::etw_ignore::add(&mut db, &trimmed, kind, note.as_deref()).map_err(|e| {
        let msg = e.to_string();
        if msg.contains("UNIQUE constraint failed") {
            "This pattern is already in the ignore list.".into()
        } else {
            msg
        }
    })
}

#[tauri::command(rename_all = "camelCase")]
pub async fn add_etw_ignored(
    state: State<'_, AppState>,
    pattern: String,
    note: Option<String>,
) -> Result<(), String> {
    let st = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || add_etw_ignored_inner(&st, pattern, note))
        .await
        .map_err(|e| e.to_string())?
}

fn remove_etw_ignored_inner(state: &AppState, id: i64) -> Result<(), String> {
    let mut db = state.db.lock().map_err(|e| e.to_string())?;
    crate::etw_ignore::remove(&mut db, id).map_err(|e| e.to_string())
}

#[tauri::command(rename_all = "camelCase")]
pub async fn remove_etw_ignored(state: State<'_, AppState>, id: i64) -> Result<(), String> {
    let st = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || remove_etw_ignored_inner(&st, id))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command(rename_all = "camelCase")]
pub fn set_allowlist_entry(
    state: State<AppState>,
    image_path: String,
    name: String,
    trusted: bool,
    reason: Option<String>,
) -> Result<(), String> {
    let db = state.db.lock().map_err(|e| e.to_string())?;
    crate::allowlist::set_entry(&db, &image_path, &name, trusted, reason.as_deref())
        .map_err(|e| e.to_string())?;
    let detail = image_path.trim();
    if trusted {
        let reason_bit = reason
            .as_ref()
            .map(|r| r.trim())
            .filter(|s| !s.is_empty())
            .map(|s| format!(" reason=\"{s}\""))
            .unwrap_or_default();
        crate::app_log::append_line(&format!(
            "allowlist ignore path=\"{detail}\" name=\"{}\"{reason_bit}",
            name.trim()
        ));
        log_event(
            EventKind::Ignored,
            "low",
            None,
            Some(name.trim().to_string()),
            Some(detail.to_string()),
            Some(serde_json::json!({
                "path": detail,
                "reason": reason.as_ref().map(|r| r.trim()).filter(|s| !s.is_empty()),
            })),
            format!("Ignored process path ({})", name.trim()),
        );
    } else {
        crate::app_log::append_line(&format!("allowlist trust_cleared path=\"{detail}\""));
        log_event(
            EventKind::Unignored,
            "low",
            None,
            Some(name.trim().to_string()),
            Some(detail.to_string()),
            Some(serde_json::json!({ "path": detail })),
            "Removed from ignore list (trust cleared)",
        );
    }
    Ok(())
}

#[tauri::command(rename_all = "camelCase")]
pub fn remove_allowlist_entry(state: State<AppState>, image_path: String) -> Result<(), String> {
    let db = state.db.lock().map_err(|e| e.to_string())?;
    crate::allowlist::remove_entry(&db, &image_path).map_err(|e| e.to_string())?;
    let p = image_path.trim().to_string();
    crate::app_log::append_line(&format!("allowlist removed path=\"{}\"", p));
    log_event(
        EventKind::Unignored,
        "low",
        None,
        None,
        Some(p.clone()),
        Some(serde_json::json!({ "path": p })),
        "Entry removed from ignore list",
    );
    Ok(())
}

#[tauri::command(rename_all = "camelCase")]
pub fn set_allowlist_trusted(
    state: State<AppState>,
    path: String,
    trusted: bool,
) -> Result<(), String> {
    let db = state.db.lock().map_err(|e| e.to_string())?;
    crate::allowlist::set_trusted(&db, &path, trusted).map_err(|e| e.to_string())?;
    let detail = path.trim();
    if trusted {
        crate::app_log::append_line(&format!("allowlist ignore path=\"{detail}\" (legacy add)"));
        log_event(
            EventKind::Ignored,
            "low",
            None,
            None,
            Some(detail.to_string()),
            Some(serde_json::json!({ "path": detail })),
            "Ignored path (legacy)",
        );
    } else {
        crate::app_log::append_line(&format!("allowlist removed path=\"{detail}\" (legacy)"));
        log_event(
            EventKind::Unignored,
            "low",
            None,
            None,
            Some(detail.to_string()),
            Some(serde_json::json!({ "path": detail })),
            "Unignored path (legacy)",
        );
    }
    Ok(())
}

#[tauri::command(rename_all = "camelCase")]
pub fn get_app_settings(state: State<AppState>) -> Result<AppSettings, String> {
    let t0 = std::time::Instant::now();
    crate::diagnostics::log("[ipc:get_app_settings] start");
    let result = (|| -> Result<AppSettings, String> {
        let db = state.db.lock().map_err(|e| e.to_string())?;
        crate::settings::load_app_settings(&db)
    })();
    let elapsed = t0.elapsed().as_millis();
    match &result {
        Ok(_) => crate::diagnostics::log(&format!("[ipc:get_app_settings] ok in {elapsed}ms")),
        Err(e) => {
            crate::diagnostics::log(&format!("[ipc:get_app_settings] error in {elapsed}ms: {e}"))
        }
    }
    result
}

#[tauri::command(rename_all = "camelCase")]
pub fn set_app_settings(state: State<AppState>, value: AppSettings) -> Result<(), String> {
    let t0 = std::time::Instant::now();
    crate::diagnostics::log("[ipc:set_app_settings] start");
    let result = (|| -> Result<(), String> {
        let db = state.db.lock().map_err(|e| e.to_string())?;
        let prev = crate::settings::load_app_settings(&db)?;
        crate::settings::save_app_settings(&db, &value)?;
        crate::diagnostics::set_enabled(value.diagnostic_logging);
        crate::thread_injection::set_scanner_enabled(value.thread_injection_scanner_enabled);
        #[cfg(windows)]
        {
            crate::etw_win::set_process_etw_enabled(value.process_etw_enabled);
            crate::etw_win32k::set_win32k_etw_enabled(value.win32k_etw_enabled);
            crate::etw_dns::set_dns_etw_enabled(value.dns_etw_enabled);
            crate::camera_win::set_camera_monitor_enabled(value.camera_monitor_enabled);
            crate::scheduler::set_periodic_scan_enabled(value.periodic_scan_enabled);
        }
        if prev.warn_threshold != value.warn_threshold {
            log_event(
                EventKind::SettingsChanged,
                "info",
                None,
                None,
                None,
                Some(serde_json::json!({
                    "key": "warn_threshold",
                    "value": value.warn_threshold,
                })),
                format!("warn_threshold → {}", value.warn_threshold),
            );
        }
        if prev.alert_threshold != value.alert_threshold {
            log_event(
                EventKind::SettingsChanged,
                "info",
                None,
                None,
                None,
                Some(serde_json::json!({
                    "key": "alert_threshold",
                    "value": value.alert_threshold,
                })),
                format!("alert_threshold → {}", value.alert_threshold),
            );
        }
        let prev_toks = serde_json::to_string(&prev.disabled_signature_tokens).unwrap_or_default();
        let next_toks = serde_json::to_string(&value.disabled_signature_tokens).unwrap_or_default();
        if prev_toks != next_toks {
            log_event(
                EventKind::SettingsChanged,
                "info",
                None,
                None,
                None,
                Some(serde_json::json!({
                    "key": "disabled_signature_tokens",
                    "value": value.disabled_signature_tokens,
                })),
                "disabled_signature_tokens updated",
            );
        }
        if prev.ioc_last_refreshed_at != value.ioc_last_refreshed_at {
            log_event(
                EventKind::SettingsChanged,
                "info",
                None,
                None,
                None,
                Some(serde_json::json!({
                    "key": "ioc_last_refreshed_at",
                    "value": value.ioc_last_refreshed_at,
                })),
                "ioc_last_refreshed_at updated",
            );
        }
        if prev.amsi_enabled != value.amsi_enabled {
            log_event(
                EventKind::SettingsChanged,
                "info",
                None,
                None,
                None,
                Some(serde_json::json!({
                    "key": "amsi_enabled",
                    "value": value.amsi_enabled,
                })),
                format!("amsi_enabled → {}", value.amsi_enabled),
            );
        }
        if prev.yara_enabled != value.yara_enabled {
            log_event(
                EventKind::SettingsChanged,
                "info",
                None,
                None,
                None,
                Some(serde_json::json!({
                    "key": "yara_enabled",
                    "value": value.yara_enabled,
                })),
                format!("yara_enabled → {}", value.yara_enabled),
            );
        }
        if prev.auto_scan_on_launch != value.auto_scan_on_launch {
            log_event(
                EventKind::SettingsChanged,
                "info",
                None,
                None,
                None,
                Some(serde_json::json!({
                    "key": "auto_scan_on_launch",
                    "value": value.auto_scan_on_launch,
                })),
                format!("auto_scan_on_launch → {}", value.auto_scan_on_launch),
            );
        }
        if prev.tray_alerts_enabled != value.tray_alerts_enabled {
            log_event(
                EventKind::SettingsChanged,
                "info",
                None,
                None,
                None,
                Some(serde_json::json!({
                    "key": "tray_alerts_enabled",
                    "value": value.tray_alerts_enabled,
                })),
                format!("tray_alerts_enabled → {}", value.tray_alerts_enabled),
            );
        }
        #[cfg(windows)]
        crate::amsi::sync_enabled_from_db(&db);
        Ok(())
    })();
    let elapsed = t0.elapsed().as_millis();
    match &result {
        Ok(()) => crate::diagnostics::log(&format!("[ipc:set_app_settings] ok in {elapsed}ms")),
        Err(e) => {
            crate::diagnostics::log(&format!("[ipc:set_app_settings] error in {elapsed}ms: {e}"))
        }
    }
    result
}

#[tauri::command(rename_all = "camelCase")]
pub fn get_yara_status() -> Result<crate::yara_scan::YaraStatus, String> {
    crate::yara_scan::global_index()
        .map(|i| i.status())
        .ok_or_else(|| {
            crate::yara_scan::global_load_error()
                .unwrap_or("YARA rules failed to load")
                .to_string()
        })
}

#[tauri::command(rename_all = "camelCase")]
pub fn yara_scan_path(path: String) -> Result<Vec<crate::yara_scan::YaraMatch>, String> {
    let idx = crate::yara_scan::global_index().ok_or_else(|| {
        crate::yara_scan::global_load_error()
            .unwrap_or("YARA unavailable")
            .to_string()
    })?;
    let p = std::path::Path::new(path.trim());
    idx.match_path(p)
}

#[tauri::command(rename_all = "camelCase")]
pub fn export_latest_scan_json(state: State<AppState>) -> Result<String, String> {
    let db = state.db.lock().map_err(|e| e.to_string())?;
    export_reports::export_latest_json(&db)
}

#[tauri::command(rename_all = "camelCase")]
pub fn export_latest_scan_markdown(state: State<AppState>) -> Result<String, String> {
    let db = state.db.lock().map_err(|e| e.to_string())?;
    export_reports::export_latest_markdown(&db)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IocEntryView {
    pub token: String,
    pub kind: String,
    pub source: String,
    pub disabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub indicator_count: Option<u32>,
}

fn ioc_source_label(s: IocEntrySource) -> &'static str {
    match s {
        IocEntrySource::Bundled => "bundled",
        IocEntrySource::Upstream => "upstream",
        IocEntrySource::WindowsSignatures => "windows_signatures",
    }
}

fn rule_storage_key(kind: &str, token: &str) -> Result<String, String> {
    let token = token.trim();
    if token.is_empty() {
        return Err("empty IOC token".into());
    }
    match kind {
        "process_name" => Ok(crate::ioc::norm_token(token)),
        "path_needle" => Ok(format!("path:{}", token.to_lowercase())),
        "domain" => Ok(format!("net:{}", crate::ioc::domain_key(token))),
        "ip" => {
            let ip: std::net::IpAddr = token
                .parse()
                .map_err(|_| "invalid IP for IOC rule".to_string())?;
            Ok(format!("net:{ip}").to_lowercase())
        }
        _ => Err(format!("unknown IOC kind: {kind}")),
    }
}

fn rule_row_disabled(disabled: &HashSet<String>, kind: &str, token: &str) -> bool {
    rule_storage_key(kind, token)
        .ok()
        .map(|k| disabled.contains(&k.to_lowercase()))
        .unwrap_or(false)
}

fn list_ioc_entries_inner(state: &AppState) -> Result<Vec<IocEntryView>, String> {
    let t0 = std::time::Instant::now();
    crate::diagnostics::log("[ipc:list_ioc_entries] start");
    let result = (|| -> Result<Vec<IocEntryView>, String> {
        let ioc = state.ioc.read().map_err(|e| e.to_string())?;
        let feeds_idx = state.ip_feeds.read().map_err(|e| e.to_string())?;
        let lock_t0 = std::time::Instant::now();
        crate::diagnostics::log("[ipc:list_ioc_entries] acquiring db lock");
        let db = state.db.lock().map_err(|e| e.to_string())?;
        crate::diagnostics::log(&format!(
            "[ipc:list_ioc_entries] db lock acquired in {}ms",
            lock_t0.elapsed().as_millis()
        ));
        let disabled = crate::settings::disabled_token_set(&db)?;
        let rows = ioc.list_rule_rows();
        let mut out = Vec::with_capacity(rows.len() + ip_feeds::FEEDS.len());
        for r in rows {
            out.push(IocEntryView {
                disabled: rule_row_disabled(&disabled, r.kind, &r.token),
                token: r.token.clone(),
                kind: r.kind.to_string(),
                source: ioc_source_label(r.source).to_string(),
                indicator_count: None,
            });
        }
        for feed in ip_feeds::FEEDS {
            let enabled = ip_feeds::feed_enabled(&db, feed.slug, feed.default_enabled)?;
            out.push(IocEntryView {
                token: feed.slug.to_string(),
                kind: "ip_feed".into(),
                source: feed.label.to_string(),
                disabled: !enabled,
                indicator_count: Some(feeds_idx.indicator_count(feed.slug)),
            });
        }
        Ok(out)
    })();
    let elapsed = t0.elapsed().as_millis();
    match &result {
        Ok(v) => crate::diagnostics::log(&format!(
            "[ipc:list_ioc_entries] ok in {elapsed}ms (rows={})",
            v.len()
        )),
        Err(e) => {
            crate::diagnostics::log(&format!("[ipc:list_ioc_entries] error in {elapsed}ms: {e}"))
        }
    }
    result
}

#[tauri::command(rename_all = "camelCase")]
pub async fn list_ioc_entries(state: State<'_, AppState>) -> Result<Vec<IocEntryView>, String> {
    let st = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || list_ioc_entries_inner(&st))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command(rename_all = "camelCase")]
pub fn set_signature_disabled(
    state: State<AppState>,
    token: String,
    kind: String,
    disabled: bool,
) -> Result<(), String> {
    let key = rule_storage_key(&kind, &token)?.to_lowercase();
    let db = state.db.lock().map_err(|e| e.to_string())?;
    let mut s = crate::settings::load_app_settings(&db)?;
    let mut set: HashSet<String> = s
        .disabled_signature_tokens
        .iter()
        .map(|t| t.trim().to_lowercase())
        .filter(|t| !t.is_empty())
        .collect();
    if disabled {
        set.insert(key);
    } else {
        set.remove(&key);
    }
    let mut v: Vec<String> = set.into_iter().collect();
    v.sort();
    s.disabled_signature_tokens = v;
    crate::settings::save_app_settings(&db, &s)?;
    log_event(
        EventKind::SettingsChanged,
        "info",
        None,
        None,
        None,
        Some(serde_json::json!({
            "key": "signature_rule",
            "token": token.trim(),
            "kind": kind.trim(),
            "disabled": disabled,
        })),
        format!(
            "IOC rule {} {}",
            token.trim(),
            if disabled { "disabled" } else { "enabled" }
        ),
    );
    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshIocResult {
    pub success: bool,
    pub message: String,
    pub entries_loaded: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IocCatalogMeta {
    pub upstream_url: String,
    pub upstream_source: String,
    pub last_refreshed_at: Option<String>,
}

#[tauri::command(rename_all = "camelCase")]
pub fn get_ioc_catalog_meta(state: State<AppState>) -> Result<IocCatalogMeta, String> {
    let db = state.db.lock().map_err(|e| e.to_string())?;
    let s = settings::load_app_settings(&db)?;
    let upstream_source = if IocIndex::user_upstream_ioc_path()
        .map(|p| p.is_file())
        .unwrap_or(false)
    {
        "downloaded"
    } else {
        "bundled"
    };
    Ok(IocCatalogMeta {
        upstream_url: STALKERWARE_IOC_URL.into(),
        upstream_source: upstream_source.into(),
        last_refreshed_at: s.ioc_last_refreshed_at,
    })
}

#[tauri::command(rename_all = "camelCase")]
pub async fn check_rules_update(
    state: State<'_, AppState>,
) -> Result<ioc_refresh::CheckRulesUpdateResult, String> {
    let etag = {
        let db = state.db.lock().map_err(|e| e.to_string())?;
        user_setting_get(&db, "ioc_last_remote_etag")?
    };
    let ims = {
        let db = state.db.lock().map_err(|e| e.to_string())?;
        user_setting_get(&db, "ioc_last_remote_last_modified")?
    };
    Ok(ioc_refresh::check_rules_update_remote(etag, ims).await)
}

#[tauri::command(rename_all = "camelCase")]
pub fn list_ip_feeds(state: State<AppState>) -> Result<Vec<IpFeedStatus>, String> {
    let db = state.db.lock().map_err(|e| e.to_string())?;
    let idx = state.ip_feeds.read().map_err(|e| e.to_string())?;
    ip_feeds::list_feed_statuses(&db, &idx)
}

#[tauri::command(rename_all = "camelCase")]
pub fn set_ip_feed_enabled(
    state: State<AppState>,
    slug: String,
    enabled: bool,
) -> Result<(), String> {
    let slug_t = slug.trim();
    if !ip_feeds::FEEDS.iter().any(|f| f.slug == slug_t) {
        return Err("Unknown IP feed.".into());
    }
    let idx = {
        let db = state.db.lock().map_err(|e| e.to_string())?;
        ip_feeds::set_feed_enabled(&db, slug_t, enabled)?;
        IpFeedIndex::reload(&db)?
    };
    *state.ip_feeds.write().map_err(|e| e.to_string())? = idx;
    log_event(
        EventKind::SettingsChanged,
        "info",
        None,
        None,
        None,
        Some(serde_json::json!({
            "key": format!("ip_feed_enabled:{slug_t}"),
            "enabled": enabled,
        })),
        format!(
            "IP feed {} {}",
            slug_t,
            if enabled { "enabled" } else { "disabled" }
        ),
    );
    Ok(())
}

#[tauri::command(rename_all = "camelCase")]
pub async fn refresh_ip_feeds(
    state: State<'_, AppState>,
) -> Result<ip_feeds::IpFeedsRefreshSummary, String> {
    use std::time::Duration;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(45))
        .user_agent("spy-detector/0.1")
        .build()
        .map_err(|e| e.to_string())?;

    let enabled_flags: Vec<bool> = {
        let db = state.db.lock().map_err(|e| e.to_string())?;
        ip_feeds::FEEDS
            .iter()
            .map(|f| ip_feeds::feed_enabled(&db, f.slug, f.default_enabled))
            .collect::<Result<Vec<_>, _>>()?
    };

    let mut fetched: Vec<Result<String, String>> = Vec::with_capacity(ip_feeds::FEEDS.len());
    for (idx, feed) in ip_feeds::FEEDS.iter().enumerate() {
        if !enabled_flags[idx] {
            fetched.push(Err("skipped".into()));
            continue;
        }
        let step = async {
            let resp = client
                .get(feed.upstream_url)
                .send()
                .await
                .map_err(|e| e.to_string())?;
            if !resp.status().is_success() {
                return Err(format!("HTTP {}", resp.status().as_u16()));
            }
            let bytes = resp.bytes().await.map_err(|e| e.to_string())?;
            String::from_utf8(bytes.to_vec()).map_err(|e| format!("invalid UTF-8: {e}"))
        };
        fetched.push(step.await);
    }

    let mut rows: Vec<ip_feeds::IpFeedRefreshRow> = Vec::new();
    let mut any_fail = false;

    let idx = {
        let db = state.db.lock().map_err(|e| e.to_string())?;
        for (feed, res) in ip_feeds::FEEDS.iter().zip(fetched) {
            match res {
                Err(e) if e == "skipped" => {
                    rows.push(ip_feeds::IpFeedRefreshRow {
                        slug: feed.slug.to_string(),
                        status: "skipped".into(),
                        indicator_count: 0,
                        message: Some("feed disabled".into()),
                    });
                }
                Err(e) => {
                    any_fail = true;
                    rows.push(ip_feeds::IpFeedRefreshRow {
                        slug: feed.slug.to_string(),
                        status: "error".into(),
                        indicator_count: 0,
                        message: Some(e),
                    });
                }
                Ok(text) => match ip_feeds::persist_refreshed_feed(&db, feed, &text) {
                    Ok(count) => {
                        rows.push(ip_feeds::IpFeedRefreshRow {
                            slug: feed.slug.to_string(),
                            status: "ok".into(),
                            indicator_count: count,
                            message: None,
                        });
                    }
                    Err(e) => {
                        any_fail = true;
                        rows.push(ip_feeds::IpFeedRefreshRow {
                            slug: feed.slug.to_string(),
                            status: "error".into(),
                            indicator_count: 0,
                            message: Some(e),
                        });
                    }
                },
            }
        }
        ip_feeds::touch_global_feed_refresh(&db)?;
        IpFeedIndex::reload(&db)?
    };

    *state.ip_feeds.write().map_err(|e| e.to_string())? = idx;

    log_event(
        EventKind::IocRefresh,
        "info",
        None,
        None,
        None,
        Some(serde_json::json!({
            "source": "ip-feeds",
            "feeds": rows.iter().map(|r| serde_json::json!({
                "slug": r.slug,
                "indicatorCount": r.indicator_count,
                "status": r.status,
                "message": r.message,
            })).collect::<Vec<_>>(),
        })),
        if any_fail {
            "Some IP feeds failed to refresh"
        } else {
            "IP feeds refreshed"
        },
    );

    Ok(ip_feeds::IpFeedsRefreshSummary {
        ok: !any_fail,
        feeds: rows,
    })
}

#[tauri::command(rename_all = "camelCase")]
pub fn list_abusech_sources(state: State<AppState>) -> Result<Vec<AbuseChSourceStatus>, String> {
    let db = state.db.lock().map_err(|e| e.to_string())?;
    let idx = state.abuse_ch.read().map_err(|e| e.to_string())?;
    abuse_ch::list_source_statuses(&db, &idx)
}

#[tauri::command(rename_all = "camelCase")]
pub fn set_abusech_enabled(
    state: State<AppState>,
    slug: String,
    enabled: bool,
) -> Result<(), String> {
    let slug_t = slug.trim();
    if !abuse_ch::SOURCES.iter().any(|s| s.slug == slug_t) {
        return Err("Unknown abuse.ch source.".into());
    }
    let idx = {
        let db = state.db.lock().map_err(|e| e.to_string())?;
        abuse_ch::set_source_enabled(&db, slug_t, enabled)?;
        AbuseChIndex::reload(&db)?
    };
    *state.abuse_ch.write().map_err(|e| e.to_string())? = idx;
    log_event(
        EventKind::SettingsChanged,
        "info",
        None,
        None,
        None,
        Some(serde_json::json!({
            "key": abuse_ch::enabled_setting_key(slug_t),
            "enabled": enabled,
        })),
        format!(
            "abuse.ch {} {}",
            slug_t,
            if enabled { "enabled" } else { "disabled" }
        ),
    );
    Ok(())
}

#[tauri::command(rename_all = "camelCase")]
pub async fn refresh_abusech(state: State<'_, AppState>) -> Result<AbuseChRefreshSummary, String> {
    use std::time::Duration;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(90))
        .user_agent("spy-detector/0.1")
        .build()
        .map_err(|e| e.to_string())?;

    let tf_on = {
        let db = state.db.lock().map_err(|e| e.to_string())?;
        abuse_ch::source_enabled(&db, "threatfox", true)?
    };
    let uh_on = {
        let db = state.db.lock().map_err(|e| e.to_string())?;
        abuse_ch::source_enabled(&db, "urlhaus", true)?
    };

    let tf_body: Result<String, String> = if tf_on {
        let resp = client
            .get(abuse_ch::THREATFOX_URL)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if !resp.status().is_success() {
            Err(format!("HTTP {}", resp.status().as_u16()))
        } else {
            let bytes = resp.bytes().await.map_err(|e| e.to_string())?;
            String::from_utf8(bytes.to_vec()).map_err(|e| format!("invalid UTF-8: {e}"))
        }
    } else {
        Err("skipped".into())
    };

    let uh_body: Result<String, String> = if uh_on {
        let resp = client
            .get(abuse_ch::URLHAUS_CSV_URL)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if !resp.status().is_success() {
            Err(format!("HTTP {}", resp.status().as_u16()))
        } else {
            let bytes = resp.bytes().await.map_err(|e| e.to_string())?;
            String::from_utf8(bytes.to_vec()).map_err(|e| format!("invalid UTF-8: {e}"))
        }
    } else {
        Err("skipped".into())
    };

    let mut rows: Vec<abuse_ch::AbuseChRefreshRow> = Vec::new();
    let mut any_fail = false;

    let idx = {
        let db = state.db.lock().map_err(|e| e.to_string())?;
        match tf_body {
            Err(e) if e == "skipped" => {
                rows.push(abuse_ch::AbuseChRefreshRow {
                    slug: "threatfox".into(),
                    status: "skipped".into(),
                    indicator_count: 0,
                    message: Some("feed disabled".into()),
                });
            }
            Err(e) => {
                any_fail = true;
                rows.push(abuse_ch::AbuseChRefreshRow {
                    slug: "threatfox".into(),
                    status: "error".into(),
                    indicator_count: 0,
                    message: Some(e),
                });
            }
            Ok(text) => match abuse_ch::persist_threatfox(&db, &text) {
                Ok(count) => {
                    rows.push(abuse_ch::AbuseChRefreshRow {
                        slug: "threatfox".into(),
                        status: "ok".into(),
                        indicator_count: count,
                        message: None,
                    });
                }
                Err(e) => {
                    any_fail = true;
                    rows.push(abuse_ch::AbuseChRefreshRow {
                        slug: "threatfox".into(),
                        status: "error".into(),
                        indicator_count: 0,
                        message: Some(e),
                    });
                }
            },
        }
        match uh_body {
            Err(e) if e == "skipped" => {
                rows.push(abuse_ch::AbuseChRefreshRow {
                    slug: "urlhaus".into(),
                    status: "skipped".into(),
                    indicator_count: 0,
                    message: Some("feed disabled".into()),
                });
            }
            Err(e) => {
                any_fail = true;
                rows.push(abuse_ch::AbuseChRefreshRow {
                    slug: "urlhaus".into(),
                    status: "error".into(),
                    indicator_count: 0,
                    message: Some(e),
                });
            }
            Ok(text) => match abuse_ch::persist_urlhaus(&db, &text) {
                Ok(count) => {
                    rows.push(abuse_ch::AbuseChRefreshRow {
                        slug: "urlhaus".into(),
                        status: "ok".into(),
                        indicator_count: count,
                        message: None,
                    });
                }
                Err(e) => {
                    any_fail = true;
                    rows.push(abuse_ch::AbuseChRefreshRow {
                        slug: "urlhaus".into(),
                        status: "error".into(),
                        indicator_count: 0,
                        message: Some(e),
                    });
                }
            },
        }
        rows.push(abuse_ch::AbuseChRefreshRow {
            slug: "malwarebazaar".into(),
            status: "skipped".into(),
            indicator_count: 0,
            message: Some("on-demand lookups only".into()),
        });
        AbuseChIndex::reload(&db)?
    };

    *state.abuse_ch.write().map_err(|e| e.to_string())? = idx;

    log_event(
        EventKind::IocRefresh,
        "info",
        None,
        None,
        None,
        Some(serde_json::json!({
            "source": "abuse-ch",
            "feeds": rows.iter().map(|r| serde_json::json!({
                "slug": r.slug,
                "indicatorCount": r.indicator_count,
                "status": r.status,
                "message": r.message,
            })).collect::<Vec<_>>(),
        })),
        if any_fail {
            "Some abuse.ch feeds failed to refresh"
        } else {
            "abuse.ch refreshed"
        },
    );

    Ok(AbuseChRefreshSummary {
        ok: !any_fail,
        feeds: rows,
    })
}

#[tauri::command(rename_all = "camelCase")]
pub async fn lookup_hash_malwarebazaar(
    state: State<'_, AppState>,
    sha256: String,
) -> Result<Option<MbLookupResult>, String> {
    let enabled = {
        let db = state.db.lock().map_err(|e| e.to_string())?;
        abuse_ch::source_enabled(&db, "malwarebazaar", false)?
    };
    if !enabled {
        return Ok(None);
    }
    match abuse_ch::malwarebazaar_lookup(&sha256).await {
        Ok(v) => Ok(v),
        Err(_) => Ok(None),
    }
}

#[tauri::command(rename_all = "camelCase")]
pub fn file_sha256_hex(path: String) -> Result<String, String> {
    use sha2::{Digest, Sha256};
    use std::fs::File;
    use std::io::Read;
    let path = path.trim();
    let mut f = File::open(path).map_err(|e| e.to_string())?;
    let mut h = Sha256::new();
    let mut buf = [0u8; 65_536];
    loop {
        let n = f.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(format!("{:x}", h.finalize()))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BugReportPayload {
    pub title: String,
    pub description: String,
    pub include_diagnostics: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BugReportSaved {
    pub path: String,
}

#[tauri::command(rename_all = "camelCase")]
pub fn submit_bug_report(payload: BugReportPayload) -> Result<BugReportSaved, String> {
    let title = payload.title.trim();
    if title.is_empty() {
        return Err("Title is required.".into());
    }

    let dir = app_log::app_data_dir()?.join("bug-reports");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let ts = chrono::Utc::now().format("%Y%m%dT%H%M%SZ");
    let path = dir.join(format!("report-{ts}.txt"));

    let mut body = String::new();
    body.push_str("spy-detector bug report\n");
    body.push_str("========================\n\n");
    body.push_str(&format!("title: {title}\n"));
    body.push_str(&format!("app_version: {}\n", env!("CARGO_PKG_VERSION")));
    body.push_str(&format!("os: {}\n", std::env::consts::OS));
    body.push_str(&format!("elevated: {}\n", privilege::is_process_elevated()));
    body.push_str("\n--- user description ---\n");
    body.push_str(payload.description.trim());
    body.push('\n');

    if payload.include_diagnostics {
        body.push_str("\n--- last app.log lines (up to 200) ---\n");
        body.push_str(&app_log::read_last_lines(200));
        body.push('\n');
    }

    std::fs::write(&path, &body).map_err(|e| e.to_string())?;

    let path_str = path.to_string_lossy().into_owned();
    app_log::append_line(&format!(
        "submit_bug_report saved path={path_str} diagnostics={}",
        payload.include_diagnostics
    ));

    Ok(BugReportSaved { path: path_str })
}

#[tauri::command(rename_all = "camelCase")]
pub async fn refresh_ioc(state: State<'_, AppState>) -> Result<RefreshIocResult, String> {
    match crate::ioc_refresh::download_validate_replace_user_ioc().await {
        Ok(meta) => {
            let new_idx = IocIndex::load_preferred()?;
            let entries_loaded = new_idx.indicator_count();
            {
                let mut w = state.ioc.write().map_err(|e| e.to_string())?;
                *w = new_idx;
            }
            let ts = chrono::Utc::now().to_rfc3339();
            let db = state.db.lock().map_err(|e| e.to_string())?;
            db.execute(
                "INSERT OR REPLACE INTO user_settings (key, value) VALUES ('ioc_last_refreshed_at', ?1)",
                [&ts],
            )
            .map_err(|e| e.to_string())?;
            if let Some(ref e) = meta.etag {
                user_setting_put(&db, "ioc_last_remote_etag", e)?;
            }
            if let Some(ref m) = meta.last_modified {
                user_setting_put(&db, "ioc_last_remote_last_modified", m)?;
            }
            log_event(
                EventKind::IocRefresh,
                "info",
                None,
                None,
                None,
                Some(serde_json::json!({
                    "source": "upstream",
                    "status": "ok",
                    "count": entries_loaded,
                })),
                "IOC refresh succeeded",
            );
            Ok(RefreshIocResult {
                success: true,
                message: "IOC refreshed from upstream.".into(),
                entries_loaded,
            })
        }
        Err(e) => {
            log_event(
                EventKind::IocRefresh,
                "info",
                None,
                None,
                None,
                Some(serde_json::json!({
                    "source": "upstream",
                    "status": "error",
                    "count": 0,
                    "message": &e,
                })),
                "IOC refresh failed",
            );
            Ok(RefreshIocResult {
                success: false,
                message: e,
                entries_loaded: 0,
            })
        }
    }
}

#[tauri::command(rename_all = "camelCase")]
pub fn set_language(state: State<AppState>, code: String) -> Result<(), String> {
    let Some(canonical) = normalize_language_code(&code) else {
        return Err(format!("Unsupported language code: {}", code.trim()));
    };
    let db = state.db.lock().map_err(|e| e.to_string())?;
    user_setting_put(&db, "language", canonical)?;
    log_event(
        EventKind::SettingsChanged,
        "info",
        None,
        None,
        None,
        Some(serde_json::json!({ "key": "language", "value": canonical })),
        format!("language → {canonical}"),
    );
    Ok(())
}

#[tauri::command(rename_all = "camelCase")]
pub fn get_language(state: State<AppState>) -> Result<Option<String>, String> {
    let db = state.db.lock().map_err(|e| e.to_string())?;
    user_setting_get(&db, "language")
}

#[tauri::command(rename_all = "camelCase")]
pub fn accept_terms(state: State<AppState>) -> Result<(), String> {
    let db = state.db.lock().map_err(|e| e.to_string())?;
    let ts = chrono::Utc::now().to_rfc3339();
    user_setting_put(&db, "terms_accepted_at", &ts)
}

#[tauri::command(rename_all = "camelCase")]
pub fn get_terms_accepted_at(state: State<AppState>) -> Result<Option<String>, String> {
    let db = state.db.lock().map_err(|e| e.to_string())?;
    user_setting_get(&db, "terms_accepted_at")
}

#[tauri::command(rename_all = "camelCase")]
pub fn quit_app(app: tauri::AppHandle) {
    app.exit(0);
}

fn list_event_log_inner(
    state: &AppState,
    limit: u32,
    offset: u32,
    kinds: Option<Vec<String>>,
    search: Option<String>,
    severities: Option<Vec<String>>,
) -> Result<Vec<crate::event_log::EventLogRow>, String> {
    let t0 = std::time::Instant::now();
    crate::diagnostics::log("[ipc:list_event_log] start");
    let result = (|| -> Result<Vec<crate::event_log::EventLogRow>, String> {
        let lock_t0 = std::time::Instant::now();
        crate::diagnostics::log("[ipc:list_event_log] acquiring db lock");
        let db = state.db.lock().map_err(|e| e.to_string())?;
        crate::diagnostics::log(&format!(
            "[ipc:list_event_log] db lock acquired in {}ms",
            lock_t0.elapsed().as_millis()
        ));
        crate::event_log::list_rows(
            &db,
            limit,
            offset,
            kinds.as_deref(),
            search.as_deref(),
            severities.as_deref(),
        )
    })();
    let elapsed = t0.elapsed().as_millis();
    match &result {
        Ok(v) => crate::diagnostics::log(&format!(
            "[ipc:list_event_log] ok in {elapsed}ms (rows={})",
            v.len()
        )),
        Err(e) => {
            crate::diagnostics::log(&format!("[ipc:list_event_log] error in {elapsed}ms: {e}"))
        }
    }
    result
}

fn count_event_log_inner(
    state: &AppState,
    kinds: Option<Vec<String>>,
    search: Option<String>,
    severities: Option<Vec<String>>,
) -> Result<u64, String> {
    let t0 = std::time::Instant::now();
    crate::diagnostics::log("[ipc:count_event_log] start");
    let result = (|| -> Result<u64, String> {
        let db = state.db.lock().map_err(|e| e.to_string())?;
        crate::event_log::count_filtered(
            &db,
            kinds.as_deref(),
            search.as_deref(),
            severities.as_deref(),
        )
    })();
    let elapsed = t0.elapsed().as_millis();
    match &result {
        Ok(v) => crate::diagnostics::log(&format!(
            "[ipc:count_event_log] ok in {elapsed}ms (count={v})"
        )),
        Err(e) => {
            crate::diagnostics::log(&format!("[ipc:count_event_log] error in {elapsed}ms: {e}"))
        }
    }
    result
}

#[tauri::command(rename_all = "camelCase")]
pub async fn list_event_log(
    state: State<'_, AppState>,
    limit: u32,
    offset: u32,
    kinds: Option<Vec<String>>,
    search: Option<String>,
    severities: Option<Vec<String>>,
) -> Result<Vec<crate::event_log::EventLogRow>, String> {
    let st = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        list_event_log_inner(&st, limit, offset, kinds, search, severities)
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command(rename_all = "camelCase")]
pub async fn count_event_log(
    state: State<'_, AppState>,
    kinds: Option<Vec<String>>,
    search: Option<String>,
    severities: Option<Vec<String>>,
) -> Result<u64, String> {
    let st = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        count_event_log_inner(&st, kinds, search, severities)
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command(rename_all = "camelCase")]
pub fn clear_event_log(state: State<AppState>) -> Result<(), String> {
    let db = state.db.lock().map_err(|e| e.to_string())?;
    crate::event_log::clear_table(&db)
}

#[tauri::command(rename_all = "camelCase")]
pub fn get_autostart_enabled(app: tauri::AppHandle) -> Result<bool, String> {
    app.autolaunch().is_enabled().map_err(|e| e.to_string())
}

#[tauri::command(rename_all = "camelCase")]
pub fn set_autostart_enabled(app: tauri::AppHandle, enabled: bool) -> Result<(), String> {
    let manager = app.autolaunch();
    if enabled {
        manager.enable().map_err(|e| e.to_string())?;
    } else {
        manager.disable().map_err(|e| e.to_string())?;
    }
    log_event(
        EventKind::SettingsChanged,
        "info",
        None,
        None,
        None,
        Some(serde_json::json!({ "key": "autostart", "value": enabled })),
        if enabled {
            "Auto-start on boot enabled"
        } else {
            "Auto-start on boot disabled"
        },
    );
    let _ = app.emit("autostart_changed", enabled);
    Ok(())
}

fn list_startup_entries_inner(
    state: &AppState,
) -> Result<Vec<crate::system_surfaces::StartupEntry>, String> {
    let t0 = std::time::Instant::now();
    crate::diagnostics::log("[ipc:list_startup_entries] start");
    let result = crate::startup_items::list_all(state);
    let elapsed = t0.elapsed().as_millis();
    match &result {
        Ok(v) => crate::diagnostics::log(&format!(
            "[ipc:list_startup_entries] ok in {elapsed}ms (rows={})",
            v.len()
        )),
        Err(e) => crate::diagnostics::log(&format!(
            "[ipc:list_startup_entries] error in {elapsed}ms: {e}"
        )),
    }
    result
}

#[tauri::command(rename_all = "camelCase")]
pub async fn list_startup_entries(
    state: State<'_, AppState>,
) -> Result<Vec<crate::system_surfaces::StartupEntry>, String> {
    let st = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || list_startup_entries_inner(&st))
        .await
        .map_err(|e| e.to_string())?
}

fn refresh_startup_entries_inner(
    state: &AppState,
) -> Result<Vec<crate::system_surfaces::StartupEntry>, String> {
    let t0 = std::time::Instant::now();
    crate::diagnostics::log("[ipc:refresh_startup_entries] start");
    let result = crate::startup_items::refresh(state);
    let elapsed = t0.elapsed().as_millis();
    match &result {
        Ok(v) => crate::diagnostics::log(&format!(
            "[ipc:refresh_startup_entries] ok in {elapsed}ms (rows={})",
            v.len()
        )),
        Err(e) => crate::diagnostics::log(&format!(
            "[ipc:refresh_startup_entries] error in {elapsed}ms: {e}"
        )),
    }
    result
}

#[tauri::command(rename_all = "camelCase")]
pub async fn refresh_startup_entries(
    state: State<'_, AppState>,
) -> Result<Vec<crate::system_surfaces::StartupEntry>, String> {
    let st = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || refresh_startup_entries_inner(&st))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command(rename_all = "camelCase")]
pub fn set_startup_entry_enabled(
    state: State<AppState>,
    id: String,
    enabled: bool,
) -> Result<(), String> {
    #[cfg(windows)]
    {
        crate::startup_items::set_enabled(&state, id, enabled)
    }
    #[cfg(not(windows))]
    {
        let _ = (state, id, enabled);
        Ok(())
    }
}

#[tauri::command(rename_all = "camelCase")]
pub fn set_startup_entry_note(
    state: State<AppState>,
    id: String,
    note: Option<String>,
) -> Result<(), String> {
    crate::startup_items::set_note(&state, id, note)
}

fn list_services_inner(
    state: &AppState,
) -> Result<Vec<crate::system_surfaces::ServiceEntry>, String> {
    let t0 = std::time::Instant::now();
    crate::diagnostics::log("[ipc:list_services] start");
    let result = (|| -> Result<Vec<crate::system_surfaces::ServiceEntry>, String> {
        #[cfg(windows)]
        {
            use rusqlite::OptionalExtension;
            let mut rows = crate::services::list_services(state)?;
            let lock_t0 = std::time::Instant::now();
            crate::diagnostics::log("[ipc:list_services] acquiring db lock");
            let db = state.db.lock().map_err(|e| e.to_string())?;
            crate::diagnostics::log(&format!(
                "[ipc:list_services] db lock acquired in {}ms",
                lock_t0.elapsed().as_millis()
            ));
            for row in &mut rows {
                let n: Option<Option<String>> = db
                    .query_row(
                        "SELECT note FROM service_state WHERE service_name = ?1",
                        [&row.name],
                        |r| r.get(0),
                    )
                    .optional()
                    .map_err(|e| e.to_string())?;
                row.note = n.flatten();
            }
            Ok(rows)
        }
        #[cfg(not(windows))]
        {
            Ok(vec![])
        }
    })();
    let elapsed = t0.elapsed().as_millis();
    match &result {
        Ok(v) => crate::diagnostics::log(&format!(
            "[ipc:list_services] ok in {elapsed}ms (rows={})",
            v.len()
        )),
        Err(e) => {
            crate::diagnostics::log(&format!("[ipc:list_services] error in {elapsed}ms: {e}"))
        }
    }
    result
}

#[tauri::command(rename_all = "camelCase")]
pub async fn list_services(
    state: State<'_, AppState>,
) -> Result<Vec<crate::system_surfaces::ServiceEntry>, String> {
    let st = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || list_services_inner(&st))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command(rename_all = "camelCase")]
pub fn set_service_enabled(name: String, enabled: bool) -> Result<(), String> {
    #[cfg(windows)]
    {
        crate::services::set_service_enabled(name, enabled)
    }
    #[cfg(not(windows))]
    {
        let _ = (name, enabled);
        Ok(())
    }
}

#[tauri::command(rename_all = "camelCase")]
pub fn set_service_start_type(name: String, start_type: String) -> Result<(), String> {
    #[cfg(windows)]
    {
        crate::services::set_service_start_type(name, start_type)
    }
    #[cfg(not(windows))]
    {
        let _ = (name, start_type);
        Ok(())
    }
}

#[tauri::command(rename_all = "camelCase")]
pub fn start_service_cmd(name: String) -> Result<(), String> {
    #[cfg(windows)]
    {
        crate::services::start_service_cmd(name)
    }
    #[cfg(not(windows))]
    {
        let _ = name;
        Ok(())
    }
}

#[tauri::command(rename_all = "camelCase")]
pub fn stop_service_cmd(name: String) -> Result<(), String> {
    #[cfg(windows)]
    {
        crate::services::stop_service_cmd(name)
    }
    #[cfg(not(windows))]
    {
        let _ = name;
        Ok(())
    }
}

#[tauri::command(rename_all = "camelCase")]
pub fn set_service_note(
    state: State<AppState>,
    name: String,
    note: Option<String>,
) -> Result<(), String> {
    #[cfg(windows)]
    {
        crate::services::set_service_note(&state, name, note)
    }
    #[cfg(not(windows))]
    {
        let _ = (state, name, note);
        Ok(())
    }
}

#[tauri::command(rename_all = "camelCase")]
pub async fn open_diagnostic_log(app: tauri::AppHandle) -> Result<(), String> {
    let path = crate::app_log::log_path()?;
    use tauri_plugin_opener::OpenerExt;
    app.opener()
        .open_path(path.to_string_lossy(), None::<&str>)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn open_devtools(window: tauri::WebviewWindow) -> Result<(), String> {
    #[cfg(any(debug_assertions, feature = "devtools"))]
    {
        window.open_devtools();
        Ok(())
    }
    #[cfg(not(any(debug_assertions, feature = "devtools")))]
    {
        let _ = window;
        Err("DevTools not available in this build".to_string())
    }
}

pub(crate) fn complete_setup_task(
    app: &tauri::AppHandle,
    setup: &std::sync::Mutex<crate::SetupState>,
    task: &str,
) -> Result<(), String> {
    let mut g = setup.lock().map_err(|e| e.to_string())?;
    match task {
        "frontend" => g.frontend_task = true,
        "backend" => g.backend_task = true,
        _ => return Err(format!("unknown setup task: {task}")),
    }
    let done = g.frontend_task && g.backend_task;
    drop(g);
    if done {
        if let Some(splash) = app.get_webview_window("splash") {
            let _ = splash.close();
        }
        if let Some(main) = app.get_webview_window("main") {
            let _ = main.show();
            let _ = main.set_focus();
        }
    }
    Ok(())
}

#[tauri::command(rename_all = "camelCase")]
pub fn set_complete(
    app: tauri::AppHandle,
    setup: State<std::sync::Mutex<crate::SetupState>>,
    task: String,
) -> Result<(), String> {
    complete_setup_task(&app, setup.inner(), task.trim())
}
