//! Shared monitoring payloads (`monitoring_tick`, initial IPC snapshot) and tick assembly.

use crate::AppState;
use chrono::Utc;
use serde::Serialize;
use sysinfo::{ProcessesToUpdate, System};

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct MonitoringTick {
    pub at: String,
    pub process_count: u32,
    pub established_connections: u32,
    pub latest_alert_at: Option<String>,
    pub etw_process_active: bool,
    pub etw_win32k_active: bool,
    pub dns_etw_active: bool,
    pub dns_cache_size: u32,
    pub camera_monitor_active: bool,
    /// PIDs currently streaming from a camera-attributed sensor (Media Foundation).
    pub active_camera_pids: Vec<u32>,
    pub elevated: bool,
    pub scan_in_progress: bool,
    pub last_scan_at: Option<String>,
    pub last_scan_max_score: Option<u8>,
    pub recent_launches_5m: u32,
    pub remote_thread_events_5m: u32,
    pub yara_rule_count: u32,
    pub amsi_active: bool,
    pub amsi_detection_count: u32,
    pub yara_source_sets: u32,
    pub abusech_threatfox_count: u32,
    pub abusech_urlhaus_count: u32,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ScanCompletedEvent {
    pub at: String,
    pub findings_count: u32,
    pub max_score: u8,
}

/// Pure assembly of the monitoring tick payload (used by tests and `build_monitoring_tick`).
// internal helper; refactoring to a struct adds boilerplate without behavior change
#[allow(clippy::too_many_arguments)]
pub fn assemble_monitoring_tick(
    at: String,
    process_count: u32,
    established_connections: u32,
    latest_alert_at: Option<String>,
    etw_process_active: bool,
    etw_win32k_active: bool,
    dns_etw_active: bool,
    dns_cache_size: u32,
    camera_monitor_active: bool,
    active_camera_pids: Vec<u32>,
    elevated: bool,
    scan_in_progress: bool,
    last_scan_at: Option<String>,
    last_scan_max_score: Option<u8>,
    recent_launches_5m: u32,
    remote_thread_events_5m: u32,
    yara_rule_count: u32,
    amsi_active: bool,
    amsi_detection_count: u32,
    yara_source_sets: u32,
    abusech_threatfox_count: u32,
    abusech_urlhaus_count: u32,
) -> MonitoringTick {
    MonitoringTick {
        at,
        process_count,
        established_connections,
        latest_alert_at,
        etw_process_active,
        etw_win32k_active,
        dns_etw_active,
        dns_cache_size,
        camera_monitor_active,
        active_camera_pids,
        elevated,
        scan_in_progress,
        last_scan_at,
        last_scan_max_score,
        recent_launches_5m,
        remote_thread_events_5m,
        yara_rule_count,
        amsi_active,
        amsi_detection_count,
        yara_source_sets,
        abusech_threatfox_count,
        abusech_urlhaus_count,
    }
}

pub fn build_monitoring_tick(state: &AppState) -> Result<MonitoringTick, String> {
    let at = chrono::Utc::now().to_rfc3339();

    let mut sys = System::new_all();
    sys.refresh_processes(ProcessesToUpdate::All, true);
    let process_count = sys.processes().len() as u32;

    #[cfg(windows)]
    let established_connections = crate::scan::established_tcp_count();
    #[cfg(not(windows))]
    let established_connections = 0u32;

    let latest_alert_at = state
        .latest_alert_at
        .lock()
        .map_err(|e| e.to_string())?
        .map(|t| t.to_rfc3339());

    #[cfg(windows)]
    let etw_process_active = crate::etw_win::is_running();
    #[cfg(windows)]
    let etw_win32k_active = crate::etw_win32k::is_running();
    #[cfg(windows)]
    let dns_etw_active = crate::etw_dns::is_running();
    #[cfg(windows)]
    let dns_cache_size = crate::etw_dns::cached_count() as u32;
    #[cfg(windows)]
    let camera_monitor_active = crate::camera_win::is_running();

    #[cfg(not(windows))]
    let etw_process_active = false;
    #[cfg(not(windows))]
    let etw_win32k_active = false;
    #[cfg(not(windows))]
    let dns_etw_active = false;
    #[cfg(not(windows))]
    let dns_cache_size = 0u32;
    #[cfg(not(windows))]
    let camera_monitor_active = false;

    #[cfg(windows)]
    let active_camera_pids = crate::camera_win::active_camera_pids();
    #[cfg(not(windows))]
    let active_camera_pids: Vec<u32> = Vec::new();

    let elevated = crate::privilege::is_process_elevated();

    let scan_guard = state.scan_state.lock().map_err(|e| e.to_string())?;
    let scan_in_progress = scan_guard.in_progress;
    let last_scan_at = scan_guard.last_scan_at.clone();
    let last_scan_max_score = scan_guard.last_max_score;

    let since_5m = (Utc::now() - chrono::Duration::minutes(5)).to_rfc3339();
    let db_guard = state.db.lock().map_err(|e| e.to_string())?;
    let recent_launches_5m =
        crate::db::count_process_launches_since(&db_guard, &since_5m).map_err(|e| e.to_string())?;
    let remote_thread_events_5m =
        crate::db::count_thread_events_since(&db_guard, &since_5m).map_err(|e| e.to_string())?;

    let (yara_rule_count, yara_source_sets) = crate::yara_scan::global_index()
        .map_or((0u32, 0u32), |i| {
            (i.rule_count(), i.status().sources.len() as u32)
        });
    #[cfg(windows)]
    let amsi_active = crate::amsi::is_running();
    #[cfg(not(windows))]
    let amsi_active = false;
    #[cfg(windows)]
    let amsi_detection_count = crate::amsi::detection_count().min(u32::MAX as u64) as u32;
    #[cfg(not(windows))]
    let amsi_detection_count = 0u32;

    let abuse_guard = state.abuse_ch.read().map_err(|e| e.to_string())?;
    let tf_on = crate::abuse_ch::source_enabled(&db_guard, "threatfox", true).unwrap_or(true);
    let uh_on = crate::abuse_ch::source_enabled(&db_guard, "urlhaus", true).unwrap_or(true);
    let abusech_threatfox_count = if tf_on {
        abuse_guard.threatfox_indicator_count()
    } else {
        0
    };
    let abusech_urlhaus_count = if uh_on {
        abuse_guard.urlhaus_url_count()
    } else {
        0
    };

    Ok(assemble_monitoring_tick(
        at,
        process_count,
        established_connections,
        latest_alert_at,
        etw_process_active,
        etw_win32k_active,
        dns_etw_active,
        dns_cache_size,
        camera_monitor_active,
        active_camera_pids,
        elevated,
        scan_in_progress,
        last_scan_at,
        last_scan_max_score,
        recent_launches_5m,
        remote_thread_events_5m,
        yara_rule_count,
        amsi_active,
        amsi_detection_count,
        yara_source_sets,
        abusech_threatfox_count,
        abusech_urlhaus_count,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn assemble_monitoring_tick_maps_fields() {
        let tick = assemble_monitoring_tick(
            "2020-01-01T00:00:00Z".into(),
            42,
            7,
            Some("2020-01-02T00:00:00Z".into()),
            true,
            false,
            true,
            128,
            true,
            vec![100, 200],
            false,
            true,
            Some("2019-12-31T12:00:00Z".into()),
            Some(88),
            3,
            9,
            42,
            false,
            7,
            3,
            12,
            34,
        );
        assert_eq!(tick.at, "2020-01-01T00:00:00Z");
        assert_eq!(tick.process_count, 42);
        assert_eq!(tick.established_connections, 7);
        assert_eq!(
            tick.latest_alert_at.as_deref(),
            Some("2020-01-02T00:00:00Z")
        );
        assert!(tick.etw_process_active);
        assert!(!tick.etw_win32k_active);
        assert!(tick.dns_etw_active);
        assert_eq!(tick.dns_cache_size, 128);
        assert!(tick.camera_monitor_active);
        assert_eq!(tick.active_camera_pids, vec![100, 200]);
        assert!(!tick.elevated);
        assert!(tick.scan_in_progress);
        assert_eq!(tick.last_scan_at.as_deref(), Some("2019-12-31T12:00:00Z"));
        assert_eq!(tick.last_scan_max_score, Some(88));
        assert_eq!(tick.recent_launches_5m, 3);
        assert_eq!(tick.remote_thread_events_5m, 9);
        assert_eq!(tick.yara_rule_count, 42);
        assert!(!tick.amsi_active);
        assert_eq!(tick.amsi_detection_count, 7);
        assert_eq!(tick.yara_source_sets, 3);
        assert_eq!(tick.abusech_threatfox_count, 12);
        assert_eq!(tick.abusech_urlhaus_count, 34);
    }
}
