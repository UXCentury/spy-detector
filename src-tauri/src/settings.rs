use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

fn default_bool_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppSettings {
    pub warn_threshold: u8,
    pub alert_threshold: u8,
    pub disabled_signature_tokens: Vec<String>,
    #[serde(default)]
    pub ioc_last_refreshed_at: Option<String>,
    #[serde(default = "default_bool_true")]
    pub amsi_enabled: bool,
    #[serde(default = "default_bool_true")]
    pub yara_enabled: bool,
    #[serde(default = "default_bool_true")]
    pub auto_scan_on_launch: bool,
    #[serde(default = "default_bool_true")]
    pub tray_alerts_enabled: bool,
    #[serde(default)]
    pub diagnostic_logging: bool,
    #[serde(default = "default_bool_true")]
    pub thread_injection_scanner_enabled: bool,
    #[serde(default = "default_bool_true")]
    pub process_etw_enabled: bool,
    #[serde(default = "default_bool_true")]
    pub win32k_etw_enabled: bool,
    #[serde(default = "default_bool_true")]
    pub dns_etw_enabled: bool,
    #[serde(default = "default_bool_true")]
    pub camera_monitor_enabled: bool,
    #[serde(default = "default_bool_true")]
    pub periodic_scan_enabled: bool,
}

pub fn load_app_settings(conn: &Connection) -> Result<AppSettings, String> {
    let wt: String = conn
        .query_row(
            "SELECT value FROM user_settings WHERE key = 'warn_threshold'",
            [],
            |r| r.get(0),
        )
        .map_err(|e| e.to_string())?;
    let at: String = conn
        .query_row(
            "SELECT value FROM user_settings WHERE key = 'alert_threshold'",
            [],
            |r| r.get(0),
        )
        .map_err(|e| e.to_string())?;
    let dis: String = conn
        .query_row(
            "SELECT value FROM user_settings WHERE key = 'disabled_signature_tokens'",
            [],
            |r| r.get(0),
        )
        .map_err(|e| e.to_string())?;
    let ioc_last_refreshed_at = conn
        .query_row(
            "SELECT value FROM user_settings WHERE key = 'ioc_last_refreshed_at'",
            [],
            |r| r.get::<_, String>(0),
        )
        .optional()
        .map_err(|e| e.to_string())?;
    let amsi_enabled = read_amsi_enabled(conn).unwrap_or(true);
    let yara_enabled = read_yara_enabled(conn).unwrap_or(true);
    let auto_scan_on_launch = read_auto_scan_on_launch(conn).unwrap_or(true);
    let tray_alerts_enabled = read_tray_alerts_enabled(conn).unwrap_or(true);
    let diagnostic_logging = read_diagnostic_logging(conn).unwrap_or(false);
    let thread_injection_scanner_enabled =
        read_thread_injection_scanner_enabled(conn).unwrap_or(true);
    let process_etw_enabled = read_process_etw_enabled(conn).unwrap_or(true);
    let win32k_etw_enabled = read_win32k_etw_enabled(conn).unwrap_or(true);
    let dns_etw_enabled = read_dns_etw_enabled(conn).unwrap_or(true);
    let camera_monitor_enabled = read_camera_monitor_enabled(conn).unwrap_or(true);
    let periodic_scan_enabled = read_periodic_scan_enabled(conn).unwrap_or(true);
    Ok(AppSettings {
        warn_threshold: wt.parse().unwrap_or(50),
        alert_threshold: at.parse().unwrap_or(75),
        disabled_signature_tokens: serde_json::from_str(&dis).unwrap_or_default(),
        ioc_last_refreshed_at,
        amsi_enabled,
        yara_enabled,
        auto_scan_on_launch,
        tray_alerts_enabled,
        diagnostic_logging,
        thread_injection_scanner_enabled,
        process_etw_enabled,
        win32k_etw_enabled,
        dns_etw_enabled,
        camera_monitor_enabled,
        periodic_scan_enabled,
    })
}

pub fn save_app_settings(conn: &Connection, s: &AppSettings) -> Result<(), String> {
    conn.execute(
        "UPDATE user_settings SET value = ?1 WHERE key = 'warn_threshold'",
        [s.warn_threshold.to_string()],
    )
    .map_err(|e| e.to_string())?;
    conn.execute(
        "UPDATE user_settings SET value = ?1 WHERE key = 'alert_threshold'",
        [s.alert_threshold.to_string()],
    )
    .map_err(|e| e.to_string())?;
    let dj = serde_json::to_string(&s.disabled_signature_tokens).map_err(|e| e.to_string())?;
    conn.execute(
        "UPDATE user_settings SET value = ?1 WHERE key = 'disabled_signature_tokens'",
        [dj],
    )
    .map_err(|e| e.to_string())?;
    if let Some(ref ts) = s.ioc_last_refreshed_at {
        conn.execute(
            "INSERT OR REPLACE INTO user_settings (key, value) VALUES ('ioc_last_refreshed_at', ?1)",
            [ts.as_str()],
        )
        .map_err(|e| e.to_string())?;
    }
    conn.execute(
        "INSERT OR REPLACE INTO user_settings (key, value) VALUES ('amsi_enabled', ?1)",
        [if s.amsi_enabled { "1" } else { "0" }],
    )
    .map_err(|e| e.to_string())?;
    conn.execute(
        "INSERT OR REPLACE INTO user_settings (key, value) VALUES ('yara_enabled', ?1)",
        [if s.yara_enabled { "1" } else { "0" }],
    )
    .map_err(|e| e.to_string())?;
    conn.execute(
        "INSERT OR REPLACE INTO user_settings (key, value) VALUES ('auto_scan_on_launch', ?1)",
        [if s.auto_scan_on_launch { "1" } else { "0" }],
    )
    .map_err(|e| e.to_string())?;
    conn.execute(
        "INSERT OR REPLACE INTO user_settings (key, value) VALUES ('tray_alerts_enabled', ?1)",
        [if s.tray_alerts_enabled { "1" } else { "0" }],
    )
    .map_err(|e| e.to_string())?;
    conn.execute(
        "INSERT OR REPLACE INTO user_settings (key, value) VALUES ('diagnostic_logging', ?1)",
        [if s.diagnostic_logging { "1" } else { "0" }],
    )
    .map_err(|e| e.to_string())?;
    conn.execute(
        "INSERT OR REPLACE INTO user_settings (key, value) VALUES ('thread_injection_scanner_enabled', ?1)",
        [if s.thread_injection_scanner_enabled {
            "1"
        } else {
            "0"
        }],
    )
    .map_err(|e| e.to_string())?;
    conn.execute(
        "INSERT OR REPLACE INTO user_settings (key, value) VALUES ('process_etw_enabled', ?1)",
        [if s.process_etw_enabled { "1" } else { "0" }],
    )
    .map_err(|e| e.to_string())?;
    conn.execute(
        "INSERT OR REPLACE INTO user_settings (key, value) VALUES ('win32k_etw_enabled', ?1)",
        [if s.win32k_etw_enabled { "1" } else { "0" }],
    )
    .map_err(|e| e.to_string())?;
    conn.execute(
        "INSERT OR REPLACE INTO user_settings (key, value) VALUES ('dns_etw_enabled', ?1)",
        [if s.dns_etw_enabled { "1" } else { "0" }],
    )
    .map_err(|e| e.to_string())?;
    conn.execute(
        "INSERT OR REPLACE INTO user_settings (key, value) VALUES ('camera_monitor_enabled', ?1)",
        [if s.camera_monitor_enabled { "1" } else { "0" }],
    )
    .map_err(|e| e.to_string())?;
    conn.execute(
        "INSERT OR REPLACE INTO user_settings (key, value) VALUES ('periodic_scan_enabled', ?1)",
        [if s.periodic_scan_enabled { "1" } else { "0" }],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

pub fn read_amsi_enabled(conn: &Connection) -> Result<bool, String> {
    let v: Result<String, rusqlite::Error> = conn.query_row(
        "SELECT value FROM user_settings WHERE key = 'amsi_enabled'",
        [],
        |r| r.get(0),
    );
    match v {
        Ok(s) => Ok(s == "1" || s.eq_ignore_ascii_case("true")),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(true),
        Err(e) => Err(e.to_string()),
    }
}

pub fn read_yara_enabled(conn: &Connection) -> Result<bool, String> {
    let v: Result<String, rusqlite::Error> = conn.query_row(
        "SELECT value FROM user_settings WHERE key = 'yara_enabled'",
        [],
        |r| r.get(0),
    );
    match v {
        Ok(s) => Ok(s == "1" || s.eq_ignore_ascii_case("true")),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(true),
        Err(e) => Err(e.to_string()),
    }
}

pub fn read_auto_scan_on_launch(conn: &Connection) -> Result<bool, String> {
    let v: Result<String, rusqlite::Error> = conn.query_row(
        "SELECT value FROM user_settings WHERE key = 'auto_scan_on_launch'",
        [],
        |r| r.get(0),
    );
    match v {
        Ok(s) => Ok(s == "1" || s.eq_ignore_ascii_case("true")),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(true),
        Err(e) => Err(e.to_string()),
    }
}

pub fn read_thread_injection_scanner_enabled(conn: &Connection) -> Result<bool, String> {
    let v: Result<String, rusqlite::Error> = conn.query_row(
        "SELECT value FROM user_settings WHERE key = 'thread_injection_scanner_enabled'",
        [],
        |r| r.get(0),
    );
    match v {
        Ok(s) => Ok(s == "1" || s.eq_ignore_ascii_case("true")),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(true),
        Err(e) => Err(e.to_string()),
    }
}

pub fn read_diagnostic_logging(conn: &Connection) -> Result<bool, String> {
    let v: Result<String, rusqlite::Error> = conn.query_row(
        "SELECT value FROM user_settings WHERE key = 'diagnostic_logging'",
        [],
        |r| r.get(0),
    );
    match v {
        Ok(s) => Ok(s == "1" || s.eq_ignore_ascii_case("true")),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(false),
        Err(e) => Err(e.to_string()),
    }
}

pub fn read_tray_alerts_enabled(conn: &Connection) -> Result<bool, String> {
    let v: Result<String, rusqlite::Error> = conn.query_row(
        "SELECT value FROM user_settings WHERE key = 'tray_alerts_enabled'",
        [],
        |r| r.get(0),
    );
    match v {
        Ok(s) => Ok(s == "1" || s.eq_ignore_ascii_case("true")),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(true),
        Err(e) => Err(e.to_string()),
    }
}

fn read_bool_setting_default_true(conn: &Connection, key: &str) -> Result<bool, String> {
    let v: Result<String, rusqlite::Error> = conn.query_row(
        "SELECT value FROM user_settings WHERE key = ?1",
        [key],
        |r| r.get(0),
    );
    match v {
        Ok(s) => Ok(s == "1" || s.eq_ignore_ascii_case("true")),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(true),
        Err(e) => Err(e.to_string()),
    }
}

pub fn read_process_etw_enabled(conn: &Connection) -> Result<bool, String> {
    read_bool_setting_default_true(conn, "process_etw_enabled")
}

pub fn read_win32k_etw_enabled(conn: &Connection) -> Result<bool, String> {
    read_bool_setting_default_true(conn, "win32k_etw_enabled")
}

pub fn read_dns_etw_enabled(conn: &Connection) -> Result<bool, String> {
    read_bool_setting_default_true(conn, "dns_etw_enabled")
}

pub fn read_camera_monitor_enabled(conn: &Connection) -> Result<bool, String> {
    read_bool_setting_default_true(conn, "camera_monitor_enabled")
}

pub fn read_periodic_scan_enabled(conn: &Connection) -> Result<bool, String> {
    read_bool_setting_default_true(conn, "periodic_scan_enabled")
}

const PERIODIC_SCAN_INTERVAL_KEY: &str = "periodic_scan_interval_secs";
const TRAY_CLOSE_NOTIFIED_KEY: &str = "tray_close_notified";

pub fn read_tray_close_notified(conn: &Connection) -> Result<bool, String> {
    let v: Result<String, rusqlite::Error> = conn.query_row(
        "SELECT value FROM user_settings WHERE key = ?1",
        [TRAY_CLOSE_NOTIFIED_KEY],
        |r| r.get(0),
    );
    match v {
        Ok(s) => Ok(s == "1" || s.eq_ignore_ascii_case("true")),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(false),
        Err(e) => Err(e.to_string()),
    }
}

pub fn write_tray_close_notified(conn: &Connection, notified: bool) -> Result<(), String> {
    let v = if notified { "1" } else { "0" };
    conn.execute(
        "INSERT OR REPLACE INTO user_settings (key, value) VALUES (?1, ?2)",
        rusqlite::params![TRAY_CLOSE_NOTIFIED_KEY, v],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

pub fn read_scan_interval_secs(conn: &Connection) -> Result<u32, String> {
    let v: Result<String, rusqlite::Error> = conn.query_row(
        "SELECT value FROM user_settings WHERE key = ?1",
        [PERIODIC_SCAN_INTERVAL_KEY],
        |r| r.get(0),
    );
    match v {
        Ok(s) => Ok(s.parse::<u32>().unwrap_or(300).clamp(60, 86400)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(300),
        Err(e) => Err(e.to_string()),
    }
}

pub fn write_scan_interval_secs(conn: &Connection, seconds: u32) -> Result<(), String> {
    let clamped = seconds.clamp(60, 86400);
    conn.execute(
        "INSERT OR REPLACE INTO user_settings (key, value) VALUES (?1, ?2)",
        rusqlite::params![PERIODIC_SCAN_INTERVAL_KEY, clamped.to_string()],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

pub fn disabled_token_set(conn: &Connection) -> Result<HashSet<String>, String> {
    let s = load_app_settings(conn)?;
    Ok(s.disabled_signature_tokens
        .into_iter()
        .map(|t| t.trim().to_lowercase())
        .filter(|t| !t.is_empty())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_db() -> Connection {
        let conn = Connection::open_in_memory().expect("open in-memory db");
        crate::db::init_db(&conn).expect("init schema");
        conn
    }

    #[test]
    fn auto_scan_and_tray_alerts_default_true_on_fresh_db() {
        let conn = fresh_db();
        let s = load_app_settings(&conn).expect("load settings");
        assert!(
            s.auto_scan_on_launch,
            "auto_scan_on_launch must default to true"
        );
        assert!(
            s.tray_alerts_enabled,
            "tray_alerts_enabled must default to true"
        );
        assert!(
            s.thread_injection_scanner_enabled,
            "thread_injection_scanner_enabled must default to true"
        );
    }

    #[test]
    fn read_helpers_default_true_when_row_missing() {
        let conn = fresh_db();
        // Remove the seeded rows so we hit the QueryReturnedNoRows arm.
        conn.execute(
            "DELETE FROM user_settings WHERE key IN ('auto_scan_on_launch', 'tray_alerts_enabled')",
            [],
        )
        .unwrap();
        assert!(read_auto_scan_on_launch(&conn).unwrap());
        assert!(read_tray_alerts_enabled(&conn).unwrap());
    }

    #[test]
    fn diagnostic_logging_defaults_false_and_round_trips() {
        let conn = fresh_db();
        assert!(!read_diagnostic_logging(&conn).unwrap());
        let mut s = load_app_settings(&conn).expect("load settings");
        assert!(!s.diagnostic_logging);
        s.diagnostic_logging = true;
        save_app_settings(&conn, &s).expect("save settings");
        assert!(read_diagnostic_logging(&conn).unwrap());
        let reloaded = load_app_settings(&conn).expect("reload settings");
        assert!(reloaded.diagnostic_logging);
    }

    #[test]
    fn save_round_trips_auto_scan_and_tray_alerts() {
        let conn = fresh_db();
        let mut s = load_app_settings(&conn).expect("initial load");
        s.auto_scan_on_launch = false;
        s.tray_alerts_enabled = false;
        save_app_settings(&conn, &s).expect("save settings");

        let reloaded = load_app_settings(&conn).expect("reload settings");
        assert!(!reloaded.auto_scan_on_launch);
        assert!(!reloaded.tray_alerts_enabled);
        assert!(!read_auto_scan_on_launch(&conn).unwrap());
        assert!(!read_tray_alerts_enabled(&conn).unwrap());

        let mut s2 = reloaded;
        s2.auto_scan_on_launch = true;
        s2.tray_alerts_enabled = true;
        save_app_settings(&conn, &s2).expect("re-save settings");
        let reloaded2 = load_app_settings(&conn).expect("reload again");
        assert!(reloaded2.auto_scan_on_launch);
        assert!(reloaded2.tray_alerts_enabled);
    }

    #[test]
    fn thread_injection_scanner_round_trips() {
        let conn = fresh_db();
        let mut s = load_app_settings(&conn).expect("load settings");
        assert!(s.thread_injection_scanner_enabled);
        s.thread_injection_scanner_enabled = false;
        save_app_settings(&conn, &s).expect("save settings");
        assert!(!read_thread_injection_scanner_enabled(&conn).unwrap());
        let reloaded = load_app_settings(&conn).expect("reload");
        assert!(!reloaded.thread_injection_scanner_enabled);
    }

    #[test]
    fn detection_runtime_toggles_default_true_and_round_trip() {
        let conn = fresh_db();
        let s = load_app_settings(&conn).expect("load settings");
        assert!(s.process_etw_enabled);
        assert!(s.win32k_etw_enabled);
        assert!(s.dns_etw_enabled);
        assert!(s.camera_monitor_enabled);
        assert!(s.periodic_scan_enabled);

        let mut s = s;
        s.process_etw_enabled = false;
        s.win32k_etw_enabled = false;
        s.dns_etw_enabled = false;
        s.camera_monitor_enabled = false;
        s.periodic_scan_enabled = false;
        save_app_settings(&conn, &s).expect("save settings");

        assert!(!read_process_etw_enabled(&conn).unwrap());
        assert!(!read_win32k_etw_enabled(&conn).unwrap());
        assert!(!read_dns_etw_enabled(&conn).unwrap());
        assert!(!read_camera_monitor_enabled(&conn).unwrap());
        assert!(!read_periodic_scan_enabled(&conn).unwrap());

        let reloaded = load_app_settings(&conn).expect("reload");
        assert!(!reloaded.process_etw_enabled);
        assert!(!reloaded.win32k_etw_enabled);
        assert!(!reloaded.dns_etw_enabled);
        assert!(!reloaded.camera_monitor_enabled);
        assert!(!reloaded.periodic_scan_enabled);
    }
}
