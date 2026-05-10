use crate::system_surfaces::{severity_from_score, ServiceEntry};
use crate::AppState;
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use windows::core::PCWSTR;
use windows::Win32::Foundation::ERROR_MORE_DATA;
use windows::Win32::System::Services::{
    CloseServiceHandle, EnumServicesStatusExW, OpenSCManagerW, ENUM_SERVICE_STATUS_PROCESSW,
    SC_ENUM_PROCESS_INFO, SC_MANAGER_ENUMERATE_SERVICE, SERVICE_STATE_ALL, SERVICE_WIN32,
};
use windows_service::service::{
    ServiceAccess, ServiceConfig, ServiceInfo, ServiceStartType, ServiceState,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

const ADMIN_ERR: &str =
    "Requires administrator. Use 'Restart as administrator' from the title bar.";

const CRITICAL_DENY: &[&str] = &[
    "WinDefend",
    "MpsSvc",
    "EventLog",
    "RpcSs",
    "RpcEptMapper",
    "Schedule",
    "BFE",
    "LanmanServer",
    "LSM",
    "gpsvc",
    "Dhcp",
    "Dnscache",
    "LanmanWorkstation",
];

fn require_elevated() -> Result<(), String> {
    if !crate::privilege::is_process_elevated() {
        return Err(ADMIN_ERR.into());
    }
    Ok(())
}

fn is_critical(name: &str) -> bool {
    CRITICAL_DENY.iter().any(|s| s.eq_ignore_ascii_case(name))
}

unsafe fn pwstr_to_osstring(ptr: *const u16) -> OsString {
    if ptr.is_null() {
        return OsString::new();
    }
    let mut len = 0usize;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    OsString::from_wide(std::slice::from_raw_parts(ptr, len))
}

unsafe fn enumerate_service_names() -> Result<Vec<OsString>, String> {
    let scm = OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_ENUMERATE_SERVICE)
        .map_err(|e| e.to_string())?;
    let mut resume: u32 = 0;
    let mut buf = vec![0u8; 256 * 1024];
    let mut names: Vec<OsString> = Vec::new();
    loop {
        let mut needed: u32 = 0;
        let mut returned: u32 = 0;
        let r = EnumServicesStatusExW(
            scm,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_STATE_ALL,
            Some(&mut buf),
            &mut needed,
            &mut returned,
            Some(&mut resume),
            PCWSTR::null(),
        );
        if let Err(e) = r {
            if e.code().0 as u32 == ERROR_MORE_DATA.0 {
                buf.resize((needed as usize).max(buf.len()) + 8192, 0);
                resume = 0;
                continue;
            }
            let _ = CloseServiceHandle(scm);
            return Err(e.to_string());
        }
        if returned == 0 {
            break;
        }
        let base = buf.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW;
        for i in 0..returned as isize {
            let row = base.offset(i).read_unaligned();
            names.push(pwstr_to_osstring(row.lpServiceName.as_ptr() as *const u16));
        }
        if resume == 0 {
            break;
        }
    }
    let _ = CloseServiceHandle(scm);
    Ok(names)
}

fn start_type_label(st: ServiceStartType) -> String {
    match st {
        ServiceStartType::AutoStart => "AutoStart".into(),
        ServiceStartType::OnDemand => "DemandStart".into(),
        ServiceStartType::Disabled => "Disabled".into(),
        ServiceStartType::BootStart => "BootStart".into(),
        ServiceStartType::SystemStart => "SystemStart".into(),
    }
}

fn state_label(st: ServiceState) -> String {
    match st {
        ServiceState::Running => "Running".into(),
        ServiceState::Stopped => "Stopped".into(),
        ServiceState::Paused => "Paused".into(),
        ServiceState::StartPending => "StartPending".into(),
        ServiceState::StopPending => "StopPending".into(),
        _ => format!("{st:?}"),
    }
}

fn parse_start_type(s: &str) -> Result<ServiceStartType, String> {
    Ok(match s.trim() {
        "AutoStart" => ServiceStartType::AutoStart,
        "DemandStart" => ServiceStartType::OnDemand,
        "Disabled" => ServiceStartType::Disabled,
        "BootStart" => ServiceStartType::BootStart,
        "SystemStart" => ServiceStartType::SystemStart,
        _ => return Err("Invalid start type".into()),
    })
}

fn service_info_with_start(
    cfg: &ServiceConfig,
    name: &OsString,
    st: ServiceStartType,
) -> ServiceInfo {
    ServiceInfo {
        name: name.clone(),
        display_name: cfg.display_name.clone(),
        service_type: cfg.service_type,
        start_type: st,
        error_control: cfg.error_control,
        executable_path: cfg.executable_path.clone(),
        launch_arguments: vec![],
        dependencies: cfg.dependencies.clone(),
        account_name: cfg.account_name.clone(),
        account_password: None,
    }
}

fn is_under_windows_dir(path: &std::path::Path) -> bool {
    let Ok(wd) = std::env::var("WINDIR") else {
        return false;
    };
    let Some(ps) = path.to_str() else {
        return false;
    };
    ps.to_lowercase()
        .starts_with(&wd.to_lowercase().replace('/', "\\"))
}

pub fn list_services(state: &AppState) -> Result<Vec<ServiceEntry>, String> {
    let ioc = state.ioc.read().map_err(|e| e.to_string())?;
    list_services_with_ioc(&ioc)
}

fn list_services_with_ioc(ioc: &crate::ioc::IocIndex) -> Result<Vec<ServiceEntry>, String> {
    let names = unsafe { enumerate_service_names()? };
    let mgr = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::ENUMERATE_SERVICE,
    )
    .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for name_os in names {
        let name_s = name_os.to_string_lossy().to_string();
        let Ok(svc) = mgr.open_service(
            &name_os,
            ServiceAccess::QUERY_CONFIG | ServiceAccess::QUERY_STATUS,
        ) else {
            continue;
        };
        let cfg = match svc.query_config() {
            Ok(c) => c,
            Err(_) => continue,
        };
        let status = match svc.query_status() {
            Ok(s) => s,
            Err(_) => continue,
        };
        let bin = cfg.executable_path.to_string_lossy().to_string();
        let bin_path = std::path::Path::new(&cfg.executable_path);
        let signed = if bin_path.exists() {
            Some(matches!(
                crate::authenticode::is_signed(bin_path),
                crate::authenticode::SignatureStatus::Signed
            ))
        } else {
            None
        };
        let account = cfg
            .account_name
            .as_ref()
            .map(|a| a.to_string_lossy().into_owned());
        let is_ms = is_under_windows_dir(bin_path) && signed == Some(true);
        let exe_stem = bin_path
            .file_stem()
            .and_then(|s| s.to_str())
            .map(crate::ioc::norm_token)
            .unwrap_or_default();
        let bin_l = bin.to_lowercase();
        let ioc_match = ioc.startup_ioc_match(&exe_stem, &bin_l, &name_s.to_lowercase());
        let mut score: u32 = 0;
        let mut reasons = Vec::new();
        if matches!(status.current_state, ServiceState::Running)
            && matches!(cfg.start_type, ServiceStartType::AutoStart)
            && signed == Some(false)
        {
            score = score.saturating_add(40);
            reasons.push("Auto-start service is running unsigned".into());
        }
        if matches!(cfg.start_type, ServiceStartType::AutoStart)
            && crate::authenticode::is_in_user_writable_path(bin_path)
        {
            score = score.saturating_add(35);
            reasons.push("Auto-start service binary in user-writable path".into());
        }
        if let Some(ref ac) = account {
            if ac.to_lowercase().contains("localsystem") && signed == Some(false) {
                score = score.saturating_add(20);
                reasons.push("LocalSystem service with unsigned binary".into());
            }
        }
        if let Some(ref lb) = ioc_match {
            score = score.saturating_add(50);
            reasons.push(format!("IOC match: {lb}"));
        }
        let desc_blank = cfg.display_name.is_empty();
        if desc_blank && signed == Some(false) {
            score = score.saturating_add(10);
        }
        if is_ms && matches!(status.current_state, ServiceState::Running) {
            score = 0;
            reasons.clear();
        }
        let score = score.min(100);
        let severity = severity_from_score(score);
        let crit = is_critical(&name_s);
        let can_disable = !crit && !is_ms;
        out.push(ServiceEntry {
            name: name_s.clone(),
            display_name: cfg.display_name.to_string_lossy().into_owned(),
            description: None,
            status: state_label(status.current_state),
            start_type: start_type_label(cfg.start_type),
            binary_path: Some(bin),
            account,
            signed,
            publisher: None,
            ioc_match,
            score,
            severity,
            reasons,
            can_disable,
            is_microsoft: is_ms,
            is_critical: crit,
            note: None,
        });
    }
    out.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.name.cmp(&b.name)));
    Ok(out)
}

pub fn set_service_note(
    state: &AppState,
    name: String,
    note: Option<String>,
) -> Result<(), String> {
    let conn = state.db.lock().map_err(|e| e.to_string())?;
    let now = chrono::Utc::now().to_rfc3339();
    conn.execute(
        "INSERT INTO service_state (service_name, note, last_observed_at) VALUES (?1, ?2, ?3)
         ON CONFLICT(service_name) DO UPDATE SET note = excluded.note, last_observed_at = excluded.last_observed_at",
        rusqlite::params![name, note, &now],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

pub fn set_service_start_type(name: String, start_type: String) -> Result<(), String> {
    require_elevated()?;
    if is_critical(&name) {
        return Err("Critical Windows service — cannot change start type.".into());
    }
    let st = parse_start_type(&start_type)?;
    let mgr = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::ENUMERATE_SERVICE,
    )
    .map_err(|e| e.to_string())?;
    let svc = mgr
        .open_service(
            OsString::from(name.clone()),
            ServiceAccess::QUERY_CONFIG | ServiceAccess::CHANGE_CONFIG,
        )
        .map_err(|e| e.to_string())?;
    let cfg = svc.query_config().map_err(|e| e.to_string())?;
    let info = service_info_with_start(&cfg, &OsString::from(&name), st);
    svc.change_config(&info).map_err(|e| e.to_string())?;
    crate::event_log::log(
        crate::event_log::EventKind::ServiceStartTypeChanged,
        "low",
        None,
        None,
        None,
        None,
        format!("Service {name} start type -> {start_type}"),
    );
    Ok(())
}

pub fn set_service_enabled(name: String, enabled: bool) -> Result<(), String> {
    require_elevated()?;
    if is_critical(&name) {
        return Err("Critical Windows service — cannot change start type.".into());
    }
    let st = if enabled {
        ServiceStartType::AutoStart
    } else {
        ServiceStartType::Disabled
    };
    set_service_start_type(name, start_type_label(st))
}

pub fn start_service_cmd(name: String) -> Result<(), String> {
    require_elevated()?;
    if is_critical(&name) {
        return Err("Critical Windows service — protected.".into());
    }
    let mgr = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::ENUMERATE_SERVICE,
    )
    .map_err(|e| e.to_string())?;
    let svc = mgr
        .open_service(
            OsString::from(name.clone()),
            ServiceAccess::QUERY_STATUS | ServiceAccess::START,
        )
        .map_err(|e| e.to_string())?;
    svc.start(&[] as &[&std::ffi::OsStr])
        .map_err(|e| e.to_string())?;
    crate::event_log::log(
        crate::event_log::EventKind::ServiceStateChanged,
        "low",
        None,
        None,
        None,
        None,
        format!("Service {name} start requested"),
    );
    Ok(())
}

pub fn stop_service_cmd(name: String) -> Result<(), String> {
    require_elevated()?;
    if is_critical(&name) {
        return Err("Critical Windows service — protected.".into());
    }
    let mgr = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::ENUMERATE_SERVICE,
    )
    .map_err(|e| e.to_string())?;
    let svc = mgr
        .open_service(
            OsString::from(name.clone()),
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP,
        )
        .map_err(|e| e.to_string())?;
    let _ = svc.stop().map_err(|e| e.to_string())?;
    crate::event_log::log(
        crate::event_log::EventKind::ServiceStateChanged,
        "low",
        None,
        None,
        None,
        None,
        format!("Service {name} stop requested"),
    );
    Ok(())
}
