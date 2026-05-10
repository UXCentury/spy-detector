use crate::abuse_ch::AbuseChIndex;
use crate::allowlist;
use crate::beaconing::{BeaconTracker, PeerKey};
use crate::dev_infra::DevInfraIndex;
use crate::event_log::{log as log_event, EventKind};
use crate::ioc::IocIndex;
use crate::ip_feeds::IpFeedIndex;
use crate::score;
use rusqlite::Connection;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::Instant;
use sysinfo::{Pid, System};

#[cfg(windows)]
use netstat2::{get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, TcpState};

const WEIGHT_NETWORK_IOC: u8 = 30;
const WEIGHT_BEACONING: u8 = 20;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub pid: u32,
    pub name: String,
    pub exe_path: Option<String>,
    pub score: u8,
    pub reasons: Vec<String>,
    pub suspicious_image_loads: u32,
    #[serde(default)]
    pub ignored: bool,
    #[serde(default)]
    pub authenticode_signed: Option<bool>,
}

pub const SCAN_BUSY_ERR: &str = "scan_already_running";

fn lolbin_process(name: &str) -> bool {
    matches!(
        name.to_lowercase().as_str(),
        "powershell.exe"
            | "pwsh.exe"
            | "cmd.exe"
            | "wscript.exe"
            | "cscript.exe"
            | "mshta.exe"
            | "regsvr32.exe"
            | "rundll32.exe"
            | "certutil.exe"
            | "bitsadmin.exe"
            | "curl.exe"
            | "wget.exe"
            | "installutil.exe"
            | "msbuild.exe"
            | "dotnet.exe"
    )
}

// internal helper; refactoring to a struct adds boilerplate without behavior change
#[allow(clippy::too_many_arguments)]
pub fn execute_scan_with_state(
    ioc: &IocIndex,
    ip_feeds: &IpFeedIndex,
    abuse_ch: &AbuseChIndex,
    dev_infra: &DevInfraIndex,
    conn: &mut Connection,
    beacons: &mut BeaconTracker,
    scan_state: &std::sync::Mutex<crate::ScanState>,
    trigger: &str,
) -> Result<Vec<Finding>, String> {
    {
        let mut g = scan_state.lock().map_err(|e| e.to_string())?;
        if g.in_progress {
            return Err(SCAN_BUSY_ERR.into());
        }
        g.in_progress = true;
    }

    let result = execute_scan(ioc, ip_feeds, abuse_ch, dev_infra, conn, beacons, trigger);

    let mut g = scan_state.lock().map_err(|e| e.to_string())?;
    g.in_progress = false;
    if let Ok(ref findings) = result {
        g.last_scan_at = Some(chrono::Utc::now().to_rfc3339());
        g.last_max_score = findings
            .iter()
            .filter(|f| !f.ignored)
            .map(|f| f.score)
            .max();
    }

    result
}

pub fn execute_scan(
    ioc: &IocIndex,
    ip_feeds: &IpFeedIndex,
    abuse_ch: &AbuseChIndex,
    dev_infra: &DevInfraIndex,
    conn: &mut Connection,
    beacons: &mut BeaconTracker,
    trigger: &str,
) -> Result<Vec<Finding>, String> {
    log_event(
        EventKind::ScanStarted,
        "info",
        None,
        None,
        None,
        Some(serde_json::json!({ "trigger": trigger })),
        "Scan started",
    );

    let started = chrono::Utc::now().to_rfc3339();

    let mut sys = System::new_all();
    sys.refresh_cpu_usage();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
    std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);
    sys.refresh_cpu_usage();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);

    let disabled = crate::settings::disabled_token_set(conn)?;
    let yara_on = crate::settings::read_yara_enabled(conn).unwrap_or(true);

    let mut feed_scan_matches: Vec<(String, String)> = Vec::new();
    let mut feed_scan_keys: HashSet<String> = HashSet::new();
    let mut abuse_ch_match_details: Vec<serde_json::Value> = Vec::new();

    let endpoint_pairs = pid_remote_endpoints().unwrap_or_default();
    let mut endpoints: HashMap<u32, Vec<IpAddr>> = HashMap::new();
    let now = Instant::now();
    for (pid, peer_ip, peer_port) in &endpoint_pairs {
        endpoints.entry(*pid).or_default().push(*peer_ip);
        beacons.observe(
            PeerKey {
                pid: *pid,
                ip: *peer_ip,
                port: *peer_port,
            },
            now,
        );
    }
    beacons.prune_older_than(std::time::Duration::from_secs(24 * 3600), now);

    #[cfg(windows)]
    let mic_paths = crate::mic_win::paths_with_active_microphone();
    #[cfg(not(windows))]
    let mic_paths = HashSet::<String>::new();

    #[cfg(windows)]
    let cam_pids: HashSet<u32> = crate::camera_win::active_camera_pids()
        .into_iter()
        .collect();
    #[cfg(not(windows))]
    let cam_pids = HashSet::<u32>::new();

    #[cfg(windows)]
    let visible_pids: HashSet<u32> = crate::window_enum::pids_with_visible_window();
    #[cfg(not(windows))]
    let visible_pids = HashSet::<u32>::new();

    #[cfg(windows)]
    let autostart_diff = crate::autostart::snapshot_and_diff(conn).map_err(|e| e.to_string())?;

    let mut findings: Vec<Finding> = Vec::new();

    for (pid, proc_) in sys.processes() {
        let pid_u = pid_as_u32(*pid);
        let name = proc_.name().to_string_lossy().into_owned();
        let exe_path = proc_
            .exe()
            .map(|p| p.to_string_lossy().into_owned())
            .filter(|s| !s.is_empty());
        let cpu_pct = proc_.cpu_usage();

        let trusted =
            allowlist::is_trusted(conn, exe_path.as_deref()).map_err(|e| e.to_string())?;
        if trusted {
            findings.push(Finding {
                pid: pid_u,
                name,
                exe_path,
                score: 0,
                reasons: vec![],
                suspicious_image_loads: 0,
                ignored: true,
                authenticode_signed: None,
            });
            continue;
        }

        let (mut score, mut reasons) =
            score::signature_signals(ioc, &name, exe_path.as_deref(), &disabled);
        let mut seen_reasons: HashSet<String> = reasons.iter().cloned().collect();

        if let Some(peer_ips) = endpoints.get(&pid_u) {
            let mut net_points_applied = false;
            let mut max_feed_net_weight: u8 = 0;
            let allow_dns = peer_ips.len() <= 32;
            for ip in peer_ips {
                if ip.is_loopback() || ip.is_unspecified() {
                    continue;
                }
                if ioc.ips.contains(ip) {
                    let ip_flag = format!("net:{ip}").to_lowercase();
                    if disabled.contains(&ip_flag) {
                        continue;
                    }
                    if !net_points_applied {
                        score = score.saturating_add(WEIGHT_NETWORK_IOC).min(100);
                        net_points_applied = true;
                    }
                    let msg = format!("Established TCP peer matches IOC IP ({ip})");
                    if seen_reasons.insert(msg.clone()) {
                        reasons.push(msg);
                    }
                    continue;
                }
                let ip_flag = format!("net:{ip}").to_lowercase();
                if !disabled.contains(&ip_flag) {
                    if let Some(hit) = ip_feeds.match_ip(*ip) {
                        max_feed_net_weight = max_feed_net_weight.max(hit.score_weight);
                        let msg = format!(
                            "IP feed match: {} ({}) — {}",
                            hit.label, hit.category_slug, ip
                        );
                        if seen_reasons.insert(msg.clone()) {
                            reasons.push(msg);
                        }
                        let k = format!("{}|{}", hit.slug, ip);
                        if feed_scan_keys.insert(k.clone()) {
                            feed_scan_matches.push((hit.slug.to_string(), ip.to_string()));
                        }
                        continue;
                    }
                }
                if allow_dns && reasons.len() < 64 {
                    #[cfg(windows)]
                    let etw_host = crate::etw_dns::lookup_host_for_ip(ip);
                    #[cfg(not(windows))]
                    let etw_host: Option<String> = None;
                    let rev_host = dns_lookup::lookup_addr(ip).ok().map(|s| s.to_lowercase());
                    let host_for_lolbin = etw_host.clone().or_else(|| rev_host.clone());

                    let mut ioc_handled = false;
                    if let Some(ref eh) = etw_host {
                        if let Some(dom) = ioc.host_matches_domain(eh) {
                            let dom_flag = format!("net:{dom}");
                            if disabled.contains(&dom_flag) {
                                // fall through to reverse-DNS path
                            } else {
                                ioc_handled = true;
                                if !net_points_applied {
                                    score = score.saturating_add(WEIGHT_NETWORK_IOC).min(100);
                                    net_points_applied = true;
                                }
                                let rev_misses = rev_host
                                    .as_ref()
                                    .and_then(|h| ioc.host_matches_domain(h))
                                    .is_none();
                                let msg = if rev_misses {
                                    format!(
                                        "DNS ETW resolved {eh} for peer {ip} matches IOC domain ({dom}); reverse DNS did not expose this hostname"
                                    )
                                } else {
                                    format!(
                                        "DNS ETW resolved hostname for peer {ip} matches IOC domain ({dom}; {eh})"
                                    )
                                };
                                if seen_reasons.insert(msg.clone()) {
                                    reasons.push(msg);
                                }
                            }
                        }
                    }
                    if !ioc_handled {
                        if let Some(ref rh) = rev_host {
                            if let Some(dom) = ioc.host_matches_domain(rh) {
                                let dom_flag = format!("net:{dom}");
                                if disabled.contains(&dom_flag) {
                                    // no IOC domain credit
                                } else {
                                    if !net_points_applied {
                                        score = score.saturating_add(WEIGHT_NETWORK_IOC).min(100);
                                        net_points_applied = true;
                                    }
                                    let msg = format!(
                                        "Reverse DNS for peer {ip} matches IOC domain ({dom}; {rh})"
                                    );
                                    if seen_reasons.insert(msg.clone()) {
                                        reasons.push(msg);
                                    }
                                }
                            }
                        }
                    }
                    if reasons.len() < 64 {
                        if let Some(ref host_l) = host_for_lolbin {
                            if let Some(cat) =
                                crate::dev_infra::lolbin_dns_staging_hit(host_l, dev_infra)
                            {
                                if lolbin_process(&name) {
                                    let msg = format!(
                                        "LOLBin {} connected to {} ({})",
                                        name, cat, host_l
                                    );
                                    if seen_reasons.insert(msg.clone()) {
                                        score = score.saturating_add(35).min(100);
                                        reasons.push(msg);
                                    }
                                }
                            }
                        }
                    }
                }
                let ip_flag_ab = format!("net:{ip}").to_lowercase();
                if !disabled.contains(&ip_flag_ab) {
                    if let Some(rec) = abuse_ch.match_ip(ip) {
                        score = score.saturating_add(25).min(100);
                        let msg = AbuseChIndex::format_match_reason(rec);
                        if seen_reasons.insert(msg.clone()) {
                            reasons.push(msg);
                        }
                        if abuse_ch_match_details.len() < 80 {
                            abuse_ch_match_details.push(serde_json::json!({
                                "kind": "ip",
                                "pid": pid_u,
                                "ip": ip.to_string(),
                                "source": rec.source.slug(),
                            }));
                        }
                    }
                    if allow_dns && reasons.len() < 96 {
                        #[cfg(windows)]
                        let etw_ab = crate::etw_dns::lookup_host_for_ip(ip);
                        #[cfg(not(windows))]
                        let etw_ab: Option<String> = None;
                        let rev_ab = dns_lookup::lookup_addr(ip).ok().map(|s| s.to_lowercase());
                        let mut seen_ab_hosts: HashSet<String> = HashSet::new();
                        for h in [etw_ab, rev_ab].into_iter().flatten() {
                            let hn = h.trim_end_matches('.').to_lowercase();
                            if !seen_ab_hosts.insert(hn.clone()) {
                                continue;
                            }
                            if let Some(rec) = abuse_ch.match_host(&hn) {
                                score = score.saturating_add(25).min(100);
                                let msg = AbuseChIndex::format_match_reason(rec);
                                if seen_reasons.insert(msg.clone()) {
                                    reasons.push(msg);
                                }
                                if abuse_ch_match_details.len() < 80 {
                                    abuse_ch_match_details.push(serde_json::json!({
                                        "kind": "host",
                                        "pid": pid_u,
                                        "host": hn,
                                        "source": rec.source.slug(),
                                    }));
                                }
                            }
                        }
                    }
                }
            }
            if max_feed_net_weight > 0 {
                score = score.saturating_add(max_feed_net_weight).min(100);
            }
        }

        let pid_beacons: Vec<PeerKey> = beacons.keys_for_pid(pid_u).copied().collect();
        let mut beacon_points_applied = false;
        for key in &pid_beacons {
            if let Some(hit) = beacons.evaluate(key) {
                if !beacon_points_applied {
                    score = score.saturating_add(WEIGHT_BEACONING).min(100);
                    beacon_points_applied = true;
                }
                let msg = format!(
                    "Beaconing pattern to {}:{} (mean ~{:.0}s, jitter {:.2})",
                    hit.key.ip, hit.key.port, hit.mean_secs, hit.jitter
                );
                if seen_reasons.insert(msg.clone()) {
                    reasons.push(msg);
                }
            }
        }

        #[cfg(windows)]
        {
            if let Some(ref ep) = exe_path {
                let el = ep.to_lowercase();
                if crate::mic_win::exe_matches_active_mic(&el, &mic_paths) {
                    score = score.saturating_add(25).min(100);
                    reasons
                        .push("Microphone consent store reports active use (NonPackaged)".into());
                }
            }
            if cam_pids.contains(&pid_u) {
                score = score.saturating_add(25).min(100);
                reasons.push(
                    "Camera sensor activity attributed to this PID (Media Foundation)".into(),
                );
            }

            if let Some(ref ep) = exe_path {
                let exe_p = std::path::Path::new(ep);
                if !crate::authenticode::is_system_protected_path(exe_p)
                    && crate::authenticode::is_in_user_writable_path(exe_p)
                    && matches!(
                        crate::authenticode::is_signed(exe_p),
                        crate::authenticode::SignatureStatus::Unsigned
                    )
                {
                    score = score.saturating_add(10).min(100);
                    reasons.push("Unsigned binary in user-writable path".into());
                    if yara_on {
                        if let Some(idx) = crate::yara_scan::global_index() {
                            match idx.match_path(exe_p) {
                                Ok(matches) if !matches.is_empty() => {
                                    let n = matches.len() as u8;
                                    let add = n.saturating_mul(40).min(60);
                                    score = score.saturating_add(add).min(100);
                                    for m in &matches {
                                        let msg =
                                            format!("YARA: {} ({})", m.rule_name, m.source_file);
                                        if seen_reasons.insert(msg.clone()) {
                                            reasons.push(msg);
                                        }
                                    }
                                    log_event(
                                        EventKind::YaraMatch,
                                        "info",
                                        Some(pid_u),
                                        Some(name.clone()),
                                        exe_path.clone(),
                                        Some(serde_json::json!({
                                            "rules": matches.iter().map(|m| serde_json::json!({
                                                "rule": m.rule_name,
                                                "source": m.source_file,
                                            })).collect::<Vec<_>>(),
                                        })),
                                        format!("YARA matched {} rule(s) on {}", matches.len(), ep),
                                    );
                                }
                                Err(e) => {
                                    eprintln!("spy-detector: YARA scan failed for {ep}: {e}");
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }

            let has_net = endpoints
                .get(&pid_u)
                .map(|v| !v.is_empty())
                .unwrap_or(false);
            if has_net && !visible_pids.contains(&pid_u) {
                score = score.saturating_add(10).min(100);
                reasons.push("Process has network activity but no visible window".into());
            }

            if let Some(ref ep) = exe_path {
                let key = ep.to_lowercase();
                if autostart_diff.existing.contains(&key) {
                    if autostart_diff.new_in_last_24h.contains(&key) {
                        score = score.saturating_add(15).min(100);
                        reasons.push("Recently added to autostart (within last 24h)".into());
                    } else {
                        score = score.saturating_add(5).min(100);
                        reasons.push("Configured to auto-start".into());
                    }
                }
            }

            if crate::etw_win32k::recent_hook_install(pid_u) {
                score = score.saturating_add(15).min(100);
                reasons.push("Recently installed a keyboard/mouse hook (ETW Win32k)".into());
            }

            let clip_n = crate::etw_win32k::clipboard_opens_last_60s(pid_u);
            if clip_n >= 10 {
                score = score.saturating_add(15).min(100);
                reasons.push(format!(
                    "Polling clipboard at high frequency ({clip_n} opens/min)"
                ));
            }

            let susp_img = crate::etw_win::suspicious_image_loads(pid_u);
            if susp_img >= 1 {
                score = score.saturating_add(10).min(100);
                reasons.push(format!(
                    "{susp_img} suspicious DLL loads observed (ETW image-load)"
                ));
            }

            if let Some(epath) = exe_path.as_deref().map(std::path::Path::new) {
                if let Some(bonus) = crate::screen_capture::silent_capture_bonus(
                    pid_u,
                    proc_,
                    Some(epath),
                    &visible_pids,
                    cpu_pct,
                ) {
                    score = score.saturating_add(bonus).min(100);
                    reasons.push(
                        "Possible silent screen-capture process (hidden, unsigned, sustained CPU)"
                            .into(),
                    );
                }
            }
        }

        if let Some(ppid) = proc_.parent() {
            if let Some(pa) = sys.process(ppid) {
                let pname = pa.name().to_string_lossy();
                if let Some(msg) = crate::process_tree::anomaly_reason(&pname, &name) {
                    score = score.saturating_add(15).min(100);
                    reasons.push(msg.to_string());
                }
            }
        }

        if score > 0 {
            #[cfg(windows)]
            let susp_img = crate::etw_win::suspicious_image_loads(pid_u);
            #[cfg(not(windows))]
            let susp_img = 0u32;
            #[cfg(windows)]
            let authenticode_signed = exe_path.as_deref().and_then(|ep| {
                let p = std::path::Path::new(ep);
                match crate::authenticode::is_signed(p) {
                    crate::authenticode::SignatureStatus::Signed => Some(true),
                    crate::authenticode::SignatureStatus::Unsigned => Some(false),
                    crate::authenticode::SignatureStatus::Unknown => None,
                }
            });
            #[cfg(not(windows))]
            let authenticode_signed: Option<bool> = None;
            findings.push(Finding {
                pid: pid_u,
                name,
                exe_path,
                score,
                reasons,
                suspicious_image_loads: susp_img,
                ignored: false,
                authenticode_signed,
            });
        }
    }

    findings.sort_by(|a, b| {
        (a.ignored as u8)
            .cmp(&(b.ignored as u8))
            .then_with(|| b.score.cmp(&a.score))
            .then_with(|| a.name.cmp(&b.name))
    });

    if !feed_scan_matches.is_empty() {
        log_event(
            EventKind::IpFeedMatch,
            "info",
            None,
            None,
            None,
            Some(serde_json::json!({
                "matches": feed_scan_matches.iter().map(|(slug, ip)| {
                    serde_json::json!({ "slug": slug, "ip": ip })
                }).collect::<Vec<_>>()
            })),
            format!(
                "IP feed matches during scan ({} hits)",
                feed_scan_matches.len()
            ),
        );
    }

    if !abuse_ch_match_details.is_empty() {
        log_event(
            EventKind::AbuseChMatch,
            "info",
            None,
            None,
            None,
            Some(serde_json::json!({ "matches": abuse_ch_match_details })),
            format!(
                "abuse.ch matches during scan ({} hits)",
                abuse_ch_match_details.len()
            ),
        );
    }

    let tx = conn.transaction().map_err(|e| e.to_string())?;
    tx.execute(
        "INSERT INTO scans (started_at, finished_at) VALUES (?1, ?1)",
        [&started],
    )
    .map_err(|e| e.to_string())?;
    let scan_id = tx.last_insert_rowid();
    for f in &findings {
        let reasons_json = serde_json::to_string(&f.reasons).map_err(|e| e.to_string())?;
        tx.execute(
            "INSERT INTO findings (scan_id, pid, name, exe_path, score, reasons, suspicious_image_loads) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                scan_id,
                f.pid as i64,
                f.name,
                f.exe_path,
                f.score as i64,
                reasons_json,
                f.suspicious_image_loads as i64,
            ],
        )
        .map_err(|e| e.to_string())?;
    }
    let finished = chrono::Utc::now().to_rfc3339();
    tx.execute(
        "UPDATE scans SET finished_at = ?1 WHERE id = ?2",
        rusqlite::params![finished, scan_id],
    )
    .map_err(|e| e.to_string())?;
    tx.commit().map_err(|e| e.to_string())?;

    let risk_relevant: Vec<&Finding> = findings.iter().filter(|f| !f.ignored).collect();
    let max_score = risk_relevant.iter().map(|f| f.score).max().unwrap_or(0);
    log_event(
        EventKind::ScanCompleted,
        "info",
        None,
        None,
        None,
        Some(serde_json::json!({
            "findingsCount": risk_relevant.len(),
            "maxScore": max_score,
            "trigger": trigger,
        })),
        format!("Scan completed ({} finding rows)", findings.len()),
    );

    for f in &findings {
        if f.score >= 50 && !f.ignored {
            log_event(
                EventKind::FindingNew,
                "high",
                Some(f.pid),
                Some(f.name.clone()),
                f.exe_path.clone(),
                Some(serde_json::json!({ "reasons": f.reasons, "score": f.score })),
                format!("{} score {}", f.name, f.score),
            );
        }
    }

    Ok(findings)
}

fn pid_as_u32(pid: Pid) -> u32 {
    pid.as_u32()
}

#[cfg(windows)]
fn pid_remote_endpoints() -> Result<Vec<(u32, IpAddr, u16)>, String> {
    let sockets = get_sockets_info(
        AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6,
        ProtocolFlags::TCP | ProtocolFlags::UDP,
    )
    .map_err(|e| e.to_string())?;

    let mut out: Vec<(u32, IpAddr, u16)> = Vec::new();
    for s in sockets {
        if let ProtocolSocketInfo::Tcp(t) = &s.protocol_socket_info {
            if t.state != TcpState::Established {
                continue;
            }
            let ip = t.remote_addr;
            if ip.is_unspecified() || ip.is_loopback() {
                continue;
            }
            for pid in &s.associated_pids {
                out.push((*pid, ip, t.remote_port));
            }
        }
    }
    Ok(out)
}

#[cfg(not(windows))]
fn pid_remote_endpoints() -> Result<Vec<(u32, IpAddr, u16)>, String> {
    Ok(Vec::new())
}

/// Established TCP remote peers: PID, remote IP, remote port (Windows only; empty elsewhere).
pub fn established_tcp_peers() -> Vec<(u32, IpAddr, u16)> {
    pid_remote_endpoints().unwrap_or_default()
}

/// Number of established TCP sockets (remote ends); cheap aggregate for heartbeat UI.
pub fn established_tcp_count() -> u32 {
    pid_remote_endpoints().map(|v| v.len() as u32).unwrap_or(0)
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanHistoryRow {
    pub at: String,
    pub count: u32,
    pub max_score: u32,
}

pub fn load_scan_history(conn: &Connection, limit: u32) -> Result<Vec<ScanHistoryRow>, String> {
    let lim = (limit as i64).clamp(1, 500);
    let mut stmt = conn
        .prepare(
            "SELECT s.finished_at, COUNT(f.id) AS cnt, COALESCE(MAX(f.score), 0) AS mx
             FROM scans s
             LEFT JOIN findings f ON f.scan_id = s.id
             GROUP BY s.id
             ORDER BY s.id DESC
             LIMIT ?1",
        )
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([lim], |r| {
            Ok(ScanHistoryRow {
                at: r.get(0)?,
                count: r.get::<_, i64>(1)? as u32,
                max_score: r.get::<_, i64>(2)? as u32,
            })
        })
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|e| e.to_string())?);
    }
    Ok(out)
}

pub fn load_latest_findings(conn: &Connection) -> Result<Option<Vec<Finding>>, String> {
    let scan_id: Result<i64, rusqlite::Error> =
        conn.query_row("SELECT id FROM scans ORDER BY id DESC LIMIT 1", [], |row| {
            row.get(0)
        });
    let scan_id = match scan_id {
        Ok(id) => id,
        Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };
    let mut stmt = conn
        .prepare(
            "SELECT pid, name, exe_path, score, reasons, suspicious_image_loads FROM findings WHERE scan_id = ?1 ORDER BY score DESC, name ASC",
        )
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([scan_id], |r| {
            let reasons_s: String = r.get(4)?;
            let reasons: Vec<String> = serde_json::from_str(&reasons_s).unwrap_or_default();
            let susp: i64 = r.get(5).unwrap_or(0);
            Ok(Finding {
                pid: r.get::<_, i64>(0)? as u32,
                name: r.get(1)?,
                exe_path: r.get(2)?,
                score: r.get::<_, i64>(3)? as u8,
                reasons,
                suspicious_image_loads: susp as u32,
                ignored: false,
                authenticode_signed: None,
            })
        })
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|e| e.to_string())?);
    }
    for f in &mut out {
        let trusted =
            allowlist::is_trusted(conn, f.exe_path.as_deref()).map_err(|e| e.to_string())?;
        if trusted {
            f.ignored = true;
            f.score = 0;
            f.reasons.clear();
        }
    }
    #[cfg(windows)]
    for f in &mut out {
        if let Some(ep) = f.exe_path.as_deref() {
            let p = std::path::Path::new(ep);
            f.authenticode_signed = match crate::authenticode::is_signed(p) {
                crate::authenticode::SignatureStatus::Signed => Some(true),
                crate::authenticode::SignatureStatus::Unsigned => Some(false),
                crate::authenticode::SignatureStatus::Unknown => None,
            };
        }
    }
    out.sort_by(|a, b| {
        (a.ignored as u8)
            .cmp(&(b.ignored as u8))
            .then_with(|| b.score.cmp(&a.score))
            .then_with(|| a.name.cmp(&b.name))
    });
    Ok(Some(out))
}
