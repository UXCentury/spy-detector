//! ETW consumer for `Microsoft-Windows-DNS-Client` (`{1c95126e-7eea-49a9-a3fe-a378b03ddb4d}`).
//!
//! Event **3008** records completed DNS queries with `QueryName`, `QueryStatus`, and `QueryResults`
//! (addresses as a semicolon-separated list). User-session resolutions are typically visible **without
//! admin**; some kernel-mode or cross-session resolutions may require elevation — subscription failures
//! are handled without panicking.

use crate::etw_win::EtwCallback;
use crate::event_log::{log as log_event, EventKind};
use ferrisetw::native::EvntraceNativeError;
use ferrisetw::parser::Parser;
use ferrisetw::provider::{EventFilter, Provider};
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::{TraceError, UserTrace};
use ferrisetw::EventRecord;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const DNS_CLIENT_GUID: &str = "1c95126e-7eea-49a9-a3fe-a378b03ddb4d";
const EVT_QUERY_COMPLETED: u16 = 3008;
const KW_ANY: u64 = !0u64;

pub static DNS_ETW_ACTIVE: AtomicBool = AtomicBool::new(false);

static DNS_ETW_ENABLED: AtomicBool = AtomicBool::new(true);

pub fn set_dns_etw_enabled(enabled: bool) {
    DNS_ETW_ENABLED.store(enabled, Ordering::Relaxed);
}

pub fn is_dns_etw_enabled() -> bool {
    DNS_ETW_ENABLED.load(Ordering::Relaxed)
}

static FIRST_ACTIVE_EVENT_LOGGED: AtomicBool = AtomicBool::new(false);
static EVENT_COUNTER: AtomicUsize = AtomicUsize::new(0);
const PRUNE_EVERY_N_EVENTS: usize = 256;

#[derive(Debug, Clone)]
struct CachedHostname {
    host: String,
    seen_at: Instant,
}

static DNS_CACHE: Lazy<Mutex<HashMap<IpAddr, CachedHostname>>> =
    Lazy::new(|| Mutex::new(HashMap::with_capacity(2048)));

const ENTRY_TTL: Duration = Duration::from_secs(30 * 60);
const MAX_ENTRIES: usize = 4096;

pub fn is_running() -> bool {
    DNS_ETW_ACTIVE.load(Ordering::Relaxed)
}

pub fn lookup_host_for_ip(ip: &IpAddr) -> Option<String> {
    let cache = DNS_CACHE.lock().ok()?;
    let ent = cache.get(ip)?;
    if Instant::now().duration_since(ent.seen_at) > ENTRY_TTL {
        return None;
    }
    Some(ent.host.clone())
}

pub fn cached_count() -> usize {
    DNS_CACHE.lock().map(|c| c.len()).unwrap_or(0)
}

pub fn clear_cache() {
    if let Ok(mut g) = DNS_CACHE.lock() {
        g.clear();
    }
}

fn normalize_query_name(raw: &str) -> String {
    let s = raw.trim().trim_end_matches('.').to_lowercase();
    if s.is_empty() {
        return String::new();
    }
    s
}

fn parse_query_results(raw: &str) -> Vec<IpAddr> {
    let mut out = Vec::new();
    for part in raw.split(';') {
        let t = part.trim();
        if t.is_empty() {
            continue;
        }
        let ip_part = t.split('%').next().unwrap_or(t).trim();
        if let Ok(ip) = ip_part.parse::<IpAddr>() {
            out.push(ip);
        }
    }
    out
}

fn prune_cache(cache: &mut HashMap<IpAddr, CachedHostname>) {
    let now = Instant::now();
    cache.retain(|_, v| now.duration_since(v.seen_at) <= ENTRY_TTL);
    while cache.len() > MAX_ENTRIES {
        let oldest = cache.iter().min_by_key(|(_, v)| v.seen_at).map(|(k, _)| *k);
        match oldest {
            Some(k) => {
                cache.remove(&k);
            }
            None => break,
        }
    }
}

fn insert_dns_mapping(host_norm: String, ips: &[IpAddr]) {
    if host_norm.is_empty() || ips.is_empty() {
        return;
    }
    let now = Instant::now();
    let Ok(mut cache) = DNS_CACHE.lock() else {
        return;
    };
    for ip in ips {
        cache.insert(
            *ip,
            CachedHostname {
                host: host_norm.clone(),
                seen_at: now,
            },
        );
    }
    let n = EVENT_COUNTER.fetch_add(1, Ordering::Relaxed) + 1;
    if n.is_multiple_of(PRUNE_EVERY_N_EVENTS) || cache.len() > MAX_ENTRIES {
        prune_cache(&mut cache);
    }
}

pub fn spawn_dns_monitor(_app: tauri::AppHandle) {
    if !crate::privilege::is_process_elevated() {
        eprintln!(
            "spy-detector: DNS-Client ETW running non-elevated; user-session DNS is visible; some system resolutions may be missing"
        );
    }

    tauri::async_runtime::spawn(async move {
        let _ = tokio::task::spawn_blocking(run_dns_loop).await;
    });
}

fn run_dns_loop() {
    let session = format!("spy-detector-dns-{}", std::process::id());

    let cb: EtwCallback = Arc::new(Mutex::new(Box::new(
        move |record: &EventRecord, locator: &SchemaLocator| {
            if record.event_id() != EVT_QUERY_COMPLETED {
                return;
            }
            let Ok(schema) = locator.event_schema(record) else {
                return;
            };
            let parser = Parser::create(record, &schema);

            let status: u32 = if let Ok(v) = parser.try_parse::<u32>("QueryStatus") {
                v
            } else if let Ok(v) = parser.try_parse::<i32>("QueryStatus") {
                v as u32
            } else {
                !0
            };
            if status != 0 {
                return;
            }

            let query_name = match parser.try_parse::<String>("QueryName") {
                Ok(s) => s,
                Err(_) => return,
            };
            let host_norm = normalize_query_name(&query_name);
            if host_norm.is_empty() {
                return;
            }

            let results_raw = match parser.try_parse::<String>("QueryResults") {
                Ok(s) => s,
                Err(_) => return,
            };
            let ips = parse_query_results(&results_raw);
            if ips.is_empty() {
                return;
            }

            if !is_dns_etw_enabled() {
                return;
            }

            insert_dns_mapping(host_norm, &ips);

            DNS_ETW_ACTIVE.store(true, Ordering::Relaxed);
            if !FIRST_ACTIVE_EVENT_LOGGED.swap(true, Ordering::SeqCst) {
                log_event(
                    EventKind::EtwSubscriptionStateChanged,
                    "info",
                    None,
                    None,
                    None,
                    Some(serde_json::json!({ "provider": "DNS-Client", "active": true })),
                    "DNS-Client ETW active",
                );
                eprintln!("spy-detector: DNS-Client ETW receiving query completions (IOC hostname cache enabled)");
            }
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
        let provider = Provider::by_guid(DNS_CLIENT_GUID)
            .any(KW_ANY)
            .level(4)
            .add_filter(EventFilter::ByEventIds(vec![EVT_QUERY_COMPLETED]))
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
                    std::thread::sleep(Duration::from_millis(150));
                    attempt += 1;
                    continue;
                }
                let hint = crate::etw_cleanup::format_etw_trace_start_failure(&e);
                DNS_ETW_ACTIVE.store(false, Ordering::Relaxed);
                log_event(
                    EventKind::EtwSubscriptionStateChanged,
                    "info",
                    None,
                    None,
                    None,
                    Some(serde_json::json!({ "provider": "DNS-Client", "active": false })),
                    "DNS-Client ETW unavailable",
                );
                eprintln!(
                    "spy-detector: DNS-Client ETW disabled (scanner falls back to reverse DNS): {hint} ({e:?})"
                );
                break None;
            }
        }
    };

    let Some(_session_handle) = _session_handle else {
        return;
    };

    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}
