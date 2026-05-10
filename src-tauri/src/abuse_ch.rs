//! abuse.ch ThreatFox + URLhaus offline indexes and MalwareBazaar on-demand lookups.
//! Optional `Auth-Key` for bulk/API tier is documented at https://auth.abuse.ch/ — v1 ships without it.

use crate::ioc::domain_key;
use rusqlite::{Connection, OptionalExtension};
use serde::Serialize;
use serde_json::Value as JsonValue;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

pub const THREATFOX_URL: &str = "https://threatfox.abuse.ch/export/json/recent/";
pub const URLHAUS_CSV_URL: &str = "https://urlhaus.abuse.ch/downloads/csv_recent/";
pub const MALWAREBAZAAR_API: &str = "https://mb-api.abuse.ch/api/v1/";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum AbuseChSource {
    ThreatFox,
    UrlHaus,
    MalwareBazaar,
}

impl AbuseChSource {
    pub fn slug(self) -> &'static str {
        match self {
            Self::ThreatFox => "threatfox",
            Self::UrlHaus => "urlhaus",
            Self::MalwareBazaar => "malwarebazaar",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::ThreatFox => "ThreatFox",
            Self::UrlHaus => "URLhaus",
            Self::MalwareBazaar => "MalwareBazaar",
        }
    }
}

#[derive(Debug, Clone)]
pub struct AbuseChFeedSource {
    pub slug: &'static str,
    pub label: &'static str,
    pub upstream_url: &'static str,
    pub default_enabled: bool,
    pub bulk_refresh: bool,
}

pub const SOURCES: &[AbuseChFeedSource] = &[
    AbuseChFeedSource {
        slug: "threatfox",
        label: "ThreatFox",
        upstream_url: THREATFOX_URL,
        default_enabled: true,
        bulk_refresh: true,
    },
    AbuseChFeedSource {
        slug: "urlhaus",
        label: "URLhaus",
        upstream_url: URLHAUS_CSV_URL,
        default_enabled: true,
        bulk_refresh: true,
    },
    AbuseChFeedSource {
        slug: "malwarebazaar",
        label: "MalwareBazaar",
        upstream_url: MALWAREBAZAAR_API,
        default_enabled: false,
        bulk_refresh: false,
    },
];

pub fn enabled_setting_key(slug: &str) -> String {
    format!("abusech_{slug}_enabled")
}

pub fn last_refresh_key(slug: &str) -> String {
    format!("abusech_{slug}_last_refresh")
}

pub fn source_enabled(
    conn: &Connection,
    slug: &str,
    default_enabled: bool,
) -> Result<bool, String> {
    let key = enabled_setting_key(slug);
    let v: Option<String> = conn
        .query_row(
            "SELECT value FROM user_settings WHERE key = ?1",
            [&key],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| e.to_string())?;
    Ok(match v.as_deref() {
        Some(s) if s == "1" || s.eq_ignore_ascii_case("true") => true,
        Some(s) if s == "0" || s.eq_ignore_ascii_case("false") => false,
        _ => default_enabled,
    })
}

pub fn set_source_enabled(conn: &Connection, slug: &str, enabled: bool) -> Result<(), String> {
    let key = enabled_setting_key(slug);
    let v = if enabled { "1" } else { "0" };
    conn.execute(
        "INSERT OR REPLACE INTO user_settings (key, value) VALUES (?1, ?2)",
        rusqlite::params![key, v],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

#[derive(Clone)]
pub struct ThreatRecord {
    pub source: AbuseChSource,
    pub family: Option<String>,
    pub tags: Vec<String>,
    pub first_seen: Option<String>,
    pub confidence: u8,
}

#[derive(Default)]
pub struct AbuseChIndex {
    threatfox_domains: HashSet<String>,
    threatfox_ips: HashSet<IpAddr>,
    threatfox_urls: HashSet<String>,
    threatfox_hashes: HashSet<String>,
    urlhaus_hosts: HashSet<String>,
    urlhaus_urls: HashSet<String>,
    host_records: HashMap<String, ThreatRecord>,
    ip_records: HashMap<IpAddr, ThreatRecord>,
    url_records: HashMap<String, ThreatRecord>,
    hash_records: HashMap<String, ThreatRecord>,
}

fn bundled_threatfox() -> &'static str {
    include_str!("../resources/abuse-ch/threatfox-recent.json")
}

fn bundled_urlhaus() -> &'static str {
    include_str!("../resources/abuse-ch/urlhaus-recent.csv")
}

fn user_abuse_ch_dir() -> Result<PathBuf, String> {
    let dir = dirs::data_dir()
        .ok_or_else(|| "could not resolve app data dir".to_string())?
        .join("spy-detector")
        .join("abuse-ch");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir)
}

fn user_threatfox_path() -> Result<PathBuf, String> {
    Ok(user_abuse_ch_dir()?.join("threatfox-recent.json"))
}

fn user_urlhaus_path() -> Result<PathBuf, String> {
    Ok(user_abuse_ch_dir()?.join("urlhaus-recent.csv"))
}

fn load_threatfox_text() -> Result<String, String> {
    let p = user_threatfox_path()?;
    if p.is_file() {
        return std::fs::read_to_string(&p).map_err(|e| format!("read {}: {e}", p.display()));
    }
    Ok(bundled_threatfox().to_string())
}

fn load_urlhaus_text() -> Result<String, String> {
    let p = user_urlhaus_path()?;
    if p.is_file() {
        return std::fs::read_to_string(&p).map_err(|e| format!("read {}: {e}", p.display()));
    }
    Ok(bundled_urlhaus().to_string())
}

fn confidence_from_json(v: &JsonValue) -> Option<u8> {
    match v {
        JsonValue::Number(n) => n.as_u64().and_then(|u| u.try_into().ok()),
        JsonValue::String(s) => s.parse().ok(),
        _ => None,
    }
}

fn tags_from_json(v: &JsonValue) -> Vec<String> {
    match v {
        JsonValue::Array(a) => a
            .iter()
            .filter_map(|x| x.as_str().map(|s| s.trim().to_string()))
            .filter(|s| !s.is_empty())
            .collect(),
        JsonValue::String(s) => s
            .split(',')
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty())
            .collect(),
        _ => Vec::new(),
    }
}

fn first_seen_from_obj(obj: &serde_json::Map<String, JsonValue>) -> Option<String> {
    obj.get("first_seen_utc")
        .or_else(|| obj.get("first_seen"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn parse_ip_from_ioc(raw: &str) -> Option<IpAddr> {
    let s = raw.trim();
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Some(ip);
    }
    if let Ok(sa) = s.parse::<std::net::SocketAddr>() {
        return Some(sa.ip());
    }
    if let Some(pos) = s.rfind(':') {
        let host = s[..pos].trim().trim_matches(['[', ']']);
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Some(ip);
        }
    }
    None
}

pub(crate) fn normalize_http_url_for_match(url: &str) -> Option<String> {
    let u = url.trim();
    let lower = u.to_lowercase();
    let base = lower.split('#').next()?.trim();
    let (h, p) = crate::dev_infra::parse_http_url(base)?;
    Some(format!("http://{h}{p}"))
}

fn record_from_tf_obj(
    obj: &serde_json::Map<String, JsonValue>,
    malware_family: Option<String>,
) -> ThreatRecord {
    let conf =
        confidence_from_json(obj.get("confidence_level").unwrap_or(&JsonValue::Null)).unwrap_or(0);
    let tags = tags_from_json(obj.get("tags").unwrap_or(&JsonValue::Null));
    ThreatRecord {
        source: AbuseChSource::ThreatFox,
        family: malware_family,
        tags,
        first_seen: first_seen_from_obj(obj),
        confidence: conf,
    }
}

fn merge_record_prefer_existing(old: ThreatRecord, new: ThreatRecord) -> ThreatRecord {
    if old.confidence >= new.confidence {
        old
    } else {
        new
    }
}

impl AbuseChIndex {
    pub fn load_preferred() -> Result<Self, String> {
        Self::build_from_text(&load_threatfox_text()?, &load_urlhaus_text()?, true, true)
    }

    pub fn reload(conn: &Connection) -> Result<Self, String> {
        let tf_on = source_enabled(conn, "threatfox", true)?;
        let uh_on = source_enabled(conn, "urlhaus", true)?;
        let tf_text = if tf_on {
            load_threatfox_text()?
        } else {
            "{}".to_string()
        };
        let uh_text = if uh_on {
            load_urlhaus_text()?
        } else {
            String::new()
        };
        Self::build_from_text(&tf_text, &uh_text, tf_on, uh_on)
    }

    fn build_from_text(tf: &str, uh: &str, tf_on: bool, uh_on: bool) -> Result<Self, String> {
        let mut idx = AbuseChIndex::default();

        if tf_on {
            if let Err(e) = ingest_threatfox(tf, &mut idx) {
                let msg = format!("ThreatFox ingest failed: {e}");
                eprintln!("{msg}; continuing without ThreatFox data");
                crate::app_log::append_line(&msg);
            }
        }

        if uh_on && !uh.trim().is_empty() {
            let _ = ingest_urlhaus_csv(uh, &mut idx);
        }

        Ok(idx)
    }

    pub fn threatfox_indicator_count(&self) -> u32 {
        (self.threatfox_domains.len()
            + self.threatfox_ips.len()
            + self.threatfox_urls.len()
            + self.threatfox_hashes.len()) as u32
    }

    pub fn urlhaus_url_count(&self) -> u32 {
        self.urlhaus_urls.len() as u32
    }

    pub fn indicator_count(&self) -> u32 {
        self.threatfox_indicator_count()
            .saturating_add(self.urlhaus_url_count())
    }

    pub fn match_host(&self, host: &str) -> Option<&ThreatRecord> {
        let host = host.trim_end_matches('.').to_lowercase();
        if let Some(r) = self.host_records.get(&host) {
            return Some(r);
        }
        let parts: Vec<&str> = host.split('.').collect();
        for i in 1..parts.len() {
            let suffix = parts[i..].join(".");
            if let Some(r) = self.host_records.get(&suffix) {
                return Some(r);
            }
        }
        None
    }

    pub fn match_ip(&self, ip: &IpAddr) -> Option<&ThreatRecord> {
        self.ip_records.get(ip)
    }

    pub fn match_url(&self, url: &str) -> Option<&ThreatRecord> {
        let key = normalize_http_url_for_match(url)?;
        if let Some(r) = self.url_records.get(&key) {
            return Some(r);
        }
        self.url_records.get(&url.trim().to_lowercase())
    }

    pub fn match_hash(&self, sha256: &str) -> Option<&ThreatRecord> {
        let h = sha256.trim().to_lowercase();
        self.hash_records.get(&h)
    }

    pub fn format_match_reason(rec: &ThreatRecord) -> String {
        let fam = rec.family.as_deref().unwrap_or("unknown");
        let fs = rec.first_seen.as_deref().unwrap_or("n/a");
        format!("abuse.ch {}: {} ({})", rec.source.label(), fam, fs)
    }
}

fn ingest_threatfox(text: &str, idx: &mut AbuseChIndex) -> Result<(), String> {
    let text = text.strip_prefix('\u{FEFF}').unwrap_or(text).trim_start();
    if text.is_empty() {
        return Ok(());
    }
    let root: JsonValue = if text.starts_with('[') {
        serde_json::from_str(text).map_err(|e| format!("ThreatFox JSON: {e}"))?
    } else {
        let json_start = text
            .find('{')
            .ok_or_else(|| "ThreatFox: expected JSON object or array".to_string())?;
        serde_json::from_str(&text[json_start..]).map_err(|e| format!("ThreatFox JSON: {e}"))?
    };
    if let JsonValue::Array(a) = &root {
        if a.is_empty() {
            return Ok(());
        }
        return Err("ThreatFox: expected JSON object or empty array".into());
    }
    let obj = root
        .as_object()
        .ok_or_else(|| "ThreatFox: expected JSON object".to_string())?;
    for (_k, v) in obj.iter() {
        let Some(arr) = v.as_array() else {
            continue;
        };
        for item in arr {
            let Some(ent) = item.as_object() else {
                continue;
            };
            let conf =
                confidence_from_json(ent.get("confidence_level").unwrap_or(&JsonValue::Null))
                    .unwrap_or(0);
            if conf < 50 {
                continue;
            }
            let ioc_type = ent
                .get("ioc_type")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_lowercase();
            let raw_val = ent
                .get("ioc_value")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .trim();
            if raw_val.is_empty() {
                continue;
            }
            let malware_family = ent
                .get("malware_printable")
                .and_then(|x| x.as_str())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .or_else(|| {
                    ent.get("malware")
                        .and_then(|x| x.as_str())
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                });
            let rec = record_from_tf_obj(ent, malware_family.clone());

            match ioc_type.as_str() {
                "domain" => {
                    let dk = domain_key(raw_val);
                    idx.threatfox_domains.insert(dk.clone());
                    idx.host_records
                        .entry(dk.clone())
                        .and_modify(|e| *e = merge_record_prefer_existing(e.clone(), rec.clone()))
                        .or_insert(rec);
                }
                "ip:port" => {
                    if let Some(ip) = parse_ip_from_ioc(raw_val) {
                        idx.threatfox_ips.insert(ip);
                        idx.ip_records
                            .entry(ip)
                            .and_modify(|e| {
                                *e = merge_record_prefer_existing(e.clone(), rec.clone())
                            })
                            .or_insert(rec);
                    }
                }
                "url" => {
                    if let Some(key) = normalize_http_url_for_match(raw_val) {
                        idx.threatfox_urls.insert(key.clone());
                        idx.url_records
                            .entry(key)
                            .and_modify(|e| {
                                *e = merge_record_prefer_existing(e.clone(), rec.clone())
                            })
                            .or_insert(rec);
                    }
                }
                "md5_hash" | "sha1_hash" | "sha256_hash" => {
                    let hx = raw_val.to_lowercase();
                    idx.threatfox_hashes.insert(hx.clone());
                    idx.hash_records
                        .entry(hx)
                        .and_modify(|e| *e = merge_record_prefer_existing(e.clone(), rec.clone()))
                        .or_insert(rec);
                }
                _ => {}
            }
        }
    }
    Ok(())
}

fn split_csv(line: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut in_q = false;
    let mut chars = line.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '"' => {
                if in_q && chars.peek() == Some(&'"') {
                    chars.next();
                    cur.push('"');
                } else {
                    in_q = !in_q;
                }
            }
            ',' if !in_q => {
                out.push(cur.clone());
                cur.clear();
            }
            _ => cur.push(ch),
        }
    }
    out.push(cur);
    out
}

fn normalize_urlhaus_header_cell(s: &str) -> String {
    s.trim().trim_matches('"').to_lowercase()
}

fn urlhaus_header_candidate(trimmed: &str) -> Option<&str> {
    let body = trimmed.strip_prefix('#').unwrap_or(trimmed).trim();
    let cells = split_csv(body);
    let first = cells.first().map(|c| normalize_urlhaus_header_cell(c))?;
    if first == "id" {
        Some(body)
    } else {
        None
    }
}

fn ingest_urlhaus_csv(text: &str, idx: &mut AbuseChIndex) -> Result<(), String> {
    let text = text.strip_prefix('\u{FEFF}').unwrap_or(text);
    let lines: Vec<&str> = text.lines().collect();
    let mut i = 0usize;
    let mut header_src: Option<&str> = None;
    while i < lines.len() {
        let t = lines[i].trim();
        i += 1;
        if t.is_empty() {
            continue;
        }
        if let Some(h) = urlhaus_header_candidate(t) {
            header_src = Some(h);
            break;
        }
        if !t.starts_with('#') {
            let msg = "URLhaus CSV: no header row before first data line; skipping URLhaus data";
            eprintln!("{msg}");
            crate::app_log::append_line(msg);
            return Ok(());
        }
    }
    let Some(header_src) = header_src else {
        let msg = "URLhaus CSV: no header row found; skipping URLhaus data";
        eprintln!("{msg}");
        crate::app_log::append_line(msg);
        return Ok(());
    };

    let hdr_cells: Vec<String> = split_csv(header_src)
        .into_iter()
        .map(|c| normalize_urlhaus_header_cell(&c))
        .collect();
    let mut col_url = hdr_cells.iter().position(|c| c == "url");
    let mut col_status = hdr_cells.iter().position(|c| c == "url_status");
    let use_positional = col_url.is_none() || col_status.is_none();
    if use_positional {
        crate::app_log::append_line(
            "URLhaus CSV: header missing url/url_status names; using positional columns",
        );
        col_url = Some(2);
        col_status = Some(3);
    }

    let url_i = col_url.expect("url column");
    let status_i = col_status.expect("url_status column");

    while i < lines.len() {
        let raw_line = lines[i];
        i += 1;
        let line = raw_line.trim_end();
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let cols = split_csv(line);
        let min_len = url_i.max(status_i) + 1;
        if cols.len() < min_len.max(4) {
            continue;
        }

        let row: HashMap<String, String> = if use_positional {
            HashMap::new()
        } else {
            hdr_cells
                .iter()
                .cloned()
                .zip(cols.iter().map(|c| c.trim().to_string()))
                .collect()
        };

        let status = if use_positional {
            normalize_urlhaus_header_cell(&cols[status_i])
        } else {
            row.get("url_status")
                .map(|s| normalize_urlhaus_header_cell(s))
                .unwrap_or_default()
        };
        if status != "online" {
            continue;
        }

        let url = if use_positional {
            cols[url_i].trim()
        } else {
            row.get("url").map(|s| s.as_str()).unwrap_or("").trim()
        };
        if url.is_empty() {
            continue;
        }

        let tags = if use_positional {
            Vec::new()
        } else {
            row.get("tags")
                .map(|s| {
                    s.split(',')
                        .map(|t| t.trim().to_string())
                        .filter(|t| !t.is_empty())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default()
        };
        let threat = if use_positional {
            cols.get(5).and_then(|s| {
                let t = s.trim();
                if t.is_empty() {
                    None
                } else {
                    Some(t.to_string())
                }
            })
        } else {
            row.get("threat")
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        };
        let dateadded = if use_positional {
            cols.get(1).and_then(|s| {
                let t = s.trim();
                if t.is_empty() {
                    None
                } else {
                    Some(t.to_string())
                }
            })
        } else {
            row.get("dateadded")
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        };

        let rec = ThreatRecord {
            source: AbuseChSource::UrlHaus,
            family: threat,
            tags,
            first_seen: dateadded,
            confidence: 100,
        };
        if let Some(key) = normalize_http_url_for_match(url) {
            idx.urlhaus_urls.insert(key.clone());
            idx.url_records.insert(key, rec.clone());
        }
        if let Some((h, _)) = crate::dev_infra::parse_http_url(url) {
            let dk = domain_key(&h);
            idx.urlhaus_hosts.insert(dk.clone());
            idx.host_records
                .entry(dk)
                .and_modify(|e| {
                    if e.source == AbuseChSource::ThreatFox && e.confidence >= rec.confidence {
                        return;
                    }
                    *e = rec.clone();
                })
                .or_insert(rec);
        }
    }
    Ok(())
}

fn replace_atomic(tmp: &Path, dest: &Path) -> Result<(), String> {
    #[cfg(windows)]
    if dest.exists() {
        std::fs::remove_file(dest).map_err(|e| e.to_string())?;
    }
    std::fs::rename(tmp, dest).map_err(|e| e.to_string())?;
    Ok(())
}

pub fn persist_threatfox(conn: &Connection, raw_utf8: &str) -> Result<u32, String> {
    let dir = user_abuse_ch_dir()?;
    let hdr = format!(
        "# Snapshot from {THREATFOX_URL} fetched {}\n# Refresh via IOC Refresh or Settings\n",
        chrono::Utc::now().format("%Y-%m-%dT%H:%MZ")
    );
    let body = format!("{hdr}{raw_utf8}");
    let dest = dir.join("threatfox-recent.json");
    let tmp = dir.join("threatfox-recent.json.tmp");
    std::fs::write(&tmp, body.as_bytes()).map_err(|e| e.to_string())?;
    replace_atomic(&tmp, &dest)?;
    let ts = chrono::Utc::now().to_rfc3339();
    let lk = last_refresh_key("threatfox");
    conn.execute(
        "INSERT OR REPLACE INTO user_settings (key, value) VALUES (?1, ?2)",
        rusqlite::params![lk, ts],
    )
    .map_err(|e| e.to_string())?;
    let mut probe = AbuseChIndex::default();
    ingest_threatfox(&body, &mut probe)?;
    Ok(probe.threatfox_indicator_count())
}

pub fn persist_urlhaus(conn: &Connection, raw_utf8: &str) -> Result<u32, String> {
    let dir = user_abuse_ch_dir()?;
    let hdr = format!(
        "# Snapshot from {URLHAUS_CSV_URL} fetched {}\n# Refresh via IOC Refresh or Settings\n",
        chrono::Utc::now().format("%Y-%m-%dT%H:%MZ")
    );
    let body = format!("{hdr}{raw_utf8}");
    let dest = dir.join("urlhaus-recent.csv");
    let tmp = dir.join("urlhaus-recent.csv.tmp");
    std::fs::write(&tmp, body.as_bytes()).map_err(|e| e.to_string())?;
    replace_atomic(&tmp, &dest)?;
    let ts = chrono::Utc::now().to_rfc3339();
    let lk = last_refresh_key("urlhaus");
    conn.execute(
        "INSERT OR REPLACE INTO user_settings (key, value) VALUES (?1, ?2)",
        rusqlite::params![lk, ts],
    )
    .map_err(|e| e.to_string())?;
    let mut probe = AbuseChIndex::default();
    ingest_urlhaus_csv(&body, &mut probe)?;
    Ok(probe.urlhaus_url_count())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AbuseChRefreshRow {
    pub slug: String,
    pub status: String,
    pub indicator_count: u32,
    pub message: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AbuseChRefreshSummary {
    pub ok: bool,
    pub feeds: Vec<AbuseChRefreshRow>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AbuseChSourceStatus {
    pub slug: String,
    pub label: String,
    pub enabled: bool,
    pub indicator_count: u32,
    pub last_refreshed_at: Option<String>,
    pub default_enabled: bool,
    pub upstream_url: String,
}

pub fn list_source_statuses(
    conn: &Connection,
    index: &AbuseChIndex,
) -> Result<Vec<AbuseChSourceStatus>, String> {
    let mut out = Vec::with_capacity(SOURCES.len());
    for s in SOURCES {
        let enabled = source_enabled(conn, s.slug, s.default_enabled)?;
        let last_key = last_refresh_key(s.slug);
        let last_refreshed_at: Option<String> = conn
            .query_row(
                "SELECT value FROM user_settings WHERE key = ?1",
                [&last_key],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| e.to_string())?;
        let indicator_count = if !s.bulk_refresh {
            0
        } else if s.slug == "threatfox" {
            index.threatfox_indicator_count()
        } else {
            index.urlhaus_url_count()
        };
        out.push(AbuseChSourceStatus {
            slug: s.slug.to_string(),
            label: s.label.to_string(),
            enabled,
            indicator_count,
            last_refreshed_at,
            default_enabled: s.default_enabled,
            upstream_url: s.upstream_url.to_string(),
        });
    }
    Ok(out)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MbLookupResult {
    pub signature: Option<String>,
    pub tags: Vec<String>,
    pub first_seen: Option<String>,
}

pub fn normalize_sha256_hex(s: &str) -> Result<String, String> {
    let t = s.trim().to_lowercase();
    if t.len() != 64 || !t.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("SHA256 must be 64 hex characters.".into());
    }
    Ok(t)
}

pub async fn malwarebazaar_lookup(sha256: &str) -> Result<Option<MbLookupResult>, String> {
    let hash = normalize_sha256_hex(sha256)?;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(25))
        .user_agent("spy-detector/0.1")
        .build()
        .map_err(|e| e.to_string())?;
    let form = [("query", "get_info"), ("hash", hash.as_str())];
    let resp = client
        .post(MALWAREBAZAAR_API)
        .form(&form)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Ok(None);
    }
    let bytes = resp.bytes().await.map_err(|e| e.to_string())?;
    let val: JsonValue = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    let status = val
        .get("query_status")
        .and_then(|x| x.as_str())
        .unwrap_or("");
    if status != "ok" {
        return Ok(None);
    }
    let data = val
        .get("data")
        .and_then(|d| d.as_array())
        .cloned()
        .unwrap_or_default();
    let first = data.first().and_then(|x| x.as_object());
    let Some(obj) = first else {
        return Ok(None);
    };
    let signature = obj
        .get("signature")
        .and_then(|x| x.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let tags = tags_from_json(obj.get("tags").unwrap_or(&JsonValue::Null));
    let first_seen = obj
        .get("first_seen")
        .and_then(|x| x.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    Ok(Some(MbLookupResult {
        signature,
        tags,
        first_seen,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn parses_threatfox_fixture_domains_respect_confidence() {
        let j = r#"{
            "1": [{
                "ioc_value": "evil.example",
                "ioc_type": "domain",
                "confidence_level": 55,
                "malware_printable": "TestMalware",
                "first_seen_utc": "2026-01-01 00:00:00",
                "tags": "a,b"
            }],
            "2": [{
                "ioc_value": "low.example",
                "ioc_type": "domain",
                "confidence_level": 10,
                "malware_printable": "No",
                "tags": ""
            }]
        }"#;
        let mut idx = AbuseChIndex::default();
        ingest_threatfox(j, &mut idx).expect("ingest");
        assert!(idx.threatfox_domains.contains("evil.example"));
        assert!(!idx.threatfox_domains.contains("low.example"));
        let rec = idx.match_host("sub.evil.example").expect("host match");
        assert_eq!(rec.source, AbuseChSource::ThreatFox);
        assert_eq!(rec.family.as_deref(), Some("TestMalware"));
    }

    #[test]
    fn parses_urlhaus_csv_online_only() {
        let csv = r#"################################################################
# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
"1","2026-01-01","http://bad.test/x","online","","malware_download","t1,t2","http://x","r"
"2","2026-01-01","http://off.test/y","offline","","malware_download","","http://y","r"
"#;
        let mut idx = AbuseChIndex::default();
        ingest_urlhaus_csv(csv, &mut idx).expect("csv");
        assert_eq!(idx.urlhaus_urls.len(), 1);
        assert!(idx.match_url("http://bad.test/x").is_some());
        assert!(idx.match_url("http://off.test/y").is_none());
    }

    #[test]
    fn urlhaus_parser_handles_empty_and_comment_only_input() {
        let mut idx = AbuseChIndex::default();
        assert!(ingest_urlhaus_csv("", &mut idx).is_ok());
        assert_eq!(idx.urlhaus_urls.len(), 0);

        let mut idx2 = AbuseChIndex::default();
        assert!(ingest_urlhaus_csv("# only comments\n# nothing useful\n", &mut idx2).is_ok());
        assert_eq!(idx2.urlhaus_urls.len(), 0);
    }

    #[test]
    fn abusech_from_feed_strings_keeps_threatfox_when_urlhaus_has_no_header() {
        let tf = r#"{
            "1": [{
                "ioc_value": "evil.example",
                "ioc_type": "domain",
                "confidence_level": 55,
                "malware_printable": "TestMalware",
                "first_seen_utc": "2026-01-01 00:00:00",
                "tags": "a,b"
            }]
        }"#;
        let uh = "# nothing\n# no header row\n";
        let idx = AbuseChIndex::build_from_text(tf, uh, true, true).expect("composed load");
        assert!(idx.threatfox_domains.contains("evil.example"));
        assert_eq!(idx.urlhaus_urls.len(), 0);
    }

    #[test]
    fn urlhaus_parser_accepts_unhashed_quoted_header_row() {
        let csv = concat!(
            "\"id\",\"dateadded\",\"url\",\"url_status\",\"last_online\",\"threat\",\"tags\",\"urlhaus_link\",\"reporter\"\n",
            "\"1\",\"2026-01-01\",\"http://bad.test/x\",\"online\",\"\",\"malware_download\",\"\",\"http://x\",\"r\"\n",
        );
        let mut idx = AbuseChIndex::default();
        ingest_urlhaus_csv(csv, &mut idx).expect("csv");
        assert_eq!(idx.urlhaus_urls.len(), 1);
    }
}
