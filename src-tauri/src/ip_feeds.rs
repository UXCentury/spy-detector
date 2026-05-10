//! Bundled and user-refreshed public IP blocklists (Spamhaus DROP, CINS, ET, Tor exits, optional FireHOL L1).
//! FireHOL Level 1 can exceed 600k CIDR rows; it is default-disabled and only loaded after explicit opt-in + refresh.

use ipnet::IpNet;
use rusqlite::{Connection, OptionalExtension};
use serde::Serialize;
use std::collections::HashSet;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpFeedCategory {
    NetworkMalicious,
    MaliciousHost,
    CompromisedHost,
    TorExit,
}

impl IpFeedCategory {
    pub fn slug(self) -> &'static str {
        match self {
            Self::NetworkMalicious => "network-malicious",
            Self::MaliciousHost => "malicious-host",
            Self::CompromisedHost => "compromised-host",
            Self::TorExit => "tor-exit",
        }
    }

    pub fn score_weight(self) -> u8 {
        match self {
            Self::NetworkMalicious => 30,
            Self::MaliciousHost => 25,
            Self::CompromisedHost => 15,
            Self::TorExit => 5,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct IpFeedSource {
    pub slug: &'static str,
    pub label: &'static str,
    pub category: IpFeedCategory,
    pub upstream_url: &'static str,
    pub default_enabled: bool,
}

pub const FEEDS: &[IpFeedSource] = &[
    IpFeedSource {
        slug: "spamhaus-drop",
        label: "Spamhaus DROP",
        category: IpFeedCategory::NetworkMalicious,
        upstream_url: "https://www.spamhaus.org/drop/drop.txt",
        default_enabled: true,
    },
    IpFeedSource {
        slug: "spamhaus-edrop",
        label: "Spamhaus EDROP",
        category: IpFeedCategory::NetworkMalicious,
        upstream_url: "https://www.spamhaus.org/drop/edrop.txt",
        default_enabled: true,
    },
    IpFeedSource {
        slug: "cins-army",
        label: "CINS Army",
        category: IpFeedCategory::MaliciousHost,
        upstream_url: "https://cinsscore.com/list/ci-badguys.txt",
        default_enabled: true,
    },
    IpFeedSource {
        slug: "et-compromised",
        label: "Emerging Threats compromised IPs",
        category: IpFeedCategory::CompromisedHost,
        upstream_url: "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        default_enabled: true,
    },
    IpFeedSource {
        slug: "firehol-level1",
        label: "FireHOL Level 1",
        category: IpFeedCategory::NetworkMalicious,
        upstream_url: "https://iplists.firehol.org/files/firehol_level1.netset",
        default_enabled: false,
    },
    IpFeedSource {
        slug: "tor-exits",
        label: "Tor exit nodes",
        category: IpFeedCategory::TorExit,
        upstream_url: "https://check.torproject.org/exit-addresses",
        default_enabled: true,
    },
];

#[derive(Debug, Clone)]
pub struct IpFeedHit {
    pub slug: &'static str,
    pub label: &'static str,
    pub category_slug: &'static str,
    pub score_weight: u8,
}

pub fn enabled_setting_key(slug: &str) -> String {
    format!("ip_feed_enabled:{slug}")
}

pub fn last_refresh_key(slug: &str) -> String {
    format!("ip_feed_last_refreshed:{slug}")
}

pub fn feed_enabled(conn: &Connection, slug: &str, default_enabled: bool) -> Result<bool, String> {
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

pub fn set_feed_enabled(conn: &Connection, slug: &str, enabled: bool) -> Result<(), String> {
    let key = enabled_setting_key(slug);
    let v = if enabled { "1" } else { "0" };
    conn.execute(
        "INSERT OR REPLACE INTO user_settings (key, value) VALUES (?1, ?2)",
        rusqlite::params![key, v],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

fn user_feed_path(slug: &str) -> Result<PathBuf, String> {
    let dir = dirs::data_dir()
        .ok_or_else(|| "could not resolve app data dir".to_string())?
        .join("spy-detector")
        .join("ip-feeds");
    Ok(dir.join(format!("{slug}.txt")))
}

fn bundled_embed(slug: &str) -> Option<&'static str> {
    Some(match slug {
        "spamhaus-drop" => include_str!("../resources/ip-feeds/spamhaus-drop.txt"),
        "spamhaus-edrop" => include_str!("../resources/ip-feeds/spamhaus-edrop.txt"),
        "cins-army" => include_str!("../resources/ip-feeds/cins-army.txt"),
        "et-compromised" => include_str!("../resources/ip-feeds/et-compromised.txt"),
        "tor-exits" => include_str!("../resources/ip-feeds/tor-exits.txt"),
        _ => return None,
    })
}

fn load_feed_text(feed: &IpFeedSource) -> Result<String, String> {
    let user = user_feed_path(feed.slug)?;
    if user.is_file() {
        return std::fs::read_to_string(&user).map_err(|e| format!("read {}: {e}", user.display()));
    }
    if let Some(embed) = bundled_embed(feed.slug) {
        return Ok(embed.to_string());
    }
    Ok(String::new())
}

#[derive(Default)]
pub struct ParsedFeed {
    pub ips: HashSet<IpAddr>,
    pub nets: Vec<IpNet>,
}

fn strip_comments(line: &str) -> &str {
    let line = line.trim();
    if let Some(i) = line.find(';') {
        line[..i].trim()
    } else {
        line
    }
}

fn parse_tor_exit_line(line: &str) -> Option<IpAddr> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let rest = line.strip_prefix("ExitAddress")?;
    let tok = rest.split_whitespace().next()?;
    tok.parse().ok()
}

pub fn parse_feed_content(feed: &IpFeedSource, text: &str) -> ParsedFeed {
    let mut out = ParsedFeed::default();
    if feed.slug == "tor-exits" {
        for line in text.lines() {
            if let Some(ip) = parse_tor_exit_line(line) {
                out.ips.insert(ip);
            }
        }
        return out;
    }

    for raw in text.lines() {
        let line = strip_comments(raw);
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let token = line.split_whitespace().next().unwrap_or(line).trim();
        if token.is_empty() {
            continue;
        }
        if let Ok(net) = token.parse::<IpNet>() {
            out.nets.push(net);
            continue;
        }
        if let Ok(ip) = token.parse::<IpAddr>() {
            out.ips.insert(ip);
        }
    }
    out
}

pub struct LoadedFeedBucket {
    pub source: &'static IpFeedSource,
    pub ips: HashSet<IpAddr>,
    pub nets: Vec<IpNet>,
}

#[derive(Default)]
pub struct IpFeedIndex {
    buckets: Vec<LoadedFeedBucket>,
}

impl IpFeedIndex {
    pub fn reload(conn: &Connection) -> Result<Self, String> {
        let mut buckets = Vec::new();
        for feed in FEEDS {
            if !feed_enabled(conn, feed.slug, feed.default_enabled)? {
                continue;
            }
            let text = load_feed_text(feed)?;
            let parsed = parse_feed_content(feed, &text);
            if parsed.ips.is_empty() && parsed.nets.is_empty() {
                continue;
            }
            buckets.push(LoadedFeedBucket {
                source: feed,
                ips: parsed.ips,
                nets: parsed.nets,
            });
        }
        Ok(Self { buckets })
    }

    pub fn match_ip(&self, ip: IpAddr) -> Option<IpFeedHit> {
        for b in &self.buckets {
            if b.ips.contains(&ip) {
                return Some(IpFeedHit {
                    slug: b.source.slug,
                    label: b.source.label,
                    category_slug: b.source.category.slug(),
                    score_weight: b.source.category.score_weight(),
                });
            }
            for n in &b.nets {
                if n.contains(&ip) {
                    return Some(IpFeedHit {
                        slug: b.source.slug,
                        label: b.source.label,
                        category_slug: b.source.category.slug(),
                        score_weight: b.source.category.score_weight(),
                    });
                }
            }
        }
        None
    }

    pub fn indicator_count(&self, slug: &str) -> u32 {
        self.buckets
            .iter()
            .find(|b| b.source.slug == slug)
            .map(|b| (b.ips.len() + b.nets.len()) as u32)
            .unwrap_or(0)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IpFeedStatus {
    pub slug: String,
    pub label: String,
    pub category: String,
    pub enabled: bool,
    pub indicator_count: u32,
    pub last_refreshed_at: Option<String>,
    pub default_enabled: bool,
    pub upstream_url: String,
}

pub fn list_feed_statuses(
    conn: &Connection,
    index: &IpFeedIndex,
) -> Result<Vec<IpFeedStatus>, String> {
    let mut out = Vec::with_capacity(FEEDS.len());
    for feed in FEEDS {
        let enabled = feed_enabled(conn, feed.slug, feed.default_enabled)?;
        let last_key = last_refresh_key(feed.slug);
        let last_refreshed_at: Option<String> = conn
            .query_row(
                "SELECT value FROM user_settings WHERE key = ?1",
                [&last_key],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| e.to_string())?;
        out.push(IpFeedStatus {
            slug: feed.slug.to_string(),
            label: feed.label.to_string(),
            category: feed.category.slug().to_string(),
            enabled,
            indicator_count: index.indicator_count(feed.slug),
            last_refreshed_at,
            default_enabled: feed.default_enabled,
            upstream_url: feed.upstream_url.to_string(),
        });
    }
    Ok(out)
}

fn replace_atomic(tmp: &Path, dest: &Path) -> Result<(), String> {
    #[cfg(windows)]
    if dest.exists() {
        std::fs::remove_file(dest).map_err(|e| e.to_string())?;
    }
    std::fs::rename(tmp, dest).map_err(|e| e.to_string())?;
    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IpFeedRefreshRow {
    pub slug: String,
    pub status: String,
    pub indicator_count: u32,
    pub message: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IpFeedsRefreshSummary {
    pub ok: bool,
    pub feeds: Vec<IpFeedRefreshRow>,
}

pub fn user_feed_dir() -> Result<PathBuf, String> {
    let dir = dirs::data_dir()
        .ok_or_else(|| "could not resolve app data dir".to_string())?
        .join("spy-detector")
        .join("ip-feeds");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir)
}

/// Writes refreshed UTF-8 body to the user feed path, updates per-feed `last_refreshed`, returns parsed indicator count.
pub fn persist_refreshed_feed(
    conn: &Connection,
    feed: &IpFeedSource,
    raw_utf8: &str,
) -> Result<u32, String> {
    let base_dir = user_feed_dir()?;
    let hdr = format!(
        "# Snapshot from {} fetched {}\n# Refresh via the IOC Refresh page in the app\n",
        feed.upstream_url,
        chrono::Utc::now().format("%Y-%m-%dT%H:%MZ")
    );
    let body = format!("{hdr}{raw_utf8}");

    let dest = base_dir.join(format!("{}.txt", feed.slug));
    let tmp = base_dir.join(format!("{}.txt.tmp", feed.slug));
    std::fs::write(&tmp, body.as_bytes()).map_err(|e| e.to_string())?;
    replace_atomic(&tmp, &dest)?;

    let ts = chrono::Utc::now().to_rfc3339();
    let lk = last_refresh_key(feed.slug);
    conn.execute(
        "INSERT OR REPLACE INTO user_settings (key, value) VALUES (?1, ?2)",
        rusqlite::params![lk, ts],
    )
    .map_err(|e| e.to_string())?;

    let parsed = parse_feed_content(feed, &body);
    Ok((parsed.ips.len() + parsed.nets.len()) as u32)
}

pub fn touch_global_feed_refresh(conn: &Connection) -> Result<(), String> {
    let ts = chrono::Utc::now().to_rfc3339();
    conn.execute(
        "INSERT OR REPLACE INTO user_settings (key, value) VALUES ('ip_feeds_last_refreshed_at', ?1)",
        [&ts],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(test)]
impl IpFeedIndex {
    pub(crate) fn from_buckets(buckets: Vec<LoadedFeedBucket>) -> Self {
        Self { buckets }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use std::collections::HashSet;
    use std::net::{IpAddr, Ipv4Addr};

    fn spamhaus_feed() -> &'static IpFeedSource {
        FEEDS
            .iter()
            .find(|f| f.slug == "spamhaus-drop")
            .expect("spamhaus-drop feed")
    }

    fn cins_feed() -> &'static IpFeedSource {
        FEEDS
            .iter()
            .find(|f| f.slug == "cins-army")
            .expect("cins feed")
    }

    #[test]
    fn parse_spamhaus_drop_comments_and_host_lines() {
        let text = indoc::indoc! {"
            ; Spamhaus DROP
            192.0.2.5
            203.0.113.0/24 ; optional comment
            "};
        let parsed = parse_feed_content(spamhaus_feed(), text);
        assert!(parsed
            .ips
            .contains(&IpAddr::V4(Ipv4Addr::new(192, 0, 2, 5))));
        assert_eq!(parsed.nets.len(), 1);
        assert!(parsed.nets[0].contains(&IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))));
    }

    #[test]
    fn parse_cins_ip_per_line_like_bundle() {
        let text = "203.0.113.8\n";
        let parsed = parse_feed_content(cins_feed(), text);
        assert!(parsed
            .ips
            .contains(&IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8))));
        assert!(parsed.nets.is_empty());
    }

    #[test]
    fn parse_tor_exit_address_lines() {
        let tor = FEEDS.iter().find(|f| f.slug == "tor-exits").unwrap();
        let text = "# ignore\nExitAddress 192.0.2.77 Foo\n";
        let parsed = parse_feed_content(tor, text);
        assert!(parsed
            .ips
            .contains(&IpAddr::V4(Ipv4Addr::new(192, 0, 2, 77))));
    }

    #[test]
    fn parse_ipv6_cidr_line() {
        let text = "2001:db8::/32\n";
        let parsed = parse_feed_content(spamhaus_feed(), text);
        assert_eq!(parsed.nets.len(), 1);
        assert!(parsed.nets[0].contains(&"2001:db8::1".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn match_ip_direct_and_cidr_ipv6() {
        let drop = spamhaus_feed();
        let bucket = LoadedFeedBucket {
            source: drop,
            ips: HashSet::from([IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2))]),
            nets: ["2001:db8::/32".parse().unwrap()].into(),
        };
        let idx = IpFeedIndex::from_buckets(vec![bucket]);
        assert!(idx
            .match_ip(Ipv4Addr::new(198, 51, 100, 2).into())
            .is_some());
        assert!(idx.match_ip("2001:db8::abcd".parse().unwrap()).is_some());
        assert!(idx.match_ip(Ipv4Addr::new(10, 0, 0, 1).into()).is_none());
    }

    #[test]
    fn feed_enabled_defaults_and_overrides() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        crate::db::init_db(&conn).unwrap();
        assert!(feed_enabled(&conn, "spamhaus-drop", true).unwrap());
        set_feed_enabled(&conn, "spamhaus-drop", false).unwrap();
        assert!(!feed_enabled(&conn, "spamhaus-drop", true).unwrap());
    }
}
