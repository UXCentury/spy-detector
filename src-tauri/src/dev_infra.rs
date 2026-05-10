use serde::Deserialize;
use std::collections::HashMap;

const YAML_EMBED: &str = include_str!("../resources/dev-infra-iocs.yaml");

#[derive(Debug, Deserialize)]
struct YamlGithubRepos {
    #[serde(default)]
    malicious: Vec<String>,
    #[serde(default)]
    offensive_tooling: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct YamlRoot {
    snapshot_date: String,
    github_repos: YamlGithubRepos,
    #[serde(default)]
    paste_sites: Vec<String>,
    #[serde(default)]
    ipfs_gateways: Vec<String>,
    #[serde(default)]
    discord_cdn: Vec<String>,
    #[serde(default)]
    telegram_cdn: Vec<String>,
    #[serde(default)]
    url_shorteners: Vec<String>,
    #[serde(default)]
    file_share_abuse: Vec<String>,
    #[serde(default)]
    suspicious_paths: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct DevInfraMatch {
    pub category: String,
    pub label: String,
    pub score_delta: i32,
    pub severity: &'static str,
}

#[derive(Debug)]
struct HostPathPattern {
    host: String,
    path_prefix: Option<String>,
}

#[derive(Debug)]
pub struct DevInfraIndex {
    pub snapshot_date: String,
    github_malicious: Vec<String>,
    github_offensive: Vec<String>,
    paste_hosts: Vec<String>,
    ipfs_hosts: Vec<String>,
    discord_patterns: Vec<HostPathPattern>,
    telegram_patterns: Vec<HostPathPattern>,
    shortener_hosts: Vec<String>,
    file_share_hosts: Vec<String>,
    suspicious_path_needles: Vec<String>,
    category_counts: HashMap<String, u32>,
}

fn norm_host(h: &str) -> String {
    h.trim().trim_end_matches('.').to_lowercase()
}

fn split_pattern(entry: &str) -> HostPathPattern {
    let s = entry.trim().to_lowercase();
    if let Some(idx) = s.find('/') {
        HostPathPattern {
            host: s[..idx].to_string(),
            path_prefix: Some(s[idx..].to_string()),
        }
    } else {
        HostPathPattern {
            host: s,
            path_prefix: None,
        }
    }
}

fn host_suffix_match(host: &str, suffix: &str) -> bool {
    host == suffix || host.ends_with(&format!(".{suffix}"))
}

fn github_hosts(host: &str) -> bool {
    host == "github.com"
        || host.ends_with(".github.com")
        || host == "gist.github.com"
        || host.ends_with(".gist.github.com")
        || host == "raw.githubusercontent.com"
}

fn parse_github_path(path: &str) -> Option<(String, String)> {
    let p = path.to_lowercase();
    let mut parts = p.split('/').filter(|s| !s.is_empty());
    let a = parts.next()?;
    let b = parts.next()?;
    Some((a.to_string(), b.to_string()))
}

impl DevInfraIndex {
    pub fn load_embedded() -> Result<Self, String> {
        let doc: YamlRoot =
            serde_yaml::from_str(YAML_EMBED).map_err(|e| format!("dev-infra YAML: {e}"))?;

        let github_malicious: Vec<String> = doc
            .github_repos
            .malicious
            .into_iter()
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty())
            .collect();
        let github_offensive: Vec<String> = doc
            .github_repos
            .offensive_tooling
            .into_iter()
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty())
            .collect();

        let paste_hosts: Vec<String> = doc.paste_sites.into_iter().map(|s| norm_host(&s)).collect();
        let ipfs_hosts: Vec<String> = doc
            .ipfs_gateways
            .into_iter()
            .map(|s| norm_host(&s))
            .collect();
        let discord_patterns: Vec<HostPathPattern> = doc
            .discord_cdn
            .into_iter()
            .map(|s| split_pattern(&s))
            .collect();
        let telegram_patterns: Vec<HostPathPattern> = doc
            .telegram_cdn
            .into_iter()
            .map(|s| split_pattern(&s))
            .collect();
        let shortener_hosts: Vec<String> = doc
            .url_shorteners
            .into_iter()
            .map(|s| norm_host(&s))
            .collect();
        let file_share_hosts: Vec<String> = doc
            .file_share_abuse
            .into_iter()
            .map(|s| norm_host(&s))
            .collect();
        let suspicious_path_needles: Vec<String> = doc
            .suspicious_paths
            .into_iter()
            .map(|s| s.to_lowercase())
            .collect();

        let mut category_counts = HashMap::new();
        *category_counts.entry("githubMalicious".into()).or_insert(0) =
            github_malicious.len() as u32;
        *category_counts.entry("githubOffensive".into()).or_insert(0) =
            github_offensive.len() as u32;
        *category_counts.entry("paste".into()).or_insert(0) = paste_hosts.len() as u32;
        *category_counts.entry("ipfs".into()).or_insert(0) = ipfs_hosts.len() as u32;
        *category_counts.entry("discordCdn".into()).or_insert(0) = discord_patterns.len() as u32;
        *category_counts.entry("telegramCdn".into()).or_insert(0) = telegram_patterns.len() as u32;
        *category_counts.entry("shortener".into()).or_insert(0) = shortener_hosts.len() as u32;
        *category_counts.entry("fileShare".into()).or_insert(0) = file_share_hosts.len() as u32;
        *category_counts.entry("suspiciousPath".into()).or_insert(0) =
            suspicious_path_needles.len() as u32;

        Ok(Self {
            snapshot_date: doc.snapshot_date,
            github_malicious,
            github_offensive,
            paste_hosts,
            ipfs_hosts,
            discord_patterns,
            telegram_patterns,
            shortener_hosts,
            file_share_hosts,
            suspicious_path_needles,
            category_counts,
        })
    }

    pub fn category_counts_cloned(&self) -> HashMap<String, u32> {
        self.category_counts.clone()
    }

    pub fn match_url(&self, url: &str) -> Vec<DevInfraMatch> {
        let Some((host, path)) = parse_http_url(url) else {
            return Vec::new();
        };
        self.match_host_path_inner(&host, &path, true)
    }

    pub fn match_host_path(&self, host: &str, path: &str) -> Vec<DevInfraMatch> {
        let host = norm_host(host);
        let path = if path.is_empty() {
            "/".to_string()
        } else if path.starts_with('/') {
            path.to_lowercase()
        } else {
            format!("/{}", path.to_lowercase())
        };
        self.match_host_path_inner(&host, &path, true)
    }

    fn suspicious_path_hits(&self, path_l: &str) -> Vec<DevInfraMatch> {
        let mut out = Vec::new();
        for needle in &self.suspicious_path_needles {
            if path_l.contains(needle.as_str()) {
                out.push(DevInfraMatch {
                    category: "suspicious-path".into(),
                    label: needle.clone(),
                    score_delta: 10,
                    severity: "low",
                });
                break;
            }
        }
        out
    }

    fn match_github(
        &self,
        host: &str,
        path_l: &str,
        require_qualifier: bool,
    ) -> Vec<DevInfraMatch> {
        if !github_hosts(host) {
            return Vec::new();
        }
        let mut out = Vec::new();
        let path_qual = parse_github_path(path_l);
        if let Some((owner, repo)) = &path_qual {
            let pair = format!("{owner}/{repo}");
            for m in &self.github_malicious {
                if m.contains('/') {
                    if m == &pair || pair.starts_with(&format!("{m}/")) {
                        out.push(DevInfraMatch {
                            category: "github-malicious".into(),
                            label: pair.clone(),
                            score_delta: 45,
                            severity: "high",
                        });
                        break;
                    }
                } else if m == owner {
                    out.push(DevInfraMatch {
                        category: "github-malicious".into(),
                        label: pair.clone(),
                        score_delta: 45,
                        severity: "high",
                    });
                    break;
                }
            }
            if out.iter().any(|x| x.category == "github-malicious") {
                return out;
            }
            for entry in &self.github_offensive {
                if entry.contains('/') {
                    if entry == &pair || pair.starts_with(&format!("{entry}/")) {
                        out.push(DevInfraMatch {
                            category: "github-offensive".into(),
                            label: entry.clone(),
                            score_delta: 25,
                            severity: "warn",
                        });
                        break;
                    }
                } else if entry == owner {
                    out.push(DevInfraMatch {
                        category: "github-offensive".into(),
                        label: pair.clone(),
                        score_delta: 25,
                        severity: "warn",
                    });
                    break;
                }
            }
        }
        if require_qualifier && out.is_empty() {
            let susp = self.suspicious_path_hits(path_l);
            if !susp.is_empty() {
                out.extend(susp);
            }
        }
        out
    }

    // internal helper; refactoring to a struct adds boilerplate without behavior change
    #[allow(clippy::too_many_arguments)]
    fn match_host_suffix_list(
        &self,
        host: &str,
        list: &[String],
        category: &str,
        label_prefix: &str,
        score: i32,
        severity: &'static str,
        path_required: bool,
        path_l: &str,
    ) -> Vec<DevInfraMatch> {
        let mut out = Vec::new();
        for h in list {
            if !host_suffix_match(host, h) {
                continue;
            }
            if path_required && self.suspicious_path_hits(path_l).is_empty() {
                continue;
            }
            out.push(DevInfraMatch {
                category: category.into(),
                label: format!("{label_prefix}:{h}"),
                score_delta: score,
                severity,
            });
            break;
        }
        out
    }

    fn match_host_path_patterns(
        &self,
        host: &str,
        path_l: &str,
        patterns: &[HostPathPattern],
        category: &str,
        base_score: i32,
        base_severity: &'static str,
    ) -> Vec<DevInfraMatch> {
        let mut out = Vec::new();
        let susp = !self.suspicious_path_hits(path_l).is_empty();
        for pat in patterns {
            if !host_suffix_match(host, &pat.host) {
                continue;
            }
            let ok_path = match &pat.path_prefix {
                None => true,
                Some(prefix) => path_l.starts_with(prefix),
            };
            if !ok_path {
                continue;
            }
            let (score, sev) = if category == "discord-cdn" && susp {
                (30, "warn")
            } else {
                (base_score, base_severity)
            };
            out.push(DevInfraMatch {
                category: category.into(),
                label: format!(
                    "{}:{}/{}",
                    category,
                    pat.host,
                    pat.path_prefix.as_deref().unwrap_or("")
                ),
                score_delta: score,
                severity: sev,
            });
            break;
        }
        out
    }

    fn match_host_path_inner(
        &self,
        host: &str,
        path_l: &str,
        full_url_context: bool,
    ) -> Vec<DevInfraMatch> {
        let mut all = Vec::new();

        all.extend(self.match_github(host, path_l, full_url_context));

        let paste_req = full_url_context;
        all.extend(self.match_host_suffix_list(
            host,
            &self.paste_hosts,
            "paste",
            "paste",
            10,
            "low",
            paste_req,
            path_l,
        ));

        all.extend(self.match_host_suffix_list(
            host,
            &self.ipfs_hosts,
            "ipfs",
            "ipfs",
            10,
            "low",
            false,
            path_l,
        ));

        all.extend(self.match_host_path_patterns(
            host,
            path_l,
            &self.discord_patterns,
            "discord-cdn",
            15,
            "low",
        ));

        let mut tg = self.match_host_path_patterns(
            host,
            path_l,
            &self.telegram_patterns,
            "telegram-cdn",
            10,
            "low",
        );
        if tg.is_empty() && host_suffix_match(host, "telegra.ph") {
            tg.push(DevInfraMatch {
                category: "telegram-cdn".into(),
                label: "telegra.ph".into(),
                score_delta: 10,
                severity: "low",
            });
        }
        all.extend(tg);

        all.extend(self.match_host_suffix_list(
            host,
            &self.shortener_hosts,
            "shortener",
            "shortener",
            10,
            "low",
            false,
            path_l,
        ));

        all.extend(self.match_host_suffix_list(
            host,
            &self.file_share_hosts,
            "file-share",
            "share",
            10,
            "low",
            false,
            path_l,
        ));

        let sp_hit = self.suspicious_path_hits(path_l);
        if full_url_context
            && !sp_hit.is_empty()
            && !all.iter().any(|m| m.category == "suspicious-path")
        {
            all.push(sp_hit[0].clone());
        }

        let mut seen_sp = false;
        all.retain(|m| {
            if m.category == "suspicious-path" {
                if seen_sp {
                    return false;
                }
                seen_sp = true;
            }
            true
        });

        self.apply_combo_severity(&mut all);
        all
    }

    fn apply_combo_severity(&self, matches: &mut [DevInfraMatch]) {
        let has_sp = matches.iter().any(|m| m.category == "suspicious-path");
        let has_other = matches.iter().any(|m| {
            matches!(
                m.category.as_str(),
                "paste" | "ipfs" | "discord-cdn" | "telegram-cdn" | "shortener" | "file-share"
            )
        });
        if has_sp && has_other {
            for m in matches.iter_mut() {
                if m.severity == "low" {
                    m.severity = "warn";
                }
            }
        }
    }

    /// Reverse-DNS / network staging indicator for LOLBin correlation (host only).
    pub fn network_staging_category(&self, host: &str) -> Option<String> {
        let host = norm_host(host);
        if self.ipfs_hosts.iter().any(|h| host_suffix_match(&host, h)) {
            return Some("IPFS gateway".into());
        }
        if self
            .file_share_hosts
            .iter()
            .any(|h| host_suffix_match(&host, h))
        {
            return Some("file share host".into());
        }
        if self
            .shortener_hosts
            .iter()
            .any(|h| host_suffix_match(&host, h))
        {
            return Some("URL shortener".into());
        }
        if self.paste_hosts.iter().any(|h| host_suffix_match(&host, h)) {
            return Some("paste site".into());
        }
        for pat in &self.discord_patterns {
            if host_suffix_match(&host, &pat.host) {
                return Some("Discord CDN".into());
            }
        }
        if host_suffix_match(&host, "telegra.ph") || host_suffix_match(&host, "t.me") {
            return Some("Telegram".into());
        }
        None
    }
}

pub fn parse_http_url(url: &str) -> Option<(String, String)> {
    let u = url.trim();
    let rest = u
        .strip_prefix("https://")
        .or_else(|| u.strip_prefix("http://"))?;
    let rest = rest.split('#').next().unwrap_or(rest);
    let rest = rest.split('?').next().unwrap_or(rest);
    let (host_port, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, "/".to_string()),
    };
    let host = host_port.split(':').next()?.trim();
    let host = norm_host(host);
    let path = if path.is_empty() {
        "/".to_string()
    } else {
        path.to_lowercase()
    };
    Some((host, path))
}

pub fn lolbin_dns_staging_hit(host_l: &str, dev_infra: &DevInfraIndex) -> Option<String> {
    let h = host_l.to_lowercase();
    if h.contains("github")
        || h.contains("githubusercontent")
        || h.contains("gist.github")
        || h.contains("pastebin")
        || h.contains("hastebin")
        || h.contains("rentry.co")
    {
        return Some("developer staging / CDN".into());
    }
    dev_infra.network_staging_category(&h)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn parses_github_offensive() {
        let idx = DevInfraIndex::load_embedded().unwrap();
        let m = idx.match_url("https://github.com/BishopFox/sliver/releases");
        assert!(m.iter().any(|x| x.category == "github-offensive"));
    }

    #[test]
    fn parse_http_url_splits_host_and_path() {
        assert_eq!(
            parse_http_url("https://Example.COM:8443/foo/Bar?q=1#frag"),
            Some(("example.com".into(), "/foo/bar".into()))
        );
        assert_eq!(
            parse_http_url("http://cdn.test"),
            Some(("cdn.test".into(), "/".into()))
        );
        assert_eq!(parse_http_url("ftp://bad"), None);
    }

    #[test]
    fn match_host_path_normalizes_and_matches_shortener_suffix() {
        let idx = DevInfraIndex::load_embedded().unwrap();
        let hits = idx.match_host_path("bit.ly", "");
        assert!(
            hits.iter().any(|h| h.category == "shortener"),
            "expected shortener hit: {hits:?}"
        );
    }
}
