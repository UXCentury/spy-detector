use serde::Deserialize;
use serde_yaml::Value;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IocEntrySource {
    Bundled,
    Upstream,
    WindowsSignatures,
}

#[derive(Debug)]
pub struct IocRuleRow {
    pub token: String,
    pub kind: &'static str,
    pub source: IocEntrySource,
}

#[derive(Debug, Default)]
pub struct IocIndex {
    pub process_names: HashSet<String>,
    pub path_needles: Vec<String>,
    pub domains: HashSet<String>,
    pub ips: HashSet<IpAddr>,
    process_sources: HashMap<String, IocEntrySource>,
    domain_sources: HashMap<String, IocEntrySource>,
    ip_sources: HashMap<IpAddr, IocEntrySource>,
    path_sources: HashMap<String, IocEntrySource>,
    /// Best-effort label for matched process name tokens (Windows sigs + upstream entry names).
    process_match_labels: HashMap<String, String>,
    /// Best-effort label for path needles (Windows signatures).
    path_needle_labels: HashMap<String, String>,
    /// Pre-sorted rows for the Rules UI; rebuilt only when the index is loaded/refreshed.
    rule_rows: Arc<Vec<IocRuleRow>>,
}

#[derive(Debug, Deserialize)]
struct WindowsIocFile {
    #[serde(default)]
    signatures: Vec<WindowsSig>,
}

#[derive(Debug, Deserialize)]
struct WindowsSig {
    #[allow(dead_code)]
    label: String,
    #[serde(default)]
    process_names: Vec<String>,
    #[serde(default)]
    path_substrings: Vec<String>,
}

#[derive(Clone, Copy)]
enum UpstreamPackaging {
    Bundled,
    RefreshedUserFile,
}

const IOC_UPSTREAM_YAML: &str = include_str!("../resources/ioc.yaml");
const IOC_WINDOWS_YAML: &str = include_str!("../resources/windows-spy-signatures.yaml");

impl IocIndex {
    /// Match startup-related strings against process names and path needles; returns a display label.
    pub fn startup_ioc_match(
        &self,
        exe_stem_norm: &str,
        path_lower: &str,
        command_lower: &str,
    ) -> Option<String> {
        if self.process_names.contains(exe_stem_norm) {
            return self
                .process_match_labels
                .get(exe_stem_norm)
                .cloned()
                .or_else(|| Some(exe_stem_norm.to_string()));
        }
        for needle in &self.path_needles {
            if path_lower.contains(needle) || command_lower.contains(needle) {
                return self
                    .path_needle_labels
                    .get(needle)
                    .cloned()
                    .or_else(|| Some(needle.clone()));
            }
        }
        None
    }

    /// `%APPDATA%\\spy-detector\\ioc.yaml` when refresh has populated it; otherwise bundled upstream YAML.
    pub fn load_preferred() -> Result<Self, String> {
        let mut idx = IocIndex::default();
        let (upstream, packaging) = match Self::user_upstream_ioc_path() {
            Some(p) if p.exists() => {
                let u =
                    std::fs::read_to_string(&p).map_err(|e| format!("read user IOC file: {e}"))?;
                (u, UpstreamPackaging::RefreshedUserFile)
            }
            _ => (IOC_UPSTREAM_YAML.to_string(), UpstreamPackaging::Bundled),
        };
        idx.ingest_upstream_yaml(&upstream, packaging)?;
        idx.ingest_windows_yaml(IOC_WINDOWS_YAML)?;
        idx.rule_rows = Arc::new(idx.build_rule_rows_sorted());
        Ok(idx)
    }

    pub fn load_embedded() -> Result<Self, String> {
        let mut idx = IocIndex::default();
        idx.ingest_upstream_yaml(IOC_UPSTREAM_YAML, UpstreamPackaging::Bundled)?;
        idx.ingest_windows_yaml(IOC_WINDOWS_YAML)?;
        idx.rule_rows = Arc::new(idx.build_rule_rows_sorted());
        Ok(idx)
    }

    pub fn user_upstream_ioc_path() -> Option<PathBuf> {
        dirs::data_dir().map(|d| d.join("spy-detector").join("ioc.yaml"))
    }

    /// Ensures downloaded YAML parses like production loading (upstream + bundled Windows sigs).
    pub fn validate_refreshed_upstream_yaml(yaml: &str) -> Result<(), String> {
        let mut idx = IocIndex::default();
        idx.ingest_upstream_yaml(yaml, UpstreamPackaging::Bundled)?;
        idx.ingest_windows_yaml(IOC_WINDOWS_YAML)?;
        Ok(())
    }

    pub fn indicator_count(&self) -> u32 {
        (self.process_names.len() + self.domains.len() + self.ips.len() + self.path_needles.len())
            as u32
    }

    /// Rows for the Rules UI: sorted by kind, then token (snapshot from last full load).
    pub fn list_rule_rows(&self) -> &[IocRuleRow] {
        &self.rule_rows
    }

    fn build_rule_rows_sorted(&self) -> Vec<IocRuleRow> {
        fn kind_rank(kind: &str) -> u8 {
            match kind {
                "domain" => 0,
                "ip" => 1,
                "path_needle" => 2,
                "process_name" => 3,
                _ => 9,
            }
        }

        let mut rows: Vec<IocRuleRow> = Vec::new();

        for d in &self.domains {
            let source = self
                .domain_sources
                .get(d)
                .copied()
                .unwrap_or(IocEntrySource::Bundled);
            rows.push(IocRuleRow {
                token: d.clone(),
                kind: "domain",
                source,
            });
        }

        let mut ip_list: Vec<IpAddr> = self.ips.iter().copied().collect();
        ip_list.sort_by_key(|a| a.to_string());
        for ip in ip_list {
            let source = self
                .ip_sources
                .get(&ip)
                .copied()
                .unwrap_or(IocEntrySource::Bundled);
            rows.push(IocRuleRow {
                token: ip.to_string(),
                kind: "ip",
                source,
            });
        }

        for needle in &self.path_needles {
            let source = self
                .path_sources
                .get(needle)
                .copied()
                .unwrap_or(IocEntrySource::WindowsSignatures);
            rows.push(IocRuleRow {
                token: needle.clone(),
                kind: "path_needle",
                source,
            });
        }

        let mut proc_list: Vec<String> = self.process_names.iter().cloned().collect();
        proc_list.sort();
        for name in proc_list {
            let source = self
                .process_sources
                .get(&name)
                .copied()
                .unwrap_or(IocEntrySource::Bundled);
            rows.push(IocRuleRow {
                token: name,
                kind: "process_name",
                source,
            });
        }

        rows.sort_by(|a, b| {
            kind_rank(a.kind)
                .cmp(&kind_rank(b.kind))
                .then_with(|| a.token.cmp(&b.token))
        });
        rows
    }

    fn ingest_windows_yaml(&mut self, yaml: &str) -> Result<(), String> {
        let doc: WindowsIocFile =
            serde_yaml::from_str(yaml).map_err(|e| format!("windows IOC YAML: {e}"))?;
        let src = IocEntrySource::WindowsSignatures;
        for sig in doc.signatures {
            let label = sig.label.trim();
            let label_owned = if label.is_empty() {
                None
            } else {
                Some(label.to_string())
            };
            for n in sig.process_names {
                let t = norm_token(&n);
                self.process_names.insert(t.clone());
                self.process_sources.insert(t.clone(), src);
                if let Some(ref lb) = label_owned {
                    self.process_match_labels.insert(t, lb.clone());
                }
            }
            for p in sig.path_substrings {
                let needle = p.to_lowercase();
                if self.path_sources.contains_key(&needle) {
                    continue;
                }
                self.path_needles.push(needle.clone());
                self.path_sources.insert(needle.clone(), src);
                if let Some(ref lb) = label_owned {
                    self.path_needle_labels.insert(needle, lb.clone());
                }
            }
        }
        Ok(())
    }

    fn ingest_upstream_yaml(
        &mut self,
        yaml: &str,
        packaging: UpstreamPackaging,
    ) -> Result<(), String> {
        let src = match packaging {
            UpstreamPackaging::Bundled => IocEntrySource::Bundled,
            UpstreamPackaging::RefreshedUserFile => IocEntrySource::Upstream,
        };
        let root: Value =
            serde_yaml::from_str(yaml).map_err(|e| format!("upstream IOC YAML: {e}"))?;
        let seq = root
            .as_sequence()
            .ok_or_else(|| "upstream IOC: expected top-level array".to_string())?;
        for entry in seq {
            let Some(map) = entry.as_mapping() else {
                continue;
            };
            let entry_label = map
                .get(Value::String("name".into()))
                .and_then(|v| v.as_str())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());
            self.try_insert_process_string(map, "name", src, entry_label.as_deref());
            self.try_insert_seq_process_names(map, "names", src, entry_label.as_deref());
            self.try_insert_seq_domains(map, "websites", src);
            self.try_insert_seq_domains(map, "distribution", src);
            if let Some(Value::Mapping(c2)) = map.get(Value::String("c2".into())) {
                self.try_insert_seq_domains(c2, "domains", src);
                self.try_insert_seq_ips(c2, "ips", src);
            }
        }
        Ok(())
    }

    fn try_insert_process_string(
        &mut self,
        map: &serde_yaml::Mapping,
        key: &str,
        src: IocEntrySource,
        entry_label: Option<&str>,
    ) {
        if let Some(Value::String(s)) = map.get(Value::String(key.into())) {
            let t = norm_token(s);
            self.process_names.insert(t.clone());
            self.process_sources.insert(t.clone(), src);
            if let Some(lb) = entry_label {
                self.process_match_labels.insert(t, lb.to_string());
            }
        }
    }

    fn try_insert_seq_process_names(
        &mut self,
        map: &serde_yaml::Mapping,
        key: &str,
        src: IocEntrySource,
        entry_label: Option<&str>,
    ) {
        let Some(Value::Sequence(seq)) = map.get(Value::String(key.into())) else {
            return;
        };
        for v in seq {
            if let Value::String(s) = v {
                let t = norm_token(s);
                self.process_names.insert(t.clone());
                self.process_sources.insert(t.clone(), src);
                if let Some(lb) = entry_label {
                    self.process_match_labels.insert(t, lb.to_string());
                }
            }
        }
    }

    fn try_insert_seq_domains(
        &mut self,
        map: &serde_yaml::Mapping,
        key: &str,
        src: IocEntrySource,
    ) {
        let Some(Value::Sequence(seq)) = map.get(Value::String(key.into())) else {
            return;
        };
        for v in seq {
            if let Value::String(s) = v {
                let d = domain_key(s);
                self.domains.insert(d.clone());
                self.domain_sources.insert(d, src);
            }
        }
    }

    fn try_insert_seq_ips(&mut self, map: &serde_yaml::Mapping, key: &str, src: IocEntrySource) {
        let Some(Value::Sequence(seq)) = map.get(Value::String(key.into())) else {
            return;
        };
        for v in seq {
            if let Value::String(s) = v {
                if let Ok(ip) = s.parse::<IpAddr>() {
                    self.ips.insert(ip);
                    self.ip_sources.insert(ip, src);
                }
            }
        }
    }

    pub fn host_matches_domain(&self, host: &str) -> Option<String> {
        let host = host.trim_end_matches('.').to_lowercase();
        if self.domains.contains(&host) {
            return Some(host);
        }
        let parts: Vec<&str> = host.split('.').collect();
        for i in 1..parts.len() {
            let suffix = parts[i..].join(".");
            if self.domains.contains(&suffix) {
                return Some(suffix);
            }
        }
        None
    }
}

pub fn domain_key(s: &str) -> String {
    let s = s.trim().to_lowercase();
    let s = s.trim_end_matches('.');
    s.trim_start_matches("www.").to_string()
}

pub fn norm_token(s: &str) -> String {
    let s = s.trim().to_lowercase();
    s.strip_suffix(".exe").map(str::to_string).unwrap_or(s)
}

#[cfg(test)]
fn ioc_from_upstream_yaml(yaml: &str) -> Result<IocIndex, String> {
    let mut idx = IocIndex::default();
    idx.ingest_upstream_yaml(yaml, UpstreamPackaging::Bundled)?;
    Ok(idx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use indoc::indoc;
    use pretty_assertions::assert_eq;
    use std::net::Ipv4Addr;

    #[test]
    fn domain_key_normalizes_host() {
        assert_eq!(domain_key("WWW.Example.com."), "example.com");
        assert_eq!(domain_key("  evil.org  "), "evil.org");
        assert_eq!(domain_key("WWW.foo.BAR."), "foo.bar");
    }

    #[test]
    fn norm_token_strips_exe_suffix() {
        assert_eq!(norm_token("Notepad.EXE"), "notepad");
        assert_eq!(norm_token("  CMD.exe  "), "cmd");
        assert_eq!(norm_token("pwsh"), "pwsh");
    }

    #[test]
    fn host_matches_domain_exact_suffix_and_miss() {
        let yaml = indoc! {"
            - websites:
                - tracked.example
            "};
        let idx = ioc_from_upstream_yaml(yaml).expect("yaml");
        assert_eq!(
            idx.host_matches_domain("tracked.example"),
            Some("tracked.example".into())
        );
        assert_eq!(
            idx.host_matches_domain("sub.TRACKED.example."),
            Some("tracked.example".into())
        );
        assert_eq!(idx.host_matches_domain("other.org"), None);
    }

    #[test]
    fn ingest_upstream_yaml_populates_sets() {
        let yaml = indoc! {"
            - name: MalwareProc
              names:
                - Other.EXE
              websites:
                - bad.example
              c2:
                domains:
                  - c2.evil
                ips:
                  - 192.0.2.1
                  - 2001:db8::1
            "};
        let idx = ioc_from_upstream_yaml(yaml).expect("yaml");
        assert!(idx.process_names.contains("malwareproc"));
        assert!(idx.process_names.contains("other"));
        assert!(idx.domains.contains("bad.example"));
        assert!(idx.domains.contains("c2.evil"));
        assert!(idx
            .ips
            .contains(&std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))));
        assert!(idx.ips.contains(&"2001:db8::1".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn ingest_upstream_yaml_rejects_non_sequence_root() {
        let err = ioc_from_upstream_yaml("foo: bar").unwrap_err();
        assert!(
            err.contains("expected top-level array"),
            "unexpected err: {err}"
        );
    }

    #[test]
    fn ingest_upstream_yaml_rejects_invalid_yaml() {
        let err = ioc_from_upstream_yaml("[ ").unwrap_err();
        assert!(err.contains("upstream IOC YAML"), "unexpected err: {err}");
    }
}
