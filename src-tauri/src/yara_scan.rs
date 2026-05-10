use serde::Serialize;
use std::collections::HashMap;
use std::path::Path;
use std::sync::OnceLock;
use yara_x::{Compiler, MetaValue, Scanner, SourceCode};

static GLOBAL_INDEX: OnceLock<Result<YaraIndex, String>> = OnceLock::new();

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct YaraMatch {
    pub rule_name: String,
    pub source_file: String,
    pub tags: Vec<String>,
    pub meta: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct YaraSourceInfo {
    pub slug: String,
    pub path: String,
    pub rule_count: u32,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct YaraStatus {
    pub rule_count: u32,
    pub sources: Vec<YaraSourceInfo>,
}

pub struct YaraIndex {
    rules: yara_x::Rules,
    rule_count: u32,
    sources: Vec<YaraSourceInfo>,
}

const SOURCE_APT: (&str, &str, &str) = (
    "apt_general",
    "resources/yara/apt_general.yar",
    include_str!("../resources/yara/apt_general.yar"),
);
const SOURCE_WINMAL: (&str, &str, &str) = (
    "windows_malware",
    "resources/yara/windows_malware.yar",
    include_str!("../resources/yara/windows_malware.yar"),
);
const SOURCE_STALKER: (&str, &str, &str) = (
    "stalkerware",
    "resources/yara/stalkerware.yar",
    include_str!("../resources/yara/stalkerware.yar"),
);

fn count_rules_in_source(src: &str) -> u32 {
    src.lines()
        .filter(|line| {
            let t = line.trim_start();
            if t.starts_with("//") {
                return false;
            }
            t.starts_with("rule ")
                || t.starts_with("private rule ")
                || t.starts_with("global rule ")
                || t.starts_with("global private rule ")
                || t.starts_with("private global rule ")
        })
        .count() as u32
}

impl YaraIndex {
    pub fn load_embedded() -> Result<Self, String> {
        let bundles = [SOURCE_APT, SOURCE_WINMAL, SOURCE_STALKER];
        let mut compiler = Compiler::new();
        let mut sources_meta: Vec<YaraSourceInfo> = Vec::new();
        let mut rule_total: u32 = 0;

        for (slug, path, text) in bundles {
            let rc = count_rules_in_source(text);
            rule_total += rc;
            sources_meta.push(YaraSourceInfo {
                slug: slug.to_string(),
                path: path.to_string(),
                rule_count: rc,
            });
            compiler
                .add_source(SourceCode::from(text).with_origin(path.to_string()))
                .map_err(|e| format!("{path}: {e}"))?;
        }

        let rules = compiler.build();
        Ok(YaraIndex {
            rules,
            rule_count: rule_total,
            sources: sources_meta,
        })
    }

    pub fn rule_count(&self) -> u32 {
        self.rule_count
    }

    pub fn status(&self) -> YaraStatus {
        YaraStatus {
            rule_count: self.rule_count,
            sources: self.sources.clone(),
        }
    }

    pub fn match_path(&self, path: &Path) -> Result<Vec<YaraMatch>, String> {
        let mut scanner = Scanner::new(&self.rules);
        let results = scanner
            .scan_file(path)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        Ok(Self::collect_matches(&results))
    }

    #[allow(dead_code)]
    pub fn match_bytes(&self, bytes: &[u8]) -> Result<Vec<YaraMatch>, String> {
        let mut scanner = Scanner::new(&self.rules);
        let results = scanner.scan(bytes).map_err(|e| format!("yara scan: {e}"))?;
        Ok(Self::collect_matches(&results))
    }

    fn collect_matches(results: &yara_x::ScanResults<'_, '_>) -> Vec<YaraMatch> {
        let mut out = Vec::new();
        for rule in results.matching_rules() {
            let rule_name = rule.identifier().to_string();
            let mut source_file = String::from("unknown");
            let mut meta_map = HashMap::new();
            for (k, v) in rule.metadata() {
                let vs = match v {
                    MetaValue::String(s) => s.to_string(),
                    MetaValue::Integer(i) => i.to_string(),
                    MetaValue::Bool(b) => b.to_string(),
                    MetaValue::Float(f) => f.to_string(),
                    MetaValue::Bytes(_) => continue,
                };
                if k == "source" {
                    source_file = vs.clone();
                }
                meta_map.insert(k.to_string(), vs);
            }
            let tags: Vec<String> = rule.tags().map(|t| t.identifier().to_string()).collect();
            out.push(YaraMatch {
                rule_name,
                source_file,
                tags,
                meta: meta_map,
            });
        }
        out
    }
}

pub fn global_index() -> Option<&'static YaraIndex> {
    GLOBAL_INDEX.get().and_then(|r| r.as_ref().ok())
}

pub fn global_load_error() -> Option<&'static str> {
    GLOBAL_INDEX
        .get()
        .and_then(|r| r.as_ref().err().map(|s| s.as_str()))
}

pub fn init_global_index() {
    let _ = GLOBAL_INDEX.set(YaraIndex::load_embedded());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_rules_compile() {
        let idx = YaraIndex::load_embedded().expect("embedded yara");
        assert!(idx.rule_count() >= 1);
    }

    #[test]
    fn match_bytes_finds_known_string() {
        let idx = YaraIndex::load_embedded().expect("embedded yara");
        let buf = b"MZ\x00\x00UPX0xxxxUPX1";
        let m = idx.match_bytes(buf).expect("scan");
        assert!(
            m.iter().any(|x| x.rule_name == "upx_like_sections"),
            "{m:?}"
        );
    }
}
