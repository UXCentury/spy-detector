use crate::authenticode::{self, SignatureStatus};
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use sysinfo::{Pid, System};

static SCANNER_ENABLED: AtomicBool = AtomicBool::new(true);

pub fn set_scanner_enabled(enabled: bool) {
    SCANNER_ENABLED.store(enabled, Ordering::Relaxed);
}

pub fn is_scanner_enabled() -> bool {
    SCANNER_ENABLED.load(Ordering::Relaxed)
}

const SOURCE_COOLDOWN: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Warn,
    High,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Warn => "warn",
            Severity::High => "high",
        }
    }

    pub fn is_high(self) -> bool {
        matches!(self, Severity::High)
    }
}

#[derive(Debug, Clone)]
pub struct ThreadEvent {
    pub source_pid: u32,
    pub source_name: String,
    pub source_path: String,
    pub target_pid: u32,
    pub target_name: String,
    pub target_path: String,
}

#[derive(Clone, Copy)]
enum PathPattern {
    Any,
    Basename(&'static str),
    Contains(&'static str),
}

struct KnownBenignPair {
    sources: &'static [&'static str],
    targets: &'static [PathPattern],
}

const KNOWN_BENIGN_PAIRS: &[KnownBenignPair] = &[
    KnownBenignPair {
        sources: &["rustup.exe", "rustup-init.exe"],
        targets: &[
            PathPattern::Basename("rustup.exe"),
            PathPattern::Basename("rustc.exe"),
            PathPattern::Basename("cargo.exe"),
            PathPattern::Contains("\\.rustup\\"),
            PathPattern::Contains("\\.cargo\\bin\\"),
        ],
    },
    KnownBenignPair {
        sources: &["cargo.exe"],
        targets: &[
            PathPattern::Contains("\\.cargo\\"),
            PathPattern::Contains("\\target\\debug\\"),
            PathPattern::Contains("\\target\\release\\"),
        ],
    },
    KnownBenignPair {
        sources: &["node.exe", "npm.cmd", "pnpm.exe", "yarn.exe"],
        targets: &[PathPattern::Contains("\\node_modules\\.bin\\")],
    },
    KnownBenignPair {
        sources: &["python.exe", "pythonw.exe", "conda.exe"],
        targets: &[
            PathPattern::Basename("python.exe"),
            PathPattern::Basename("pythonw.exe"),
            PathPattern::Basename("conda.exe"),
            PathPattern::Contains("\\conda\\"),
            PathPattern::Contains("\\anaconda"),
            PathPattern::Contains("\\miniconda"),
        ],
    },
    KnownBenignPair {
        sources: &["powershell.exe", "pwsh.exe", "cmd.exe"],
        targets: &[PathPattern::Any],
    },
    KnownBenignPair {
        sources: &["git.exe"],
        targets: &[
            PathPattern::Basename("git.exe"),
            PathPattern::Contains("\\git\\cmd\\"),
            PathPattern::Contains("\\git\\mingw"),
            PathPattern::Contains("\\git\\usr\\bin\\"),
        ],
    },
    KnownBenignPair {
        sources: &["cursor.exe", "code.exe"],
        targets: &[
            PathPattern::Basename("cursor.exe"),
            PathPattern::Basename("code.exe"),
            PathPattern::Basename("powershell.exe"),
            PathPattern::Basename("pwsh.exe"),
            PathPattern::Contains("\\extension"),
            PathPattern::Contains("\\language"),
            PathPattern::Contains("\\node_modules\\"),
        ],
    },
];

#[derive(Default)]
pub struct ThreadInjectionFilter {
    signer_cache: HashMap<String, Option<String>>,
    recent_source_alerts: HashMap<u32, Instant>,
    #[cfg(test)]
    signer_overrides: HashMap<String, Option<String>>,
    #[cfg(test)]
    signature_overrides: HashMap<String, SignatureStatus>,
    #[cfg(test)]
    writable_overrides: HashMap<String, bool>,
    #[cfg(test)]
    parent_overrides: HashMap<u32, Option<u32>>,
    #[cfg(test)]
    now_override: Option<Instant>,
}

impl ThreadInjectionFilter {
    pub fn should_alert(&mut self, event: &ThreadEvent, sysinfo: &System) -> Option<Severity> {
        if event.source_pid == event.target_pid {
            return None;
        }
        if self.is_parent_child_or_same_group(event, sysinfo) {
            return None;
        }
        if same_non_empty_path(&event.source_path, &event.target_path) {
            return None;
        }
        if self.same_publisher(event) {
            return None;
        }
        if is_known_benign_pair(event) {
            return None;
        }
        if self.source_in_cooldown(event.source_pid) {
            return None;
        }

        let severity = if self.is_unsigned_user_writable_target(event) {
            Severity::High
        } else {
            Severity::Warn
        };
        self.note_source_alert(event.source_pid);
        Some(severity)
    }

    fn is_parent_child_or_same_group(&self, event: &ThreadEvent, sysinfo: &System) -> bool {
        let source_parent = self.parent_pid(event.source_pid, sysinfo);
        let target_parent = self.parent_pid(event.target_pid, sysinfo);

        source_parent == Some(event.target_pid)
            || target_parent == Some(event.source_pid)
            || (source_parent.is_some() && source_parent == target_parent)
    }

    fn parent_pid(&self, pid: u32, sysinfo: &System) -> Option<u32> {
        #[cfg(test)]
        if let Some(parent) = self.parent_overrides.get(&pid) {
            return *parent;
        }

        sysinfo
            .process(Pid::from_u32(pid))
            .and_then(|p| p.parent())
            .map(|p| p.as_u32())
    }

    fn same_publisher(&mut self, event: &ThreadEvent) -> bool {
        let src = Path::new(&event.source_path);
        let tgt = Path::new(&event.target_path);
        if !matches!(self.signature_status(src), SignatureStatus::Signed)
            || !matches!(self.signature_status(tgt), SignatureStatus::Signed)
        {
            return false;
        }

        match (self.signer_subject(src), self.signer_subject(tgt)) {
            (Some(a), Some(b)) if normalize_subject(&a) == normalize_subject(&b) => true,
            _ => match (publisher_path_hint(src), publisher_path_hint(tgt)) {
                (Some(a), Some(b)) => a == b,
                _ => false,
            },
        }
    }

    fn signer_subject(&mut self, path: &Path) -> Option<String> {
        let key = normalize_path(path);
        #[cfg(test)]
        if let Some(subject) = self.signer_overrides.get(&key) {
            return subject.clone();
        }
        if let Some(subject) = self.signer_cache.get(&key) {
            return subject.clone();
        }
        let subject = authenticode::signer_subject(path);
        self.signer_cache.insert(key, subject.clone());
        subject
    }

    fn signature_status(&self, path: &Path) -> SignatureStatus {
        #[cfg(test)]
        if let Some(status) = self.signature_overrides.get(&normalize_path(path)) {
            return *status;
        }
        authenticode::is_signed(path)
    }

    fn is_user_writable_path(&self, path: &Path) -> bool {
        #[cfg(test)]
        if let Some(is_writable) = self.writable_overrides.get(&normalize_path(path)) {
            return *is_writable;
        }
        authenticode::is_in_user_writable_path(path)
    }

    fn is_unsigned_user_writable_target(&self, event: &ThreadEvent) -> bool {
        let target_path = Path::new(&event.target_path);
        matches!(
            self.signature_status(target_path),
            SignatureStatus::Unsigned
        ) && self.is_user_writable_path(target_path)
    }

    fn source_in_cooldown(&mut self, source_pid: u32) -> bool {
        let now = self.now();
        self.recent_source_alerts
            .retain(|_, then| now.duration_since(*then) < SOURCE_COOLDOWN);
        self.recent_source_alerts
            .get(&source_pid)
            .is_some_and(|then| now.duration_since(*then) < SOURCE_COOLDOWN)
    }

    fn note_source_alert(&mut self, source_pid: u32) {
        let now = self.now();
        self.recent_source_alerts.insert(source_pid, now);
    }

    fn now(&self) -> Instant {
        #[cfg(test)]
        if let Some(now) = self.now_override {
            return now;
        }
        Instant::now()
    }
}

fn is_known_benign_pair(event: &ThreadEvent) -> bool {
    let source_base = basename(&event.source_name, &event.source_path);
    KNOWN_BENIGN_PAIRS.iter().any(|pair| {
        pair.sources.iter().any(|src| source_base == *src)
            && pair
                .targets
                .iter()
                .any(|pattern| pattern_matches(*pattern, &event.target_name, &event.target_path))
    })
}

fn pattern_matches(pattern: PathPattern, name: &str, path: &str) -> bool {
    match pattern {
        PathPattern::Any => true,
        PathPattern::Basename(expected) => basename(name, path) == expected,
        PathPattern::Contains(needle) => normalize_str(path).contains(&normalize_str(needle)),
    }
}

fn same_non_empty_path(a: &str, b: &str) -> bool {
    let a = normalize_str(a);
    let b = normalize_str(b);
    !a.is_empty() && a == b
}

fn basename(name: &str, path: &str) -> String {
    Path::new(path)
        .file_name()
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty())
        .unwrap_or(name)
        .to_lowercase()
}

fn normalize_path(path: &Path) -> String {
    normalize_str(&path.to_string_lossy())
}

fn normalize_str(value: &str) -> String {
    value.trim().replace('/', "\\").to_lowercase()
}

fn normalize_subject(value: &str) -> String {
    value.trim().to_lowercase()
}

fn publisher_path_hint(path: &Path) -> Option<String> {
    let p = normalize_path(path);
    for env_name in ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"] {
        let Ok(root) = std::env::var(env_name) else {
            continue;
        };
        let root = normalize_str(&root);
        let root = root.trim_end_matches('\\');
        let Some(rel) = p.strip_prefix(&(root.to_string() + "\\")) else {
            continue;
        };
        let vendor = rel.split('\\').next().unwrap_or_default();
        if !vendor.is_empty() {
            return Some(format!("programfiles:{vendor}"));
        }
    }
    let windir = std::env::var("WINDIR").unwrap_or_else(|_| "c:\\windows".into());
    let windir = normalize_str(&windir);
    if p.starts_with(&(windir.trim_end_matches('\\').to_string() + "\\"))
        || p.starts_with("c:\\windows\\")
    {
        return Some("windows".into());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn event(source_pid: u32, source: &str, target_pid: u32, target: &str) -> ThreadEvent {
        ThreadEvent {
            source_pid,
            source_name: basename_from_path(source),
            source_path: source.to_string(),
            target_pid,
            target_name: basename_from_path(target),
            target_path: target.to_string(),
        }
    }

    fn basename_from_path(path: &str) -> String {
        Path::new(path)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(path)
            .to_string()
    }

    fn filter() -> ThreadInjectionFilter {
        ThreadInjectionFilter {
            now_override: Some(Instant::now()),
            ..ThreadInjectionFilter::default()
        }
    }

    impl ThreadInjectionFilter {
        fn with_parent(mut self, pid: u32, parent: Option<u32>) -> Self {
            self.parent_overrides.insert(pid, parent);
            self
        }

        fn with_signature(mut self, path: &str, status: SignatureStatus) -> Self {
            self.signature_overrides.insert(normalize_str(path), status);
            self
        }

        fn with_signer(mut self, path: &str, signer: Option<&str>) -> Self {
            self.signer_overrides
                .insert(normalize_str(path), signer.map(str::to_string));
            self
        }

        fn with_writable(mut self, path: &str, is_writable: bool) -> Self {
            self.writable_overrides
                .insert(normalize_str(path), is_writable);
            self
        }

        fn advance(&mut self, duration: Duration) {
            self.now_override = self.now_override.map(|now| now + duration);
        }
    }

    #[test]
    fn same_publisher_pair_suppresses() {
        let src = r"C:\Program Files\Vendor\a.exe";
        let tgt = r"C:\Program Files\Vendor\b.exe";
        let mut filter = filter()
            .with_signature(src, SignatureStatus::Signed)
            .with_signature(tgt, SignatureStatus::Signed)
            .with_signer(src, Some("Vendor Inc."))
            .with_signer(tgt, Some("Vendor Inc."));

        assert_eq!(
            filter.should_alert(&event(10, src, 20, tgt), &System::new()),
            None
        );
    }

    #[test]
    fn parent_child_pair_suppresses() {
        let src = r"C:\Tools\parent.exe";
        let tgt = r"C:\Tools\child.exe";
        let mut filter = filter().with_parent(20, Some(10));

        assert_eq!(
            filter.should_alert(&event(10, src, 20, tgt), &System::new()),
            None
        );
    }

    #[test]
    fn shell_to_any_child_suppresses() {
        let src = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
        let tgt = r"C:\Users\dev\AppData\Local\Temp\dosky.exe";
        let mut filter = filter();

        assert_eq!(
            filter.should_alert(&event(10, src, 20, tgt), &System::new()),
            None
        );
    }

    #[test]
    fn unsigned_target_in_temp_emits_high() {
        let src = r"C:\Tools\injector.exe";
        let tgt = r"C:\Users\dev\AppData\Local\Temp\payload.exe";
        let mut filter = filter()
            .with_signature(src, SignatureStatus::Signed)
            .with_signature(tgt, SignatureStatus::Unsigned)
            .with_signer(src, Some("Tool Vendor"))
            .with_signer(tgt, None)
            .with_writable(tgt, true);

        assert_eq!(
            filter.should_alert(&event(10, src, 20, tgt), &System::new()),
            Some(Severity::High)
        );
    }

    #[test]
    fn same_source_twice_within_sixty_seconds_is_rate_limited() {
        let src = r"C:\Tools\injector.exe";
        let tgt1 = r"C:\Users\dev\AppData\Local\Temp\payload1.exe";
        let tgt2 = r"C:\Users\dev\AppData\Local\Temp\payload2.exe";
        let mut filter = filter()
            .with_signature(src, SignatureStatus::Signed)
            .with_signature(tgt1, SignatureStatus::Unsigned)
            .with_signature(tgt2, SignatureStatus::Unsigned)
            .with_writable(tgt1, true)
            .with_writable(tgt2, true);

        assert_eq!(
            filter.should_alert(&event(10, src, 20, tgt1), &System::new()),
            Some(Severity::High)
        );
        assert_eq!(
            filter.should_alert(&event(10, src, 21, tgt2), &System::new()),
            None
        );
    }

    #[test]
    fn two_distinct_sources_within_sixty_seconds_both_emit() {
        let src1 = r"C:\Tools\injector1.exe";
        let src2 = r"C:\Tools\injector2.exe";
        let tgt1 = r"C:\Users\dev\AppData\Local\Temp\payload1.exe";
        let tgt2 = r"C:\Users\dev\AppData\Local\Temp\payload2.exe";
        let mut filter = filter()
            .with_signature(src1, SignatureStatus::Signed)
            .with_signature(src2, SignatureStatus::Signed)
            .with_signature(tgt1, SignatureStatus::Unsigned)
            .with_signature(tgt2, SignatureStatus::Unsigned)
            .with_writable(tgt1, true)
            .with_writable(tgt2, true);

        assert_eq!(
            filter.should_alert(&event(10, src1, 20, tgt1), &System::new()),
            Some(Severity::High)
        );
        assert_eq!(
            filter.should_alert(&event(11, src2, 21, tgt2), &System::new()),
            Some(Severity::High)
        );
    }

    #[test]
    fn source_cooldown_expires_after_sixty_seconds() {
        let src = r"C:\Tools\injector.exe";
        let tgt1 = r"C:\Users\dev\AppData\Local\Temp\payload1.exe";
        let tgt2 = r"C:\Users\dev\AppData\Local\Temp\payload2.exe";
        let mut filter = filter()
            .with_signature(src, SignatureStatus::Signed)
            .with_signature(tgt1, SignatureStatus::Unsigned)
            .with_signature(tgt2, SignatureStatus::Unsigned)
            .with_writable(tgt1, true)
            .with_writable(tgt2, true);

        assert_eq!(
            filter.should_alert(&event(10, src, 20, tgt1), &System::new()),
            Some(Severity::High)
        );
        filter.advance(Duration::from_secs(61));
        assert_eq!(
            filter.should_alert(&event(10, src, 21, tgt2), &System::new()),
            Some(Severity::High)
        );
    }
}
