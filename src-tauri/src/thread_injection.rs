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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadBurstUserOutcome {
    ScannerDisabled,
    /// Our own executable — no DB, emit, or unified log row.
    DroppedSelf,
    /// Kernel / System–attributed source — no user-visible rows.
    SuppressedKernelIssued,
    /// SCM starting a signed service image — no user-visible rows.
    SuppressedScmSignedService,
    SuppressedSameImage,
    SuppressedSamePublisher,
    RateLimited,
    AlertWarn,
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

const SELF_EXE_BASE: &str = "spy-detector.exe";

/// True when the process image basename is our own EXE (installation path may vary).
pub(crate) fn is_self_exe(path: &str, process_name_fallback: &str) -> bool {
    let base = Path::new(path.trim())
        .file_name()
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| process_name_fallback.trim())
        .to_lowercase();
    base == SELF_EXE_BASE
}

/// PID 4 is the NT kernel; threads attributed to it are kernel-issued and never user-mode injection.
fn is_kernel_thread_source(event: &ThreadEvent) -> bool {
    if event.source_pid == 4 {
        return true;
    }
    matches!(
        basename(&event.source_name, &event.source_path).as_str(),
        "system" | "registry"
    )
}

#[derive(Clone, Copy)]
enum PathPattern {
    Any,
    Basename(&'static str),
    BasenameStartsWith(&'static str),
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
            PathPattern::Basename("clippy-driver.exe"),
            PathPattern::Basename("rustc.exe"),
            PathPattern::BasenameStartsWith("cargo-"),
            PathPattern::Contains("\\.cargo\\"),
            PathPattern::Contains("\\target\\debug\\"),
            PathPattern::Contains("\\target\\release\\"),
        ],
    },
    KnownBenignPair {
        sources: &["clippy-driver.exe"],
        targets: &[PathPattern::Basename("cmd.exe")],
    },
    KnownBenignPair {
        sources: &["rustc.exe"],
        targets: &[PathPattern::Basename("cmd.exe")],
    },
    KnownBenignPair {
        sources: &["cargo-fmt.exe"],
        targets: &[PathPattern::Basename("cargo.exe")],
    },
    KnownBenignPair {
        sources: &["node.exe", "npm.cmd", "pnpm.exe", "yarn.exe"],
        targets: &[
            PathPattern::Contains("\\node_modules\\.bin\\"),
            PathPattern::Basename("git.exe"),
            PathPattern::Basename("npm.cmd"),
            PathPattern::Basename("npx.cmd"),
        ],
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
            PathPattern::Basename("git.exe"),
            PathPattern::Basename("cmd.exe"),
            PathPattern::Basename("powershell.exe"),
            PathPattern::Basename("pwsh.exe"),
            PathPattern::Basename("rg.exe"),
            PathPattern::Contains("\\extension"),
            PathPattern::Contains("\\language"),
            PathPattern::Contains("\\node_modules\\"),
        ],
    },
    KnownBenignPair {
        sources: &["sh.exe"],
        targets: &[
            PathPattern::Basename("cygpath.exe"),
            PathPattern::Basename("uname.exe"),
            PathPattern::Basename("dirname.exe"),
            PathPattern::Basename("sed.exe"),
            PathPattern::Basename("grep.exe"),
            PathPattern::Basename("git.exe"),
            PathPattern::Basename("bash.exe"),
        ],
    },
    KnownBenignPair {
        sources: &["bash.exe"],
        targets: &[
            PathPattern::Contains("\\msys64\\"),
            PathPattern::Contains("\\depot_tools\\"),
            PathPattern::Contains("\\git\\usr\\bin\\"),
        ],
    },
    KnownBenignPair {
        sources: &["msedgewebview2.exe"],
        targets: &[PathPattern::Basename("msedgewebview2.exe")],
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
    pub fn evaluate_thread_burst_alert(
        &mut self,
        event: &ThreadEvent,
        _sysinfo: &System,
    ) -> ThreadBurstUserOutcome {
        if !is_scanner_enabled() {
            return ThreadBurstUserOutcome::ScannerDisabled;
        }
        if is_self_exe(&event.source_path, &event.source_name)
            || is_self_exe(&event.target_path, &event.target_name)
        {
            return ThreadBurstUserOutcome::DroppedSelf;
        }
        if is_kernel_thread_source(event) {
            return ThreadBurstUserOutcome::SuppressedKernelIssued;
        }
        if self.suppress_scm_signed_service_spawn(event) {
            return ThreadBurstUserOutcome::SuppressedScmSignedService;
        }
        if same_non_empty_path(&event.source_path, &event.target_path) {
            return ThreadBurstUserOutcome::SuppressedSameImage;
        }
        if self.same_publisher(event) {
            return ThreadBurstUserOutcome::SuppressedSamePublisher;
        }
        if self.source_in_cooldown(event.source_pid) {
            return ThreadBurstUserOutcome::RateLimited;
        }
        self.note_source_alert(event.source_pid);
        ThreadBurstUserOutcome::AlertWarn
    }

    /// Same signed publisher and same image basename (e.g. multi-process WebView2) — not injection noise.
    pub(crate) fn drops_signed_same_basename_same_publisher(
        &mut self,
        event: &ThreadEvent,
    ) -> bool {
        let sb = basename(&event.source_name, &event.source_path);
        let tb = basename(&event.target_name, &event.target_path);
        sb == tb && self.same_publisher(event)
    }

    pub fn should_alert(&mut self, event: &ThreadEvent, sysinfo: &System) -> Option<Severity> {
        if is_self_exe(&event.source_path, &event.source_name)
            || is_self_exe(&event.target_path, &event.target_name)
        {
            return None;
        }
        if is_kernel_thread_source(event) {
            return None;
        }
        if self.suppress_scm_signed_service_spawn(event) {
            return None;
        }
        if event.source_pid == event.target_pid {
            return None;
        }
        if basename(&event.target_name, &event.target_path) == "conhost.exe" {
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

    /// Service Control Manager (`services.exe`) legitimately creates threads in signed service
    /// processes; only suppress when the target image is clearly signed (not Unsigned / Unknown).
    fn suppress_scm_signed_service_spawn(&self, event: &ThreadEvent) -> bool {
        if basename(&event.source_name, &event.source_path) != "services.exe" {
            return false;
        }
        let src_trim = event.source_path.trim();
        if src_trim.is_empty() {
            return false;
        }
        let windir = std::env::var("WINDIR").unwrap_or_else(|_| r"C:\Windows".into());
        let expected = authenticode::normalize_image_path(
            &Path::new(windir.trim())
                .join("System32")
                .join("services.exe"),
        );
        let src_norm = authenticode::normalize_image_path(Path::new(src_trim));
        if normalize_str(&src_norm.to_string_lossy()) != normalize_str(&expected.to_string_lossy())
        {
            return false;
        }
        matches!(
            self.signature_status(Path::new(event.target_path.trim())),
            SignatureStatus::Signed
        )
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
        PathPattern::BasenameStartsWith(prefix) => basename(name, path).starts_with(prefix),
        PathPattern::Contains(needle) => normalize_str(path).contains(&normalize_str(needle)),
    }
}

fn same_non_empty_path(a: &str, b: &str) -> bool {
    let a = a.trim();
    let b = b.trim();
    if a.is_empty() || b.is_empty() {
        return false;
    }
    let na = authenticode::normalize_image_path(Path::new(a));
    let nb = authenticode::normalize_image_path(Path::new(b));
    normalize_str(&na.to_string_lossy()) == normalize_str(&nb.to_string_lossy())
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

    #[test]
    fn git_to_conhost_suppresses() {
        let src = r"C:\Program Files\Git\bin\git.exe";
        let tgt = r"C:\Windows\System32\conhost.exe";
        let mut filter = filter();
        assert_eq!(
            filter.should_alert(&event(10, src, 20, tgt), &System::new()),
            None
        );
    }

    #[test]
    fn random_to_conhost_suppresses() {
        let src = r"C:\Tools\random.exe";
        let tgt = r"C:\Windows\System32\conhost.exe";
        let mut filter = filter();
        assert_eq!(
            filter.should_alert(&event(10, src, 20, tgt), &System::new()),
            None
        );
    }

    #[test]
    fn cursor_to_git_suppresses() {
        let src = r"C:\Users\dev\AppData\Local\Programs\cursor\Cursor.exe";
        let tgt = r"C:\Program Files\Git\bin\git.exe";
        let mut filter = filter();
        assert_eq!(
            filter.should_alert(&event(10, src, 20, tgt), &System::new()),
            None
        );
    }

    #[test]
    fn cargo_to_clippy_driver_suppresses() {
        let src = r"C:\Users\dev\.cargo\bin\cargo.exe";
        let tgt = r"C:\Users\dev\.rustup\toolchains\stable\lib\clippy-driver.exe";
        let mut filter = filter();
        assert_eq!(
            filter.should_alert(&event(10, src, 20, tgt), &System::new()),
            None
        );
    }

    #[test]
    fn sh_to_cygpath_suppresses() {
        let src = r"C:\msys64\usr\bin\sh.exe";
        let tgt = r"C:\msys64\usr\bin\cygpath.exe";
        let mut filter = filter();
        assert_eq!(
            filter.should_alert(&event(10, src, 20, tgt), &System::new()),
            None
        );
    }

    #[test]
    fn msedge_webview2_self_suppresses() {
        let p = r"C:\Program Files (x86)\Microsoft\EdgeWebView\Application\msedgewebview2.exe";
        let mut filter = filter();
        assert_eq!(
            filter.should_alert(&event(10, p, 20, p), &System::new()),
            None
        );
    }

    #[test]
    fn unsigned_cross_process_without_gates_emits_high() {
        let src = r"C:\Tools\evilthing.exe";
        let tgt = r"C:\Users\dev\AppData\Local\Temp\notepad_stub.exe";
        let mut filter = filter()
            .with_signature(src, SignatureStatus::Unsigned)
            .with_signature(tgt, SignatureStatus::Unsigned)
            .with_writable(tgt, true);
        assert_eq!(
            filter.should_alert(&event(10, src, 20, tgt), &System::new()),
            Some(Severity::High)
        );
    }

    #[test]
    fn thread_burst_same_image_suppresses() {
        let p = r"C:\Tools\overlay\LogiOverlay.exe";
        let mut filter = filter();
        let ev = ThreadEvent {
            source_pid: 10,
            source_name: "LogiOverlay.exe".into(),
            source_path: p.into(),
            target_pid: 11,
            target_name: "LogiOverlay.exe".into(),
            target_path: p.into(),
        };
        assert_eq!(
            filter.evaluate_thread_burst_alert(&ev, &System::new()),
            ThreadBurstUserOutcome::SuppressedSameImage
        );
    }

    #[test]
    fn thread_burst_same_publisher_suppresses() {
        let src = r"C:\Program Files\Vendor\a.exe";
        let tgt = r"C:\Program Files\Vendor\b.exe";
        let mut filter = filter()
            .with_signature(src, SignatureStatus::Signed)
            .with_signature(tgt, SignatureStatus::Signed)
            .with_signer(src, Some("Vendor Inc."))
            .with_signer(tgt, Some("Vendor Inc."));
        let ev = ThreadEvent {
            source_pid: 10,
            source_name: "a.exe".into(),
            source_path: src.into(),
            target_pid: 20,
            target_name: "b.exe".into(),
            target_path: tgt.into(),
        };
        assert_eq!(
            filter.evaluate_thread_burst_alert(&ev, &System::new()),
            ThreadBurstUserOutcome::SuppressedSamePublisher
        );
    }

    #[test]
    fn thread_burst_rate_limited_after_alert() {
        let src = r"C:\A\x.exe";
        let tgt = r"C:\B\y.exe";
        let mut filter = filter()
            .with_signature(src, SignatureStatus::Unsigned)
            .with_signature(tgt, SignatureStatus::Unsigned)
            .with_writable(tgt, true);
        let ev1 = ThreadEvent {
            source_pid: 100,
            source_name: "x.exe".into(),
            source_path: src.into(),
            target_pid: 200,
            target_name: "y.exe".into(),
            target_path: tgt.into(),
        };
        assert_eq!(
            filter.evaluate_thread_burst_alert(&ev1, &System::new()),
            ThreadBurstUserOutcome::AlertWarn
        );
        let ev2 = ThreadEvent {
            source_pid: 100,
            source_name: "x.exe".into(),
            source_path: src.into(),
            target_pid: 201,
            target_name: "y.exe".into(),
            target_path: tgt.into(),
        };
        assert_eq!(
            filter.evaluate_thread_burst_alert(&ev2, &System::new()),
            ThreadBurstUserOutcome::RateLimited
        );
    }

    #[test]
    fn thread_burst_scanner_disabled_is_quiet() {
        set_scanner_enabled(false);
        let src = r"C:\A\x.exe";
        let tgt = r"C:\B\y.exe";
        let mut filter = filter();
        let ev = ThreadEvent {
            source_pid: 1,
            source_name: "x.exe".into(),
            source_path: src.into(),
            target_pid: 2,
            target_name: "y.exe".into(),
            target_path: tgt.into(),
        };
        assert_eq!(
            filter.evaluate_thread_burst_alert(&ev, &System::new()),
            ThreadBurstUserOutcome::ScannerDisabled
        );
        set_scanner_enabled(true);
    }

    #[test]
    fn in_process_same_pid_suppresses_should_alert() {
        let p = r"C:\Tools\worker.exe";
        assert_eq!(
            filter().should_alert(&event(42, p, 42, p), &System::new()),
            None
        );
    }

    #[test]
    fn spy_detector_as_source_suppresses_should_alert() {
        let sd = r"C:\Program Files\Spy Detector\spy-detector.exe";
        let tgt = r"C:\Users\dev\AppData\Local\Temp\notepad_stub.exe";
        assert_eq!(
            filter().should_alert(&event(10, sd, 20, tgt), &System::new()),
            None
        );
    }

    #[test]
    fn spy_detector_as_target_suppresses_should_alert() {
        let src = r"C:\Tools\injector.exe";
        let sd = r"C:\Portable\spy-detector.exe";
        assert_eq!(
            filter().should_alert(&event(10, src, 20, sd), &System::new()),
            None
        );
    }

    #[test]
    fn webviewhost_cross_pid_same_publisher_suppresses_should_alert() {
        let src = r"C:\Windows\System32\webviewhost.exe";
        let tgt = r"C:\Windows\SysWOW64\webviewhost.exe";
        let mut filter = filter()
            .with_signature(src, SignatureStatus::Signed)
            .with_signature(tgt, SignatureStatus::Signed)
            .with_signer(src, Some("Microsoft Corporation"))
            .with_signer(tgt, Some("Microsoft Corporation"));
        assert_eq!(
            filter.should_alert(&event(10, src, 11, tgt), &System::new()),
            None
        );
    }

    #[test]
    fn thread_burst_spy_detector_returns_dropped_self() {
        let p = r"C:\Program Files\Spy Detector\spy-detector.exe";
        let mut filter = filter();
        let ev = ThreadEvent {
            source_pid: 10,
            source_name: "spy-detector.exe".into(),
            source_path: p.into(),
            target_pid: 11,
            target_name: "spy-detector.exe".into(),
            target_path: p.into(),
        };
        assert_eq!(
            filter.evaluate_thread_burst_alert(&ev, &System::new()),
            ThreadBurstUserOutcome::DroppedSelf
        );
    }

    #[test]
    fn kernel_pid_four_suppresses_thread_alert_to_chrome() {
        let chrome = r"C:\Program Files\Google\Chrome\Application\chrome.exe";
        let mut filter = filter().with_signature(chrome, SignatureStatus::Signed);
        let ev = ThreadEvent {
            source_pid: 4,
            source_name: "System".into(),
            source_path: String::new(),
            target_pid: 35872,
            target_name: "chrome.exe".into(),
            target_path: chrome.into(),
        };
        assert_eq!(filter.should_alert(&ev, &System::new()), None);
    }

    #[test]
    fn kernel_pid_four_suppresses_thread_alert_to_msedgewebview2() {
        let wv = r"C:\Program Files (x86)\Microsoft\EdgeWebView\Application\147.0.3912.98\msedgewebview2.exe";
        let mut filter = filter().with_signature(wv, SignatureStatus::Signed);
        let ev = ThreadEvent {
            source_pid: 4,
            source_name: "System".into(),
            source_path: String::new(),
            target_pid: 27024,
            target_name: "msedgewebview2.exe".into(),
            target_path: wv.into(),
        };
        assert_eq!(filter.should_alert(&ev, &System::new()), None);
    }

    #[test]
    fn services_exe_to_signed_elevation_service_suppresses_should_alert() {
        let windir = std::env::var("WINDIR").unwrap_or_else(|_| r"C:\Windows".into());
        let svc = format!(r"{windir}\System32\services.exe");
        let tgt =
            r"C:\Program Files\Google\Chrome\Application\147.0.7727.139\elevation_service.exe";
        let mut filter = filter()
            .with_signature(&svc, SignatureStatus::Signed)
            .with_signature(tgt, SignatureStatus::Signed)
            .with_signer(&svc, Some("Microsoft Windows"))
            .with_signer(tgt, Some("Google LLC"));
        let ev = ThreadEvent {
            source_pid: 1412,
            source_name: "services.exe".into(),
            source_path: svc,
            target_pid: 32236,
            target_name: "elevation_service.exe".into(),
            target_path: tgt.into(),
        };
        assert_eq!(filter.should_alert(&ev, &System::new()), None);
    }

    #[test]
    fn services_exe_to_unsigned_target_still_alerts_high() {
        let windir = std::env::var("WINDIR").unwrap_or_else(|_| r"C:\Windows".into());
        let svc = format!(r"{windir}\System32\services.exe");
        let tgt = r"C:\Users\dev\AppData\Local\Temp\unsigned_svc_stub.exe";
        let mut filter = filter()
            .with_signature(&svc, SignatureStatus::Signed)
            .with_signature(tgt, SignatureStatus::Unsigned)
            .with_writable(tgt, true);
        let ev = ThreadEvent {
            source_pid: 1412,
            source_name: "services.exe".into(),
            source_path: svc,
            target_pid: 32236,
            target_name: "unsigned_svc_stub.exe".into(),
            target_path: tgt.into(),
        };
        assert_eq!(
            filter.should_alert(&ev, &System::new()),
            Some(Severity::High)
        );
    }

    #[test]
    fn non_services_source_not_suppressed_by_scm_gate() {
        let src = r"C:\Tools\not-services.exe";
        let tgt =
            r"C:\Program Files\Google\Chrome\Application\147.0.7727.139\elevation_service.exe";
        let mut filter = filter()
            .with_signature(src, SignatureStatus::Signed)
            .with_signature(tgt, SignatureStatus::Signed)
            .with_signer(src, Some("Other Publisher"))
            .with_signer(tgt, Some("Google LLC"));
        assert_eq!(
            filter.should_alert(&event(10, src, 20, tgt), &System::new()),
            Some(Severity::Warn)
        );
    }
}
