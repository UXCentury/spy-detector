//! Best-effort cleanup of stale `spy-detector-*` ETW sessions left over from
//! previous runs that crashed without unwinding.

use std::collections::BTreeSet;

/// Extract session names from `logman query -ets` stdout: lines containing
/// `spy-detector-`, first whitespace-delimited token taken as the name.
pub(crate) fn parse_spy_detector_sessions_from_logman(output: &str) -> Vec<String> {
    let mut out = BTreeSet::new();
    for line in output.lines() {
        let line = line.trim();
        if !line.contains("spy-detector-") {
            continue;
        }
        let Some(first) = line.split_whitespace().next() else {
            continue;
        };
        if first.contains("spy-detector-") {
            out.insert(first.to_string());
        }
    }
    out.into_iter().collect()
}

fn embedded_pid_from_session_name(name: &str) -> Option<u32> {
    let rest = name.rsplit_once('-')?.1;
    rest.parse().ok()
}

fn should_attempt_stop(name: &str, current_pid: u32) -> bool {
    match embedded_pid_from_session_name(name) {
        Some(p) => p != current_pid,
        None => false,
    }
}

#[cfg(windows)]
mod win {
    use super::{parse_spy_detector_sessions_from_logman, should_attempt_stop};
    use crate::app_log;
    use ferrisetw::native::EvntraceNativeError;
    use ferrisetw::trace::TraceError;
    use std::os::windows::process::CommandExt;
    use std::process::Command;

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    pub fn format_etw_trace_start_failure(err: &TraceError) -> String {
        match err {
            TraceError::InvalidTraceName => "invalid ETW trace session name".to_string(),
            TraceError::EtwNativeError(EvntraceNativeError::AlreadyExist) => {
                "another spy-detector instance may be running, or a stale session collided (cleanup retried once)"
                    .to_string()
            }
            TraceError::EtwNativeError(EvntraceNativeError::IoError(io)) => {
                let code = io.raw_os_error();
                if code == Some(-2147023446) || code == Some(1450) {
                    "Windows hit the ETW session cap (~64). Reboot or stop unused trace sessions (logman query -ets)."
                        .to_string()
                } else {
                    format!("I/O error ({io})")
                }
            }
            TraceError::EtwNativeError(EvntraceNativeError::InvalidHandle) => {
                format!("invalid ETW handle ({err:?})")
            }
        }
    }

    /// Returns the names of currently-registered ETW sessions whose name starts
    /// with `spy-detector-`. Best effort: returns empty Vec on any error.
    pub(crate) fn list_stale_sessions() -> Vec<String> {
        let output = match Command::new("logman")
            .args(["query", "-ets"])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
        {
            Ok(o) => String::from_utf8_lossy(&o.stdout).into_owned(),
            Err(_) => return Vec::new(),
        };
        parse_spy_detector_sessions_from_logman(&output)
    }

    /// Best-effort stop of a single named ETW session. Returns Ok(()) on success
    /// or a stringified error otherwise.
    pub fn stop_session(name: &str) -> Result<(), String> {
        let out = Command::new("logman")
            .args(["stop", name, "-ets"])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map_err(|e| e.to_string())?;
        if out.status.success() {
            return Ok(());
        }
        let msg = String::from_utf8_lossy(&out.stderr);
        let msg = msg.trim();
        if msg.is_empty() {
            Err(format!("logman exited with code {:?}", out.status.code()))
        } else {
            Err(msg.to_string())
        }
    }

    /// Coordinated cleanup. Logs every action to `app_log` with `[etw-cleanup]`
    /// prefix. Always returns; never panics.
    pub fn cleanup_stale_sessions() {
        let names = list_stale_sessions();
        let current = std::process::id();
        let stoppable: Vec<_> = names
            .into_iter()
            .filter(|n| should_attempt_stop(n, current))
            .collect();

        app_log::append_line(&format!(
            "[etw-cleanup] found {} stale spy-detector ETW sessions to stop (current pid {})",
            stoppable.len(),
            current
        ));

        for name in stoppable {
            match stop_session(&name) {
                Ok(()) => {
                    app_log::append_line(&format!("[etw-cleanup] stopped {name}"));
                }
                Err(e) => {
                    app_log::append_line(&format!("[etw-cleanup] could not stop {name}: {e}"));
                }
            }
        }
    }
}

#[cfg(windows)]
pub use win::{cleanup_stale_sessions, format_etw_trace_start_failure, stop_session};

#[cfg(not(windows))]
pub fn cleanup_stale_sessions() {}

#[cfg(not(windows))]
pub fn stop_session(_name: &str) -> Result<(), String> {
    Err("ETW cleanup is only supported on Windows".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_logman_fixture_includes_spy_detector_sessions() {
        let fixture = r"
Data Collector Set                      Type                          Status
-------------------------------------------------------------------------------
Eventlog-Security                       Trace                         Running
spy-detector-35552                      Trace                         Running
SleepStudyTraceSession                  Trace                         Running
spy-detector-dns-12345                  Trace                         Running
";
        let mut v = parse_spy_detector_sessions_from_logman(fixture);
        v.sort();
        assert_eq!(
            v,
            vec![
                "spy-detector-35552".to_string(),
                "spy-detector-dns-12345".to_string(),
            ]
        );
    }

    #[test]
    fn parse_empty_yields_empty() {
        assert!(parse_spy_detector_sessions_from_logman("").is_empty());
    }

    #[test]
    fn cleanup_stale_sessions_no_panic_empty_parser_input() {
        let names = parse_spy_detector_sessions_from_logman("");
        assert!(names.is_empty());
        let current = 999_999_u32;
        let stoppable: Vec<_> = names
            .into_iter()
            .filter(|n| should_attempt_stop(n, current))
            .collect();
        assert!(stoppable.is_empty());
    }

    #[test]
    fn cleanup_stale_sessions_does_not_panic_on_non_windows_no_op() {
        #[cfg(not(windows))]
        cleanup_stale_sessions();
    }

    #[cfg(windows)]
    #[test]
    fn cleanup_stale_sessions_runs_without_panic() {
        cleanup_stale_sessions();
    }
}
