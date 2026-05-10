//! Heuristic detection for processes that may be capturing the screen without a visible UI.
//!
//! There is no reliable user-mode API that lists “who is recording the desktop”. Win32k ETW does
//! not expose a documented, low-noise provider keyword for `PrintWindow` / DWM thumbnail reads
//! (see `etw_win32k`). We therefore combine cheap process metadata only.

use crate::authenticode::{is_signed, SignatureStatus};
use std::collections::HashSet;
use std::path::Path;
use sysinfo::Process;

const RUNTIME_MIN_SECS: u64 = 30;
const CPU_MIN_PCT: f32 = 2.0;

/// Returns score delta (+15) when the process looks like a silent, unsigned screen-grabber candidate.
pub fn silent_capture_bonus(
    pid: u32,
    proc_: &Process,
    exe_path: Option<&Path>,
    visible_pids: &HashSet<u32>,
    cpu_usage_pct: f32,
) -> Option<u8> {
    if visible_pids.contains(&pid) {
        return None;
    }
    if proc_.run_time() < RUNTIME_MIN_SECS {
        return None;
    }
    if cpu_usage_pct < CPU_MIN_PCT {
        return None;
    }
    let ep = exe_path?;
    if is_signed(ep) != SignatureStatus::Unsigned {
        return None;
    }
    Some(15)
}
