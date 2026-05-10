//! Fallback when Win32k ETW is unavailable: track clipboard sequence churn globally.
//! The app prefers `etw_win32k` for per-PID clipboard metrics; `install_clipboard_poll` is kept
//! only for possible future unattributed fallback (`recent_churn_ticks`), not started at runtime.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use windows::Win32::System::DataExchange::GetClipboardSequenceNumber;

static SEQ: AtomicU32 = AtomicU32::new(0);

pub fn capture_sequence() -> u32 {
    unsafe { GetClipboardSequenceNumber() }
}

#[allow(dead_code)]
pub fn install_clipboard_poll() {
    let last = Arc::new(AtomicU32::new(capture_sequence()));
    let last_c = last.clone();
    std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_secs(2));
        let now = capture_sequence();
        let prev = last_c.swap(now, Ordering::SeqCst);
        if now.wrapping_sub(prev) > 5 {
            SEQ.fetch_add(1, Ordering::SeqCst);
        }
    });
}

#[allow(dead_code)]
pub fn recent_churn_ticks() -> u32 {
    SEQ.load(Ordering::SeqCst)
}
