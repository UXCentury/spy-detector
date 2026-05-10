//! Build a snapshot of PIDs that own at least one visible top-level
//! window via `EnumWindows`. Used to flag processes that have network
//! activity but no UI presence (a classic background-spyware shape).

use std::collections::HashSet;
use std::sync::Mutex;

use windows::core::BOOL;
use windows::Win32::Foundation::{HWND, LPARAM, RECT};
use windows::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetWindowRect, GetWindowTextLengthW, GetWindowThreadProcessId, IsWindowVisible,
};

pub fn pids_with_visible_window() -> HashSet<u32> {
    let collected: Mutex<HashSet<u32>> = Mutex::new(HashSet::new());
    let lparam = LPARAM(&collected as *const _ as isize);
    unsafe {
        let _ = EnumWindows(Some(enum_proc), lparam);
    }
    collected.into_inner().unwrap_or_default()
}

unsafe extern "system" fn enum_proc(hwnd: HWND, lparam: LPARAM) -> BOOL {
    let collected = unsafe { &*(lparam.0 as *const Mutex<HashSet<u32>>) };
    if !unsafe { IsWindowVisible(hwnd) }.as_bool() {
        return BOOL(1);
    }

    let title_len = unsafe { GetWindowTextLengthW(hwnd) };
    let mut rect = RECT::default();
    let has_rect = unsafe { GetWindowRect(hwnd, &mut rect) }.is_ok()
        && (rect.right - rect.left) > 0
        && (rect.bottom - rect.top) > 0;

    if title_len <= 0 && !has_rect {
        return BOOL(1);
    }

    let mut pid: u32 = 0;
    let _tid = unsafe { GetWindowThreadProcessId(hwnd, Some(&mut pid)) };
    if pid != 0 {
        if let Ok(mut g) = collected.lock() {
            g.insert(pid);
        }
    }
    BOOL(1)
}
