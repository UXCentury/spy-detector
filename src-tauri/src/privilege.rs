#[cfg(windows)]
pub fn shell_restart_elevated() -> Result<(), String> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::HWND;
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWDEFAULT;

    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let cwd = std::env::current_dir().map_err(|e| e.to_string())?;

    fn nul_terminated_wide(s: &OsStr) -> Vec<u16> {
        s.encode_wide().chain(std::iter::once(0)).collect()
    }

    let verb = nul_terminated_wide(OsStr::new("runas"));
    let file = nul_terminated_wide(exe.as_os_str());
    let dir = nul_terminated_wide(cwd.as_os_str());

    let r = unsafe {
        ShellExecuteW(
            Some(HWND::default()),
            PCWSTR(verb.as_ptr()),
            PCWSTR(file.as_ptr()),
            PCWSTR::null(),
            PCWSTR(dir.as_ptr()),
            SW_SHOWDEFAULT,
        )
    };

    // Legacy ShellExecute: success values are > 32.
    if (r.0 as isize) <= 32 {
        return Err(format!(
            "could not start elevated instance (ShellExecute returned {})",
            r.0 as isize
        ));
    }

    Ok(())
}

#[cfg(not(windows))]
pub fn shell_restart_elevated() -> Result<(), String> {
    Err("elevation restart is only supported on Windows".into())
}

#[cfg(windows)]
pub fn is_process_elevated() -> bool {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut ret = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret,
        )
        .is_ok();
        let _ = CloseHandle(token);
        ok && elevation.TokenIsElevated != 0
    }
}

#[cfg(not(windows))]
pub fn is_process_elevated() -> bool {
    false
}
