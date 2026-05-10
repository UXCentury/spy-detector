//! Authenticode verification via `WinVerifyTrust`. The call is expensive
//! (it can hit the network for revocation) so results are memoized in a
//! process-wide map keyed by the file's full path. We do not bother
//! invalidating: an exe replaced on disk will keep its prior verdict
//! until the app restarts, which is acceptable for an opt-in scanner.

use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use windows::core::PCWSTR;
use windows::Win32::Foundation::HWND;
use windows::Win32::Security::Cryptography::{CertGetNameStringW, CERT_NAME_SIMPLE_DISPLAY_TYPE};
use windows::Win32::Security::WinTrust::{
    WTHelperGetProvCertFromChain, WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData,
    WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0,
    WINTRUST_FILE_INFO, WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE,
    WTD_STATEACTION_VERIFY, WTD_UI_NONE,
};
use windows::Win32::Storage::FileSystem::QueryDosDeviceW;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureStatus {
    Signed,
    Unsigned,
    Unknown,
}

static CACHE: Lazy<Mutex<HashMap<PathBuf, SignatureStatus>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static SIGNER_SUBJECT_CACHE: Lazy<Mutex<HashMap<PathBuf, Option<String>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

static DRIVE_DEVICE_MAP: Lazy<Mutex<HashMap<String, String>>> =
    Lazy::new(|| Mutex::new(build_drive_device_map()));

fn build_drive_device_map() -> HashMap<String, String> {
    let mut out = HashMap::new();
    for letter in b'A'..=b'Z' {
        let drive = format!("{}:", letter as char);
        let drive_wide: Vec<u16> = drive.encode_utf16().chain(std::iter::once(0)).collect();
        let mut buf = vec![0u16; 1024];
        let n = unsafe { QueryDosDeviceW(PCWSTR(drive_wide.as_ptr()), Some(&mut buf)) };
        if n == 0 {
            continue;
        }
        let take = (n as usize).min(buf.len());
        let slice = &buf[..take];
        let first_end = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
        let first = String::from_utf16_lossy(&slice[..first_end]);
        let first = first.trim();
        if !first.is_empty() {
            out.insert(first.to_lowercase(), drive);
        }
    }
    out
}

fn globalroot_device_path(path_utf8: &str) -> PathBuf {
    PathBuf::from(format!(r"\\?\GLOBALROOT{path_utf8}"))
}

fn drive_unc_or_extended_path(path_utf8: &str) -> bool {
    let s = path_utf8.trim();
    if s.starts_with(r"\\?\") || s.starts_with(r"\\.\\") {
        return true;
    }
    if s.starts_with(r"\\") && !s.starts_with(r"\\?\") && !s.starts_with(r"\\.\\") {
        return true;
    }
    let mut it = s.chars();
    matches!(
        (it.next(), it.next()),
        (Some(c), Some(':')) if c.is_ascii_alphabetic()
    )
}

fn longest_matching_drive(sl: &str, map: &HashMap<String, String>) -> Option<(usize, String)> {
    let mut best: Option<(usize, String)> = None;
    for (device_lower, drive) in map {
        let boundary = device_lower.len();
        if !sl.starts_with(device_lower.as_str()) {
            continue;
        }
        let next = sl.as_bytes().get(boundary);
        if (next.is_none() || next == Some(&b'\\'))
            && best
                .as_ref()
                .map(|(prev_len, _)| boundary > *prev_len)
                .unwrap_or(true)
        {
            best = Some((boundary, drive.clone()));
        }
    }
    best
}

/// Converts NT device paths from ETW (e.g. `\Device\HarddiskVolume8\...`) into Win32 paths so
/// `WinVerifyTrust` and file APIs can open the image.
///
/// Unknown `\Device\HarddiskVolumeN\...` prefixes (no DOS-drive mapping) use the Win32 NT namespace
/// form `\\?\GLOBALROOT\Device\...`, which most file-opening APIs accept.
pub fn normalize_image_path(path: &Path) -> PathBuf {
    let Some(raw) = path.to_str() else {
        return path.to_path_buf();
    };
    let s = raw.trim();
    if s.is_empty() {
        return path.to_path_buf();
    }
    if drive_unc_or_extended_path(s) {
        return PathBuf::from(s);
    }

    let sl = s.to_lowercase();
    if !sl.starts_with("\\device\\harddiskvolume") {
        return PathBuf::from(s);
    }

    let map_guard = DRIVE_DEVICE_MAP.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((prefix_len, drive)) = longest_matching_drive(&sl, &map_guard) {
        let suffix = &s[prefix_len..];
        return PathBuf::from(format!("{drive}{suffix}"));
    }

    globalroot_device_path(s)
}

pub fn is_signed(path: &Path) -> SignatureStatus {
    let normalized = normalize_image_path(path);
    let key = normalized.clone();
    if let Ok(g) = CACHE.lock() {
        if let Some(v) = g.get(&key) {
            return *v;
        }
    }
    let status = verify(&normalized);
    if let Ok(mut g) = CACHE.lock() {
        g.insert(key, status);
    }
    status
}

pub fn signer_subject(path: &Path) -> Option<String> {
    let normalized = normalize_image_path(path);
    let key = normalized.clone();
    if let Ok(g) = SIGNER_SUBJECT_CACHE.lock() {
        if let Some(v) = g.get(&key) {
            return v.clone();
        }
    }

    let subject = signer_subject_uncached(&normalized);
    if let Ok(mut g) = SIGNER_SUBJECT_CACHE.lock() {
        g.insert(key, subject.clone());
    }
    subject
}

fn verify(path: &Path) -> SignatureStatus {
    let Some(s) = path.to_str() else {
        return SignatureStatus::Unknown;
    };
    let mut wide: Vec<u16> = s.encode_utf16().collect();
    wide.push(0);

    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: PCWSTR(wide.as_ptr()),
        hFile: Default::default(),
        pgKnownSubject: std::ptr::null_mut(),
    };

    let mut data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        pPolicyCallbackData: std::ptr::null_mut(),
        pSIPClientData: std::ptr::null_mut(),
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 {
            pFile: &mut file_info as *mut _,
        },
        dwStateAction: WTD_STATEACTION_VERIFY,
        hWVTStateData: Default::default(),
        pwszURLReference: Default::default(),
        dwProvFlags: Default::default(),
        dwUIContext: Default::default(),
        pSignatureSettings: std::ptr::null_mut(),
    };

    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let hr = unsafe {
        WinVerifyTrust(
            HWND::default(),
            &mut action,
            &mut data as *mut _ as *mut c_void,
        )
    };

    data.dwStateAction = WTD_STATEACTION_CLOSE;
    unsafe {
        WinVerifyTrust(
            HWND::default(),
            &mut action,
            &mut data as *mut _ as *mut c_void,
        );
    }

    match hr {
        0 => SignatureStatus::Signed,
        // TRUST_E_NOSIGNATURE / TRUST_E_PROVIDER_UNKNOWN / TRUST_E_SUBJECT_FORM_UNKNOWN
        // are best treated as "unsigned"; everything else (chain failure,
        // revocation, expiry, etc.) we lump as Unknown to avoid false positives.
        x if x as u32 == 0x800B0100 || x as u32 == 0x800B0003 || x as u32 == 0x800B0001 => {
            SignatureStatus::Unsigned
        }
        _ => SignatureStatus::Unknown,
    }
}

fn signer_subject_uncached(path: &Path) -> Option<String> {
    let s = path.to_str()?;
    let mut wide: Vec<u16> = s.encode_utf16().collect();
    wide.push(0);

    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: PCWSTR(wide.as_ptr()),
        hFile: Default::default(),
        pgKnownSubject: std::ptr::null_mut(),
    };

    let mut data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        pPolicyCallbackData: std::ptr::null_mut(),
        pSIPClientData: std::ptr::null_mut(),
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 {
            pFile: &mut file_info as *mut _,
        },
        dwStateAction: WTD_STATEACTION_VERIFY,
        hWVTStateData: Default::default(),
        pwszURLReference: Default::default(),
        dwProvFlags: Default::default(),
        dwUIContext: Default::default(),
        pSignatureSettings: std::ptr::null_mut(),
    };

    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let hr = unsafe {
        WinVerifyTrust(
            HWND::default(),
            &mut action,
            &mut data as *mut _ as *mut c_void,
        )
    };

    let subject = if hr == 0 {
        signer_subject_from_state(&data)
    } else {
        None
    };

    data.dwStateAction = WTD_STATEACTION_CLOSE;
    unsafe {
        WinVerifyTrust(
            HWND::default(),
            &mut action,
            &mut data as *mut _ as *mut c_void,
        );
    }

    subject
}

fn signer_subject_from_state(data: &WINTRUST_DATA) -> Option<String> {
    let provider_data = unsafe { WTHelperProvDataFromStateData(data.hWVTStateData) };
    if provider_data.is_null() {
        return None;
    }
    let signer = unsafe { WTHelperGetProvSignerFromChain(provider_data, 0, false, 0) };
    if signer.is_null() {
        return None;
    }
    let cert = unsafe { WTHelperGetProvCertFromChain(signer, 0) };
    if cert.is_null() {
        return None;
    }
    let cert_context = unsafe { (*cert).pCert };
    if cert_context.is_null() {
        return None;
    }

    let len =
        unsafe { CertGetNameStringW(cert_context, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, None) };
    if len <= 1 {
        return None;
    }
    let mut buf = vec![0u16; len as usize];
    let written = unsafe {
        CertGetNameStringW(
            cert_context,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            None,
            Some(&mut buf),
        )
    };
    if written <= 1 {
        return None;
    }
    let subject = String::from_utf16_lossy(&buf[..(written as usize - 1)])
        .trim()
        .to_string();
    if subject.is_empty() {
        None
    } else {
        Some(subject)
    }
}

pub fn is_in_user_writable_path(path: &Path) -> bool {
    let Some(p) = path.to_str() else {
        return false;
    };
    let pl = p.to_lowercase();
    let candidates = [
        std::env::var("TEMP").ok(),
        std::env::var("TMP").ok(),
        std::env::var("APPDATA").ok(),
        std::env::var("LOCALAPPDATA").ok(),
        std::env::var("USERPROFILE")
            .ok()
            .map(|u| format!("{u}\\Downloads")),
    ];

    for c in candidates.into_iter().flatten() {
        let cl = c.replace('/', "\\").to_lowercase();
        if !cl.is_empty() && pl.starts_with(&cl) {
            return true;
        }
    }
    false
}

pub fn is_system_protected_path(path: &Path) -> bool {
    let Some(p) = path.to_str() else {
        return false;
    };
    let pl = p.to_lowercase();
    let mut prefixes: Vec<String> = Vec::new();
    if let Ok(w) = std::env::var("WINDIR") {
        prefixes.push(w.to_lowercase());
    }
    if let Ok(p) = std::env::var("ProgramFiles") {
        prefixes.push(p.to_lowercase());
    }
    if let Ok(p) = std::env::var("ProgramFiles(x86)") {
        prefixes.push(p.to_lowercase());
    }
    if let Ok(p) = std::env::var("ProgramW6432") {
        prefixes.push(p.to_lowercase());
    }
    prefixes
        .iter()
        .any(|pre| !pre.is_empty() && pl.starts_with(pre))
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use std::path::Path;
    use std::sync::{Mutex, OnceLock};

    static ENV_MUTEX: OnceLock<Mutex<()>> = OnceLock::new();

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        ENV_MUTEX
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("env test mutex poisoned")
    }

    #[test]
    fn is_in_user_writable_path_detects_under_temp() {
        let _guard = env_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        let prev = std::env::var("TEMP").ok();
        std::env::set_var("TEMP", dir.path());
        let probe = dir.path().join("nested").join("bad.exe");
        assert!(
            is_in_user_writable_path(Path::new(&probe)),
            "path under %TEMP% should be user-writable"
        );
        match prev {
            Some(v) => std::env::set_var("TEMP", v),
            None => std::env::remove_var("TEMP"),
        }
    }

    #[test]
    fn is_system_protected_path_program_files_prefix() {
        let _guard = env_lock();
        let fake_pf = tempfile::tempdir().expect("tempdir");
        let prev = std::env::var("ProgramFiles").ok();
        std::env::set_var("ProgramFiles", fake_pf.path());
        let probe = fake_pf.path().join("Vendor").join("app.exe");
        assert!(
            is_system_protected_path(Path::new(&probe)),
            "path under ProgramFiles should be treated as protected"
        );
        match prev {
            Some(v) => std::env::set_var("ProgramFiles", v),
            None => std::env::remove_var("ProgramFiles"),
        }
    }

    #[test]
    fn normalize_nt_device_path_maps_when_querydosdevice_works() {
        let Ok(sys_drive) = std::env::var("SystemDrive") else {
            return;
        };
        let drive = sys_drive.trim_end_matches('\\').to_string();
        if drive.len() != 2 || !drive.ends_with(':') {
            return;
        }
        let drive_wide: Vec<u16> = drive.encode_utf16().chain(std::iter::once(0)).collect();
        let mut buf = vec![0u16; 1024];
        let n = unsafe { QueryDosDeviceW(PCWSTR(drive_wide.as_ptr()), Some(&mut buf)) };
        if n == 0 {
            return;
        }
        let take = (n as usize).min(buf.len());
        let slice = &buf[..take];
        let first_end = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
        let device = String::from_utf16_lossy(&slice[..first_end]);
        let device = device.trim();
        if device.is_empty()
            || !device
                .to_lowercase()
                .starts_with("\\device\\harddiskvolume")
        {
            return;
        }
        let synthetic = format!(r"{device}\Windows\System32\notepad.exe");
        let normalized = normalize_image_path(Path::new(&synthetic));
        let ns = normalized.to_string_lossy().to_lowercase();
        assert!(
            ns.starts_with(&drive.to_lowercase()) && ns.contains("notepad.exe"),
            "expected drive letter path, got {ns}"
        );
    }

    #[test]
    fn normalize_win32_path_unchanged() {
        let windir = std::env::var("WINDIR").unwrap_or_else(|_| r"C:\Windows".to_string());
        let p = Path::new(&windir).join("System32").join("notepad.exe");
        let n = normalize_image_path(&p);
        assert_eq!(n, p);
    }

    /// Unknown `\Device\HarddiskVolumeN\` prefixes get `\\?\GLOBALROOT\Device\...` so file APIs can
    /// resolve the NT namespace path when no DOS drive mapping matches.
    #[test]
    fn normalize_unknown_harddisk_volume_uses_globalroot() {
        let p = Path::new(r"\Device\HarddiskVolume424242\Foo\bar.exe");
        let n = normalize_image_path(p);
        let s = n.to_string_lossy();
        assert!(
            s.starts_with(r"\\?\GLOBALROOT\Device\HarddiskVolume424242\"),
            "expected GLOBALROOT wrap, got {s}"
        );
    }
}
