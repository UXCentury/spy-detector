//! Authenticode verification via `WinVerifyTrust`. The call is expensive
//! (it can hit the network for revocation) so results are memoized in a
//! process-wide map keyed by the file's full path. We do not bother
//! invalidating: an exe replaced on disk will keep its prior verdict
//! until the app restarts, which is acceptable for an opt-in scanner.
//!
//! Order for images without embedded Authenticode (`TRUST_E_NOSIGNATURE`): try a
//! **catalog** chain (`CryptCATAdmin*` + `WinVerifyTrust` with `WTD_CHOICE_CATALOG`), then a
//! **system-directory heuristic** (`%WINDIR%\System32`, `SysWOW64`, `WinSxS`) for existing paths
//! only—see `is_heuristic_catalog_system_file`.

use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use windows::core::w;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE, HWND, INVALID_HANDLE_VALUE};
use windows::Win32::Security::Cryptography::Catalog::{
    CryptCATAdminAcquireContext, CryptCATAdminAcquireContext2,
    CryptCATAdminCalcHashFromFileHandle2, CryptCATAdminEnumCatalogFromHash,
    CryptCATAdminReleaseCatalogContext, CryptCATAdminReleaseContext,
    CryptCATCatalogInfoFromContext, CATALOG_INFO,
};
use windows::Win32::Security::Cryptography::{CertGetNameStringW, CERT_NAME_SIMPLE_DISPLAY_TYPE};
use windows::Win32::Security::WinTrust::{
    WTHelperGetProvCertFromChain, WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData,
    WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_CATALOG_INFO, WINTRUST_DATA,
    WINTRUST_DATA_0, WINTRUST_FILE_INFO, WTD_CHOICE_CATALOG, WTD_CHOICE_FILE, WTD_REVOKE_NONE,
    WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, QueryDosDeviceW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_SHARE_READ,
    OPEN_EXISTING,
};

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

/// Publisher string used when catalog APIs fail but the binary still lives under protected Windows
/// directories (see `is_heuristic_catalog_system_file`).
const HEURISTIC_MS_PUBLISHER: &str = "Microsoft Windows";

fn trust_is_no_embedded_signature(hr: i32) -> bool {
    matches!(
        hr as u32,
        0x800B0100 | 0x800B0003 | 0x800B0001 // TRUST_E_NOSIGNATURE / _PROVIDER_UNKNOWN / _SUBJECT_FORM_UNKNOWN
    )
}

fn winverify_trust_choice_file(path: &Path) -> Option<i32> {
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

    data.dwStateAction = WTD_STATEACTION_CLOSE;
    unsafe {
        WinVerifyTrust(
            HWND::default(),
            &mut action,
            &mut data as *mut _ as *mut c_void,
        );
    }

    Some(hr)
}

/// Embedded Authenticode only (no catalog fallback). Used to read signer from a `.cat` file and to
/// avoid recursion when resolving catalog publishers.
fn signer_subject_embedded_authenticode_only(path: &Path) -> Option<String> {
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

fn string_from_wchar_buf(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

/// Secondary fallback when `CryptCATAdmin*` fails: paths under `%WINDIR%\System32`, `SysWOW64`, or
/// `WinSxS` are ACL-protected; treating catalog-signed Microsoft binaries there as signed avoids
/// false "unsigned" labels when APIs are blocked (sandboxes, policies).
fn is_heuristic_catalog_system_file(path: &Path) -> bool {
    if !path.exists() {
        return false;
    }
    let Some(ps) = path.to_str() else {
        return false;
    };
    let pl = ps.trim().replace('/', "\\").to_lowercase();
    let windir = std::env::var("WINDIR").unwrap_or_else(|_| "C:\\Windows".into());
    let w = windir
        .trim_end_matches('\\')
        .trim_end_matches('/')
        .replace('/', "\\")
        .to_lowercase();
    for sub in ["system32", "syswow64", "winsxs"] {
        let base = format!("{w}\\{sub}");
        if pl == base || pl.starts_with(&(base + "\\")) {
            return true;
        }
    }
    false
}

enum CatalogMembership {
    Verified { catalog_os_path: String },
    NotFound,
}

fn catalog_membership(path: &Path) -> CatalogMembership {
    let Some(member_os) = path.to_str().map(str::to_owned) else {
        return CatalogMembership::NotFound;
    };

    let outcome = (|| -> Option<String> {
        let mut h_admin: isize = 0;
        unsafe {
            if CryptCATAdminAcquireContext2(&mut h_admin, None, w!("SHA256"), None, None).is_err()
                && CryptCATAdminAcquireContext(&mut h_admin, None, None).is_err()
            {
                return None;
            }

            let mut wide: Vec<u16> = member_os.encode_utf16().collect();
            wide.push(0);
            let h_file = CreateFileW(
                PCWSTR(wide.as_ptr()),
                FILE_GENERIC_READ.0,
                FILE_SHARE_READ,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
            .unwrap_or(INVALID_HANDLE_VALUE);
            if h_file == INVALID_HANDLE_VALUE {
                let _ = CryptCATAdminReleaseContext(h_admin, 0);
                return None;
            }

            let mut cb_hash: u32 = 0;
            if CryptCATAdminCalcHashFromFileHandle2(h_admin, h_file, &mut cb_hash, None, None)
                .is_err()
            {
                let _ = CloseHandle(h_file);
                let _ = CryptCATAdminReleaseContext(h_admin, 0);
                return None;
            }

            let mut hash = vec![0u8; cb_hash as usize];
            let mut cb2 = cb_hash;
            if CryptCATAdminCalcHashFromFileHandle2(
                h_admin,
                h_file,
                &mut cb2,
                Some(hash.as_mut_ptr()),
                None,
            )
            .is_err()
            {
                let _ = CloseHandle(h_file);
                let _ = CryptCATAdminReleaseContext(h_admin, 0);
                return None;
            }
            let _ = CloseHandle(h_file);

            let mut prev: isize = 0;
            let h_cat = CryptCATAdminEnumCatalogFromHash(
                h_admin,
                &hash[..cb2 as usize],
                None,
                Some(&mut prev),
            );
            if h_cat == 0 {
                let _ = CryptCATAdminReleaseContext(h_admin, 0);
                return None;
            }

            let mut cat_info = CATALOG_INFO {
                cbStruct: std::mem::size_of::<CATALOG_INFO>() as u32,
                ..Default::default()
            };
            if CryptCATCatalogInfoFromContext(h_cat, &mut cat_info, 0).is_err() {
                let _ = CryptCATAdminReleaseCatalogContext(h_admin, h_cat, 0);
                let _ = CryptCATAdminReleaseContext(h_admin, 0);
                return None;
            }

            let catalog_path = string_from_wchar_buf(&cat_info.wszCatalogFile);

            let mut catalog_wide: Vec<u16> = catalog_path.encode_utf16().collect();
            catalog_wide.push(0);
            let mut member_wide: Vec<u16> = member_os.encode_utf16().collect();
            member_wide.push(0);

            let mut cat_trust = WINTRUST_CATALOG_INFO {
                cbStruct: std::mem::size_of::<WINTRUST_CATALOG_INFO>() as u32,
                dwCatalogVersion: 0,
                pcwszCatalogFilePath: PCWSTR(catalog_wide.as_ptr()),
                pcwszMemberTag: PCWSTR::null(),
                pcwszMemberFilePath: PCWSTR(member_wide.as_ptr()),
                hMemberFile: HANDLE::default(),
                pbCalculatedFileHash: hash.as_mut_ptr(),
                cbCalculatedFileHash: cb2,
                pcCatalogContext: std::ptr::null_mut(),
                hCatAdmin: h_admin,
            };

            let mut data = WINTRUST_DATA {
                cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
                pPolicyCallbackData: std::ptr::null_mut(),
                pSIPClientData: std::ptr::null_mut(),
                dwUIChoice: WTD_UI_NONE,
                fdwRevocationChecks: WTD_REVOKE_NONE,
                dwUnionChoice: WTD_CHOICE_CATALOG,
                Anonymous: WINTRUST_DATA_0 {
                    pCatalog: &mut cat_trust as *mut _,
                },
                dwStateAction: WTD_STATEACTION_VERIFY,
                hWVTStateData: Default::default(),
                pwszURLReference: Default::default(),
                dwProvFlags: Default::default(),
                dwUIContext: Default::default(),
                pSignatureSettings: std::ptr::null_mut(),
            };

            let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            let hr = WinVerifyTrust(
                HWND::default(),
                &mut action,
                &mut data as *mut _ as *mut c_void,
            );
            data.dwStateAction = WTD_STATEACTION_CLOSE;
            let _ = WinVerifyTrust(
                HWND::default(),
                &mut action,
                &mut data as *mut _ as *mut c_void,
            );

            let _ = CryptCATAdminReleaseCatalogContext(h_admin, h_cat, 0);
            let _ = CryptCATAdminReleaseContext(h_admin, 0);

            if hr == 0 {
                Some(catalog_path)
            } else {
                None
            }
        }
    })();

    match outcome {
        Some(catalog_os_path) => CatalogMembership::Verified { catalog_os_path },
        None => CatalogMembership::NotFound,
    }
}

fn verify(path: &Path) -> SignatureStatus {
    let Some(hr) = winverify_trust_choice_file(path) else {
        return SignatureStatus::Unknown;
    };
    if hr == 0 {
        return SignatureStatus::Signed;
    }
    if trust_is_no_embedded_signature(hr) {
        if let CatalogMembership::Verified { .. } = catalog_membership(path) {
            return SignatureStatus::Signed;
        }
        if is_heuristic_catalog_system_file(path) {
            return SignatureStatus::Signed;
        }
        return SignatureStatus::Unsigned;
    }
    SignatureStatus::Unknown
}

fn signer_subject_uncached(path: &Path) -> Option<String> {
    let hr = winverify_trust_choice_file(path)?;
    if hr == 0 {
        return signer_subject_embedded_authenticode_only(path);
    }
    if trust_is_no_embedded_signature(hr) {
        if let CatalogMembership::Verified { catalog_os_path } = catalog_membership(path) {
            let cat_pb = PathBuf::from(&catalog_os_path);
            return Some(
                signer_subject_embedded_authenticode_only(&cat_pb)
                    .unwrap_or_else(|| HEURISTIC_MS_PUBLISHER.to_string()),
            );
        }
        if is_heuristic_catalog_system_file(path) {
            return Some(HEURISTIC_MS_PUBLISHER.to_string());
        }
    }
    None
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

    #[test]
    fn system32_conhost_or_cmd_reports_signed_microsoft() {
        let windir = std::env::var("WINDIR").unwrap_or_else(|_| r"C:\Windows".to_string());
        for name in ["conhost.exe", "cmd.exe"] {
            let p = Path::new(&windir).join("System32").join(name);
            if !p.exists() {
                continue;
            }
            assert_eq!(
                is_signed(&p),
                SignatureStatus::Signed,
                "expected {:?} to verify as signed",
                p
            );
            let sub = signer_subject(&p).unwrap_or_default();
            assert!(
                sub.to_lowercase().contains("microsoft"),
                "signer for {:?}: {:?}",
                p,
                sub
            );
            return;
        }
        panic!("neither conhost.exe nor cmd.exe found under System32");
    }

    #[test]
    fn tiny_file_in_temp_is_unsigned() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = dir.path().join("unsigned_probe.exe");
        std::fs::write(&p, [0u8; 8]).expect("write");
        assert_eq!(is_signed(&p), SignatureStatus::Unsigned);
    }

    #[test]
    fn missing_system32_path_is_unknown_not_heuristic_signed() {
        let windir = std::env::var("WINDIR").unwrap_or_else(|_| r"C:\Windows".to_string());
        let p = Path::new(&windir)
            .join("System32")
            .join("__spy_detector_authenticode_missing__.exe");
        assert!(!p.exists(), "probe path unexpectedly exists: {:?}", p);
        assert_eq!(is_signed(&p), SignatureStatus::Unknown);
    }
}
