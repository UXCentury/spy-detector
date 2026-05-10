//! AMSI provider skeleton for script-buffer heuristics. Windows loads AMSI providers from
//! signed, registered DLLs; this EXE embeds the COM object for future packaging but does not
//! register under `HKLM\\SOFTWARE\\Microsoft\\AMSI\\Providers`, so system AMSI will not invoke
//! `Scan` in stock dev builds. Events dispatch on a dedicated thread via `crossbeam-channel`.

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Once, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(windows)]
mod windows_imp {
    use super::*;
    use crossbeam_channel::{unbounded, Sender};
    use tauri::Emitter;
    use windows::core::{Ref, Result as WinResult, PWSTR};
    use windows::Win32::Foundation::E_OUTOFMEMORY;
    use windows::Win32::System::Antimalware::{
        IAmsiStream, IAntimalwareProvider, IAntimalwareProvider_Impl, AMSI_ATTRIBUTE_APP_NAME,
        AMSI_ATTRIBUTE_CONTENT_NAME, AMSI_ATTRIBUTE_CONTENT_SIZE, AMSI_RESULT_NOT_DETECTED,
    };
    use windows::Win32::System::Com::CoTaskMemAlloc;
    use windows_implement::implement;

    pub static AMSI_ACTIVE: AtomicBool = AtomicBool::new(false);

    static AMSI_USER_ENABLED: AtomicBool = AtomicBool::new(true);
    static DETECTION_COUNT: AtomicU64 = AtomicU64::new(0);
    static LAST_DETECTION_MS: AtomicU64 = AtomicU64::new(0);

    static DISPATCH_TX: OnceLock<Sender<AmsiJob>> = OnceLock::new();
    static START_DISPATCHER: Once = Once::new();

    #[derive(Debug)]
    enum AmsiJob {
        Publish {
            summary: String,
            details: serde_json::Value,
            score: u8,
        },
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct AmsiDetectionPayload {
        score: u8,
        reasons: Vec<String>,
        content_sha256: String,
        snippet: String,
        app_name: Option<String>,
        content_name: Option<String>,
        content_len: usize,
    }

    pub fn is_running() -> bool {
        AMSI_ACTIVE.load(Ordering::Relaxed)
    }

    pub fn detection_count() -> u64 {
        DETECTION_COUNT.load(Ordering::Relaxed)
    }

    #[allow(dead_code)]
    pub fn last_detection_at() -> Option<SystemTime> {
        let ms = LAST_DETECTION_MS.load(Ordering::Relaxed);
        if ms == 0 {
            return None;
        }
        UNIX_EPOCH.checked_add(std::time::Duration::from_millis(ms))
    }

    pub fn sync_enabled_from_db(conn: &rusqlite::Connection) {
        let en = crate::settings::read_amsi_enabled(conn).unwrap_or(true);
        AMSI_USER_ENABLED.store(en, Ordering::Relaxed);
    }

    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    fn ensure_dispatcher(app: &tauri::AppHandle) {
        START_DISPATCHER.call_once(|| {
            let (tx, rx) = unbounded::<AmsiJob>();
            let _ = DISPATCH_TX.set(tx);
            let app = app.clone();
            let _ = std::thread::Builder::new()
                .name("spy-detector-amsi-events".into())
                .spawn(move || {
                    while let Ok(job) = rx.recv() {
                        match job {
                            AmsiJob::Publish {
                                summary,
                                details,
                                score,
                            } => {
                                DETECTION_COUNT.fetch_add(1, Ordering::Relaxed);
                                LAST_DETECTION_MS.store(now_ms(), Ordering::Relaxed);
                                crate::event_log::log(
                                    crate::event_log::EventKind::AmsiDetection,
                                    if score >= 70 { "warn" } else { "info" },
                                    None,
                                    None,
                                    None,
                                    Some(details.clone()),
                                    summary.clone(),
                                );
                                let _ = app.emit("amsi_detection", &details);
                            }
                        }
                    }
                });
        });
    }

    pub fn try_register_provider(app_handle: tauri::AppHandle) -> Result<(), String> {
        crate::app_log::append_line(
            "amsi: provider COM object available; system AMSI will not load EXE-hosted providers without signed DLL + HKLM registration",
        );
        ensure_dispatcher(&app_handle);
        let elevated = crate::privilege::is_process_elevated();
        if !elevated {
            crate::app_log::append_line(
                "amsi: AMSI provider disabled (admin + signed installer required for registration)",
            );
        }
        AMSI_ACTIVE.store(false, Ordering::Relaxed);
        Ok(())
    }

    fn dispatch_detection(payload: AmsiDetectionPayload, summary: String) {
        if !AMSI_USER_ENABLED.load(Ordering::Relaxed) {
            return;
        }
        let score = payload.score;
        let details = serde_json::to_value(&payload).unwrap_or(serde_json::json!({}));
        if let Some(tx) = DISPATCH_TX.get() {
            if tx
                .send(AmsiJob::Publish {
                    summary,
                    details,
                    score,
                })
                .is_err()
            {
                crate::app_log::append_line("amsi: dispatch queue unavailable");
            }
        }
    }

    fn read_attr_u64(
        stream: &IAmsiStream,
        attr: windows::Win32::System::Antimalware::AMSI_ATTRIBUTE,
    ) -> Option<u64> {
        let mut buf = [0u8; 8];
        let mut ret = 0u32;
        unsafe {
            stream.GetAttribute(attr, &mut buf, &mut ret).ok()?;
        }
        Some(u64::from_le_bytes(buf))
    }

    fn read_attr_wstring(
        stream: &IAmsiStream,
        attr: windows::Win32::System::Antimalware::AMSI_ATTRIBUTE,
    ) -> Option<String> {
        let mut buf = vec![0u8; 8192];
        let mut ret = 0u32;
        unsafe {
            stream.GetAttribute(attr, &mut buf, &mut ret).ok()?;
        }
        let n = (ret as usize).min(buf.len());
        let slice = &buf[..n];
        if slice.len() < 2 {
            return None;
        }
        let units: Vec<u16> = slice
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&u| u != 0)
            .collect();
        String::from_utf16(&units).ok()
    }

    fn read_content(stream: &IAmsiStream, len: usize) -> Option<Vec<u8>> {
        let addr = read_attr_u64(
            stream,
            windows::Win32::System::Antimalware::AMSI_ATTRIBUTE_CONTENT_ADDRESS,
        )
        .unwrap_or(0) as usize;
        if addr != 0 && len > 0 && len <= 64 * 1024 * 1024 {
            return Some(unsafe { std::slice::from_raw_parts(addr as *const u8, len).to_vec() });
        }
        let mut out = Vec::new();
        let mut pos = 0u64;
        while out.len() < len {
            let mut chunk = vec![0u8; 65536.min(len.saturating_sub(out.len()).max(1))];
            let mut got = 0u32;
            unsafe {
                stream.Read(pos, &mut chunk, &mut got).ok()?;
            }
            if got == 0 {
                break;
            }
            out.extend_from_slice(&chunk[..got as usize]);
            pos += got as u64;
        }
        if out.is_empty() {
            None
        } else {
            Some(out)
        }
    }

    fn heuristic_eval(content: &[u8], app_l: &str) -> (u8, Vec<String>) {
        static NEEDLES: &[&str] = &[
            "iex",
            "invoke-expression",
            "downloadstring",
            "frombase64string",
            "powershell -enc",
            "powershell.exe -enc",
            "-encodedcommand",
            "mshta",
            "rundll32",
            "regsvr32",
            "bitsadmin",
            "invoke-webrequest",
            "wscript.shell",
            "vbs",
            "certutil -decode",
        ];
        let mut reasons = Vec::new();
        let hay = String::from_utf8_lossy(content);
        let hay_l = hay.to_lowercase();
        for n in NEEDLES {
            if hay_l.contains(n) {
                reasons.push(format!("matched substring `{n}`"));
            }
        }
        let mut score: u32 = reasons.len().saturating_mul(12) as u32;
        if app_l.contains("powershell") || app_l.contains("pwsh") {
            score = score.saturating_add(15);
            reasons.push("sender looks like PowerShell host".into());
        }
        if content.len() > 12_000 {
            score = score.saturating_add(8);
            reasons.push("large script buffer".into());
        }
        if reasons.is_empty() {
            return (0, reasons);
        }
        (score.min(100) as u8, reasons)
    }

    fn process_scan(
        stream: Ref<'_, IAmsiStream>,
    ) -> windows::Win32::System::Antimalware::AMSI_RESULT {
        if !AMSI_USER_ENABLED.load(Ordering::Relaxed) {
            return AMSI_RESULT_NOT_DETECTED;
        }
        let Some(stream) = stream.as_ref() else {
            return AMSI_RESULT_NOT_DETECTED;
        };
        let len = match read_attr_u64(stream, AMSI_ATTRIBUTE_CONTENT_SIZE) {
            Some(n) => n as usize,
            None => return AMSI_RESULT_NOT_DETECTED,
        };
        let content = match read_content(stream, len) {
            Some(c) => c,
            None => return AMSI_RESULT_NOT_DETECTED,
        };
        let app_name = read_attr_wstring(stream, AMSI_ATTRIBUTE_APP_NAME);
        let content_name = read_attr_wstring(stream, AMSI_ATTRIBUTE_CONTENT_NAME);
        let app_l = app_name.as_deref().unwrap_or("").to_lowercase();

        let mut hasher = Sha256::new();
        hasher.update(&content);
        let hash = format!("{:x}", hasher.finalize());

        let snippet: String =
            String::from_utf8_lossy(&content[..content.len().min(512)]).into_owned();

        let (score, reasons) = heuristic_eval(&content, &app_l);
        if score < 40 || reasons.is_empty() {
            return AMSI_RESULT_NOT_DETECTED;
        }

        let payload = AmsiDetectionPayload {
            score,
            reasons: reasons.clone(),
            content_sha256: hash,
            snippet,
            app_name: app_name.clone(),
            content_name: content_name.clone(),
            content_len: content.len(),
        };
        let summary = format!("AMSI heuristic score {score}");
        dispatch_detection(payload, summary);

        AMSI_RESULT_NOT_DETECTED
    }

    #[implement(IAntimalwareProvider)]
    pub struct SpyDetectorAmsiProvider;

    impl IAntimalwareProvider_Impl for SpyDetectorAmsiProvider_Impl {
        fn Scan(
            &self,
            stream: Ref<'_, IAmsiStream>,
        ) -> WinResult<windows::Win32::System::Antimalware::AMSI_RESULT> {
            let r = process_scan(stream);
            Ok(r)
        }

        fn CloseSession(&self, _session: u64) {}

        fn DisplayName(&self) -> WinResult<PWSTR> {
            let wide: Vec<u16> = "Spy Detector AMSI".encode_utf16().chain(Some(0)).collect();
            let units = wide.len().saturating_sub(1);
            let bytes = wide.len() * core::mem::size_of::<u16>();
            let raw = unsafe { CoTaskMemAlloc(bytes) };
            if raw.is_null() {
                return Err(E_OUTOFMEMORY.into());
            }
            let slice = unsafe { std::slice::from_raw_parts_mut(raw.cast::<u16>(), wide.len()) };
            slice[..units].copy_from_slice(&wide[..units]);
            slice[units] = 0;
            Ok(PWSTR(raw.cast()))
        }
    }
}

#[cfg(windows)]
pub use windows_imp::*;

#[cfg(not(windows))]
mod stub {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::time::SystemTime;

    pub static AMSI_ACTIVE: AtomicBool = AtomicBool::new(false);

    pub fn is_running() -> bool {
        false
    }

    pub fn detection_count() -> u64 {
        0
    }

    pub fn last_detection_at() -> Option<SystemTime> {
        None
    }

    pub fn sync_enabled_from_db(_conn: &rusqlite::Connection) {}

    pub fn try_register_provider(_app_handle: tauri::AppHandle) -> Result<(), String> {
        Ok(())
    }
}

#[cfg(not(windows))]
pub use stub::*;
