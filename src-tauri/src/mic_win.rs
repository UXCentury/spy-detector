//! HKCU microphone consent NonPackaged entries: `LastUsedTimeStop == 0` implies active use.

use std::collections::HashSet;
use winreg::enums::*;
use winreg::RegKey;

fn decode_subkey_to_path(key_name: &str) -> String {
    key_name.replace('#', "\\").to_lowercase()
}

pub fn paths_with_active_microphone() -> HashSet<String> {
    let mut out = HashSet::new();
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let path = r"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\NonPackaged";
    let Ok(non_pkg) = hkcu.open_subkey_with_flags(path, KEY_READ) else {
        return out;
    };
    for sub in non_pkg.enum_keys().filter_map(Result::ok) {
        let Ok(sk) = non_pkg.open_subkey_with_flags(&sub, KEY_READ) else {
            continue;
        };
        let stop = sk
            .get_value::<String, _>("LastUsedTimeStop")
            .unwrap_or_default();
        if stop == "0" || stop.parse::<u64>().ok() == Some(0) {
            out.insert(decode_subkey_to_path(&sub));
        }
    }
    out
}

pub fn exe_matches_active_mic(path_lower: &str, active: &HashSet<String>) -> bool {
    let n = path_lower.trim().to_lowercase();
    active
        .iter()
        .any(|a| !a.is_empty() && (n == *a || n.ends_with(a)))
}
