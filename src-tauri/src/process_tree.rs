use crate::ioc::norm_token;

pub fn anomaly_reason(parent_image_name: &str, child_image_name: &str) -> Option<&'static str> {
    let p = norm_token(parent_image_name);
    let c = norm_token(child_image_name);
    match (p.as_str(), c.as_str()) {
        ("winword", "powershell") | ("winword", "pwsh") => {
            Some("Word spawned a PowerShell child (common staging pattern)")
        }
        ("excel", "powershell") | ("excel", "pwsh") => {
            Some("Excel spawned a PowerShell child (common staging pattern)")
        }
        ("outlook", "powershell") | ("outlook", "pwsh") => {
            Some("Outlook spawned a PowerShell child")
        }
        ("outlook", "wscript") | ("outlook", "cscript") => {
            Some("Outlook spawned Windows Script Host")
        }
        ("msedge", "powershell") | ("chrome", "powershell") => {
            Some("Browser spawned PowerShell (uncommon)")
        }
        ("explorer", "powershell") => Some("Explorer.exe launched PowerShell directly"),
        ("svchost", "regsvr32") => Some("svchost launched regsvr32 (review context)"),
        ("dllhost", "powershell") => Some("dllhost spawned PowerShell"),
        ("notepad", "cmd") => Some("Notepad spawned cmd (possible chained abuse)"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn anomaly_reason_word_powershell() {
        assert_eq!(
            anomaly_reason("WINWORD.EXE", "powershell.exe"),
            Some("Word spawned a PowerShell child (common staging pattern)")
        );
    }

    #[test]
    fn anomaly_reason_excel_pwsh() {
        assert_eq!(
            anomaly_reason("excel.exe", "pwsh.exe"),
            Some("Excel spawned a PowerShell child (common staging pattern)")
        );
    }

    #[test]
    fn anomaly_reason_outlook_wscript() {
        assert_eq!(
            anomaly_reason("Outlook.exe", "wscript.exe"),
            Some("Outlook spawned Windows Script Host")
        );
    }

    #[test]
    fn benign_pair_returns_none() {
        assert_eq!(anomaly_reason("notepad.exe", "explorer.exe"), None);
        assert_eq!(anomaly_reason("chrome.exe", "notepad.exe"), None);
    }
}
