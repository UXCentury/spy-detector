use crate::ioc::{norm_token, IocIndex};
use std::collections::HashSet;

const WEIGHT_SIGNATURE: u8 = 60;

pub fn signature_signals(
    ioc: &IocIndex,
    proc_name: &str,
    exe_path: Option<&str>,
    disabled: &HashSet<String>,
) -> (u8, Vec<String>) {
    let mut score: u8 = 0;
    let mut reasons: Vec<String> = Vec::new();
    let norm = norm_token(proc_name);

    if !disabled.contains(&norm) && ioc.process_names.contains(&norm) {
        score = score.saturating_add(WEIGHT_SIGNATURE).min(100);
        reasons.push(format!(
            "Process name matches IOC or bundled signature ({norm})"
        ));
    }

    if let Some(path) = exe_path {
        let pl = path.to_lowercase();
        for needle in &ioc.path_needles {
            let flag = format!("path:{needle}");
            if disabled.contains(&flag) {
                continue;
            }
            if pl.contains(needle) {
                score = score.saturating_add(WEIGHT_SIGNATURE).min(100);
                reasons.push(format!(
                    "Image path contains monitored substring ({needle})"
                ));
            }
        }
    }

    (score, reasons)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ioc::IocIndex;
    use pretty_assertions::assert_eq;
    use std::collections::HashSet;

    #[test]
    fn process_name_match_scores_and_reason() {
        let mut ioc = IocIndex::default();
        ioc.process_names.insert("evilbot".into());
        let disabled = HashSet::new();
        let (score, reasons) = signature_signals(&ioc, "EvilBot.EXE", None, &disabled);
        assert_eq!(score, 60);
        assert_eq!(reasons.len(), 1);
        assert!(
            reasons[0].contains("evilbot"),
            "reason should mention token: {:?}",
            reasons
        );
    }

    #[test]
    fn disabled_process_name_skipped() {
        let mut ioc = IocIndex::default();
        ioc.process_names.insert("evilbot".into());
        let mut disabled = HashSet::new();
        disabled.insert("evilbot".into());
        let (score, reasons) = signature_signals(&ioc, "evilbot.exe", None, &disabled);
        assert_eq!(score, 0);
        assert!(reasons.is_empty());
    }

    #[test]
    fn path_needle_and_process_caps_at_100() {
        let mut ioc = IocIndex::default();
        ioc.process_names.insert("badproc".into());
        ioc.path_needles.push("\\temp\\staging\\".into());
        let disabled = HashSet::new();
        let (score, reasons) = signature_signals(
            &ioc,
            "badproc.exe",
            Some(r"C:\Temp\Staging\run.exe"),
            &disabled,
        );
        assert_eq!(score, 100);
        assert_eq!(reasons.len(), 2);
    }

    #[test]
    fn path_needle_respects_disabled_flag_token() {
        let mut ioc = IocIndex::default();
        ioc.path_needles.push("\\secret\\".into());
        let mut disabled = HashSet::new();
        disabled.insert("path:\\secret\\".into());
        let (score, _) =
            signature_signals(&ioc, "notepad.exe", Some(r"C:\secret\x.exe"), &disabled);
        assert_eq!(score, 0);
    }
}
