use rusqlite::Connection;
use std::fs;
use std::path::PathBuf;

pub fn export_latest_json(conn: &Connection) -> Result<String, String> {
    let findings =
        crate::scan::load_latest_findings(conn)?.ok_or_else(|| "No scan to export".to_string())?;
    let dir = export_dir()?;
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let path = dir.join("latest-scan.json");
    let body = serde_json::to_string_pretty(&findings).map_err(|e| e.to_string())?;
    fs::write(&path, body).map_err(|e| e.to_string())?;
    Ok(path.to_string_lossy().into_owned())
}

pub fn export_latest_markdown(conn: &Connection) -> Result<String, String> {
    let findings =
        crate::scan::load_latest_findings(conn)?.ok_or_else(|| "No scan to export".to_string())?;
    let dir = export_dir()?;
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let path = dir.join("latest-scan.md");
    let mut md = String::from("# Spy Detector latest scan\n\n");
    for f in &findings {
        md.push_str(&format!(
            "## {} (PID {}) — score {}\n\n",
            f.name, f.pid, f.score
        ));
        if f.ignored {
            md.push_str("Status: ignored (allowlisted)\n\n");
        }
        if let Some(ref p) = f.exe_path {
            md.push_str(&format!("Path: `{p}`\n\n"));
        }
        if f.suspicious_image_loads > 0 {
            md.push_str(&format!(
                "Suspicious DLL loads (ETW): {}\n\n",
                f.suspicious_image_loads
            ));
        }
        for r in &f.reasons {
            md.push_str(&format!("- {r}\n"));
        }
        md.push('\n');
    }
    fs::write(&path, md).map_err(|e| e.to_string())?;
    Ok(path.to_string_lossy().into_owned())
}

fn export_dir() -> Result<PathBuf, String> {
    let root = dirs::data_dir()
        .ok_or_else(|| "could not resolve %APPDATA%".to_string())?
        .join("spy-detector")
        .join("exports");
    Ok(root)
}
