//! Rolling-style application log under `%APPDATA%\\spy-detector\\app.log` (append-only).

use std::io::Write;
use std::path::{Path, PathBuf};

const MAX_LOG_BYTES: u64 = 512 * 1024;

pub fn app_data_dir() -> Result<PathBuf, String> {
    let dir = dirs::data_dir()
        .ok_or_else(|| "could not resolve %APPDATA%".to_string())?
        .join("spy-detector");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir)
}

pub fn log_path() -> Result<PathBuf, String> {
    Ok(app_data_dir()?.join("app.log"))
}

/// Best-effort append; never panics.
pub fn append_line(message: &str) {
    let Ok(path) = log_path() else {
        return;
    };
    let ts = chrono::Utc::now().to_rfc3339();
    let line = format!("[{ts}] {message}\n");
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let _ = f.write_all(line.as_bytes());
        let _ = f.flush();
    }
    let _ = trim_log_if_huge(&path);
}

fn trim_log_if_huge(path: &Path) -> std::io::Result<()> {
    let meta = std::fs::metadata(path)?;
    if meta.len() <= MAX_LOG_BYTES {
        return Ok(());
    }
    let data = std::fs::read_to_string(path)?;
    let keep_from = data.len().saturating_sub(MAX_LOG_BYTES as usize / 2);
    let truncated = data[keep_from..].to_string();
    let mut out = std::fs::File::create(path)?;
    writeln!(
        out,
        "[{}] app.log truncated (size cap)",
        chrono::Utc::now().to_rfc3339()
    )?;
    out.write_all(truncated.as_bytes())?;
    Ok(())
}

pub fn read_last_lines(n: usize) -> String {
    let Ok(path) = log_path() else {
        return String::new();
    };
    let Ok(data) = std::fs::read_to_string(&path) else {
        return String::new();
    };
    let lines: Vec<&str> = data.lines().collect();
    let start = lines.len().saturating_sub(n);
    lines[start..].join("\n")
}
