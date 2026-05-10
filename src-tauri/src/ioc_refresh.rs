//! Download AssoEchap stalkerware indicators and atomically replace the user IOC file.

use crate::ioc::IocIndex;
use reqwest::header::{ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED};
use std::path::Path;
use std::time::Duration;

pub const STALKERWARE_IOC_URL: &str =
    "https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/ioc.yaml";

#[derive(Debug, Clone, Default)]
pub struct UpstreamResponseMeta {
    pub etag: Option<String>,
    pub last_modified: Option<String>,
}

fn meta_from_response(resp: &reqwest::Response) -> UpstreamResponseMeta {
    UpstreamResponseMeta {
        etag: resp
            .headers()
            .get(ETAG)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim().to_string()),
        last_modified: resp
            .headers()
            .get(LAST_MODIFIED)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string()),
    }
}

fn http_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent("spy-detector/0.1")
        .build()
        .map_err(|e| format!("HTTP client: {e}"))
}

/// Fetch upstream YAML, validate parsing, replace `%APPDATA%\spy-detector\ioc.yaml` via temp file + rename.
/// Returns cache validators from the HTTP response when present (for later conditional requests).
pub async fn download_validate_replace_user_ioc() -> Result<UpstreamResponseMeta, String> {
    let client = http_client()?;

    let resp = client
        .get(STALKERWARE_IOC_URL)
        .send()
        .await
        .map_err(|e| format!("IOC download failed: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("IOC download HTTP {}", resp.status().as_u16()));
    }

    let header_meta = meta_from_response(&resp);

    let bytes = resp
        .bytes()
        .await
        .map_err(|e| format!("IOC response body: {e}"))?;

    let text = std::str::from_utf8(&bytes).map_err(|e| format!("IOC is not valid UTF-8: {e}"))?;
    IocIndex::validate_refreshed_upstream_yaml(text)?;

    let path = IocIndex::user_upstream_ioc_path().ok_or_else(|| "no APPDATA path".to_string())?;
    let parent = path
        .parent()
        .ok_or_else(|| "invalid IOC path".to_string())?;
    std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;

    let tmp = parent.join("ioc.yaml.tmp");
    std::fs::write(&tmp, &bytes).map_err(|e| e.to_string())?;

    replace_atomic(&tmp, &path)?;

    Ok(header_meta)
}

fn replace_atomic(tmp: &Path, dest: &Path) -> Result<(), String> {
    #[cfg(windows)]
    if dest.exists() {
        std::fs::remove_file(dest).map_err(|e| e.to_string())?;
    }
    std::fs::rename(tmp, dest).map_err(|e| e.to_string())?;
    Ok(())
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckRulesUpdateResult {
    pub has_update: bool,
    pub remote_size: Option<u64>,
    pub message: String,
}

fn http_date_from_modified(tm: std::time::SystemTime) -> Option<String> {
    let dt: chrono::DateTime<chrono::Utc> = tm.into();
    Some(dt.format("%a, %d %b %Y %H:%M:%S GMT").to_string())
}

/// HEAD with validators from last refresh (if any) or local IOC file mtime.
pub async fn check_rules_update_remote(
    stored_etag: Option<String>,
    stored_last_modified: Option<String>,
) -> CheckRulesUpdateResult {
    let client = match http_client() {
        Ok(c) => c,
        Err(e) => {
            return CheckRulesUpdateResult {
                has_update: false,
                remote_size: None,
                message: format!("Compare remote digest — full refresh recommended ({e})"),
            };
        }
    };

    let path_opt = IocIndex::user_upstream_ioc_path();
    let file_ims = path_opt
        .as_ref()
        .filter(|p| p.is_file())
        .and_then(|p| std::fs::metadata(p).ok())
        .and_then(|m| m.modified().ok())
        .and_then(http_date_from_modified);

    let if_none_match = stored_etag.filter(|s| !s.is_empty());
    let if_modified_since = stored_last_modified.filter(|s| !s.is_empty()).or(file_ims);

    let mut req = client.head(STALKERWARE_IOC_URL);
    if let Some(ref v) = if_none_match {
        req = req.header(IF_NONE_MATCH, v);
    }
    if let Some(ref v) = if_modified_since {
        req = req.header(IF_MODIFIED_SINCE, v);
    }

    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            return CheckRulesUpdateResult {
                has_update: false,
                remote_size: None,
                message: format!(
                    "Compare remote digest — full refresh recommended (HEAD failed: {e})"
                ),
            };
        }
    };

    let status = resp.status();
    let remote_size = resp.content_length();

    if status == reqwest::StatusCode::NOT_MODIFIED {
        return CheckRulesUpdateResult {
            has_update: false,
            remote_size,
            message: "Remote rules unchanged (not modified).".into(),
        };
    }

    if status.is_success() {
        return CheckRulesUpdateResult {
            has_update: true,
            remote_size,
            message: "Upstream indicates there may be newer IOC content.".into(),
        };
    }

    CheckRulesUpdateResult {
        has_update: false,
        remote_size: None,
        message: format!(
            "Compare remote digest — full refresh recommended (HEAD HTTP {})",
            status.as_u16()
        ),
    }
}

#[cfg(test)]
mod tests {
    use crate::ioc::IocIndex;
    use indoc::indoc;

    #[test]
    fn validate_refreshed_upstream_yaml_accepts_minimal_bundle() {
        let yaml = indoc! {"
            - name: testrunner
            "};
        IocIndex::validate_refreshed_upstream_yaml(yaml).expect("valid upstream + windows bundle");
    }

    #[test]
    fn validate_refreshed_upstream_yaml_rejects_bad_root() {
        let err = IocIndex::validate_refreshed_upstream_yaml("not_a_list: true").unwrap_err();
        assert!(
            err.contains("expected top-level array"),
            "unexpected: {err}"
        );
    }
}
