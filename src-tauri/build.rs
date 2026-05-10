fn embed_build_metadata() {
    let commit = std::process::Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                String::from_utf8(o.stdout).ok()
            } else {
                None
            }
        })
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".into());
    println!("cargo:rustc-env=SPY_GIT_COMMIT={}", commit);

    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    println!("cargo:rustc-env=SPY_BUILD_DATE_EPOCH={}", secs);

    println!("cargo:rerun-if-changed=../.git/HEAD");
    println!("cargo:rerun-if-changed=../.git/refs/heads");
}

fn main() {
    embed_build_metadata();

    let mut attrs = tauri_build::Attributes::new();
    #[cfg(target_os = "windows")]
    {
        let mut win = tauri_build::WindowsAttributes::new();
        let manifest = if std::env::var("PROFILE").as_deref() == Ok("release") {
            include_str!("windows/app.release.manifest")
        } else {
            include_str!("windows/app.manifest")
        };
        win = win.app_manifest(manifest);
        attrs = attrs.windows_attributes(win);
    }
    tauri_build::try_build(attrs).expect("failed to run tauri-build");
}
