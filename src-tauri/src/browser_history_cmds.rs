use crate::app_log;
use crate::browser_close::{self, CloseBrowserResult};
use crate::browser_history::{self, BrowserHistoryScanResult, DevInfraMeta, HistoryFinding};
use crate::browser_history_delete::{self, DeleteOutcome};
use crate::db;
use crate::event_log::{log as log_event, EventKind};
use crate::AppState;
use serde::Serialize;
use std::collections::{BTreeSet, HashMap, HashSet};
use sysinfo::{ProcessesToUpdate, System};
use tauri::State;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteSummary {
    pub attempted: u32,
    pub succeeded: u32,
    pub failed: u32,
    pub locked_browsers: Vec<String>,
    pub running_browsers: Vec<String>,
    pub outcomes: Vec<DeleteOutcome>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreflightSummary {
    pub finding_count: u32,
    pub affected_browsers: Vec<String>,
    pub running_browsers: Vec<String>,
}

fn detect_running_browsers(target_display_names: &HashSet<String>) -> Vec<String> {
    if target_display_names.is_empty() {
        return Vec::new();
    }
    let mut sys = System::new_all();
    sys.refresh_processes(ProcessesToUpdate::All, true);
    let mut exe_seen: HashSet<String> = HashSet::new();
    for (_, proc_) in sys.processes().iter() {
        exe_seen.insert(proc_.name().to_string_lossy().to_lowercase());
    }
    let mut out: BTreeSet<String> = BTreeSet::new();
    for b in target_display_names {
        if let Some(exe) = browser_close::browser_exe_name(b) {
            if exe_seen.contains(exe) {
                out.insert(b.clone());
            }
        }
    }
    out.into_iter().collect()
}

fn locked_browser_names_from_outcomes(outcomes: &[DeleteOutcome]) -> Vec<String> {
    let mut set: BTreeSet<String> = BTreeSet::new();
    for o in outcomes {
        let Some(e) = &o.error else { continue };
        let Some(rest) = e.strip_prefix("locked:") else {
            continue;
        };
        let trimmed = rest.trim();
        if !trimmed.is_empty() {
            set.insert(trimmed.to_string());
        }
    }
    set.into_iter().collect()
}

fn dedupe_ids_preserve_order(ids: Vec<i64>) -> Vec<i64> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for id in ids {
        if seen.insert(id) {
            out.push(id);
        }
    }
    out
}

fn run_delete_for_records(
    state: &AppState,
    finding_ids: Vec<i64>,
) -> Result<DeleteSummary, String> {
    let deduped = dedupe_ids_preserve_order(finding_ids);
    let attempted = deduped.len() as u32;
    app_log::append_line(&format!(
        "[browser-history-delete] ipc delete_browser_history_findings requested_ids={}",
        attempted
    ));
    if deduped.is_empty() {
        app_log::append_line("[browser-history-delete] pre-flight running_browsers=[]");
        return Ok(DeleteSummary {
            attempted: 0,
            succeeded: 0,
            failed: 0,
            locked_browsers: Vec::new(),
            running_browsers: Vec::new(),
            outcomes: Vec::new(),
        });
    }

    let records = {
        let db = state.db.lock().map_err(|e| e.to_string())?;
        db::list_browser_history_findings_by_ids(&db, &deduped).map_err(|e| e.to_string())?
    };
    app_log::append_line(&format!(
        "[browser-history-delete] ipc findings_resolved_from_db={} requested_ids={}",
        records.len(),
        attempted
    ));

    let browsers_in_job: HashSet<String> = records.iter().map(|r| r.browser.clone()).collect();
    let running_browsers = detect_running_browsers(&browsers_in_job);
    app_log::append_line(&format!(
        "[browser-history-delete] pre-flight running_browsers=[{}]",
        running_browsers.join(", ")
    ));

    if !running_browsers.is_empty() {
        return Ok(DeleteSummary {
            attempted: 0,
            succeeded: 0,
            failed: 0,
            locked_browsers: Vec::new(),
            running_browsers,
            outcomes: Vec::new(),
        });
    }

    let mut by_id: HashMap<i64, db::BrowserHistoryFindingRecord> =
        records.into_iter().map(|r| (r.id, r)).collect();

    let mut outcomes: Vec<DeleteOutcome> = Vec::new();
    let mut ids_to_purge: Vec<i64> = Vec::new();

    for id in deduped {
        let Some(rec) = by_id.remove(&id) else {
            outcomes.push(DeleteOutcome {
                url: String::new(),
                browser: "unknown".into(),
                success: false,
                not_present: false,
                error: Some("finding not found".into()),
            });
            continue;
        };

        let slug = browser_history_delete::browser_slug(&rec.browser);
        let db_path = match browser_history_delete::resolve_history_sqlite_path(
            &rec.browser,
            &rec.profile,
        ) {
            Ok(p) => p,
            Err(e) => {
                app_log::append_line(&format!(
                    "[browser-history-delete] resolve_history_path failed browser={} profile={} err={}",
                    rec.browser, rec.profile, e
                ));
                outcomes.push(DeleteOutcome {
                    url: rec.url.clone(),
                    browser: slug.clone(),
                    success: false,
                    not_present: false,
                    error: Some(e),
                });
                continue;
            }
        };

        match browser_history_delete::delete_url_from_browser(&rec.browser, &db_path, &rec.url) {
            Ok(ok) => {
                log_event(
                    EventKind::BrowserHistoryUrlRemoved,
                    "info",
                    None,
                    None,
                    None,
                    Some(serde_json::json!({
                        "browser": rec.browser,
                        "url": rec.url,
                        "finding_id": rec.id,
                        "notPresentInHistory": ok.not_present,
                    })),
                    format!(
                        "Removed URL from {} history{}",
                        rec.browser,
                        if ok.not_present {
                            " (already absent)"
                        } else {
                            ""
                        }
                    ),
                );
                outcomes.push(DeleteOutcome {
                    url: rec.url.clone(),
                    browser: slug,
                    success: true,
                    not_present: ok.not_present,
                    error: if ok.not_present {
                        Some("not-present-in-history".into())
                    } else {
                        None
                    },
                });
                ids_to_purge.push(rec.id);
            }
            Err(e) => {
                app_log::append_line(&format!(
                    "[browser-history-delete] delete failed browser={} url={} err={}",
                    rec.browser, rec.url, e
                ));
                outcomes.push(DeleteOutcome {
                    url: rec.url.clone(),
                    browser: slug,
                    success: false,
                    not_present: false,
                    error: Some(e),
                });
            }
        }
    }

    if !ids_to_purge.is_empty() {
        let db = state.db.lock().map_err(|e| e.to_string())?;
        db::delete_browser_history_findings_by_ids(&db, &ids_to_purge)
            .map_err(|e| e.to_string())?;
    }

    let succeeded = outcomes.iter().filter(|o| o.success).count() as u32;
    let failed = attempted.saturating_sub(succeeded);
    let locked_browsers = locked_browser_names_from_outcomes(&outcomes);

    app_log::append_line(&format!(
        "[browser-history-delete] ipc summary attempted={} succeeded={} failed={} locked={} running_flagged={}",
        attempted,
        succeeded,
        failed,
        locked_browsers.len(),
        running_browsers.len()
    ));

    Ok(DeleteSummary {
        attempted,
        succeeded,
        failed,
        locked_browsers,
        running_browsers,
        outcomes,
    })
}

#[tauri::command(rename_all = "camelCase")]
pub async fn scan_browser_history(
    state: State<'_, AppState>,
) -> Result<BrowserHistoryScanResult, String> {
    let st = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || browser_history::scan_and_persist(&st))
        .await
        .map_err(|e| e.to_string())?
}

fn list_browser_history_findings_inner(
    state: &AppState,
    limit: u32,
    offset: u32,
    severity: Option<String>,
) -> Result<Vec<HistoryFinding>, String> {
    let t0 = std::time::Instant::now();
    crate::diagnostics::log("[ipc:list_browser_history_findings] start");
    let result = (|| -> Result<Vec<HistoryFinding>, String> {
        let lock_t0 = std::time::Instant::now();
        crate::diagnostics::log("[ipc:list_browser_history_findings] acquiring db lock");
        let db = state.db.lock().map_err(|e| e.to_string())?;
        crate::diagnostics::log(&format!(
            "[ipc:list_browser_history_findings] db lock acquired in {}ms",
            lock_t0.elapsed().as_millis()
        ));
        browser_history::db_list_browser_history_findings(&db, limit, offset, severity.as_deref())
    })();
    let elapsed = t0.elapsed().as_millis();
    match &result {
        Ok(v) => crate::diagnostics::log(&format!(
            "[ipc:list_browser_history_findings] ok in {elapsed}ms (rows={})",
            v.len()
        )),
        Err(e) => crate::diagnostics::log(&format!(
            "[ipc:list_browser_history_findings] error in {elapsed}ms: {e}"
        )),
    }
    result
}

#[tauri::command(rename_all = "camelCase")]
pub async fn list_browser_history_findings(
    state: State<'_, AppState>,
    limit: u32,
    offset: u32,
    severity: Option<String>,
) -> Result<Vec<HistoryFinding>, String> {
    let st = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        list_browser_history_findings_inner(&st, limit, offset, severity)
    })
    .await
    .map_err(|e| e.to_string())?
}

fn clear_browser_history_findings_inner(state: &AppState) -> Result<(), String> {
    let t0 = std::time::Instant::now();
    crate::diagnostics::log("[ipc:clear_browser_history_findings] start");
    let result = (|| -> Result<(), String> {
        let db = state.db.lock().map_err(|e| e.to_string())?;
        browser_history::clear_browser_history_findings(&db)
    })();
    let elapsed = t0.elapsed().as_millis();
    match &result {
        Ok(()) => crate::diagnostics::log(&format!(
            "[ipc:clear_browser_history_findings] ok in {elapsed}ms"
        )),
        Err(e) => crate::diagnostics::log(&format!(
            "[ipc:clear_browser_history_findings] error in {elapsed}ms: {e}"
        )),
    }
    result
}

#[tauri::command(rename_all = "camelCase")]
pub async fn clear_browser_history_findings(state: State<'_, AppState>) -> Result<(), String> {
    let st = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || clear_browser_history_findings_inner(&st))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command(rename_all = "camelCase")]
pub fn get_dev_infra_meta(state: State<AppState>) -> Result<DevInfraMeta, String> {
    Ok(browser_history::dev_infra_meta(&state))
}

#[tauri::command(rename_all = "camelCase")]
pub async fn delete_browser_history_findings(
    state: State<'_, AppState>,
    finding_ids: Vec<i64>,
) -> Result<DeleteSummary, String> {
    let st = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || run_delete_for_records(&st, finding_ids))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command(rename_all = "camelCase")]
pub async fn delete_all_browser_history_findings(
    state: State<'_, AppState>,
) -> Result<DeleteSummary, String> {
    let st = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let ids = {
            let db = st.db.lock().map_err(|e| e.to_string())?;
            let mut stmt = db
                .prepare("SELECT id FROM browser_history_findings ORDER BY id ASC")
                .map_err(|e| e.to_string())?;
            let rows = stmt
                .query_map([], |r| r.get(0))
                .map_err(|e| e.to_string())?;
            rows.collect::<Result<Vec<i64>, _>>()
                .map_err(|e| e.to_string())?
        };
        run_delete_for_records(&st, ids)
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command(rename_all = "camelCase")]
pub fn preflight_browser_history_delete(
    state: State<AppState>,
    finding_ids: Vec<i64>,
) -> Result<PreflightSummary, String> {
    let deduped = dedupe_ids_preserve_order(finding_ids);
    let finding_count = deduped.len() as u32;
    if deduped.is_empty() {
        return Ok(PreflightSummary {
            finding_count: 0,
            affected_browsers: Vec::new(),
            running_browsers: Vec::new(),
        });
    }

    let records = {
        let db = state.db.lock().map_err(|e| e.to_string())?;
        db::list_browser_history_findings_by_ids(&db, &deduped).map_err(|e| e.to_string())?
    };

    let mut browsers: BTreeSet<String> = BTreeSet::new();
    for r in &records {
        browsers.insert(r.browser.clone());
    }
    let affected_browsers: Vec<String> = browsers.into_iter().collect();
    let set: HashSet<String> = affected_browsers.iter().cloned().collect();
    let running_browsers = detect_running_browsers(&set);

    Ok(PreflightSummary {
        finding_count,
        affected_browsers,
        running_browsers,
    })
}

#[tauri::command(rename_all = "camelCase")]
pub async fn close_browser_safely_cmd(
    browser: String,
    force: bool,
) -> Result<CloseBrowserResult, String> {
    tauri::async_runtime::spawn_blocking(move || {
        browser_close::close_browser_safely(&browser, force)
    })
    .await
    .map_err(|e| e.to_string())
}
