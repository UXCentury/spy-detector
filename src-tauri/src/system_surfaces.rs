use serde::Serialize;

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct StartupEntry {
    pub id: String,
    pub name: String,
    pub command: String,
    pub image_path: Option<String>,
    pub source: StartupSource,
    pub scope: StartupScope,
    pub first_seen: String,
    pub last_modified: Option<String>,
    pub signed: Option<bool>,
    pub publisher: Option<String>,
    pub ioc_match: Option<String>,
    pub enabled: bool,
    pub score: u32,
    pub severity: String,
    pub reasons: Vec<String>,
    pub can_disable: bool,
    pub note: Option<String>,
}

#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum StartupSource {
    HkcuRun,
    HkcuRunOnce,
    HklmRun,
    HklmRunOnce,
    HklmWow64Run,
    StartupFolderUser,
    StartupFolderAllUsers,
    TaskScheduler,
}

#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum StartupScope {
    CurrentUser,
    AllUsers,
    System,
}

impl StartupSource {
    pub fn as_db_key(&self) -> &'static str {
        match self {
            StartupSource::HkcuRun => "hkcu-run",
            StartupSource::HkcuRunOnce => "hkcu-run-once",
            StartupSource::HklmRun => "hklm-run",
            StartupSource::HklmRunOnce => "hklm-run-once",
            StartupSource::HklmWow64Run => "hklm-wow64-run",
            StartupSource::StartupFolderUser => "startup-folder-user",
            StartupSource::StartupFolderAllUsers => "startup-folder-all-users",
            StartupSource::TaskScheduler => "task-scheduler",
        }
    }

    pub fn parse_db_key(s: &str) -> Option<Self> {
        Some(match s {
            "hkcu-run" => StartupSource::HkcuRun,
            "hkcu-run-once" => StartupSource::HkcuRunOnce,
            "hklm-run" => StartupSource::HklmRun,
            "hklm-run-once" => StartupSource::HklmRunOnce,
            "hklm-wow64-run" => StartupSource::HklmWow64Run,
            "startup-folder-user" => StartupSource::StartupFolderUser,
            "startup-folder-all-users" => StartupSource::StartupFolderAllUsers,
            "task-scheduler" => StartupSource::TaskScheduler,
            _ => return None,
        })
    }
}

impl StartupScope {
    pub fn as_db_key(&self) -> &'static str {
        match self {
            StartupScope::CurrentUser => "current-user",
            StartupScope::AllUsers => "all-users",
            StartupScope::System => "system",
        }
    }

    pub fn parse_db_key(s: &str) -> Option<Self> {
        Some(match s {
            "current-user" => StartupScope::CurrentUser,
            "all-users" => StartupScope::AllUsers,
            "system" => StartupScope::System,
            _ => return None,
        })
    }
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ServiceEntry {
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub status: String,
    pub start_type: String,
    pub binary_path: Option<String>,
    pub account: Option<String>,
    pub signed: Option<bool>,
    pub publisher: Option<String>,
    pub ioc_match: Option<String>,
    pub score: u32,
    pub severity: String,
    pub reasons: Vec<String>,
    pub can_disable: bool,
    pub is_microsoft: bool,
    pub is_critical: bool,
    pub note: Option<String>,
}

pub fn severity_from_score(score: u32) -> String {
    if score >= 75 {
        "high".into()
    } else if score >= 60 {
        "warn".into()
    } else if score >= 40 {
        "low".into()
    } else {
        "info".into()
    }
}
