use serde::Serialize;

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ProcessLaunchedPayload {
    pub ts: String,
    pub pid: u32,
    pub name: String,
    pub path: String,
    pub ppid: u32,
    pub parent_name: String,
    pub classification: String,
    pub signed: bool,
    pub started_at: String,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ThreadEventPayload {
    pub ts: String,
    pub kind: String,
    pub source_pid: u32,
    pub source_name: String,
    pub source_path: String,
    pub target_pid: u32,
    pub target_name: String,
    pub target_path: String,
    pub suspicious: bool,
    pub severity: String,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ProcessLaunchRow {
    pub id: i64,
    pub ts: String,
    pub pid: u32,
    pub name: String,
    pub path: String,
    pub ppid: u32,
    pub parent_name: String,
    pub classification: String,
    pub signed: bool,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ThreadEventRow {
    pub id: i64,
    pub ts: String,
    pub kind: String,
    pub source_pid: u32,
    pub source_name: String,
    pub source_path: String,
    pub target_pid: u32,
    pub target_name: String,
    pub target_path: String,
    pub suspicious: bool,
}
