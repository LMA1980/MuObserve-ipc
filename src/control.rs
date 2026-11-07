use std::sync::OnceLock;

use crate::error::IpcError;
use fory::{Fory, ForyEnum, ForyStruct};
use serde::{Deserialize, Serialize};

pub use fory::ForyStruct as ForyObject;

pub const FORY_ID_CENTRAL_JOB_RECORD: u32 = 1;
pub const FORY_ID_CENTRAL_BRANCH_SNAPSHOT: u32 = 2;
pub const FORY_ID_CENTRAL_SUBMODULE_SNAPSHOT: u32 = 3;
pub const FORY_ID_UPSERT_JOB_RECORD_REQ: u32 = 4;
pub const FORY_ID_UPSERT_JOB_RECORD_RESP: u32 = 5;
pub const FORY_ID_UPSERT_JOB_BATCH_REQ: u32 = 6;
pub const FORY_ID_QUERY_JOBS_HISTORY_REQ: u32 = 7;
pub const FORY_ID_QUERY_JOBS_HISTORY_RESP: u32 = 8;
pub const FORY_ID_QUERY_BRANCH_SNAPSHOTS_REQ: u32 = 9;
pub const FORY_ID_QUERY_BRANCH_SNAPSHOTS_RESP: u32 = 10;
pub const FORY_ID_QUERY_SUBMODULE_SNAPSHOTS_REQ: u32 = 11;
pub const FORY_ID_QUERY_SUBMODULE_SNAPSHOTS_RESP: u32 = 12;
pub const FORY_ID_REGRESSION_VERDICT: u32 = 13;
pub const FORY_ID_BENCHMARK_REGRESSION_ITEM: u32 = 14;
pub const FORY_ID_TEST_REGRESSION_ITEM: u32 = 15;
pub const FORY_ID_REGRESSION_GATE_REQ: u32 = 16;
pub const FORY_ID_REGRESSION_GATE_REPORT: u32 = 17;
pub const FORY_ID_CANARY_SLO_REQ: u32 = 18;
pub const FORY_ID_CANARY_SLO_RESP: u32 = 19;
pub const FORY_ID_WAL_BATCH_ACK: u32 = 20;
pub const FORY_ID_CONTROL_RPC_ENVELOPE: u32 = 21;

/// Centralized `ActionRunner-controller` job history row persisted in `MuObserve`.
#[derive(ForyStruct, Serialize, Deserialize, Debug, PartialEq, Clone, Default)]
pub struct CentralJobRecord {
    pub job_id: String,
    pub event_type: String,
    pub repo_name: String,
    pub repo_key: String,
    pub clone_url: String,
    pub commit_sha: String,
    pub ref_name: String,
    pub branch_key: String,
    pub sender: String,
    pub queued_at_us: i64,
    pub updated_at_us: i64,
    pub status_state: String,
    pub exit_code: Option<i32>,
    pub duration_secs: Option<i64>,
    pub quality_score: Option<i32>,
    pub letter_grade: Option<String>,
    pub coverage_pct: Option<f64>,
    pub benchmark_summary: Option<String>,
    pub tests_passed: Option<i32>,
    pub tests_total: Option<i32>,
    pub advisories_count: Option<i32>,
    pub clippy_warnings: Option<i32>,
    pub record_json: String,
}

/// Centralized `ActionRunner-controller` branch snapshot row persisted in `MuObserve`.
#[derive(ForyStruct, Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Default)]
pub struct CentralBranchSnapshot {
    pub repo_key: String,
    pub branch_key: String,
    pub repo_name: String,
    pub ref_name: String,
    pub latest_active_job_id: Option<String>,
    pub latest_active_json: Option<String>,
    pub latest_active_queued_us: Option<i64>,
    pub latest_completed_job_id: Option<String>,
    pub latest_completed_json: Option<String>,
    pub latest_completed_queued_us: Option<i64>,
}

/// Centralized `ActionRunner-controller` submodule snapshot row persisted in `MuObserve`.
#[derive(ForyStruct, Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Default)]
pub struct CentralSubmoduleSnapshot {
    pub parent_repo_key: String,
    pub branch_key: String,
    pub submodule_key: String,
    pub submodule_path_key: String,
    pub latest_active_job_id: Option<String>,
    pub latest_active_json: Option<String>,
    pub latest_active_queued_us: Option<i64>,
    pub latest_completed_job_id: Option<String>,
    pub latest_completed_json: Option<String>,
    pub latest_completed_queued_us: Option<i64>,
}

/// Request to upsert a single `CentralJobRecord` along with optional branch/submodule snapshots.
#[derive(ForyStruct, Serialize, Deserialize, Debug, PartialEq, Clone, Default)]
pub struct UpsertJobRecordRequest {
    pub request_id: String,
    pub record: CentralJobRecord,
    pub branch_snapshot: Option<CentralBranchSnapshot>,
    pub submodule_snapshots: Vec<CentralSubmoduleSnapshot>,
}

/// Response acknowledging a single or batch job record upsert in `MuObserve`.
#[derive(ForyStruct, Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Default)]
pub struct UpsertJobRecordResponse {
    pub request_id: String,
    pub accepted: bool,
    pub upserted_count: u32,
    pub error_message: Option<String>,
}

/// Request to upsert a batch of `CentralJobRecord`, `CentralBranchSnapshot`, and `CentralSubmoduleSnapshot` rows.
#[derive(ForyStruct, Serialize, Deserialize, Debug, PartialEq, Clone, Default)]
pub struct UpsertJobBatchRequest {
    pub request_id: String,
    pub records: Vec<CentralJobRecord>,
    pub branch_snapshots: Vec<CentralBranchSnapshot>,
    pub submodule_snapshots: Vec<CentralSubmoduleSnapshot>,
}

/// Request to query recent or filtered `CentralJobRecord` rows from `MuObserve`.
#[derive(ForyStruct, Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Default)]
pub struct QueryJobsHistoryRequest {
    pub request_id: String,
    pub repo_key: Option<String>,
    pub branch_key: Option<String>,
    pub job_id: Option<String>,
    pub limit: u32,
}

/// Response returning matching `CentralJobRecord` rows.
#[derive(ForyStruct, Serialize, Deserialize, Debug, PartialEq, Clone, Default)]
pub struct QueryJobsHistoryResponse {
    pub request_id: String,
    pub records: Vec<CentralJobRecord>,
}

/// Request to query `CentralBranchSnapshot` rows by optional `repo_key` and `branch_key`.
#[derive(ForyStruct, Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Default)]
pub struct QueryBranchSnapshotsRequest {
    pub request_id: String,
    pub repo_key: Option<String>,
    pub branch_key: Option<String>,
}

/// Response returning matching `CentralBranchSnapshot` rows.
#[derive(ForyStruct, Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Default)]
pub struct QueryBranchSnapshotsResponse {
    pub request_id: String,
    pub snapshots: Vec<CentralBranchSnapshot>,
}

/// Request to query `CentralSubmoduleSnapshot` rows by optional `parent_repo_key`, `submodule_key`, and `branch_key`.
#[derive(ForyStruct, Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Default)]
pub struct QuerySubmoduleSnapshotsRequest {
    pub request_id: String,
    pub parent_repo_key: Option<String>,
    pub submodule_key: Option<String>,
    pub branch_key: Option<String>,
}

/// Response returning matching `CentralSubmoduleSnapshot` rows.
#[derive(ForyStruct, Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Default)]
pub struct QuerySubmoduleSnapshotsResponse {
    pub request_id: String,
    pub snapshots: Vec<CentralSubmoduleSnapshot>,
}

/// Overall decision produced by the `MuObserve` hardware-stratified regression gate.
#[derive(ForyEnum, Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Copy, Default)]
pub enum RegressionVerdict {
    #[default]
    Pass,
    Warn,
    Fail,
}

/// Per-benchmark regression evaluation detail stratified by `(arch, cpu_cluster, vlen_bits)`.
#[derive(ForyStruct, Serialize, Deserialize, Debug, PartialEq, Clone, Default)]
pub struct BenchmarkRegressionItem {
    pub crate_name: String,
    pub bench_name: String,
    pub arch: String,
    pub cpu_cluster: String,
    pub vlen_bits: u32,
    pub baseline_median_ns: f64,
    pub candidate_ns: f64,
    pub delta_pct: f64,
    pub mad_z_score: f64,
    pub regressed: bool,
}

/// Per-test regression or rolling 30-day flakiness finding.
#[derive(ForyStruct, Serialize, Deserialize, Debug, PartialEq, Clone, Default)]
pub struct TestRegressionItem {
    pub crate_name: String,
    pub test_binary: String,
    pub test_name: String,
    pub status: String,
    pub flakiness_pct: f64,
    pub flip_flop_count: u32,
    pub failure_summary: Option<String>,
}

/// Request sent by `ActionRunner-controller` or MCP tools to evaluate candidate benchmark/test runs against baseline.
#[derive(ForyStruct, Serialize, Deserialize, Debug, PartialEq, Clone, Default)]
pub struct RegressionGateRequest {
    pub request_id: String,
    pub repo_key: String,
    pub candidate_commit: String,
    pub baseline_branch: String,
    pub max_slowdown_pct: f64,
    pub max_flakiness_pct: f64,
}

/// Comprehensive hardware-stratified regression report returned by `MuObserve`.
#[derive(ForyStruct, Serialize, Deserialize, Debug, PartialEq, Clone, Default)]
pub struct RegressionGateReport {
    pub request_id: String,
    pub repo_key: String,
    pub candidate_commit: String,
    pub baseline_branch: String,
    pub verdict: RegressionVerdict,
    pub regressed_benchmarks: Vec<BenchmarkRegressionItem>,
    pub flaky_or_failed_tests: Vec<TestRegressionItem>,
    pub summary: String,
}

/// Request sent by `MuConDe-controller` to verify service SLOs during an A/B canary bake window.
#[derive(ForyStruct, Serialize, Deserialize, Debug, PartialEq, Clone, Default)]
pub struct CanarySloAssertionRequest {
    pub request_id: String,
    pub service_name: String,
    pub candidate_digest: String,
    pub node_id: String,
    pub bake_window_secs: u64,
    pub max_error_logs: u32,
    pub max_p99_latency_ms: f64,
}

/// Response returned by `MuObserve` indicating whether a canary deployment meets SLO bounds or must be rolled back/tainted.
#[derive(ForyStruct, Serialize, Deserialize, Debug, PartialEq, Clone, Default)]
pub struct CanarySloAssertionResponse {
    pub request_id: String,
    pub healthy: bool,
    pub error_log_count: u32,
    pub p99_latency_ms: f64,
    pub taint_recommended: bool,
    pub reason: String,
}

/// Acknowledgment frame returned by `MuObserve` allowing `MuObserve-collector` to truncate flushed WAL batches.
#[derive(ForyStruct, Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Default)]
pub struct WalBatchAck {
    pub sequence: u64,
    pub accepted_rows: u32,
    pub ok: bool,
    pub error_message: Option<String>,
}

/// Umbrella control-plane RPC envelope multiplexing all `MuObserve` Fory requests and responses.
#[allow(clippy::large_enum_variant)]
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Default)]
pub enum ControlRpcEnvelope {
    #[default]
    Noop,
    UpsertJobRecordReq(UpsertJobRecordRequest),
    UpsertJobRecordResp(UpsertJobRecordResponse),
    UpsertJobBatchReq(UpsertJobBatchRequest),
    QueryJobsHistoryReq(QueryJobsHistoryRequest),
    QueryJobsHistoryResp(QueryJobsHistoryResponse),
    QueryBranchSnapshotsReq(QueryBranchSnapshotsRequest),
    QueryBranchSnapshotsResp(QueryBranchSnapshotsResponse),
    QuerySubmoduleSnapshotsReq(QuerySubmoduleSnapshotsRequest),
    QuerySubmoduleSnapshotsResp(QuerySubmoduleSnapshotsResponse),
    RegressionGateReq(RegressionGateRequest),
    RegressionGateResp(RegressionGateReport),
    CanarySloReq(CanarySloAssertionRequest),
    CanarySloResp(CanarySloAssertionResponse),
    WalAck(WalBatchAck),
}

impl fory::Serializer for ControlRpcEnvelope {
    type Target = Self;

    fn write_data(value: &Self, context: &mut fory::WriteContext) -> Result<(), fory::Error> {
        match value {
            Self::Noop => {
                <u8 as fory::Serializer>::write_data(&0u8, context)?;
            }
            Self::UpsertJobRecordReq(v) => {
                <u8 as fory::Serializer>::write_data(&1u8, context)?;
                <UpsertJobRecordRequest as fory::Serializer>::write_data(v, context)?;
            }
            Self::UpsertJobRecordResp(v) => {
                <u8 as fory::Serializer>::write_data(&2u8, context)?;
                <UpsertJobRecordResponse as fory::Serializer>::write_data(v, context)?;
            }
            Self::UpsertJobBatchReq(v) => {
                <u8 as fory::Serializer>::write_data(&3u8, context)?;
                <UpsertJobBatchRequest as fory::Serializer>::write_data(v, context)?;
            }
            Self::QueryJobsHistoryReq(v) => {
                <u8 as fory::Serializer>::write_data(&4u8, context)?;
                <QueryJobsHistoryRequest as fory::Serializer>::write_data(v, context)?;
            }
            Self::QueryJobsHistoryResp(v) => {
                <u8 as fory::Serializer>::write_data(&5u8, context)?;
                <QueryJobsHistoryResponse as fory::Serializer>::write_data(v, context)?;
            }
            Self::QueryBranchSnapshotsReq(v) => {
                <u8 as fory::Serializer>::write_data(&6u8, context)?;
                <QueryBranchSnapshotsRequest as fory::Serializer>::write_data(v, context)?;
            }
            Self::QueryBranchSnapshotsResp(v) => {
                <u8 as fory::Serializer>::write_data(&7u8, context)?;
                <QueryBranchSnapshotsResponse as fory::Serializer>::write_data(v, context)?;
            }
            Self::QuerySubmoduleSnapshotsReq(v) => {
                <u8 as fory::Serializer>::write_data(&8u8, context)?;
                <QuerySubmoduleSnapshotsRequest as fory::Serializer>::write_data(v, context)?;
            }
            Self::QuerySubmoduleSnapshotsResp(v) => {
                <u8 as fory::Serializer>::write_data(&9u8, context)?;
                <QuerySubmoduleSnapshotsResponse as fory::Serializer>::write_data(v, context)?;
            }
            Self::RegressionGateReq(v) => {
                <u8 as fory::Serializer>::write_data(&10u8, context)?;
                <RegressionGateRequest as fory::Serializer>::write_data(v, context)?;
            }
            Self::RegressionGateResp(v) => {
                <u8 as fory::Serializer>::write_data(&11u8, context)?;
                <RegressionGateReport as fory::Serializer>::write_data(v, context)?;
            }
            Self::CanarySloReq(v) => {
                <u8 as fory::Serializer>::write_data(&12u8, context)?;
                <CanarySloAssertionRequest as fory::Serializer>::write_data(v, context)?;
            }
            Self::CanarySloResp(v) => {
                <u8 as fory::Serializer>::write_data(&13u8, context)?;
                <CanarySloAssertionResponse as fory::Serializer>::write_data(v, context)?;
            }
            Self::WalAck(v) => {
                <u8 as fory::Serializer>::write_data(&14u8, context)?;
                <WalBatchAck as fory::Serializer>::write_data(v, context)?;
            }
        }
        Ok(())
    }

    fn read_data(context: &mut fory::ReadContext) -> Result<Self, fory::Error> {
        let tag = <u8 as fory::Serializer>::read_data(context)?;
        match tag {
            0 => Ok(Self::Noop),
            1 => Ok(Self::UpsertJobRecordReq(
                <UpsertJobRecordRequest as fory::Serializer>::read_data(context)?,
            )),
            2 => Ok(Self::UpsertJobRecordResp(
                <UpsertJobRecordResponse as fory::Serializer>::read_data(context)?,
            )),
            3 => Ok(Self::UpsertJobBatchReq(
                <UpsertJobBatchRequest as fory::Serializer>::read_data(context)?,
            )),
            4 => Ok(Self::QueryJobsHistoryReq(
                <QueryJobsHistoryRequest as fory::Serializer>::read_data(context)?,
            )),
            5 => Ok(Self::QueryJobsHistoryResp(
                <QueryJobsHistoryResponse as fory::Serializer>::read_data(context)?,
            )),
            6 => Ok(Self::QueryBranchSnapshotsReq(
                <QueryBranchSnapshotsRequest as fory::Serializer>::read_data(context)?,
            )),
            7 => Ok(Self::QueryBranchSnapshotsResp(
                <QueryBranchSnapshotsResponse as fory::Serializer>::read_data(context)?,
            )),
            8 => Ok(Self::QuerySubmoduleSnapshotsReq(
                <QuerySubmoduleSnapshotsRequest as fory::Serializer>::read_data(context)?,
            )),
            9 => Ok(Self::QuerySubmoduleSnapshotsResp(
                <QuerySubmoduleSnapshotsResponse as fory::Serializer>::read_data(context)?,
            )),
            10 => Ok(Self::RegressionGateReq(
                <RegressionGateRequest as fory::Serializer>::read_data(context)?,
            )),
            11 => Ok(Self::RegressionGateResp(
                <RegressionGateReport as fory::Serializer>::read_data(context)?,
            )),
            12 => Ok(Self::CanarySloReq(
                <CanarySloAssertionRequest as fory::Serializer>::read_data(context)?,
            )),
            13 => Ok(Self::CanarySloResp(
                <CanarySloAssertionResponse as fory::Serializer>::read_data(context)?,
            )),
            14 => Ok(Self::WalAck(<WalBatchAck as fory::Serializer>::read_data(
                context,
            )?)),
            other => Err(fory::Error::invalid_data(format!(
                "Invalid ControlRpcEnvelope tag: {other}"
            ))),
        }
    }

    fn default_value(_context: &mut fory::ReadContext) -> Result<Self, fory::Error> {
        Ok(Self::Noop)
    }
}

/// Builds and initializes an Apache [`Fory`] registry with all `MuObserve` control-plane RPC types registered.
pub fn create_fory_registry() -> Result<Fory, IpcError> {
    let mut fory = Fory::builder().xlang(false).build();
    fory.register::<CentralJobRecord>(FORY_ID_CENTRAL_JOB_RECORD)?;
    fory.register::<CentralBranchSnapshot>(FORY_ID_CENTRAL_BRANCH_SNAPSHOT)?;
    fory.register::<CentralSubmoduleSnapshot>(FORY_ID_CENTRAL_SUBMODULE_SNAPSHOT)?;
    fory.register::<UpsertJobRecordRequest>(FORY_ID_UPSERT_JOB_RECORD_REQ)?;
    fory.register::<UpsertJobRecordResponse>(FORY_ID_UPSERT_JOB_RECORD_RESP)?;
    fory.register::<UpsertJobBatchRequest>(FORY_ID_UPSERT_JOB_BATCH_REQ)?;
    fory.register::<QueryJobsHistoryRequest>(FORY_ID_QUERY_JOBS_HISTORY_REQ)?;
    fory.register::<QueryJobsHistoryResponse>(FORY_ID_QUERY_JOBS_HISTORY_RESP)?;
    fory.register::<QueryBranchSnapshotsRequest>(FORY_ID_QUERY_BRANCH_SNAPSHOTS_REQ)?;
    fory.register::<QueryBranchSnapshotsResponse>(FORY_ID_QUERY_BRANCH_SNAPSHOTS_RESP)?;
    fory.register::<QuerySubmoduleSnapshotsRequest>(FORY_ID_QUERY_SUBMODULE_SNAPSHOTS_REQ)?;
    fory.register::<QuerySubmoduleSnapshotsResponse>(FORY_ID_QUERY_SUBMODULE_SNAPSHOTS_RESP)?;
    fory.register::<RegressionVerdict>(FORY_ID_REGRESSION_VERDICT)?;
    fory.register::<BenchmarkRegressionItem>(FORY_ID_BENCHMARK_REGRESSION_ITEM)?;
    fory.register::<TestRegressionItem>(FORY_ID_TEST_REGRESSION_ITEM)?;
    fory.register::<RegressionGateRequest>(FORY_ID_REGRESSION_GATE_REQ)?;
    fory.register::<RegressionGateReport>(FORY_ID_REGRESSION_GATE_REPORT)?;
    fory.register::<CanarySloAssertionRequest>(FORY_ID_CANARY_SLO_REQ)?;
    fory.register::<CanarySloAssertionResponse>(FORY_ID_CANARY_SLO_RESP)?;
    fory.register::<WalBatchAck>(FORY_ID_WAL_BATCH_ACK)?;
    fory.register_serializer::<ControlRpcEnvelope>(FORY_ID_CONTROL_RPC_ENVELOPE)?;
    Ok(fory)
}

/// Alias for [`create_fory_registry`] matching `ActionRunner-ipc` and `MuConDe-ipc` naming conventions.
pub fn create_fory_runtime() -> Result<Fory, IpcError> {
    create_fory_registry()
}

/// Returns a process-wide shared [`Fory`] registry instance so repeated RPC serialization
/// reuses the same Fory registry ID and avoids unbounded thread-local `ContextCache` growth.
pub fn shared_fory_registry() -> Result<&'static Fory, IpcError> {
    static SHARED_FORY: OnceLock<Fory> = OnceLock::new();
    if let Some(fory) = SHARED_FORY.get() {
        return Ok(fory);
    }
    let built = create_fory_registry()?;
    let _ = SHARED_FORY.set(built);
    SHARED_FORY.get().ok_or_else(|| {
        IpcError::Fory(fory::Error::invalid_data(
            "Failed to initialize shared Fory registry",
        ))
    })
}

/// Encodes a [`ControlRpcEnvelope`] into Apache Fory binary bytes using the shared registry
/// and a caller-owned buffer so no capacity is retained in thread-local `WriteContext` caches.
pub fn encode_control_envelope(envelope: &ControlRpcEnvelope) -> Result<Vec<u8>, IpcError> {
    let fory = shared_fory_registry()?;
    let mut buf = Vec::new();
    fory.serialize_to(&mut buf, envelope)?;
    Ok(buf)
}

/// Decodes a [`ControlRpcEnvelope`] from Apache Fory binary bytes using the shared registry.
pub fn decode_control_envelope(bytes: &[u8]) -> Result<ControlRpcEnvelope, IpcError> {
    let fory = shared_fory_registry()?;
    Ok(fory.deserialize::<ControlRpcEnvelope>(bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_job_record() -> CentralJobRecord {
        CentralJobRecord {
            job_id: "job-9001".to_string(),
            event_type: "pull_request".to_string(),
            repo_name: "LMA1980/k3-kernels-rvv".to_string(),
            repo_key: "lma1980/k3-kernels-rvv".to_string(),
            clone_url: "https://github.com/LMA1980/k3-kernels-rvv.git".to_string(),
            commit_sha: "abcdef0123456789".to_string(),
            ref_name: "feat/rvv-tiling".to_string(),
            branch_key: "feat/rvv-tiling".to_string(),
            sender: "LMA1980".to_string(),
            queued_at_us: 1_700_000_000_000_000,
            updated_at_us: 1_700_000_045_000_000,
            status_state: "Completed".to_string(),
            exit_code: Some(0),
            duration_secs: Some(45),
            quality_score: Some(98),
            letter_grade: Some("A+".to_string()),
            coverage_pct: Some(93.5),
            benchmark_summary: Some("41.2 us/iter".to_string()),
            tests_passed: Some(42),
            tests_total: Some(42),
            advisories_count: Some(0),
            clippy_warnings: Some(0),
            record_json: r#"{"job":{"id":"job-9001"}}"#.to_string(),
        }
    }

    #[test]
    fn test_fory_ci_state_crud_roundtrip() {
        let fory = create_fory_registry().expect("fory registry");

        let branch_snap = CentralBranchSnapshot {
            repo_key: "lma1980/k3-kernels-rvv".to_string(),
            branch_key: "main".to_string(),
            repo_name: "LMA1980/k3-kernels-rvv".to_string(),
            ref_name: "refs/heads/main".to_string(),
            latest_active_job_id: Some("job-9001".to_string()),
            latest_active_json: Some("{}".to_string()),
            latest_active_queued_us: Some(1_700_000_000_000_000),
            latest_completed_job_id: Some("job-9001".to_string()),
            latest_completed_json: Some("{}".to_string()),
            latest_completed_queued_us: Some(1_700_000_000_000_000),
        };

        let sub_snap = CentralSubmoduleSnapshot {
            parent_repo_key: "lma1980/k3".to_string(),
            branch_key: "main".to_string(),
            submodule_key: "k3-kernels-rvv".to_string(),
            submodule_path_key: "kernels-rvv".to_string(),
            latest_active_job_id: Some("job-9001".to_string()),
            latest_active_json: Some("{}".to_string()),
            latest_active_queued_us: Some(1_700_000_000_000_000),
            latest_completed_job_id: Some("job-9001".to_string()),
            latest_completed_json: Some("{}".to_string()),
            latest_completed_queued_us: Some(1_700_000_000_000_000),
        };

        let upsert_req = UpsertJobRecordRequest {
            request_id: "req-1".to_string(),
            record: sample_job_record(),
            branch_snapshot: Some(branch_snap.clone()),
            submodule_snapshots: vec![sub_snap.clone()],
        };
        let bytes = fory.serialize(&upsert_req).expect("serialize upsert_req");
        let decoded: UpsertJobRecordRequest =
            fory.deserialize(&bytes).expect("deserialize upsert_req");
        assert_eq!(decoded, upsert_req);

        let batch_req = UpsertJobBatchRequest {
            request_id: "req-batch-1".to_string(),
            records: vec![sample_job_record()],
            branch_snapshots: vec![branch_snap],
            submodule_snapshots: vec![sub_snap],
        };
        let batch_bytes = fory.serialize(&batch_req).expect("serialize batch_req");
        let decoded_batch: UpsertJobBatchRequest = fory
            .deserialize(&batch_bytes)
            .expect("deserialize batch_req");
        assert_eq!(decoded_batch, batch_req);

        let query_req = QueryJobsHistoryRequest {
            request_id: "req-q1".to_string(),
            repo_key: Some("lma1980/k3-kernels-rvv".to_string()),
            branch_key: Some("main".to_string()),
            job_id: None,
            limit: 50,
        };
        let q_bytes = fory.serialize(&query_req).expect("serialize query_req");
        let decoded_q: QueryJobsHistoryRequest =
            fory.deserialize(&q_bytes).expect("deserialize query_req");
        assert_eq!(decoded_q, query_req);
    }

    #[test]
    fn test_fory_and_json_regression_gate_and_canary_slo_roundtrip() {
        let fory = create_fory_registry().expect("fory registry");

        let gate_req = RegressionGateRequest {
            request_id: "gate-req-1".to_string(),
            repo_key: "lma1980/k3-kernels-rvv".to_string(),
            candidate_commit: "deadbeef12345678".to_string(),
            baseline_branch: "main".to_string(),
            max_slowdown_pct: 5.0,
            max_flakiness_pct: 2.0,
        };
        let gate_req_bytes = fory.serialize(&gate_req).expect("serialize gate_req");
        let gate_req_dec: RegressionGateRequest = fory
            .deserialize(&gate_req_bytes)
            .expect("deserialize gate_req");
        assert_eq!(gate_req_dec, gate_req);

        let report = RegressionGateReport {
            request_id: "gate-req-1".to_string(),
            repo_key: "lma1980/k3-kernels-rvv".to_string(),
            candidate_commit: "deadbeef12345678".to_string(),
            baseline_branch: "main".to_string(),
            verdict: RegressionVerdict::Fail,
            regressed_benchmarks: vec![BenchmarkRegressionItem {
                crate_name: "k3-kernels-rvv".to_string(),
                bench_name: "q8_0_matvec_4096x4096".to_string(),
                arch: "riscv64gc".to_string(),
                cpu_cluster: "A100".to_string(),
                vlen_bits: 1024,
                baseline_median_ns: 41_100.0,
                candidate_ns: 46_500.0,
                delta_pct: 13.14,
                mad_z_score: 6.8,
                regressed: true,
            }],
            flaky_or_failed_tests: vec![TestRegressionItem {
                crate_name: "k3-kernels-rvv".to_string(),
                test_binary: "k3_kernels_rvv".to_string(),
                test_name: "test_vmadot_tile".to_string(),
                status: "failed".to_string(),
                flakiness_pct: 12.5,
                flip_flop_count: 3,
                failure_summary: Some("tile accumulator mismatch".to_string()),
            }],
            summary: "1 benchmark regression on A100 (VLEN=1024) and 1 failed test".to_string(),
        };

        let report_bytes = fory.serialize(&report).expect("serialize report");
        let report_dec: RegressionGateReport =
            fory.deserialize(&report_bytes).expect("deserialize report");
        assert_eq!(report_dec, report);

        let report_json = serde_json::to_string(&report).expect("json encode report");
        let report_from_json: RegressionGateReport =
            serde_json::from_str(&report_json).expect("json decode report");
        assert_eq!(report_from_json, report);

        let slo_req = CanarySloAssertionRequest {
            request_id: "slo-1".to_string(),
            service_name: "action-runner-worker".to_string(),
            candidate_digest: "sha256:0123456789abcdef".to_string(),
            node_id: "worker-riscv64".to_string(),
            bake_window_secs: 60,
            max_error_logs: 0,
            max_p99_latency_ms: 250.0,
        };
        let slo_resp = CanarySloAssertionResponse {
            request_id: "slo-1".to_string(),
            healthy: false,
            error_log_count: 3,
            p99_latency_ms: 412.5,
            taint_recommended: true,
            reason: "error_log_count (3 > 0) and p99_latency_ms (412.5 > 250.0) breached SLO"
                .to_string(),
        };

        let env_req = ControlRpcEnvelope::CanarySloReq(slo_req);
        let env_req_bytes = encode_control_envelope(&env_req).expect("encode envelope");
        let env_req_dec = decode_control_envelope(&env_req_bytes).expect("decode envelope");
        assert_eq!(env_req_dec, env_req);

        let env_resp = ControlRpcEnvelope::CanarySloResp(slo_resp);
        let env_resp_bytes = encode_control_envelope(&env_resp).expect("encode envelope");
        let env_resp_dec = decode_control_envelope(&env_resp_bytes).expect("decode envelope");
        assert_eq!(env_resp_dec, env_resp);
    }
}
