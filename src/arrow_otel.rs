use crate::error::IpcError;
use crate::redact::SecretRedactor;
use arrow::array::{
    Array, ArrayRef, Float64Array, Int32Array, RecordBatch, StringArray, TimestampNanosecondArray,
    UInt32Array, UInt64Array,
};
use arrow::datatypes::{DataType, Field, Schema, TimeUnit};
use arrow::ipc::reader::StreamReader;
use arrow::ipc::writer::StreamWriter;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Structured OpenTelemetry log record correlated with W3C `trace_id` and `span_id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OtelLogEntry {
    pub timestamp_unix_nano: i64,
    pub trace_id: String,
    pub span_id: String,
    pub severity_number: i32,
    pub severity_text: String,
    pub service_name: String,
    pub node_id: String,
    pub body: String,
    pub attributes_json: String,
    pub job_id: Option<String>,
    pub stage_id: Option<String>,
}

impl OtelLogEntry {
    /// Scrubs `body` and `attributes_json` in place using the provided [`SecretRedactor`].
    pub fn redact_in_place(&mut self, redactor: &dyn SecretRedactor) {
        self.body = redactor.redact(&self.body);
        self.attributes_json = redactor.redact(&self.attributes_json);
    }
}

/// Distributed OpenTelemetry trace span record with parent-child W3C linkage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OtelSpanEntry {
    pub trace_id: String,
    pub span_id: String,
    pub parent_span_id: Option<String>,
    pub service_name: String,
    pub node_id: String,
    pub span_name: String,
    pub span_kind: String,
    pub start_time_unix_nano: i64,
    pub end_time_unix_nano: i64,
    pub duration_ns: u64,
    pub status_code: String,
    pub status_message: Option<String>,
    pub attributes_json: String,
}

impl OtelSpanEntry {
    /// Scrubs `status_message` and `attributes_json` in place using the provided [`SecretRedactor`].
    pub fn redact_in_place(&mut self, redactor: &dyn SecretRedactor) {
        if let Some(ref msg) = self.status_message {
            self.status_message = Some(redactor.redact(msg));
        }
        self.attributes_json = redactor.redact(&self.attributes_json);
    }
}

/// Hardware-aware OpenTelemetry metric sample including SpacemiT K3 `X100`/`A100`
/// cluster tags, `VLEN` bit width, and `RLIMIT_MEMLOCK` telemetry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OtelMetricEntry {
    pub timestamp_unix_nano: i64,
    pub service_name: String,
    pub node_id: String,
    pub metric_name: String,
    pub metric_unit: String,
    pub value_f64: f64,
    pub arch: String,
    pub cpu_cluster: Option<String>,
    pub vlen_bits: Option<u32>,
    pub memlock_used_bytes: Option<u64>,
    pub memlock_limit_bytes: Option<u64>,
    pub trace_id: Option<String>,
    pub span_id: Option<String>,
    pub attributes_json: String,
}

/// Returns the canonical Apache Arrow [`Schema`] for [`OtelLogEntry`] batches (`otel_logs`).
#[must_use]
pub fn otel_log_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new(
            "timestamp_unix_nano",
            DataType::Timestamp(TimeUnit::Nanosecond, None),
            false,
        ),
        Field::new("trace_id", DataType::Utf8, false),
        Field::new("span_id", DataType::Utf8, false),
        Field::new("severity_number", DataType::Int32, false),
        Field::new("severity_text", DataType::Utf8, false),
        Field::new("service_name", DataType::Utf8, false),
        Field::new("node_id", DataType::Utf8, false),
        Field::new("body", DataType::Utf8, false),
        Field::new("attributes_json", DataType::Utf8, false),
        Field::new("job_id", DataType::Utf8, true),
        Field::new("stage_id", DataType::Utf8, true),
    ]))
}

/// Returns the canonical Apache Arrow [`Schema`] for [`OtelSpanEntry`] batches (`otel_spans`).
#[must_use]
pub fn otel_span_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("trace_id", DataType::Utf8, false),
        Field::new("span_id", DataType::Utf8, false),
        Field::new("parent_span_id", DataType::Utf8, true),
        Field::new("service_name", DataType::Utf8, false),
        Field::new("node_id", DataType::Utf8, false),
        Field::new("span_name", DataType::Utf8, false),
        Field::new("span_kind", DataType::Utf8, false),
        Field::new(
            "start_time_unix_nano",
            DataType::Timestamp(TimeUnit::Nanosecond, None),
            false,
        ),
        Field::new(
            "end_time_unix_nano",
            DataType::Timestamp(TimeUnit::Nanosecond, None),
            false,
        ),
        Field::new("duration_ns", DataType::UInt64, false),
        Field::new("status_code", DataType::Utf8, false),
        Field::new("status_message", DataType::Utf8, true),
        Field::new("attributes_json", DataType::Utf8, false),
    ]))
}

/// Returns the canonical Apache Arrow [`Schema`] for [`OtelMetricEntry`] batches (`otel_metrics`).
#[must_use]
pub fn otel_metric_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new(
            "timestamp_unix_nano",
            DataType::Timestamp(TimeUnit::Nanosecond, None),
            false,
        ),
        Field::new("service_name", DataType::Utf8, false),
        Field::new("node_id", DataType::Utf8, false),
        Field::new("metric_name", DataType::Utf8, false),
        Field::new("metric_unit", DataType::Utf8, false),
        Field::new("value_f64", DataType::Float64, false),
        Field::new("arch", DataType::Utf8, false),
        Field::new("cpu_cluster", DataType::Utf8, true),
        Field::new("vlen_bits", DataType::UInt32, true),
        Field::new("memlock_used_bytes", DataType::UInt64, true),
        Field::new("memlock_limit_bytes", DataType::UInt64, true),
        Field::new("trace_id", DataType::Utf8, true),
        Field::new("span_id", DataType::Utf8, true),
        Field::new("attributes_json", DataType::Utf8, false),
    ]))
}

/// Converts a slice of [`OtelLogEntry`] records into an Apache Arrow [`RecordBatch`].
pub fn log_entries_to_record_batch(entries: &[OtelLogEntry]) -> Result<RecordBatch, IpcError> {
    let len = entries.len();
    let mut ts = Vec::with_capacity(len);
    let mut trace_id = Vec::with_capacity(len);
    let mut span_id = Vec::with_capacity(len);
    let mut sev_num = Vec::with_capacity(len);
    let mut sev_txt = Vec::with_capacity(len);
    let mut svc = Vec::with_capacity(len);
    let mut node = Vec::with_capacity(len);
    let mut body = Vec::with_capacity(len);
    let mut attrs = Vec::with_capacity(len);
    let mut job_id = Vec::with_capacity(len);
    let mut stage_id = Vec::with_capacity(len);

    for e in entries {
        ts.push(e.timestamp_unix_nano);
        trace_id.push(e.trace_id.as_str());
        span_id.push(e.span_id.as_str());
        sev_num.push(e.severity_number);
        sev_txt.push(e.severity_text.as_str());
        svc.push(e.service_name.as_str());
        node.push(e.node_id.as_str());
        body.push(e.body.as_str());
        attrs.push(e.attributes_json.as_str());
        job_id.push(e.job_id.as_deref());
        stage_id.push(e.stage_id.as_deref());
    }

    let columns: Vec<ArrayRef> = vec![
        Arc::new(TimestampNanosecondArray::from(ts)),
        Arc::new(StringArray::from(trace_id)),
        Arc::new(StringArray::from(span_id)),
        Arc::new(Int32Array::from(sev_num)),
        Arc::new(StringArray::from(sev_txt)),
        Arc::new(StringArray::from(svc)),
        Arc::new(StringArray::from(node)),
        Arc::new(StringArray::from(body)),
        Arc::new(StringArray::from(attrs)),
        Arc::new(StringArray::from(job_id)),
        Arc::new(StringArray::from(stage_id)),
    ];

    Ok(RecordBatch::try_new(otel_log_schema(), columns)?)
}

/// Decodes an Apache Arrow [`RecordBatch`] into [`OtelLogEntry`] records.
pub fn record_batch_to_log_entries(batch: &RecordBatch) -> Result<Vec<OtelLogEntry>, IpcError> {
    let ts_col = downcast_col::<TimestampNanosecondArray>(batch, 0, "timestamp_unix_nano")?;
    let trace_col = downcast_col::<StringArray>(batch, 1, "trace_id")?;
    let span_col = downcast_col::<StringArray>(batch, 2, "span_id")?;
    let sev_num_col = downcast_col::<Int32Array>(batch, 3, "severity_number")?;
    let sev_txt_col = downcast_col::<StringArray>(batch, 4, "severity_text")?;
    let svc_col = downcast_col::<StringArray>(batch, 5, "service_name")?;
    let node_col = downcast_col::<StringArray>(batch, 6, "node_id")?;
    let body_col = downcast_col::<StringArray>(batch, 7, "body")?;
    let attrs_col = downcast_col::<StringArray>(batch, 8, "attributes_json")?;
    let job_col = downcast_col::<StringArray>(batch, 9, "job_id")?;
    let stage_col = downcast_col::<StringArray>(batch, 10, "stage_id")?;

    let num_rows = batch.num_rows();
    let mut out = Vec::with_capacity(num_rows);
    for i in 0..num_rows {
        out.push(OtelLogEntry {
            timestamp_unix_nano: ts_col.value(i),
            trace_id: trace_col.value(i).to_string(),
            span_id: span_col.value(i).to_string(),
            severity_number: sev_num_col.value(i),
            severity_text: sev_txt_col.value(i).to_string(),
            service_name: svc_col.value(i).to_string(),
            node_id: node_col.value(i).to_string(),
            body: body_col.value(i).to_string(),
            attributes_json: attrs_col.value(i).to_string(),
            job_id: opt_string(job_col, i),
            stage_id: opt_string(stage_col, i),
        });
    }
    Ok(out)
}

/// Encodes [`OtelLogEntry`] records into an Apache Arrow IPC stream byte buffer.
pub fn encode_log_batch(entries: &[OtelLogEntry]) -> Result<Vec<u8>, IpcError> {
    let batch = log_entries_to_record_batch(entries)?;
    encode_record_batch(&batch)
}

/// Decodes [`OtelLogEntry`] records from an Apache Arrow IPC stream byte slice.
pub fn decode_log_batch(bytes: &[u8]) -> Result<Vec<OtelLogEntry>, IpcError> {
    decode_record_batches(bytes, record_batch_to_log_entries)
}

/// Converts a slice of [`OtelSpanEntry`] records into an Apache Arrow [`RecordBatch`].
pub fn span_entries_to_record_batch(entries: &[OtelSpanEntry]) -> Result<RecordBatch, IpcError> {
    let len = entries.len();
    let mut trace_id = Vec::with_capacity(len);
    let mut span_id = Vec::with_capacity(len);
    let mut parent_span_id = Vec::with_capacity(len);
    let mut svc = Vec::with_capacity(len);
    let mut node = Vec::with_capacity(len);
    let mut span_name = Vec::with_capacity(len);
    let mut span_kind = Vec::with_capacity(len);
    let mut start_ts = Vec::with_capacity(len);
    let mut end_ts = Vec::with_capacity(len);
    let mut duration = Vec::with_capacity(len);
    let mut status_code = Vec::with_capacity(len);
    let mut status_msg = Vec::with_capacity(len);
    let mut attrs = Vec::with_capacity(len);

    for e in entries {
        trace_id.push(e.trace_id.as_str());
        span_id.push(e.span_id.as_str());
        parent_span_id.push(e.parent_span_id.as_deref());
        svc.push(e.service_name.as_str());
        node.push(e.node_id.as_str());
        span_name.push(e.span_name.as_str());
        span_kind.push(e.span_kind.as_str());
        start_ts.push(e.start_time_unix_nano);
        end_ts.push(e.end_time_unix_nano);
        duration.push(e.duration_ns);
        status_code.push(e.status_code.as_str());
        status_msg.push(e.status_message.as_deref());
        attrs.push(e.attributes_json.as_str());
    }

    let columns: Vec<ArrayRef> = vec![
        Arc::new(StringArray::from(trace_id)),
        Arc::new(StringArray::from(span_id)),
        Arc::new(StringArray::from(parent_span_id)),
        Arc::new(StringArray::from(svc)),
        Arc::new(StringArray::from(node)),
        Arc::new(StringArray::from(span_name)),
        Arc::new(StringArray::from(span_kind)),
        Arc::new(TimestampNanosecondArray::from(start_ts)),
        Arc::new(TimestampNanosecondArray::from(end_ts)),
        Arc::new(UInt64Array::from(duration)),
        Arc::new(StringArray::from(status_code)),
        Arc::new(StringArray::from(status_msg)),
        Arc::new(StringArray::from(attrs)),
    ];

    Ok(RecordBatch::try_new(otel_span_schema(), columns)?)
}

/// Decodes an Apache Arrow [`RecordBatch`] into [`OtelSpanEntry`] records.
pub fn record_batch_to_span_entries(batch: &RecordBatch) -> Result<Vec<OtelSpanEntry>, IpcError> {
    let trace_col = downcast_col::<StringArray>(batch, 0, "trace_id")?;
    let span_col = downcast_col::<StringArray>(batch, 1, "span_id")?;
    let parent_col = downcast_col::<StringArray>(batch, 2, "parent_span_id")?;
    let svc_col = downcast_col::<StringArray>(batch, 3, "service_name")?;
    let node_col = downcast_col::<StringArray>(batch, 4, "node_id")?;
    let name_col = downcast_col::<StringArray>(batch, 5, "span_name")?;
    let kind_col = downcast_col::<StringArray>(batch, 6, "span_kind")?;
    let start_col = downcast_col::<TimestampNanosecondArray>(batch, 7, "start_time_unix_nano")?;
    let end_col = downcast_col::<TimestampNanosecondArray>(batch, 8, "end_time_unix_nano")?;
    let dur_col = downcast_col::<UInt64Array>(batch, 9, "duration_ns")?;
    let code_col = downcast_col::<StringArray>(batch, 10, "status_code")?;
    let msg_col = downcast_col::<StringArray>(batch, 11, "status_message")?;
    let attrs_col = downcast_col::<StringArray>(batch, 12, "attributes_json")?;

    let num_rows = batch.num_rows();
    let mut out = Vec::with_capacity(num_rows);
    for i in 0..num_rows {
        out.push(OtelSpanEntry {
            trace_id: trace_col.value(i).to_string(),
            span_id: span_col.value(i).to_string(),
            parent_span_id: opt_string(parent_col, i),
            service_name: svc_col.value(i).to_string(),
            node_id: node_col.value(i).to_string(),
            span_name: name_col.value(i).to_string(),
            span_kind: kind_col.value(i).to_string(),
            start_time_unix_nano: start_col.value(i),
            end_time_unix_nano: end_col.value(i),
            duration_ns: dur_col.value(i),
            status_code: code_col.value(i).to_string(),
            status_message: opt_string(msg_col, i),
            attributes_json: attrs_col.value(i).to_string(),
        });
    }
    Ok(out)
}

/// Encodes [`OtelSpanEntry`] records into an Apache Arrow IPC stream byte buffer.
pub fn encode_span_batch(entries: &[OtelSpanEntry]) -> Result<Vec<u8>, IpcError> {
    let batch = span_entries_to_record_batch(entries)?;
    encode_record_batch(&batch)
}

/// Decodes [`OtelSpanEntry`] records from an Apache Arrow IPC stream byte slice.
pub fn decode_span_batch(bytes: &[u8]) -> Result<Vec<OtelSpanEntry>, IpcError> {
    decode_record_batches(bytes, record_batch_to_span_entries)
}

/// Converts a slice of [`OtelMetricEntry`] records into an Apache Arrow [`RecordBatch`].
pub fn metric_entries_to_record_batch(
    entries: &[OtelMetricEntry],
) -> Result<RecordBatch, IpcError> {
    let len = entries.len();
    let mut ts = Vec::with_capacity(len);
    let mut svc = Vec::with_capacity(len);
    let mut node = Vec::with_capacity(len);
    let mut name = Vec::with_capacity(len);
    let mut unit = Vec::with_capacity(len);
    let mut val = Vec::with_capacity(len);
    let mut arch = Vec::with_capacity(len);
    let mut cluster = Vec::with_capacity(len);
    let mut vlen = Vec::with_capacity(len);
    let mut mem_used = Vec::with_capacity(len);
    let mut mem_limit = Vec::with_capacity(len);
    let mut trace_id = Vec::with_capacity(len);
    let mut span_id = Vec::with_capacity(len);
    let mut attrs = Vec::with_capacity(len);

    for e in entries {
        ts.push(e.timestamp_unix_nano);
        svc.push(e.service_name.as_str());
        node.push(e.node_id.as_str());
        name.push(e.metric_name.as_str());
        unit.push(e.metric_unit.as_str());
        val.push(e.value_f64);
        arch.push(e.arch.as_str());
        cluster.push(e.cpu_cluster.as_deref());
        vlen.push(e.vlen_bits);
        mem_used.push(e.memlock_used_bytes);
        mem_limit.push(e.memlock_limit_bytes);
        trace_id.push(e.trace_id.as_deref());
        span_id.push(e.span_id.as_deref());
        attrs.push(e.attributes_json.as_str());
    }

    let columns: Vec<ArrayRef> = vec![
        Arc::new(TimestampNanosecondArray::from(ts)),
        Arc::new(StringArray::from(svc)),
        Arc::new(StringArray::from(node)),
        Arc::new(StringArray::from(name)),
        Arc::new(StringArray::from(unit)),
        Arc::new(Float64Array::from(val)),
        Arc::new(StringArray::from(arch)),
        Arc::new(StringArray::from(cluster)),
        Arc::new(UInt32Array::from(vlen)),
        Arc::new(UInt64Array::from(mem_used)),
        Arc::new(UInt64Array::from(mem_limit)),
        Arc::new(StringArray::from(trace_id)),
        Arc::new(StringArray::from(span_id)),
        Arc::new(StringArray::from(attrs)),
    ];

    Ok(RecordBatch::try_new(otel_metric_schema(), columns)?)
}

/// Decodes an Apache Arrow [`RecordBatch`] into [`OtelMetricEntry`] records.
pub fn record_batch_to_metric_entries(
    batch: &RecordBatch,
) -> Result<Vec<OtelMetricEntry>, IpcError> {
    let ts_col = downcast_col::<TimestampNanosecondArray>(batch, 0, "timestamp_unix_nano")?;
    let svc_col = downcast_col::<StringArray>(batch, 1, "service_name")?;
    let node_col = downcast_col::<StringArray>(batch, 2, "node_id")?;
    let name_col = downcast_col::<StringArray>(batch, 3, "metric_name")?;
    let unit_col = downcast_col::<StringArray>(batch, 4, "metric_unit")?;
    let val_col = downcast_col::<Float64Array>(batch, 5, "value_f64")?;
    let arch_col = downcast_col::<StringArray>(batch, 6, "arch")?;
    let cluster_col = downcast_col::<StringArray>(batch, 7, "cpu_cluster")?;
    let vlen_col = downcast_col::<UInt32Array>(batch, 8, "vlen_bits")?;
    let mem_used_col = downcast_col::<UInt64Array>(batch, 9, "memlock_used_bytes")?;
    let mem_limit_col = downcast_col::<UInt64Array>(batch, 10, "memlock_limit_bytes")?;
    let trace_col = downcast_col::<StringArray>(batch, 11, "trace_id")?;
    let span_col = downcast_col::<StringArray>(batch, 12, "span_id")?;
    let attrs_col = downcast_col::<StringArray>(batch, 13, "attributes_json")?;

    let num_rows = batch.num_rows();
    let mut out = Vec::with_capacity(num_rows);
    for i in 0..num_rows {
        out.push(OtelMetricEntry {
            timestamp_unix_nano: ts_col.value(i),
            service_name: svc_col.value(i).to_string(),
            node_id: node_col.value(i).to_string(),
            metric_name: name_col.value(i).to_string(),
            metric_unit: unit_col.value(i).to_string(),
            value_f64: val_col.value(i),
            arch: arch_col.value(i).to_string(),
            cpu_cluster: opt_string(cluster_col, i),
            vlen_bits: if vlen_col.is_null(i) {
                None
            } else {
                Some(vlen_col.value(i))
            },
            memlock_used_bytes: if mem_used_col.is_null(i) {
                None
            } else {
                Some(mem_used_col.value(i))
            },
            memlock_limit_bytes: if mem_limit_col.is_null(i) {
                None
            } else {
                Some(mem_limit_col.value(i))
            },
            trace_id: opt_string(trace_col, i),
            span_id: opt_string(span_col, i),
            attributes_json: attrs_col.value(i).to_string(),
        });
    }
    Ok(out)
}

/// Encodes [`OtelMetricEntry`] records into an Apache Arrow IPC stream byte buffer.
pub fn encode_metric_batch(entries: &[OtelMetricEntry]) -> Result<Vec<u8>, IpcError> {
    let batch = metric_entries_to_record_batch(entries)?;
    encode_record_batch(&batch)
}

/// Decodes [`OtelMetricEntry`] records from an Apache Arrow IPC stream byte slice.
pub fn decode_metric_batch(bytes: &[u8]) -> Result<Vec<OtelMetricEntry>, IpcError> {
    decode_record_batches(bytes, record_batch_to_metric_entries)
}

pub(crate) fn encode_record_batch(batch: &RecordBatch) -> Result<Vec<u8>, IpcError> {
    let schema = batch.schema();
    let mut buffer = Vec::new();
    {
        let mut writer = StreamWriter::try_new(&mut buffer, &schema)?;
        writer.write(batch)?;
        writer.finish()?;
    }
    Ok(buffer)
}

pub(crate) fn decode_record_batches<T, F>(bytes: &[u8], convert: F) -> Result<Vec<T>, IpcError>
where
    F: Fn(&RecordBatch) -> Result<Vec<T>, IpcError>,
{
    let mut reader = StreamReader::try_new(bytes, None)?;
    let mut all_entries = Vec::new();
    for batch_res in &mut reader {
        let batch = batch_res?;
        let entries = convert(&batch)?;
        all_entries.extend(entries);
    }
    Ok(all_entries)
}

pub(crate) fn downcast_col<'a, T: 'static>(
    batch: &'a RecordBatch,
    idx: usize,
    name: &str,
) -> Result<&'a T, IpcError> {
    batch
        .column(idx)
        .as_any()
        .downcast_ref::<T>()
        .ok_or_else(|| {
            IpcError::Arrow(arrow::error::ArrowError::ParseError(format!(
                "Invalid or mismatched Arrow column at index {idx} ({name})"
            )))
        })
}

pub(crate) fn opt_string(col: &StringArray, row: usize) -> Option<String> {
    if col.is_null(row) {
        None
    } else {
        Some(col.value(row).to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::redact::DeterministicSecretRedactor;

    #[test]
    fn test_otel_log_batch_roundtrip_and_redaction() {
        let redactor = DeterministicSecretRedactor::new();
        let mut entry = OtelLogEntry {
            timestamp_unix_nano: 1_700_000_000_000_000_000,
            trace_id: "4bf92f3577b34da6a3ce929d0e0e4736".to_string(),
            span_id: "00f067aa0ba902b7".to_string(),
            severity_number: 17,
            severity_text: "ERROR".to_string(),
            service_name: "action-runner-worker".to_string(),
            node_id: "worker-riscv64".to_string(),
            body: "auth failed with token=ghp_secret1234567890".to_string(),
            attributes_json: r#"{"stage":"clippy-check"}"#.to_string(),
            job_id: Some("job-101".to_string()),
            stage_id: Some("clippy-check".to_string()),
        };
        entry.redact_in_place(&redactor);
        assert!(entry.body.contains("[REDACTED:MUOBSERVE]"));

        let encoded = encode_log_batch(std::slice::from_ref(&entry)).expect("encode logs");
        let decoded = decode_log_batch(&encoded).expect("decode logs");
        assert_eq!(decoded, vec![entry]);
    }

    #[test]
    fn test_otel_span_batch_roundtrip() {
        let spans = vec![
            OtelSpanEntry {
                trace_id: "4bf92f3577b34da6a3ce929d0e0e4736".to_string(),
                span_id: "00f067aa0ba902b7".to_string(),
                parent_span_id: None,
                service_name: "action-runner-controller".to_string(),
                node_id: "node-a".to_string(),
                span_name: "ci.job.pipeline".to_string(),
                span_kind: "SERVER".to_string(),
                start_time_unix_nano: 1_700_000_000_000_000_000,
                end_time_unix_nano: 1_700_000_005_000_000_000,
                duration_ns: 5_000_000_000,
                status_code: "OK".to_string(),
                status_message: None,
                attributes_json: r#"{"repo":"LMA1980/k3-core"}"#.to_string(),
            },
            OtelSpanEntry {
                trace_id: "4bf92f3577b34da6a3ce929d0e0e4736".to_string(),
                span_id: "1122334455667788".to_string(),
                parent_span_id: Some("00f067aa0ba902b7".to_string()),
                service_name: "action-runner-worker".to_string(),
                node_id: "worker-riscv64".to_string(),
                span_name: "ci.stage.test".to_string(),
                span_kind: "INTERNAL".to_string(),
                start_time_unix_nano: 1_700_000_001_000_000_000,
                end_time_unix_nano: 1_700_000_004_000_000_000,
                duration_ns: 3_000_000_000,
                status_code: "OK".to_string(),
                status_message: Some("all tests passed".to_string()),
                attributes_json: r#"{"threads":6}"#.to_string(),
            },
        ];

        let encoded = encode_span_batch(&spans).expect("encode spans");
        let decoded = decode_span_batch(&encoded).expect("decode spans");
        assert_eq!(decoded, spans);
    }

    #[test]
    fn test_otel_metric_batch_roundtrip() {
        let metrics = vec![OtelMetricEntry {
            timestamp_unix_nano: 1_700_000_010_000_000_000,
            service_name: "k3-manager".to_string(),
            node_id: "worker-riscv64".to_string(),
            metric_name: "k3.inference.decode_tokens_per_sec".to_string(),
            metric_unit: "tok/s".to_string(),
            value_f64: 48.75,
            arch: "riscv64gc".to_string(),
            cpu_cluster: Some("A100".to_string()),
            vlen_bits: Some(1024),
            memlock_used_bytes: Some(4 * 1024 * 1024 * 1024),
            memlock_limit_bytes: Some(28 * 1024 * 1024 * 1024),
            trace_id: Some("4bf92f3577b34da6a3ce929d0e0e4736".to_string()),
            span_id: Some("00f067aa0ba902b7".to_string()),
            attributes_json: r#"{"model":"qwen2.5-3b-q8_0"}"#.to_string(),
        }];

        let encoded = encode_metric_batch(&metrics).expect("encode metrics");
        let decoded = decode_metric_batch(&encoded).expect("decode metrics");
        assert_eq!(decoded, metrics);
    }
}
