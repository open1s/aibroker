//! Parquet capture of complete request/response exchanges (`-w FILE`).
//!
//! The log dump (`--dump-request`/`--dump-response`) is built for watching
//! traffic live: one line per event, bodies truncated. This file is built for
//! the *afterwards* — a developer opening it in DuckDB, pandas or any parquet
//! viewer to answer "what exactly did we send, and what came back?". One row
//! per request, with the full bodies (up to a generous cap), the routing
//! outcome and the latency, so a rotation or a rewrite is visible without
//! correlating log lines by hand:
//!
//! ```sql
//! SELECT id, model, provider, key_id, attempts, status, duration_ms
//! FROM 'traffic.parquet' WHERE status != 200;
//! ```
//!
//! The same redaction rules as the log dump apply, and they apply *before*
//! anything is buffered here: a credential must never reach this file, which
//! is durable storage just like the log. Unlike the log, bodies are kept whole
//! across chunks (a secret at offset 6278 must be captured, not missed), and a
//! key rotation records each attempt's response separately.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::{SystemTime, UNIX_EPOCH};

use arrow_array::{
    ArrayRef, BooleanArray, Int64Array, RecordBatch, StringArray, UInt16Array, UInt32Array,
    UInt64Array,
};
use arrow_schema::{DataType, Field, Schema, SchemaRef};
use parquet::arrow::ArrowWriter;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use parquet::file::properties::WriterProperties;

/// Bodies larger than this are truncated in the file, with the real size kept
/// in `request_bytes`/`response_bytes`. Generous on purpose: the point of the
/// file is the *complete* exchange, and an agentic request is easily 100 KB.
pub const DEFAULT_MAX_CAPTURE_BYTES: usize = 1024 * 1024;

/// Rows buffered per write before they are flushed into a parquet row group.
const ROW_GROUP_ROWS: usize = 64;

/// How often the writer re-finalizes the file so readers can see new rows.
/// A parquet file is only readable once its footer is written, and the
/// footer can only be written by closing the writer — so the capture is
/// periodically closed and reopened, carrying the existing rows forward.
const PUBLISH_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);

/// One upstream attempt inside a captured exchange.
#[derive(Debug, Clone, Default)]
pub struct CapturedAttempt {
    pub provider: Option<String>,
    pub key: Option<String>,
    pub method: String,
    pub url: String,
    pub status: Option<u16>,
    /// Headers as sent upstream, credential values already redacted.
    pub headers: String,
    /// Response headers, credential values already redacted.
    pub response_headers: String,
    /// The response body of this attempt, redacted. On a rotation this is the
    /// 429/5xx body that triggered it — usually the most interesting bytes in
    /// the whole capture.
    pub response_body: String,
}

/// Everything captured about one request, ready to become a row.
///
/// Every text field has already been through the dump's redactor by the time
/// it lands here; this struct is transport-only and never sees a raw secret.
#[derive(Debug, Clone, Default)]
pub struct CapturedExchange {
    pub id: u64,
    /// Unix epoch milliseconds when the request entered the proxy.
    pub timestamp_ms: u64,
    pub duration_ms: u64,
    pub method: String,
    pub uri: String,
    pub request_headers: String,
    pub request_body: String,
    pub request_bytes: u64,
    pub request_truncated: bool,
    pub model: Option<String>,
    pub provider: Option<String>,
    pub key: Option<String>,
    pub client: Option<String>,
    pub attempts: u32,
    pub status: Option<u16>,
    pub response_headers: String,
    pub response_body: String,
    pub response_bytes: u64,
    pub response_truncated: bool,
    pub upstream_attempts: Vec<CapturedAttempt>,
}

/// The capture schema. Kept in one place so writer and reader cannot drift.
pub fn schema() -> SchemaRef {
    let utf8 = || DataType::Utf8;
    Arc::new(Schema::new(vec![
        Field::new("id", DataType::UInt64, false),
        Field::new("timestamp_ms", DataType::Int64, false),
        Field::new("duration_ms", DataType::UInt64, false),
        Field::new("method", utf8(), false),
        Field::new("uri", utf8(), false),
        Field::new("request_headers", utf8(), false),
        Field::new("request_body", utf8(), false),
        Field::new("request_bytes", DataType::UInt64, false),
        Field::new("request_truncated", DataType::Boolean, false),
        Field::new("model", utf8(), true),
        Field::new("provider", utf8(), true),
        Field::new("key_id", utf8(), true),
        Field::new("client", utf8(), true),
        Field::new("attempts", DataType::UInt32, false),
        Field::new("status", DataType::UInt16, true),
        Field::new("response_headers", utf8(), false),
        Field::new("response_body", utf8(), false),
        Field::new("response_bytes", DataType::UInt64, false),
        Field::new("response_truncated", DataType::Boolean, false),
        Field::new("upstream_attempts", utf8(), false),
    ]))
}

/// Turn exchanges into one arrow batch matching [`schema`].
pub fn batch_of(
    exchanges: &[CapturedExchange],
    schema: &SchemaRef,
) -> parquet::errors::Result<RecordBatch> {
    let attempts_json = exchanges
        .iter()
        .map(|e| {
            serde_json::to_string(
                &e.upstream_attempts
                    .iter()
                    .map(attempt_json)
                    .collect::<Vec<_>>(),
            )
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            parquet::errors::ParquetError::General(format!("cannot encode attempts: {e}"))
        })?;

    let columns: Vec<ArrayRef> = vec![
        Arc::new(UInt64Array::from_iter_values(
            exchanges.iter().map(|e| e.id),
        )),
        Arc::new(Int64Array::from_iter_values(
            exchanges.iter().map(|e| e.timestamp_ms as i64),
        )),
        Arc::new(UInt64Array::from_iter_values(
            exchanges.iter().map(|e| e.duration_ms),
        )),
        Arc::new(StringArray::from_iter_values(
            exchanges.iter().map(|e| e.method.as_str()),
        )),
        Arc::new(StringArray::from_iter_values(
            exchanges.iter().map(|e| e.uri.as_str()),
        )),
        Arc::new(StringArray::from_iter_values(
            exchanges.iter().map(|e| e.request_headers.as_str()),
        )),
        Arc::new(StringArray::from_iter_values(
            exchanges.iter().map(|e| e.request_body.as_str()),
        )),
        Arc::new(UInt64Array::from_iter_values(
            exchanges.iter().map(|e| e.request_bytes),
        )),
        Arc::new(BooleanArray::from_iter(
            exchanges.iter().map(|e| Some(e.request_truncated)),
        )),
        Arc::new(StringArray::from_iter(
            exchanges.iter().map(|e| e.model.as_deref()),
        )),
        Arc::new(StringArray::from_iter(
            exchanges.iter().map(|e| e.provider.as_deref()),
        )),
        Arc::new(StringArray::from_iter(
            exchanges.iter().map(|e| e.key.as_deref()),
        )),
        Arc::new(StringArray::from_iter(
            exchanges.iter().map(|e| e.client.as_deref()),
        )),
        Arc::new(UInt32Array::from_iter_values(
            exchanges.iter().map(|e| e.attempts),
        )),
        Arc::new(UInt16Array::from_iter(exchanges.iter().map(|e| e.status))),
        Arc::new(StringArray::from_iter_values(
            exchanges.iter().map(|e| e.response_headers.as_str()),
        )),
        Arc::new(StringArray::from_iter_values(
            exchanges.iter().map(|e| e.response_body.as_str()),
        )),
        Arc::new(UInt64Array::from_iter_values(
            exchanges.iter().map(|e| e.response_bytes),
        )),
        Arc::new(BooleanArray::from_iter(
            exchanges.iter().map(|e| Some(e.response_truncated)),
        )),
        Arc::new(StringArray::from_iter_values(
            attempts_json.iter().map(String::as_str),
        )),
    ];
    RecordBatch::try_new(Arc::clone(schema), columns)
        .map_err(|e| parquet::errors::ParquetError::ArrowError(e.to_string()))
}

fn attempt_json(attempt: &CapturedAttempt) -> serde_json::Value {
    serde_json::json!({
        "provider": attempt.provider,
        "key": attempt.key,
        "method": attempt.method,
        "url": attempt.url,
        "status": attempt.status,
        "headers": attempt.headers,
        "response_headers": attempt.response_headers,
        "response_body": attempt.response_body,
    })
}

/// Shared handle to the background parquet writer.
///
/// `record` never blocks on disk: it hands the row to a dedicated thread over
/// a bounded channel, and drops the row (with one warning) if that thread has
/// fallen irrecoverably behind. Diagnostics must not become an outage.
#[derive(Debug, Clone)]
pub struct CaptureWriter {
    sender: mpsc::SyncSender<CapturedExchange>,
    path: PathBuf,
    dropped: Arc<AtomicU64>,
}

impl CaptureWriter {
    /// Create (or truncate) `path` and start the writer thread.
    ///
    /// The file is created eagerly so an unwritable path fails at startup,
    /// not on the first request.
    pub fn create(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = File::create(&path)
            .map_err(|e| anyhow::anyhow!("cannot create capture file `{}`: {e}", path.display()))?;
        let schema = schema();
        // Write a valid empty file right away so the path is queryable from
        // startup, before any request has been proxied.
        ArrowWriter::try_new(file, Arc::clone(&schema), None)?.close()?;
        // std's channel, not tokio's: the writer is a plain thread with no
        // runtime, and tokio's blocking_recv panics outside one.
        let (sender, receiver) = mpsc::sync_channel(1024);
        let dropped = Arc::new(AtomicU64::new(0));
        let thread_path = path.clone();
        std::thread::Builder::new()
            .name("parquet-capture".into())
            .spawn(move || write_loop(schema, receiver, thread_path))?;
        Ok(Self {
            sender,
            path,
            dropped,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Queue one finished exchange. Never blocks the caller on disk I/O.
    pub fn record(&self, exchange: CapturedExchange) {
        if let Err(err) = self.sender.try_send(exchange) {
            let count = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
            // Warn on the first drop and every power of ten after: a full
            // channel means the disk cannot keep up, and a warning per
            // request would bury the very log being debugged.
            if count == 1 || count.is_power_of_ten() {
                tracing::warn!(
                    target: "llm_broker::dump",
                    dropped = count,
                    "capture file `{}` is falling behind: {err}",
                    self.path.display()
                );
            }
        }
    }

    /// Rows dropped because the writer could not keep up.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

trait PowerOfTen {
    fn is_power_of_ten(&self) -> bool;
}

impl PowerOfTen for u64 {
    fn is_power_of_ten(&self) -> bool {
        let mut n = *self;
        while n > 1 && n.is_multiple_of(10) {
            n /= 10;
        }
        n == 1
    }
}

/// The writer thread: batch rows, publish the file, finalize it on EOF.
///
/// Parquet has no append-in-place: a reader — DuckDB mid-run — only sees a
/// file whose footer is complete, and the footer is only written when the
/// writer closes. So each publish rewrites the whole file (previous rows
/// read back from disk, new rows appended) into a temporary file, closes
/// that, and renames it over the target. The rename is atomic: a reader
/// always sees either the old complete file or the new one, never a
/// half-written footer. The rewrite costs one read of the file per publish;
/// at the publish interval that is negligible next to the proxied traffic.
fn write_loop(schema: SchemaRef, receiver: mpsc::Receiver<CapturedExchange>, path: PathBuf) {
    let mut pending: Vec<CapturedExchange> = Vec::with_capacity(ROW_GROUP_ROWS);
    let mut last_publish = std::time::Instant::now();
    let mut dirty = false;
    loop {
        // With unpublished rows, wake up at the publish deadline even if no
        // new request arrives — an idle broker must still finalize the file.
        // Without any, block until the next row (or shutdown).
        let first = if dirty {
            match receiver.recv_timeout(PUBLISH_INTERVAL.saturating_sub(last_publish.elapsed())) {
                Ok(exchange) => Some(exchange),
                Err(mpsc::RecvTimeoutError::Timeout) => None,
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        } else {
            match receiver.recv() {
                Ok(exchange) => Some(exchange),
                Err(_) => break,
            }
        };
        if let Some(first) = first {
            pending.push(first);
            while pending.len() < ROW_GROUP_ROWS {
                match receiver.try_recv() {
                    Ok(exchange) => pending.push(exchange),
                    Err(_) => break,
                }
            }
            dirty = true;
        }
        if dirty && last_publish.elapsed() >= PUBLISH_INTERVAL {
            if let Err(error) = publish(&path, &schema, &pending) {
                tracing::warn!(
                    target: "llm_broker::dump",
                    "parquet capture publish failed: {error}"
                );
            }
            pending.clear();
            last_publish = std::time::Instant::now();
            dirty = false;
        }
    }
    // All senders are gone (shutdown): land whatever is left.
    if dirty && let Err(error) = publish(&path, &schema, &pending) {
        tracing::warn!(target: "llm_broker::dump", "final parquet capture publish failed: {error}");
    }
}

/// Rewrite `path` with its existing rows plus `pending`, atomically.
///
/// The previous rows are read back from the published file rather than kept
/// in memory, so a long-running broker's capture does not grow the heap.
fn publish(path: &Path, schema: &SchemaRef, pending: &[CapturedExchange]) -> anyhow::Result<()> {
    let mut batches: Vec<RecordBatch> = Vec::new();
    // An empty file (just created, nothing published yet) has no rows; a
    // non-empty file that fails to parse is an error, not "no rows" —
    // rewriting it would silently discard captured traffic.
    if path.metadata().map(|m| m.len() > 0).unwrap_or(false) {
        let file = File::open(path)?;
        let reader = ParquetRecordBatchReaderBuilder::try_new(file)?.build()?;
        for batch in reader {
            batches.push(batch?);
        }
    }
    if !pending.is_empty() {
        batches.push(batch_of(pending, schema)?);
    }
    let tmp = path.with_file_name(format!(
        "{}.tmp",
        path.file_name().unwrap_or_default().to_string_lossy()
    ));
    let props = WriterProperties::builder()
        .set_max_row_group_row_count(Some(ROW_GROUP_ROWS))
        .build();
    let mut writer = ArrowWriter::try_new(File::create(&tmp)?, Arc::clone(schema), Some(props))?;
    for batch in &batches {
        writer.write(batch)?;
    }
    writer.close()?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Unix epoch milliseconds, for correlating a capture with other logs.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Append `chunk` to `buffer`, keeping at most `cap` bytes and reporting
/// whether anything had to be dropped.
///
/// Truncation walks back to a UTF-8 boundary so the stored text is always
/// valid; the byte counters next to it carry the real size.
pub fn append_capped(buffer: &mut String, chunk: &[u8], cap: usize) -> bool {
    let room = cap.saturating_sub(buffer.len());
    if room == 0 {
        return !chunk.is_empty();
    }
    let take = chunk.len().min(room);
    let text = String::from_utf8_lossy(&chunk[..take]);
    buffer.push_str(&text);
    // Lossy conversion keeps the text valid UTF-8 even when the cap cuts
    // inside a multi-byte character; the byte counters carry the real size.
    take < chunk.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
    use std::time::Duration;

    fn exchange(id: u64) -> CapturedExchange {
        CapturedExchange {
            id,
            timestamp_ms: 1_700_000_000_000 + id,
            duration_ms: 42,
            method: "POST".into(),
            uri: "/v1/chat/completions".into(),
            request_headers: "content-type: application/json".into(),
            request_body: r#"{"model":"test-model","messages":[]}"#.into(),
            request_bytes: 35,
            model: Some("test-model".into()),
            provider: Some("openai".into()),
            key: Some("k1".into()),
            attempts: 2,
            status: Some(200),
            response_headers: "content-type: application/json".into(),
            response_body: r#"{"id":"mock"}"#.into(),
            response_bytes: 13,
            upstream_attempts: vec![
                CapturedAttempt {
                    provider: Some("openai".into()),
                    key: Some("k1".into()),
                    method: "POST".into(),
                    url: "https://up.test/v1/chat/completions".into(),
                    status: Some(429),
                    headers: "authorization: <redacted>".into(),
                    response_headers: "retry-after: 1".into(),
                    response_body: r#"{"error":"rate limited"}"#.into(),
                },
                CapturedAttempt {
                    provider: Some("openai".into()),
                    key: Some("k2".into()),
                    method: "POST".into(),
                    url: "https://up.test/v1/chat/completions".into(),
                    status: Some(200),
                    headers: "authorization: <redacted>".into(),
                    response_headers: "content-type: application/json".into(),
                    response_body: r#"{"id":"mock"}"#.into(),
                },
            ],
            ..CapturedExchange::default()
        }
    }

    fn temp_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("aibroker-parquet-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(name)
    }

    /// Read whatever has landed so far. A file the writer thread has not
    /// flushed yet has no footer, which reads as "no rows yet", not a panic.
    fn read_rows(path: &Path) -> Vec<RecordBatch> {
        let Ok(file) = File::open(path) else {
            return Vec::new();
        };
        let Ok(builder) = ParquetRecordBatchReaderBuilder::try_new(file) else {
            return Vec::new();
        };
        match builder.build() {
            Ok(reader) => reader.map(|b| b.unwrap()).collect(),
            Err(_) => Vec::new(),
        }
    }

    #[test]
    fn a_batch_round_trips_through_a_real_parquet_file() {
        let path = temp_path("roundtrip.parquet");
        let schema = schema();
        let mut writer =
            ArrowWriter::try_new(File::create(&path).unwrap(), Arc::clone(&schema), None).unwrap();
        writer
            .write(&batch_of(&[exchange(1), exchange(2)], &schema).unwrap())
            .unwrap();
        writer.close().unwrap();

        let batches = read_rows(&path);
        let rows: usize = batches.iter().map(|b| b.num_rows()).sum();
        assert_eq!(rows, 2);
        let batch = &batches[0];
        let column = |name: &str| {
            batch
                .column_by_name(name)
                .unwrap_or_else(|| panic!("missing column {name}"))
        };
        let ids = column("id").as_any().downcast_ref::<UInt64Array>().unwrap();
        assert_eq!(ids.values(), &[1, 2]);
        let bodies = column("request_body")
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert!(bodies.value(0).contains("test-model"));
        let statuses = column("status")
            .as_any()
            .downcast_ref::<UInt16Array>()
            .unwrap();
        assert_eq!(statuses.value(0), 200);
        // The rotation is inspectable: two attempts, first a 429 on k1.
        let attempts = column("upstream_attempts")
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(attempts.value(0)).unwrap();
        assert_eq!(parsed.as_array().unwrap().len(), 2);
        assert_eq!(parsed[0]["status"], 429);
        assert_eq!(parsed[0]["key"], "k1");
        assert_eq!(parsed[1]["key"], "k2");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn the_writer_thread_persists_rows_without_an_explicit_close() {
        // The proxy never gets a shutdown hook (run_forever), so a row must be
        // readable while the broker is still running.
        let path = temp_path("live.parquet");
        let writer = CaptureWriter::create(&path).unwrap();
        writer.record(exchange(7));
        writer.record(exchange(8));

        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            let rows: usize = read_rows(&path).iter().map(|b| b.num_rows()).sum();
            if rows == 2 {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "rows never landed on disk"
            );
            std::thread::sleep(Duration::from_millis(25));
        }
        assert_eq!(writer.dropped(), 0);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn an_unwritable_path_fails_at_creation() {
        let error = CaptureWriter::create("/nonexistent-dir-8f2c/traffic.parquet").unwrap_err();
        assert!(
            error.to_string().contains("cannot create capture file"),
            "{error}"
        );
    }

    #[test]
    fn append_capped_keeps_utf8_valid_and_reports_truncation() {
        let mut buffer = String::new();
        assert!(!append_capped(&mut buffer, "héllo".as_bytes(), 1024));
        assert_eq!(buffer, "héllo");
        // Cap in the middle of the two-byte é: the text stays valid UTF-8.
        let mut buffer = String::new();
        assert!(append_capped(&mut buffer, "héllo".as_bytes(), 2));
        assert!(buffer.starts_with('h'));
        let full = buffer.len();
        // Once full, everything further is reported as dropped.
        assert!(append_capped(&mut buffer, b"x", full));
        assert_eq!(buffer.len(), full);
    }
}
