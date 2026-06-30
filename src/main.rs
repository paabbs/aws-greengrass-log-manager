// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! gg-log-manager - Greengrass LogManager Generic Type Component
//!
//! Rust implementation of aws.greengrass.LogManager for GG Classic and GG Lite.
//! Tails log files and EMF JSON files, uploads to CloudWatch Logs.

use gg_log_manager::config::{
    derive_log_group_name, load_config, validate_config, ConfigError, LogLevel, LogManagerConfig,
    LogSourceConfig,
};
use gg_log_manager::credentials::resolve_thing_name;
use gg_log_manager::scanner::{
    assemble_multiline, load_checkpoint, read_file_from_offset, recover_offsets, save_checkpoint,
    scan_directory, trim_stale_on_load, CheckpointStore, LastFileProcessedTimestamp, LogEvent,
    ScannedFile,
};
use gg_log_manager::uploader::{
    advance_checkpoints, effective_interval_secs, evict_stale_entries, format_log_stream_name,
    mtime_to_ms, upload_source_events, CwLogsClient, TTL_24H_MS,
};

use regex::Regex;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Notify;
use tokio::time::Duration;
use tracing::{error, info, warn};

static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

#[cfg(not(tarpaulin_include))]
#[tokio::main(flavor = "current_thread")]
async fn main() {
    tracing_subscriber::fmt::init();

    let args: Vec<String> = std::env::args().collect();
    let raw_config = resolve_raw_config(&args);
    let work_dir = parse_arg(&args, "--work-dir").unwrap_or_else(|| ".".to_string());

    let config = match load_config(&raw_config) {
        Ok(c) => c,
        Err(e) => {
            error!("Config load error: {e}");
            std::process::exit(1);
        }
    };

    if let Err(e) = validate_config(&config) {
        error!("Config validation error: {e}");
        std::process::exit(1);
    }

    info!(
        components = ?config
            .logs_uploader_configuration
            .component_logs_configuration_map
            .keys()
            .collect::<Vec<_>>(),
        system_logs = config
            .logs_uploader_configuration
            .system_logs_configuration
            .is_some(),
        interval_sec = config.periodic_upload_interval_sec,
        "Configuration loaded"
    );

    // Resolve the thing name used in the log stream path. Missing/empty is non-fatal:
    // log and continue with a placeholder so uploads still flow to a discoverable stream.
    let thing_name = resolve_thing_name().unwrap_or_else(|| {
        error!("AWS_IOT_THING_NAME not set or empty, using 'unknown'");
        "unknown".to_string()
    });

    let checkpoint_path = Path::new(&work_dir).join("checkpoint.json");
    let mut store = load_checkpoint(&checkpoint_path).unwrap_or_else(|e| {
        error!("Failed to load checkpoint: {e}, starting fresh");
        CheckpointStore::default()
    });
    trim_stale_on_load(&mut store);

    let mut client = CwLogsClient::new().await;

    // Shutdown signal handling (Ctrl-C and, on Unix, SIGTERM).
    let shutdown_notify = Arc::new(Notify::new());
    let shutdown_clone = shutdown_notify.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        initiate_shutdown(&shutdown_clone);
    });
    #[cfg(unix)]
    {
        let shutdown_sigterm = shutdown_notify.clone();
        tokio::spawn(async move {
            let mut sigterm =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("Failed to register SIGTERM handler");
            sigterm.recv().await;
            initiate_shutdown(&shutdown_sigterm);
        });
    }

    // TODO: a LogManager struct that owns the client, checkpoint store, thing name, and
    // checkpoint path would let the loop and the process_* helpers carry less state. That
    // refactor is future work; the orchestration is kept as free functions for now.
    let mut last_persist = Instant::now();
    let persist_interval = Duration::from_secs(config.periodic_upload_interval_sec);

    // Fixed-delay loop: each cycle processes every source, then waits the upload interval
    // — plus 0–5s of jitter from effective_interval_secs, to avoid a thundering herd —
    // before starting the next cycle. This matches the aws.greengrass.LogManager component,
    // which sleeps the periodic upload interval after each pass rather than firing at a
    // fixed rate, so a slow cycle never overlaps the next.
    loop {
        if SHUTDOWN_REQUESTED.load(Ordering::SeqCst) {
            break;
        }

        process_all_sources(&config, &mut client, &mut store, &thing_name).await;

        // Persist the checkpoint at most once per interval. The component uses a separate
        // tlog-update interval for this; that dedicated cadence is not yet wired, so the
        // persist follows the upload interval.
        if last_persist.elapsed() >= persist_interval {
            if let Err(e) = save_checkpoint(&checkpoint_path, &store) {
                error!("Failed to persist checkpoint: {e}");
            }
            last_persist = Instant::now();
        }

        // TODO: honor per-source uploadIntervalSec here. It is parsed but not yet wired,
        // so every source currently uploads on the global periodicUploadIntervalSec cadence.
        let sleep_secs = effective_interval_secs(None, config.periodic_upload_interval_sec);
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(sleep_secs)) => {}
            _ = shutdown_notify.notified() => { break; }
        }
    }

    // Persist the checkpoint unconditionally on the way out so progress is not lost.
    info!("Shutting down — persisting final checkpoint");
    if let Err(e) = save_checkpoint(&checkpoint_path, &store) {
        error!("Failed to persist checkpoint on shutdown: {e}");
    }
    info!("Shutdown complete");
}

/// Resolve the raw config from an ordered list of sources; the first source that yields
/// a value wins. Keeping the lookup behind this seam lets `load_config`, `parse_config`,
/// and `validate_config` stay agnostic about where the configuration came from.
///
/// Order today: (1) CLI `--config <inline-json-or-path>`, (2) env `GG_LOG_MANAGER_CONFIG`,
/// (3) the empty-object default.
// TODO: prepend a Greengrass IPC GetConfiguration source (device-primary) once the
// component SDK integration lands; on a device it should take precedence over the CLI/env
// fallbacks used for local runs and tests.
fn resolve_raw_config(args: &[String]) -> String {
    for source in [config_from_cli(args), config_from_env()] {
        match source {
            Ok(Some(raw)) => return raw,
            Ok(None) => {}
            Err(e) => error!("Config source error: {e}; trying next source"),
        }
    }
    // (3) DEFAULT: empty object — start with no sources configured.
    "{}".to_string()
}

/// (1) CLI source: the `--config` argument value (inline JSON or a file path), if present.
fn config_from_cli(args: &[String]) -> Result<Option<String>, ConfigError> {
    Ok(parse_arg(args, "--config"))
}

/// (2) Env source: the `GG_LOG_MANAGER_CONFIG` variable (inline JSON or a file path), if
/// set and non-empty.
fn config_from_env() -> Result<Option<String>, ConfigError> {
    Ok(std::env::var("GG_LOG_MANAGER_CONFIG")
        .ok()
        .filter(|s| !s.is_empty()))
}

/// Process all configured log sources in one cycle.
/// Collects all sources (component + system) into a uniform list and processes them
/// sequentially, matching the component's single-threaded per-source processing.
#[cfg(not(tarpaulin_include))]
async fn process_all_sources(
    config: &LogManagerConfig,
    client: &mut CwLogsClient,
    store: &mut CheckpointStore,
    thing_name: &str,
) {
    // Collect all sources as (source, log_group).
    let mut sources: Vec<(&LogSourceConfig, String)> = Vec::new();

    for (name, comp) in &config
        .logs_uploader_configuration
        .component_logs_configuration_map
    {
        let log_group = comp
            .log_group_name
            .as_deref()
            .map(str::to_string)
            .unwrap_or_else(|| derive_log_group_name(name, None));
        sources.push((&comp.source, log_group));
    }

    if let Some(ref sys) = config.logs_uploader_configuration.system_logs_configuration {
        let enabled = sys.upload_to_cloud_watch;
        // TODO: when logFileDirectoryPath/logFileRegex are unset on the system source,
        // they should be runtime-resolved from the Nucleus logging configuration (via the
        // component SDK GetConfiguration) rather than skipped. That derivation lands with
        // the IPC work; until then an unconfigured system source is skipped with a warning.
        if enabled && !sys.source.log_file_directory_path.is_empty() {
            let log_group = sys
                .log_group_name
                .as_deref()
                .map(str::to_string)
                .unwrap_or_else(|| {
                    derive_log_group_name("System", Some("GreengrassSystemComponent"))
                });
            sources.push((&sys.source, log_group));
        } else if enabled {
            warn!("systemLogsConfiguration has uploadToCloudWatch enabled but no logFileDirectoryPath configured — skipping");
        }
    }

    // TODO: per-source fault isolation/containment is future work. Sources are processed
    // sequentially (matching the component), so a slow or failing source delays the rest.
    for (source, log_group) in sources {
        if SHUTDOWN_REQUESTED.load(Ordering::SeqCst) {
            return;
        }
        let pattern = match Regex::new(&source.log_file_regex) {
            Ok(r) => r,
            Err(e) => {
                error!(log_group, error = %e, "Invalid file regex, skipping");
                continue;
            }
        };
        process_source(source, &log_group, &pattern, client, store, thing_name).await;
    }
}

/// Process a single log source: scan → read → batch → upload → checkpoint → disk.
// Note: uses std::fs (blocking I/O) inside async. This is safe because we run on the
// tokio current_thread runtime — there are no other tasks to block. If the runtime is
// ever changed to multi-thread, these calls must be replaced with tokio::fs.
#[cfg(not(tarpaulin_include))]
async fn process_source(
    source: &LogSourceConfig,
    log_group: &str,
    pattern: &Regex,
    client: &mut CwLogsClient,
    store: &mut CheckpointStore,
    thing_name: &str,
) {
    let scanned_files = match scan_and_filter_files(source, log_group, pattern, store) {
        Some(files) => files,
        None => return,
    };

    let file_events = read_file_events(source, log_group, &scanned_files, store);
    if file_events.is_empty() {
        return;
    }

    upload_and_advance_checkpoints(
        source,
        log_group,
        pattern,
        client,
        store,
        thing_name,
        &scanned_files,
        file_events,
    )
    .await;
}

/// Scan the configured log directory for files matching the regex, then drop files older
/// than the component's last successfully uploaded file (unless still mid-upload) to avoid
/// re-processing completed files.
fn scan_and_filter_files(
    source: &LogSourceConfig,
    log_group: &str,
    pattern: &Regex,
    store: &CheckpointStore,
) -> Option<Vec<ScannedFile>> {
    let scanned_files = match scan_directory(&source.log_file_directory_path, pattern) {
        Ok(files) => files,
        Err(e) => {
            error!(directory = source.log_file_directory_path, error = %e, "Failed to scan directory");
            return None;
        }
    };

    if scanned_files.is_empty() {
        return None;
    }

    let last_ts = store
        .last_processed_timestamps
        .get(log_group)
        .map(|t| t.last_file_processed_time_stamp)
        .unwrap_or(0);
    let scanned_files: Vec<_> = scanned_files
        .into_iter()
        .filter(|f| {
            mtime_to_ms(f.mtime) > last_ts
                || store
                    .file_processing_info
                    .get(log_group)
                    .is_some_and(|m| m.contains_key(&f.content_hash))
        })
        .collect();

    if scanned_files.is_empty() {
        return None;
    }

    Some(scanned_files)
}

/// Read new content from each scanned file starting at its checkpointed byte offset, then
/// assemble multi-line log entries when a start pattern is configured.
fn read_file_events(
    source: &LogSourceConfig,
    log_group: &str,
    scanned_files: &[ScannedFile],
    store: &mut CheckpointStore,
) -> Vec<(PathBuf, Vec<LogEvent>, u64, String)> {
    let offsets = recover_offsets(store, log_group, scanned_files);
    let multi_regex = source
        .multi_line_start_pattern
        .as_deref()
        .and_then(|p| Regex::new(p).ok());
    let default_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;

    let mut file_events: Vec<(PathBuf, Vec<LogEvent>, u64, String)> =
        Vec::with_capacity(offsets.len());

    for (path, offset) in &offsets {
        // Handle the rotation edge case: a file already fully read and no longer active is
        // marked completed (checkpoint cleared, timestamp advanced, deleted if configured).
        let file_len = match std::fs::metadata(path) {
            Ok(m) => m.len(),
            Err(e) => {
                tracing::debug!(path = %path.display(), error = %e, "Cannot stat file, skipping");
                continue;
            }
        };
        if *offset >= file_len && file_len > 0 {
            let scanned_file = scanned_files.iter().find(|f| f.path == *path);
            let is_active = scanned_file.is_some_and(|f| f.is_active);
            if !is_active {
                if let Some(sf) = scanned_file {
                    if let Some(file_map) = store.file_processing_info.get_mut(log_group) {
                        file_map.remove(&sf.content_hash);
                    }
                    let mtime_ms = mtime_to_ms(sf.mtime);
                    let ts = store
                        .last_processed_timestamps
                        .entry(log_group.to_string())
                        .or_insert(LastFileProcessedTimestamp {
                            last_file_processed_time_stamp: 0,
                        });
                    if mtime_ms > ts.last_file_processed_time_stamp {
                        ts.last_file_processed_time_stamp = mtime_ms;
                    }
                    if source.delete_log_file_after_cloud_upload {
                        if let Err(e) = std::fs::remove_file(path) {
                            warn!(path = %path.display(), error = %e, "Failed to delete completed file");
                        } else {
                            info!(path = %path.display(), "Deleted completed file (rotation edge case)");
                        }
                    }
                }
                continue;
            }
        }

        let (events, new_offset) = match read_file_from_offset(path, *offset, default_ts) {
            Ok(result) => result,
            Err(e) => {
                warn!(path = %path.display(), error = %e, "Failed to read file, skipping");
                continue;
            }
        };

        if events.is_empty() {
            continue;
        }

        let assembled = assemble_multiline(events, multi_regex.as_ref());

        let content_hash = scanned_files
            .iter()
            .find(|f| f.path == *path)
            .map(|f| f.content_hash.clone())
            .unwrap_or_default();

        file_events.push((path.clone(), assembled, new_offset, content_hash));
    }

    file_events
}

/// Upload batched events, advance checkpoints for fully-uploaded files, delete completed
/// files when configured, and enforce the disk-space limit.
#[cfg(not(tarpaulin_include))]
#[allow(clippy::too_many_arguments)]
async fn upload_and_advance_checkpoints(
    source: &LogSourceConfig,
    log_group: &str,
    pattern: &Regex,
    client: &mut CwLogsClient,
    store: &mut CheckpointStore,
    thing_name: &str,
    scanned_files: &[ScannedFile],
    file_events: Vec<(PathBuf, Vec<LogEvent>, u64, String)>,
) {
    let log_stream = format_log_stream_name(thing_name);

    // DEBUG means "no filtering" — all events pass through.
    let min_level = if matches!(source.minimum_log_level, LogLevel::Debug) {
        None
    } else {
        Some(source.minimum_log_level)
    };

    let result = upload_source_events(client, log_group, &log_stream, file_events, min_level).await;

    if !result.succeeded.is_empty() {
        let completed = advance_checkpoints(store, log_group, &result.succeeded, scanned_files);

        if source.delete_log_file_after_cloud_upload {
            for path in &completed {
                if let Err(e) = std::fs::remove_file(path) {
                    warn!(path = %path.display(), error = %e, "Failed to delete completed file");
                } else {
                    info!(path = %path.display(), "Deleted completed file after upload");
                }
            }
        }

        // Disk-space enforcement runs only after a successful upload and only deletes
        // fully-uploaded files (matching the component's design).
        // TODO: when the directory is over the disk limit AND the upload did not complete,
        // nothing is freed this cycle because only successfully-uploaded files are
        // deletable. Revisiting this trade-off (e.g. enforcing even without a successful
        // upload) is future work.
        if let Some(limit_str) = source.disk_space_limit.as_deref() {
            if let Ok(limit_val) = limit_str.parse::<u64>() {
                let limit_bytes = source.disk_space_limit_unit.to_bytes(limit_val);
                let last_ts = store
                    .last_processed_timestamps
                    .get(log_group)
                    .map(|t| t.last_file_processed_time_stamp)
                    .unwrap_or(0);
                let all_eligible: Vec<PathBuf> = scanned_files
                    .iter()
                    .filter(|f| !f.is_active)
                    .filter(|f| mtime_to_ms(f.mtime) <= last_ts)
                    .map(|f| f.path.clone())
                    .collect();
                let deleted = gg_log_manager::disk::free_disk_space(
                    Path::new(&source.log_file_directory_path),
                    pattern,
                    limit_bytes,
                    &all_eligible,
                );
                if !deleted.is_empty() {
                    if let Some(file_map) = store.file_processing_info.get_mut(log_group) {
                        for del_path in &deleted {
                            if let Some(sf) = scanned_files.iter().find(|f| f.path == *del_path) {
                                file_map.remove(&sf.content_hash);
                            }
                        }
                    }
                }
            }
        }
    }

    // Evict stale checkpoint entries each cycle to keep the checkpoint from growing
    // unbounded as files rotate away.
    evict_stale_entries(store, log_group, TTL_24H_MS);

    if !result.failed.is_empty() {
        warn!(
            log_group,
            failed_files = result.failed.len(),
            "Some files failed upload — will retry next cycle"
        );
    }
}

fn parse_arg(args: &[String], flag: &str) -> Option<String> {
    for i in 0..args.len() {
        if args[i] == flag && i + 1 < args.len() {
            return Some(args[i + 1].clone());
        }
    }
    None
}

fn initiate_shutdown(notify: &Notify) {
    if !SHUTDOWN_REQUESTED.swap(true, Ordering::SeqCst) {
        info!("Received shutdown signal");
        notify.notify_one();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[test]
    fn test_parse_arg_with_flag() {
        let args = vec![
            "bin".to_string(),
            "--config".to_string(),
            "/path/config.json".to_string(),
        ];
        assert_eq!(
            parse_arg(&args, "--config"),
            Some("/path/config.json".to_string())
        );
    }

    #[test]
    fn test_parse_arg_missing() {
        let args = vec!["bin".to_string()];
        assert_eq!(parse_arg(&args, "--config"), None);
    }

    #[test]
    fn test_parse_arg_flag_at_end() {
        let args = vec!["bin".to_string(), "--config".to_string()];
        assert_eq!(parse_arg(&args, "--config"), None);
    }

    #[test]
    fn test_parse_arg_work_dir() {
        let args = vec![
            "bin".to_string(),
            "--work-dir".to_string(),
            "/tmp/work".to_string(),
        ];
        assert_eq!(
            parse_arg(&args, "--work-dir"),
            Some("/tmp/work".to_string())
        );
    }

    #[test]
    fn test_config_from_cli_present() {
        let args = vec!["bin".to_string(), "--config".to_string(), "{}".to_string()];
        assert_eq!(config_from_cli(&args).unwrap(), Some("{}".to_string()));
    }

    #[test]
    fn test_config_from_cli_absent() {
        let args = vec!["bin".to_string()];
        assert_eq!(config_from_cli(&args).unwrap(), None);
    }

    #[test]
    #[serial]
    fn test_config_from_env_present_and_absent() {
        std::env::set_var(
            "GG_LOG_MANAGER_CONFIG",
            r#"{"periodicUploadIntervalSec":7}"#,
        );
        assert_eq!(
            config_from_env().unwrap(),
            Some(r#"{"periodicUploadIntervalSec":7}"#.to_string())
        );
        // Empty is treated as absent.
        std::env::set_var("GG_LOG_MANAGER_CONFIG", "");
        assert_eq!(config_from_env().unwrap(), None);
        std::env::remove_var("GG_LOG_MANAGER_CONFIG");
        assert_eq!(config_from_env().unwrap(), None);
    }

    #[test]
    #[serial]
    fn test_resolve_raw_config_cli_wins_over_env() {
        std::env::set_var("GG_LOG_MANAGER_CONFIG", "ENV");
        let args = vec!["bin".to_string(), "--config".to_string(), "CLI".to_string()];
        assert_eq!(resolve_raw_config(&args), "CLI");
        std::env::remove_var("GG_LOG_MANAGER_CONFIG");
    }

    #[test]
    #[serial]
    fn test_resolve_raw_config_env_used_without_cli() {
        std::env::set_var("GG_LOG_MANAGER_CONFIG", "ENV");
        let args = vec!["bin".to_string()];
        assert_eq!(resolve_raw_config(&args), "ENV");
        std::env::remove_var("GG_LOG_MANAGER_CONFIG");
    }

    #[test]
    #[serial]
    fn test_resolve_raw_config_default_when_no_source() {
        std::env::remove_var("GG_LOG_MANAGER_CONFIG");
        let args = vec!["bin".to_string()];
        assert_eq!(resolve_raw_config(&args), "{}");
    }

    #[test]
    fn test_initiate_shutdown_sets_flag() {
        SHUTDOWN_REQUESTED.store(false, Ordering::SeqCst);
        let notify = Notify::new();
        initiate_shutdown(&notify);
        assert!(SHUTDOWN_REQUESTED.load(Ordering::SeqCst));
    }

    #[test]
    fn test_initiate_shutdown_idempotent() {
        SHUTDOWN_REQUESTED.store(false, Ordering::SeqCst);
        let notify = Notify::new();
        initiate_shutdown(&notify);
        initiate_shutdown(&notify); // Second call should be a no-op.
        assert!(SHUTDOWN_REQUESTED.load(Ordering::SeqCst));
    }
}
