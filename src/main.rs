use std::io::{self, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use clap::Parser;

use tlscap::ek_output::{EkWriter, NdjsonWriter};
use tlscap::keylog::Keylog;
use tlscap::keylog_source::KeylogSource;
use tlscap::lua::LuaEngine;
use tlscap::orchestrator::{DecodedMessage, Orchestrator, OrchestratorConfig, PacketEvent};
use tlscap::rotation::{RotateBy, RotatingGzWriter};
use tlscap::{memstats, pcap_input, plugin_loader, reassembly};

/// A tshark-compatible, Lua-pluggable, TLS-decrypting live packet capture tool.
///
/// Reads a pcap/pcapng stream on stdin (e.g. `tcpdump -w - | tlscap ...`), decrypts TLS 1.2/1.3
/// application data via a growing SSLKEYLOGFILE, and dissects it using unmodified Wireshark Lua
/// plugins. Output matches `tshark -T ek -e <field> ...` (or, with `-T ndjson`, a single-JSON-
/// object-per-line format with no Elasticsearch bulk index-action line -- see `ek_output.rs`).
#[derive(Parser, Debug)]
#[command(name = "tlscap", version)]
struct Cli {
    /// Path to a growing SSLKEYLOGFILE-format keylog (e.g. written by jSSLKeyLog). If omitted, no
    /// TLS record is ever decrypted -- `-w`'s decoded-message output stays empty, but
    /// `--packet-log`'s per-frame events (SYN/FIN/RST/ACK) are emitted regardless, since they
    /// never depend on decryption.
    #[arg(long, env = "TLSCAP_KEYLOG")]
    keylog: Option<PathBuf>,

    /// How often to check the keylog file for new secrets (a decrypt miss also triggers an
    /// immediate out-of-cycle check regardless of this interval).
    #[arg(long, default_value_t = 5)]
    keylog_reload_interval: u64,

    /// Directory to scan for Wireshark Lua dissector plugins (*.lua, non-recursive). Repeatable.
    #[arg(long = "plugin-dir", default_value = "/usr/lib/tlscap/plugins")]
    plugin_dirs: Vec<PathBuf>,

    /// Load one specific Lua dissector script (tshark's `-X lua_script:` equivalent). Repeatable.
    #[arg(long = "lua-script")]
    lua_scripts: Vec<PathBuf>,

    /// Select an output field by name (e.g. `ip.src`, `myproto.field.kv`). Repeatable; order is
    /// preserved in output. At least one is required to produce non-empty output. Under
    /// `-T ndjson`, selection works at group granularity (`ip.src`/`ip.dst` both just mean
    /// "include `ip`") -- see `ek_output.rs::NdjsonWriter`'s doc comment.
    #[arg(short = 'e', long = "field")]
    fields: Vec<String>,

    /// Output format: `ek` (tshark's `-T ek`, two lines per message, everything stringified) or
    /// `ndjson` (one JSON object per line, type-aware, structure-aware -- for direct ingestion by
    /// tools like Athena/Glue that expect one record per line, not an Elasticsearch bulk payload).
    #[arg(short = 'T', long = "format", default_value = "ek")]
    format: String,

    /// `_index` prefix for the `-T ek` index-action line (`<prefix>-YYYY-MM-DD`). Not used by
    /// `-T ndjson` (it has no index-action line at all).
    #[arg(long, default_value = "packets")]
    ek_index_prefix: String,

    /// Output file prefix, or `-` for stdout (uncompressed, unrotated). Chunk files are named
    /// `<prefix>_NNNNNN_YYYYMMDDHHMMSS.gz`, matching editcap's own naming convention.
    #[arg(short = 'w', long = "output")]
    output: String,

    /// A second, independent rotating output for this frame's own header-level event
    /// (SYN/FIN/RST/ACK, emitted for every frame regardless of whether it carries TLS data) --
    /// same prefix/rotation semantics as `-w`. Requires `-T ndjson` (packet events have no `-T ek`
    /// shape at all). Unset (the default) disables packet-level output entirely.
    #[arg(long = "packet-log")]
    packet_log: Option<String>,

    /// `-T ndjson` only. Split a top-level, repeated Lua-produced field's N occurrences into N
    /// separate output lines (envelope repeated on each, the field rendered singular) instead of
    /// one line with an N-element array. Zero occurrences still emits exactly one line, without
    /// the field -- see `ek_output.rs::NdjsonWriter`'s doc comment.
    #[arg(long = "ndjson-explode")]
    ndjson_explode: Option<String>,

    /// `-T ndjson` only. Collapse a repeated `{name, value, ...}` subtree group (found at any
    /// nesting depth) into a JSON map keyed by each occurrence's own `name` leaf, valued by its
    /// `value` leaf -- other sub-fields dropped, an occurrence missing `name` skipped entirely.
    /// Repeatable. See `ek_output.rs::NdjsonWriter`'s doc comment.
    #[arg(long = "ndjson-map")]
    ndjson_map: Vec<String>,

    /// Rotate output after this many dissected messages. Mutually exclusive with `--rotate-seconds`.
    /// Governs both `-w` and `--packet-log` (one shared rotation policy, not a separate one per
    /// stream).
    #[arg(short = 'c', long = "rotate-count")]
    rotate_count: Option<u64>,

    /// Rotate output after this many seconds. Mutually exclusive with `--rotate-count`.
    #[arg(short = 'i', long = "rotate-seconds")]
    rotate_seconds: Option<u64>,

    /// Compression for file output. `gzip` is the only supported value (matching editcap).
    #[arg(long)]
    compress: Option<String>,

    /// Evict a connection after this many seconds of inactivity, REGARDLESS of FIN/RST state.
    /// Off (0) by default and deliberately so: production guidance is to leave this disabled so
    /// no data from a merely-idle (not dead) connection is ever lost. FIN/RST is the real,
    /// always-on eviction signal (see orchestrator.rs) -- this is a secondary safety net only,
    /// for connections truly abandoned without a clean close.
    #[arg(long, default_value_t = 0)]
    idle_timeout_seconds: u64,

    /// Per-(connection,direction) cap on out-of-order-buffered bytes before a gap is treated as
    /// abandoned (logged loudly, never silent -- see reassembly.rs).
    #[arg(long, default_value_t = reassembly::DEFAULT_MAX_PENDING_BYTES)]
    max_pending_bytes: usize,

    /// Log a memory/connection-tracking stats line every N seconds: process RSS, active
    /// connections, bytes buffered in reassembly, keylog entry count, and running packet/message
    /// counters. Helps diagnose gradual memory growth (e.g. an OOM-killed decode process) without
    /// an external profiler. 0 disables periodic stats logging.
    #[arg(long, default_value_t = 60)]
    stats_interval_seconds: u64,
}

fn main() {
    let cli = Cli::parse();

    if cli.rotate_count.is_some() && cli.rotate_seconds.is_some() {
        eprintln!("tlscap: --rotate-count and --rotate-seconds are mutually exclusive");
        std::process::exit(2);
    }
    if cli.format != "ek" && cli.format != "ndjson" {
        eprintln!("tlscap: -T must be 'ek' or 'ndjson' (got: {})", cli.format);
        std::process::exit(2);
    }
    if cli.packet_log.is_some() && cli.format != "ndjson" {
        eprintln!(
            "tlscap: --packet-log requires -T ndjson (packet events have no -T ek representation)"
        );
        std::process::exit(2);
    }
    if cli.ndjson_explode.is_some() && cli.format != "ndjson" {
        eprintln!("tlscap: --ndjson-explode requires -T ndjson");
        std::process::exit(2);
    }
    if !cli.ndjson_map.is_empty() && cli.format != "ndjson" {
        eprintln!("tlscap: --ndjson-map requires -T ndjson");
        std::process::exit(2);
    }
    if let Some(c) = &cli.compress
        && c != "gzip"
    {
        eprintln!("tlscap: --compress only supports 'gzip' (got: {c})");
        std::process::exit(2);
    }

    if let Err(e) = run(cli) {
        eprintln!("tlscap: fatal: {e}");
        std::process::exit(1);
    }
}

// A single `Output` value is created once and lives for the whole process -- boxing the larger
// variant would only add indirection with no real benefit here (this isn't a hot array of them).
#[allow(clippy::large_enum_variant)]
enum Output {
    Stdout,
    Rotating(RotatingGzWriter),
}

impl Output {
    fn new(prefix: &str, rotate_by: RotateBy) -> Self {
        if prefix == "-" {
            Output::Stdout
        } else {
            Output::Rotating(RotatingGzWriter::new(PathBuf::from(prefix), rotate_by))
        }
    }

    fn write(&mut self, data: &[u8]) -> io::Result<()> {
        match self {
            Output::Stdout => {
                let stdout = io::stdout();
                let mut lock = stdout.lock();
                lock.write_all(data)?;
                lock.flush()
            }
            Output::Rotating(w) => w.write_message(data),
        }
    }

    fn finish(&mut self) -> io::Result<()> {
        match self {
            Output::Stdout => io::stdout().flush(),
            Output::Rotating(w) => w.finish_current(),
        }
    }
}

/// Dispatches to whichever `-T` format was selected, for both output streams `main.rs` can have
/// open (`-w`'s decrypted messages, `--packet-log`'s raw frame events).
enum MessageWriter {
    Ek(EkWriter),
    Ndjson(NdjsonWriter),
}

impl MessageWriter {
    fn write_tls_record(&self, buf: &mut Vec<u8>, msg: &DecodedMessage) -> io::Result<()> {
        match self {
            MessageWriter::Ek(w) => w.write_message(buf, msg).map(|_| ()),
            MessageWriter::Ndjson(w) => w.write_tls_record(buf, msg).map(|_| ()),
        }
    }

    /// Only ever called when `format == ndjson` -- `main()` validates `--packet-log` requires
    /// `-T ndjson` before `run()` is even reached, so the `Ek` arm here is unreachable in
    /// practice. A hard panic rather than a silent no-op: a future bug wiring this up wrong should
    /// fail loudly, not quietly drop every packet event.
    fn write_packet_event(&self, buf: &mut Vec<u8>, evt: &PacketEvent) -> io::Result<()> {
        match self {
            MessageWriter::Ek(_) => {
                unreachable!("validated in main(): --packet-log requires -T ndjson")
            }
            MessageWriter::Ndjson(w) => w.write_packet_event(buf, evt).map(|_| ()),
        }
    }
}

fn run(cli: Cli) -> io::Result<()> {
    let keylog = match &cli.keylog {
        Some(path) => KeylogSource::open(
            path.clone(),
            Duration::from_secs(cli.keylog_reload_interval),
        )
        .map_err(|e| io::Error::new(e.kind(), format!("opening keylog {}: {e}", path.display())))?,
        None => {
            eprintln!(
                "tlscap: no --keylog given -- TLS records will never decrypt, packet-log output is unaffected"
            );
            KeylogSource::from_parsed(Keylog::parse(""))
        }
    };

    let lua =
        LuaEngine::new().map_err(|e| io::Error::other(format!("initializing Lua engine: {e}")))?;
    let mut plugins_loaded = 0;
    for dir in &cli.plugin_dirs {
        plugins_loaded += plugin_loader::load_directory(&lua, dir)
            .map_err(|e| io::Error::other(e.to_string()))?;
    }
    plugin_loader::load_scripts(&lua, &cli.lua_scripts)
        .map_err(|e| io::Error::other(e.to_string()))?;
    eprintln!(
        "tlscap: loaded {plugins_loaded} plugin(s) from directory scan, {} explicit script(s)",
        cli.lua_scripts.len()
    );

    let idle_timeout = if cli.idle_timeout_seconds == 0 {
        None
    } else {
        Some(Duration::from_secs(cli.idle_timeout_seconds))
    };
    if idle_timeout.is_none() {
        eprintln!(
            "tlscap: idle-timeout eviction is OFF (default) -- FIN/RST is the only eviction driver"
        );
    }
    let config = OrchestratorConfig {
        idle_timeout,
        sweep_interval: Duration::from_secs(60),
        max_pending_bytes: cli.max_pending_bytes,
    };
    let mut orchestrator = Orchestrator::new(keylog, lua, config);

    let writer = if cli.format == "ndjson" {
        MessageWriter::Ndjson(NdjsonWriter::new(
            cli.fields.clone(),
            cli.ndjson_explode.clone(),
            cli.ndjson_map.clone(),
        ))
    } else {
        MessageWriter::Ek(EkWriter::new(
            cli.fields.clone(),
            cli.ek_index_prefix.clone(),
        ))
    };

    let rotate_by = match (cli.rotate_count, cli.rotate_seconds) {
        (Some(n), None) => RotateBy::Count(n),
        (None, Some(s)) => RotateBy::Seconds(Duration::from_secs(s)),
        (None, None) => RotateBy::Never,
        (Some(_), Some(_)) => unreachable!("validated mutually exclusive above"),
    };
    let mut output = Output::new(&cli.output, rotate_by);
    let mut packet_output = cli
        .packet_log
        .as_deref()
        .map(|prefix| Output::new(prefix, rotate_by));

    let stdin = io::stdin();
    let mut source = match pcap_input::open(stdin.lock()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("tlscap: fatal: opening capture stream on stdin: {e}");
            std::process::exit(1);
        }
    };

    let stats_interval =
        (cli.stats_interval_seconds > 0).then(|| Duration::from_secs(cli.stats_interval_seconds));
    let mut last_stats = Instant::now();

    let mut packet_index = 0usize;
    let mut messages_written = 0u64;
    let mut packet_events_written = 0u64;
    // One scratch buffer, cleared and reused every write instead of a fresh `Vec::new()` per
    // message/packet-event -- at real production throughput this loop runs millions of times an
    // hour, and a fresh allocation + free on every single iteration is enough allocator churn to
    // show up as steadily climbing RSS over a long-running process's lifetime even though nothing
    // is actually unboundedly retained (see `--stats-interval-seconds`: `connections`/
    // `buffered_bytes`/`keylog_entries`/`lua_mb` can all stay flat while this happens).
    let mut write_buf = Vec::new();
    // `next_packet` returning `None` is clean EOF (upstream tcpdump's FIFO write-end closed) --
    // the loop just ends, no signal handling needed for a graceful shutdown.
    while let Some(result) = source.next_packet(packet_index) {
        let (raw, link_type) = match result {
            Ok(v) => v,
            Err(e) => {
                eprintln!(
                    "tlscap: WARNING error reading next packet, stopping capture stream: {e}"
                );
                break;
            }
        };
        packet_index += 1;

        let frame = match pcap_input::parse_tcp_frame(link_type, &raw.data) {
            Ok(f) => f,
            Err(_) => continue, // non-TCP/malformed frame -- nothing to decode, skip (not an error)
        };

        let (packet_event, messages) =
            orchestrator.process_frame(&frame, raw.index, &raw.data, raw.timestamp);

        if let Some(packet_output) = &mut packet_output {
            write_buf.clear();
            writer.write_packet_event(&mut write_buf, &packet_event)?;
            packet_output.write(&write_buf)?;
            packet_events_written += 1;
        }

        for msg in &messages {
            write_buf.clear();
            writer.write_tls_record(&mut write_buf, msg)?;
            output.write(&write_buf)?;
            messages_written += 1;
        }

        if let Some(interval) = stats_interval
            && last_stats.elapsed() >= interval
        {
            log_stats(
                &orchestrator,
                packet_index,
                messages_written,
                packet_events_written,
            );
            last_stats = Instant::now();
        }
    }

    output.finish()?;
    if let Some(packet_output) = &mut packet_output {
        packet_output.finish()?;
    }
    eprintln!(
        "tlscap: shutting down cleanly -- {} packets processed, {} messages written, {} packet events written, {} connections evicted, {} bytes lost to unrecoverable reassembly gaps, {} connections still active at exit",
        packet_index,
        messages_written,
        packet_events_written,
        orchestrator.evicted_connections,
        orchestrator.gap_abandoned_bytes,
        orchestrator.active_connections(),
    );
    eprintln!(
        "tlscap: TLS records: {} seen, {} decrypted, {} no-key, {} auth-failed, {} no-client-hello, {} plaintext-handshake",
        orchestrator.tls_records_seen,
        orchestrator.tls_records_decrypted,
        orchestrator.tls_records_nokey,
        orchestrator.tls_records_authfailed,
        orchestrator.tls_records_no_client_hello,
        orchestrator.tls_records_plaintext_handshake,
    );
    Ok(())
}

/// Logs one memory/connection-tracking snapshot -- see `--stats-interval-seconds`. `rss_mb` is
/// the number that actually matters for an OOM-kill; the rest help attribute *why* it's climbing:
/// `connections` growing without bound points at missing FIN/RST (idle-timeout is off by
/// default), `buffered_bytes` growing faster than `connections` points at a stalled reassembly
/// gap, and `keylog_entries` climbs on its own over a long-lived source JVM regardless of
/// connection activity (see `Orchestrator::keylog_entries`'s doc comment).
fn log_stats(
    orchestrator: &Orchestrator,
    packets_processed: usize,
    messages_written: u64,
    packet_events_written: u64,
) {
    let rss_mb = memstats::rss_bytes().map(|b| b / (1024 * 1024));
    eprintln!(
        "tlscap: stats rss_mb={} lua_mb={} connections={} buffered_bytes={} keylog_entries={} packets={} messages={} packet_events={} evicted={} gap_abandoned_bytes={}",
        rss_mb
            .map(|mb| mb.to_string())
            .unwrap_or_else(|| "unknown".to_string()),
        orchestrator.lua_used_memory() / (1024 * 1024),
        orchestrator.active_connections(),
        orchestrator.buffered_bytes(),
        orchestrator.keylog_entries(),
        packets_processed,
        messages_written,
        packet_events_written,
        orchestrator.evicted_connections,
        orchestrator.gap_abandoned_bytes,
    );
}
