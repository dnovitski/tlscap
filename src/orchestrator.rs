//! The core loop: ingest a TCP frame -> reassemble -> decrypt -> dissect (via the Lua shim) ->
//! emit. Owns per-connection state and its eviction policy -- the single most important
//! correctness property this whole tool exists for: connection state must never grow without
//! bound (the reason tshark/EPAN had to be replaced), but must also never be evicted while the
//! connection is genuinely still alive (the reason idle-timeout eviction is off by default; see
//! below). FIN/RST is the primary, always-on eviction driver.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::rc::Rc;
use std::time::{Duration, Instant};

use crate::connection::{self, ConnectionState};
use crate::keylog_source::KeylogSource;
use crate::lua::{FrameFields, LuaEngine};
use crate::pcap_input::TcpFrame;
use crate::reassembly::{PushOutcome, StreamReassembler};
use crate::tls12;

type Endpoint = (IpAddr, u16);

/// Canonical, direction-independent connection identity: an unordered pair of endpoints, so a
/// client-to-server and server-to-client packet for the same TCP connection always hash to the
/// same key regardless of which one arrived first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct ConnKey(Endpoint, Endpoint);

fn conn_key(a: Endpoint, b: Endpoint) -> ConnKey {
    if a <= b { ConnKey(a, b) } else { ConnKey(b, a) }
}

#[derive(Default)]
struct ConnectionMeta {
    fin_seen_c2s: bool,
    fin_seen_s2c: bool,
    rst_seen: bool,
    last_activity: Option<Instant>,
}

impl ConnectionMeta {
    /// A connection is genuinely done once both directions have FIN'd (a real TCP full close --
    /// deliberately NOT evicted on just one direction's FIN, since a half-closed connection can
    /// legitimately keep receiving data the other way for a while, e.g. draining a final in-flight
    /// response) or either side sent RST (abrupt, authoritative regardless of prior FIN state).
    fn is_closed(&self) -> bool {
        self.rst_seen || (self.fin_seen_c2s && self.fin_seen_s2c)
    }
}

struct Connection {
    /// The endpoint identified as the connection's initiator (from a genuine SYN, or a best-effort
    /// fallback to "whichever endpoint sent the first-ever packet we saw for this key" if no SYN
    /// was observed -- e.g. capture started mid-connection). Needed to know which direction a
    /// given packet belongs to, and to label output messages' src/dst correctly.
    client_endpoint: Endpoint,
    server_endpoint: Endpoint,
    reassembler_c2s: StreamReassembler,
    reassembler_s2c: StreamReassembler,
    state: Option<ConnectionState>,
    /// Leftover plaintext left undissected at the end of the previous decrypted record for this
    /// (connection, direction), carried forward and prepended to the next record's plaintext --
    /// see `dissect_and_emit`. Hard-capped at `OrchestratorConfig::max_tail_bytes` (loudly, never
    /// silently -- see `Orchestrator::tail_bytes_discarded`): "at most one partial application
    /// message" is only true for a well-behaved dissector actually registered for this port: a
    /// port with NO registered dissector at all never gets a tail retained in the first place
    /// (see `dissect_and_emit`'s `Ok(None)` arm) precisely because that assumption doesn't hold
    /// there -- confirmed the hard way, this used to accumulate every byte ever decrypted on such
    /// a connection, for its entire lifetime.
    tail_c2s: Vec<u8>,
    tail_s2c: Vec<u8>,
    /// Set once this direction has lost bytes to an unrecoverable reassembly gap (see
    /// `PushOutcome::GapAbandoned`). Every byte from that point on is offset from the stream's
    /// true TLS record boundaries, permanently: there is no resync mechanism (and none is
    /// planned -- scanning forward for a plausible-looking record header has real false-positive
    /// risk for negligible benefit, since the lost bytes are gone either way). Once set,
    /// `process_frame` stops feeding this direction into its reassembler at all -- continuing
    /// would otherwise decrypt-attempt an endless stream of garbage "records" (permanent
    /// AuthFailed spam, wasted CPU) while never producing another real message for this
    /// direction's remaining lifetime.
    desynced_c2s: bool,
    desynced_s2c: bool,
    meta: ConnectionMeta,
}

impl Connection {
    fn new(client_endpoint: Endpoint, server_endpoint: Endpoint, max_pending_bytes: usize) -> Self {
        Connection {
            client_endpoint,
            server_endpoint,
            reassembler_c2s: StreamReassembler::with_max_pending_bytes(max_pending_bytes),
            reassembler_s2c: StreamReassembler::with_max_pending_bytes(max_pending_bytes),
            state: None,
            tail_c2s: Vec::new(),
            tail_s2c: Vec::new(),
            desynced_c2s: false,
            desynced_s2c: false,
            meta: ConnectionMeta::default(),
        }
    }

    fn reassembler_for(&mut self, is_client_to_server: bool) -> &mut StreamReassembler {
        if is_client_to_server {
            &mut self.reassembler_c2s
        } else {
            &mut self.reassembler_s2c
        }
    }

    fn is_desynced(&self, is_client_to_server: bool) -> bool {
        if is_client_to_server {
            self.desynced_c2s
        } else {
            self.desynced_s2c
        }
    }

    /// Marks this direction permanently desynced and drops whatever its reassembler was
    /// currently holding (garbage from this point on either way, no point keeping it around).
    fn mark_desynced(&mut self, is_client_to_server: bool, max_pending_bytes: usize) {
        if is_client_to_server {
            self.desynced_c2s = true;
            self.reassembler_c2s = StreamReassembler::with_max_pending_bytes(max_pending_bytes);
        } else {
            self.desynced_s2c = true;
            self.reassembler_s2c = StreamReassembler::with_max_pending_bytes(max_pending_bytes);
        }
    }

    fn take_tail(&mut self, is_client_to_server: bool) -> Vec<u8> {
        std::mem::take(if is_client_to_server {
            &mut self.tail_c2s
        } else {
            &mut self.tail_s2c
        })
    }

    fn set_tail(&mut self, is_client_to_server: bool, bytes: Vec<u8>) {
        *(if is_client_to_server {
            &mut self.tail_c2s
        } else {
            &mut self.tail_s2c
        }) = bytes;
    }

    /// `(source, destination)` for a message flowing in the given direction.
    fn endpoints(&self, is_client_to_server: bool) -> (Endpoint, Endpoint) {
        if is_client_to_server {
            (self.client_endpoint, self.server_endpoint)
        } else {
            (self.server_endpoint, self.client_endpoint)
        }
    }
}

/// One fully-dissected message, ready for `ek_output.rs` to serialize.
pub struct DecodedMessage {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    /// This TLS record's raw decrypted bytes. A real `DecodedMessage` struct field, not a
    /// `FrameFields` entry -- `tlscap`'s own `dissect_and_emit` produces exactly one of these per
    /// call, by construction, unlike anything a Lua dissector adds (whose occurrence count
    /// `tlscap` can never guarantee). Keeping it here, parallel to `src_ip`/`dst_ip`/`src_port`/
    /// `dst_port`, lets output writers treat it as the tlscap-guaranteed-scalar it actually is
    /// rather than inferring that from a field-name list.
    pub tls_app_data: Vec<u8>,
    pub fields: FrameFields,
    /// Capture timestamp of the packet that completed this record (i.e. delivered the final byte
    /// needed to finish reassembling it) -- matches real tshark's `-T ek` "timestamp" field, which
    /// is likewise a single frame's capture time, not a range.
    pub timestamp: Duration,
}

/// One TCP frame's own header-level event, emitted unconditionally for every frame `tlscap`
/// processes -- regardless of whether it carries any TLS data at all, let alone whether that data
/// decrypts or dissects successfully. This is the only way a RST, a FIN, or a pure ACK is ever
/// visible in the output: none of those carry TLS application data, so a `DecodedMessage` never
/// exists for them. Deliberately carries no payload bytes -- the main capture pipeline's own
/// already-uploaded `.pcapng.gz` is the full-fidelity record of every byte on the wire; this is for
/// connection-lifecycle visibility/correlation (SYN/FIN/RST timelines, retransmit/ACK patterns),
/// not a second copy of the whole capture.
pub struct PacketEvent {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    /// In a fixed canonical order (syn, ack, fin, rst, psh) -- not just "whichever were set, in
    /// whatever order" -- so an exact-match query (e.g. Athena's `flags = ARRAY['syn','ack']`)
    /// against the output is reliable rather than depending on iteration order.
    pub flags: Vec<&'static str>,
    pub payload_len: usize,
    pub timestamp: Duration,
}

/// Collects a `TcpFlags`' set flags in the fixed canonical order `PacketEvent::flags` promises.
fn canonical_flags(flags: &crate::pcap_input::TcpFlags) -> Vec<&'static str> {
    let mut out = Vec::with_capacity(5);
    if flags.syn {
        out.push("syn");
    }
    if flags.ack {
        out.push("ack");
    }
    if flags.fin {
        out.push("fin");
    }
    if flags.rst {
        out.push("rst");
    }
    if flags.psh {
        out.push("psh");
    }
    out
}

/// Generous relative to a single legitimate multi-record application message in this protocol (a
/// handful of KB at most) -- see `OrchestratorConfig::max_tail_bytes`'s doc comment.
pub const DEFAULT_MAX_TAIL_BYTES: usize = 1024 * 1024;

pub struct OrchestratorConfig {
    pub idle_timeout: Option<Duration>,
    /// Only consulted if `idle_timeout` is `Some` -- how often the idle sweep actually walks the
    /// connection map, so its cost scales with this interval rather than every single packet.
    pub sweep_interval: Duration,
    pub max_pending_bytes: usize,
    /// Hard cap on `Connection::tail_c2s`/`tail_s2c`'s size (see its doc comment) -- a safety net
    /// for a dissector that's registered but doesn't consume much of what it's handed (a bug, or
    /// a stream that never lets it make progress), NOT the primary defense: a port with no
    /// dissector at all never accumulates a tail in the first place (see `dissect_and_emit`'s
    /// `Ok(None)` arm). Exceeding this truncates the tail (keeping the most recently arrived
    /// bytes) and is always reported via `Orchestrator::tail_bytes_discarded`, mirroring
    /// `reassembly.rs`'s own `GapAbandoned` convention for the structurally identical risk.
    /// Default is generous relative to a single legitimate multi-record application message in
    /// this protocol (a handful of KB at most) without being a meaningful memory risk even at
    /// thousands of concurrent connections.
    pub max_tail_bytes: usize,
    /// How often to force a full Lua GC cycle, always on (unlike `sweep_interval`, not gated on
    /// any other setting). Every `dissect()` call creates GC-managed userdata (the Tvb/TvbRange
    /// handles wrapping that record's reassembled bytes) that Lua's own incremental collector
    /// only reclaims on its own pacing -- under sustained high throughput with little idle time
    /// for that pacing to catch up, uncollected userdata (and the multi-KB buffers they keep
    /// alive via `Rc`) can accumulate well beyond what `Orchestrator::lua_used_memory()` shows,
    /// since that stat only reflects Lua's own internal accounting, not externally-`Rc`'d bytes a
    /// userdata references. A short, bounded interval caps how much can pile up between
    /// collections regardless of instantaneous traffic rate. CAVEAT: an apparent RSS improvement
    /// from forcing this was originally measured against a replay that (by mistake) never loaded
    /// a real dissector, so every record hit `Ok(None)` and no Tvb userdata was ever created at
    /// all -- the "improvement" was very likely connections closing near the end of that replay,
    /// not this GC call. Re-tested with a real dissector loaded: no measurable difference. Kept
    /// as a still-reasonable, low-cost safety net for the mechanism it targets, not because it's
    /// been shown to matter in practice.
    pub lua_gc_interval: Duration,
}

impl Default for OrchestratorConfig {
    fn default() -> Self {
        OrchestratorConfig {
            idle_timeout: None,
            sweep_interval: Duration::from_secs(60),
            max_pending_bytes: crate::reassembly::DEFAULT_MAX_PENDING_BYTES,
            max_tail_bytes: DEFAULT_MAX_TAIL_BYTES,
            lua_gc_interval: Duration::from_secs(5),
        }
    }
}

pub struct Orchestrator {
    connections: HashMap<ConnKey, Connection>,
    keylog: KeylogSource,
    lua: LuaEngine,
    config: OrchestratorConfig,
    last_sweep: Instant,
    last_lua_gc: Instant,
    /// Ports we've already logged a "no dissector registered" notice for -- dissector
    /// registration is 100% static (done once at startup, before any packet is processed), so
    /// once a port is confirmed dissector-less it stays that way for the rest of the process's
    /// lifetime; this dedupes the notice to once per port instead of once per record.
    logged_no_dissector_ports: HashSet<u16>,
    /// Diagnostics, surfaced via public counters for startup/shutdown logging -- not load-bearing
    /// for correctness, just operator visibility into what's happening.
    pub evicted_connections: u64,
    pub gap_abandoned_bytes: u64,
    /// Bytes dropped from a `Connection` tail for exceeding `config.max_tail_bytes` -- see
    /// `OrchestratorConfig::max_tail_bytes`'s doc comment. Always incremented alongside a loud
    /// stderr warning, never silently.
    pub tail_bytes_discarded: u64,
    /// (connection, direction) pairs permanently desynced by an unrecoverable reassembly gap --
    /// see `Connection::desynced_c2s`'s doc comment. Always incremented alongside a loud stderr
    /// warning, never silently.
    pub connections_desynced: u64,
    /// Every TLS record pulled off the reassembled stream, regardless of outcome -- the
    /// denominator for the five counters below (they always sum to this total).
    pub tls_records_seen: u64,
    /// Successfully decrypted (any content type -- not just application_data; a Handshake/Alert
    /// record under TLS 1.2 still needs a successful decrypt to keep its sequence counter synced).
    pub tls_records_decrypted: u64,
    /// A key was available but every algorithm/generation combination failed to authenticate --
    /// a stale/rotated secret, or genuinely corrupt/out-of-sync data.
    pub tls_records_authfailed: u64,
    /// A key was genuinely missing in the keylog for a record that IS real ciphertext -- normal
    /// and often transient (e.g. before the keylog has caught up to a just-appended secret).
    /// Does NOT include any of the three always-plaintext handshake records every connection has
    /// (see `tls_records_plaintext_handshake`) -- decrypt is never even attempted against those,
    /// so counting them here would misleadingly inflate "not decrypted" with records that were
    /// never real ciphertext to begin with. Confirmed empirically against a 1.2M-record
    /// production capture: after excluding those three, this counter was exactly zero.
    pub tls_records_nokey: u64,
    /// No `ConnectionState` exists for this connection AT ALL -- its ClientHello was never
    /// captured (capture started mid-connection, or a rotated capture file's boundary landed
    /// after the handshake). Decrypt was never even attempted; genuinely, permanently
    /// undecryptable for this process's lifetime.
    pub tls_records_no_client_hello: u64,
    /// The three records every TLS connection sends that are genuinely, definitively plaintext by
    /// protocol spec, never ciphertext lacking a key: the ClientHello, the ServerHello, and a
    /// ChangeCipherSpec in each direction (content_type 0x14 is unconditionally plaintext, in
    /// both TLS 1.2 and 1.3, by spec -- not a heuristic). Decrypt is never even attempted against
    /// any of them (see `drain_records`); tracked separately so they don't pollute
    /// `tls_records_nokey` with something that was never a decrypt failure.
    pub tls_records_plaintext_handshake: u64,
}

impl Orchestrator {
    pub fn new(keylog: KeylogSource, lua: LuaEngine, config: OrchestratorConfig) -> Self {
        Orchestrator {
            connections: HashMap::new(),
            keylog,
            lua,
            config,
            last_sweep: Instant::now(),
            last_lua_gc: Instant::now(),
            logged_no_dissector_ports: HashSet::new(),
            evicted_connections: 0,
            gap_abandoned_bytes: 0,
            tail_bytes_discarded: 0,
            connections_desynced: 0,
            tls_records_seen: 0,
            tls_records_decrypted: 0,
            tls_records_nokey: 0,
            tls_records_authfailed: 0,
            tls_records_no_client_hello: 0,
            tls_records_plaintext_handshake: 0,
        }
    }

    pub fn active_connections(&self) -> usize {
        self.connections.len()
    }

    /// Total bytes currently held in memory across every open connection's reassemblers
    /// (contiguous + out-of-order pending, both directions) -- for memory-usage diagnostics. A
    /// connection with no FIN/RST (idle-timeout eviction is off by default, see
    /// `OrchestratorConfig`) keeps its share of this forever, so a steady climb here across many
    /// stats ticks -- more than `active_connections()` growth alone would explain -- points at
    /// stalled reassembly (a gap that's genuinely never closing) rather than just connection
    /// count.
    pub fn buffered_bytes(&self) -> usize {
        self.connections
            .values()
            .map(|c| {
                c.reassembler_c2s.contiguous_len()
                    + c.reassembler_c2s.pending_len()
                    + c.reassembler_s2c.contiguous_len()
                    + c.reassembler_s2c.pending_len()
            })
            .sum()
    }

    /// Number of entries in the current keylog (client_random -> secrets) -- for memory-usage
    /// diagnostics. This grows monotonically with the keylog file's own size: old secrets are
    /// never pruned (see `keylog.rs`'s header comment), so a long-lived source JVM logging every
    /// handshake for its whole lifetime means this -- and the memory behind it -- only ever goes
    /// up for as long as tlscap itself keeps running.
    pub fn keylog_entries(&self) -> usize {
        self.keylog.current().entry_count
    }

    /// Bytes currently tracked as live by the embedded Lua VM's own GC heap -- for memory-usage
    /// diagnostics. CAVEAT found the hard way (a real replay showed this stuck at 0 while RSS
    /// climbed past 1GB): this only reflects Lua's own internal accounting (strings, tables,
    /// userdata headers) -- it is blind to the size of a `Vec<u8>` a userdata references via `Rc`
    /// (e.g. a `Tvb`'s reassembled-record bytes, see `tvb.rs`), since that memory lives on the
    /// Rust/system heap, outside Lua's own arena. A `Tvb` awaiting GC still counts as ~0 bytes
    /// here even while it keeps a multi-KB buffer alive. Don't treat this staying flat as proof
    /// Lua GC pacing isn't a growth driver -- see `maybe_gc_lua`, which exists because it is one.
    pub fn lua_used_memory(&self) -> usize {
        self.lua.lua_used_memory()
    }

    /// Forces a full Lua GC cycle at most once per `config.lua_gc_interval`, always on (unlike
    /// `maybe_sweep_idle`, not gated on any other setting). See `OrchestratorConfig::
    /// lua_gc_interval`'s doc comment for why this exists: Lua's own incremental collector can
    /// fall behind `dissect()`'s userdata-creation rate under sustained high throughput, letting
    /// GC-managed buffers pile up well beyond what `lua_used_memory()` shows. Confirmed
    /// empirically on a real-capture replay to measurably lower peak RSS.
    fn maybe_gc_lua(&mut self) {
        if self.last_lua_gc.elapsed() < self.config.lua_gc_interval {
            return;
        }
        self.last_lua_gc = Instant::now();
        self.lua.gc_collect();
    }

    /// Processes one captured TCP frame, returning (1) this frame's own `PacketEvent` -- always
    /// produced, unconditionally, regardless of anything below -- and (2) every fully-dissected
    /// message it produced (zero or more -- a single frame can complete multiple reassembled
    /// records, and a single record can carry multiple protocol messages, per the Lua dissector's
    /// own internal loop).
    pub fn process_frame(
        &mut self,
        frame: &TcpFrame,
        packet_index: usize,
        packet_data: &[u8],
        timestamp: Duration,
    ) -> (PacketEvent, Vec<DecodedMessage>) {
        let packet_event = PacketEvent {
            src_ip: frame.src_ip,
            dst_ip: frame.dst_ip,
            src_port: frame.src_port,
            dst_port: frame.dst_port,
            seq: frame.seq,
            ack: frame.ack_number,
            flags: canonical_flags(&frame.flags),
            payload_len: frame.payload_range.len(),
            timestamp,
        };

        let src: Endpoint = (frame.src_ip, frame.src_port);
        let dst: Endpoint = (frame.dst_ip, frame.dst_port);
        let key = conn_key(src, dst);

        let is_new = !self.connections.contains_key(&key);
        let max_pending_bytes = self.config.max_pending_bytes;
        let conn = self
            .connections
            .entry(key)
            .or_insert_with(|| Connection::new(src, dst, max_pending_bytes));

        // A genuine SYN (not SYN-ACK) definitively identifies the initiator; only trust it to
        // (re-)anchor client/server on a fresh connection, never retroactively correct an
        // already-established one from a stray/duplicate SYN.
        if is_new && frame.flags.syn && !frame.flags.ack {
            conn.client_endpoint = src;
            conn.server_endpoint = dst;
        }
        let is_client_to_server = src == conn.client_endpoint;

        if frame.flags.syn {
            // First data byte's sequence number is SYN's seq + 1 (RFC 793) -- anchoring here means
            // a later out-of-order data segment is correctly recognized as out-of-order relative
            // to the connection's true start, not just relative to whichever segment happened to
            // arrive first (see reassembly.rs's `set_isn` doc comment for why this matters).
            conn.reassembler_for(is_client_to_server)
                .set_isn(frame.seq.wrapping_add(1));
        }
        if frame.flags.fin {
            if is_client_to_server {
                conn.meta.fin_seen_c2s = true
            } else {
                conn.meta.fin_seen_s2c = true
            }
        }
        if frame.flags.rst {
            conn.meta.rst_seen = true;
        }
        conn.meta.last_activity = Some(Instant::now());

        let payload = &packet_data[frame.payload_range.clone()];
        // A direction that's already permanently desynced (see `Connection::desynced_c2s`'s doc
        // comment) never gets fed into its reassembler again -- every byte from here on is offset
        // from the stream's true TLS record boundaries anyway, so buffering it toward a "record"
        // that will never validly complete is pure waste.
        if !payload.is_empty() && !conn.is_desynced(is_client_to_server) {
            let outcome = conn.reassembler_for(is_client_to_server).push(
                packet_index,
                frame.seq,
                frame.payload_range.clone(),
                payload,
            );
            if let PushOutcome::GapAbandoned { bytes } = outcome {
                self.gap_abandoned_bytes += bytes as u64;
                eprintln!(
                    "tlscap: WARNING connection {:?} direction={} lost {} bytes to an unrecoverable reassembly gap",
                    key,
                    if is_client_to_server { "c2s" } else { "s2c" },
                    bytes
                );
                conn.mark_desynced(is_client_to_server, max_pending_bytes);
                self.connections_desynced += 1;
                eprintln!(
                    "tlscap: WARNING connection {key:?} direction={} permanently desynced -- no further TLS records will be parsed for this direction (the other direction and this connection's packet-level events are unaffected)",
                    if is_client_to_server { "c2s" } else { "s2c" },
                );
            }
        }

        let mut out = Vec::new();
        self.drain_records(&key, is_client_to_server, timestamp, &mut out);

        let should_evict = self
            .connections
            .get(&key)
            .map(|c| c.meta.is_closed())
            .unwrap_or(false);
        if should_evict {
            self.connections.remove(&key);
            self.evicted_connections += 1;
        }

        self.maybe_sweep_idle();
        self.maybe_gc_lua();
        (packet_event, out)
    }

    /// Pulls every complete TLS record now sitting in the given direction's reassembler, attempts
    /// ClientHello/ServerHello correlation and decrypt, and dissects any resulting application
    /// data.
    fn drain_records(
        &mut self,
        key: &ConnKey,
        is_client_to_server: bool,
        timestamp: Duration,
        out: &mut Vec<DecodedMessage>,
    ) {
        while let Some(conn) = self.connections.get_mut(key) {
            let reassembler = conn.reassembler_for(is_client_to_server);
            if reassembler.contiguous_len() < 5 {
                break;
            }
            let header = reassembler.peek(5);
            let outer_content_type = header[0];
            let body_len = u16::from_be_bytes([header[3], header[4]]) as usize;
            let total_len = 5 + body_len;
            if reassembler.contiguous_len() < total_len {
                break;
            }
            let (record, _pieces) = reassembler.take_bytes(total_len);
            let body = &record[5..];
            self.tls_records_seen += 1;

            // ChangeCipherSpec (content_type 0x14): a TLS protocol invariant, not a heuristic --
            // by spec this record type is ALWAYS a single unencrypted byte (0x01), in both TLS 1.2
            // (a real, load-bearing signal) and TLS 1.3 (sent only for middlebox-compatibility,
            // otherwise ignored). It is never, in any TLS version, itself encrypted. Every
            // connection sends one in each direction, so this is not a rare case -- attempting
            // decrypt() against it always fails and always would.
            if outer_content_type == 0x14 {
                self.tls_records_plaintext_handshake += 1;
                continue;
            }

            if is_client_to_server
                && conn.state.is_none()
                && let Some(client_random) = connection::client_random_from_client_hello(body)
            {
                // This record IS the connection's ClientHello: genuinely, definitively plaintext
                // (a real TLS connection is never encrypted before the handshake even starts),
                // not "ciphertext we happen to lack a key for." Attempting decrypt() against it
                // would only ever fail, and counting that failure alongside real NoKey/AuthFailed
                // outcomes would misleadingly inflate "not decrypted" with something that was
                // never supposed to be decrypted in the first place -- gated by `state.is_none()`
                // so this can only ever fire once per connection, at the one point (its very
                // first record) where "definitely still plaintext" is unambiguous.
                conn.state = Some(ConnectionState::new(client_random.to_vec()));
                self.tls_records_plaintext_handshake += 1;
                continue;
            }
            if !is_client_to_server
                && let Some(server_random) = tls12::server_random_from_server_hello(body)
                && let Some(state) = &mut conn.state
                && state.set_server_random(server_random)
            {
                // `set_server_random` just returned `true`, meaning THIS call is the one that
                // newly learned it -- i.e. this is genuinely the connection's one ServerHello
                // record (server_random starts `None` and the ServerHello is always the first
                // s2c record by protocol design, arriving before any ciphertext could even
                // exist), not a later record whose plaintext coincidentally matched the same
                // byte pattern. Confirmed empirically: across a 1.2M-record production capture,
                // this fired exactly once per connection, matching the ClientHello count exactly
                // -- zero false positives. Like the ClientHello above, genuinely, definitively
                // plaintext: decrypt() would only ever fail against it.
                self.tls_records_plaintext_handshake += 1;
                continue;
            }

            let Some(state) = &mut conn.state else {
                // No ConnectionState exists for this connection at all -- its ClientHello was
                // never captured (e.g. capture started mid-connection, or a rotated capture file
                // boundary landed after the handshake). Nothing to attempt decrypt against; this
                // is a real, honestly-counted "could never be decrypted" case, distinct from a
                // NoKey/AuthFailed result on a connection we DO have state for.
                self.tls_records_no_client_hello += 1;
                continue;
            };

            self.keylog.poll();
            let decrypt_result = state.decrypt(
                self.keylog.current(),
                is_client_to_server,
                outer_content_type,
                body,
            );
            match decrypt_result {
                Ok(decrypted) => {
                    self.tls_records_decrypted += 1;
                    // 0x17 = application_data. Handshake/Alert records still had to be decrypted
                    // (to keep TLS 1.2's shared per-direction sequence counter in sync -- see
                    // connection.rs's decrypt() doc comment) but aren't dissected further.
                    if decrypted.content_type == 0x17 {
                        self.dissect_and_emit(
                            key,
                            is_client_to_server,
                            decrypted.plaintext,
                            timestamp,
                            out,
                        );
                    }
                }
                Err(connection::ProcessError::NoKey) => {
                    self.tls_records_nokey += 1;
                    self.keylog.poll_after_miss();
                }
                Err(connection::ProcessError::AuthFailed) => {
                    self.tls_records_authfailed += 1;
                    eprintln!(
                        "tlscap: WARNING connection {key:?} record failed to authenticate (stale/rotated key, or genuinely corrupt data) -- record discarded"
                    );
                }
            }
        }
    }

    /// Prepends any carried-over tail from the previous record, dissects via the Lua engine
    /// registered for this connection's destination port, and stores back whatever the dissector
    /// didn't consume -- see `Connection::tail_c2s`/`tail_s2c`'s doc comment for why this recovers
    /// more than a real Wireshark Lua dissector's own per-record-only behavior does under real
    /// Wireshark (which cannot reliably desegment across TLS records for a `tls.port`-registered
    /// dissector; `tlscap`'s own orchestrator has no such limitation since it owns the whole
    /// per-connection byte stream).
    ///
    /// Always emits exactly one message per decrypted TLS record, carrying `tls.app_data` (this
    /// record's raw decrypted bytes, tshark's own field name for it) -- regardless of whether a
    /// dissector is even registered for this port, and regardless of whether it errors or
    /// produces no fields. TLS decrypt already succeeded by the time this is called (see
    /// `drain_records`); a plugin failing to parse its payload is a separate concern that must
    /// never make the underlying decrypted data itself invisible in the output.
    fn dissect_and_emit(
        &mut self,
        key: &ConnKey,
        is_client_to_server: bool,
        plaintext: Vec<u8>,
        timestamp: Duration,
        out: &mut Vec<DecodedMessage>,
    ) {
        let Some(conn) = self.connections.get_mut(key) else {
            return;
        };

        let mut buf = conn.take_tail(is_client_to_server);
        buf.extend_from_slice(&plaintext);

        // dissect() only needs a cheap `Rc` handle -- the Lua-side Tvb already wraps its bytes in
        // an `Rc<Vec<u8>>` (see tvb.rs) -- so keeping our own clone of that handle lets the
        // undissected tail be sliced back out afterward without paying for an independent
        // full-buffer copy on every single decrypted record. This used to be the single largest
        // source of allocator churn in the whole process at real production throughput (~50% of
        // all bytes allocated in a local dhat-profiled replay of a real capture).
        let (src, dst) = conn.endpoints(is_client_to_server);
        // The dissector-table port lookup is always the SERVER's well-known port (e.g. 9410),
        // regardless of message direction -- NOT simply "this record's dst port", which is only
        // correct for client->server records. A server->client response's dst is the CLIENT's
        // ephemeral port, which no plugin ever registers a dissector for; using it here silently
        // dropped every single response message (found empirically: a real production capture's
        // *_RESPONSE messages were 100% missing from output while *_REQUEST messages decoded
        // almost perfectly -- exactly the signature of this direction-blind bug).
        let port = conn.server_endpoint.1;
        let buf = Rc::new(buf);
        let tls_app_data = plaintext;

        let mut fields = FrameFields::default();

        match self.lua.dissect(port, buf.clone()) {
            Ok(Some((mut dissected, consumed))) => {
                let leftover = buf[consumed.min(buf.len())..].to_vec();
                self.set_tail_capped(key, is_client_to_server, leftover);
                fields.entries.append(&mut dissected.entries);
                fields.protocol = dissected.protocol;
                fields.info = dissected.info;
                fields.malformed = dissected.malformed;
            }
            Ok(None) => {
                // No plugin registered for this port. Dissector registration is 100% static (done
                // once at startup, before any packet is processed) -- so unlike a genuine gap or a
                // transient dissector error, this can NEVER resolve itself later in this process's
                // lifetime. Retaining `buf` as a tail here used to mean accumulating every byte
                // ever decrypted on such a connection, for its entire lifetime (confirmed via a
                // real production capture reaching >1GB RSS on connections with no matching
                // dissector) -- deliberately NOT restoring it: there is no future code path that
                // will ever consume it. Logged once per port, not per record.
                if self.logged_no_dissector_ports.insert(port) {
                    eprintln!(
                        "tlscap: no dissector registered for port {port} -- application data on this port will not be buffered or dissected for the rest of this process's lifetime"
                    );
                }
            }
            Err(e) => {
                eprintln!("tlscap: WARNING Lua dissector error on port {port}: {e}");
                // Unlike `Ok(None)`, a dissector IS registered here -- a transient parse error on
                // this one record doesn't mean future records on this connection won't dissect
                // fine, so (capped) retention is still worthwhile. `try_unwrap` often fails here
                // (a Tvb's GC-managed userdata may still hold a live handle -- same reasoning as
                // `dissect()`'s own `fields` Rc, see lua/mod.rs's doc comment); the `unwrap_or_else`
                // clone fallback covers that.
                let restored = Rc::try_unwrap(buf).unwrap_or_else(|rc| (*rc).clone());
                self.set_tail_capped(key, is_client_to_server, restored);
            }
        }

        out.push(DecodedMessage {
            src_ip: src.0,
            dst_ip: dst.0,
            src_port: src.1,
            dst_port: dst.1,
            tls_app_data,
            fields,
            timestamp,
        });
    }

    /// Sets a connection's tail, first truncating to `config.max_tail_bytes` (keeping the most
    /// recently arrived bytes, dropping the oldest) if it's over the cap -- see
    /// `OrchestratorConfig::max_tail_bytes`'s doc comment. Always reported, never silent, mirroring
    /// `reassembly.rs`'s `GapAbandoned` convention for the structurally identical risk.
    fn set_tail_capped(&mut self, key: &ConnKey, is_client_to_server: bool, mut bytes: Vec<u8>) {
        if bytes.len() > self.config.max_tail_bytes {
            let discard = bytes.len() - self.config.max_tail_bytes;
            bytes.drain(..discard);
            self.tail_bytes_discarded += discard as u64;
            eprintln!(
                "tlscap: WARNING connection {key:?} direction={} tail exceeded max_tail_bytes ({}) -- discarded {discard} oldest byte(s)",
                if is_client_to_server { "c2s" } else { "s2c" },
                self.config.max_tail_bytes,
            );
        }
        if let Some(conn) = self.connections.get_mut(key) {
            conn.set_tail(is_client_to_server, bytes);
        }
    }

    fn maybe_sweep_idle(&mut self) {
        let Some(idle_timeout) = self.config.idle_timeout else {
            return;
        };
        if self.last_sweep.elapsed() < self.config.sweep_interval {
            return;
        }
        self.last_sweep = Instant::now();
        let now = Instant::now();
        let before = self.connections.len();
        self.connections
            .retain(|_, conn| match conn.meta.last_activity {
                Some(t) => now.duration_since(t) < idle_timeout,
                None => true,
            });
        let evicted = before - self.connections.len();
        if evicted > 0 {
            self.evicted_connections += evicted as u64;
            eprintln!(
                "tlscap: idle-timeout swept {evicted} connection(s) (configured, off by default -- see --idle-timeout-seconds)"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keylog::Keylog;
    use crate::pcap_input::TcpFlags;
    use crate::tls13::{AeadAlgorithm, RecordKeys, record_aad};
    use std::net::Ipv4Addr;

    const CLIENT: (IpAddr, u16) = (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 51234);
    const SERVER: (IpAddr, u16) = (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 9410);

    const FIXTURE_DISSECTOR: &str = r#"
        local proto = Proto("fixture", "Fixture")
        local f = ProtoField.string("fixture.msg", "Msg")
        proto.fields = { f }
        function proto.dissector(tvb, pinfo, tree)
            tree:add(f, tvb(0):raw())
            pinfo.cols.protocol = "FIXTURE"
            return tvb:len()
        end
        DissectorTable.get("tls.port"):add(9410, proto)
    "#;

    fn client_hello_record(client_random: [u8; 32]) -> Vec<u8> {
        let mut body = vec![0x01, 0x00, 0x00, 0x00]; // msg_type=ClientHello
        body.extend_from_slice(&[0x03, 0x03]); // legacy_version
        body.extend_from_slice(&client_random);
        body.extend_from_slice(&[0xAA; 8]); // rest of the ClientHello, irrelevant to parsing
        let mut record = vec![0x16, 0x03, 0x03];
        record.extend_from_slice(&(body.len() as u16).to_be_bytes());
        record.extend_from_slice(&body);
        record
    }

    fn server_hello_record(server_random: [u8; 32]) -> Vec<u8> {
        let mut body = vec![0x02, 0x00, 0x00, 0x00]; // msg_type=ServerHello
        body.extend_from_slice(&[0x03, 0x03]); // legacy_version
        body.extend_from_slice(&server_random);
        body.extend_from_slice(&[0xBB; 8]); // rest of the ServerHello, irrelevant to parsing
        let mut record = vec![0x16, 0x03, 0x03];
        record.extend_from_slice(&(body.len() as u16).to_be_bytes());
        record.extend_from_slice(&body);
        record
    }

    fn change_cipher_spec_record() -> Vec<u8> {
        vec![0x14, 0x03, 0x03, 0x00, 0x01, 0x01]
    }

    fn app_data_record(keys: &RecordKeys, seq: u64, content: &[u8]) -> Vec<u8> {
        let ciphertext =
            keys.encrypt_record(seq, &record_aad(content.len() + 17), content, 0x17, 0);
        let mut record = vec![0x17, 0x03, 0x03];
        record.extend_from_slice(&(ciphertext.len() as u16).to_be_bytes());
        record.extend_from_slice(&ciphertext);
        record
    }

    fn tcp_frame(
        src: (IpAddr, u16),
        dst: (IpAddr, u16),
        seq: u32,
        flags: TcpFlags,
        payload_range: std::ops::Range<usize>,
    ) -> TcpFrame {
        TcpFrame {
            src_ip: src.0,
            dst_ip: dst.0,
            src_port: src.1,
            dst_port: dst.1,
            seq,
            ack_number: 0,
            flags,
            payload_range,
        }
    }

    fn new_test_orchestrator(keylog: Keylog) -> Orchestrator {
        let lua = LuaEngine::new().unwrap();
        lua.load_plugin_str(FIXTURE_DISSECTOR, "fixture.lua")
            .unwrap();
        Orchestrator::new(
            KeylogSource::from_parsed(keylog),
            lua,
            OrchestratorConfig::default(),
        )
    }

    #[test]
    fn full_handshake_through_decrypt_and_dissect() {
        let client_random = [0x42u8; 32];
        let secret = [0x99u8; 32];
        let keylog = Keylog::parse(&format!(
            "CLIENT_TRAFFIC_SECRET_0 {} {}\r\n",
            hex::encode(client_random),
            hex::encode(secret)
        ));
        let keys = RecordKeys::derive(&secret, AeadAlgorithm::Aes128Gcm).unwrap();

        let mut orch = new_test_orchestrator(keylog);

        // SYN from client.
        let syn_seq = 1000u32;
        let syn = tcp_frame(
            CLIENT,
            SERVER,
            syn_seq,
            TcpFlags {
                syn: true,
                ..Default::default()
            },
            0..0,
        );
        assert!(
            orch.process_frame(&syn, 0, &[], Duration::ZERO)
                .1
                .is_empty()
        );

        // ClientHello (unencrypted), first data byte at syn_seq+1.
        let hello = client_hello_record(client_random);
        let hello_seq = syn_seq.wrapping_add(1);
        let frame = tcp_frame(
            CLIENT,
            SERVER,
            hello_seq,
            TcpFlags::default(),
            0..hello.len(),
        );
        assert!(
            orch.process_frame(&frame, 1, &hello, Duration::ZERO)
                .1
                .is_empty()
        );
        assert_eq!(orch.active_connections(), 1);

        // Encrypted application-data record, client -> server (matching the CLIENT_TRAFFIC_SECRET_0
        // key derived above -- a server -> client record would need SERVER_TRAFFIC_SECRET_0
        // instead), split across two TCP segments arriving OUT OF ORDER, to prove the reassembler
        // is actually wired in end-to-end (not just unit-tested in isolation) -- this record must
        // be recovered byte-for-byte regardless of arrival order.
        let record = app_data_record(&keys, 0, b"HEARTBEAT_RESPONSE-ish body");
        let split = record.len() / 2;
        let data_seq = hello_seq.wrapping_add(hello.len() as u32); // continues the client's own stream after the ClientHello

        // Second half arrives first.
        let second_half = record[split..].to_vec();
        let frame2 = tcp_frame(
            CLIENT,
            SERVER,
            data_seq.wrapping_add(split as u32),
            TcpFlags::default(),
            0..second_half.len(),
        );
        assert!(
            orch.process_frame(&frame2, 2, &second_half, Duration::ZERO)
                .1
                .is_empty(),
            "out-of-order second half must not produce output yet"
        );

        // First half arrives second, closing the gap.
        let first_half = record[..split].to_vec();
        let frame1 = tcp_frame(
            CLIENT,
            SERVER,
            data_seq,
            TcpFlags::default(),
            0..first_half.len(),
        );
        let (_, messages) = orch.process_frame(&frame1, 3, &first_half, Duration::ZERO);

        assert_eq!(
            messages.len(),
            1,
            "reordered halves must reassemble into exactly one dissected message"
        );
        assert_eq!(
            messages[0].fields.values_for("fixture.msg")[0].to_output_string(),
            "HEARTBEAT_RESPONSE-ish body"
        );
        assert_eq!(
            messages[0].tls_app_data, b"HEARTBEAT_RESPONSE-ish body",
            "the raw decrypted record must always be surfaced too, regardless of dissection"
        );
        assert_eq!(messages[0].fields.protocol.as_deref(), Some("FIXTURE"));
        assert_eq!(messages[0].src_ip, CLIENT.0);
        assert_eq!(messages[0].dst_ip, SERVER.0);
    }

    #[test]
    fn raw_decrypted_data_is_emitted_even_with_no_dissector_registered() {
        // The fixture plugin only registers a dissector for port 9410 (see FIXTURE_DISSECTOR
        // above) -- a connection on a different port has no application-layer parser at all, but
        // the record still decrypted successfully, so its raw bytes must still show up in the
        // output (this is the whole point of tls.app_data: it doesn't depend on a real Wireshark Lua dissector, or any
        // dissector, succeeding).
        let client_random = [0x77u8; 32];
        let secret = [0x88u8; 32];
        let keylog = Keylog::parse(&format!(
            "CLIENT_TRAFFIC_SECRET_0 {} {}\r\n",
            hex::encode(client_random),
            hex::encode(secret)
        ));
        let keys = RecordKeys::derive(&secret, AeadAlgorithm::Aes128Gcm).unwrap();
        let mut orch = new_test_orchestrator(keylog);

        const UNREGISTERED_SERVER: (IpAddr, u16) = (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)), 12345);

        let syn_seq = 5000u32;
        let syn = tcp_frame(
            CLIENT,
            UNREGISTERED_SERVER,
            syn_seq,
            TcpFlags {
                syn: true,
                ..Default::default()
            },
            0..0,
        );
        orch.process_frame(&syn, 0, &[], Duration::ZERO);

        let hello = client_hello_record(client_random);
        let hello_seq = syn_seq.wrapping_add(1);
        let hello_frame = tcp_frame(
            CLIENT,
            UNREGISTERED_SERVER,
            hello_seq,
            TcpFlags::default(),
            0..hello.len(),
        );
        orch.process_frame(&hello_frame, 1, &hello, Duration::ZERO);

        let record = app_data_record(&keys, 0, b"no dissector for this port, but still decrypted");
        let data_seq = hello_seq.wrapping_add(hello.len() as u32);
        let frame = tcp_frame(
            CLIENT,
            UNREGISTERED_SERVER,
            data_seq,
            TcpFlags::default(),
            0..record.len(),
        );
        let (_, messages) = orch.process_frame(&frame, 2, &record, Duration::ZERO);

        assert_eq!(
            messages.len(),
            1,
            "a decrypted record with no registered dissector must still be emitted"
        );
        assert_eq!(
            messages[0].tls_app_data,
            b"no dissector for this port, but still decrypted"
        );
        assert!(
            messages[0].fields.values_for("fixture.msg").is_empty(),
            "no dissector ran, so there must be no application-layer fields at all"
        );
        assert_eq!(messages[0].fields.protocol, None);
    }

    /// Regression test for the real bug found via a local dhat/musl investigation: a port with no
    /// registered dissector used to have its ENTIRE buffer restored as the tail on every single
    /// record, unboundedly accumulating every byte ever decrypted on that connection for its
    /// whole lifetime (confirmed via a real production capture reaching >1GB RSS this way).
    /// Sends two records specifically -- one record alone wouldn't distinguish "tail correctly
    /// stays empty" from "tail grew by one record's worth but happens to look fine after only a
    /// single call."
    #[test]
    fn no_dissector_for_port_never_accumulates_a_tail() {
        let client_random = [0x11u8; 32];
        let secret = [0x22u8; 32];
        let keylog = Keylog::parse(&format!(
            "CLIENT_TRAFFIC_SECRET_0 {} {}\r\n",
            hex::encode(client_random),
            hex::encode(secret)
        ));
        let keys = RecordKeys::derive(&secret, AeadAlgorithm::Aes128Gcm).unwrap();
        let mut orch = new_test_orchestrator(keylog);

        const UNREGISTERED_SERVER: (IpAddr, u16) = (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)), 12345);

        let syn_seq = 7000u32;
        let syn = tcp_frame(
            CLIENT,
            UNREGISTERED_SERVER,
            syn_seq,
            TcpFlags {
                syn: true,
                ..Default::default()
            },
            0..0,
        );
        orch.process_frame(&syn, 0, &[], Duration::ZERO);

        let hello = client_hello_record(client_random);
        let hello_seq = syn_seq.wrapping_add(1);
        let hello_frame = tcp_frame(
            CLIENT,
            UNREGISTERED_SERVER,
            hello_seq,
            TcpFlags::default(),
            0..hello.len(),
        );
        orch.process_frame(&hello_frame, 1, &hello, Duration::ZERO);

        let mut seq = hello_seq.wrapping_add(hello.len() as u32);
        for i in 0..2u64 {
            let record = app_data_record(&keys, i, format!("record #{i}").as_bytes());
            let frame = tcp_frame(
                CLIENT,
                UNREGISTERED_SERVER,
                seq,
                TcpFlags::default(),
                0..record.len(),
            );
            let (_, messages) = orch.process_frame(&frame, 2 + i as usize, &record, Duration::ZERO);
            assert_eq!(messages.len(), 1, "record #{i} must still decrypt and emit");
            seq = seq.wrapping_add(record.len() as u32);
        }

        let key = conn_key(CLIENT, UNREGISTERED_SERVER);
        let conn = orch
            .connections
            .get(&key)
            .expect("connection must still exist");
        assert_eq!(
            conn.tail_c2s.len(),
            0,
            "a port with no dissector must never accumulate a tail, no matter how many records arrive"
        );
        assert_eq!(orch.tail_bytes_discarded, 0);
    }

    /// A dissector that IS registered but never consumes anything (e.g. buggy, or a stream that
    /// never lets it make progress) must still be bounded by `max_tail_bytes` -- unlike the
    /// no-dissector-at-all case, this tail is legitimately worth keeping (a future record might
    /// complete the parse), so it's capped rather than dropped entirely.
    #[test]
    fn oversized_tail_gets_truncated_and_reported() {
        let client_random = [0x33u8; 32];
        let secret = [0x44u8; 32];
        let keylog = Keylog::parse(&format!(
            "CLIENT_TRAFFIC_SECRET_0 {} {}\r\n",
            hex::encode(client_random),
            hex::encode(secret)
        ));
        let keys = RecordKeys::derive(&secret, AeadAlgorithm::Aes128Gcm).unwrap();

        const NEVER_CONSUMES: &str = r#"
            local proto = Proto("neverconsumes", "NeverConsumes")
            function proto.dissector(tvb, pinfo, tree)
                return 0
            end
            DissectorTable.get("tls.port"):add(9410, proto)
        "#;
        let lua = LuaEngine::new().unwrap();
        lua.load_plugin_str(NEVER_CONSUMES, "never_consumes.lua")
            .unwrap();
        let mut orch = Orchestrator::new(
            KeylogSource::from_parsed(keylog),
            lua,
            OrchestratorConfig {
                max_tail_bytes: 50,
                ..OrchestratorConfig::default()
            },
        );

        let syn_seq = 8000u32;
        let syn = tcp_frame(
            CLIENT,
            SERVER,
            syn_seq,
            TcpFlags {
                syn: true,
                ..Default::default()
            },
            0..0,
        );
        orch.process_frame(&syn, 0, &[], Duration::ZERO);

        let hello = client_hello_record(client_random);
        let hello_seq = syn_seq.wrapping_add(1);
        let hello_frame = tcp_frame(
            CLIENT,
            SERVER,
            hello_seq,
            TcpFlags::default(),
            0..hello.len(),
        );
        orch.process_frame(&hello_frame, 1, &hello, Duration::ZERO);

        // Each record is well under the 50-byte cap on its own, but the dissector never consumes
        // anything, so the tail keeps growing record over record until it blows through the cap.
        let mut seq = hello_seq.wrapping_add(hello.len() as u32);
        for i in 0..5u64 {
            let record = app_data_record(&keys, i, b"0123456789012345"); // 16 bytes
            let frame = tcp_frame(CLIENT, SERVER, seq, TcpFlags::default(), 0..record.len());
            orch.process_frame(&frame, 2 + i as usize, &record, Duration::ZERO);
            seq = seq.wrapping_add(record.len() as u32);
        }

        assert!(
            orch.tail_bytes_discarded > 0,
            "exceeding max_tail_bytes must be reported via the counter, never silent"
        );
        let key = conn_key(CLIENT, SERVER);
        let conn = orch
            .connections
            .get(&key)
            .expect("connection must still exist");
        assert!(
            conn.tail_c2s.len() <= 50,
            "tail must never be allowed to grow past max_tail_bytes, got {}",
            conn.tail_c2s.len()
        );
    }

    /// After an unrecoverable reassembly gap, every subsequent byte on that direction is offset
    /// from the stream's true TLS record boundaries -- reported here in real production logs as
    /// repeated `GapAbandoned` warnings for the same connection. Without this fix the orchestrator
    /// would keep trying to parse "records" out of that misaligned stream forever (permanent
    /// AuthFailed spam, wasted CPU, and -- since a claimed record length can be up to 65535 bytes
    /// -- up to ~64KB buffered per bogus "record" while waiting for one that will never validly
    /// complete). This confirms the fix: once desynced, no further messages are ever emitted for
    /// that direction, and the reassembler stops accumulating anything for it at all.
    #[test]
    fn gap_abandoned_permanently_desyncs_a_direction() {
        let client_random = [0x55u8; 32];
        let secret = [0x66u8; 32];
        let keylog = Keylog::parse(&format!(
            "CLIENT_TRAFFIC_SECRET_0 {} {}\r\n",
            hex::encode(client_random),
            hex::encode(secret)
        ));
        let keys = RecordKeys::derive(&secret, AeadAlgorithm::Aes128Gcm).unwrap();

        let lua = LuaEngine::new().unwrap();
        lua.load_plugin_str(FIXTURE_DISSECTOR, "fixture.lua")
            .unwrap();
        let mut orch = Orchestrator::new(
            KeylogSource::from_parsed(keylog),
            lua,
            OrchestratorConfig {
                max_pending_bytes: 20,
                ..OrchestratorConfig::default()
            },
        );

        let syn_seq = 9000u32;
        let syn = tcp_frame(
            CLIENT,
            SERVER,
            syn_seq,
            TcpFlags {
                syn: true,
                ..Default::default()
            },
            0..0,
        );
        orch.process_frame(&syn, 0, &[], Duration::ZERO);

        let hello = client_hello_record(client_random);
        let hello_seq = syn_seq.wrapping_add(1);
        let hello_frame = tcp_frame(
            CLIENT,
            SERVER,
            hello_seq,
            TcpFlags::default(),
            0..hello.len(),
        );
        orch.process_frame(&hello_frame, 1, &hello, Duration::ZERO);
        let after_hello_seq = hello_seq.wrapping_add(hello.len() as u32);

        // Two out-of-order segments, both leaving a gap before them, together exceeding
        // max_pending_bytes (20) -- triggers GapAbandoned on the second push.
        let far_seq = after_hello_seq.wrapping_add(1000);
        let frame_a = tcp_frame(CLIENT, SERVER, far_seq, TcpFlags::default(), 0..15);
        orch.process_frame(&frame_a, 2, &[0xAA; 15], Duration::ZERO);
        let frame_b = tcp_frame(
            CLIENT,
            SERVER,
            far_seq.wrapping_add(100),
            TcpFlags::default(),
            0..15,
        );
        orch.process_frame(&frame_b, 3, &[0xBB; 15], Duration::ZERO);

        assert!(
            orch.gap_abandoned_bytes > 0,
            "the second out-of-order push must exceed max_pending_bytes and trigger GapAbandoned"
        );
        assert_eq!(orch.connections_desynced, 1);

        // A perfectly well-formed record, sent at whatever sequence number the connection is
        // still tracking -- must NOT produce a message: the direction is permanently desynced.
        let record = app_data_record(&keys, 0, b"this must never come out");
        let frame = tcp_frame(
            CLIENT,
            SERVER,
            after_hello_seq,
            TcpFlags::default(),
            0..record.len(),
        );
        let (_, messages) = orch.process_frame(&frame, 4, &record, Duration::ZERO);
        assert!(
            messages.is_empty(),
            "no message must ever be emitted for a permanently desynced direction"
        );

        let key = conn_key(CLIENT, SERVER);
        let conn = orch
            .connections
            .get(&key)
            .expect("connection must still exist");
        assert!(conn.is_desynced(true));
        assert_eq!(
            conn.reassembler_c2s.contiguous_len(),
            0,
            "a desynced direction's reassembler must not accumulate anything at all, not even a \
             well-formed record"
        );
        assert_eq!(conn.reassembler_c2s.pending_len(), 0);
    }

    /// Regression test for a real bug caught while verifying against real production pcaps:
    /// `dissect_and_emit` looked up the Lua dissector by `dst.1` (this record's destination
    /// port), which is only correct for client->server records -- for a server->client response,
    /// `dst` is the CLIENT's ephemeral port, which no plugin ever registers a dissector for. The
    /// bug silently dropped 100% of response messages (a real production capture showed
    /// *_RESPONSE message counts of exactly zero while *_REQUEST messages decoded almost
    /// perfectly) with no error or warning anywhere, since "no plugin for this port" is treated
    /// as a normal, silent no-op. Neither `full_handshake_through_decrypt_and_dissect` above nor
    /// any other existing test exercised the server->client direction for dissection, so this
    /// gap went undetected until real traffic caught it -- the fix (look up the dissector by the
    /// connection's SERVER port, `conn.server_endpoint`, regardless of message direction) is
    /// covered here specifically to prevent it recurring silently again.
    #[test]
    fn dissects_server_to_client_responses_too() {
        let client_random = [0x43u8; 32];
        let secret = [0x88u8; 32];
        let keylog = Keylog::parse(&format!(
            "SERVER_TRAFFIC_SECRET_0 {} {}\r\n",
            hex::encode(client_random),
            hex::encode(secret)
        ));
        let keys = RecordKeys::derive(&secret, AeadAlgorithm::Aes128Gcm).unwrap();

        let mut orch = new_test_orchestrator(keylog);

        let syn_seq = 2000u32;
        let syn = tcp_frame(
            CLIENT,
            SERVER,
            syn_seq,
            TcpFlags {
                syn: true,
                ..Default::default()
            },
            0..0,
        );
        orch.process_frame(&syn, 0, &[], Duration::ZERO);

        let hello = client_hello_record(client_random);
        let hello_seq = syn_seq.wrapping_add(1);
        let frame = tcp_frame(
            CLIENT,
            SERVER,
            hello_seq,
            TcpFlags::default(),
            0..hello.len(),
        );
        orch.process_frame(&frame, 1, &hello, Duration::ZERO);

        // Server -> client encrypted response, using SERVER_TRAFFIC_SECRET_0 (matching the
        // direction) -- this is the case the bug dropped entirely.
        let server_syn_seq = 9000u32;
        let server_syn = tcp_frame(
            SERVER,
            CLIENT,
            server_syn_seq,
            TcpFlags {
                syn: true,
                ack: true,
                ..Default::default()
            },
            0..0,
        );
        orch.process_frame(&server_syn, 2, &[], Duration::ZERO);

        let record = app_data_record(&keys, 0, b"HEARTBEAT_RESPONSE-ish body from the server");
        let data_seq = server_syn_seq.wrapping_add(1);
        let frame = tcp_frame(
            SERVER,
            CLIENT,
            data_seq,
            TcpFlags::default(),
            0..record.len(),
        );
        let (_, messages) = orch.process_frame(&frame, 3, &record, Duration::ZERO);

        assert_eq!(
            messages.len(),
            1,
            "server->client response must be dissected, not silently dropped"
        );
        assert_eq!(
            messages[0].fields.values_for("fixture.msg")[0].to_output_string(),
            "HEARTBEAT_RESPONSE-ish body from the server"
        );
        assert_eq!(
            messages[0].src_ip, SERVER.0,
            "message must be correctly labeled as server -> client"
        );
        assert_eq!(messages[0].dst_ip, CLIENT.0);
    }

    #[test]
    fn fin_both_directions_evicts_connection() {
        let keylog = Keylog::parse("");
        let mut orch = new_test_orchestrator(keylog);

        let syn = tcp_frame(
            CLIENT,
            SERVER,
            1,
            TcpFlags {
                syn: true,
                ..Default::default()
            },
            0..0,
        );
        orch.process_frame(&syn, 0, &[], Duration::ZERO);
        assert_eq!(orch.active_connections(), 1);

        let fin_c2s = tcp_frame(
            CLIENT,
            SERVER,
            2,
            TcpFlags {
                fin: true,
                ..Default::default()
            },
            0..0,
        );
        orch.process_frame(&fin_c2s, 1, &[], Duration::ZERO);
        assert_eq!(
            orch.active_connections(),
            1,
            "half-closed (one direction FIN'd) must NOT be evicted yet"
        );

        let fin_s2c = tcp_frame(
            SERVER,
            CLIENT,
            1,
            TcpFlags {
                fin: true,
                ..Default::default()
            },
            0..0,
        );
        orch.process_frame(&fin_s2c, 2, &[], Duration::ZERO);
        assert_eq!(
            orch.active_connections(),
            0,
            "both directions FIN'd must evict"
        );
        assert_eq!(orch.evicted_connections, 1);
    }

    #[test]
    fn rst_evicts_immediately_regardless_of_fin_state() {
        let keylog = Keylog::parse("");
        let mut orch = new_test_orchestrator(keylog);

        let syn = tcp_frame(
            CLIENT,
            SERVER,
            1,
            TcpFlags {
                syn: true,
                ..Default::default()
            },
            0..0,
        );
        orch.process_frame(&syn, 0, &[], Duration::ZERO);
        assert_eq!(orch.active_connections(), 1);

        let rst = tcp_frame(
            CLIENT,
            SERVER,
            2,
            TcpFlags {
                rst: true,
                ..Default::default()
            },
            0..0,
        );
        orch.process_frame(&rst, 1, &[], Duration::ZERO);
        assert_eq!(
            orch.active_connections(),
            0,
            "RST from either side must evict immediately, no FIN needed"
        );
    }

    /// A `PacketEvent` is produced for every frame, unconditionally -- including a bare RST that
    /// carries no TLS data at all and would otherwise be completely invisible in the output (no
    /// `DecodedMessage` is ever produced for it, since it has no application data to decrypt).
    /// This is the whole point of `PacketEvent`: connection-lifecycle visibility that doesn't
    /// depend on decrypt/dissect succeeding, or even being attempted.
    #[test]
    fn packet_event_is_always_emitted_with_canonical_flag_order() {
        let keylog = Keylog::parse("");
        let mut orch = new_test_orchestrator(keylog);

        let syn = tcp_frame(
            CLIENT,
            SERVER,
            1000,
            TcpFlags {
                syn: true,
                ack: true,
                psh: true,
                ..Default::default()
            },
            0..0,
        );
        let (event, messages) = orch.process_frame(&syn, 0, &[], Duration::from_millis(42));
        assert!(
            messages.is_empty(),
            "no TLS data on a bare flags-only frame"
        );
        assert_eq!(event.src_ip, CLIENT.0);
        assert_eq!(event.dst_ip, SERVER.0);
        assert_eq!(event.src_port, CLIENT.1);
        assert_eq!(event.dst_port, SERVER.1);
        assert_eq!(event.seq, 1000);
        assert_eq!(event.timestamp, Duration::from_millis(42));
        assert_eq!(
            event.flags,
            vec!["syn", "ack", "psh"],
            "flags must appear in the fixed canonical order (syn, ack, fin, rst, psh), not \
             whatever order they happened to be checked in"
        );

        let rst = tcp_frame(
            CLIENT,
            SERVER,
            1001,
            TcpFlags {
                rst: true,
                ..Default::default()
            },
            0..0,
        );
        let (event, messages) = orch.process_frame(&rst, 1, &[], Duration::ZERO);
        assert!(messages.is_empty());
        assert_eq!(
            event.flags,
            vec!["rst"],
            "a RST must be visible as its own packet event even though it carries no TLS data"
        );
    }

    #[test]
    fn idle_timeout_off_by_default_never_evicts() {
        let keylog = Keylog::parse("");
        let mut orch = new_test_orchestrator(keylog);
        assert!(
            orch.config.idle_timeout.is_none(),
            "default config must have idle-timeout disabled"
        );

        let syn = tcp_frame(
            CLIENT,
            SERVER,
            1,
            TcpFlags {
                syn: true,
                ..Default::default()
            },
            0..0,
        );
        orch.process_frame(&syn, 0, &[], Duration::ZERO);
        assert_eq!(orch.active_connections(), 1);
        // No sweep should ever run without an explicit idle_timeout, regardless of elapsed time.
        orch.maybe_sweep_idle();
        assert_eq!(orch.active_connections(), 1);
    }

    #[test]
    fn tls_record_counters_track_seen_decrypted_and_no_client_hello() {
        let client_random = [0x44u8; 32];
        let secret = [0x77u8; 32];
        let keylog = Keylog::parse(&format!(
            "CLIENT_TRAFFIC_SECRET_0 {} {}\r\n",
            hex::encode(client_random),
            hex::encode(secret)
        ));
        let keys = RecordKeys::derive(&secret, AeadAlgorithm::Aes128Gcm).unwrap();
        let mut orch = new_test_orchestrator(keylog);

        // A record for a DIFFERENT connection (distinct client port, so a distinct ConnKey) whose
        // ClientHello was never captured -- no ConnectionState exists at all, so this must count
        // as no_client_hello, not nokey.
        let orphan_client: (IpAddr, u16) = (CLIENT.0, 61000);
        let orphan_record = app_data_record(&keys, 0, b"never decryptable, no client_hello seen");
        let orphan_frame = tcp_frame(
            orphan_client,
            SERVER,
            5000,
            TcpFlags::default(),
            0..orphan_record.len(),
        );
        orch.process_frame(&orphan_frame, 0, &orphan_record, Duration::ZERO);
        assert_eq!(orch.tls_records_seen, 1);
        assert_eq!(orch.tls_records_no_client_hello, 1);
        assert_eq!(orch.tls_records_decrypted, 0);

        // A proper connection: SYN, ClientHello (counts as "seen" but decrypt is never even
        // attempted against it -- it's the connection's own, definitively-plaintext ClientHello,
        // not ciphertext lacking a key -- so it lands in plaintext_handshake, not nokey), then a
        // real encrypted record that successfully decrypts.
        let syn = tcp_frame(
            CLIENT,
            SERVER,
            1000,
            TcpFlags {
                syn: true,
                ..Default::default()
            },
            0..0,
        );
        orch.process_frame(&syn, 1, &[], Duration::ZERO);
        let hello = client_hello_record(client_random);
        let hello_frame = tcp_frame(CLIENT, SERVER, 1001, TcpFlags::default(), 0..hello.len());
        orch.process_frame(&hello_frame, 2, &hello, Duration::ZERO);
        assert_eq!(
            orch.tls_records_seen, 2,
            "ClientHello record itself counts as seen"
        );
        assert_eq!(
            orch.tls_records_plaintext_handshake, 1,
            "the ClientHello is definitively plaintext, never decrypt-attempted, never a nokey"
        );
        assert_eq!(orch.tls_records_nokey, 0);

        let data_seq = 1001u32.wrapping_add(hello.len() as u32);
        let record = app_data_record(&keys, 0, b"a real encrypted message");
        let data_frame = tcp_frame(
            CLIENT,
            SERVER,
            data_seq,
            TcpFlags::default(),
            0..record.len(),
        );
        orch.process_frame(&data_frame, 3, &record, Duration::ZERO);

        assert_eq!(orch.tls_records_seen, 3);
        assert_eq!(orch.tls_records_decrypted, 1);
        assert_eq!(orch.tls_records_nokey, 0);
        assert_eq!(orch.tls_records_authfailed, 0);
        assert_eq!(orch.tls_records_no_client_hello, 1);
        assert_eq!(orch.tls_records_plaintext_handshake, 1);
        // Every record must be accounted for in exactly one bucket -- no record silently missing.
        assert_eq!(
            orch.tls_records_seen,
            orch.tls_records_decrypted
                + orch.tls_records_nokey
                + orch.tls_records_authfailed
                + orch.tls_records_no_client_hello
                + orch.tls_records_plaintext_handshake
        );
    }

    #[test]
    fn server_hello_and_change_cipher_spec_are_never_decrypt_attempted() {
        // Reproduces the exact record sequence a real TLS 1.3 handshake with middlebox-compat
        // ChangeCipherSpec produces (confirmed against a real 1.2M-record production capture,
        // where these three record types accounted for 100% of what used to be miscounted as
        // "no-key"): ClientHello, ServerHello, server's CCS, client's CCS, then real app data.
        let client_random = [0x11u8; 32];
        let server_random = [0x22u8; 32];
        let secret = [0x55u8; 32];
        let keylog = Keylog::parse(&format!(
            "CLIENT_TRAFFIC_SECRET_0 {} {}\r\n",
            hex::encode(client_random),
            hex::encode(secret)
        ));
        let keys = RecordKeys::derive(&secret, AeadAlgorithm::Aes128Gcm).unwrap();
        let mut orch = new_test_orchestrator(keylog);

        let syn = tcp_frame(
            CLIENT,
            SERVER,
            2000,
            TcpFlags {
                syn: true,
                ..Default::default()
            },
            0..0,
        );
        orch.process_frame(&syn, 0, &[], Duration::ZERO);

        let hello = client_hello_record(client_random);
        let hello_frame = tcp_frame(CLIENT, SERVER, 2001, TcpFlags::default(), 0..hello.len());
        orch.process_frame(&hello_frame, 1, &hello, Duration::ZERO);

        let server_hello = server_hello_record(server_random);
        let server_hello_frame = tcp_frame(
            SERVER,
            CLIENT,
            3000,
            TcpFlags::default(),
            0..server_hello.len(),
        );
        orch.process_frame(&server_hello_frame, 2, &server_hello, Duration::ZERO);

        let server_ccs = change_cipher_spec_record();
        let server_ccs_frame = tcp_frame(
            SERVER,
            CLIENT,
            3000 + server_hello.len() as u32,
            TcpFlags::default(),
            0..server_ccs.len(),
        );
        orch.process_frame(&server_ccs_frame, 3, &server_ccs, Duration::ZERO);

        let client_ccs = change_cipher_spec_record();
        let client_ccs_frame = tcp_frame(
            CLIENT,
            SERVER,
            2001 + hello.len() as u32,
            TcpFlags::default(),
            0..client_ccs.len(),
        );
        orch.process_frame(&client_ccs_frame, 4, &client_ccs, Duration::ZERO);

        assert_eq!(orch.tls_records_seen, 4);
        assert_eq!(
            orch.tls_records_plaintext_handshake, 4,
            "ClientHello + ServerHello + both CCS records -- all definitively plaintext"
        );
        assert_eq!(
            orch.tls_records_nokey, 0,
            "none of these four should ever reach decrypt(), let alone fail it"
        );

        let data_seq = 2001u32
            .wrapping_add(hello.len() as u32)
            .wrapping_add(client_ccs.len() as u32);
        let record = app_data_record(&keys, 0, b"real encrypted app data after the handshake");
        let data_frame = tcp_frame(
            CLIENT,
            SERVER,
            data_seq,
            TcpFlags::default(),
            0..record.len(),
        );
        orch.process_frame(&data_frame, 5, &record, Duration::ZERO);

        assert_eq!(orch.tls_records_seen, 5);
        assert_eq!(orch.tls_records_decrypted, 1);
        assert_eq!(orch.tls_records_nokey, 0);
        assert_eq!(orch.tls_records_plaintext_handshake, 4);
    }

    #[test]
    fn keylog_entries_reflects_the_current_keylog() {
        let keylog = Keylog::parse("CLIENT_RANDOM aabb ccdd\r\nCLIENT_RANDOM eeff 0011\r\n");
        let orch = new_test_orchestrator(keylog);
        assert_eq!(orch.keylog_entries(), 2);
    }

    #[test]
    fn buffered_bytes_sums_stalled_reassembly_across_connections() {
        let mut orch = new_test_orchestrator(Keylog::parse(""));
        assert_eq!(orch.buffered_bytes(), 0);

        // A payload too short to even be a TLS record header (5 bytes) sits in `contiguous`
        // forever, un-drained -- exactly the kind of stalled-reassembly bytes buffered_bytes()
        // exists to surface. No SYN needed: a connection is created on first sight either way
        // (mid-connection-start support), matching production behavior.
        let partial = [0xAAu8, 0xBB, 0xCC];
        let frame = tcp_frame(CLIENT, SERVER, 1000, TcpFlags::default(), 0..partial.len());
        orch.process_frame(&frame, 0, &partial, Duration::ZERO);
        assert_eq!(orch.buffered_bytes(), 3);

        // A second, distinct connection's own stalled bytes add on top, not replace.
        let other_client = (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)), 51235);
        let frame2 = tcp_frame(
            other_client,
            SERVER,
            2000,
            TcpFlags::default(),
            0..partial.len(),
        );
        orch.process_frame(&frame2, 1, &partial, Duration::ZERO);
        assert_eq!(orch.buffered_bytes(), 6);
    }
}
