# tlscap

A tshark-compatible, Lua-pluggable, TLS-decrypting live packet capture tool.

`tlscap` reads a pcap/pcapng stream (e.g. `tcpdump -w - | tlscap ...`), reassembles TCP streams
**losslessly**, decrypts TLS 1.2/1.3 application data via a growing SSLKEYLOGFILE-format keylog,
and dissects the decrypted payload using **unmodified Wireshark Lua dissector plugins** — the same
`.lua` file you'd drop into Wireshark's own plugins directory runs here, unchanged.

Output matches tshark's `-T ek` (Elasticsearch Bulk NDJSON) format with `-e <field>` selection, so
it's a drop-in replacement for `tshark -T ek -e ...` in a decode pipeline — or, with `-T ndjson`,
one type-aware, structure-aware JSON object per line, for direct ingestion by tools (e.g. AWS
Athena/Glue) that expect exactly that rather than an Elasticsearch bulk payload. Output rotation and
compression use `editcap`-compatible flags (`-c`/`-i`/`--compress gzip`) — no external
`split`/`gzip` stage needed; nothing uncompressed ever touches disk.

## Why this exists instead of just using tshark

`tlscap` was built to replace `tshark` in a **long-running, never-restarted** live-decode pipeline
(a compliance/security packet-capture sidecar that must run indefinitely). tshark/Wireshark's EPAN
dissection engine retains per-frame and per-conversation state for the *entire process lifetime* by
inherent design — not a bug, not a leak, just how it's built. For a short-lived `tshark -r file.pcap`
invocation that's irrelevant. For a process that's supposed to run for weeks without restarting, it
means memory grows for as long as the process lives. tshark's own mitigation for this (`-M <count>`,
periodic internal session reset) also wipes TLS decryption state, permanently breaking decrypt for
any connection whose handshake predates a reset — not usable for a "never lose data" requirement.

`tlscap` is a from-scratch, purpose-built orchestrator instead, with two correctness properties
tshark doesn't give you in this scenario:

- **Lossless TCP reassembly.** Out-of-order and retransmitted segments are buffered and correctly
  reordered, never silently dropped (see [`src/reassembly.rs`](src/reassembly.rs)). This matters in
  practice, not just in theory: Linux's cooked-capture "any" pseudo-interface (`tcpdump -i any`) can
  deliver packets to userspace out of per-flow wire order under load, independent of whether the
  underlying TCP stream itself experienced real network reordering.
- **FIN/RST-driven connection eviction.** Connection (decrypt + reassembly) state is retained until
  a connection is genuinely closed — RST from either side, or FIN from *both* directions (a
  half-closed connection that's still draining a final response is not evicted early). An optional
  idle-timeout eviction exists as a secondary safety net, but is **off by default and deliberately
  so**: it's easy for an idle timeout to silently discard a connection that's merely quiet, not dead,
  and that's a worse failure mode than using a bit more memory.

## How it works

```
tcpdump -w - | tlscap --keylog keys.log -e ip.src -e ip.dst -e myproto.field.kv -T ek \
  --compress gzip -i 600 --output /pcap/decode
```

```
                    ┌─────────────┐
 pcap/pcapng ──────▶│ pcap_input   │  auto-detects classic pcap vs. pcapng,
   (stdin)          │              │  parses Ethernet/Linux-SLL + IPv4/IPv6 + TCP
                    └──────┬───────┘
                           ▼
                    ┌─────────────┐
                    │ reassembly   │  per-(connection,direction) lossless TCP
                    │              │  reassembly -- buffers & reorders, never drops
                    └──────┬───────┘
                           ▼
                    ┌─────────────┐
                    │ connection   │  TLS 1.2/1.3 record-layer decrypt via a growing
                    │ /tls12/tls13 │  SSLKEYLOGFILE-format keylog (hot-reloaded)
                    │ /keylog*     │
                    └──────┬───────┘
                           ▼
                    ┌─────────────┐
                    │ lua/         │  embedded Lua VM + a Wireshark-Lua-API-compatible
                    │              │  shim (Proto/ProtoField/Tvb/TreeItem/DissectorTable/
                    │              │  pinfo/gui_enabled) -- runs real Wireshark plugins
                    └──────┬───────┘
                           ▼
                    ┌─────────────┐
                    │ ek_output    │  tshark -T ek compatible NDJSON
                    │ /rotation    │  editcap-style -c/-i rotation + gzip, in-process
                    └──────┬───────┘
                           ▼
                  rotated .gz chunks
```

The `orchestrator` module (`src/orchestrator.rs`) ties these together: per TCP frame, it updates
connection/eviction state, feeds the payload into the right direction's reassembler, pulls out
complete TLS records, attempts ClientHello/ServerHello correlation and decrypt, and — for decrypted
application data — hands the plaintext to whatever Lua plugin registered for that port, buffering
any leftover undissected tail bytes forward into the next record (a message spanning a TLS record
boundary is *not* lost, unlike under real Wireshark's own `tls.port`-dissector desegmentation
limitation).

## Building

```sh
cargo build --release
```

Requires a C toolchain (`mlua`'s `vendored` feature statically compiles Lua 5.4 from source — on
Debian/Ubuntu, `apt install build-essential`; on Alpine, `apk add build-base`).

Prebuilt static binaries (`x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl`) are
published on the [releases page](https://github.com/dnovitski/tlscap/releases) for each tagged
version, built natively on each architecture's own CI runner.

## Usage

```
tlscap -w <output-prefix> -e <field> [-e <field> ...] [--keylog <path>] [options]
```

| Flag | Default | Meaning |
|---|---|---|
| `--keylog <path>` | *(unset)* | Growing SSLKEYLOGFILE-format keylog (e.g. written by [jSSLKeyLog](https://github.com/dnovitski/jsslkeylog)). Hot-reloaded: a decrypt miss triggers an immediate out-of-cycle re-read. Omit it to run without decryption — `-w`'s decoded-message output stays empty, but `--packet-log` keeps working, since packet events never depend on decryption. |
| `--keylog-reload-interval <secs>` | `5` | Periodic keylog re-check interval. |
| `--plugin-dir <dir>` | `/usr/lib/tlscap/plugins` | Directory scanned (non-recursive) for `*.lua` Wireshark dissector plugins. Repeatable. |
| `--lua-script <path>` | | Load one specific plugin file (tshark's `-X lua_script:` equivalent). Repeatable. |
| `-e <field>` | | Select an output field by Wireshark filter name (`ip.src`, `tcp.srcport`, or any field a loaded plugin registers, e.g. `myproto.field.kv`). Repeatable; order is preserved. |
| `-T <format>` | `ek` | Output format: `ek` (tshark's `-T ek` NDJSON) or `ndjson` (one JSON object per line, type-aware, structure-aware — see [Output format](#output-format)). |
| `--ek-index-prefix <name>` | `packets` | `_index` prefix for the `-T ek` index-action line (`<prefix>-YYYY-MM-DD`). Not used by `-T ndjson`. |
| `-w, --output <prefix>` | *(required)* | Output file prefix, or `-` for stdout (uncompressed, unrotated). |
| `--packet-log <prefix>` | | A second, independent rotating output for this frame's own header-level event (SYN/FIN/RST/ACK, emitted for every frame regardless of whether it carries TLS data). Requires `-T ndjson`. Unset (default) disables packet-level output entirely. |
| `--ndjson-explode <field>` | | Split a top-level field's N occurrences into N separate output lines instead of one line with an N-element array. Requires `-T ndjson` — see [`-T ndjson`](#-t-ndjson). |
| `--ndjson-map <field>` | | Collapse a repeated `{name, value, ...}` subtree group into a JSON map. Repeatable. Requires `-T ndjson` — see [`-T ndjson`](#-t-ndjson). |
| `-c <count>` | | Rotate output after this many dissected messages. Mutually exclusive with `-i`. Governs both `-w` and `--packet-log`. |
| `-i <seconds>` | | Rotate output after this many seconds. Mutually exclusive with `-c`. Governs both `-w` and `--packet-log`. |
| `--compress <gzip>` | | Compress rotated output chunks. `gzip` is the only supported value (matching `editcap`). |
| `--compress-level <0-9>` | `6` | gzip compression level (0 = none, 9 = max, 6 = zlib's own default). Unlike `editcap` (no level control at all), this is tunable — worth lowering in a live-capture pipeline where CPU spent compressing competes with `tcpdump`'s own need to drain its kernel capture buffer promptly. |
| `--idle-timeout-seconds <secs>` | `0` (disabled) | Evict a connection after this many idle seconds, **regardless of FIN/RST**. Leave disabled in production — see [Why](#why-this-exists-instead-of-just-using-tshark). |
| `--max-pending-bytes <bytes>` | `4194304` | Per-(connection,direction) cap on out-of-order-buffered bytes before a gap is treated as abandoned (logged loudly, never silently). Protects against a single large permanent gap; see the next two flags for the limits that catch permanent gaps too small to ever trip this one. |
| `--max-pending-packets <count>` | `50` | Per-(connection,direction) cap on the number of out-of-order segments buffered before a gap is treated as abandoned. Catches busy connections whose permanent gap accumulates many small segments long before `--max-pending-bytes` would trip. |
| `--max-pending-age-seconds <secs>` | `30` | Per-(connection,direction) age limit on how long a gap may stay open before it's treated as abandoned. Catches low-traffic connections whose permanent gap never accumulates enough bytes or packets to trip either of the other two limits. |
| `--max-tail-bytes <bytes>` | `1048576` | Per-(connection,direction) cap on undissected tail bytes carried into the next record before they're truncated (logged loudly, never silently). Safety net for a registered dissector that doesn't consume much of what it's handed — a port with no dissector at all never accumulates a tail in the first place. |
| `--stats-interval-seconds <secs>` | `60` | Log a `tlscap: stats ...` line this often: process RSS, active connections, bytes buffered in reassembly, keylog entry count, and running packet/message counters — for diagnosing gradual memory growth. `0` disables it. |
| `--lua-gc-interval-seconds <secs>` | `5` | Force a full Lua GC cycle at most this often, as a low-cost safety net against Lua's own incremental collector falling behind under sustained high throughput. |

With rotation, chunk files are named `<prefix>_NNNNNN_YYYYMMDDHHMMSS.gz`, matching `editcap`'s own
naming convention.

### Example: live capture

```sh
tcpdump -p -i any -U -w - port 9410 \
  | tlscap --keylog /shared/keylog.log \
      -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e myproto.type_name -e myproto.field.kv \
      -T ek --compress gzip -i 600 \
      --output /pcap/decode
```

### Example: offline replay (testing / debugging)

```sh
cat capture.pcap | tlscap --keylog keys.log -e ip.src -e myproto.field.kv -w - > decoded.jsonl
```

## Writing / using plugins

`tlscap` embeds a Lua 5.4 VM (via [`mlua`](https://github.com/mlua-rs/mlua)) exposing a
Wireshark-Lua-API-compatible shim — scoped to exactly the surface a typical TLS-application-data
dissector actually uses, not a claim of full Wireshark Lua API coverage:

- `Proto(name, description)` — returns a plain Lua table; assign `.fields` and `.dissector` to it
  exactly as you would for real Wireshark.
- `ProtoField.uint8/uint16/uint32/uint64/string/bytes(name, display_name, [base])`
- `Tvb`/`TvbRange` — `tvb:len()`, `tvb(offset, [length])`, `:uint()`/`:le_uint()`/`:le_uint64()`/`:raw()`
- `TreeItem:add()`/`:add_le()`/`:set_generated()`/`:add_expert_info()` — records field values for
  output; builds no real display tree (there's no GUI here), so this is cheap regardless of how many
  fields a dissector adds.
- `DissectorTable.get("tls.port")` / `"ssl.port"`, `:add(port, proto)` — registers a dissector for
  decrypted TLS application data on a given TCP port. This is what makes plugin loading genuinely
  generic: any Lua file calling this the same way a real Wireshark Lua dissector does just works,
  with zero `tlscap`-side protocol-specific code anywhere.
- `pinfo.cols.protocol` / `pinfo.cols.info`
- `gui_enabled()` — always returns `false`, so a plugin's own `if gui_enabled() then ... end`
  GUI-only code paths (e.g. expensive per-field label subtrees) are skipped, same as under real
  tshark.
- `UInt64.new(value)`, `PI_MALFORMED`, `PI_ERROR`, `base.HEX`/`base.DEC`/`base.NONE`

A dissector function's own return value (bytes consumed) is honored the same way real Wireshark
uses it: `tlscap` carries forward whatever a dissector didn't consume into the next TLS record for
that (connection, direction), so a message split across a TLS record boundary isn't lost — something
real Wireshark's own `tls.port` dissector dispatch can't reliably do (see the doc comment on
`Connection::tail_c2s` in `src/orchestrator.rs`).

Drop a plugin file into `--plugin-dir` (or load it explicitly via `--lua-script`) and it's active —
no `tlscap`-side changes needed for a new protocol.

## Output format

Matches real tshark's `-T ek` NDJSON exactly (verified against a live `tshark 4.6.6` capture, not
assumed from documentation): two lines per decoded message —

```json
{"index":{"_index":"packets-2026-07-09"}}
{"timestamp":"1783670400123","layers":{"ip_src":["10.0.0.1"],"myproto_field_kv":["timestamp=123","echoField=abc"]}}
```

- Dots in field names become underscores (`ip.src` → `ip_src`).
- Every value is a JSON array of strings, even for a field that only occurs once.
- A field that didn't fire for a given message has its key **omitted entirely** — not an empty array.
- Repeated fields (e.g. one `myproto.field.kv` per protobuf field in a message) become a
  multi-element array in encounter order.

Every decrypted TLS record also always carries `tls.app_data` (matching tshark's own field name for
it): the record's raw decrypted bytes, hex-encoded, unconditionally — regardless of whether a Lua
dissector is even registered for the port, whether it errors, or whether it produces no fields at
all. TLS decrypt succeeding is independent from application-layer parsing succeeding; a plugin bug
or an unrecognized message type must never make the underlying decrypted data itself invisible.
Select it like any other field with `-e tls.app_data`.

### `-T ndjson`

A second output format, built for direct ingestion by tools that expect one JSON record per line
(e.g. AWS Athena/Glue's JSON SerDe) rather than an Elasticsearch bulk payload — `-T ek`'s two-line-
per-message, everything-stringified-and-array-wrapped convention isn't that. `-T ndjson` is free to
be genuinely ergonomic for its own purpose:

- **One JSON object per line**, no index-action line.
- **Type-aware**: a numeric field renders as a bare JSON number, not a quoted string.
- **Structure-aware**: a Lua dissector's nested subtrees (`tree:add(proto, ...)` — see
  [Writing / using plugins](#writing--using-plugins)) render as real nested JSON objects/arrays,
  not flattened.
- **Scalar vs. array** is decided by what `tlscap` can actually guarantee is single-valued: its own
  envelope fields (`ip`, `tcp`, `tls`) always are. Within a Lua dissector's own output, a nested
  subtree (`tree:add(someProto, ...)`) always stays an array regardless of count — that's the one
  thing a dissector can structurally repeat (looping over `tree:add(proto, ...)`) — while a plain
  leaf value (a `ProtoField` added directly, e.g. `tree:add(f_type_id, ...)`) renders as a bare
  scalar whenever it occurs exactly once, which is every time for a field a dissector's own linear,
  non-looping control flow only ever adds once.
- Every line carries `"kind":"packet"` or `"kind":"tls_record"` — see `--packet-log` above.
- `tstamp` is **microsecond**-resolution epoch (unlike `-T ek`'s `timestamp`, millis, kept there
  for tshark compatibility) — real capture interfaces typically report microsecond timestamps,
  and millis was coarse enough to collapse multiple distinct packets from the same reassembly
  burst onto one value. Named `tstamp` rather than `timestamp` so Athena/Presto SQL never needs
  `"timestamp"` quoting (a reserved word there).

`-e` selection works at group granularity, not individual leaf fields: `ip.src`/`ip.dst` both just
mean "include the `ip` object"; `tcp.srcport`/`tcp.dstport` mean "include `tcp`"; `tls.app_data`
means "include `tls`"; anything else (e.g. a plugin-registered top-level field like `myproto`)
selects that whole subtree, rendered in full nested structure. Example:

```json
{"kind":"tls_record","tstamp":1783670400123456,
 "ip":{"src":"10.0.0.1","dst":"10.0.0.2"},"tcp":{"srcport":51234,"dstport":9410},
 "tls":{"app_data":"deadbeef..."},
 "myproto":[{"type_name":"HEARTBEAT","sequence_id":123,
             "field":[{"name":"echoField","value":"abc"}]}]}
{"kind":"packet","tstamp":1783670400456789,
 "ip":{"src":"10.0.0.1","dst":"10.0.0.2"},
 "tcp":{"srcport":51234,"dstport":9410,"seq":1001,"ack":5001,"flags":["ack","psh"],"payload_len":128}}
```

The second line shows `--packet-log`'s own shape: one event per TCP frame `tlscap` processes,
emitted unconditionally — regardless of whether it carries any TLS data at all, let alone whether
that data decrypts or dissects successfully. This is the only way a RST, a FIN, or a pure ACK is
ever visible in the output: none of those carry TLS application data, so a `kind:"tls_record"` line
never exists for them. `flags` is always in a fixed canonical order (`syn`, `ack`, `fin`, `rst`,
`psh`) so an exact-match query (e.g. `flags = ARRAY['syn','ack']`) is reliable. Deliberately no raw
payload bytes on packet events — a main `tcpdump`/`editcap` capture pipeline running alongside
`tlscap` already has the full-fidelity byte-for-byte record for that; packet events are for
connection-lifecycle visibility/correlation, not a second copy of the whole capture.

#### `--ndjson-explode` / `--ndjson-map`: two opt-in, purely structural transforms

Neither requires any change to a Lua plugin — both work on the shape a dissector already produces.

**`--ndjson-explode <field>`** — when one TLS record legitimately contains N occurrences of a
top-level field (e.g. a protocol that multiplexes several application messages into one record),
that field normally renders as an N-element array. With `--ndjson-explode myproto`, `tlscap`
instead writes N separate `tls_record` lines: the envelope (`tstamp`/`ip`/`tcp`/`tls`) repeated on
each, `myproto` rendered singular every time. Zero occurrences still writes exactly one line,
without the field — the same "a field that didn't fire is omitted" convention as everywhere else,
so a record's raw `tls.app_data` never becomes invisible just because a dissector's own group
didn't fire.

**`--ndjson-map <field>`** — collapses a repeated `{name, value, ...}` subtree group (found at any
nesting depth) into a JSON map keyed by each occurrence's own `name` leaf, valued by its `value`
leaf. Any other sub-fields are dropped, and an occurrence missing `name` entirely (e.g. an
unrecognized sub-message type) is skipped rather than producing a null map key. Repeatable.

Combined example — `-e ip.src -e ip.dst -e myproto --ndjson-explode myproto --ndjson-map field`,
against a record carrying two multiplexed `myproto` messages:

```json
{"kind":"tls_record","tstamp":...,"ip":{...},
 "myproto":{"type_name":"HEARTBEAT","sequence_id":123,
            "field":{"echoField":"abc","timestamp":"1700000000000"}}}
{"kind":"tls_record","tstamp":...,"ip":{...},
 "myproto":{"type_name":"HEARTBEAT","sequence_id":124,
            "field":{"echoField":"def","timestamp":"1700000000456"}}}
```
Without either flag, this would instead be one line with `"myproto":[{...},{...}]`, each with its
own `"field":[{"name":"echoField","value":"abc"},...]` array — directly queryable in Athena either
way, but the exploded/mapped shape needs no `CROSS JOIN UNNEST` / `map_from_entries(TRANSFORM(...))`
at query time.

## Testing

```sh
cargo test          # unit + integration tests
cargo fmt --check
cargo clippy --all-targets -- -D warnings
```

Includes a cross-validation test (`tests/rustls_cross_validation.rs`) that drives a real TLS 1.3
handshake between two independent [`rustls`](https://github.com/rustls/rustls) connections in
memory, captures the exact wire ciphertext and secrets `rustls` produced, and confirms `tlscap`'s
own decrypt path recovers the original plaintext — proving the TLS 1.3 key derivation and AEAD
decrypt are correct against an implementation that had no part in writing them, not just
self-consistent against `tlscap`'s own test fixtures.

## Known limitations

- TLS 1.2 support is AES-GCM cipher suites only (no CBC, no ChaCha20-Poly1305 for 1.2) — matches
  what's actually seen in practice for the traffic this was built for; CBC in particular is legacy
  and actively deprecated (RFC 9325).
- A connection whose ClientHello was never captured (e.g. a capture that starts mid-connection, or a
  rotated capture file that begins after the handshake) can't be decrypted — `tlscap` learns a
  connection's identity (and hence which keylog secrets apply) from its ClientHello's `random`
  field; there's no fallback correlation mechanism.
- `-T ek` and `-T ndjson` are the only output formats implemented. No PDML/PSML (tshark's other
  `-T` targets).
- No `-Y`-style display filter language — `-e <field>` selects *output* fields only; which records
  get dissected at all is inherent to the pipeline (decrypted TLS application data on a port some
  loaded plugin registered for), not separately filterable. See the design note in
  [`src/ek_output.rs`](src/ek_output.rs) for the reasoning.
- Memory use isn't fully bounded over the process's whole lifetime -- watch
  `--stats-interval-seconds`'s output if you see gradual RSS growth. Two known, by-design sources:
  - **Connection tracking**: with `--idle-timeout-seconds` at its default (0, disabled), a
    connection with no FIN/RST is never evicted. A source that regularly abandons connections
    without a clean close (e.g. a NAT/firewall silently dropping idle sessions) accumulates
    entries forever.
  - **The keylog**: old secrets are never pruned (see [`src/keylog.rs`](src/keylog.rs)'s header
    comment) -- the in-memory index grows with the *keylog file's* own size, which itself only
    ever grows for as long as the source JVM keeps logging new handshakes.

  Two real, now-fixed bugs were found while chasing a production OOM:
  - **A port with no registered dissector used to accumulate an unbounded tail.**
    `dissect_and_emit`'s "no dissector for this port" path used to restore the *entire* buffer as
    the connection's tail every single record, unconditionally -- for a connection with no
    matching dissector, that meant accumulating every byte ever decrypted on it, for its whole
    lifetime (confirmed reaching >1GB RSS this way on a real capture where the loaded dissector
    didn't happen to match). Fixed: a port confirmed dissector-less (registration is 100% static,
    done once at startup) never gets a tail retained at all now. A *registered* dissector that
    doesn't consume much of what it's handed is still a real, if rarer, risk -- bounded now by
    `--max-tail-bytes` (truncated and reported via a counter, never silently).
  - **An unrecoverable reassembly gap used to leave a connection permanently, silently desynced.**
    Once bytes are lost to a `GapAbandoned` gap, every subsequent byte is offset from the stream's
    true TLS record boundaries. The record-length parser would keep trying anyway -- since a
    claimed length can be up to 65535 bytes, that meant buffering up to ~64KB per bogus "record"
    while decrypt permanently failed (`AuthFailed` spam) and no real message would ever come out
    for that direction again, all invisibly. Fixed: a direction is marked desynced on its first
    `GapAbandoned` event (logged loudly) and its reassembler stops accumulating anything for it at
    all from then on.

  Neither of these turned out to explain the original production OOM, though -- a real-capture
  replay with the actual Lua dissector loaded (the mistake that led to finding the tail-growth bug
  above in the first place: earlier local replays never loaded one, so *every* connection hit the
  no-dissector path) showed **flat RSS for a full hour of real traffic, on the actual musl/Alpine
  deployment target**, both before and after every fix in this section. Two allocation-churn fixes
  in `dissect_and_emit` and `ek_output.rs` (avoiding a full buffer clone and a redundant per-call
  scratch `Vec` respectively -- together cutting total bytes allocated by ~62% on a profiled
  replay) are real and kept, but that measurement predates loading a real dissector too, so treat
  it as "a legitimate reduction in allocator churn," not "the fix for the OOM." `mimalloc` (chosen
  over musl's own allocator, which is known to fragment and hold onto freed pages) and a periodic
  forced Lua GC cycle (`--lua-gc-interval-seconds`) are kept as low-cost safety nets for mechanisms
  that are real in principle, not because either has been shown to matter in practice.

  **The original OOM's root cause was found and fixed.** It wasn't allocator churn, Lua GC pacing,
  or either bug above -- it was `pending` (the out-of-order reassembly buffer) accumulating
  indefinitely. A gap in `pending` doesn't necessarily mean data was lost on the real wire: it can
  mean *this capture* missed a packet, e.g. to an AF_PACKET kernel ring-buffer overflow (see
  `--stats-interval-seconds` and the buffer-sizing flags on the capture side). The real sender
  already got ACK'd by the real receiver and will never retransmit, so that gap is permanent from
  `tlscap`'s point of view even though the underlying connection is completely healthy. Before this
  fix, only `--max-pending-bytes` guarded against it -- fine for a busy connection whose gap
  accumulates bytes fast, but a connection with a small, permanent gap could sit forever just under
  that cap without ever being evicted. A single kernel ring-buffer overflow drops packets
  indiscriminately across every connection sharing that capture socket, so one such event could
  produce many simultaneous small permanent gaps whose aggregate `pending` bytes summed into
  hundreds of MB of RSS growth, up to an actual OOM kill -- confirmed via direct correlation between
  `Orchestrator::buffered_bytes()` and observed RSS in production logs, right up to the kill event.
  Fixed with two more independent limits alongside `--max-pending-bytes`, whichever trips first:
  `--max-pending-packets` (catches busy connections' permanent gaps well before the byte cap would)
  and `--max-pending-age-seconds` (catches low-traffic connections' permanent gaps that never
  accumulate enough bytes or packets to trip either of the other two). See `PendingLimits` in
  [`src/reassembly.rs`](src/reassembly.rs) for the full design rationale.

  `--features dhat-heap` (see `Cargo.toml`'s `[profile.dhat]`) remains available as a permanent,
  zero-cost-when-disabled way to profile allocations locally if a different pattern ever emerges.

## License

MIT
