//! Serializes `DecodedMessage`s in tshark's `-T ek` format, for drop-in compatibility with a
//! decode pipeline built around `tshark -T ek -e <field> ...`.
//!
//! Format verified against real `tshark 4.6.6` output (not assumed/guessed from documentation --
//! `tshark -r <capture> -T ek -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e tcp.flags`),
//! confirming:
//! - Two NDJSON lines per message: an Elasticsearch Bulk API "index" action line, then a data
//!   line. tshark 4.6.6 emits `{"index":{"_index":"packets-YYYY-MM-DD"}}` -- no `_type` key at
//!   all (older tshark/documentation examples show `_type`, matching Elasticsearch's own removal
//!   of mapping types in ES 7+; not reproduced here since the version actually tested omits it).
//! - Data line: `{"timestamp":"<epoch-millis-as-string>","layers":{...}}`.
//! - Requested `-e` fields become flat top-level keys under `layers`, with `.` replaced by `_`
//!   (`ip.src` -> `ip_src`).
//! - Every value is a JSON array of strings, even for a field that only ever occurs once.
//! - A field that didn't fire for this message has its key **omitted entirely** from `layers` --
//!   confirmed empirically (a TCP ACK-only packet with no MSS option produces no
//!   `tcp_options_mss_val` key at all, not an empty array).

use std::collections::HashSet;
use std::io::{self, Write};

use crate::lua::{FieldValue, FrameFields};
use crate::orchestrator::{DecodedMessage, PacketEvent};

/// Forwards every write to `inner` while counting the bytes that pass through -- lets
/// `write_message`/`write_one_tls_record`/`write_packet_event` format field-by-field directly
/// into the caller's own (already-reused) buffer instead of building an independent scratch `Vec`
/// per call and copying it out at the end, while still reporting how many bytes were written. That
/// per-call scratch `Vec` used to be the second-largest source of allocator churn in the whole
/// process at real production throughput, right behind `orchestrator.rs::dissect_and_emit`'s own
/// (since-fixed) full-buffer clone -- both found via a local dhat-profiled replay of a real
/// capture, not guessed.
struct CountingWriter<'a, W: Write> {
    inner: &'a mut W,
    count: usize,
}

impl<W: Write> Write for CountingWriter<'_, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.count += n;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

pub struct EkWriter {
    fields: Vec<String>,
    index_prefix: String,
}

impl EkWriter {
    /// `fields` are the `-e`-style field names to select, e.g. `["ip.src", "example.field.kv"]` --
    /// order is preserved in the output, matching tshark's own behavior.
    pub fn new(fields: Vec<String>, index_prefix: String) -> Self {
        EkWriter {
            fields,
            index_prefix,
        }
    }

    /// Writes one message's two-line NDJSON entry. Returns the number of bytes written, so
    /// `rotation.rs` can track output-chunk size without a second pass.
    pub fn write_message<W: Write>(&self, w: &mut W, msg: &DecodedMessage) -> io::Result<usize> {
        let mut w = CountingWriter { inner: w, count: 0 };

        writeln!(
            w,
            "{{\"index\":{{\"_index\":\"{}-{}\"}}}}",
            self.index_prefix,
            index_date(msg.timestamp)
        )?;

        write!(
            w,
            "{{\"timestamp\":\"{}\",\"layers\":{{",
            epoch_millis(msg.timestamp)
        )?;
        let mut first = true;
        for field in &self.fields {
            let Some(values) = self.values_for(field, msg) else {
                continue;
            };
            if values.is_empty() {
                continue;
            }
            if !first {
                w.write_all(b",")?;
            }
            first = false;
            write_json_string(&mut w, &field.replace('.', "_"))?;
            w.write_all(b":[")?;
            for (i, v) in values.iter().enumerate() {
                if i > 0 {
                    w.write_all(b",")?;
                }
                write_json_string(&mut w, v)?;
            }
            w.write_all(b"]")?;
        }
        writeln!(w, "}}}}")?;

        Ok(w.count)
    }

    /// Resolves one `-e` field name against a message's built-in envelope fields (`ip.src`,
    /// `ip.dst`, `tcp.srcport`, `tcp.dstport`) or its Lua-dissector-recorded fields. Returns
    /// `None` for a field name that isn't recognized at all (vs. `Some(vec![])` for a recognized
    /// field that simply didn't fire on this message) -- both cases end up omitting the key, but
    /// kept distinct for a future `--strict-fields` mode that could warn on the former.
    fn values_for(&self, field: &str, msg: &DecodedMessage) -> Option<Vec<String>> {
        match field {
            "ip.src" => Some(vec![msg.src_ip.to_string()]),
            "ip.dst" => Some(vec![msg.dst_ip.to_string()]),
            "tcp.srcport" => Some(vec![msg.src_port.to_string()]),
            "tcp.dstport" => Some(vec![msg.dst_port.to_string()]),
            "tls.app_data" => Some(vec![hex::encode(&msg.tls_app_data)]),
            _ => Some(
                msg.fields
                    .values_for(field)
                    .into_iter()
                    .map(|v| v.to_output_string())
                    .collect(),
            ),
        }
    }
}

/// Serializes `DecodedMessage`s and `PacketEvent`s as plain NDJSON -- one JSON object per line, no
/// Elasticsearch bulk index-action line -- for direct ingestion by tools that expect exactly that
/// (e.g. Athena/Glue's JSON SerDe), which `-T ek`'s two-line-per-message, everything-stringified
/// convention isn't. Unlike `EkWriter` (which stays byte-for-byte tshark-compatible, untouched by
/// anything below), this format is free to be genuinely ergonomic for its own purpose:
/// - Type-aware: a `FieldValue::UInt` renders as a bare JSON number, not a quoted string.
/// - Structure-aware: a Lua dissector's nested subtrees (`FieldValue::Tree`) render as real nested
///   JSON objects/arrays, not flattened.
/// - Scalar vs. array is decided by what `tlscap` can actually guarantee is single-valued: its own
///   envelope fields (`ip`/`tcp`/`tls`, produced by `tlscap`'s own Rust code) always are. Within a
///   Lua dissector's own output, a nested subtree (`FieldValue::Tree`, from `tree:add(someProto,
///   ...)`) always stays an array regardless of count -- that's the one thing a dissector can
///   structurally repeat (looping over `tree:add(proto, ...)`) -- while a plain leaf value (a
///   `ProtoField` added directly, e.g. `tree:add(f_type_id, ...)`) renders as a bare scalar
///   whenever it occurs exactly once, which is every time for a field a dissector's own linear,
///   non-looping control flow only ever adds once. See `write_value_or_array`.
/// - Every line carries `"kind":"packet"` or `"kind":"tls_record"` -- technically redundant with
///   the Hive `kind=` partition a line ends up under (see the Glue table schema), but kept so a
///   line is self-describing outside of Athena too (e.g. `zcat file.gz | jq`, piped to another
///   tool) without needing to know which file it came from.
/// - `tstamp` is microsecond-resolution epoch (unlike `-T ek`'s `timestamp`, millis) -- real
///   capture interfaces typically report microsecond timestamps (see
///   `pcap_input.rs::correct_epb_timestamp`), and millis was coarse enough to collapse multiple
///   distinct packets from the same burst onto one value. Named `tstamp`, not `timestamp`, so
///   Athena/Presto SQL never needs `"timestamp"` quoting (a reserved word there).
///
/// `-e <field>` selection works at group granularity, not individual leaf fields: `ip.src`/
/// `ip.dst` both just mean "include the `ip` object"; `tcp.srcport`/`tcp.dstport` mean "include
/// `tcp`"; `tls.app_data` means "include `tls`"; anything else (e.g. `myproto`) selects that whole
/// top-level Lua-produced subtree, rendered in full -- there's no leaf-level narrowing within a
/// subtree the way `-T ek`'s flat selection allows, since the whole point here is the nested shape
/// (except `--ndjson-map`, see `write_map`, which does narrow -- deliberately, opt-in).
///
/// Two opt-in, purely structural transforms, neither requiring any Lua-side change:
/// - `--ndjson-explode <field>`: a top-level Lua-produced group (e.g. `myproto`, when one TLS record
///   legitimately contains N multiplexed protocol messages) normally renders as an N-element
///   array. With this set, tlscap instead writes N separate `tls_record` lines -- envelope
///   (`tstamp`/`ip`/`tcp`/`tls`) repeated on each, the exploded field rendered singular each time.
///   Zero occurrences still writes exactly one line, without the field at all (same "a field that
///   didn't fire is omitted" convention as everywhere else) -- so a TLS record's raw decrypted
///   `tls.app_data` never becomes invisible just because a dissector's own group didn't fire.
/// - `--ndjson-map <field>`: collapses a repeated `{name, value, ...}` subtree group (e.g.
///   a real Wireshark Lua dissector's own `myproto.field`, unmodified) into a JSON map keyed by each occurrence's own `name`
///   leaf, valued by its `value` leaf -- other sub-fields are dropped, and an occurrence missing
///   `name` (an unrecognized protobuf field number, say) is skipped rather than producing a null
///   map key. See `write_map`.
pub struct NdjsonWriter {
    /// Precomputed once from the `-e` field list: the set of top-level group names to include
    /// (`ip`, `tcp`, `tls`, or any Lua-produced top-level name like `myproto`).
    groups: HashSet<String>,
    /// Non-`ip`/`tcp`/`tls` group names, in the order they were first selected -- controls output
    /// key order for Lua-produced fields, matching `-e`'s own order-preserving convention.
    generic_group_order: Vec<String>,
    /// `--ndjson-explode` target, if any -- see the struct's own doc comment.
    explode: Option<String>,
    /// `--ndjson-map` targets -- see the struct's own doc comment. A field name (matched at
    /// whatever nesting depth it's found, by its own short/stripped name) in this set renders as
    /// a JSON map instead of the usual scalar-or-array.
    map_fields: HashSet<String>,
}

impl NdjsonWriter {
    /// `fields` are `-e`-style names exactly like `EkWriter` takes (`ip.src`, `myproto`, ...) --
    /// interpreted at group granularity, see the struct's own doc comment. `explode`/`map_fields`
    /// come from `--ndjson-explode`/`--ndjson-map`.
    pub fn new(fields: Vec<String>, explode: Option<String>, map_fields: Vec<String>) -> Self {
        let mut groups = HashSet::new();
        let mut generic_group_order = Vec::new();
        for field in &fields {
            let group = field.split('.').next().unwrap_or(field).to_string();
            if groups.insert(group.clone()) && !matches!(group.as_str(), "ip" | "tcp" | "tls") {
                generic_group_order.push(group);
            }
        }
        NdjsonWriter {
            groups,
            generic_group_order,
            explode,
            map_fields: map_fields.into_iter().collect(),
        }
    }

    fn write_preamble<W: Write>(
        &self,
        w: &mut W,
        kind: &str,
        timestamp: std::time::Duration,
    ) -> io::Result<()> {
        write!(
            w,
            "{{\"kind\":\"{kind}\",\"tstamp\":{}",
            epoch_micros(timestamp)
        )
    }

    fn write_ip<W: Write>(&self, w: &mut W, src: &str, dst: &str) -> io::Result<()> {
        if !self.groups.contains("ip") {
            return Ok(());
        }
        w.write_all(b",\"ip\":{\"src\":")?;
        write_json_string(w, src)?;
        w.write_all(b",\"dst\":")?;
        write_json_string(w, dst)?;
        w.write_all(b"}")
    }

    /// Writes one decrypted-and-dissected TLS record -- one line, unless `--ndjson-explode`
    /// applies (see the struct's own doc comment), in which case one line per occurrence of the
    /// exploded field. Returns the number of bytes written, so `rotation.rs` can track
    /// output-chunk size without a second pass (matching `EkWriter`).
    pub fn write_tls_record<W: Write>(&self, w: &mut W, msg: &DecodedMessage) -> io::Result<usize> {
        let grouped = grouped_entries(&msg.fields);

        if let Some(explode_name) = &self.explode
            && let Some((_, values)) = grouped.iter().find(|(n, _)| n == explode_name)
            && !values.is_empty()
        {
            let mut total = 0;
            for v in values {
                total +=
                    self.write_one_tls_record(w, msg, &grouped, Some((explode_name.as_str(), v)))?;
            }
            return Ok(total);
        }
        self.write_one_tls_record(w, msg, &grouped, None)
    }

    /// The actual single-line writer. `exploded`, when set, substitutes one single occurrence of
    /// the named group in place of its usual scalar-or-array rendering -- the caller
    /// (`write_tls_record`) is responsible for calling this once per occurrence when exploding.
    fn write_one_tls_record<W: Write>(
        &self,
        w: &mut W,
        msg: &DecodedMessage,
        grouped: &[(&str, Vec<&FieldValue>)],
        exploded: Option<(&str, &FieldValue)>,
    ) -> io::Result<usize> {
        let mut w = CountingWriter { inner: w, count: 0 };
        self.write_preamble(&mut w, "tls_record", msg.timestamp)?;
        self.write_ip(&mut w, &msg.src_ip.to_string(), &msg.dst_ip.to_string())?;
        if self.groups.contains("tcp") {
            write!(
                w,
                ",\"tcp\":{{\"srcport\":{},\"dstport\":{}}}",
                msg.src_port, msg.dst_port
            )?;
        }
        if self.groups.contains("tls") {
            w.write_all(b",\"tls\":{\"app_data\":")?;
            write_json_string(&mut w, &hex::encode(&msg.tls_app_data))?;
            w.write_all(b"}")?;
        }
        for group in &self.generic_group_order {
            if let Some((exploded_name, single_value)) = exploded
                && group == exploded_name
            {
                w.write_all(b",")?;
                write_json_string(&mut w, group)?;
                w.write_all(b":")?;
                write_field_value(&mut w, single_value, group, &self.map_fields)?;
                continue;
            }
            let Some(values) = grouped.iter().find(|(n, _)| n == group).map(|(_, v)| v) else {
                continue;
            };
            w.write_all(b",")?;
            write_json_string(&mut w, group)?;
            w.write_all(b":")?;
            write_named_value(&mut w, group, values, group, &self.map_fields)?;
        }
        w.write_all(b"}\n")?;

        Ok(w.count)
    }

    /// Writes one raw TCP frame's own header-level event. Returns bytes written, same reasoning as
    /// `write_tls_record`.
    pub fn write_packet_event<W: Write>(&self, w: &mut W, evt: &PacketEvent) -> io::Result<usize> {
        let mut w = CountingWriter { inner: w, count: 0 };
        self.write_preamble(&mut w, "packet", evt.timestamp)?;
        self.write_ip(&mut w, &evt.src_ip.to_string(), &evt.dst_ip.to_string())?;
        if self.groups.contains("tcp") {
            w.write_all(b",\"tcp\":{\"srcport\":")?;
            write!(w, "{}", evt.src_port)?;
            w.write_all(b",\"dstport\":")?;
            write!(w, "{}", evt.dst_port)?;
            w.write_all(b",\"seq\":")?;
            write!(w, "{}", evt.seq)?;
            w.write_all(b",\"ack\":")?;
            write!(w, "{}", evt.ack)?;
            w.write_all(b",\"flags\":[")?;
            for (i, flag) in evt.flags.iter().enumerate() {
                if i > 0 {
                    w.write_all(b",")?;
                }
                write_json_string(&mut w, flag)?;
            }
            w.write_all(b"],\"payload_len\":")?;
            write!(w, "{}", evt.payload_len)?;
            w.write_all(b"}")?;
        }
        w.write_all(b"}\n")?;

        Ok(w.count)
    }
}

/// Groups `FrameFields.entries` by name, preserving first-occurrence order for the group list and
/// original encounter order for values within each group -- a repeated field (e.g. N occurrences
/// of a `Tree` subtree, or N leaf values) becomes one `(name, values)` pair with all N values, not
/// N separate pairs.
fn grouped_entries(ff: &FrameFields) -> Vec<(&str, Vec<&FieldValue>)> {
    let mut order: Vec<&str> = Vec::new();
    let mut map: std::collections::HashMap<&str, Vec<&FieldValue>> =
        std::collections::HashMap::new();
    for (name, value) in &ff.entries {
        if !map.contains_key(name.as_str()) {
            order.push(name.as_str());
        }
        map.entry(name.as_str()).or_default().push(value);
    }
    order
        .into_iter()
        .map(|name| (name, map.remove(name).unwrap()))
        .collect()
}

/// Writes `[v1,v2,...]` for one field's (possibly single-element) group of values. `prefix` is the
/// enclosing subtree's own full dotted name (e.g. `"myproto"`, or `""` at the top level) -- stripped
/// from each nested `Tree`'s own entry names so nested keys read as `type_name`/`field`/`number`
/// rather than repeating the full `myproto.type_name`/`myproto.field`/`myproto.field.number` path at every
/// level. A purely structural transformation (strip-the-enclosing-name-as-prefix), not a
/// protocol-specific one -- applies identically to any future plugin's own nested output.
/// A bare scalar if this group has exactly one *leaf* value (a plain `ProtoField` added directly,
/// e.g. `subtree:add(f_type_id, ...)`), an array otherwise. A `FieldValue::Tree` (a nested subtree
/// from `tree:add(someProto, ...)`) always stays an array regardless of count -- that's the one
/// thing a Lua dissector can structurally repeat (looping over `tree:add(proto, ...)`), so
/// `tlscap` can't guarantee its cardinality the way it can for a leaf `ProtoField` added directly
/// by a dissector's own linear, non-looping control flow (e.g. `a real Wireshark Lua dissector`'s per-message header
/// fields -- marker/sequence_id/type_id/type_name/body_len/body -- each added exactly once, never
/// in a loop). No new Lua API needed for this: it reads the distinction `dispatch_add` already
/// makes between a `Proto` first argument (creates `Tree`) and a `ProtoField` first argument
/// (creates a plain leaf value) from ordinary, unmodified Wireshark Lua dissector code.
fn write_value_or_array<W: Write>(
    w: &mut W,
    values: &[&FieldValue],
    prefix: &str,
    map_fields: &HashSet<String>,
) -> io::Result<()> {
    if let [single] = values
        && !matches!(single, FieldValue::Tree(_))
    {
        return write_field_value(w, single, prefix, map_fields);
    }
    w.write_all(b"[")?;
    for (i, v) in values.iter().enumerate() {
        if i > 0 {
            w.write_all(b",")?;
        }
        write_field_value(w, v, prefix, map_fields)?;
    }
    w.write_all(b"]")
}

/// Dispatches one named group to its map or scalar-or-array rendering, depending on whether
/// `short_name` (the group's own, already-prefix-stripped name) was selected via `--ndjson-map`.
fn write_named_value<W: Write>(
    w: &mut W,
    short_name: &str,
    values: &[&FieldValue],
    prefix: &str,
    map_fields: &HashSet<String>,
) -> io::Result<()> {
    if map_fields.contains(short_name) {
        write_map(w, values, prefix)
    } else {
        write_value_or_array(w, values, prefix, map_fields)
    }
}

fn write_field_value<W: Write>(
    w: &mut W,
    v: &FieldValue,
    prefix: &str,
    map_fields: &HashSet<String>,
) -> io::Result<()> {
    match v {
        FieldValue::UInt(n) => write!(w, "{n}"),
        FieldValue::Str(s) => write_json_string(w, s),
        FieldValue::Bytes(b) => write_json_string(w, &hex::encode(b)),
        FieldValue::Tree(child) => {
            write_frame_fields_object(w, &child.borrow(), prefix, map_fields)
        }
    }
}

/// `--ndjson-map` target: collapses a repeated `{name, value, ...}` subtree group into a JSON
/// map keyed by each occurrence's own `name` leaf, valued by its `value` leaf -- any other
/// sub-fields (e.g. a real Wireshark Lua dissector's `number`/`wiretype`/`varint`/`string`/`bytes`) are silently
/// dropped, and an occurrence missing `name` entirely (an unrecognized protobuf field number,
/// say) is skipped rather than producing a null map key. Reads exactly the `name`/`value` leaves
/// a dissector already produces for its own per-occurrence subtree -- no Lua-side change needed,
/// this is purely how tlscap chooses to render an existing shape.
fn write_map<W: Write>(w: &mut W, values: &[&FieldValue], prefix: &str) -> io::Result<()> {
    w.write_all(b"{")?;
    let stripped_prefix = format!("{prefix}.");
    let mut first = true;
    for v in values {
        let FieldValue::Tree(child) = v else { continue };
        let ff = child.borrow();
        let mut key: Option<&str> = None;
        let mut val: Option<&str> = None;
        for (name, value) in &ff.entries {
            let short = name.strip_prefix(stripped_prefix.as_str()).unwrap_or(name);
            match (short, value) {
                ("name", FieldValue::Str(s)) => key = Some(s.as_str()),
                ("value", FieldValue::Str(s)) => val = Some(s.as_str()),
                _ => {}
            }
        }
        if let (Some(k), Some(v)) = (key, val) {
            if !first {
                w.write_all(b",")?;
            }
            first = false;
            write_json_string(w, k)?;
            w.write_all(b":")?;
            write_json_string(w, v)?;
        }
    }
    w.write_all(b"}")
}

/// Renders one nested level as a JSON object: every entry name has the enclosing subtree's own
/// name (`prefix`) stripped as a leading-dot prefix, then any remaining dots become underscores
/// (matching `-T ek`'s own convention), then becomes `"key":<value-or-array-or-map>` -- see
/// `write_named_value` for the scalar/array/map decision.
fn write_frame_fields_object<W: Write>(
    w: &mut W,
    ff: &FrameFields,
    prefix: &str,
    map_fields: &HashSet<String>,
) -> io::Result<()> {
    w.write_all(b"{")?;
    let stripped_prefix = format!("{prefix}.");
    let mut first = true;
    for (name, values) in grouped_entries(ff) {
        if !first {
            w.write_all(b",")?;
        }
        first = false;
        let short = name.strip_prefix(stripped_prefix.as_str()).unwrap_or(name);
        write_json_string(w, &short.replace('.', "_"))?;
        w.write_all(b":")?;
        write_named_value(w, short, &values, name, map_fields)?;
    }
    w.write_all(b"}")
}

fn epoch_millis(timestamp: std::time::Duration) -> u128 {
    timestamp.as_millis()
}

/// `-T ndjson` uses microsecond resolution (unlike `-T ek`'s millis, kept for tshark
/// compatibility) -- real capture interfaces typically report microsecond timestamps (see
/// `pcap_input.rs::correct_epb_timestamp`), and millis was coarse enough to collapse multiple
/// distinct packets from the same reassembly burst onto one value.
fn epoch_micros(timestamp: std::time::Duration) -> u128 {
    timestamp.as_micros()
}

/// `"packets-YYYY-MM-DD"` index-date suffix, derived from the message's own capture timestamp
/// (matching real tshark, which indexes by the frame's own time, not wall-clock processing time).
fn index_date(timestamp: std::time::Duration) -> String {
    // No chrono::DateTime::from_timestamp-style dependency on wall-clock "now" -- purely a
    // deterministic calendar computation from a Unix epoch offset, civil-from-days (Howard
    // Hinnant's well-known constant-time algorithm), so this stays testable without a real clock.
    let days = (timestamp.as_secs() / 86400) as i64;
    let (y, m, d) = civil_from_days(days);
    format!("{:04}-{:02}-{:02}", y, m, d)
}

/// http://howardhinnant.github.io/date_algorithms.html#civil_from_days -- days since 1970-01-01 ->
/// (year, month, day). Avoids pulling in a full calendar-arithmetic dependency for one field.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Minimal JSON string escaping -- values here are always either our own formatted numbers/IPs
/// (never need escaping) or Lua-dissector-produced strings (which can contain arbitrary bytes,
/// including quotes/control characters/non-UTF8, since they come from decrypted protocol data).
fn write_json_string<W: Write>(w: &mut W, s: &str) -> io::Result<()> {
    w.write_all(b"\"")?;
    for c in s.chars() {
        match c {
            '"' => w.write_all(b"\\\"")?,
            '\\' => w.write_all(b"\\\\")?,
            '\n' => w.write_all(b"\\n")?,
            '\r' => w.write_all(b"\\r")?,
            '\t' => w.write_all(b"\\t")?,
            c if (c as u32) < 0x20 => write!(w, "\\u{:04x}", c as u32)?,
            c => write!(w, "{c}")?,
        }
    }
    w.write_all(b"\"")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lua::FrameFields;
    use crate::lua::tree::FieldValue;
    use std::cell::RefCell;
    use std::net::{IpAddr, Ipv4Addr};
    use std::rc::Rc;
    use std::time::Duration;

    fn sample_message() -> DecodedMessage {
        let mut fields = FrameFields::default();
        fields.entries.push((
            "example.type_name".to_string(),
            FieldValue::Str("HEARTBEAT_REQUEST".to_string()),
        ));
        fields.entries.push((
            "example.field.kv".to_string(),
            FieldValue::Str("timestamp=123".to_string()),
        ));
        fields.entries.push((
            "example.field.kv".to_string(),
            FieldValue::Str("echoField=abc".to_string()),
        ));
        fields.protocol = Some("EXAMPLE".to_string());

        DecodedMessage {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: 51234,
            dst_port: 9410,
            tls_app_data: vec![0xAA, 0xBB],
            fields,
            timestamp: Duration::from_millis(1_783_600_000_123),
        }
    }

    #[test]
    fn writes_two_line_ndjson_with_expected_shape() {
        let writer = EkWriter::new(
            vec![
                "ip.src".into(),
                "ip.dst".into(),
                "example.type_name".into(),
                "example.field.kv".into(),
            ],
            "packets".into(),
        );
        let mut out = Vec::new();
        writer.write_message(&mut out, &sample_message()).unwrap();
        let text = String::from_utf8(out).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with(r#"{"index":{"_index":"packets-"#));
        assert!(lines[0].ends_with("\"}}"));
        assert!(lines[1].starts_with(r#"{"timestamp":"1783600000123","layers":{"#));
    }

    #[test]
    fn dot_to_underscore_and_array_wrapping() {
        let writer = EkWriter::new(
            vec!["ip.src".into(), "example.type_name".into()],
            "packets".into(),
        );
        let mut out = Vec::new();
        writer.write_message(&mut out, &sample_message()).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains(r#""ip_src":["10.0.0.1"]"#));
        assert!(text.contains(r#""example_type_name":["HEARTBEAT_REQUEST"]"#));
    }

    #[test]
    fn repeated_field_becomes_multi_element_array_in_encounter_order() {
        let writer = EkWriter::new(vec!["example.field.kv".into()], "packets".into());
        let mut out = Vec::new();
        writer.write_message(&mut out, &sample_message()).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains(r#""example_field_kv":["timestamp=123","echoField=abc"]"#));
    }

    #[test]
    fn unfired_field_key_is_omitted_entirely_not_empty_array() {
        let writer = EkWriter::new(
            vec!["ip.src".into(), "example.sequence_id".into()],
            "packets".into(),
        );
        let mut out = Vec::new();
        writer.write_message(&mut out, &sample_message()).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(
            !text.contains("example_sequence_id"),
            "a field that never fired must not appear as a key at all"
        );
    }

    #[test]
    fn values_are_json_escaped() {
        let mut fields = FrameFields::default();
        fields.entries.push((
            "example.field.kv".to_string(),
            FieldValue::Str("name=\"quoted\"\nvalue".to_string()),
        ));
        let msg = DecodedMessage {
            src_ip: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            src_port: 0,
            dst_port: 0,
            tls_app_data: Vec::new(),
            fields,
            timestamp: Duration::ZERO,
        };
        let writer = EkWriter::new(vec!["example.field.kv".into()], "packets".into());
        let mut out = Vec::new();
        writer.write_message(&mut out, &msg).unwrap();
        let text = String::from_utf8(out).unwrap();
        // Must still parse as valid JSON lines despite embedded quotes/newlines.
        let data_line = text.lines().nth(1).unwrap();
        assert!(data_line.contains(r#"\"quoted\""#));
        assert!(data_line.contains(r"\n"));
    }

    #[test]
    fn civil_date_matches_known_epoch_days() {
        // 1970-01-01 is day 0.
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        // 2026-07-09 (today, at time of writing) -- cross-checked against `date -d @<epoch>`.
        let epoch = 1_783_670_400i64; // 2026-07-09T00:00:00Z... approx, see next assert for the real check
        let days = epoch / 86400;
        let (y, m, d) = civil_from_days(days);
        assert_eq!(y, 2026);
        assert_eq!(m, 7);
        assert!((1..=31).contains(&d));
    }

    #[test]
    fn ndjson_writes_one_line_no_index_action() {
        let writer = NdjsonWriter::new(vec!["ip.src".into(), "ip.dst".into()], None, vec![]);
        let mut out = Vec::new();
        writer
            .write_tls_record(&mut out, &sample_message())
            .unwrap();
        let text = String::from_utf8(out).unwrap();
        assert_eq!(
            text.lines().count(),
            1,
            "ndjson is one JSON object per line, no index-action line"
        );
        assert!(!text.contains("\"index\""));
        assert!(text.starts_with(r#"{"kind":"tls_record","tstamp":1783600000123000"#));
    }

    #[test]
    fn ndjson_envelope_fields_are_scalar_not_arrays() {
        let writer = NdjsonWriter::new(
            vec![
                "ip.src".into(),
                "ip.dst".into(),
                "tcp.srcport".into(),
                "tcp.dstport".into(),
                "tls.app_data".into(),
            ],
            None,
            vec![],
        );
        let mut out = Vec::new();
        writer
            .write_tls_record(&mut out, &sample_message())
            .unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains(r#""ip":{"src":"10.0.0.1","dst":"10.0.0.2"}"#));
        assert!(text.contains(r#""tcp":{"srcport":51234,"dstport":9410}"#));
        assert!(text.contains(r#""tls":{"app_data":"aabb"}"#));
    }

    #[test]
    fn ndjson_timestamp_is_microsecond_resolution() {
        let writer = NdjsonWriter::new(vec![], None, vec![]);
        let msg = DecodedMessage {
            timestamp: Duration::from_micros(1_783_600_000_123_456),
            ..sample_message()
        };
        let mut out = Vec::new();
        writer.write_tls_record(&mut out, &msg).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.starts_with(r#"{"kind":"tls_record","tstamp":1783600000123456"#),
            "sub-millisecond precision must survive, unlike -T ek's millis: {text}"
        );
    }

    /// Simulates the shape `a real Wireshark Lua dissector` now produces (after its own restructuring): one
    /// message-level subtree ("myproto"), itself containing a nested per-protobuf-field subtree
    /// ("myproto.field") -- exercising both levels of nesting, the prefix-stripping at each level,
    /// type-awareness (UInt fields render as bare numbers), and that a leaf field occurring
    /// exactly once (`type_name`, `sequence_id`, `number`, `name`, `value`) renders as a bare
    /// scalar rather than a single-element array, while the two genuinely-repeatable `Tree`
    /// containers (`myproto`, `field`) still render as arrays even though only one of each occurs
    /// here -- see `write_value_or_array`.
    #[test]
    fn ndjson_nested_subtree_strips_enclosing_prefix_and_stays_type_aware() {
        let mut field_tree = FrameFields::default();
        field_tree
            .entries
            .push(("myproto.field.number".to_string(), FieldValue::UInt(2)));
        field_tree.entries.push((
            "myproto.field.name".to_string(),
            FieldValue::Str("echoField".to_string()),
        ));
        field_tree.entries.push((
            "myproto.field.value".to_string(),
            FieldValue::Str("1783648538342".to_string()),
        ));

        let mut message_tree = FrameFields::default();
        message_tree.entries.push((
            "myproto.type_name".to_string(),
            FieldValue::Str("HEARTBEAT_REQUEST".to_string()),
        ));
        message_tree.entries.push((
            "myproto.sequence_id".to_string(),
            FieldValue::UInt(40977388),
        ));
        message_tree.entries.push((
            "myproto.field".to_string(),
            FieldValue::Tree(Rc::new(RefCell::new(field_tree))),
        ));

        let mut fields = FrameFields::default();
        fields.entries.push((
            "myproto".to_string(),
            FieldValue::Tree(Rc::new(RefCell::new(message_tree))),
        ));

        let msg = DecodedMessage {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: 51234,
            dst_port: 9410,
            tls_app_data: Vec::new(),
            fields,
            timestamp: Duration::ZERO,
        };

        let writer = NdjsonWriter::new(vec!["myproto".into()], None, vec![]);
        let mut out = Vec::new();
        writer.write_tls_record(&mut out, &msg).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains(
            r#""myproto":[{"type_name":"HEARTBEAT_REQUEST","sequence_id":40977388,"field":[{"number":2,"name":"echoField","value":"1783648538342"}]}]"#
        ));
    }

    /// A leaf field added more than once under the same parent (unusual, but not something
    /// `tlscap` can rule out for an arbitrary plugin) must still fall back to an array -- only a
    /// leaf occurring *exactly* once gets the scalar treatment.
    #[test]
    fn ndjson_leaf_field_occurring_twice_stays_an_array() {
        let mut message_tree = FrameFields::default();
        message_tree
            .entries
            .push(("myproto.type_id".to_string(), FieldValue::UInt(1)));
        message_tree
            .entries
            .push(("myproto.type_id".to_string(), FieldValue::UInt(2)));

        let mut fields = FrameFields::default();
        fields.entries.push((
            "myproto".to_string(),
            FieldValue::Tree(Rc::new(RefCell::new(message_tree))),
        ));

        let msg = DecodedMessage {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: 51234,
            dst_port: 9410,
            tls_app_data: Vec::new(),
            fields,
            timestamp: Duration::ZERO,
        };

        let writer = NdjsonWriter::new(vec!["myproto".into()], None, vec![]);
        let mut out = Vec::new();
        writer.write_tls_record(&mut out, &msg).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains(r#""myproto":[{"type_id":[1,2]}]"#));
    }

    #[test]
    fn ndjson_packet_event_has_kind_packet_canonical_flags_and_no_tls_or_app_data() {
        let writer = NdjsonWriter::new(
            vec![
                "ip.src".into(),
                "ip.dst".into(),
                "tcp.srcport".into(),
                "tcp.dstport".into(),
            ],
            None,
            vec![],
        );
        let evt = PacketEvent {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: 51234,
            dst_port: 9410,
            seq: 1001,
            ack: 5001,
            flags: vec!["ack", "psh"],
            payload_len: 128,
            timestamp: Duration::from_millis(999),
        };
        let mut out = Vec::new();
        writer.write_packet_event(&mut out, &evt).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert_eq!(text.lines().count(), 1);
        assert!(text.starts_with(r#"{"kind":"packet","tstamp":999000"#));
        assert!(text.contains(
            r#""tcp":{"srcport":51234,"dstport":9410,"seq":1001,"ack":5001,"flags":["ack","psh"],"payload_len":128}"#
        ));
        assert!(
            !text.contains("\"tls\""),
            "a packet event never has tls/myproto data"
        );
        assert!(!text.contains("\"myproto\""));
    }

    fn myproto_message_tree(sequence_id: u64) -> FieldValue {
        let mut message_tree = FrameFields::default();
        message_tree.entries.push((
            "myproto.type_name".to_string(),
            FieldValue::Str("HEARTBEAT_REQUEST".to_string()),
        ));
        message_tree.entries.push((
            "myproto.sequence_id".to_string(),
            FieldValue::UInt(sequence_id),
        ));
        FieldValue::Tree(Rc::new(RefCell::new(message_tree)))
    }

    /// Two multiplexed `myproto` messages in one TLS record (the real-world case `--ndjson-explode`
    /// exists for) become two separate lines, envelope repeated, `myproto` singular on each -- not
    /// one line with a 2-element `myproto` array.
    #[test]
    fn ndjson_explode_splits_repeated_top_level_group_into_multiple_lines() {
        let mut fields = FrameFields::default();
        fields
            .entries
            .push(("myproto".to_string(), myproto_message_tree(1)));
        fields
            .entries
            .push(("myproto".to_string(), myproto_message_tree(2)));

        let msg = DecodedMessage {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: 51234,
            dst_port: 9410,
            tls_app_data: vec![0xAA],
            fields,
            timestamp: Duration::ZERO,
        };

        let writer = NdjsonWriter::new(
            vec!["ip.src".into(), "tls.app_data".into(), "myproto".into()],
            Some("myproto".to_string()),
            vec![],
        );
        let mut out = Vec::new();
        writer.write_tls_record(&mut out, &msg).unwrap();
        let text = String::from_utf8(out).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "one line per exploded occurrence: {text}");
        assert!(
            lines[0].contains(r#""myproto":{"type_name":"HEARTBEAT_REQUEST","sequence_id":1}"#)
        );
        assert!(
            lines[1].contains(r#""myproto":{"type_name":"HEARTBEAT_REQUEST","sequence_id":2}"#)
        );
        // envelope (ip/tls) repeated identically on both exploded lines
        for line in &lines {
            assert!(line.contains(r#""ip":{"src":"10.0.0.1""#));
            assert!(line.contains(r#""tls":{"app_data":"aa"}"#));
        }
    }

    /// A TLS record whose dissector found no `myproto` message at all (malformed, or simply not this
    /// protocol) must still produce exactly one line, with `tls.app_data` visible -- exploding on
    /// zero occurrences must never make the underlying decrypted data disappear.
    #[test]
    fn ndjson_explode_with_zero_occurrences_emits_one_line_without_the_field() {
        let msg = DecodedMessage {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: 51234,
            dst_port: 9410,
            tls_app_data: vec![0xAA],
            fields: FrameFields::default(),
            timestamp: Duration::ZERO,
        };

        let writer = NdjsonWriter::new(
            vec!["tls.app_data".into(), "myproto".into()],
            Some("myproto".to_string()),
            vec![],
        );
        let mut out = Vec::new();
        writer.write_tls_record(&mut out, &msg).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert_eq!(text.lines().count(), 1);
        assert!(text.contains(r#""tls":{"app_data":"aa"}"#));
        assert!(!text.contains("\"myproto\""));
    }

    /// `--ndjson-map field` collapses a real Wireshark Lua dissector's own, unmodified `myproto.field` shape (an array of
    /// `{number, name, wiretype, value, ...}` structs) into a `map<string,string>` keyed by
    /// `name`/valued by `value` -- other sub-fields dropped, no Lua-side change involved.
    #[test]
    fn ndjson_map_collapses_name_value_pairs_into_a_json_map() {
        let mut field1 = FrameFields::default();
        field1
            .entries
            .push(("field.number".to_string(), FieldValue::UInt(1)));
        field1.entries.push((
            "field.name".to_string(),
            FieldValue::Str("timestamp".to_string()),
        ));
        field1.entries.push((
            "field.value".to_string(),
            FieldValue::Str("123".to_string()),
        ));

        let mut field2 = FrameFields::default();
        field2
            .entries
            .push(("field.number".to_string(), FieldValue::UInt(2)));
        field2.entries.push((
            "field.name".to_string(),
            FieldValue::Str("echoField".to_string()),
        ));
        field2.entries.push((
            "field.value".to_string(),
            FieldValue::Str("abc".to_string()),
        ));

        let mut fields = FrameFields::default();
        fields.entries.push((
            "field".to_string(),
            FieldValue::Tree(Rc::new(RefCell::new(field1))),
        ));
        fields.entries.push((
            "field".to_string(),
            FieldValue::Tree(Rc::new(RefCell::new(field2))),
        ));

        let msg = DecodedMessage {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: 51234,
            dst_port: 9410,
            tls_app_data: Vec::new(),
            fields,
            timestamp: Duration::ZERO,
        };

        let writer = NdjsonWriter::new(vec!["field".into()], None, vec!["field".to_string()]);
        let mut out = Vec::new();
        writer.write_tls_record(&mut out, &msg).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains(r#""field":{"timestamp":"123","echoField":"abc"}"#));
    }

    /// An occurrence with no `name` leaf at all (a real Wireshark Lua dissector's own convention for an unrecognized
    /// protobuf field number) is skipped -- never produces a null-keyed map entry, which is
    /// exactly the shape that broke Athena's JSON SerDe before this existed.
    #[test]
    fn ndjson_map_skips_entries_missing_name() {
        let mut named = FrameFields::default();
        named.entries.push((
            "field.name".to_string(),
            FieldValue::Str("echoField".to_string()),
        ));
        named.entries.push((
            "field.value".to_string(),
            FieldValue::Str("abc".to_string()),
        ));

        let mut nameless = FrameFields::default();
        nameless
            .entries
            .push(("field.number".to_string(), FieldValue::UInt(66)));
        nameless.entries.push((
            "field.value".to_string(),
            FieldValue::Str("unrecognized".to_string()),
        ));

        let mut fields = FrameFields::default();
        fields.entries.push((
            "field".to_string(),
            FieldValue::Tree(Rc::new(RefCell::new(named))),
        ));
        fields.entries.push((
            "field".to_string(),
            FieldValue::Tree(Rc::new(RefCell::new(nameless))),
        ));

        let msg = DecodedMessage {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: 51234,
            dst_port: 9410,
            tls_app_data: Vec::new(),
            fields,
            timestamp: Duration::ZERO,
        };

        let writer = NdjsonWriter::new(vec!["field".into()], None, vec!["field".to_string()]);
        let mut out = Vec::new();
        writer.write_tls_record(&mut out, &msg).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains(r#""field":{"echoField":"abc"}"#));
        assert!(!text.contains("unrecognized"));
        assert!(!text.contains("null"));
    }
}
