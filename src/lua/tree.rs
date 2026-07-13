//! `ProtoField`, `TreeItem`, and the per-frame field accumulator that actually produces
//! `tlscap`'s output. `gui_enabled()` is hardcoded to `false` (see `lua/mod.rs`), so every
//! dissector this shim runs takes the same lean, non-GUI code path it already takes under real
//! tshark. `tree:add(field, ...)` records `(field_name, value)` into the current level's flat
//! accumulator, in encounter order; `tree:add(proto, ...)` (subtree creation) genuinely nests --
//! matching real Wireshark's own Lua API, where a subtree handle's own `:add()` calls appear under
//! it -- rather than flattening into the parent (see `FieldValue::Tree`). `-e <field>` selection
//! (`ek_output.rs`) reads through this via `FrameFields::values_for`'s recursive search, so nesting
//! depth is transparent to output-field selection: `-e myproto.type_name` finds it regardless of how
//! many subtree levels it's actually nested under.

use std::cell::RefCell;
use std::rc::Rc;

use mlua::{
    Error as LuaError, Lua, MultiValue, Result as LuaResult, Table, UserData, UserDataMethods,
    Value,
};

use super::tvb::TvbRange;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldKind {
    UInt,
    Str,
    Bytes,
}

/// A registered `ProtoField` -- returned by `ProtoField.uint16(...)` etc. Carries just enough to
/// let `TreeItem:add()` know the field's output name and how to auto-extract a value from a
/// `TvbRange` when no explicit value was passed.
#[derive(Clone)]
pub struct FieldDef {
    pub name: Rc<str>,
    pub kind: FieldKind,
}

impl UserData for FieldDef {}

#[derive(Clone, Debug, PartialEq)]
pub enum FieldValue {
    UInt(u64),
    Str(String),
    Bytes(Vec<u8>),
    /// A nested subtree, created by `tree:add(proto, tvbrange, label)` -- real Wireshark's own Lua
    /// API genuinely nests (a subtree handle's own `:add()` calls appear under it, not flattened
    /// into the parent), and so does this. Keyed in the parent's `entries` by the `Proto`'s own
    /// `.name` -- repeated `tree:add(proto, ...)` calls under the same parent (e.g. N occurrences
    /// of one message type in a combined buffer) naturally produce N `Tree` entries under that
    /// same name, reusing the *existing* repeated-field-as-array convention rather than inventing
    /// a new one.
    Tree(Rc<RefCell<FrameFields>>),
}

impl FieldValue {
    pub fn to_output_string(&self) -> String {
        match self {
            FieldValue::UInt(v) => v.to_string(),
            FieldValue::Str(s) => s.clone(),
            FieldValue::Bytes(b) => hex_encode(b),
            // A subtree has no single scalar representation -- `-T ek`-style flat field selection
            // never resolves directly to a `Tree` value (see `FrameFields::values_for`'s recursive
            // descent, which only ever collects the *leaf* values found inside one), so this arm is
            // unreachable in practice. Not treated as a hard error: matches this enum's existing
            // philosophy of always producing *some* string rather than panicking on a shape it
            // wasn't expecting.
            FieldValue::Tree(_) => String::new(),
        }
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Everything recorded for one dissection call (one Lua dissector invocation over one TLS
/// record's worth of plaintext), in encounter order. `-e <field>` selection at output time reads
/// straight out of this.
#[derive(Default, Debug, Clone, PartialEq)]
pub struct FrameFields {
    pub entries: Vec<(String, FieldValue)>,
    pub protocol: Option<String>,
    pub info: Option<String>,
    pub malformed: Vec<String>,
}

impl FrameFields {
    /// Depth-first search across the whole nested structure, not just this level's own `entries` --
    /// required once a dissector nests (e.g. `myproto.type_name` living one level down inside each
    /// message's own subtree), and also the technically-correct behavior to match real tshark's own
    /// `-T ek`, which already flattens repeated nested-subtree fields into one array regardless of
    /// depth. A `Tree`-valued entry itself is never returned (it has no scalar `FieldValue`) -- only
    /// leaf values are collected, from anywhere inside it. Returns owned values, not references --
    /// a `Tree` child lives behind an `Rc<RefCell<_>>`, so borrowing into it can only ever yield a
    /// reference bounded by that borrow's own guard, not by `&self`'s lifetime.
    pub fn values_for(&self, field_name: &str) -> Vec<FieldValue> {
        let mut out = Vec::new();
        self.collect_values_for(field_name, &mut out);
        out
    }

    fn collect_values_for(&self, field_name: &str, out: &mut Vec<FieldValue>) {
        for (name, value) in &self.entries {
            match value {
                FieldValue::Tree(child) => {
                    // The field being searched for might live inside, at any depth, regardless of
                    // whether this subtree's own name happens to match (selecting a whole subtree
                    // isn't meaningful as a scalar -- see `to_output_string`'s doc comment, so a
                    // name match on a `Tree` entry itself is never pushed).
                    child.borrow().collect_values_for(field_name, out);
                }
                _ if name == field_name => out.push(value.clone()),
                _ => {}
            }
        }
    }
}

/// The `tree`/subtree handle passed into a Lua dissector. Every `TreeItem` created during one
/// dissection call (via chained `:add()`s) shares the same underlying accumulator -- there's no
/// real tree structure, just a flat, ordered log of what was added.
#[derive(Clone)]
pub struct TreeItem {
    pub fields: Rc<RefCell<FrameFields>>,
}

impl TreeItem {
    pub fn new(fields: Rc<RefCell<FrameFields>>) -> Self {
        Self { fields }
    }

    fn record(&self, name: &str, value: FieldValue) {
        self.fields
            .borrow_mut()
            .entries
            .push((name.to_string(), value));
    }
}

fn value_from_lua(v: &Value) -> Option<FieldValue> {
    match v {
        Value::Integer(i) => Some(FieldValue::UInt(*i as u64)),
        Value::Number(n) => Some(FieldValue::UInt(*n as u64)),
        Value::String(s) => Some(FieldValue::Str(s.to_string_lossy())),
        Value::UserData(ud) => {
            if let Ok(u) = ud.borrow::<UInt64>() {
                return Some(FieldValue::UInt(u.0));
            }
            None
        }
        _ => None,
    }
}

fn value_from_tvbrange(range: &TvbRange, kind: FieldKind) -> FieldValue {
    match kind {
        FieldKind::UInt => FieldValue::UInt(range.uint_be().unwrap_or(0)),
        FieldKind::Bytes => FieldValue::Bytes(range.bytes().to_vec()),
        FieldKind::Str => FieldValue::Str(String::from_utf8_lossy(range.bytes()).into_owned()),
    }
}

fn value_from_tvbrange_le(range: &TvbRange, kind: FieldKind) -> FieldValue {
    match kind {
        FieldKind::UInt => FieldValue::UInt(range.uint_le().unwrap_or(0)),
        other => value_from_tvbrange(range, other),
    }
}

/// Handles the generic, overloaded `TreeItem:add(field_or_proto, ...)` call shape used throughout
/// real Wireshark Lua dissectors:
///   tree:add(protofield, tvbrange)              -- auto-extract value from tvbrange (big-endian)
///   tree:add(protofield, tvbrange, value)        -- explicit value, tvbrange only for provenance
///   tree:add(protofield, value)                   -- explicit value, no tvbrange at all
///   tree:add(proto, tvbrange, "label")              -- subtree creation, records nothing
fn dispatch_add(this: &TreeItem, args: MultiValue, little_endian: bool) -> LuaResult<TreeItem> {
    let mut iter = args.into_iter();
    let first = iter.next().ok_or_else(|| {
        LuaError::RuntimeError("TreeItem:add: missing field/proto argument".into())
    })?;

    // First argument is a ProtoField -> this call records a field value.
    if let Value::UserData(ud) = &first
        && let Ok(field) = ud.borrow::<FieldDef>()
    {
        let rest: Vec<Value> = iter.collect();
        let value = match rest.as_slice() {
            [Value::UserData(tvb_ud), explicit] => {
                if let Ok(range) = tvb_ud.borrow::<TvbRange>() {
                    value_from_lua(explicit)
                        .unwrap_or_else(|| value_from_tvbrange(&range, field.kind))
                } else {
                    value_from_lua(explicit).unwrap_or(FieldValue::UInt(0))
                }
            }
            [Value::UserData(tvb_ud)] => {
                if let Ok(range) = tvb_ud.borrow::<TvbRange>() {
                    if little_endian {
                        value_from_tvbrange_le(&range, field.kind)
                    } else {
                        value_from_tvbrange(&range, field.kind)
                    }
                } else {
                    FieldValue::UInt(0)
                }
            }
            [only] => value_from_lua(only).unwrap_or(FieldValue::UInt(0)),
            [] => FieldValue::UInt(0),
            _ => value_from_lua(&rest[rest.len() - 1]).unwrap_or(FieldValue::UInt(0)),
        };
        this.record(&field.name, value);
        return Ok(this.clone());
    }

    // Otherwise: a Proto (plain table) as the first argument -- subtree creation. Real Wireshark's
    // own Lua API genuinely nests here (a subtree handle's own `:add()` calls appear under it, not
    // flattened into the parent) -- create a real child accumulator, record it into the current
    // level keyed by the Proto's own `.name`, and hand back a `TreeItem` wrapping the child so
    // subsequent calls on it go there instead.
    if let Value::Table(proto) = &first
        && let Ok(name) = proto.get::<String>("name")
    {
        let child = Rc::new(RefCell::new(FrameFields::default()));
        this.record(&name, FieldValue::Tree(child.clone()));
        return Ok(TreeItem::new(child));
    }

    // Neither a ProtoField nor a Proto table -- not a shape real Wireshark dissectors produce, but
    // fail soft (matching this method's existing philosophy elsewhere) rather than erroring out and
    // aborting the whole dissection over one unexpected call shape.
    Ok(this.clone())
}

impl UserData for TreeItem {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        methods.add_method("add", |_, this, args: MultiValue| {
            dispatch_add(this, args, false)
        });
        methods.add_method("add_le", |_, this, args: MultiValue| {
            dispatch_add(this, args, true)
        });
        methods.add_method("set_generated", |_, this, ()| Ok(this.clone()));
        methods.add_method("set_hidden", |_, this, ()| Ok(this.clone()));
        methods.add_method(
            "add_expert_info",
            |_, this, (_severity, _group, msg): (Value, Value, Option<String>)| {
                this.fields
                    .borrow_mut()
                    .malformed
                    .push(msg.unwrap_or_default());
                Ok(())
            },
        );
    }
}

/// `UInt64.new(value)` -- real Wireshark requires this wrapper for `ProtoField.uint64` values
/// since a plain Lua number can't losslessly hold a 64-bit integer under older Lua number models.
/// Under Lua 5.4's native 64-bit integer subtype this wrapper is no longer strictly necessary for
/// precision, but real Wireshark Lua dissectors still construct and pass it, so the shim must
/// accept it.
#[derive(Clone, Copy)]
pub struct UInt64(pub u64);

impl UserData for UInt64 {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        methods.add_meta_method(mlua::MetaMethod::ToString, |_, this, ()| {
            Ok(this.0.to_string())
        });
    }
}

pub fn install(lua: &Lua, globals: &Table) -> LuaResult<()> {
    let proto_field = lua.create_table()?;
    for (name, kind) in [
        ("uint8", FieldKind::UInt),
        ("uint16", FieldKind::UInt),
        ("uint32", FieldKind::UInt),
        ("uint64", FieldKind::UInt),
        ("string", FieldKind::Str),
        ("bytes", FieldKind::Bytes),
    ] {
        proto_field.set(
            name,
            lua.create_function(move |_, args: MultiValue| {
                let mut iter = args.into_iter();
                let field_name: String = match iter.next() {
                    Some(Value::String(s)) => s.to_string_lossy(),
                    _ => {
                        return Err(LuaError::RuntimeError(
                            "ProtoField.*: field name (first arg) must be a string".into(),
                        ));
                    }
                };
                Ok(FieldDef {
                    name: Rc::from(field_name.as_str()),
                    kind,
                })
            })?,
        )?;
    }
    globals.set("ProtoField", proto_field)?;

    let uint64_table = lua.create_table()?;
    uint64_table.set(
        "new",
        lua.create_function(|_, v: Value| {
            let n = match v {
                Value::Integer(i) => i as u64,
                Value::Number(n) => n as u64,
                _ => 0,
            };
            Ok(UInt64(n))
        })?,
    )?;
    globals.set("UInt64", uint64_table)?;

    globals.set("PI_MALFORMED", "malformed")?;
    globals.set("PI_ERROR", "error")?;

    let base = lua.create_table()?;
    base.set("HEX", "hex")?;
    base.set("DEC", "dec")?;
    base.set("NONE", "none")?;
    globals.set("base", base)?;

    Ok(())
}
