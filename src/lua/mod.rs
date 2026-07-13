//! Embedded Lua VM exposing a Wireshark-Lua-API-compatible shim, scoped to exactly the surface a
//! real Wireshark Lua dissector (and similarly-shaped dissectors) actually use: `Proto`,
//! `ProtoField.*`, `Tvb`/`TvbRange`, `TreeItem:add()`, `pinfo.cols`, `DissectorTable`,
//! `gui_enabled()`, `UInt64.new()`, `PI_MALFORMED`/`PI_ERROR`, `base.HEX`/`base.DEC`. Not a claim
//! of full Wireshark Lua API coverage -- a genuinely pluggable architecture, extensible
//! incrementally.

pub mod dissector_table;
pub mod pinfo;
pub mod tree;
pub mod tvb;

use std::cell::RefCell;
use std::rc::Rc;

use mlua::{Lua, Result as LuaResult, Table};

pub use tree::{FieldValue, FrameFields};

use dissector_table::Registry as DissectorRegistry;
use tvb::Tvb;

pub struct LuaEngine {
    lua: Lua,
    tls_port_registry: DissectorRegistry,
}

impl LuaEngine {
    pub fn new() -> LuaResult<Self> {
        let lua = Lua::new();
        let globals = lua.globals();
        let tls_port_registry: DissectorRegistry =
            Rc::new(RefCell::new(std::collections::HashMap::new()));

        install_proto(&lua, &globals)?;
        install_gui(&lua, &globals)?;
        tree::install(&lua, &globals)?;
        dissector_table::install(&lua, &globals, tls_port_registry.clone())?;

        Ok(Self {
            lua,
            tls_port_registry,
        })
    }

    /// Loads and executes one Lua plugin file's top-level code (registration side effects only --
    /// `Proto()`, `ProtoField.*`, and `DissectorTable...:add()` calls run immediately; the
    /// dissector function itself is only invoked later, per decrypted record, via `dissect()`).
    pub fn load_plugin_file(&self, path: &std::path::Path) -> LuaResult<()> {
        let src = std::fs::read_to_string(path).map_err(|e| {
            mlua::Error::RuntimeError(format!("reading plugin {}: {}", path.display(), e))
        })?;
        self.load_plugin_str(&src, &path.display().to_string())
    }

    pub fn load_plugin_str(&self, src: &str, chunk_name: &str) -> LuaResult<()> {
        self.lua.load(src).set_name(chunk_name).exec()
    }

    /// Returns true if some loaded plugin registered a dissector for `port` on `tls.port`.
    pub fn has_dissector_for_port(&self, port: u16) -> bool {
        self.tls_port_registry.borrow().contains_key(&port)
    }

    /// Bytes currently tracked as live by the Lua GC heap -- diagnostic only (see
    /// `dissect()`'s doc comment: the userdata it creates per call is GC-managed, not
    /// deterministically freed, so this is expected to fluctuate with GC pacing under load).
    pub fn lua_used_memory(&self) -> usize {
        self.lua.used_memory()
    }

    /// Invokes the Lua dissector registered for `port` against `plaintext`, returning everything
    /// it recorded via `tree:add()`/`pinfo.cols`, plus how many leading bytes of `plaintext` it
    /// actually consumed (real Wireshark dissectors return this as their function's own return
    /// value, e.g. `return dissected_any and offset or 0`; a dissector that
    /// doesn't return a number is treated as having consumed everything, the conservative choice
    /// that avoids accidentally re-feeding already-processed bytes back in on the next call).
    /// Returns `Ok(None)` if no plugin registered for this port (caller should treat the record
    /// as un-dissectable, not an error).
    pub fn dissect(
        &self,
        port: u16,
        plaintext: Rc<Vec<u8>>,
    ) -> LuaResult<Option<(FrameFields, usize)>> {
        let proto_table = match self.tls_port_registry.borrow().get(&port) {
            Some(t) => t.clone(),
            None => return Ok(None),
        };
        let dissector: mlua::Function = proto_table.get("dissector")?;
        let plaintext_len = plaintext.len();

        let fields = Rc::new(RefCell::new(FrameFields::default()));
        let tvb = Tvb::new(plaintext);
        let tree = tree::TreeItem::new(fields.clone());
        let pinfo = pinfo::new_pinfo(&self.lua, fields.clone())?;

        let ret: mlua::Value = dissector.call((tvb, pinfo, tree))?;
        let consumed = match ret {
            mlua::Value::Integer(n) if n >= 0 => (n as usize).min(plaintext_len),
            mlua::Value::Number(n) if n >= 0.0 => (n as usize).min(plaintext_len),
            _ => plaintext_len,
        };

        // NOT Rc::try_unwrap: Lua userdata (the subtree handles / pinfo.cols created during the
        // call) are garbage-collected, not deterministically dropped when the call returns, so
        // the Rc can still have live references here even though dissection is fully finished.
        // try_unwrap would fail in that case -- cloning out of the RefCell is correct regardless
        // of GC timing and is cheap (FrameFields is small).
        Ok(Some((fields.borrow().clone(), consumed)))
    }
}

/// `Proto(name, description)` -- returns a plain Lua table. Deliberately not a custom UserData:
/// a real Wireshark Lua dissector's `my_proto.fields = {...}` and
/// `function my_proto.dissector(...) ... end` are just ordinary Lua table field writes, which a
/// plain table already supports natively with zero special-casing needed on the Rust side.
fn install_proto(lua: &Lua, globals: &Table) -> LuaResult<()> {
    globals.set(
        "Proto",
        lua.create_function(|lua, (name, description): (String, Option<String>)| {
            let t = lua.create_table()?;
            t.set("name", name)?;
            if let Some(d) = description {
                t.set("description", d)?;
            }
            Ok(t)
        })?,
    )?;
    Ok(())
}

/// `gui_enabled()` always returns `false` -- there is no GUI here, so every loaded dissector takes
/// the same lean, non-GUI-subtree code path it already takes under real tshark.
fn install_gui(lua: &Lua, globals: &Table) -> LuaResult<()> {
    globals.set("gui_enabled", lua.create_function(|_, ()| Ok(false))?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree::FieldValue;

    const FIXTURE_DISSECTOR: &str = r#"
        local proto = Proto("fixture", "Fixture Protocol")
        local f_kind   = ProtoField.uint8("fixture.kind", "Kind")
        local f_name   = ProtoField.string("fixture.name", "Name")
        local f_marker = ProtoField.uint16("fixture.marker", "Marker")
        proto.fields = { f_kind, f_name, f_marker }

        function proto.dissector(tvb, pinfo, tree)
            local subtree = tree:add(proto, tvb(0), "Fixture Message")
            subtree:add(f_kind, tvb(0, 1))
            subtree:add(f_name, tvb(1, 4):raw())
            subtree:add_le(f_marker, tvb(5, 2))
            pinfo.cols.protocol = "FIXTURE"
            pinfo.cols.info = "hello"
            return tvb:len()
        end

        local ok, table = pcall(DissectorTable.get, "tls.port")
        if ok and table then
            table:add(4242, proto)
        end
    "#;

    #[test]
    fn loads_plugin_and_registers_port() {
        let engine = LuaEngine::new().unwrap();
        engine
            .load_plugin_str(FIXTURE_DISSECTOR, "fixture.lua")
            .unwrap();
        assert!(engine.has_dissector_for_port(4242));
        assert!(!engine.has_dissector_for_port(9999));
    }

    #[test]
    fn dissects_and_records_fields_in_order() {
        let engine = LuaEngine::new().unwrap();
        engine
            .load_plugin_str(FIXTURE_DISSECTOR, "fixture.lua")
            .unwrap();

        // kind=7 (1 byte), name="ABCD" (4 bytes), marker=0x0102 little-endian (2 bytes)
        let plaintext = std::rc::Rc::new(vec![7u8, b'A', b'B', b'C', b'D', 0x02, 0x01]);
        let (result, consumed) = engine
            .dissect(4242, plaintext)
            .unwrap()
            .expect("dissector should be found");

        // The dissector wraps its fields in its own subtree (`tree:add(proto, tvb(0), ...)`), so
        // the top level holds exactly one nested "fixture" entry -- not the three leaf fields
        // directly (see `tree.rs`'s nested-`TreeItem` support: a subtree genuinely nests now,
        // matching real Wireshark, rather than flattening into the parent).
        assert_eq!(result.entries.len(), 1);
        assert_eq!(result.entries[0].0, "fixture");
        assert!(matches!(result.entries[0].1, FieldValue::Tree(_)));

        // `values_for` recurses into nested subtrees regardless of depth -- this is also what
        // real `-T ek` field selection needs, and it's the same mechanism used everywhere else.
        assert_eq!(result.values_for("fixture.kind"), vec![FieldValue::UInt(7)]);
        assert_eq!(
            result.values_for("fixture.name"),
            vec![FieldValue::Str("ABCD".to_string())]
        );
        assert_eq!(
            result.values_for("fixture.marker"),
            vec![FieldValue::UInt(0x0102)]
        );
        assert_eq!(result.protocol.as_deref(), Some("FIXTURE"));
        assert_eq!(result.info.as_deref(), Some("hello"));
        assert_eq!(
            consumed, 7,
            "dissector's returned byte count should be reported back"
        );
    }

    #[test]
    fn partial_consumption_is_reported_for_cross_record_tail_buffering() {
        let engine = LuaEngine::new().unwrap();
        let partial = r#"
            local proto = Proto("partial", "Partial")
            local f = ProtoField.string("partial.msg", "Msg")
            proto.fields = { f }
            function proto.dissector(tvb, pinfo, tree)
                -- only ever claims to consume the first 3 bytes, mirroring a dissector that
                -- found one complete message and left an incomplete tail for the next record.
                tree:add(f, "consumed-3")
                return 3
            end
            DissectorTable.get("tls.port"):add(7777, proto)
        "#;
        engine.load_plugin_str(partial, "partial.lua").unwrap();
        let (_, consumed) = engine
            .dissect(7777, std::rc::Rc::new(vec![1, 2, 3, 4, 5]))
            .unwrap()
            .unwrap();
        assert_eq!(consumed, 3);
    }

    #[test]
    fn unregistered_port_returns_none() {
        let engine = LuaEngine::new().unwrap();
        engine
            .load_plugin_str(FIXTURE_DISSECTOR, "fixture.lua")
            .unwrap();
        assert!(
            engine
                .dissect(9999, std::rc::Rc::new(vec![1, 2, 3]))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn two_plugins_on_different_ports_coexist() {
        let engine = LuaEngine::new().unwrap();
        engine
            .load_plugin_str(FIXTURE_DISSECTOR, "fixture.lua")
            .unwrap();
        let second = r#"
            local proto2 = Proto("fixture2", "Fixture 2")
            local f = ProtoField.string("fixture2.msg", "Msg")
            proto2.fields = { f }
            function proto2.dissector(tvb, pinfo, tree)
                tree:add(f, tvb(0):raw())
                return tvb:len()
            end
            DissectorTable.get("tls.port"):add(5555, proto2)
        "#;
        engine.load_plugin_str(second, "fixture2.lua").unwrap();

        assert!(engine.has_dissector_for_port(4242));
        assert!(engine.has_dissector_for_port(5555));

        let (r1, _) = engine
            .dissect(
                4242,
                std::rc::Rc::new(vec![1, b'W', b'X', b'Y', b'Z', 0, 0]),
            )
            .unwrap()
            .unwrap();
        assert_eq!(r1.values_for("fixture.kind"), vec![FieldValue::UInt(1)]);

        let (r2, _) = engine
            .dissect(5555, std::rc::Rc::new(b"hi".to_vec()))
            .unwrap()
            .unwrap();
        assert_eq!(
            r2.entries,
            vec![(
                "fixture2.msg".to_string(),
                FieldValue::Str("hi".to_string())
            )]
        );
    }

    #[test]
    fn gui_enabled_is_always_false() {
        let engine = LuaEngine::new().unwrap();
        engine
            .load_plugin_str("assert(gui_enabled() == false)", "check.lua")
            .unwrap();
    }

    /// Regression test for a real bug caught while verifying against real production pcaps: a
    /// dissector that receives an already-sliced `TvbRange` (not the top-level `Tvb`) as its own
    /// `tvb` parameter, and slices it AGAIN internally -- exactly the shape of a real Wireshark
    /// Lua dissector's `read_varint(tvb, pos)` being invoked from
    /// `dissect_protobuf_fields(body_tvb, ...)`, where `body_tvb` is itself `tvb(p, body_len)`.
    /// `TvbRange` initially had no `__call` metamethod at all (only `Tvb` did), so this failed
    /// with "attempt to call a TvbRange value" against real traffic from that dissector despite
    /// every existing fixture test (which only ever sliced the top-level Tvb once) passing.
    #[test]
    fn tvbrange_supports_further_sub_slicing() {
        let engine = LuaEngine::new().unwrap();
        let nested = r#"
            local proto = Proto("nested", "Nested")
            local f = ProtoField.uint8("nested.val", "Val")
            proto.fields = { f }

            local function inner(sub_tvb)
                -- sub_tvb is already a TvbRange (sliced from the top-level tvb below), and this
                -- slices it AGAIN, relative to sub_tvb's own start -- exactly what read_varint
                -- does with the tvb parameter it's handed.
                return sub_tvb(1, 1)
            end

            function proto.dissector(tvb, pinfo, tree)
                local body = tvb(2, 4)     -- first slice: bytes [2,6) of the top-level buffer
                local nested_range = inner(body) -- second slice: byte [1,2) of THAT range = absolute byte 3
                tree:add(f, nested_range)
                return tvb:len()
            end
            DissectorTable.get("tls.port"):add(3333, proto)
        "#;
        engine.load_plugin_str(nested, "nested.lua").unwrap();

        let plaintext = std::rc::Rc::new(vec![0xAA, 0xBB, 10, 20, 30, 40, 0xCC]);
        let (result, _) = engine
            .dissect(3333, plaintext)
            .unwrap()
            .expect("dissector should be found");

        // body = bytes[2..6] = [10,20,30,40]; inner(body) = body(1,1) = byte[1] of body = 20.
        assert_eq!(
            result.entries,
            vec![("nested.val".to_string(), FieldValue::UInt(20))]
        );
    }

    /// A `tree:add(proto, tvbrange, label)` subtree genuinely nests -- fields added on the handle
    /// it returns land inside that subtree, not flattened into the parent -- matching real
    /// Wireshark's own Lua API (not the shim's earlier, deliberately-simplified flat accumulator).
    #[test]
    fn subtree_creation_genuinely_nests() {
        let engine = LuaEngine::new().unwrap();
        let nested = r#"
            local proto = Proto("outer", "Outer")
            local f_a = ProtoField.uint8("outer.a", "A")
            local f_b = ProtoField.uint8("outer.b", "B")
            proto.fields = { f_a, f_b }
            function proto.dissector(tvb, pinfo, tree)
                tree:add(f_a, tvb(0, 1))
                local sub = tree:add(proto, tvb(1, 1), "Outer Subtree")
                sub:add(f_b, tvb(1, 1))
                return tvb:len()
            end
            DissectorTable.get("tls.port"):add(2222, proto)
        "#;
        engine.load_plugin_str(nested, "nested.lua").unwrap();

        let (result, _) = engine
            .dissect(2222, std::rc::Rc::new(vec![10, 20]))
            .unwrap()
            .unwrap();

        // Top level: the direct `f_a` add, plus one nested "outer" subtree -- not three flat
        // entries.
        assert_eq!(result.entries.len(), 2);
        assert_eq!(
            result.entries[0],
            ("outer.a".to_string(), FieldValue::UInt(10))
        );
        assert_eq!(result.entries[1].0, "outer");
        let FieldValue::Tree(child) = &result.entries[1].1 else {
            panic!("expected a nested Tree entry");
        };
        assert_eq!(
            child.borrow().entries,
            vec![("outer.b".to_string(), FieldValue::UInt(20))]
        );

        // `values_for` finds the nested field regardless of depth.
        assert_eq!(result.values_for("outer.a"), vec![FieldValue::UInt(10)]);
        assert_eq!(result.values_for("outer.b"), vec![FieldValue::UInt(20)]);
    }

    /// Repeated `tree:add(proto, ...)` calls under the same parent (e.g. N occurrences of one
    /// message type dissected from a single combined buffer) produce N separate `Tree` entries
    /// under that same name -- the same repeated-field-as-array convention already used for plain
    /// leaf fields, not a new concept.
    #[test]
    fn repeated_subtree_creation_produces_multiple_tree_entries() {
        let engine = LuaEngine::new().unwrap();
        let looping = r#"
            local proto = Proto("msg", "Message")
            local f_val = ProtoField.uint8("msg.val", "Val")
            proto.fields = { f_val }
            function proto.dissector(tvb, pinfo, tree)
                local offset = 0
                while offset < tvb:len() do
                    local sub = tree:add(proto, tvb(offset, 1), "Message")
                    sub:add(f_val, tvb(offset, 1))
                    offset = offset + 1
                end
                return tvb:len()
            end
            DissectorTable.get("tls.port"):add(1111, proto)
        "#;
        engine.load_plugin_str(looping, "looping.lua").unwrap();

        let (result, _) = engine
            .dissect(1111, std::rc::Rc::new(vec![10, 20, 30]))
            .unwrap()
            .unwrap();

        assert_eq!(result.entries.len(), 3, "one Tree entry per loop iteration");
        for (name, value) in &result.entries {
            assert_eq!(name, "msg");
            assert!(matches!(value, FieldValue::Tree(_)));
        }
        // Flattened across all three messages, in encounter order -- exactly how real tshark's
        // own `-T ek` already flattens repeated nested-subtree fields.
        assert_eq!(
            result.values_for("msg.val"),
            vec![
                FieldValue::UInt(10),
                FieldValue::UInt(20),
                FieldValue::UInt(30)
            ]
        );
    }
}
