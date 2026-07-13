//! `DissectorTable` -- the port -> Lua-dissector registry. This is what makes the shim genuinely
//! pluggable rather than hardcoded to any one protocol: any Lua plugin calling
//! `DissectorTable.get("tls.port")` then `:add(port, proto)` registers itself the same way a real
//! Wireshark Lua dissector does, with zero `tlscap`-side special-casing for any particular
//! protocol.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use mlua::{Error as LuaError, Lua, Result as LuaResult, Table, UserData, UserDataMethods};

/// Shared, mutable port -> registered-Proto-table map. "tls.port" and the legacy "ssl.port" name
/// both resolve to the same underlying registry, matching real Wireshark's aliasing and the
/// `pcall(DissectorTable.get, "tls.port")` / `"ssl.port"` fallback pattern real-world Wireshark
/// Lua dissectors commonly use.
pub type Registry = Rc<RefCell<HashMap<u16, Table>>>;

#[derive(Clone)]
pub struct DissectorTableHandle {
    pub registry: Registry,
}

impl UserData for DissectorTableHandle {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        methods.add_method("add", |_, this, (port, proto): (u16, Table)| {
            this.registry.borrow_mut().insert(port, proto);
            Ok(())
        });
    }
}

pub fn install(lua: &Lua, globals: &Table, tls_port_registry: Registry) -> LuaResult<()> {
    let dissector_table = lua.create_table()?;
    let registry_for_get = tls_port_registry;
    dissector_table.set(
        "get",
        lua.create_function(move |_, name: String| match name.as_str() {
            "tls.port" | "ssl.port" => Ok(DissectorTableHandle { registry: registry_for_get.clone() }),
            other => Err(LuaError::RuntimeError(format!(
                "DissectorTable.get: unsupported table \"{}\" (tlscap only supports tls.port/ssl.port in v1)",
                other
            ))),
        })?,
    )?;
    globals.set("DissectorTable", dissector_table)?;
    Ok(())
}
