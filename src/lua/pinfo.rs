//! `pinfo.cols.protocol` / `pinfo.cols.info` -- the only `pinfo` surface the real Wireshark Lua
//! dissector(s) this shim was built against actually use.

use std::cell::RefCell;
use std::rc::Rc;

use mlua::{Lua, Result as LuaResult, Table, UserData, UserDataFields};

use super::tree::FrameFields;

#[derive(Clone)]
pub struct Cols {
    pub fields: Rc<RefCell<FrameFields>>,
}

impl UserData for Cols {
    fn add_fields<F: UserDataFields<Self>>(fields: &mut F) {
        fields.add_field_method_get("protocol", |_, this| {
            Ok(this.fields.borrow().protocol.clone().unwrap_or_default())
        });
        fields.add_field_method_set("protocol", |_, this, v: String| {
            this.fields.borrow_mut().protocol = Some(v);
            Ok(())
        });
        fields.add_field_method_get("info", |_, this| {
            Ok(this.fields.borrow().info.clone().unwrap_or_default())
        });
        fields.add_field_method_set("info", |_, this, v: String| {
            this.fields.borrow_mut().info = Some(v);
            Ok(())
        });
    }
}

pub fn new_pinfo(lua: &Lua, fields: Rc<RefCell<FrameFields>>) -> LuaResult<Table> {
    let pinfo = lua.create_table()?;
    pinfo.set("cols", Cols { fields })?;
    Ok(pinfo)
}
