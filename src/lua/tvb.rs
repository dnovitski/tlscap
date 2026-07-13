//! `Tvb`/`TvbRange` -- the byte-slicing view a Lua dissector operates on.
//!
//! Unlike real Wireshark, there's only ever one `Tvb` per dissection call, wrapping exactly the
//! decrypted plaintext bytes handed to the plugin for that TLS record (or carried-over tail).

use std::ops::Range;
use std::rc::Rc;

use mlua::{Error as LuaError, MetaMethod, Result as LuaResult, UserData, UserDataMethods};

#[derive(Clone)]
pub struct Tvb {
    pub data: Rc<Vec<u8>>,
}

impl Tvb {
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            data: Rc::new(data),
        }
    }
}

impl UserData for Tvb {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        methods.add_method("len", |_, this, ()| Ok(this.data.len()));
        // tvb(offset, length) -- length defaults to "rest of buffer" when omitted.
        methods.add_meta_method(
            MetaMethod::Call,
            |_, this, (offset, length): (i64, Option<i64>)| {
                slice(&this.data, 0, this.data.len(), offset, length)
            },
        );
    }
}

/// Shared by both `Tvb`'s and `TvbRange`'s `__call` metamethod: real Wireshark's `TvbRange` also
/// supports being called to sub-slice further (e.g. a `dissect_protobuf_fields(tvb, ...)`-style
/// helper in a real Wireshark Lua dissector receives an already-sliced `TvbRange` as its own
/// `tvb` parameter, then calls `tvb(pos, 1)` on it -- offsets there are relative to the START of
/// that range, not the underlying buffer's absolute position). `base_start`/`base_len` describe
/// the calling object's own window into `data`; `offset`/`length` are relative to that window.
fn slice(
    data: &Rc<Vec<u8>>,
    base_start: usize,
    base_len: usize,
    offset: i64,
    length: Option<i64>,
) -> LuaResult<TvbRange> {
    let offset = offset as usize;
    let avail = base_len.saturating_sub(offset);
    let len = length.map(|l| l as usize).unwrap_or(avail);
    if offset + len > base_len {
        return Err(LuaError::RuntimeError(format!(
            "Tvb/TvbRange: range {}..{} out of bounds (len {})",
            offset,
            offset + len,
            base_len
        )));
    }
    let start = base_start + offset;
    Ok(TvbRange {
        data: data.clone(),
        range: start..(start + len),
    })
}

#[derive(Clone)]
pub struct TvbRange {
    pub data: Rc<Vec<u8>>,
    pub range: Range<usize>,
}

impl TvbRange {
    pub fn bytes(&self) -> &[u8] {
        &self.data[self.range.clone()]
    }

    pub fn uint_be(&self) -> LuaResult<u64> {
        parse_uint(self.bytes(), false)
    }

    pub fn uint_le(&self) -> LuaResult<u64> {
        parse_uint(self.bytes(), true)
    }
}

fn parse_uint(bytes: &[u8], little_endian: bool) -> LuaResult<u64> {
    if bytes.is_empty() || bytes.len() > 8 {
        return Err(LuaError::RuntimeError(format!(
            "TvbRange: cannot parse {}-byte range as an integer",
            bytes.len()
        )));
    }
    let mut buf = [0u8; 8];
    if little_endian {
        buf[..bytes.len()].copy_from_slice(bytes);
        Ok(u64::from_le_bytes(buf))
    } else {
        buf[8 - bytes.len()..].copy_from_slice(bytes);
        Ok(u64::from_be_bytes(buf))
    }
}

impl UserData for TvbRange {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        methods.add_method("len", |_, this, ()| Ok(this.range.len()));
        methods.add_method("uint", |_, this, ()| this.uint_be());
        methods.add_method("le_uint", |_, this, ()| this.uint_le());
        methods.add_method("uint64", |_, this, ()| this.uint_be());
        methods.add_method("le_uint64", |_, this, ()| this.uint_le());
        methods.add_method("raw", |lua, this, ()| lua.create_string(this.bytes()));
        // TvbRange(offset, [length]) -- sub-slices further, relative to THIS range's own start,
        // not the underlying buffer's absolute position. Missing this was a real bug caught
        // against real production data: a real Wireshark Lua dissector's read_varint()/
        // dissect_protobuf_fields()-style helpers are called with an already-sliced TvbRange in
        // some call paths (e.g. a protobuf message body) and slice it again internally
        // (`tvb(pos + i, 1)`) exactly the same way it slices the top-level Tvb -- real
        // Wireshark's TvbRange supports this, so the shim must too.
        methods.add_meta_method(
            MetaMethod::Call,
            |_, this, (offset, length): (i64, Option<i64>)| {
                slice(
                    &this.data,
                    this.range.start,
                    this.range.len(),
                    offset,
                    length,
                )
            },
        );
    }
}
