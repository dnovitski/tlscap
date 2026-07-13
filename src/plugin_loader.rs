//! Loads Wireshark Lua dissector plugins into a `LuaEngine`, mirroring real Wireshark's own two
//! loading conventions: a scanned plugins directory (default `/usr/lib/tlscap/plugins/*.lua`) and
//! a repeatable `--lua-script <path>` flag (tshark's own `-X lua_script:<path>` equivalent) for
//! ad-hoc loading outside the directory convention. Both feed the same shared `LuaEngine`
//! (hence the same `DissectorTable` registry), so plugins loaded either way coexist.

use std::path::{Path, PathBuf};

use crate::lua::LuaEngine;

#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error("reading plugin directory {0}: {1}")]
    ReadDir(PathBuf, std::io::Error),
    #[error("loading plugin {0}: {1}")]
    Plugin(PathBuf, mlua::Error),
}

/// Loads every `*.lua` file directly inside `dir` (non-recursive, matching Wireshark's own
/// plugins-directory scanning) into `engine`, in a deterministic (sorted-by-filename) order so
/// load order -- and hence which plugin "wins" if two ever registered the same port, an error
/// condition but one worth being deterministic about -- doesn't depend on filesystem iteration
/// order. A missing directory is not an error (the default path may simply not exist if no
/// plugins were installed into the image); only a directory that exists but can't be read is.
pub fn load_directory(engine: &LuaEngine, dir: &Path) -> Result<usize, LoadError> {
    if !dir.exists() {
        return Ok(0);
    }
    let mut paths: Vec<PathBuf> = std::fs::read_dir(dir)
        .map_err(|e| LoadError::ReadDir(dir.to_path_buf(), e))?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|p| {
            p.extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("lua"))
        })
        .collect();
    paths.sort();

    for path in &paths {
        engine
            .load_plugin_file(path)
            .map_err(|e| LoadError::Plugin(path.clone(), e))?;
    }
    Ok(paths.len())
}

/// Loads an explicit, repeatable `--lua-script <path>` list, in the order given on the command
/// line.
pub fn load_scripts(engine: &LuaEngine, paths: &[PathBuf]) -> Result<(), LoadError> {
    for path in paths {
        engine
            .load_plugin_file(path)
            .map_err(|e| LoadError::Plugin(path.clone(), e))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tlscap-plugin-loader-test-{name}-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    const TRIVIAL_PLUGIN: &str = r#"
        local proto = Proto("t", "T")
        local f = ProtoField.string("t.msg", "Msg")
        proto.fields = { f }
        function proto.dissector(tvb, pinfo, tree)
            tree:add(f, tvb(0):raw())
            return tvb:len()
        end
        DissectorTable.get("tls.port"):add(1111, proto)
    "#;

    #[test]
    fn loads_all_lua_files_in_a_directory() {
        let dir = temp_dir("basic");
        std::fs::write(dir.join("a.lua"), TRIVIAL_PLUGIN).unwrap();
        std::fs::write(dir.join("not-lua.txt"), "ignored").unwrap();

        let engine = LuaEngine::new().unwrap();
        let count = load_directory(&engine, &dir).unwrap();
        assert_eq!(count, 1);
        assert!(engine.has_dissector_for_port(1111));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn missing_directory_is_not_an_error() {
        let engine = LuaEngine::new().unwrap();
        let dir = std::env::temp_dir().join("tlscap-this-directory-does-not-exist-hopefully");
        assert_eq!(load_directory(&engine, &dir).unwrap(), 0);
    }

    #[test]
    fn load_scripts_loads_explicit_paths_in_order() {
        let dir = temp_dir("scripts");
        let path = dir.join("explicit.lua");
        std::fs::write(&path, TRIVIAL_PLUGIN).unwrap();

        let engine = LuaEngine::new().unwrap();
        load_scripts(&engine, &[path]).unwrap();
        assert!(engine.has_dissector_for_port(1111));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn directory_and_explicit_scripts_share_the_same_engine() {
        // Two INDEPENDENT locations -- a plugins directory and a separately-placed ad-hoc script
        // -- both feeding the same LuaEngine, proving --lua-script isn't a separate/isolated VM.
        let plugins_dir = temp_dir("shared-dir");
        std::fs::write(plugins_dir.join("dir_plugin.lua"), TRIVIAL_PLUGIN).unwrap();

        let scripts_dir = temp_dir("shared-scripts");
        let second = r#"
            local proto2 = Proto("t2", "T2")
            local f2 = ProtoField.string("t2.msg", "Msg")
            proto2.fields = { f2 }
            function proto2.dissector(tvb, pinfo, tree)
                tree:add(f2, tvb(0):raw())
                return tvb:len()
            end
            DissectorTable.get("tls.port"):add(2222, proto2)
        "#;
        let explicit_path = scripts_dir.join("explicit_plugin.lua");
        std::fs::write(&explicit_path, second).unwrap();

        let engine = LuaEngine::new().unwrap();
        load_directory(&engine, &plugins_dir).unwrap();
        load_scripts(&engine, &[explicit_path]).unwrap();
        assert!(
            engine.has_dissector_for_port(1111),
            "plugin loaded from the directory scan must be registered"
        );
        assert!(
            engine.has_dissector_for_port(2222),
            "plugin loaded via an explicit --lua-script path must be registered on the SAME engine"
        );

        std::fs::remove_dir_all(&plugins_dir).ok();
        std::fs::remove_dir_all(&scripts_dir).ok();
    }
}
