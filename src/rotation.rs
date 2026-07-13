//! Output rotation + gzip compression, matching `editcap`'s CLI conventions (`-c <count>` /
//! `-i <seconds>`, mutually exclusive; `--compress gzip`) so `tlscap`'s own output stage has the
//! same ergonomics as a typical `tcpdump | editcap` main-capture pipeline running alongside it.
//! Owns its own rotation entirely internally -- unlike the earlier tshark-based design, there's
//! no external `split --filter=gzip` stage: nothing uncompressed ever touches disk.

use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use flate2::Compression;
use flate2::write::GzEncoder;

/// Mutually exclusive with `RotateBy::Seconds`, matching `editcap -c`/`-i`'s own mutual
/// exclusivity (no combined "whichever comes first" mode).
#[derive(Clone, Copy, Debug)]
pub enum RotateBy {
    /// Rotate after this many messages (editcap's `-c <count>`, counted in packets there; counted
    /// in dissected messages here, since that's `tlscap`'s natural output unit).
    Count(u64),
    /// Rotate after this many seconds of wall-clock time (editcap's `-i <seconds>`).
    Seconds(Duration),
    /// No rotation at all -- a single, never-rotated output stream. Not an `editcap` mode (it
    /// always rotates), but a sensible default for `-w -` (stdout) usage where rotation doesn't
    /// make sense.
    Never,
}

/// Writes NDJSON lines into a sequence of gzip-compressed chunks named
/// `<prefix>_<NNNNNN>_<YYYYMMDDHHMMSS>.gz`, mirroring `editcap`'s own chunk-naming convention
/// (`_NNNNN_YYYYMMDDHHMMSS` inserted before the file extension) closely enough that a glob-based
/// upload/cleanup script watching both pipelines' output needs no changes beyond the file
/// extension.
pub struct RotatingGzWriter {
    prefix: PathBuf,
    rotate_by: RotateBy,
    current: Option<CurrentChunk>,
    chunk_counter: u64,
}

struct CurrentChunk {
    encoder: GzEncoder<File>,
    path: PathBuf,
    messages_written: u64,
    opened_at: Instant,
}

impl RotatingGzWriter {
    pub fn new(prefix: PathBuf, rotate_by: RotateBy) -> Self {
        RotatingGzWriter {
            prefix,
            rotate_by,
            current: None,
            chunk_counter: 0,
        }
    }

    /// Writes one already-serialized message (its raw NDJSON bytes) into the current chunk,
    /// opening a new one first if none is open yet or the rotation threshold was crossed by the
    /// *previous* write. Rotation is checked before writing, not after, so a chunk never exceeds
    /// its threshold by more than one message/interval-check's worth of latency.
    pub fn write_message(&mut self, data: &[u8]) -> io::Result<()> {
        self.rotate_if_needed()?;
        let chunk = self
            .current
            .get_or_insert_with(|| unreachable!("rotate_if_needed always opens a chunk"));
        chunk.encoder.write_all(data)?;
        chunk.messages_written += 1;
        Ok(())
    }

    fn rotate_if_needed(&mut self) -> io::Result<()> {
        let should_rotate = match (&self.current, self.rotate_by) {
            (None, _) => true,
            (Some(_), RotateBy::Never) => false,
            (Some(c), RotateBy::Count(n)) => c.messages_written >= n,
            (Some(c), RotateBy::Seconds(d)) => c.opened_at.elapsed() >= d,
        };
        if should_rotate {
            self.finish_current()?;
            self.open_new()?;
        }
        Ok(())
    }

    fn open_new(&mut self) -> io::Result<()> {
        self.chunk_counter += 1;
        let path = chunk_path(&self.prefix, self.chunk_counter, now_stamp());
        let file = File::create(&path)?;
        let encoder = GzEncoder::new(file, Compression::default());
        self.current = Some(CurrentChunk {
            encoder,
            path,
            messages_written: 0,
            opened_at: Instant::now(),
        });
        Ok(())
    }

    /// Finalizes (flushes + closes) whatever chunk is currently open, if any. Idempotent -- safe
    /// to call even if nothing is open. `main.rs` calls this once on clean EOF-driven shutdown, so
    /// the last chunk is always a complete, valid gzip member, never truncated mid-write.
    pub fn finish_current(&mut self) -> io::Result<()> {
        if let Some(chunk) = self.current.take() {
            chunk.encoder.finish()?;
            eprintln!(
                "tlscap: finalized output chunk {} ({} message(s))",
                chunk.path.display(),
                chunk.messages_written
            );
        }
        Ok(())
    }
}

impl Drop for RotatingGzWriter {
    fn drop(&mut self) {
        let _ = self.finish_current();
    }
}

fn chunk_path(prefix: &Path, counter: u64, stamp: String) -> PathBuf {
    let mut name = prefix
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(format!("_{counter:06}_{stamp}.gz"));
    match prefix.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir.join(name),
        _ => PathBuf::from(name),
    }
}

fn now_stamp() -> String {
    let now = chrono::Local::now();
    now.format("%Y%m%d%H%M%S").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::read::GzDecoder;
    use std::io::Read;

    fn temp_prefix(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "tlscap-rotation-test-{name}-{}",
            std::process::id()
        ))
    }

    fn read_gz(path: &Path) -> String {
        let mut decoder = GzDecoder::new(File::open(path).unwrap());
        let mut out = String::new();
        decoder.read_to_string(&mut out).unwrap();
        out
    }

    #[test]
    fn writes_into_a_single_chunk_when_never_rotating() {
        let prefix = temp_prefix("never");
        let mut w = RotatingGzWriter::new(prefix.clone(), RotateBy::Never);
        w.write_message(b"line1\n").unwrap();
        w.write_message(b"line2\n").unwrap();
        let path = w.current.as_ref().unwrap().path.clone();
        w.finish_current().unwrap();

        assert_eq!(read_gz(&path), "line1\nline2\n");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn rotates_by_count() {
        let prefix = temp_prefix("count");
        let mut w = RotatingGzWriter::new(prefix.clone(), RotateBy::Count(2));
        w.write_message(b"a\n").unwrap();
        w.write_message(b"b\n").unwrap();
        let first_path = w.current.as_ref().unwrap().path.clone();
        w.write_message(b"c\n").unwrap(); // should trigger rotation before writing
        let second_path = w.current.as_ref().unwrap().path.clone();
        w.finish_current().unwrap();

        assert_ne!(first_path, second_path);
        assert_eq!(read_gz(&first_path), "a\nb\n");
        assert_eq!(read_gz(&second_path), "c\n");
        std::fs::remove_file(&first_path).ok();
        std::fs::remove_file(&second_path).ok();
    }

    #[test]
    fn rotates_by_seconds() {
        let prefix = temp_prefix("seconds");
        let mut w =
            RotatingGzWriter::new(prefix.clone(), RotateBy::Seconds(Duration::from_millis(10)));
        w.write_message(b"a\n").unwrap();
        let first_path = w.current.as_ref().unwrap().path.clone();
        std::thread::sleep(Duration::from_millis(20));
        w.write_message(b"b\n").unwrap();
        let second_path = w.current.as_ref().unwrap().path.clone();
        w.finish_current().unwrap();

        assert_ne!(first_path, second_path);
        std::fs::remove_file(&first_path).ok();
        std::fs::remove_file(&second_path).ok();
    }

    #[test]
    fn chunk_filename_matches_editcap_style_counter_and_timestamp() {
        let prefix = temp_prefix("naming");
        let mut w = RotatingGzWriter::new(prefix.clone(), RotateBy::Never);
        w.write_message(b"x\n").unwrap();
        let path = w.current.as_ref().unwrap().path.clone();
        w.finish_current().unwrap();

        let name = path.file_name().unwrap().to_str().unwrap();
        assert!(name.starts_with(&format!(
            "{}_000001_",
            prefix.file_name().unwrap().to_str().unwrap()
        )));
        assert!(name.ends_with(".gz"));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn drop_finalizes_the_open_chunk_cleanly() {
        let prefix = temp_prefix("drop");
        let path;
        {
            let mut w = RotatingGzWriter::new(prefix.clone(), RotateBy::Never);
            w.write_message(b"finalized on drop\n").unwrap();
            path = w.current.as_ref().unwrap().path.clone();
            // w drops here without an explicit finish_current() call
        }
        assert_eq!(read_gz(&path), "finalized on drop\n");
        std::fs::remove_file(&path).ok();
    }
}
