//! Keeps the orchestrator's view of the keylog fresh during a long-running, never-restarted
//! process. A keylog loaded once at startup and never revisited would never see secrets for TLS
//! connections that started after tlscap did -- jSSLKeyLog keeps appending to the same file for
//! as long as the target JVM runs, independently of tlscap's own lifetime.
//!
//! Adapted from `~/gitrepos/pcapzip/src/keylog_source.rs` (see `tls13.rs`'s header comment),
//! trimmed down: no `accumulated`-vs-`current`/flush-watermark bookkeeping (that existed purely
//! to embed newly-seen secrets into `.pcapz` output segments, which tlscap doesn't produce) and
//! no `--prune-keylog` support (tlscap's connection eviction is FIN/RST-driven at the orchestrator
//! layer, not keylog-file-driven). Reloading is throttled to a configurable interval (a plain
//! wall-clock timer), but a decrypt attempt coming back "no key" also triggers an immediate
//! out-of-cycle check: a cheap `stat()` first, only actually re-reading and re-parsing if the
//! file's mtime/size show it genuinely changed since the last read.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use crate::keylog::Keylog;

pub struct KeylogSource {
    path: Option<PathBuf>,
    reload_interval: Duration,
    last_reload_attempt: Instant,
    last_seen_mtime: Option<SystemTime>,
    /// Compared alongside mtime: some filesystems have coarse mtime resolution (as little as one
    /// second on some Linux setups), so two writes close together can share an identical mtime
    /// even though the content genuinely changed. Not foolproof either (a same-size rewrite could
    /// still be missed), but `poll()`'s interval-based reload is the actual correctness backstop
    /// -- this only affects how quickly a fresh secret gets noticed.
    last_seen_len: Option<u64>,
    current: Keylog,
}

impl KeylogSource {
    pub fn open(path: PathBuf, reload_interval: Duration) -> io::Result<Self> {
        let (current, last_seen_mtime, last_seen_len) = match fs::read_to_string(&path) {
            Ok(text) => {
                let (mtime, len) = stat_signature(&path);
                (Keylog::parse(&text), mtime, len)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                // jSSLKeyLog creates this file lazily, on the target JVM's first TLS handshake --
                // tlscap starting before that happens is a normal startup race, not a fatal
                // misconfiguration. Start with an empty keylog; `poll()`/`poll_after_miss()` pick
                // the file up the moment it appears, via the exact same stat()-based hot-reload
                // path already used for secrets appended to an already-open keylog (see
                // `reload_if_changed`'s doc comment for the matching "transient error, keep going"
                // reasoning on the read side).
                (Keylog::parse(""), None, None)
            }
            Err(e) => return Err(e),
        };
        Ok(KeylogSource {
            path: Some(path),
            reload_interval,
            last_reload_attempt: Instant::now(),
            last_seen_mtime,
            last_seen_len,
            current,
        })
    }

    /// Wraps an already-parsed keylog with no file backing -- reload becomes a permanent no-op.
    /// For tests, or a one-shot static keylog.
    pub fn from_parsed(keylog: Keylog) -> Self {
        KeylogSource {
            path: None,
            reload_interval: Duration::MAX,
            last_reload_attempt: Instant::now(),
            last_seen_mtime: None,
            last_seen_len: None,
            current: keylog,
        }
    }

    /// Call before every decrypt attempt. Throttled: a cheap no-op unless `reload_interval` has
    /// elapsed since the last attempt (successful or not).
    pub fn poll(&mut self) {
        if self.path.is_some() && self.last_reload_attempt.elapsed() >= self.reload_interval {
            self.reload_if_changed();
        }
    }

    /// Call after a decrypt attempt reports no key was available. Bypasses the interval throttle,
    /// but not the underlying work: only reloads if a `stat()` shows the file actually changed.
    pub fn poll_after_miss(&mut self) {
        let Some(path) = self.path.clone() else {
            return;
        };
        let (mtime, len) = stat_signature(&path);
        if mtime != self.last_seen_mtime || len != self.last_seen_len {
            self.reload_if_changed();
        }
    }

    pub fn current(&self) -> &Keylog {
        &self.current
    }

    fn reload_if_changed(&mut self) {
        let Some(path) = &self.path else { return };
        self.last_reload_attempt = Instant::now();

        let Ok(text) = fs::read_to_string(path) else {
            // Transient read error (e.g. jSSLKeyLog mid-write) -- keep using the last-known-good
            // keylog rather than losing decrypt capability over it; the next poll retries.
            return;
        };
        (self.last_seen_mtime, self.last_seen_len) = stat_signature(path);
        self.current = Keylog::parse(&text);
    }
}

fn stat_signature(path: &Path) -> (Option<SystemTime>, Option<u64>) {
    let Ok(meta) = fs::metadata(path) else {
        return (None, None);
    };
    (meta.modified().ok(), Some(meta.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_keylog_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "tlscap-keylog-source-test-{name}-{}",
            std::process::id()
        ))
    }

    #[test]
    fn poll_reloads_after_the_interval_elapses() {
        let path = temp_keylog_path("poll-reload");
        fs::write(&path, "").unwrap();
        let mut source = KeylogSource::open(path.clone(), Duration::from_millis(0)).unwrap();

        fs::write(&path, "CLIENT_RANDOM aa bb\r\n").unwrap();
        source.poll();
        fs::remove_file(&path).ok();

        assert_eq!(
            source.current().entry_count,
            1,
            "poll() with an elapsed interval must pick up the newly written content"
        );
    }

    #[test]
    fn poll_does_not_reload_before_the_interval_elapses() {
        let path = temp_keylog_path("poll-throttle");
        fs::write(&path, "").unwrap();
        let mut source = KeylogSource::open(path.clone(), Duration::from_secs(3600)).unwrap();

        fs::write(&path, "CLIENT_RANDOM aa bb\r\n").unwrap();
        source.poll();
        fs::remove_file(&path).ok();

        assert_eq!(
            source.current().entry_count,
            0,
            "poll() must not reload before the interval elapses"
        );
    }

    #[test]
    fn poll_after_miss_reloads_immediately_when_the_file_changed() {
        let path = temp_keylog_path("miss-changed");
        fs::write(&path, "").unwrap();
        let mut source = KeylogSource::open(path.clone(), Duration::from_secs(3600)).unwrap();

        std::thread::sleep(Duration::from_millis(20));
        fs::write(&path, "CLIENT_RANDOM aa bb\r\n").unwrap();
        source.poll_after_miss();
        fs::remove_file(&path).ok();

        assert_eq!(
            source.current().entry_count,
            1,
            "poll_after_miss() must reload immediately when the file's mtime changed, bypassing the interval"
        );
    }

    #[test]
    fn poll_after_miss_is_a_no_op_when_the_file_did_not_change() {
        let path = temp_keylog_path("miss-unchanged");
        fs::write(&path, "").unwrap();
        let mut source = KeylogSource::open(path.clone(), Duration::from_secs(3600)).unwrap();

        source.poll_after_miss();
        fs::remove_file(&path).ok();

        assert_eq!(
            source.current().entry_count,
            0,
            "poll_after_miss() must not reload when the file hasn't changed"
        );
    }

    #[test]
    fn a_transient_read_error_keeps_the_last_known_good_keylog() {
        let path = temp_keylog_path("transient-error");
        fs::write(&path, "CLIENT_RANDOM aa bb\r\n").unwrap();
        let mut source = KeylogSource::open(path.clone(), Duration::from_millis(0)).unwrap();
        assert_eq!(source.current().entry_count, 1);

        fs::remove_file(&path).unwrap();
        source.poll();

        assert_eq!(
            source.current().entry_count,
            1,
            "a failed reload must not clear out the last-known-good keylog"
        );
    }

    #[test]
    fn open_tolerates_a_not_yet_existing_keylog_file() {
        // jSSLKeyLog creates the keylog lazily, on the target JVM's first TLS handshake -- tlscap
        // starting first (e.g. right after container start, before the app has made any outbound
        // TLS connection yet) must not be fatal.
        let path = temp_keylog_path("not-yet-created");
        fs::remove_file(&path).ok(); // guard against a stale file from a prior failed test run
        let mut source =
            KeylogSource::open(path.clone(), Duration::from_millis(0)).expect("must not error");
        assert_eq!(source.current().entry_count, 0);

        fs::write(&path, "CLIENT_RANDOM aa bb\r\n").unwrap();
        source.poll();
        fs::remove_file(&path).ok();

        assert_eq!(
            source.current().entry_count,
            1,
            "poll() must pick up the keylog once it's created, same as any other reload"
        );
    }

    #[test]
    fn from_parsed_never_reloads() {
        let path = temp_keylog_path("static-source");
        fs::write(&path, "").unwrap();

        let mut source = KeylogSource::from_parsed(Keylog::parse("CLIENT_RANDOM aa bb\r\n"));
        fs::write(&path, "CLIENT_RANDOM cc dd\r\nCLIENT_RANDOM ee ff\r\n").unwrap();
        source.poll();
        source.poll_after_miss();
        fs::remove_file(&path).ok();

        assert_eq!(
            source.current().entry_count,
            1,
            "a from_parsed() source must never reload, regardless of any file on disk"
        );
    }
}
