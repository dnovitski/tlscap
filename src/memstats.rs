//! Minimal, dependency-free process memory introspection (Linux only -- fine for this project's
//! only deployment target, an Alpine/musl container). Reads `/proc/self/status` rather than
//! pulling in a crate like `sysinfo` for one integer.

use std::fs;

/// Current resident set size (RSS) in bytes -- the actual physical memory the kernel has charged
/// to this process, which is what an OOM-kill decision is based on (unlike virtual memory size).
/// Returns `None` if `/proc/self/status` is unavailable or unparseable (e.g. running on a
/// non-Linux host during local development) rather than failing -- this is diagnostic-only, never
/// load-bearing.
pub fn rss_bytes() -> Option<u64> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let kb: u64 = rest.split_whitespace().next()?.parse().ok()?;
            return Some(kb * 1024);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rss_bytes_returns_a_plausible_value_on_linux() {
        if cfg!(target_os = "linux") {
            let rss = rss_bytes().expect("must read /proc/self/status on Linux");
            assert!(rss > 0, "a running process must have nonzero RSS");
        }
    }
}
