//! End-to-end regression test: tlscap must run to completion and keep emitting
//! `--packet-log` output even when no `--keylog` is given at all. TLS decrypt is naturally
//! impossible without keys, but that must not stop per-frame packet-event visibility -- this
//! exercises the real CLI wiring (`Cli.keylog: Option<PathBuf>` -> `KeylogSource`), which the
//! library-level unit tests never touch.

use std::io::Write;
use std::process::{Command, Stdio};

use etherparse::PacketBuilder;

fn build_pcap_with_one_syn() -> Vec<u8> {
    let mut pcap = Vec::new();
    // Classic pcap global header, little-endian, LINKTYPE_ETHERNET (1).
    pcap.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
    pcap.extend_from_slice(&2u16.to_le_bytes());
    pcap.extend_from_slice(&4u16.to_le_bytes());
    pcap.extend_from_slice(&0i32.to_le_bytes());
    pcap.extend_from_slice(&0u32.to_le_bytes());
    pcap.extend_from_slice(&65535u32.to_le_bytes());
    pcap.extend_from_slice(&1u32.to_le_bytes());

    let builder = PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
        .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
        .tcp(51234, 9410, 1000, 65535)
        .syn();
    let mut frame = Vec::with_capacity(builder.size(0));
    builder.write(&mut frame, &[]).unwrap();

    pcap.extend_from_slice(&0u32.to_le_bytes()); // ts_sec
    pcap.extend_from_slice(&0u32.to_le_bytes()); // ts_usec
    pcap.extend_from_slice(&(frame.len() as u32).to_le_bytes()); // incl_len
    pcap.extend_from_slice(&(frame.len() as u32).to_le_bytes()); // orig_len
    pcap.extend_from_slice(&frame);
    pcap
}

#[test]
fn runs_and_emits_packet_log_without_a_keylog() {
    let dir = std::env::temp_dir().join(format!("tlscap-no-keylog-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let packet_prefix = dir.join("packets");
    let decode_prefix = dir.join("decode");

    let mut child = Command::new(env!("CARGO_BIN_EXE_tlscap"))
        .args([
            "-T",
            "ndjson",
            "-e",
            "ip.src",
            "-e",
            "ip.dst",
            "-e",
            "tcp.srcport",
            "-e",
            "tcp.dstport",
            "--packet-log",
            packet_prefix.to_str().unwrap(),
            "--output",
            decode_prefix.to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    child
        .stdin
        .take()
        .unwrap()
        .write_all(&build_pcap_with_one_syn())
        .unwrap();

    let output = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "tlscap must run to completion without --keylog, got stderr: {stderr}"
    );
    assert!(
        stderr.contains("no --keylog given"),
        "expected the no-keylog notice on stderr, got: {stderr}"
    );

    let entries: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();

    let packet_files: Vec<_> = entries
        .iter()
        .filter(|name| name.starts_with("packets_"))
        .collect();
    assert_eq!(
        packet_files.len(),
        1,
        "expected exactly one packet-log chunk, got {entries:?}"
    );

    let decode_files: Vec<_> = entries
        .iter()
        .filter(|name| name.starts_with("decode_"))
        .collect();
    assert!(
        decode_files.is_empty(),
        "expected no decode chunk (no TLS data in this frame), got {entries:?}"
    );

    std::fs::remove_dir_all(&dir).ok();
}
