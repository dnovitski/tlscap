//! Cross-validates `tlscap`'s TLS 1.3 decrypt path against `rustls` -- a mature, independent TLS
//! implementation. The unit tests inside `src/connection.rs`/`src/tls13.rs` only ever decrypt
//! ciphertext `tlscap` itself produced (via its own `encrypt_record` test helper), which can't
//! catch a bug that's symmetrically wrong in both directions (e.g. a subtly incorrect
//! HKDF-Expand-Label implementation that still "round-trips" against itself). This test instead
//! drives a REAL TLS 1.3 handshake between two independent `rustls` connections, captures
//! `rustls`'s own logged secrets and the exact wire ciphertext it produced, and feeds both into
//! `tlscap::connection::ConnectionState` -- proving `tlscap` can decrypt bytes it played no part
//! in creating.

use std::io::Cursor;
use std::sync::{Arc, Mutex};

use rcgen::{CertifiedKey, generate_simple_self_signed};
use rustls::pki_types::{PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection};

use tlscap::connection::ConnectionState;
use tlscap::keylog::Keylog;

/// Captures every secret `rustls` logs, in NSS SSLKEYLOGFILE text format -- the same format
/// `tlscap::keylog::Keylog::parse` consumes, and the same format jSSLKeyLog produces in production.
#[derive(Debug, Default)]
struct CapturingKeyLog(Mutex<String>);

impl rustls::KeyLog for CapturingKeyLog {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        let mut buf = self.0.lock().unwrap();
        buf.push_str(&format!(
            "{label} {} {}\r\n",
            hex::encode(client_random),
            hex::encode(secret)
        ));
    }
}

/// Drives a real TLS 1.3 handshake entirely in-memory (no real socket needed -- rustls's
/// `read_tls`/`write_tls`/`process_new_packets` operate on any `Read`/`Write`, so pumping two
/// in-memory buffers back and forth is just as genuine a handshake as a real network connection,
/// without this sandbox's live-capture permission restrictions).
fn run_handshake_and_send(client_payload: &[u8]) -> (String, Vec<u8>) {
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = cert.der().clone();
    let key_der = PrivatePkcs8KeyDer::from(signing_key.serialize_der());

    let server_keylog = Arc::new(CapturingKeyLog::default());
    let client_keylog = Arc::new(CapturingKeyLog::default());

    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der.into())
        .unwrap();
    server_config.key_log = server_keylog.clone();

    let mut root_store = RootCertStore::empty();
    root_store.add(cert_der).unwrap();
    let mut client_config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    client_config.key_log = client_keylog.clone();

    let mut server_conn = ServerConnection::new(Arc::new(server_config)).unwrap();
    let mut client_conn = ClientConnection::new(
        Arc::new(client_config),
        ServerName::try_from("localhost").unwrap(),
    )
    .unwrap();

    // Pump handshake flight-by-flight until both sides report done.
    let mut c2s = Vec::new();
    let mut s2c = Vec::new();
    for _ in 0..10 {
        if !client_conn.is_handshaking() && !server_conn.is_handshaking() {
            break;
        }
        c2s.clear();
        client_conn.write_tls(&mut c2s).unwrap();
        if !c2s.is_empty() {
            server_conn.read_tls(&mut Cursor::new(&c2s)).unwrap();
            server_conn.process_new_packets().unwrap();
        }
        s2c.clear();
        server_conn.write_tls(&mut s2c).unwrap();
        if !s2c.is_empty() {
            client_conn.read_tls(&mut Cursor::new(&s2c)).unwrap();
            client_conn.process_new_packets().unwrap();
        }
    }
    assert!(
        !client_conn.is_handshaking() && !server_conn.is_handshaking(),
        "handshake did not complete"
    );

    // Client sends real, independently-encrypted application data. Capture the EXACT wire
    // ciphertext bytes rustls produced -- this is what a real capture would have seen on the
    // wire, byte for byte.
    use std::io::Write;
    client_conn.writer().write_all(client_payload).unwrap();
    let mut wire_ciphertext = Vec::new();
    client_conn.write_tls(&mut wire_ciphertext).unwrap();

    let keylog_text = format!(
        "{}{}",
        client_keylog.0.lock().unwrap(),
        server_keylog.0.lock().unwrap()
    );
    (keylog_text, wire_ciphertext)
}

#[test]
fn tlscap_decrypts_real_rustls_produced_tls13_ciphertext() {
    let payload = b"HEARTBEAT_REQUEST-shaped application data, produced entirely by rustls";
    let (keylog_text, wire_ciphertext) = run_handshake_and_send(payload);

    // wire_ciphertext is one or more TLS records concatenated (typically exactly one for a small
    // payload): 5-byte header + AEAD ciphertext+tag. Parse the header the same way
    // orchestrator.rs's drain_records does, to feed connection.rs exactly what it expects.
    assert!(
        wire_ciphertext.len() > 5,
        "expected at least one TLS record"
    );
    let outer_content_type = wire_ciphertext[0];
    assert_eq!(
        outer_content_type, 0x17,
        "TLS 1.3 always uses opaque outer type application_data once encrypted"
    );
    let body_len = u16::from_be_bytes([wire_ciphertext[3], wire_ciphertext[4]]) as usize;
    let body = &wire_ciphertext[5..5 + body_len];

    let keylog = Keylog::parse(&keylog_text);

    // ClientHello's random correlates the connection in a real capture; here we don't have the
    // raw ClientHello bytes (handshake pumping above didn't retain them), but CLIENT_RANDOM keys
    // in an SSLKEYLOGFILE are literally the ClientHello.random value -- extract it directly from
    // the keylog text the same way a real capture's client_random_from_client_hello() would end
    // up with the same bytes.
    let client_random_hex = keylog_text
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap();
    let client_random = hex::decode(client_random_hex).unwrap();

    let mut conn = ConnectionState::new(client_random);
    let decrypted = conn
        .decrypt(&keylog, true, outer_content_type, body)
        .unwrap_or_else(|_| panic!("tlscap failed to decrypt genuine rustls-produced ciphertext"));

    assert_eq!(
        decrypted.plaintext, payload,
        "tlscap's decrypted plaintext must exactly match what rustls originally encrypted"
    );
    assert_eq!(decrypted.content_type, 0x17);
}
