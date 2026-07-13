//! Per-connection, per-direction TLS record decrypt state, for both TLS 1.3 and TLS 1.2
//! (AES-GCM cipher suites; see `tls12` module docs for scope).
//!
//! Adapted from `~/gitrepos/pcapzip/src/connection.rs` (see `tls13.rs`'s header comment), trimmed
//! to decrypt-only: pcapzip's `ConnectionState` also implements `encrypt` (for its `restore`
//! subcommand) and `ConnectionSnapshot`/`from_snapshot` (to carry state across `.pcapz` output-
//! segment rotation boundaries). tlscap never re-encrypts anything, and never needs to
//! reconstruct a mid-connection starting point from a serialized snapshot -- a `ConnectionState`
//! here lives in the one long-running `Orchestrator` for as long as the connection itself is
//! tracked (see `orchestrator.rs`'s FIN/RST-driven eviction), so it's never reset mid-flight.
//!
//! Rather than parsing ServerHello's cipher_suite extension, this leans on AEAD's authentication
//! property: try each candidate algorithm in turn, and trust that whichever one produces a valid
//! auth tag is the right one -- a wrong key/algorithm fails to authenticate with overwhelming
//! probability, so "decryption succeeded" is a reliable signal, not a guess.

use std::collections::HashMap;

use crate::keylog::{Keylog, SecretLabel};
use crate::tls13::{AeadAlgorithm, RecordKeys, Tls13Error, record_aad};

const ALL_ALGORITHMS: [AeadAlgorithm; 3] = [
    AeadAlgorithm::Aes128Gcm,
    AeadAlgorithm::Aes256Gcm,
    AeadAlgorithm::ChaCha20Poly1305,
];
const TLS12_ALGORITHMS: [AeadAlgorithm; 2] = [AeadAlgorithm::Aes128Gcm, AeadAlgorithm::Aes256Gcm];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Generation {
    Handshake,
    Application,
}

/// Which TLS version protected a record. Exposed mainly for diagnostics/logging -- tlscap has no
/// re-encrypt path that needs this replayed the way pcapzip's `restore` does.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordVersion {
    Tls13 { generation: Generation },
    Tls12 { explicit_nonce: [u8; 8] },
}

#[derive(Default)]
struct DirectionState {
    seq_handshake: u64,
    seq_application: u64,
    // Cached per (generation, algorithm): decrypt() tries multiple candidate algorithms per
    // generation while probing, and caching only by generation would silently keep reusing
    // whichever algorithm happened to be tried (and cached) first.
    keys_handshake: HashMap<AeadAlgorithm, RecordKeys>,
    keys_application: HashMap<AeadAlgorithm, RecordKeys>,
}

impl DirectionState {
    fn keys_for(
        &mut self,
        g: Generation,
        client_random: &[u8],
        keylog: &Keylog,
        is_client: bool,
        algorithm: AeadAlgorithm,
    ) -> Option<&RecordKeys> {
        let label = match (g, is_client) {
            (Generation::Handshake, true) => SecretLabel::ClientHandshakeTrafficSecret,
            (Generation::Handshake, false) => SecretLabel::ServerHandshakeTrafficSecret,
            (Generation::Application, true) => SecretLabel::ClientTrafficSecret0,
            (Generation::Application, false) => SecretLabel::ServerTrafficSecret0,
        };
        let secret = keylog.secret_for(client_random, label)?;

        let map = match g {
            Generation::Handshake => &mut self.keys_handshake,
            Generation::Application => &mut self.keys_application,
        };
        match map.entry(algorithm) {
            std::collections::hash_map::Entry::Occupied(e) => Some(e.into_mut()),
            std::collections::hash_map::Entry::Vacant(e) => {
                Some(e.insert(RecordKeys::derive(secret, algorithm)?))
            }
        }
    }

    fn next_seq(&mut self, g: Generation) -> u64 {
        let seq_ref = match g {
            Generation::Handshake => &mut self.seq_handshake,
            Generation::Application => &mut self.seq_application,
        };
        let seq = *seq_ref;
        *seq_ref = seq + 1;
        seq
    }
}

/// TLS 1.2 has just one secret (the logged master_secret) for the whole connection, hence one
/// sequence counter per direction -- no handshake/application split like TLS 1.3.
#[derive(Default)]
struct Tls12DirectionState {
    seq: u64,
    keys: HashMap<AeadAlgorithm, crate::tls12::RecordKeys>,
}

impl Tls12DirectionState {
    fn keys_for(
        &mut self,
        master_secret: &[u8],
        client_random: &[u8; 32],
        server_random: &[u8; 32],
        is_client: bool,
        algorithm: AeadAlgorithm,
    ) -> &crate::tls12::RecordKeys {
        self.keys.entry(algorithm).or_insert_with(|| {
            crate::tls12::RecordKeys::derive(
                master_secret,
                client_random,
                server_random,
                algorithm,
                is_client,
            )
        })
    }

    fn next_seq(&mut self) -> u64 {
        let seq = self.seq;
        self.seq += 1;
        seq
    }
}

/// Tracks per-direction TLS record-layer decrypt state for one connection, either TLS 1.3 or TLS
/// 1.2 (never both -- a connection is always purely one).
pub struct ConnectionState {
    client_random: Vec<u8>,
    /// Learned from an unencrypted ServerHello, needed for TLS 1.2's key_block derivation. TLS
    /// 1.3 doesn't need this at all.
    server_random: Option<[u8; 32]>,
    client_to_server: DirectionState,
    server_to_client: DirectionState,
    tls12_client_to_server: Tls12DirectionState,
    tls12_server_to_client: Tls12DirectionState,
}

#[derive(Debug)]
pub enum ProcessError {
    /// No secret for this client_random/generation/direction is in the keylog yet -- caller
    /// should retry later (the keylog may still be catching up) rather than give up.
    NoKey,
    /// A key was available but every algorithm/generation combination failed to authenticate --
    /// likely a KeyUpdate-rotated secret we don't have logged, or corrupt/out-of-sync data.
    AuthFailed,
}

pub struct DecryptedRecord {
    pub plaintext: Vec<u8>,
    pub content_type: u8,
    #[allow(dead_code)] // surfaced for future diagnostics/logging use, not consumed yet
    pub algorithm: AeadAlgorithm,
    #[allow(dead_code)]
    pub version: RecordVersion,
}

impl ConnectionState {
    pub fn new(client_random: Vec<u8>) -> Self {
        ConnectionState {
            client_random,
            server_random: None,
            client_to_server: DirectionState::default(),
            server_to_client: DirectionState::default(),
            tls12_client_to_server: Tls12DirectionState::default(),
            tls12_server_to_client: Tls12DirectionState::default(),
        }
    }

    pub fn client_random(&self) -> &[u8] {
        &self.client_random
    }

    /// Learns this connection's ServerHello.random, needed to derive TLS 1.2 key material. A
    /// no-op for TLS 1.3 connections. First-wins/idempotent -- returns `true` only the first time
    /// (i.e. this call is the one that just learned it), so a caller can distinguish "this is
    /// genuinely the ServerHello record itself" from "some later record's plaintext happened to
    /// look like one" (see `orchestrator.rs::drain_records`, which uses this to skip attempting a
    /// decrypt against the record that carried it -- ServerHello is never encrypted).
    pub fn set_server_random(&mut self, server_random: [u8; 32]) -> bool {
        let was_unset = self.server_random.is_none();
        self.server_random.get_or_insert(server_random);
        was_unset
    }

    /// Attempts to decrypt one TLSCiphertext/GenericAEADCipher record's body from the given
    /// direction: every TLS 1.3 generation/algorithm combination first (handshake before
    /// application), then TLS 1.2 (AES-GCM only) if none matched. On success, advances the
    /// relevant sequence counter.
    ///
    /// Callers MUST attempt this for every encrypted record after a connection's handshake
    /// completes, not just ones already believed to be application data: TLS 1.2 keeps a single
    /// sequence counter across every encrypted record in a direction regardless of type (RFC 5246
    /// §6.1), so a skipped record (e.g. the encrypted Finished message) silently desyncs every
    /// later sequence number for that direction if decrypt() is never even tried on it.
    pub fn decrypt(
        &mut self,
        keylog: &Keylog,
        is_client_to_server: bool,
        outer_content_type: u8,
        encrypted_body: &[u8],
    ) -> Result<DecryptedRecord, ProcessError> {
        if let Ok(record) = self.decrypt_tls13(keylog, is_client_to_server, encrypted_body) {
            return Ok(record);
        }
        self.decrypt_tls12(
            keylog,
            is_client_to_server,
            outer_content_type,
            encrypted_body,
        )
    }

    fn decrypt_tls13(
        &mut self,
        keylog: &Keylog,
        is_client_to_server: bool,
        encrypted_body: &[u8],
    ) -> Result<DecryptedRecord, ProcessError> {
        let dir = if is_client_to_server {
            &mut self.client_to_server
        } else {
            &mut self.server_to_client
        };
        let is_client = is_client_to_server;
        let client_random = &self.client_random;

        let aad = record_aad(encrypted_body.len());

        for g in [Generation::Handshake, Generation::Application] {
            let seq = match g {
                Generation::Handshake => dir.seq_handshake,
                Generation::Application => dir.seq_application,
            };

            for algorithm in ALL_ALGORITHMS {
                let Some(keys) = dir.keys_for(g, client_random, keylog, is_client, algorithm)
                else {
                    continue;
                };

                match keys.decrypt_record(seq, &aad, encrypted_body) {
                    Ok((plaintext, content_type)) => {
                        dir.next_seq(g);
                        return Ok(DecryptedRecord {
                            plaintext,
                            content_type,
                            algorithm,
                            version: RecordVersion::Tls13 { generation: g },
                        });
                    }
                    Err(Tls13Error::Aead) | Err(Tls13Error::NoContentType) => continue,
                    Err(Tls13Error::RecordTooShort) => return Err(ProcessError::AuthFailed),
                }
            }
        }

        Err(ProcessError::NoKey)
    }

    fn decrypt_tls12(
        &mut self,
        keylog: &Keylog,
        is_client_to_server: bool,
        content_type: u8,
        encrypted_body: &[u8],
    ) -> Result<DecryptedRecord, ProcessError> {
        let Some(server_random) = self.server_random else {
            return Err(ProcessError::NoKey);
        };
        let Ok(client_random) = <[u8; 32]>::try_from(self.client_random.as_slice()) else {
            return Err(ProcessError::NoKey);
        };
        let Some(master_secret) = keylog.secret_for(&self.client_random, SecretLabel::ClientRandom)
        else {
            return Err(ProcessError::NoKey);
        };

        // GenericAEADCipher = nonce_explicit(8) || AEAD-ciphered content -- too short to even
        // hold the explicit nonce plus a 16-byte tag means this was never a valid AEAD record.
        if encrypted_body.len() < 8 + 16 {
            return Err(ProcessError::AuthFailed);
        }
        let explicit_nonce: [u8; 8] = encrypted_body[0..8]
            .try_into()
            .expect("checked length above");
        let ciphertext = &encrypted_body[8..];

        let dir = if is_client_to_server {
            &mut self.tls12_client_to_server
        } else {
            &mut self.tls12_server_to_client
        };
        let seq = dir.seq;

        for algorithm in TLS12_ALGORITHMS {
            let keys = dir.keys_for(
                master_secret,
                &client_random,
                &server_random,
                is_client_to_server,
                algorithm,
            );
            if let Ok(plaintext) =
                keys.decrypt_record(seq, content_type, &explicit_nonce, ciphertext)
            {
                dir.next_seq();
                return Ok(DecryptedRecord {
                    plaintext,
                    content_type,
                    algorithm,
                    version: RecordVersion::Tls12 { explicit_nonce },
                });
            }
        }

        Err(ProcessError::NoKey)
    }
}

/// Extracts the ClientHello's `random` field (32 bytes) from an unencrypted handshake record
/// body, used to correlate a fresh connection with its keylog secrets.
pub fn client_random_from_client_hello(handshake_body: &[u8]) -> Option<[u8; 32]> {
    if handshake_body.len() < 1 + 3 + 2 + 32 || handshake_body[0] != 0x01 {
        return None;
    }
    let mut random = [0u8; 32];
    random.copy_from_slice(&handshake_body[6..38]);
    Some(random)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keylog::Keylog;

    #[test]
    fn decrypts_tls13_application_traffic() {
        let random_hex = "aa".repeat(32);
        let secret_hex = "bb".repeat(32);
        let mut kl_text = format!("CLIENT_TRAFFIC_SECRET_0 {random_hex} {secret_hex}\r\n");
        kl_text += &format!(
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET {random_hex} {}\r\n",
            "cc".repeat(32)
        );
        let kl = Keylog::parse(&kl_text);

        let client_random = hex::decode(&random_hex).unwrap();
        let secret = hex::decode(&secret_hex).unwrap();
        let keys = RecordKeys::derive(&secret, AeadAlgorithm::Aes128Gcm).unwrap();
        let content = b"HEARTBEAT_RESPONSE-ish body";
        let aad = record_aad(content.len() + 17);
        let ciphertext = keys.encrypt_record(0, &aad, content, 0x17, 0);

        let mut conn = ConnectionState::new(client_random.clone());
        let decrypted = match conn.decrypt(&kl, true, 0x17, &ciphertext) {
            Ok(v) => v,
            Err(ProcessError::NoKey) => panic!("expected a usable key"),
            Err(ProcessError::AuthFailed) => panic!("expected successful decryption"),
        };
        assert_eq!(decrypted.plaintext, content);
        assert_eq!(decrypted.content_type, 0x17);
        assert_eq!(
            decrypted.version,
            RecordVersion::Tls13 {
                generation: Generation::Application
            }
        );
        assert_eq!(decrypted.algorithm, AeadAlgorithm::Aes128Gcm);
    }

    #[test]
    fn sequence_numbers_advance_independently_per_generation() {
        let random_hex = "11".repeat(32);
        let hs_secret = "22".repeat(32);
        let app_secret = "33".repeat(32);
        let kl = Keylog::parse(&format!(
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET {random_hex} {hs_secret}\r\nCLIENT_TRAFFIC_SECRET_0 {random_hex} {app_secret}\r\n"
        ));
        let client_random = hex::decode(&random_hex).unwrap();

        let hs_keys =
            RecordKeys::derive(&hex::decode(&hs_secret).unwrap(), AeadAlgorithm::Aes128Gcm)
                .unwrap();
        let app_keys =
            RecordKeys::derive(&hex::decode(&app_secret).unwrap(), AeadAlgorithm::Aes128Gcm)
                .unwrap();

        let hs_ct = hs_keys.encrypt_record(0, &record_aad(5 + 17), b"fake ", 0x16, 0);
        let app_ct0 = app_keys.encrypt_record(0, &record_aad(5 + 17), b"app-0", 0x17, 0);
        let app_ct1 = app_keys.encrypt_record(1, &record_aad(5 + 17), b"app-1", 0x17, 0);

        let mut conn = ConnectionState::new(client_random);
        let d0 = conn.decrypt(&kl, true, 0x17, &hs_ct).ok().unwrap();
        assert_eq!(
            d0.version,
            RecordVersion::Tls13 {
                generation: Generation::Handshake
            }
        );
        let d1 = conn.decrypt(&kl, true, 0x17, &app_ct0).ok().unwrap();
        assert_eq!(
            d1.version,
            RecordVersion::Tls13 {
                generation: Generation::Application
            }
        );
        assert_eq!(d1.plaintext, b"app-0");
        let d2 = conn.decrypt(&kl, true, 0x17, &app_ct1).ok().unwrap();
        assert_eq!(d2.plaintext, b"app-1");
    }

    #[test]
    fn tls12_decrypts_application_traffic() {
        let random_hex = "44".repeat(32);
        let master_secret_hex = "55".repeat(48);
        let kl = Keylog::parse(&format!(
            "CLIENT_RANDOM {random_hex} {master_secret_hex}\r\n"
        ));

        let client_random_vec = hex::decode(&random_hex).unwrap();
        let client_random: [u8; 32] = client_random_vec.clone().try_into().unwrap();
        let server_random = [0x66u8; 32];
        let master_secret = hex::decode(&master_secret_hex).unwrap();

        let keys = crate::tls12::RecordKeys::derive(
            &master_secret,
            &client_random,
            &server_random,
            AeadAlgorithm::Aes128Gcm,
            true,
        );
        let explicit_nonce = [7u8; 8];
        let content = b"a tls 1.2 application data record";
        let ciphertext_body = {
            let mut body = explicit_nonce.to_vec();
            body.extend_from_slice(&keys.encrypt_record(0, 0x17, &explicit_nonce, content));
            body
        };

        let mut conn = ConnectionState::new(client_random_vec);
        conn.set_server_random(server_random);
        let decrypted = match conn.decrypt(&kl, true, 0x17, &ciphertext_body) {
            Ok(v) => v,
            Err(ProcessError::NoKey) => panic!("expected a usable TLS 1.2 key"),
            Err(ProcessError::AuthFailed) => panic!("expected successful decryption"),
        };
        assert_eq!(decrypted.plaintext, content);
        assert_eq!(decrypted.version, RecordVersion::Tls12 { explicit_nonce });
    }

    #[test]
    fn tls12_without_server_random_fails_closed() {
        let random_hex = "77".repeat(32);
        let kl = Keylog::parse(&format!(
            "CLIENT_RANDOM {random_hex} {}\r\n",
            "88".repeat(48)
        ));
        let mut conn = ConnectionState::new(hex::decode(&random_hex).unwrap());
        match conn.decrypt(&kl, true, 0x17, &[0u8; 30]) {
            Err(ProcessError::NoKey) => {}
            _ => panic!("expected NoKey without server_random, not a guess"),
        }
    }

    #[test]
    fn client_hello_random_extraction() {
        let mut body = vec![0x01, 0x00, 0x00, 0x00];
        body.extend_from_slice(&[0x03, 0x03]);
        let random: Vec<u8> = (0..32).collect();
        body.extend_from_slice(&random);
        body.extend_from_slice(&[0xAA; 10]);

        let extracted = client_random_from_client_hello(&body).unwrap();
        assert_eq!(&extracted[..], &random[..]);
    }

    #[test]
    fn non_client_hello_returns_none() {
        let body = vec![0x02, 0x00, 0x00, 0x00];
        assert!(client_random_from_client_hello(&body).is_none());
    }

    #[test]
    fn missing_secret_returns_no_key() {
        let kl = Keylog::parse("");
        let mut conn = ConnectionState::new(vec![0xAA; 32]);
        match conn.decrypt(&kl, true, 0x17, &[0u8; 20]) {
            Err(ProcessError::NoKey) => {}
            _ => panic!("expected NoKey when the keylog has nothing for this client_random"),
        }
    }
}
