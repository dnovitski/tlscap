//! TLS 1.2 record-layer decrypt (RFC 5246 §5/§6, RFC 5288 for the AEAD/GCM cipher suites this
//! module supports).
//!
//! Adapted from `~/gitrepos/pcapzip/src/tls12.rs` (see `tls13.rs`'s header comment for why this
//! is a port, not a dependency). Scoped to AES-GCM cipher suites only (RFC 5288) -- ChaCha20-
//! Poly1305 for TLS 1.2 and every CBC-mode suite are out of scope; CBC is legacy/deprecated (RFC
//! 9325) and needs padding-oracle-safe handling real complexity isn't worth it for.
//!
//! Structurally different from TLS 1.3: one traffic secret for the whole connection (no
//! handshake/application split); the GCM nonce is only partly implicit (a 4-byte salt from key
//! material, 8 bytes chosen by the sender and sent in cleartext per record); the AAD's length
//! field is the plaintext length, not ciphertext+tag length.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha384};
use thiserror::Error;

use crate::tls13::AeadAlgorithm;

#[derive(Debug, Error)]
pub enum Tls12Error {
    #[error("AEAD operation failed (wrong key/nonce, or corrupt/truncated record)")]
    Aead,
}

fn prf_hash(algorithm: AeadAlgorithm) -> PrfHash {
    match algorithm {
        AeadAlgorithm::Aes128Gcm => PrfHash::Sha256,
        AeadAlgorithm::Aes256Gcm => PrfHash::Sha384,
        AeadAlgorithm::ChaCha20Poly1305 => PrfHash::Sha256, // unused: TLS 1.2 here never selects this algorithm
    }
}

#[derive(Clone, Copy)]
enum PrfHash {
    Sha256,
    Sha384,
}

/// RFC 5246 §5: `P_hash(secret, seed) = HMAC(secret, A(1)+seed) || HMAC(secret, A(2)+seed) ||
/// ...` where `A(0) = seed`, `A(i) = HMAC(secret, A(i-1))`.
fn prf(secret: &[u8], label_and_seed: &[u8], out_len: usize, hash: PrfHash) -> Vec<u8> {
    match hash {
        PrfHash::Sha256 => p_hash::<Hmac<Sha256>>(secret, label_and_seed, out_len),
        PrfHash::Sha384 => p_hash::<Hmac<Sha384>>(secret, label_and_seed, out_len),
    }
}

fn p_hash<M: Mac + hmac::digest::KeyInit>(secret: &[u8], seed: &[u8], out_len: usize) -> Vec<u8> {
    let mut result = Vec::with_capacity(out_len + M::output_size());
    let mut a = hmac_once::<M>(secret, seed);
    while result.len() < out_len {
        let mut mac = M::new_from_slice(secret).expect("HMAC accepts any key length");
        mac.update(&a);
        mac.update(seed);
        result.extend_from_slice(&mac.finalize().into_bytes());
        a = hmac_once::<M>(secret, &a);
    }
    result.truncate(out_len);
    result
}

fn hmac_once<M: Mac + hmac::digest::KeyInit>(secret: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = M::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// The per-direction key material derived once for the whole connection: an AES key and the
/// 4-byte GCM salt (the fixed/implicit part of the nonce -- the other 8 bytes travel on the wire
/// per record).
pub struct RecordKeys {
    algorithm: AeadAlgorithm,
    key: Vec<u8>,
    salt: [u8; 4],
}

impl RecordKeys {
    /// Derives the full key_block from master_secret (as logged by `CLIENT_RANDOM`) and both
    /// hello messages' random values, and slices out this direction's key + salt. Key_block
    /// layout (RFC 5246 §6.3, no MAC keys for AEAD ciphers): `client_write_key ||
    /// server_write_key || client_write_IV || server_write_IV`.
    pub fn derive(
        master_secret: &[u8],
        client_random: &[u8; 32],
        server_random: &[u8; 32],
        algorithm: AeadAlgorithm,
        is_client: bool,
    ) -> Self {
        let key_len = algorithm.key_len();
        let salt_len = 4;
        let total = 2 * key_len + 2 * salt_len;

        let mut seed = Vec::with_capacity(b"key expansion".len() + 64);
        seed.extend_from_slice(b"key expansion");
        // RFC 5246 §6.3: server_random THEN client_random -- reversed from master_secret's own
        // derivation order.
        seed.extend_from_slice(server_random);
        seed.extend_from_slice(client_random);

        let key_block = prf(master_secret, &seed, total, prf_hash(algorithm));

        let client_write_key = &key_block[0..key_len];
        let server_write_key = &key_block[key_len..2 * key_len];
        let client_write_iv = &key_block[2 * key_len..2 * key_len + salt_len];
        let server_write_iv = &key_block[2 * key_len + salt_len..2 * key_len + 2 * salt_len];

        let (key, salt_slice) = if is_client {
            (client_write_key, client_write_iv)
        } else {
            (server_write_key, server_write_iv)
        };
        let mut salt = [0u8; 4];
        salt.copy_from_slice(salt_slice);

        RecordKeys {
            algorithm,
            key: key.to_vec(),
            salt,
        }
    }

    fn nonce_for(&self, explicit_nonce: &[u8; 8]) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[0..4].copy_from_slice(&self.salt);
        nonce[4..12].copy_from_slice(explicit_nonce);
        nonce
    }

    /// AAD per RFC 5246 §6.2.3.3: seq_num(8) || content_type(1) || version(2)=0x0303 ||
    /// length(2), where length is the PLAINTEXT length -- unlike TLS 1.3.
    fn aad(seq_num: u64, content_type: u8, plaintext_len: u16) -> [u8; 13] {
        let mut aad = [0u8; 13];
        aad[0..8].copy_from_slice(&seq_num.to_be_bytes());
        aad[8] = content_type;
        aad[9] = 0x03;
        aad[10] = 0x03;
        aad[11..13].copy_from_slice(&plaintext_len.to_be_bytes());
        aad
    }

    /// Decrypts a GenericAEADCipher's `ciphertext` (everything after the 8-byte
    /// `nonce_explicit`, i.e. AEAD ciphertext + 16-byte tag).
    pub fn decrypt_record(
        &self,
        seq_num: u64,
        content_type: u8,
        explicit_nonce: &[u8; 8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, Tls12Error> {
        let nonce = self.nonce_for(explicit_nonce);
        let plaintext_len = ciphertext.len().saturating_sub(16) as u16;
        let aad = Self::aad(seq_num, content_type, plaintext_len);
        let payload = Payload {
            msg: ciphertext,
            aad: &aad,
        };

        match self.algorithm {
            AeadAlgorithm::Aes128Gcm => {
                let cipher =
                    Aes128Gcm::new_from_slice(&self.key).expect("key length matches algorithm");
                cipher
                    .decrypt((&nonce).into(), payload)
                    .map_err(|_| Tls12Error::Aead)
            }
            AeadAlgorithm::Aes256Gcm => {
                let cipher =
                    Aes256Gcm::new_from_slice(&self.key).expect("key length matches algorithm");
                cipher
                    .decrypt((&nonce).into(), payload)
                    .map_err(|_| Tls12Error::Aead)
            }
            AeadAlgorithm::ChaCha20Poly1305 => Err(Tls12Error::Aead), // not a TLS 1.2 candidate here
        }
    }

    /// Encrypts `plaintext` under the given explicit nonce. Only used by tests (this module's own,
    /// and `connection.rs`'s), to build synthetic-but-valid TLS 1.2 records as fixtures --
    /// genuinely unused in a non-test build, hence the explicit allow rather than a spurious
    /// dead-code warning on infrastructure that exists specifically to make decrypt() testable.
    #[allow(dead_code)]
    pub(crate) fn encrypt_record(
        &self,
        seq_num: u64,
        content_type: u8,
        explicit_nonce: &[u8; 8],
        plaintext: &[u8],
    ) -> Vec<u8> {
        let nonce = self.nonce_for(explicit_nonce);
        let aad = Self::aad(seq_num, content_type, plaintext.len() as u16);
        let payload = Payload {
            msg: plaintext,
            aad: &aad,
        };

        match self.algorithm {
            AeadAlgorithm::Aes128Gcm => {
                let cipher =
                    Aes128Gcm::new_from_slice(&self.key).expect("key length matches algorithm");
                cipher
                    .encrypt((&nonce).into(), payload)
                    .expect("encryption with a freshly-derived key cannot fail")
            }
            AeadAlgorithm::Aes256Gcm => {
                let cipher =
                    Aes256Gcm::new_from_slice(&self.key).expect("key length matches algorithm");
                cipher
                    .encrypt((&nonce).into(), payload)
                    .expect("encryption with a freshly-derived key cannot fail")
            }
            AeadAlgorithm::ChaCha20Poly1305 => unreachable!("not a TLS 1.2 candidate here"),
        }
    }
}

/// Extracts the `random` field (32 bytes) from an unencrypted ServerHello handshake body, the
/// TLS 1.2 counterpart to `connection::client_random_from_client_hello`. Same byte layout:
/// msg_type(1)=0x02, length(3), legacy_version(2), random(32).
pub fn server_random_from_server_hello(handshake_body: &[u8]) -> Option<[u8; 32]> {
    if handshake_body.len() < 1 + 3 + 2 + 32 || handshake_body[0] != 0x02 {
        return None;
    }
    let mut random = [0u8; 32];
    random.copy_from_slice(&handshake_body[6..38]);
    Some(random)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_aes128gcm() {
        let master_secret = [0x11u8; 48];
        let client_random = [0x22u8; 32];
        let server_random = [0x33u8; 32];
        let client_keys = RecordKeys::derive(
            &master_secret,
            &client_random,
            &server_random,
            AeadAlgorithm::Aes128Gcm,
            true,
        );

        let explicit_nonce = [1, 2, 3, 4, 5, 6, 7, 8];
        let plaintext = b"HEARTBEAT_REQUEST body bytes here";
        let ciphertext = client_keys.encrypt_record(0, 0x17, &explicit_nonce, plaintext);
        assert_eq!(ciphertext.len(), plaintext.len() + 16);

        let decrypted = client_keys
            .decrypt_record(0, 0x17, &explicit_nonce, &ciphertext)
            .unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn client_and_server_derive_different_keys() {
        let master_secret = [0x44u8; 48];
        let client_random = [0x55u8; 32];
        let server_random = [0x66u8; 32];
        let client_keys = RecordKeys::derive(
            &master_secret,
            &client_random,
            &server_random,
            AeadAlgorithm::Aes256Gcm,
            true,
        );
        let server_keys = RecordKeys::derive(
            &master_secret,
            &client_random,
            &server_random,
            AeadAlgorithm::Aes256Gcm,
            false,
        );

        let explicit_nonce = [0u8; 8];
        let plaintext = b"only the right side should decrypt this";
        let ciphertext = client_keys.encrypt_record(0, 0x17, &explicit_nonce, plaintext);

        assert!(
            server_keys
                .decrypt_record(0, 0x17, &explicit_nonce, &ciphertext)
                .is_err()
        );
    }

    #[test]
    fn wrong_explicit_nonce_fails_to_decrypt() {
        let master_secret = [0x77u8; 48];
        let client_random = [0x88u8; 32];
        let server_random = [0x99u8; 32];
        let keys = RecordKeys::derive(
            &master_secret,
            &client_random,
            &server_random,
            AeadAlgorithm::Aes128Gcm,
            true,
        );

        let ciphertext = keys.encrypt_record(0, 0x17, &[1; 8], b"payload");
        let result = keys.decrypt_record(0, 0x17, &[2; 8], &ciphertext);
        assert!(
            result.is_err(),
            "decrypting with the wrong explicit nonce must fail, not silently succeed"
        );
    }

    #[test]
    fn server_hello_random_extraction() {
        let mut body = vec![0x02, 0x00, 0x00, 0x00];
        body.extend_from_slice(&[0x03, 0x03]);
        let random: Vec<u8> = (100..132).collect();
        body.extend_from_slice(&random);

        let extracted = server_random_from_server_hello(&body).unwrap();
        assert_eq!(&extracted[..], &random[..]);
    }

    #[test]
    fn non_server_hello_returns_none() {
        let body = vec![0x01, 0x00, 0x00, 0x00];
        assert!(server_random_from_server_hello(&body).is_none());
    }
}
