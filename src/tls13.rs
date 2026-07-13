//! TLS 1.3 record-layer decrypt (RFC 8446 §5 and §7.1-7.3).
//!
//! Adapted from `~/gitrepos/pcapzip/src/tls13.rs` (same author, used here as a reference/starting
//! point rather than a dependency -- pcapzip itself is a rapid proof-of-concept the user does not
//! want tlscap built on top of as a library). Deliberately not a TLS implementation: no handshake,
//! no certificate validation, no state machine. Given a traffic secret (as logged by
//! SSLKEYLOGFILE) and the record's sequence number within that secret's lifetime, this derives
//! the record's key+nonce and performs the AEAD transform.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use sha2::{Sha256, Sha384};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Tls13Error {
    #[error("AEAD operation failed (wrong key/nonce, or corrupt/truncated record)")]
    Aead,
    #[error("record too short to contain an auth tag")]
    RecordTooShort,
    #[error(
        "decrypted inner plaintext has no content-type byte (all-zero after stripping padding)"
    )]
    NoContentType,
}

/// The AEAD algorithms TLS 1.3 can negotiate that we support. Covers every cipher suite in the
/// mandatory-to-implement set (RFC 8446 §9.1) plus the two GCM variants seen in practice.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum AeadAlgorithm {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl AeadAlgorithm {
    pub fn key_len(self) -> usize {
        match self {
            AeadAlgorithm::Aes128Gcm => 16,
            AeadAlgorithm::Aes256Gcm => 32,
            AeadAlgorithm::ChaCha20Poly1305 => 32,
        }
    }

    /// TLS 1.3 uses a 12-byte IV/nonce for every AEAD algorithm it defines.
    pub const IV_LEN: usize = 12;

    /// Each TLS 1.3 cipher suite name bakes in the hash its key schedule uses (RFC 8446 §B.4):
    /// TLS_AES_128_GCM_SHA256 and TLS_CHACHA20_POLY1305_SHA256 use SHA-256; TLS_AES_256_GCM_SHA384
    /// uses SHA-384.
    fn hash(self) -> HkdfHash {
        match self {
            AeadAlgorithm::Aes128Gcm | AeadAlgorithm::ChaCha20Poly1305 => HkdfHash::Sha256,
            AeadAlgorithm::Aes256Gcm => HkdfHash::Sha384,
        }
    }
}

#[derive(Clone, Copy)]
enum HkdfHash {
    Sha256,
    Sha384,
}

/// HKDF-Expand-Label, RFC 8446 §7.1. `None` if `secret` is the wrong length to be a valid PRK for
/// `hash` (e.g. a 32-byte SHA-256 secret handed to the SHA-384 path while probing candidate
/// algorithms) -- a real possibility since `ConnectionState::decrypt` brute-forces every
/// algorithm, deliberately not a panic.
fn hkdf_expand_label(
    secret: &[u8],
    label: &str,
    context: &[u8],
    length: usize,
    hash: HkdfHash,
) -> Option<Vec<u8>> {
    let mut hkdf_label = Vec::with_capacity(2 + 1 + 6 + label.len() + 1 + context.len());
    hkdf_label.extend_from_slice(&(length as u16).to_be_bytes());
    let full_label = format!("tls13 {label}");
    hkdf_label.push(full_label.len() as u8);
    hkdf_label.extend_from_slice(full_label.as_bytes());
    hkdf_label.push(context.len() as u8);
    hkdf_label.extend_from_slice(context);

    let mut out = vec![0u8; length];
    match hash {
        HkdfHash::Sha256 => {
            let hk = Hkdf::<Sha256>::from_prk(secret).ok()?;
            hk.expand(&hkdf_label, &mut out)
                .expect("length is within HKDF-Expand's 255*HashLen limit");
        }
        HkdfHash::Sha384 => {
            let hk = Hkdf::<Sha384>::from_prk(secret).ok()?;
            hk.expand(&hkdf_label, &mut out)
                .expect("length is within HKDF-Expand's 255*HashLen limit");
        }
    }
    Some(out)
}

/// The per-direction key material derived from one traffic secret: an AEAD key and the "static"
/// IV that gets XORed with the record sequence number to form each record's actual nonce (RFC
/// 8446 §5.3).
pub struct RecordKeys {
    algorithm: AeadAlgorithm,
    key: Vec<u8>,
    iv: [u8; AeadAlgorithm::IV_LEN],
}

impl RecordKeys {
    /// `None` if `traffic_secret`'s length doesn't match what `algorithm`'s hash requires.
    pub fn derive(traffic_secret: &[u8], algorithm: AeadAlgorithm) -> Option<Self> {
        let key = hkdf_expand_label(
            traffic_secret,
            "key",
            &[],
            algorithm.key_len(),
            algorithm.hash(),
        )?;
        let iv_vec = hkdf_expand_label(
            traffic_secret,
            "iv",
            &[],
            AeadAlgorithm::IV_LEN,
            algorithm.hash(),
        )?;
        let mut iv = [0u8; AeadAlgorithm::IV_LEN];
        iv.copy_from_slice(&iv_vec);
        Some(RecordKeys { algorithm, key, iv })
    }

    /// RFC 8446 §5.3: nonce = static_iv XOR (0-padded big-endian seq_num).
    fn nonce_for(&self, seq_num: u64) -> [u8; AeadAlgorithm::IV_LEN] {
        let mut nonce = self.iv;
        let seq_bytes = seq_num.to_be_bytes();
        for i in 0..8 {
            nonce[4 + i] ^= seq_bytes[i];
        }
        nonce
    }

    /// Decrypts one TLSCiphertext record's `encrypted_record` field (ciphertext + trailing
    /// 16-byte auth tag, i.e. everything after the 5-byte record header) at the given sequence
    /// number. `aad` is the record header exactly as it appeared on the wire, per RFC 8446 §5.2.
    /// Returns `(plaintext_content, real_content_type)` with trailing zero-padding and the
    /// content-type byte already stripped, per RFC 8446 §5.4's "scan backward for the first
    /// non-zero byte" rule.
    pub fn decrypt_record(
        &self,
        seq_num: u64,
        aad: &[u8; 5],
        encrypted_record: &[u8],
    ) -> Result<(Vec<u8>, u8), Tls13Error> {
        if encrypted_record.len() < 16 {
            return Err(Tls13Error::RecordTooShort);
        }
        let nonce = self.nonce_for(seq_num);
        let payload = Payload {
            msg: encrypted_record,
            aad,
        };

        let mut inner = match self.algorithm {
            AeadAlgorithm::Aes128Gcm => {
                let cipher =
                    Aes128Gcm::new_from_slice(&self.key).expect("key length matches algorithm");
                cipher
                    .decrypt((&nonce).into(), payload)
                    .map_err(|_| Tls13Error::Aead)?
            }
            AeadAlgorithm::Aes256Gcm => {
                let cipher =
                    Aes256Gcm::new_from_slice(&self.key).expect("key length matches algorithm");
                cipher
                    .decrypt((&nonce).into(), payload)
                    .map_err(|_| Tls13Error::Aead)?
            }
            AeadAlgorithm::ChaCha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new_from_slice(&self.key)
                    .expect("key length matches algorithm");
                cipher
                    .decrypt((&nonce).into(), payload)
                    .map_err(|_| Tls13Error::Aead)?
            }
        };

        while let Some(&0) = inner.last() {
            inner.pop();
        }
        let content_type = inner.pop().ok_or(Tls13Error::NoContentType)?;
        Ok((inner, content_type))
    }

    /// Encrypts `content` (with `content_type` appended per RFC 8446 §5.2's TLSInnerPlaintext)
    /// into a ciphertext+tag blob. Only used by tests (this module's own, and `connection.rs`'s),
    /// to build synthetic-but-valid TLS 1.3 records as fixtures (`decrypt_record` is the only
    /// direction tlscap needs in production -- it never re-encrypts). Genuinely unused in a
    /// non-test build, hence the explicit allow rather than a spurious dead-code warning.
    #[allow(dead_code)]
    pub(crate) fn encrypt_record(
        &self,
        seq_num: u64,
        aad: &[u8; 5],
        content: &[u8],
        content_type: u8,
        padding_len: usize,
    ) -> Vec<u8> {
        let nonce = self.nonce_for(seq_num);
        let mut inner = Vec::with_capacity(content.len() + 1 + padding_len);
        inner.extend_from_slice(content);
        inner.push(content_type);
        inner.resize(inner.len() + padding_len, 0);
        let payload = Payload { msg: &inner, aad };

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
            AeadAlgorithm::ChaCha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new_from_slice(&self.key)
                    .expect("key length matches algorithm");
                cipher
                    .encrypt((&nonce).into(), payload)
                    .expect("encryption with a freshly-derived key cannot fail")
            }
        }
    }
}

/// Builds the 5-byte TLSCiphertext record header used as AEAD associated data: opaque_type
/// (always 0x17 for protected records) || legacy version (0x0303) || ciphertext-and-tag length.
pub fn record_aad(ciphertext_len: usize) -> [u8; 5] {
    let mut aad = [0x17, 0x03, 0x03, 0, 0];
    aad[3..5].copy_from_slice(&(ciphertext_len as u16).to_be_bytes());
    aad
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_aes128gcm() {
        let secret = [0x42u8; 32];
        let keys = RecordKeys::derive(&secret, AeadAlgorithm::Aes128Gcm).unwrap();
        let content = b"HEARTBEAT_REQUEST body bytes go here";
        let content_type = 0x17;

        let ciphertext =
            keys.encrypt_record(0, &record_aad(content.len() + 17), content, content_type, 0);
        assert_eq!(ciphertext.len(), content.len() + 17);

        let (decrypted, ct) = keys
            .decrypt_record(0, &record_aad(ciphertext.len()), &ciphertext)
            .unwrap();
        assert_eq!(decrypted, content);
        assert_eq!(ct, content_type);
    }

    #[test]
    fn round_trip_chacha20poly1305_nonzero_sequence() {
        let secret = [0x99u8; 32];
        let keys = RecordKeys::derive(&secret, AeadAlgorithm::ChaCha20Poly1305).unwrap();
        let content = b"some later record, not the first";
        let seq = 42u64;

        let ciphertext =
            keys.encrypt_record(seq, &record_aad(content.len() + 17), content, 0x17, 0);
        let (decrypted, ct) = keys
            .decrypt_record(seq, &record_aad(ciphertext.len()), &ciphertext)
            .unwrap();
        assert_eq!(decrypted, content);
        assert_eq!(ct, 0x17);
    }

    #[test]
    fn wrong_sequence_number_fails_to_decrypt() {
        let secret = [0x11u8; 48]; // Aes256Gcm's suite uses SHA-384 (48-byte PRK)
        let keys = RecordKeys::derive(&secret, AeadAlgorithm::Aes256Gcm).unwrap();
        let content = b"payload";
        let ciphertext = keys.encrypt_record(5, &record_aad(content.len() + 17), content, 0x17, 0);

        let result = keys.decrypt_record(6, &record_aad(ciphertext.len()), &ciphertext);
        assert!(
            result.is_err(),
            "decrypting with the wrong sequence number (wrong nonce) must fail, not silently succeed"
        );
    }

    #[test]
    fn key_and_iv_lengths_match_algorithm() {
        let secret = [0x55u8; 48];
        let k128 = RecordKeys::derive(&secret, AeadAlgorithm::Aes128Gcm).unwrap();
        assert_eq!(k128.key.len(), 16);
        let k256 = RecordKeys::derive(&secret, AeadAlgorithm::Aes256Gcm).unwrap();
        assert_eq!(k256.key.len(), 32);
        let kchacha = RecordKeys::derive(&secret, AeadAlgorithm::ChaCha20Poly1305).unwrap();
        assert_eq!(kchacha.key.len(), 32);
    }

    #[test]
    fn derive_returns_none_instead_of_panicking_on_a_too_short_secret() {
        let secret_32 = [0x33u8; 32];
        assert!(RecordKeys::derive(&secret_32, AeadAlgorithm::Aes256Gcm).is_none());
        assert!(RecordKeys::derive(&secret_32, AeadAlgorithm::Aes128Gcm).is_some());
        assert!(RecordKeys::derive(&secret_32, AeadAlgorithm::ChaCha20Poly1305).is_some());
    }

    #[test]
    fn padding_is_fully_stripped_from_plaintext() {
        let secret = [0x77u8; 32];
        let keys = RecordKeys::derive(&secret, AeadAlgorithm::Aes128Gcm).unwrap();
        let content = b"short body, padded out by the original sender";
        let padding_len = 24;
        let aad = record_aad(content.len() + 1 + padding_len + 16);
        let ciphertext = keys.encrypt_record(0, &aad, content, 0x17, padding_len);

        let (decrypted, ct) = keys
            .decrypt_record(0, &record_aad(ciphertext.len()), &ciphertext)
            .unwrap();
        assert_eq!(
            decrypted, content,
            "padding must be fully stripped from the returned plaintext"
        );
        assert_eq!(ct, 0x17);
    }
}

// Cross-checked, in the reference implementation this was ported from (`pcapzip`), against a
// real TLS 1.3 handshake driven by `rustls`. tlscap's own end-to-end tests (see
// `tests/orchestrator_tests.rs`, once built) re-establish that same cross-check independently
// rather than assuming correctness carries over from a different crate.
