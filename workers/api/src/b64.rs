//! Shared unpadded-base64url over the `base64` crate (F-HARD-01).
//!
//! The vault, auth and session modules previously each hand-rolled this
//! encoding; the copies are deleted in favor of this single helper. Pure
//! Rust, `wasm32`-compatible like the existing `aes-gcm`/`hmac`/`sha2`
//! dependencies. Everything decoded through here is GCM-authenticated or
//! HMAC-verified by the caller — decoding never authenticates.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

/// Encode bytes as unpadded base64url.
pub fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decode unpadded base64url. Rejects non-alphabet bytes, padding (`=`)
/// and malformed trailing quanta; callers map the error to their own
/// generic error type (never echo input or crypto details).
pub fn decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    URL_SAFE_NO_PAD.decode(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_all_lengths() {
        // Every residue class mod 3, plus empty and multi-block.
        for len in 0..=64usize {
            let bytes: Vec<u8> = (0..len as u8).map(|b| b.wrapping_mul(31)).collect();
            let encoded = encode(&bytes);
            assert_eq!(decode(&encoded).expect("round trip"), bytes);
            // Unpadded: no `=` ever emitted.
            assert!(!encoded.contains('='), "padding emitted for len {len}");
        }
    }

    #[test]
    fn known_vectors() {
        assert_eq!(encode(b""), "");
        assert_eq!(encode(b"f"), "Zg");
        assert_eq!(encode(b"fo"), "Zm8");
        assert_eq!(encode(b"foo"), "Zm9v");
        assert_eq!(decode("Zg").unwrap(), b"f");
        assert_eq!(decode("").unwrap(), b"");
    }

    #[test]
    fn rejects_non_alphabet_padding_and_truncated_lengths() {
        for bad in [
            "!!!", "a",     // length % 4 == 1 is unrepresentable
            "abcde", // length % 4 == 1
            "Zm9v=", // padding rejected (unpadded alphabet)
            "Zm9v==", "Zm+9", // standard-alphabet `+` rejected
            "Zm/9", // standard-alphabet `/` rejected
            "Zm 9", // whitespace rejected
            "Zm\n9",
        ] {
            assert!(decode(bad).is_err(), "accepted {bad:?}");
        }
    }
}
