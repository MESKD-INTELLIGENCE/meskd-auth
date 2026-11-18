use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use zeroize::Zeroize;

use crate::entry::Algorithm;

macro_rules! mac {
    ($hash:ty, $key:expr, $message:expr) => {{
        let mut mac =
            <Hmac<$hash> as KeyInit>::new_from_slice($key).expect("hmac accepts any key length");
        mac.update($message);
        mac.finalize().into_bytes().to_vec()
    }};
}

pub fn hotp(secret: &[u8], counter: u64, algorithm: Algorithm, digits: u32) -> String {
    let message = counter.to_be_bytes();
    let mut digest = match algorithm {
        Algorithm::Sha1 => mac!(Sha1, secret, &message),
        Algorithm::Sha256 => mac!(Sha256, secret, &message),
        Algorithm::Sha512 => mac!(Sha512, secret, &message),
    };
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let binary = u32::from_be_bytes([
        digest[offset] & 0x7f,
        digest[offset + 1],
        digest[offset + 2],
        digest[offset + 3],
    ]);
    digest.zeroize();
    let code = u64::from(binary) % 10u64.pow(digits);
    format!("{code:0width$}", width = digits as usize)
}

pub fn totp(
    secret: &[u8],
    unix_time: u64,
    period: u32,
    algorithm: Algorithm,
    digits: u32,
) -> String {
    hotp(
        secret,
        unix_time / u64::from(period.max(1)),
        algorithm,
        digits,
    )
}

pub fn seconds_left(unix_time: u64, period: u32) -> u32 {
    let period = u64::from(period.max(1));
    (period - unix_time % period) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED_SHA1: &[u8] = b"12345678901234567890";
    const SEED_SHA256: &[u8] = b"12345678901234567890123456789012";
    const SEED_SHA512: &[u8] = b"1234567890123456789012345678901234567890123456789012345678901234";

    #[test]
    fn rfc4226_hotp_vectors() {
        let expected = [
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
        ];
        for (counter, code) in expected.iter().enumerate() {
            assert_eq!(hotp(SEED_SHA1, counter as u64, Algorithm::Sha1, 6), *code);
        }
    }

    #[test]
    fn rfc6238_totp_vectors() {
        let cases: [(u64, &str, &str, &str); 6] = [
            (59, "94287082", "46119246", "90693936"),
            (1111111109, "07081804", "68084774", "25091201"),
            (1111111111, "14050471", "67062674", "99943326"),
            (1234567890, "89005924", "91819424", "93441116"),
            (2000000000, "69279037", "90698825", "38618901"),
            (20000000000, "65353130", "77737706", "47863826"),
        ];
        for (time, sha1, sha256, sha512) in cases {
            assert_eq!(totp(SEED_SHA1, time, 30, Algorithm::Sha1, 8), sha1);
            assert_eq!(totp(SEED_SHA256, time, 30, Algorithm::Sha256, 8), sha256);
            assert_eq!(totp(SEED_SHA512, time, 30, Algorithm::Sha512, 8), sha512);
        }
    }

    #[test]
    fn codes_keep_leading_zeros() {
        assert_eq!(
            totp(SEED_SHA1, 1111111109, 30, Algorithm::Sha1, 8),
            "07081804"
        );
        assert_eq!(
            totp(SEED_SHA1, 1111111109, 30, Algorithm::Sha1, 6),
            "081804"
        );
    }

    #[test]
    fn seconds_left_counts_down_to_the_next_step() {
        assert_eq!(seconds_left(0, 30), 30);
        assert_eq!(seconds_left(1, 30), 29);
        assert_eq!(seconds_left(29, 30), 1);
        assert_eq!(seconds_left(30, 30), 30);
        assert_eq!(seconds_left(61, 60), 59);
    }

    #[test]
    fn short_and_long_keys_are_accepted() {
        assert_eq!(hotp(b"k", 0, Algorithm::Sha1, 6).len(), 6);
        assert_eq!(hotp(&[7u8; 200], 0, Algorithm::Sha512, 8).len(), 8);
    }
}
