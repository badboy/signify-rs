//! Constants and type definitions from the `signify` design.

use rand_core::RngCore;

const KEYNUM_LEN: usize = 8;

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct KeyNumber([u8; KEYNUM_LEN]);

impl KeyNumber {
    pub const LEN: usize = KEYNUM_LEN;

    pub(crate) fn new(num: [u8; Self::LEN]) -> Self {
        Self(num)
    }

    pub(crate) fn generate<R: RngCore>(rng: &mut R) -> Self {
        let mut num = [0u8; Self::LEN];
        rng.fill_bytes(&mut num);
        Self(num)
    }
}

impl AsRef<[u8]> for KeyNumber {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

pub(crate) const PUBLIC_KEY_LEN: usize = 32;
pub(crate) const FULL_KEY_LEN: usize = 64;
pub(crate) const SIG_LEN: usize = 64;

pub(crate) const PKGALG: [u8; 2] = *b"Ed";
pub(crate) const KDFALG: [u8; 2] = *b"BK";

pub(crate) const COMMENT_HEADER: &str = "untrusted comment: ";
pub(crate) const COMMENT_MAX_LEN: usize = 1024;

pub const DEFAULT_KDF_ROUNDS: u32 = 42;
