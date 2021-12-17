//! Constants and type definitions from the `signify` design.

use rand_core::RngCore;

/// A number identifying a certain signing keypair.
///
/// A short and easy to read [8 byte] digest of the key.
///
/// [8 byte]: Self::LEN
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct KeyNumber([u8; Self::LEN]);

impl KeyNumber {
    /// The length of the key number, in bytes (8).
    pub const LEN: usize = 8;

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

/// The recommended number of KDF rounds to use when encrypting new secret keys.
///
/// This value was selected to mirror the [OpenBSD implementation]'s choice.
///
/// [OpenBSD implementation]: https://github.com/aperezdc/signify/blob/fa123eda2774c38abf98e43946baf604df85aea0/signify.c#L875
pub const DEFAULT_KDF_ROUNDS: u32 = 42;

#[cfg(test)]
mod tests {
    use super::KeyNumber;
    use std::fmt::Debug;
    use std::hash::Hash;

    static_assertions::assert_impl_all!(
        KeyNumber: Clone,
        Copy,
        Debug,
        PartialEq,
        Eq,
        Hash,
        Ord,
        PartialOrd,
        Send,
        Sync
    );
}
