//! Create cryptographic signatures for files and verify them.
//!
//! This is based on [signify], the OpenBSD tool to sign and verify signatures on files.
//! It is based on the [Ed25519 public-key signature system][ed25519] by Bernstein et al.
//!
//! `libsignify` can verify and create signatures that are interoperable with BSD signify.
//! You can read more about the ideas and concepts behind `signify` in [Securing OpenBSD From Us To You](https://www.openbsd.org/papers/bsdcan-signify.html).
//!
//! This crate is `#![no_std]` by default, but still relies on `liballoc` so your platform must
//! provide an allocator to use `libsignify`.
//!
//! To enable support for `std::error::Error`, enable the `std` feature.
//!
//! [signify]: https://github.com/aperezdc/signify
//! [ed25519]: https://ed25519.cr.yp.to/
#![warn(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![no_std]

extern crate alloc;

pub mod consts;
pub use consts::KeyNumber;

mod encoding;
pub use encoding::Codeable;

mod errors;
pub use errors::{Error, FormatError};

mod key;
pub use key::{NewKeyOpts, PrivateKey, PublicKey, Signature};

use ed25519_dalek::{Signer as _, Verifier as _};

impl PrivateKey {
    /// Signs a message with this secret key and returns the signature.
    pub fn sign(&self, msg: &[u8]) -> Signature {
        // This `unwrap` is erased in release mode.
        let keypair = ed25519_dalek::Keypair::from_bytes(self.complete_key.as_ref()).unwrap();
        let sig = keypair.sign(msg).to_bytes();
        Signature::new(self.keynum, sig)
    }
}

impl PublicKey {
    /// Use this key to verify that the provided signature for the given message
    /// is authentic.
    ///
    /// # Errors
    ///
    /// This method errors if this key's number didn't match the ID of the key
    /// which created the signature or if the signature couldn't be verified.
    pub fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), Error> {
        let current_keynum = self.keynum();
        let expected_keynum = signature.keynum;

        if expected_keynum != current_keynum {
            return Err(Error::MismatchedKey {
                expected: expected_keynum,
                found: current_keynum,
            });
        }

        // Both the key data and signature data are not verified yet,
        // so the ed25519 math can still go wrong.
        // In that case all we need to communicate is that it was a bad signature.

        let public_key =
            ed25519_dalek::PublicKey::from_bytes(&self.key()).map_err(|_| Error::BadSignature)?;
        let signature = ed25519_dalek::Signature::from_bytes(&signature.signature())
            .map_err(|_| Error::BadSignature)?;

        public_key
            .verify(msg, &signature)
            .map_err(|_| Error::BadSignature)
    }
}
