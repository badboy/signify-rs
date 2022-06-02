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
//! ## Examples
//! A simple CLI that verifies some example data:
//! ```rust
#![doc = include_str!("../examples/basic.rs")]
//! ```
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

#[cfg(test)]
pub(crate) mod test_utils;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::StepperRng;

    const MSG: &[u8] = b"signify!!!";

    #[test]
    fn check_signature_roundtrip() {
        let mut rng = StepperRng::default();

        let secret_key = PrivateKey::generate(&mut rng, NewKeyOpts::NoEncryption).unwrap();
        let public_key = secret_key.public();
        let signature = secret_key.sign(MSG);

        assert_eq!(signature.signer_keynum(), public_key.keynum());

        assert!(public_key.verify(MSG, &signature).is_ok());
    }

    #[test]
    fn check_signature_mismatched_keynum() {
        let mut rng = StepperRng::default();

        let secret_key = PrivateKey::generate(&mut rng, NewKeyOpts::NoEncryption).unwrap();
        let public_key = secret_key.public();
        let mut signature = secret_key.sign(MSG);

        let wrong_keynum = KeyNumber::new([0u8; KeyNumber::LEN]);

        signature.keynum = wrong_keynum;

        assert_eq!(
            public_key.verify(MSG, &signature),
            Err(Error::MismatchedKey {
                expected: wrong_keynum,
                found: public_key.keynum()
            })
        )
    }

    #[test]
    fn check_malformed_publickey() {
        let mut rng = StepperRng::default();

        let secret_key = PrivateKey::generate(&mut rng, NewKeyOpts::NoEncryption).unwrap();
        let mut public_key = secret_key.public();
        let signature = secret_key.sign(MSG);

        // Mess the public key up so its not a curve point anymore.
        public_key.key = [
            136, 95, 131, 189, 208, 168, 196, 163, 180, 145, 35, 42, 113, 108, 172, 178, 62, 108,
            7, 205, 20, 215, 240, 50, 149, 237, 146, 32, 181, 180, 91, 255,
        ];

        assert_eq!(public_key.verify(MSG, &signature), Err(Error::BadSignature));
    }

    #[test]
    fn check_malformed_signature() {
        let mut rng = StepperRng::default();

        let secret_key = PrivateKey::generate(&mut rng, NewKeyOpts::NoEncryption).unwrap();
        let public_key = secret_key.public();
        let mut signature = secret_key.sign(MSG);

        let real_sig = signature.sig;

        // Make the signature fail the basic validations.
        signature.sig = [255u8; consts::SIG_LEN];

        assert_eq!(public_key.verify(MSG, &signature), Err(Error::BadSignature));

        signature.sig = real_sig;
        // Slightly modify the signature so that full verification fails.
        signature.sig[20] = 3;

        assert_eq!(public_key.verify(MSG, &signature), Err(Error::BadSignature));
    }
}
