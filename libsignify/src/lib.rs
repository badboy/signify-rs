//! Create cryptographic signatures for files and verify them.
//!
//! This is based on [signify], the OpenBSD tool to sign and verify signatures on files.
//! It is based on the [Ed25519 public-key signature system][ed25519] by Bernstein et al.
//!
//! `libsignify` can verify and create signatures that are interoperable with BSD signify.
//! You can read more about the ideas and concepts behind `signify` in [Securing OpenBSD From Us To You](https://www.openbsd.org/papers/bsdcan-signify.html).
//!
//! [signify]: https://github.com/aperezdc/signify
//! [ed25519]: https://ed25519.cr.yp.to/
#![warn(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

pub mod consts;
pub use consts::KeyNumber;

mod encoding;
pub use encoding::Codeable;

mod errors;
pub use errors::{Error, FormatError};

mod key;
pub use key::{NewKeyOpts, PrivateKey, PublicKey, Signature};

use ed25519_dalek::{Keypair, Signer as _, Verifier as _};

impl PrivateKey {
    /// Signs a message with this secret key and returns the signature.
    pub fn sign(&self, msg: &[u8]) -> Signature {
        // This `unwrap` is erased in release mode.
        let keypair = Keypair::from_bytes(&self.complete_key).unwrap();
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

        let public_key = ed25519_dalek::PublicKey::from_bytes(&self.key()).unwrap();
        let signature = ed25519_dalek::Signature::new(signature.signature());

        public_key
            .verify(msg, &signature)
            .map_err(|_| Error::BadSignature)
    }
}
