use crate::consts::{KeyNumber, FULL_KEY_LEN, KDFALG, PKGALG, PUBLIC_KEY_LEN, SIG_LEN};
use crate::errors::Error;

use ed25519_dalek::{Digest, Sha512};
use rand_core::{CryptoRng, RngCore};
use std::convert::TryInto;
use std::ops::DerefMut;
use zeroize::{Zeroize, Zeroizing};

/// The public half of a keypair.
///
/// You will need this if you are trying to verify a signature.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct PublicKey {
    pub(crate) keynum: KeyNumber,
    pub(crate) key: [u8; PUBLIC_KEY_LEN],
}

impl PublicKey {
    /// The public key's bytes.
    pub fn key(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.key
    }

    /// The public key's identifying number.
    pub fn keynum(&self) -> KeyNumber {
        self.keynum
    }
}

/// Key derivation options available when creating a new key.
#[derive(Clone)]
pub enum NewKeyOpts {
    /// Don't encrypt the secret key.
    NoEncryption,
    /// Encrypt the secret key with a passphrase.
    Encrypted {
        /// Passphrase to encrypt the key with.
        passphrase: String,
        /// The number of key derivation rounds to apply to the password.
        ///
        /// If you're unsure of what this should be set to, use [the default].
        ///
        /// [the default]: crate::consts::DEFAULT_KDF_ROUNDS
        kdf_rounds: u32,
    },
}

impl Drop for NewKeyOpts {
    fn drop(&mut self) {
        if let NewKeyOpts::Encrypted { passphrase, .. } = self {
            passphrase.zeroize();
        }
    }
}

impl std::fmt::Debug for NewKeyOpts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoEncryption => f.write_str("NoEncryption"),
            Self::Encrypted { kdf_rounds, .. } => f
                .debug_struct("Encrypted")
                .field("passphrase", &"<concealed>")
                .field("kdf_rounds", kdf_rounds)
                .finish(),
        }
    }
}

/// The full secret keypair.
///
/// You will need this if you want to create signatures.
#[derive(Clone)]
#[cfg_attr(test, derive(Debug, PartialEq))] // Makes the encoding tests nicer.
pub struct PrivateKey {
    pub(crate) public_key_alg: [u8; 2],
    pub(crate) kdf_alg: [u8; 2],
    pub(crate) kdf_rounds: u32,
    pub(crate) salt: [u8; 16],
    pub(crate) checksum: [u8; 8],
    pub(super) keynum: KeyNumber,
    pub(super) complete_key: Zeroizing<[u8; FULL_KEY_LEN]>,
}

impl PrivateKey {
    /// Generates a new random secret (private) key with the provided options.
    ///
    /// # Errors
    ///
    /// This only returns an error if the provided password was empty.
    pub fn generate<R: CryptoRng + RngCore>(
        rng: &mut R,
        derivation_info: NewKeyOpts,
    ) -> Result<Self, Error> {
        let keynum = KeyNumber::generate(rng);

        let key_pair = ed25519_dalek::Keypair::generate(rng);

        let mut skey = Zeroizing::new(key_pair.secret.to_bytes());
        let pkey = key_pair.public.to_bytes();

        let mut salt = [0; 16];
        rng.fill_bytes(&mut salt);

        let kdf_rounds = if let NewKeyOpts::Encrypted {
            passphrase,
            kdf_rounds,
        } = &derivation_info
        {
            let kdf_rounds = *kdf_rounds;
            Self::inner_kdf_mix(skey.deref_mut(), kdf_rounds, &salt, passphrase)?;
            kdf_rounds
        } else {
            0
        };

        let mut complete_key = Zeroizing::new([0u8; FULL_KEY_LEN]);
        complete_key[32..].copy_from_slice(&pkey);
        complete_key[..32].copy_from_slice(skey.as_ref());

        let checksum = Self::calculate_checksum(&complete_key);

        Ok(Self {
            public_key_alg: PKGALG,
            kdf_alg: KDFALG,
            kdf_rounds,
            salt,
            checksum,
            keynum,
            complete_key,
        })
    }

    /// Decrypts a secret key that was stored in encrypted form with the passphrase.
    ///
    /// # Errors
    ///
    /// This returns an error if the provided password was empty or if it failed to decrypt the key.
    ///
    /// The wrong password does not cause an error, but instead yields an incorrect key.
    pub fn decrypt_with_password(&mut self, passphrase: &str) -> Result<(), Error> {
        let mut encrypted_key = self.complete_key.clone(); // Cheap :)

        match Self::inner_kdf_mix(
            &mut encrypted_key[..],
            self.kdf_rounds,
            &self.salt,
            passphrase,
        ) {
            Ok(_) => {
                let current_checksum = Self::calculate_checksum(&encrypted_key);

                // Non-constant time is fine since checksum is public.
                if current_checksum != self.checksum {
                    return Err(Error::BadPassword);
                }

                self.complete_key = encrypted_key;
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    fn calculate_checksum(complete_key: &[u8; FULL_KEY_LEN]) -> [u8; 8] {
        let digest = Sha512::digest(complete_key);
        let mut checksum = [0; 8];
        checksum.copy_from_slice(&digest.as_ref()[0..8]);
        checksum
    }

    fn inner_kdf_mix(
        secret_key: &mut [u8],
        rounds: u32,
        salt: &[u8],
        passphrase: &str,
    ) -> Result<(), Error> {
        if rounds == 0 {
            return Ok(());
        }

        let mut xorkey = [0; FULL_KEY_LEN];

        bcrypt_pbkdf::bcrypt_pbkdf(passphrase, salt, rounds, &mut xorkey)
            .map_err(|_| Error::BadPassword)?;

        for (prv, xor) in secret_key.iter_mut().zip(xorkey.iter()) {
            *prv ^= xor;
        }

        Ok(())
    }

    /// Returns the public half of this secret keypair.
    pub fn public(&self) -> PublicKey {
        // This `unwrap()` gets erased in release mode.
        PublicKey {
            key: self.complete_key[32..].try_into().unwrap(),
            keynum: self.keynum,
        }
    }

    /// Returns if this key was stored encrypted.
    pub fn is_encrypted(&self) -> bool {
        self.kdf_rounds != 0
    }
}

/// A signature
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Signature {
    pub(crate) keynum: KeyNumber,
    pub(crate) sig: [u8; SIG_LEN],
}

impl Signature {
    /// The ID of the keypair which created this signature.
    ///
    /// This is useful to determine if you have the right key to verify a signature.
    pub fn signer_keynum(&self) -> KeyNumber {
        self.keynum
    }

    /// Returns the signature's raw bytes.
    pub fn signature(&self) -> [u8; SIG_LEN] {
        self.sig
    }

    pub(super) fn new(keynum: KeyNumber, sig: [u8; SIG_LEN]) -> Self {
        Self { keynum, sig }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use static_assertions::assert_impl_all;
    use std::fmt::Debug;
    use std::hash::Hash;

    assert_impl_all!(
        PublicKey: Clone,
        Copy,
        Debug,
        Eq,
        PartialEq,
        Hash,
        Send,
        Sync
    );

    assert_impl_all!(PrivateKey: Clone, Send, Sync);

    assert_impl_all!(NewKeyOpts: Clone, Debug, Send, Sync);

    assert_impl_all!(
        Signature: Clone,
        Copy,
        Debug,
        Eq,
        PartialEq,
        Hash,
        Send,
        Sync
    );
}
