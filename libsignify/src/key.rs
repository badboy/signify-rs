use crate::consts::{KeyNumber, FULL_KEY_LEN, KDFALG, PKGALG, PUBLIC_KEY_LEN, SIG_LEN};
use crate::errors::Error;

use alloc::string::String;
use core::convert::TryInto;
use ed25519_dalek::{Digest, Sha512};
use rand_core::{CryptoRng, RngCore};
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

impl core::fmt::Debug for NewKeyOpts {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
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

struct UnencryptedKey(Zeroizing<[u8; FULL_KEY_LEN]>);

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

        let mut complete_key = {
            let skey = Zeroizing::new(key_pair.secret.to_bytes());
            let pkey = key_pair.public.to_bytes();

            let mut complete_key = Zeroizing::new([0u8; FULL_KEY_LEN]);
            complete_key[..32].copy_from_slice(skey.as_ref());
            complete_key[32..].copy_from_slice(&pkey);
            UnencryptedKey(complete_key)
        };

        let checksum = Self::calculate_checksum(&complete_key);

        let mut salt = [0; 16];
        rng.fill_bytes(&mut salt);

        let kdf_rounds = if let NewKeyOpts::Encrypted {
            passphrase,
            kdf_rounds,
        } = &derivation_info
        {
            let kdf_rounds = *kdf_rounds;
            Self::inner_kdf_mix(&mut complete_key.0[..32], kdf_rounds, &salt, passphrase)?;
            kdf_rounds
        } else {
            0
        };

        Ok(Self {
            public_key_alg: PKGALG,
            kdf_alg: KDFALG,
            kdf_rounds,
            salt,
            checksum,
            keynum,
            // The state of the key doesn't matter at this stage.
            complete_key: complete_key.0,
        })
    }

    /// Decrypts a secret key that was stored in encrypted form with the passphrase.
    ///
    /// # Errors
    ///
    /// This returns an error if the provided password was empty or if it failed to decrypt the key.
    pub fn decrypt_with_password(&mut self, passphrase: &str) -> Result<(), Error> {
        let mut encrypted_key = self.complete_key.clone(); // Cheap :)

        match Self::inner_kdf_mix(
            &mut encrypted_key[..32],
            self.kdf_rounds,
            &self.salt,
            passphrase,
        ) {
            Ok(_) => {
                // Since the decryption worked, its now "unencrypted", even if the passphrase was wrong
                // and the value is garbage.
                let decrypted_key = UnencryptedKey(encrypted_key);
                let current_checksum = Self::calculate_checksum(&decrypted_key);

                // Non-constant time is fine since checksum is public.
                if current_checksum != self.checksum {
                    return Err(Error::BadPassword);
                }

                // Confirmed the decryption worked, mutating the key structure.
                self.complete_key = decrypted_key.0;
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    fn calculate_checksum(complete_key: &UnencryptedKey) -> [u8; 8] {
        let digest = Sha512::digest(complete_key.0.as_ref());
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
    use crate::consts::DEFAULT_KDF_ROUNDS;
    use crate::test_utils::StepperRng;

    use super::*;
    use alloc::string::ToString;
    use core::fmt::Debug;
    use core::hash::Hash;
    use static_assertions::assert_impl_all;

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

    const PASSPHRASE: &str = "muchsecret";

    #[test]
    fn check_key_generation_passphrase_concealment() {
        let new_opts = NewKeyOpts::Encrypted {
            passphrase: PASSPHRASE.to_string(),
            kdf_rounds: DEFAULT_KDF_ROUNDS,
        };
        let debug_output = alloc::format!("{:?}", new_opts);
        assert!(!debug_output.contains(PASSPHRASE));
    }

    #[test]
    fn check_simple_private_key_getters() {
        let mut rng = StepperRng::default();
        let unencrypted_key = PrivateKey::generate(&mut rng, NewKeyOpts::NoEncryption).unwrap();

        assert_eq!(
            unencrypted_key.public().key(),
            unencrypted_key.complete_key[32..]
        ); // Ed25519 keys are private || public.

        assert!(!unencrypted_key.is_encrypted());

        let encrypted_key = PrivateKey::generate(
            &mut rng,
            NewKeyOpts::Encrypted {
                passphrase: PASSPHRASE.to_string(),
                kdf_rounds: DEFAULT_KDF_ROUNDS,
            },
        )
        .unwrap();
        assert!(encrypted_key.is_encrypted());
    }

    #[test]
    fn check_key_generation_opts() {
        let mut rng = StepperRng::default();
        let unencrypted_key = PrivateKey::generate(&mut rng, NewKeyOpts::NoEncryption).unwrap();
        assert_eq!(unencrypted_key.kdf_rounds, 0); // `0` represents not encrypted.
        assert_eq!(unencrypted_key.kdf_alg, KDFALG);
        assert_eq!(unencrypted_key.public_key_alg, PKGALG);

        let encrypted_key_1 = PrivateKey::generate(
            &mut rng,
            NewKeyOpts::Encrypted {
                passphrase: PASSPHRASE.to_string(),
                kdf_rounds: DEFAULT_KDF_ROUNDS,
            },
        )
        .unwrap();
        assert_eq!(encrypted_key_1.kdf_rounds, DEFAULT_KDF_ROUNDS);
        assert_eq!(encrypted_key_1.kdf_alg, KDFALG);
        assert_eq!(encrypted_key_1.public_key_alg, PKGALG);

        // Check non-standard KDF rounds are respected.
        let encrypted_key_2 = PrivateKey::generate(
            &mut rng,
            NewKeyOpts::Encrypted {
                passphrase: PASSPHRASE.to_string(),
                kdf_rounds: 7,
            },
        )
        .unwrap();
        assert_eq!(encrypted_key_2.kdf_rounds, 7);
        assert_eq!(encrypted_key_1.kdf_alg, KDFALG);
        assert_eq!(encrypted_key_2.public_key_alg, PKGALG);

        // Salts should be random.
        assert_ne!(encrypted_key_1.salt, encrypted_key_2.salt);
        // Key numbers should be unique.
        assert_ne!(encrypted_key_1.keynum, encrypted_key_2.keynum);
        // The keys themselves should be random and unique.
        assert_ne!(encrypted_key_1.complete_key, encrypted_key_2.complete_key);
        assert_ne!(encrypted_key_1.checksum, encrypted_key_2.checksum);
    }

    struct ConstantRng;

    impl ConstantRng {
        const VALUE: u8 = 3;
    }

    impl rand_core::RngCore for ConstantRng {
        fn next_u32(&mut self) -> u32 {
            Self::VALUE.into()
        }

        fn next_u64(&mut self) -> u64 {
            Self::VALUE.into()
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for b in dest {
                *b = Self::VALUE;
            }
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            for b in dest {
                *b = Self::VALUE;
            }

            Ok(())
        }
    }

    impl rand_core::CryptoRng for ConstantRng {}

    #[test]
    fn check_key_encryption_roundtrip() {
        const ACTUAL_KEY: [u8; 32] = [ConstantRng::VALUE; 32];
        let mut rng = ConstantRng;

        let mut encrypted_key = PrivateKey::generate(
            &mut rng,
            NewKeyOpts::Encrypted {
                passphrase: PASSPHRASE.to_string(),
                kdf_rounds: DEFAULT_KDF_ROUNDS,
            },
        )
        .unwrap();

        // Easy check that its actually being encrypted when requested.
        assert_ne!(encrypted_key.complete_key.as_ref()[..32], ACTUAL_KEY);

        // ... and then make sure it properly decrypts.
        encrypted_key.decrypt_with_password(PASSPHRASE).unwrap();
        assert_eq!(encrypted_key.complete_key.as_ref()[..32], ACTUAL_KEY);
    }

    #[test]
    fn check_wrong_passphrase_errors() {
        let mut rng = StepperRng::default();
        let mut encrypted_key = PrivateKey::generate(
            &mut rng,
            NewKeyOpts::Encrypted {
                passphrase: PASSPHRASE.to_string(),
                kdf_rounds: DEFAULT_KDF_ROUNDS,
            },
        )
        .unwrap();

        assert!(matches!(
            encrypted_key.decrypt_with_password("wrong"),
            Err(Error::BadPassword)
        ));
    }
}
