use crate::consts::{KeyNumber, FULL_KEY_LEN, KDFALG, PKGALG, PUBLIC_KEY_LEN, SIG_LEN};
use crate::errors::Error;

use ed25519_dalek::{Digest, Keypair, Sha512};
use rand_core::{CryptoRng, RngCore};
use std::convert::TryInto;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PublicKey {
    pub(crate) keynum: KeyNumber,
    pub(crate) key: [u8; PUBLIC_KEY_LEN],
}

impl PublicKey {
    pub fn key(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.key
    }

    pub fn keynum(&self) -> KeyNumber {
        self.keynum
    }
}

#[derive(Clone)]
pub enum NewKeyOpts {
    NoEncryption,
    Encrypted { passphrase: String, kdf_rounds: u32 },
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

#[derive(Clone)]
pub struct PrivateKey {
    pub(crate) public_key_alg: [u8; 2],
    pub(crate) kdf_alg: [u8; 2],
    pub(crate) kdf_rounds: u32,
    pub(crate) salt: [u8; 16],
    pub(crate) checksum: [u8; 8],
    pub(super) keynum: KeyNumber,
    pub(super) complete_key: [u8; FULL_KEY_LEN],
}

impl PrivateKey {
    pub fn derive<R: CryptoRng + RngCore>(
        rng: &mut R,
        derivation_info: NewKeyOpts,
    ) -> Result<Self, Error> {
        let keynum = KeyNumber::generate(rng);

        let key_pair = Keypair::generate(rng);

        let mut skey = key_pair.secret.to_bytes();
        let pkey = key_pair.public.to_bytes();

        let mut salt = [0; 16];
        rng.fill_bytes(&mut salt);

        let kdf_rounds = if let NewKeyOpts::Encrypted {
            passphrase,
            kdf_rounds,
        } = derivation_info
        {
            Self::inner_kdf_mix(&mut skey, kdf_rounds, &salt, &passphrase)?;
            kdf_rounds
        } else {
            0
        };

        let mut complete_key = [0u8; FULL_KEY_LEN];
        complete_key[32..].copy_from_slice(&pkey);
        complete_key[..32].copy_from_slice(&skey);

        let digest = Sha512::digest(&complete_key);
        let mut checksum = [0; 8];
        checksum.copy_from_slice(&digest.as_ref()[0..8]);

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

    pub fn decrypt_with_password(&mut self, passphrase: &str) -> Result<(), Error> {
        Self::inner_kdf_mix(
            &mut self.complete_key,
            self.kdf_rounds,
            &self.salt,
            passphrase,
        )
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

    pub fn public(&self) -> PublicKey {
        // This `unwrap()` gets erased in release mode.
        PublicKey {
            key: self.complete_key[32..].try_into().unwrap(),
            keynum: self.keynum,
        }
    }

    pub fn is_encrypted(&self) -> bool {
        self.kdf_rounds != 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Signature {
    pub(crate) keynum: KeyNumber,
    pub(crate) sig: [u8; SIG_LEN],
}

impl Signature {
    pub fn signer_keynum(&self) -> KeyNumber {
        self.keynum
    }

    pub fn signature(&self) -> [u8; SIG_LEN] {
        self.sig
    }

    pub(super) fn new(keynum: KeyNumber, sig: [u8; SIG_LEN]) -> Self {
        Self { keynum, sig }
    }
}
