use std::convert::TryInto;
use std::io::prelude::*;
use std::io::Cursor;

use crate::errors::Result;

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use ed25519_dalek::{
    Digest, Keypair, PublicKey as Ed25519PublicKey, Sha512, Signature as Ed25519Signature,
    Signer as _, Verifier as _,
};
use rand_core::{OsRng, RngCore};

const KEYNUM_LEN: usize = 8;
type KeyNumber = [u8; KEYNUM_LEN];

const PUBLICBYTES: usize = 32;
const SECRETBYTES: usize = 64;
const SIG_LEN: usize = 64;

pub const PKGALG: [u8; 2] = *b"Ed";
const KDFALG: [u8; 2] = *b"BK";

pub const COMMENTHDR: &str = "untrusted comment: ";
pub const COMMENTMAX_LEN: usize = 1024;

pub struct PublicKey {
    pub keynum: KeyNumber,
    key: [u8; PUBLICBYTES],
}

pub struct PrivateKey {
    public_key_alg: [u8; 2],
    kdf_alg: [u8; 2],
    kdf_rounds: u32,
    salt: [u8; 16],
    checksum: [u8; 8],
    keynum: KeyNumber,
    complete_key: [u8; SECRETBYTES],
}

pub struct Signature {
    pub keynum: [u8; KEYNUM_LEN],
    sig: [u8; SIG_LEN],
}

impl PublicKey {
    pub fn write<W: Write>(&self, mut w: W) -> Result<()> {
        w.write_all(&PKGALG)?;
        w.write_all(&self.keynum)?;
        w.write_all(&self.key)?;

        Ok(())
    }

    pub fn from_buf(buf: &[u8]) -> Result<PublicKey> {
        let mut buf = Cursor::new(buf);

        let mut _pkgalg = [0; 2];
        let mut keynum = [0; KEYNUM_LEN];
        let mut public_key = [0; PUBLICBYTES];

        buf.read_exact(&mut _pkgalg)?;
        buf.read_exact(&mut keynum)?;
        buf.read_exact(&mut public_key)?;

        Ok(PublicKey {
            keynum,
            key: public_key,
        })
    }
}

pub enum NewKeyOpts {
    NoEncryption,
    Encrypted { passphrase: String, kdf_rounds: u32 },
}

impl PrivateKey {
    pub fn new(derivation_info: NewKeyOpts) -> Result<Self> {
        let mut rng = OsRng;

        let mut keynum = [0u8; KEYNUM_LEN];
        rng.fill_bytes(&mut keynum);

        let key_pair = Keypair::generate(&mut rng);

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

        let mut complete_key = [0u8; SECRETBYTES];
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

    pub fn kdf_mix(&mut self, passphrase: &str) -> Result<()> {
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
    ) -> Result<()> {
        if rounds == 0 {
            return Ok(());
        }

        let mut xorkey = [0; SECRETBYTES];

        bcrypt_pbkdf::bcrypt_pbkdf(passphrase, salt, rounds, &mut xorkey)?;

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

    pub fn write<W: Write>(&self, mut w: W) -> Result<()> {
        w.write_all(&self.public_key_alg)?;
        w.write_all(&self.kdf_alg)?;
        w.write_u32::<BigEndian>(self.kdf_rounds)?;
        w.write_all(&self.salt)?;
        w.write_all(&self.checksum)?;
        w.write_all(&self.keynum)?;
        w.write_all(&self.complete_key)?;

        Ok(())
    }

    pub fn from_buf(buf: &[u8]) -> Result<PrivateKey> {
        let mut buf = Cursor::new(buf);

        let mut public_key_alg = [0; 2];
        let mut kdf_alg = [0; 2];
        let mut salt = [0; 16];
        let mut checksum = [0; 8];
        let mut keynum = [0; KEYNUM_LEN];
        let mut complete_key = [0; SECRETBYTES];

        buf.read_exact(&mut public_key_alg)?;
        buf.read_exact(&mut kdf_alg)?;
        let kdf_rounds = buf.read_u32::<BigEndian>()?;
        buf.read_exact(&mut salt)?;
        buf.read_exact(&mut checksum)?;
        buf.read_exact(&mut keynum)?;
        buf.read_exact(&mut complete_key)?;

        Ok(PrivateKey {
            public_key_alg,
            kdf_alg,
            kdf_rounds,
            salt,
            checksum,
            keynum,
            complete_key,
        })
    }

    pub fn sign(&self, msg: &[u8]) -> Result<Signature> {
        let keypair = Keypair::from_bytes(&self.complete_key).unwrap();
        let sig = keypair.sign(msg).to_bytes();
        Ok(Signature {
            keynum: self.keynum,
            sig,
        })
    }
}

impl Signature {
    pub fn write<W: Write>(&self, mut w: W) -> Result<()> {
        w.write_all(&PKGALG)?;
        w.write_all(&self.keynum)?;
        w.write_all(&self.sig)?;

        Ok(())
    }

    pub fn from_buf(buf: &[u8]) -> Result<Signature> {
        let mut buf = Cursor::new(buf);

        let mut _pkgalg = [0; 2];
        let mut keynum = [0; KEYNUM_LEN];
        let mut sig = [0; SIG_LEN];

        buf.read_exact(&mut _pkgalg)?;
        buf.read_exact(&mut keynum)?;
        buf.read_exact(&mut sig)?;

        Ok(Signature { keynum, sig })
    }

    pub fn verify(&self, msg: &[u8], public_key: &PublicKey) -> bool {
        let public_key = Ed25519PublicKey::from_bytes(&public_key.key).unwrap();
        let signature = Ed25519Signature::new(self.sig);

        public_key.verify(msg, &signature).is_ok()
    }
}
