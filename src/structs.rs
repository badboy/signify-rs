use std::io::prelude::*;
use std::io::Cursor;
use std::mem;

use crate::errors::*;

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

use ring::signature::{self, Ed25519KeyPair};

pub const KEYNUMLEN: usize = 8;
pub const PUBLICBYTES: usize = 32;
pub const SECRETBYTES: usize = 64;
pub const SIGBYTES: usize = 64;

pub const PKGALG: [u8; 2] = *b"Ed";
pub const KDFALG: [u8; 2] = *b"BK";

pub const COMMENTHDR: &str = "untrusted comment: ";
pub const COMMENTHDRLEN: usize = 19;
pub const COMMENTMAXLEN: usize = 1024;

pub struct PublicKey {
    pkgalg: [u8; 2],
    pub keynum: [u8; KEYNUMLEN],
    publkey: [u8; PUBLICBYTES],
}

pub struct PrivateKey {
    pub pkgalg: [u8; 2],
    pub kdfalg: [u8; 2],
    pub kdfrounds: u32,
    pub salt: [u8; 16],
    pub checksum: [u8; 8],
    pub keynum: [u8; KEYNUMLEN],
    pub seckey: [u8; SECRETBYTES],
}

pub struct Signature {
    pkgalg: [u8; 2],
    pub keynum: [u8; KEYNUMLEN],
    sig: [u8; SIGBYTES],
}

impl PublicKey {
    pub fn with_key_and_keynum(key: [u8; PUBLICBYTES], keynum: [u8; KEYNUMLEN]) -> PublicKey {
        PublicKey {
            pkgalg: PKGALG,
            keynum,
            publkey: key,
        }
    }

    pub fn write<W: Write>(&self, mut w: W) -> Result<()> {
        w.write_all(&self.pkgalg)?;
        w.write_all(&self.keynum)?;
        w.write_all(&self.publkey)?;

        Ok(())
    }

    pub fn from_buf(buf: &[u8]) -> Result<PublicKey> {
        assert!(buf.len() >= mem::size_of::<Self>());

        let mut buf = Cursor::new(buf);

        let mut pkgalg = [0; 2];
        let mut keynum = [0; KEYNUMLEN];
        let mut publkey = [0; PUBLICBYTES];

        buf.read_exact(&mut pkgalg)?;
        buf.read_exact(&mut keynum)?;
        buf.read_exact(&mut publkey)?;

        Ok(PublicKey {
            pkgalg,
            keynum,
            publkey,
        })
    }
}

impl PrivateKey {
    pub fn write<W: Write>(&self, mut w: W) -> Result<()> {
        w.write_all(&self.pkgalg)?;
        w.write_all(&self.kdfalg)?;
        w.write_u32::<BigEndian>(self.kdfrounds)?;
        w.write_all(&self.salt)?;
        w.write_all(&self.checksum)?;
        w.write_all(&self.keynum)?;
        w.write_all(&self.seckey)?;

        Ok(())
    }

    pub fn from_buf(buf: &[u8]) -> Result<PrivateKey> {
        assert!(buf.len() >= mem::size_of::<Self>());

        let mut buf = Cursor::new(buf);

        let mut pkgalg = [0; 2];
        let mut kdfalg = [0; 2];
        let kdfrounds;
        let mut salt = [0; 16];
        let mut checksum = [0; 8];
        let mut keynum = [0; KEYNUMLEN];
        let mut seckey = [0; SECRETBYTES];

        buf.read_exact(&mut pkgalg)?;
        buf.read_exact(&mut kdfalg)?;
        kdfrounds = buf.read_u32::<BigEndian>()?;
        buf.read_exact(&mut salt)?;
        buf.read_exact(&mut checksum)?;
        buf.read_exact(&mut keynum)?;
        buf.read_exact(&mut seckey)?;

        Ok(PrivateKey {
            pkgalg,
            kdfalg,
            kdfrounds,
            salt,
            checksum,
            keynum,
            seckey,
        })
    }

    pub fn sign(&self, msg: &[u8]) -> Result<Signature> {
        let seed = &self.seckey[0..32];
        let pubkey = &self.seckey[32..];
        let keypair = Ed25519KeyPair::from_seed_and_public_key(seed, pubkey)?;
        let signature = keypair.sign(msg);
        let mut sig = [0; 64];
        sig.copy_from_slice(signature.as_ref());
        Ok(Signature {
            pkgalg: PKGALG,
            keynum: self.keynum,
            sig,
        })
    }
}

impl Signature {
    pub fn write<W: Write>(&self, mut w: W) -> Result<()> {
        w.write_all(&self.pkgalg)?;
        w.write_all(&self.keynum)?;
        w.write_all(&self.sig)?;

        Ok(())
    }

    pub fn from_buf(buf: &[u8]) -> Result<Signature> {
        assert!(buf.len() >= mem::size_of::<Self>());

        let mut buf = Cursor::new(buf);

        let mut pkgalg = [0; 2];
        let mut keynum = [0; KEYNUMLEN];
        let mut sig = [0; SIGBYTES];

        buf.read_exact(&mut pkgalg)?;
        buf.read_exact(&mut keynum)?;
        buf.read_exact(&mut sig)?;

        Ok(Signature {
            pkgalg,
            keynum,
            sig,
        })
    }

    pub fn verify(&self, msg: &[u8], pkey: &PublicKey) -> bool {
        let public_key = signature::UnparsedPublicKey::new(&signature::ED25519, &pkey.publkey);

        public_key.verify(msg, &self.sig).is_ok()
    }
}
