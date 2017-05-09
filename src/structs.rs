use std::mem;
use std::io::prelude::*;
use std::io::Cursor;

use errors::*;

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

use ring::signature::{self, Ed25519KeyPair};
use untrusted;

pub const KEYNUMLEN : usize = 8;
pub const PUBLICBYTES : usize = 32;
pub const SECRETBYTES : usize = 64;
pub const SIGBYTES : usize = 64;

pub const PKGALG : [u8; 2] = *b"Ed";
pub const KDFALG : [u8; 2] = *b"BK";

pub const COMMENTHDR : &'static str = "untrusted comment: ";
pub const COMMENTHDRLEN : usize = 19;
pub const COMMENTMAXLEN : usize = 1024;

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
            keynum: keynum,
            publkey: key,
        }
    }

    pub fn write<W: Write>(&self, mut w: W) -> Result<()> {
        try!(w.write(&self.pkgalg));
        try!(w.write(&self.keynum));
        try!(w.write(&self.publkey));

        Ok(())
    }

    pub fn from_buf(buf: &[u8]) -> Result<PublicKey> {
        assert!(buf.len() >= mem::size_of::<Self>());

        let mut buf = Cursor::new(buf);

        let mut pkgalg = [0; 2];
        let mut keynum = [0; KEYNUMLEN];
        let mut publkey = [0; PUBLICBYTES];

        try!(buf.read(&mut pkgalg));
        try!(buf.read(&mut keynum));
        try!(buf.read(&mut publkey));

        Ok(PublicKey {
            pkgalg: pkgalg,
            keynum: keynum,
            publkey: publkey,
        })
    }
}

impl PrivateKey {
    pub fn write<W: Write>(&self, mut w: W) -> Result<()> {
        try!(w.write(&self.pkgalg));
        try!(w.write(&self.kdfalg));
        try!(w.write_u32::<BigEndian>(self.kdfrounds));
        try!(w.write(&self.salt));
        try!(w.write(&self.checksum));
        try!(w.write(&self.keynum));
        try!(w.write(&self.seckey));

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

        try!(buf.read(&mut pkgalg));
        try!(buf.read(&mut kdfalg));
        kdfrounds = try!(buf.read_u32::<BigEndian>());
        try!(buf.read(&mut salt));
        try!(buf.read(&mut checksum));
        try!(buf.read(&mut keynum));
        try!(buf.read(&mut seckey));

        Ok(PrivateKey {
            pkgalg: pkgalg,
            kdfalg: kdfalg,
            kdfrounds: kdfrounds,
            salt: salt,
            checksum: checksum,
            keynum: keynum,
            seckey: seckey,
        })
    }

    pub fn sign(&self, msg: &[u8]) -> Result<Signature> {
        let seed = untrusted::Input::from(&self.seckey[0..32]);
        let pubkey = untrusted::Input::from(&self.seckey[32..]);
        let keypair = try!(Ed25519KeyPair::from_seed_and_public_key(seed, pubkey));
        let signature = keypair.sign(msg);
        let mut sig = [0; 64];
        sig.copy_from_slice(signature.as_ref());
        Ok(Signature {
            pkgalg: PKGALG,
            keynum: self.keynum,
            sig: sig
        })
    }
}

impl Signature {
    pub fn write<W: Write>(&self, mut w: W) -> Result<()> {
        try!(w.write(&self.pkgalg));
        try!(w.write(&self.keynum));
        try!(w.write(&self.sig));

        Ok(())
    }

    pub fn from_buf(buf: &[u8]) -> Result<Signature> {
        assert!(buf.len() >= mem::size_of::<Self>());

        let mut buf = Cursor::new(buf);

        let mut pkgalg = [0; 2];
        let mut keynum = [0; KEYNUMLEN];
        let mut sig = [0; SIGBYTES];

        try!(buf.read(&mut pkgalg));
        try!(buf.read(&mut keynum));
        try!(buf.read(&mut sig));

        Ok(Signature {
            pkgalg: pkgalg,
            keynum: keynum,
            sig: sig,
        })
    }

    pub fn verify(&self, msg: &[u8], pkey: &PublicKey) -> bool {
        let public_key = untrusted::Input::from(&pkey.publkey);
        let sig = untrusted::Input::from(&self.sig);
        let msg = untrusted::Input::from(msg);

        signature::verify(&signature::ED25519,
                          public_key, msg, sig).is_ok()
    }
}
