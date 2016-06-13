extern crate crypto;
extern crate base64;
extern crate byteorder;
extern crate rand;

use std::io::{self, Write};
use std::fs::File;
use std::convert::AsRef;
use std::path::Path;
use rand::Rng;
use rand::os::OsRng;
use crypto::ed25519;
use byteorder::{BigEndian, WriteBytesExt};

const KEYNUMLEN : usize = 8;
const PUBLICBYTES : usize = 32;
const SECRETBYTES : usize = 64;
const SIGBYTES : usize = 64;

const PKGALG : [u8; 2] = *b"Ed";
const KDFALG : [u8; 2] = *b"BK";

struct PublicKey {
    pkgalg: [u8; 2],
    keynum: [u8; KEYNUMLEN],
    publkey: [u8; PUBLICBYTES],
}

struct PrivateKey {
   pkgalg: [u8; 2],
   kdfalg: [u8; 2],
   kdfrounds: u32,
   salt: [u8; 16],
   checksum: [u8; 8],
   keynum: [u8; KEYNUMLEN],
   seckey: [u8; SECRETBYTES],
}

struct Signature {
    pkgalg: [u8; 2],
    keynum: [u8; KEYNUMLEN],
    sig: [u8; SIGBYTES],
}

impl PublicKey {
    fn with_key_and_keynum(key: [u8; PUBLICBYTES], keynum: [u8; KEYNUMLEN]) -> PublicKey {
        PublicKey {
            pkgalg: PKGALG,
            keynum: keynum,
            publkey: key,
        }
    }

    fn write<W: Write>(&self, mut w: W) -> Result<(), io::Error> {
        try!(w.write(&self.pkgalg));
        try!(w.write(&self.keynum));
        try!(w.write(&self.publkey));

        Ok(())
    }

    fn verify(&self, msg: &[u8], signature: &Signature) -> bool {
        ed25519::verify(msg, &self.publkey, &signature.sig)
    }
}

impl PrivateKey {
    fn write<W: Write>(&self, mut w: W) -> Result<(), io::Error> {
        try!(w.write(&self.pkgalg));
        try!(w.write(&self.kdfalg));
        try!(w.write_u32::<BigEndian>(self.kdfrounds));
        try!(w.write(&self.salt));
        try!(w.write(&self.checksum));
        try!(w.write(&self.keynum));
        try!(w.write(&self.seckey));

        Ok(())
    }

    fn sign(&self, msg: &[u8]) -> Signature {
        let signature = ed25519::signature(msg, &self.seckey);
        Signature {
            pkgalg: PKGALG,
            keynum: self.keynum,
            sig: signature
        }
    }
}

impl Signature {
    fn write<W: Write>(&self, mut w: W) -> Result<(), io::Error> {
        try!(w.write(&self.pkgalg));
        try!(w.write(&self.keynum));
        try!(w.write(&self.sig));

        Ok(())
    }

    fn verify(&self, msg: &[u8], pkey: &PublicKey) -> bool {
        ed25519::verify(msg, &pkey.publkey, &self.sig)
    }
}

fn write_base64_file<P: AsRef<Path>>(file: P, comment: &str, buf: &[u8]) -> Result<(), io::Error> {
    let mut f = File::create(file).unwrap();

    try!(write!(f, "untrusted comment: "));
    try!(write!(f, "{}\n", comment));
    let out = base64::encode(buf);
    try!(write!(f, "{}\n", out));

    Ok(())
}

fn generate() {
    let mut keynum = [0; KEYNUMLEN];

    let mut rng = OsRng::new().expect("Can't create random number generator");
    rng.fill_bytes(&mut keynum);

    let (skey, pkey) = ed25519::keypair(&[]);
    let public_key = PublicKey::with_key_and_keynum(pkey, keynum);

    let mut out = vec![];
    public_key.write(&mut out);

    write_base64_file("key.pub", "signify public key", &out).unwrap()
}

fn main() {
    generate();
}
