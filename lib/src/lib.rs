use anyhow::anyhow;
use anyhow::Result;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

use ed25519_dalek::{self, Keypair, Signer};
use std::io::prelude::*;
use std::io::BufReader;
use std::io::{BufWriter, Cursor};
use std::mem;

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
    #[must_use]
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
        let keypair = Keypair::from_bytes(&self.seckey)?;
        let signature = keypair.try_sign(msg)?;
        Ok(Signature {
            pkgalg: PKGALG,
            keynum: self.keynum,
            sig: signature.to_bytes(),
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

    #[must_use]
    pub fn verify(&self, msg: &[u8], pkey: &PublicKey) -> bool {
        let public_key = ed25519_dalek::PublicKey::from_bytes(&pkey.publkey).unwrap();
        let sig = ed25519_dalek::Signature::new(self.sig);

        public_key.verify_strict(msg, &sig).is_ok()
    }
}

pub fn read_base64<R: Read>(file_display: &str, reader: &mut BufReader<R>) -> Result<Vec<u8>> {
    let mut comment_line = String::new();
    let len = reader.read_line(&mut comment_line)?;

    if len == 0 || len < COMMENTHDRLEN || !comment_line.starts_with(COMMENTHDR) {
        return Err(anyhow!(
            "invalid comment in {}; must start with '{}'",
            file_display,
            COMMENTHDR
        ));
    }

    if &comment_line[len - 1..len] != "\n" {
        return Err(anyhow!(
            "missing new line after comment in {}",
            file_display
        ));
    }

    if len > COMMENTHDRLEN + COMMENTMAXLEN {
        return Err(anyhow!("comment too long"));
    }

    let mut base64_line = String::new();
    let len = reader.read_line(&mut base64_line)?;

    if len == 0 {
        return Err(anyhow!("missing line in {}", file_display));
    }

    if &base64_line[len - 1..len] != "\n" {
        return Err(anyhow!(
            "missing new line after comment in {}",
            file_display
        ));
    }

    let base64_line = &base64_line[0..len - 1];

    let data = base64::decode(base64_line)?;

    if data[0..2] != PKGALG {
        return Err(anyhow!("unsupported file {}", file_display));
    }

    Ok(data)
}

pub fn write_base64<W: Write>(file: &mut BufWriter<W>, comment: &str, buf: &[u8]) -> Result<()> {
    write!(file, "{}", COMMENTHDR)?;
    writeln!(file, "{}", comment)?;
    let out = base64::encode(buf);
    writeln!(file, "{}", out)?;

    file.flush()?;
    Ok(())
}
