use anyhow::anyhow;
use anyhow::Result;
use bcrypt_pbkdf::bcrypt_pbkdf;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use ed25519_dalek::{self, Keypair, Signer};
use rand::RngCore;
use rand_core::OsRng;
use sha2::{Digest, Sha512};
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
        w.write_all(&self.publkey).map_err(std::convert::Into::into)
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
        w.write_all(&self.seckey).map_err(std::convert::Into::into)
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
        w.write_all(&self.sig).map_err(std::convert::Into::into)
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

pub fn read_base64(raw_data: &mut BufReader<impl Read>) -> Result<Vec<u8>> {
    let mut comment_line = String::new();
    let len = raw_data.read_line(&mut comment_line)?;

    if len == 0 || len < COMMENTHDRLEN || !comment_line.starts_with(COMMENTHDR) {
        return Err(anyhow!("invalid comment; must start with '{}'", COMMENTHDR));
    }

    if &comment_line[len - 1..len] != "\n" {
        return Err(anyhow!("missing new line after comment",));
    }

    if len > COMMENTHDRLEN + COMMENTMAXLEN {
        return Err(anyhow!("comment too long"));
    }

    let mut base64_line = String::new();
    let len = raw_data.read_line(&mut base64_line)?;

    if len == 0 {
        return Err(anyhow!("missing line",));
    }

    if &base64_line[len - 1..len] != "\n" {
        return Err(anyhow!("missing new line after comment"));
    }

    let base64_line = &base64_line[0..len - 1];

    let data = base64::decode(base64_line)?;

    if data[0..2] != PKGALG {
        return Err(anyhow!("unsupported file"));
    }

    Ok(data)
}
pub fn write_base64(file: &mut BufWriter<impl Write>, comment: &str, buf: &[u8]) -> Result<()> {
    write!(file, "{}", COMMENTHDR)?;
    writeln!(file, "{}", comment)?;
    let out = base64::encode(buf);
    writeln!(file, "{}", out)?;

    file.flush().map_err(std::convert::Into::into)
}

/// verify a message
pub fn verify(
    mut pubkey: BufReader<impl Read>,
    mut sig_buff: BufReader<impl Read>,
    mut message: BufReader<impl Read>,
    embed: bool,
) -> Result<()> {
    // TODO: Better error message?
    let serialized_pkey = read_base64(&mut pubkey)?;
    let pkey = PublicKey::from_buf(&serialized_pkey)?;

    // TODO: Better error message?
    let serialized_signature = read_base64(&mut sig_buff)?;
    let signature = Signature::from_buf(&serialized_signature)?;

    let mut msg = vec![];

    if embed {
        sig_buff.read_to_end(&mut msg)?
    } else {
        message.read_to_end(&mut msg)?
    };

    if signature.keynum != pkey.keynum {
        return Err(anyhow!(
            "signature verification failed: checked against wrong key",
        ));
    }

    if signature.verify(&msg, &pkey) {
        println!("Signature Verified");
        Ok(())
    } else {
        Err(anyhow!("signature verification failed"))
    }
}

/// sign a message
pub fn sign(
    mut seckey: BufReader<impl Read>,
    message: &[u8],
    mut signature: &mut BufWriter<impl Write>,
    embed: bool,
    password_reader: fn(bool) -> Result<String>,
) -> Result<()> {
    let serialized_skey = read_base64(&mut seckey)?;
    let mut skey = PrivateKey::from_buf(&serialized_skey)?;

    let rounds = skey.kdfrounds;
    let xorkey = if rounds > 0 {
        let passphrase = password_reader(false)?;

        let mut xorkey = vec![0; SECRETBYTES];
        bcrypt_pbkdf(&passphrase, &skey.salt, rounds, &mut xorkey)?;
        xorkey
    } else {
        vec![0; SECRETBYTES]
    };

    for (prv, xor) in skey.seckey.iter_mut().zip(xorkey.iter()) {
        *prv ^= xor;
    }

    let sig = skey.sign(&message)?;

    let mut out = vec![];
    sig.write(&mut out)?;
    // TODO avoid this buffering into out?
    let sig_comment = "signature from signify secret key";
    write_base64(&mut signature, sig_comment, &out)?;

    if embed {
        signature.write_all(&message)?;
    }
    signature.flush().map_err(std::convert::Into::into) // needed after write_all?
}

/// generate a new keypair
pub fn generate(
    mut pubkey: &mut BufWriter<impl Write>,
    mut private_key_file: &mut BufWriter<impl Write>,
    comment: Option<String>,
    kdfrounds_and_passphrase: Option<(std::num::NonZeroU32, String)>,
) -> Result<()> {
    let comment = match comment {
        Some(s) => s,
        None => "signify".into(),
    };

    let mut keynum = [0; KEYNUMLEN];
    OsRng.fill_bytes(&mut keynum);

    let keypair: Keypair = Keypair::generate(&mut OsRng);
    let pkey = keypair.public.to_bytes();
    let mut skey = keypair.secret.to_bytes();

    let mut salt = [0; 16];
    OsRng.fill_bytes(&mut salt);

    let (xorkey, kdfrounds): (_, u32) =
        if let Some((kdfrounds, passphrase)) = kdfrounds_and_passphrase {
            let mut xorkey = vec![0; SECRETBYTES];
            bcrypt_pbkdf(&passphrase, &salt, kdfrounds.into(), &mut xorkey)?;
            (xorkey, kdfrounds.into())
        } else {
            (vec![0; SECRETBYTES], 0)
        };

    for (prv, xor) in skey.iter_mut().zip(xorkey.iter()) {
        *prv ^= xor;
    }

    // signify stores the extended key as the private key,
    // that is the 32 byte of the secret key, followed by the 32 byte of the public key,
    // summing up to 64 byte.
    let mut complete_key = [0; 64];
    complete_key[0..32].copy_from_slice(&skey);
    complete_key[32..].copy_from_slice(&pkey);

    // Store private key
    let mut hasher = Sha512::default();
    hasher.update(&complete_key);
    let digest = hasher.finalize();
    let mut checksum = [0; 8];
    checksum.copy_from_slice(&digest.as_ref()[0..8]);

    let private_key = PrivateKey {
        pkgalg: PKGALG,
        kdfalg: KDFALG,
        kdfrounds,
        salt,
        checksum,
        keynum,
        seckey: complete_key,
    };

    let mut out = vec![];
    private_key.write(&mut out)?;

    let priv_comment = format!("{} secret key", comment);
    write_base64(&mut private_key_file, &priv_comment, &out)?;

    // Store public key
    let public_key = PublicKey::with_key_and_keynum(pkey, keynum);

    let mut out = vec![];
    public_key.write(&mut out)?;

    let pub_comment = format!("{} public key", comment);

    write_base64(&mut pubkey, &pub_comment, &out)
}
