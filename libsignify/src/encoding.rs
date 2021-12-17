use crate::consts::{
    COMMENT_HEADER, COMMENT_MAX_LEN, FULL_KEY_LEN, PKGALG, PUBLIC_KEY_LEN, SIG_LEN,
};
use crate::errors::{Error, FormatError};
use crate::{KeyNumber, PrivateKey, PublicKey, Signature};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Read, Write};

/// A structure that can be converted to and from bytes and the `signify` file format.
pub trait Codeable: Sized + Sealed {
    /// Parses a blob of serialized bytes into a structure.
    ///
    /// When working with signature files, [`from_base64`](Self::from_base64) should be
    /// prefered for compatibility with other implementations.
    fn from_bytes(bytes: &[u8]) -> Result<Self, Error>;

    /// Parses a base64 encoded string into a structure.
    ///
    /// Returns the structure and the remaining number of bytes after the structure's end
    /// inside `encoded`. This can be helpful when dealing with embedded signatures.
    ///
    /// The parsing enforces that the `signify` file format is adhered to.
    ///
    /// Said format is roughly defined as such:
    /// ```text
    /// untrusted comment: <about what the file contains><\n>
    /// <contents><\n>
    /// <\n>
    /// ```
    fn from_base64(encoded: &str) -> Result<(Self, u64), Error> {
        read_base64_contents(encoded).and_then(|(bytes, remaining)| {
            let bytes = Self::from_bytes(&bytes)?;
            Ok((bytes, remaining))
        })
    }

    /// Converts the structure into a blob of bytes and returns them.
    ///
    /// When working with signature files, [`to_file_encoding`](Self::to_file_encoding)
    /// should be prefered for compatibility with other implementations.
    fn as_bytes(&self) -> Result<Vec<u8>, Error>;

    /// Converts the structure into a base64 encoded container and returned the raw bytes.
    ///
    /// The provided comment is added as the untrusted comment in the container.
    ///
    /// The container format can be seen in the [decoder's documentation].
    ///
    /// [decoder's documentation]: Self::from_base64
    fn to_file_encoding(&self, comment: &str) -> Result<Vec<u8>, Error> {
        let bytes = self.as_bytes()?;

        let mut file_bytes = Vec::new();

        file_bytes.write_all(COMMENT_HEADER.as_bytes())?;
        writeln!(file_bytes, "{}", comment)?;

        let out = base64::encode(&bytes);
        writeln!(file_bytes, "{}", out)?;

        Ok(file_bytes)
    }
}

use sealed::Sealed;
mod sealed {
    pub trait Sealed {}
}

impl Sealed for PublicKey {}
impl Sealed for PrivateKey {}
impl Sealed for Signature {}

impl Codeable for PublicKey {
    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut buf = std::io::Cursor::new(bytes);

        let mut _pkgalg = [0; 2];
        let mut keynum = [0; KeyNumber::LEN];
        let mut public_key = [0; PUBLIC_KEY_LEN];

        buf.read_exact(&mut _pkgalg)?;
        buf.read_exact(&mut keynum)?;
        buf.read_exact(&mut public_key)?;

        Ok(Self {
            keynum: KeyNumber::new(keynum),
            key: public_key,
        })
    }

    fn as_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut w = Vec::new();

        w.write_all(&PKGALG)?;
        w.write_all(self.keynum.as_ref())?;
        w.write_all(&self.key)?;

        Ok(w)
    }
}

impl Codeable for PrivateKey {
    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut buf = std::io::Cursor::new(bytes);

        let mut public_key_alg = [0; 2];
        let mut kdf_alg = [0; 2];
        let mut salt = [0; 16];
        let mut checksum = [0; 8];
        let mut keynum = [0; KeyNumber::LEN];
        let mut complete_key = [0; FULL_KEY_LEN];

        buf.read_exact(&mut public_key_alg)?;
        buf.read_exact(&mut kdf_alg)?;
        let kdf_rounds = buf.read_u32::<BigEndian>()?;
        buf.read_exact(&mut salt)?;
        buf.read_exact(&mut checksum)?;
        buf.read_exact(&mut keynum)?;
        buf.read_exact(&mut complete_key)?;

        Ok(Self {
            public_key_alg,
            kdf_alg,
            kdf_rounds,
            salt,
            checksum,
            keynum: KeyNumber::new(keynum),
            complete_key,
        })
    }

    fn as_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut w = Vec::new();

        w.write_all(&self.public_key_alg)?;
        w.write_all(&self.kdf_alg)?;
        w.write_u32::<BigEndian>(self.kdf_rounds)?;
        w.write_all(&self.salt)?;
        w.write_all(&self.checksum)?;
        w.write_all(self.keynum.as_ref())?;
        w.write_all(&self.complete_key)?;

        Ok(w)
    }
}

impl Codeable for Signature {
    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut buf = std::io::Cursor::new(bytes);

        let mut _pkgalg = [0; 2];
        let mut keynum = [0; KeyNumber::LEN];
        let mut sig = [0; SIG_LEN];

        buf.read_exact(&mut _pkgalg)?;
        buf.read_exact(&mut keynum)?;
        buf.read_exact(&mut sig)?;

        Ok(Self {
            keynum: KeyNumber::new(keynum),
            sig,
        })
    }

    fn as_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut w = Vec::new();

        w.write_all(&PKGALG)?;
        w.write_all(self.keynum.as_ref())?;
        w.write_all(&self.sig)?;

        Ok(w)
    }
}

fn read_base64_contents(encoded: &str) -> Result<(Vec<u8>, u64), Error> {
    let mut lines = encoded.split('\n');

    // Newline ending is implicitly checked by `split`.
    let comment_line = lines.next().ok_or(FormatError::MissingNewline)?;

    if !comment_line.starts_with(COMMENT_HEADER) {
        return Err(FormatError::Comment {
            expected: COMMENT_HEADER,
        }
        .into());
    }

    if comment_line.len() > COMMENT_HEADER.len() + COMMENT_MAX_LEN {
        return Err(FormatError::LineLength.into());
    }

    let base64_line = lines.next().ok_or(FormatError::MissingNewline)?;

    if base64_line.is_empty() {
        return Err(FormatError::LineLength.into());
    }

    let data = base64::decode(base64_line.trim_end()).map_err(|_| FormatError::Base64)?;

    match data.get(0..2) {
        // Make sure the specified algorithm matches what we support
        Some(alg) if alg == PKGALG => {
            // Can't panic, we know there are two lines present.
            let mut newlines = encoded.chars().enumerate().filter(|(_, val)| *val == '\n');
            let remaining = newlines.nth(1).unwrap().0 as u64;

            Ok((data, remaining + 1))
        }
        Some(_) | None => Err(Error::UnsupportedAlgorithm),
    }
}
