use crate::consts::KeyNumber;
use std::fmt::{self, Display};
use std::io;

/// The error type which is returned when some `signify` operation fails.
#[derive(Debug)]
pub enum Error {
    /// An I/O error occured working with structure data.
    Io(io::Error),
    /// Parsing a structure's data yielded an error.
    InvalidFormat(FormatError),
    /// The key algorithm used was unknown and unsupported.
    UnsupportedAlgorithm,
    /// Attempted to verify a signature with the wrong public key.
    MismatchedKey {
        /// ID of the key which created the signature.
        expected: KeyNumber,
        /// ID of the key that tried to verify the signature, but was wrong.
        found: KeyNumber,
    },
    /// The signature didn't match the expected result.
    ///
    /// This could be the result of data corruption or malicious tampering.
    ///
    /// The contents of the message should not be trusted if this is encountered.
    BadSignature,
    /// Provided password was empty or couldn't decrypt a private key.
    BadPassword,
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => Display::fmt(e, f),
            Error::InvalidFormat(e) => Display::fmt(e, f),
            Error::UnsupportedAlgorithm => f.write_str("encountered unsupported key algorithm"),
            Error::MismatchedKey { expected, found } => {
                write!(f,
                "failed to verify signature: the wrong key was used. Expected {:?}, but found {:?}",
                expected,
                found,
            )
            }
            Error::BadSignature => f.write_str("signature verification failed"),
            Error::BadPassword => f.write_str("password was empty"),
        }
    }
}

impl std::error::Error for Error {}

/// The error that is returned when a file's contents didn't adhere
/// to the `signify` file container format.
#[derive(Debug)]
pub enum FormatError {
    /// A comment line exceeded the maximum length or a data line was empty.
    LineLength,
    /// File was missing the required `untrusted comment: ` preamble.
    Comment {
        /// The expected comment header.
        expected: &'static str,
    },
    /// File was missing a required line or wasn't correctly newline terminated.
    MissingNewline,
    /// Provided data wasn't valid base64.
    Base64,
}

impl Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FormatError::LineLength => {
                f.write_str("encountered an invalidly formatted line of data")
            }
            FormatError::Comment { expected } => {
                write!(f, "line missing comment; expected {}", expected)
            }
            FormatError::MissingNewline => f.write_str("expected newline was not found"),
            FormatError::Base64 => f.write_str("encountered invalid base64 data"),
        }
    }
}

impl std::error::Error for FormatError {}

impl From<FormatError> for Error {
    fn from(e: FormatError) -> Self {
        Self::InvalidFormat(e)
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use static_assertions::assert_impl_all;
    use std::error::Error as StdError;
    use std::fmt::{Debug, Display};

    assert_impl_all!(Error: Debug, Display, StdError, Send, Sync);
    assert_impl_all!(FormatError: Debug, Display, StdError, Send, Sync);
}
