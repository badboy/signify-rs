use crate::consts::KeyNumber;
use std::fmt::{self, Display};
use std::io;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    InvalidFormat(FormatError),
    UnsupportedAlgorithm,
    MismatchedKey {
        expected: KeyNumber,
        found: KeyNumber,
    },
    BadSignature,
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

#[derive(Debug)]
pub enum FormatError {
    LineLength,
    Comment { expected: &'static str },
    MissingNewline,
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
