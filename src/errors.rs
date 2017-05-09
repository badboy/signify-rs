use std::path::Path;
use std::io;
use ring::error::Unspecified;
use base64::DecodeError;

error_chain! {
    foreign_links {
        IoError(io::Error);
        Unspecified(Unspecified);
        Base64(DecodeError);
    }
}

pub fn write_error<P: AsRef<Path>>(file: P) -> String {
    let file = file.as_ref();
    format!("can't open '{}' for writing", file.display())
}

pub fn read_error<P: AsRef<Path>>(file: P) -> String {
    let file = file.as_ref();
    format!("can't open '{}' for reading", file.display())
}
