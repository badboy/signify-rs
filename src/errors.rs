use failure;

pub type Result<T> = ::std::result::Result<T, failure::Error>;

#[derive(Debug, Fail)]
pub enum SignifyError {
    #[fail(display = "{}", _0)]
    MessageFail(String),
}

pub fn error<T, S: Into<String>>(msg: S) -> Result<T> {
    Err(SignifyError::MessageFail(msg.into()).into())
}
