pub use failure::err_msg;

pub type Result<T> = ::std::result::Result<T, failure::Error>;
