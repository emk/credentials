//! Various error types used internally, and in our public APIs.

use std::error::{self, Error};
use std::fmt;
use std::io;
use std::ops::Deref;

//=========================================================================
// BoxedError

/// A generic error type which can contain any error caused by any of the
/// libraries we call.  This is used by our backend APIs for simplicity and
/// extensibility, and because we don't really care very much about why
/// things fail (at least not at this level).
pub type BoxedError = Box<error::Error+Send+Sync>;

/// Create a `BoxedError` with a simple string error.  We use this for
/// internal errors that we want to keep simple.
pub fn err<T: Into<String>>(message: T) -> BoxedError {
    From::from(message.into())
}

/// Create a `BoxedError` from a format string and format arguments.
macro_rules! err {
    ($( $e:expr ),*) =>
        ($crate::errors::err(format!($( $e ),*)));
}


//=========================================================================
// CredentialError

/// Represents an error which occurred accessing credentials.
#[derive(Debug)]
pub struct CredentialError {
    credential: String,
    original: BoxedError,
}

/// These methods are public inside the crate, but not visible outside.
pub trait CredentialErrorNew {
    /// Wrap an existing error.
    fn new(credential: String, err: BoxedError) -> CredentialError;
}

impl CredentialErrorNew for CredentialError {
    /// Wrap an existing error.
    fn new(credential: String, err: BoxedError) -> CredentialError {
        CredentialError {
            credential: credential,
            original: err,
        }
    }
}

impl error::Error for CredentialError {
    fn description(&self) -> &str { "can't access secure credential" }
    fn cause(&self) -> Option<&error::Error> {
        Some(self.original.deref() as &error::Error)
    }
}

impl fmt::Display for CredentialError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {}: {}", self.description(), self.credential,
               self.cause().unwrap())
    }
}


//=========================================================================
// SecretfileError

/// Represents an error which occurred parsing a `Secretfile`.
#[derive(Debug)]
pub struct SecretfileError {
    original: BoxedError,
}

/// These methods are public inside the crate, but not visible outside.
pub trait SecretfileErrorNew {
    /// Wrap an existing error.
    fn new(err: BoxedError) -> SecretfileError;
}

impl SecretfileErrorNew for SecretfileError {
    fn new(err: BoxedError) -> SecretfileError {
        SecretfileError { original: err }
    }
}

impl error::Error for SecretfileError {
    fn description(&self) -> &str { "error parsing Secretfile" }
    fn cause(&self) -> Option<&error::Error> {
        Some(self.original.deref() as &error::Error)
    }
}

impl fmt::Display for SecretfileError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}: {}", self.description(), self.cause().unwrap())
    }
}

impl From<BoxedError> for SecretfileError {
    fn from(err: BoxedError) -> SecretfileError {
        SecretfileError { original: err }
    }
}

impl From<io::Error> for SecretfileError {
    fn from(err: io::Error) -> SecretfileError {
        SecretfileError { original: Box::new(err) }
    }
}
