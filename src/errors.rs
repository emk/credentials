//! Various error types used internally, and in our public APIs.

use std::error;
// We just need this trait in scope for the methods, not its name.
use std::error::Error as ErrorTrait;
use std::fmt;
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
// Error

/// An error returned by this library.  This also carries error-specific
/// information.  Not currently public, because we might want to add more
/// error types in the future without breaking API compatibility.
#[derive(Debug)]
enum ErrorKind {
    Credential(String),
    SecretfileParse,
    Other,
}

/// Represents an error which occurred accessing credentials.
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    original: BoxedError,
}

/// These methods are public inside the crate, but not visible outside.
pub trait ErrorNew {
    /// Create a new credential-related error.
    fn credential<S, E>(credential: S, err: E) -> Error
        where S: Into<String>, E: Into<BoxedError>;

    /// Create a new Secretfile-related error.
    fn secretfile_parse<E>(err: E) -> Error
        where E: Into<BoxedError>;
}

impl ErrorNew for Error {
    fn credential<S, E>(credential: S, err: E) -> Error
        where S: Into<String>, E: Into<BoxedError>
    {
        Error {
            kind: ErrorKind::Credential(credential.into()),
            original: err.into(),
        }
    }

    fn secretfile_parse<E>(err: E) -> Error
        where E: Into<BoxedError>
    {
        Error {
            kind: ErrorKind::SecretfileParse,
            original: err.into(),
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match &self.kind {
            &ErrorKind::Credential(_) => "can't access secure credential",
            &ErrorKind::SecretfileParse => "error parsing Secretfile",
            &ErrorKind::Other => self.original.description(),
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        Some(self.original.deref() as &error::Error)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.kind {
            &ErrorKind::Other => self.original.fmt(f),
            &ErrorKind::Credential(ref name) =>
                write!(f, "{} {}: {}", self.description(), name,
                       self.original),
            _ =>
                write!(f, "{}: {}", self.description(),  &self.original),
        }
    }
}

impl From<BoxedError> for Error {
    fn from(err: BoxedError) -> Error {
        Error {
            kind: ErrorKind::Other,
            original: err,
        }
    }
}
