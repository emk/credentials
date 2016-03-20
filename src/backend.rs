//! Generic interface to secret storage backends.

use std::error;

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

/// Generic interface to a secret-storage backend.
pub trait Backend {
    /// Get the value of the specified secret.
    fn get(&mut self, credential: &str) -> Result<String, BoxedError>;
}
