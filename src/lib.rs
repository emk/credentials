//! Access secure credentials at runtime with multiple backends.
//!
//! For more information, see [the
//! homepage](https://github.com/emk/credentials).
//!
//! ```
//! use credentials;
//! use std::env;
//!
//! env::set_var("PASSWORD", "secret");
//! assert_eq!("secret", credentials::var("PASSWORD").unwrap());
//! ```

#[macro_use]
extern crate hyper;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;
extern crate regex;
extern crate rustc_serialize;
#[cfg(test)] #[macro_use]
extern crate yup_hyper_mock as hyper_mock;

use backend::{Backend, BoxedError, err};
use std::convert::AsRef;
use std::ops::{Deref, DerefMut};
use std::error::{self, Error};
use std::fmt;
use std::sync::{Mutex, MutexGuard};

// Be very careful not to export any more of the Secretfile API than
// strictly necessary, because we don't want to stablize too much at this
// point.
pub use secretfile::Secretfile;

#[macro_use]
mod backend;
mod chained;
mod envvar;
mod secretfile;
mod vault;

lazy_static! {
    // Our shared global client, initialized by `lazy_static!` and
    // protected by a Mutex.  There's no reason why we couldn't create a
    // per-thread client API for performance, but this will do for now.
    static ref BACKEND: Mutex<Result<chained::Client, BoxedError>> =
        Mutex::new(chained::Client::new_default());
}

/// An error occurred accessing credentials.
#[derive(Debug)]
pub struct CredentialError {
    credential: String,
    original: Option<backend::BoxedError>,
}

impl error::Error for CredentialError {
    fn description(&self) -> &str { "can't access secure credential" }
    fn cause(&self) -> Option<&error::Error> {
        match self.original {
            None => None,
            Some(ref bx) => Some(bx.deref() as &std::error::Error),
        }
    }
}

impl fmt::Display for CredentialError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.original.is_none() {
            write!(f, "{} {}", self.description(), self.credential)
        } else {
            write!(f, "{} {}: {}", self.description(), self.credential,
                   self.cause().unwrap())
        }
    }
}

/// Helper function for `var`, below.
fn var_inner(key: &str) -> Result<String, BoxedError> {
    // This is a bit subtle: First we need to lock our Mutex, and then--if
    // our Mutex was poisoned by a panic in another thread--we want to
    // propagate the panic in this thread using `unwrap()`.  See
    // https://doc.rust-lang.org/std/sync/struct.Mutex.html for details.
    let mut backend_result: MutexGuard<_> = BACKEND.lock().unwrap();

    // Deref our MutexGuard as a mutable reference, and then check to see
    // if it was initialized correctly.  I had to tweak the `mut` bits for
    // a few minutes to get this past the borrow checker.
    match backend_result.deref_mut() {
        &mut Ok(ref mut backend) => backend.var(key),
        &mut Err(ref e) => Err(err!("Could not initialize: {}", e)),
    }
}

/// Fetch the value of a credential.
pub fn var<K: AsRef<str>>(key: K) -> Result<String, CredentialError> {
    let key_ref = key.as_ref();
    trace!("getting secure credential {}", key_ref);
    var_inner(key.as_ref()).map_err(|e| {
        let err = CredentialError {
            credential: key_ref.to_owned(),
            original: Some(e),
        };
        warn!("{}", err);
        err
    })
}
