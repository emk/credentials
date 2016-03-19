//! Access secure credentials at runtime with multiple backends.
//!
//! ```
//! use credentials;
//! use std::env;
//!
//! env::set_var("PASSWORD", "secret");
//! assert_eq!("secret", credentials::get("PASSWORD").unwrap());
//! ```

#[macro_use]
extern crate hyper;
#[macro_use]
extern crate log;
extern crate rustc_serialize;
#[cfg(test)] #[macro_use]
extern crate yup_hyper_mock as hyper_mock;

use std::convert::AsRef;
use std::ops::Deref;
use std::env;
use std::error::{self, Error};
use std::fmt;

mod backend;
mod secretfile;
mod vault;

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

/// Fetch the value of a credential.
pub fn get<K: AsRef<str>>(key: K) -> Result<String, CredentialError> {
    let key_ref = key.as_ref();
    trace!("getting secure credential {}", key_ref);
    env::var(key.as_ref()).map_err(|err| {
        let err = CredentialError {
            credential: key_ref.to_owned(),
            original: Some(Box::new(err.clone())),
        };
        warn!("{}", err);
        err
    })
}
