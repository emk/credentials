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

use backend::Backend;
use errors::{BoxedError, CredentialErrorNew, err};
use std::convert::AsRef;
use std::ops::DerefMut;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

// Be very careful not to export any more of the Secretfile API than
// strictly necessary, because we don't want to stablize too much at this
// point.
pub use secretfile::{Secretfile, SecretfileKeys};
pub use errors::{CredentialError, SecretfileError};

#[macro_use]
mod errors;

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

/// Helper function for `file`, below.
fn file_inner(key: &str) -> Result<String, BoxedError> {
    let mut backend_result: MutexGuard<_> = BACKEND.lock().unwrap();
    match backend_result.deref_mut() {
        &mut Ok(ref mut backend) => backend.file(key),
        &mut Err(ref e) => Err(err!("Could not initialize: {}", e)),
    }
}

/// Fetch the value of an environment-variable-style credential.
pub fn var<S: AsRef<str>>(name: S) -> Result<String, CredentialError> {
    let name_ref = name.as_ref();
    trace!("getting secure credential {}", name_ref);
    var_inner(name.as_ref()).map_err(|e| {
        let err = CredentialError::new(name_ref.to_owned(), e);
        warn!("{}", err);
        err
    })
}

/// Fetch the value of a file-style credential.
pub fn file<S: AsRef<Path>>(path: S) -> Result<String, CredentialError> {
    let path_ref = path.as_ref();
    let path_str = try!(path_ref.to_str().ok_or_else(|| {
        CredentialError::new("(invalid path)".to_owned(),
                             err!("Path is not valid Unicode"))
    }));
    trace!("getting secure credential {}", path_str);
    file_inner(path_str).map_err(|e| {
        let err = CredentialError::new(path_str.to_owned(), e);
        warn!("{}", err);
        err
    })
}

#[cfg(test)]
mod test {
    use std::fs;
    use std::io::Read;
    use super::file;

    #[test]
    fn test_file() {
        // Some arbitrary file contents.
        let mut f = fs::File::open("Cargo.toml").unwrap();
        let mut expected = String::new();
        f.read_to_string(&mut expected).unwrap();

        assert_eq!(expected, file("Cargo.toml").unwrap());
        assert!(file("nosuchfile.txt").is_err());
    }
}
