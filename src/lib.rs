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
use errors::{ErrorNew, err};
use std::cell::RefCell;
use std::convert::AsRef;
use std::ops::DerefMut;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

// Be very careful not to export any more of the Secretfile API than
// strictly necessary, because we don't want to stablize too much at this
// point.
pub use secretfile::{Secretfile, SecretfileKeys};
pub use errors::Error;

#[macro_use]
mod errors;

mod backend;
mod chained;
mod envvar;
mod secretfile;
mod vault;

/// A client which fetches secrets.  Under normal circumstances, it's
/// usually easier to use the static `credentials::var` and
/// `credentials::file` methods instead, but you may need to use this to
/// customize behavior.
pub struct Client {
    sf: Secretfile,
    backend: chained::Client,
}

impl Client {
    /// Create a new client using the default `Secretfile`.
    pub fn new() -> Result<Client, Error> {
        Client::with_secretfile(try!(Secretfile::default()))
    }

    /// Create a new client using the specified `Secretfile`.
    pub fn with_secretfile(secretfile: Secretfile) -> Result<Client, Error> {
        Ok(Client {
            sf: secretfile,
            backend: try!(chained::Client::default()),
        })
    }

    /// Provide access to a copy of the Secretfile we're using.
    pub fn secretfile(&self) -> &Secretfile {
        &self.sf
    }

    /// Fetch the value of an environment-variable-style credential.
    pub fn var<S: AsRef<str>>(&mut self, name: S) -> Result<String, Error> {
        let name_ref = name.as_ref();
        trace!("getting secure credential {}", name_ref);
        self.backend.var(&self.sf, name_ref).map_err(|e| {
            let err = Error::credential(name_ref, e);
            warn!("{}", err);
            err
        })
    }

    /// Fetch the value of a file-style credential.
    pub fn file<S: AsRef<Path>>(&mut self, path: S) -> Result<String, Error> {
        let path_ref = path.as_ref();
        let path_str = try!(path_ref.to_str().ok_or_else(|| {
            Error::credential("(invalid path)", err!("Path is not valid Unicode"))
        }));
        trace!("getting secure credential {}", path_str);
        self.backend.file(&self.sf, path_str).map_err(|e| {
            let err = Error::credential(path_str, e);
            warn!("{}", err);
            err
        })
    }
}

lazy_static! {
    // Our shared global client, initialized by `lazy_static!` and
    // protected by a Mutex.
    //
    // Rust deliberately makes it a nuisance to use mutable global
    // variables.  In this case, the `Mutex` provides thread-safe locking,
    // the `RefCell` makes this assignable, and the `Option` makes this
    // optional.  This is a message from the language saying, "Really? A
    // mutable global that might be null? Have you really thought about
    // this?"  But the global default client is only for convenience, so
    // we're OK with it, at least so far.
    static ref CLIENT: Mutex<RefCell<Option<Client>>> =
        Mutex::new(RefCell::new(None));
}

/// Call `body` with the default global client, or return an error if we
/// can't allocate a default global client.
fn with_client<F>(body: F) -> Result<String, Error>
    where F: FnOnce(&mut Client) -> Result<String, Error>
{
    let client_cell: MutexGuard<_> = CLIENT.lock().unwrap();

    // Try to set up the client if we haven't already.
    if client_cell.borrow().is_none() {
        *client_cell.borrow_mut() = Some(try!(Client::new()));
    }

    // Call the provided function.  I have to break out `result` separately
    // for mysterious reasons related to the borrow checker and global
    // mutable state.
    let result = match client_cell.borrow_mut().deref_mut() {
        &mut Some(ref mut client) => body(client),
        // We theoretically handed this just above, and exited if we
        // failed.
        &mut None => panic!("Should have a client, but we don't")
    };
    result
}

/// Fetch the value of an environment-variable-style credential.
pub fn var<S: AsRef<str>>(name: S) -> Result<String, Error> {
    with_client(|client| client.var(name))
}

/// Fetch the value of a file-style credential.
pub fn file<S: AsRef<Path>>(path: S) -> Result<String, Error> {
    with_client(|client| client.file(path))
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
