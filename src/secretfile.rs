//! Map application-level credential names to secrets in the backend store.
//!
//! In the case of Vault, this is necessary to transform
//! environment-variable-style credential names into Vault secret paths and
//! keys: from `MY_SECRET_PASSWORD` to the path `secret/my_secret` and the
//! key `"password"`.

use lazy_static::lazy_static;
use regex::{Captures, Regex};
use std::cell::RefCell;
use std::collections::{btree_map, BTreeMap};
use std::env;
use std::fs::File;
use std::io::{self, BufRead};
use std::iter::Iterator;
use std::path::Path;
use std::str::FromStr;
use std::sync::Mutex;

use crate::errors::*;

lazy_static! {
    // For command-line binaries used directly by users, it may occasionally be
    // desirable to build a `Secretfile` directly into an executable.
    //
    // For an explanation of `lazy_static!`, `Mutex` and the other funky Rust
    // stuff going on here, see `CLIENT` in `lib.rs`.
    static ref BUILT_IN_SECRETFILE: Mutex<RefCell<Option<Secretfile>>> =
        Mutex::new(RefCell::new(None));
}

/// Interpolate environment variables into a string.
fn interpolate_env(text: &str) -> Result<String> {
    // Only compile this Regex once.
    lazy_static! {
        static ref RE: Regex = Regex::new(
            r"(?x)
\$(?:
    (?P<name>[a-zA-Z_][a-zA-Z0-9_]*)
  |
    \{(?P<name2>[a-zA-Z_][a-zA-Z0-9_]*)\}
  )"
        )
        .unwrap();
    }

    // Perform the replacement.  This is mostly error-handling logic,
    // because `replace_all` doesn't anticipate any errors.
    let mut err = None;
    let result = RE.replace_all(text, |caps: &Captures| {
        let name = caps
            .name("name")
            .or_else(|| caps.name("name2"))
            .unwrap()
            .as_str();
        match env::var(name) {
            Ok(s) => s.to_owned(),
            Err(env_err) => {
                err = Some(Error::UndefinedEnvironmentVariable {
                    name: name.to_owned(),
                    cause: env_err,
                });
                "".to_owned()
            }
        }
    });
    match err {
        None => Ok(result.into_owned()),
        Some(err) => Err(err),
    }
}

/// The location of a secret in a given backend.  This is exported to the
/// rest of this crate, but isn't part of the public `Secretfile` API,
/// because we might add more types of locations in the future.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Location {
    // Used for systems which identify credentials with simple string keys.
    Path(String),
    /// Used for systems like Vault where a path _and_ a hash key are
    /// needed to identify a specific credential.
    PathWithKey(String, String),
}

impl Location {
    /// Create a new `Location` from a regex `Captures` containing the
    /// named match `path` and optionally `key`.
    fn from_caps<'a>(caps: &Captures<'a>) -> Result<Location> {
        let path_opt = caps.name("path").map(|m| m.as_str());
        let key_opt = caps.name("key").map(|m| m.as_str());
        match (path_opt, key_opt) {
            (Some(path), None) => Ok(Location::Path(interpolate_env(path)?)),
            (Some(path), Some(key)) => Ok(Location::PathWithKey(
                interpolate_env(path)?,
                key.to_owned(),
            )),
            (_, _) => {
                let all = caps.get(0).unwrap().as_str().to_owned();
                Err(Error::Parse { input: all })
            }
        }
    }
}

/// A basic interface for loading a `Secretfile` and listing the various
/// variables and files contained inside.
#[derive(Debug, Clone)]
pub struct Secretfile {
    varmap: BTreeMap<String, Location>,
    filemap: BTreeMap<String, Location>,
}

impl Secretfile {
    fn read_internal(read: &mut dyn io::Read) -> Result<Secretfile> {
        // Only compile this Regex once.
        lazy_static! {
            // Match an individual line in a Secretfile.
            static ref RE: Regex = Regex::new(r"(?x)
^(?:
   # Blank line with optional comment.
   \s*(?:\#.*)?
 |
   (?:
     # VAR
     (?P<var>[a-zA-Z_][a-zA-Z0-9_]*)
   |
     # >file
     >(?P<file>\S+)
   )
   \s+
   # path/to/secret:key
   (?P<path>\S+?)(?::(?P<key>\S+))?
   \s*
 )$").unwrap();
        }

        let mut sf = Secretfile {
            varmap: BTreeMap::new(),
            filemap: BTreeMap::new(),
        };
        let buffer = io::BufReader::new(read);
        for line_or_err in buffer.lines() {
            let line = line_or_err?;
            match RE.captures(&line) {
                Some(ref caps) if caps.name("path").is_some() => {
                    let location = Location::from_caps(caps)?;
                    if caps.name("file").is_some() {
                        let file =
                            interpolate_env(caps.name("file").unwrap().as_str())?;
                        sf.filemap.insert(file, location);
                    } else if caps.name("var").is_some() {
                        let var = caps.name("var").unwrap().as_str().to_owned();
                        sf.varmap.insert(var, location);
                    }
                }
                Some(_) => {
                    // Blank or comment
                }
                _ => {
                    return Err(Error::Parse {
                        input: line.to_owned(),
                    })
                }
            }
        }
        Ok(sf)
    }

    /// Read in from an `io::Read` object.
    pub fn read(read: &mut dyn io::Read) -> Result<Secretfile> {
        Secretfile::read_internal(read).map_err(|err| Error::Secretfile(Box::new(err)))
    }

    /// Load the `Secretfile` at the specified path.
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Secretfile> {
        let path = path.as_ref();
        let mut file = File::open(path).map_err(|err| Error::FileRead {
            path: path.to_owned(),
            cause: Box::new(err.into()),
        })?;
        Secretfile::read(&mut file).map_err(|err| Error::FileRead {
            path: path.to_owned(),
            cause: Box::new(err),
        })
    }

    /// Set a built-in `Secretfile`. This is intended for command-line
    /// applications called directly by users, which do not normally have a
    /// `Secretfile` in the current directory, and which probably want to ignore
    /// one if it exists.
    ///
    /// This must be called before `credentials::var`.
    pub fn set_built_in(secretfile: Option<Secretfile>) {
        let guard = BUILT_IN_SECRETFILE
            .lock()
            .expect("Unable to lock `BUILT_IN_SECRETFILE`");
        *guard.borrow_mut() = secretfile;
    }

    /// Load the default `Secretfile`. This is normally `Secretfile` in the
    /// current working directory, but it can be overridden using
    /// `Secretfile::set_built_in`.
    pub fn default() -> Result<Secretfile> {
        // We have to use some extra temporary variables to keep the borrow
        // checker happy.
        let guard = BUILT_IN_SECRETFILE
            .lock()
            .expect("Unable to lock `BUILT_IN_SECRETFILE`");
        let built_in_opt = guard.borrow().to_owned();
        if let Some(built_in) = built_in_opt {
            Ok(built_in)
        } else {
            let mut path = env::current_dir()
                .map_err(|err| Error::Secretfile(Box::new(err.into())))?;
            path.push("Secretfile");
            Secretfile::from_path(path)
        }
    }

    /// Return an iterator over the environment variables listed in this
    /// file.
    pub fn vars(&self) -> SecretfileKeys {
        SecretfileKeys {
            keys: self.varmap.keys(),
        }
    }

    /// Return an iterator over the credential files listed in this file.
    pub fn files(&self) -> SecretfileKeys {
        SecretfileKeys {
            keys: self.filemap.keys(),
        }
    }
}

impl FromStr for Secretfile {
    type Err = Error;

    fn from_str(s: &str) -> Result<Secretfile> {
        let mut cursor = io::Cursor::new(s.as_bytes());
        Secretfile::read(&mut cursor)
    }
}

/// Internal methods for looking up `Location`s in `Secretfile`.  These are
/// hidden in a separate trait so that we can export them _within_ this
/// crate, but not expose them to other crates.
pub trait SecretfileLookup {
    /// Fetch the backend path for a variable listed in a `Secretfile`.
    fn var(&self, name: &str) -> Option<&Location>;

    /// Fetch the backend path for a file listed in a `Secretfile`.
    fn file(&self, name: &str) -> Option<&Location>;
}

impl SecretfileLookup for Secretfile {
    fn var(&self, name: &str) -> Option<&Location> {
        self.varmap.get(name)
    }

    fn file(&self, name: &str) -> Option<&Location> {
        self.filemap.get(name)
    }
}

/// An iterator over the keys mentioned in a `Secretfile`.
#[derive(Clone)]
pub struct SecretfileKeys<'a> {
    /// Our actual iterator, wrapped up only so that we don't need to
    /// expose the underlying implementation type in our stable API.
    keys: btree_map::Keys<'a, String, Location>,
}

// 'a is a lifetime specifier bound to the underlying collection we're
// iterating over, which keeps anybody from modifying it while we
// iterating.
impl<'a> Iterator for SecretfileKeys<'a> {
    type Item = &'a String;

    fn next(&mut self) -> Option<&'a String> {
        self.keys.next()
    }
}

#[test]
fn test_parse() {
    use std::str::FromStr;

    let data = "\
# This is a comment.

FOO_USERNAME secret/$SECRET_NAME:username\n\
FOO_PASSWORD secret/${SECRET_NAME}:password\n\

# Try a Keywhiz-style secret, too.
FOO_USERNAME2 ${SECRET_NAME}_username\n\

# Credentials to copy to a file.  Interpolation allowed on the left here.
>$SOMEDIR/.conf/key.pem secret/ssl:key_pem\n\
";
    env::set_var("SECRET_NAME", "foo");
    env::set_var("SOMEDIR", "/home/foo");
    let secretfile = Secretfile::from_str(data).unwrap();
    assert_eq!(
        &Location::PathWithKey("secret/foo".to_owned(), "username".to_owned()),
        secretfile.var("FOO_USERNAME").unwrap()
    );
    assert_eq!(
        &Location::PathWithKey("secret/foo".to_owned(), "password".to_owned()),
        secretfile.var("FOO_PASSWORD").unwrap()
    );
    assert_eq!(
        &Location::Path("foo_username".to_owned()),
        secretfile.var("FOO_USERNAME2").unwrap()
    );
    assert_eq!(
        &Location::PathWithKey("secret/ssl".to_owned(), "key_pem".to_owned()),
        secretfile.file("/home/foo/.conf/key.pem").unwrap()
    );

    assert_eq!(
        vec!["FOO_PASSWORD", "FOO_USERNAME", "FOO_USERNAME2"],
        secretfile.vars().collect::<Vec<_>>()
    );
    assert_eq!(
        vec!["/home/foo/.conf/key.pem"],
        secretfile.files().collect::<Vec<_>>()
    );
}
