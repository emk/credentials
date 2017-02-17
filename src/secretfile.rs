//! Map application-level credential names to secrets in the backend store.
//!
//! In the case of Vault, this is necessary to transform
//! environment-variable-style credential names into Vault secret paths and
//! keys: from `MY_SECRET_PASSWORD` to the path `secret/my_secret` and the
//! key `"password"`.

use errors::*;
use regex::{Captures, Regex};
use std::collections::{btree_map, BTreeMap};
use std::env;
use std::fs::File;
use std::iter::Iterator;
use std::io::{self, BufRead};
use std::path::Path;


/// Interpolate environment variables into a string.
fn interpolate_env(text: &str) -> Result<String> {
    // Only compile this Regex once.
    lazy_static! {
        static ref RE: Regex =
            Regex::new(r"(?x)
\$(?:
    (?P<name>[a-zA-Z_][a-zA-Z0-9_]*)
  |
    \{(?P<name2>[a-zA-Z_][a-zA-Z0-9_]*)\}
  )").unwrap();
    }

    // Perform the replacement.  This is mostly error-handling logic,
    // because `replace_all` doesn't anticipate any errors.
    let mut undefined_env_var = None;
    let result = RE.replace_all(text, |caps: &Captures| {
        let name = caps.name("name").or_else(|| caps.name("name2"))
            .unwrap()
            .as_str();
        match env::var(name) {
            Ok(s) => s.to_owned(),
            Err(_) => {
                undefined_env_var = Some(name.to_owned());
                "".to_owned()
            }
        }
    });
    match undefined_env_var {
        None => Ok(result.into_owned()),
        Some(var) => Err(ErrorKind::UndefinedEnvironmentVariable(var).into()),
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
            (Some(path), Some(key)) => {
                Ok(Location::PathWithKey(interpolate_env(path)?, key.to_owned()))
            }
            (_, _) => {
                let all = caps.get(0).unwrap().as_str().to_owned();
                Err(ErrorKind::Parse(all).into())
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
    fn read_internal(read: &mut io::Read) -> Result<Secretfile> {
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
                _ => return Err(ErrorKind::Parse(line.to_owned()).into()),
            }
        }
        Ok(sf)
    }

    /// Read in from an `io::Read` object.
    pub fn read(read: &mut io::Read) -> Result<Secretfile> {
        Secretfile::read_internal(read).chain_err(|| ErrorKind::Secretfile)
    }

    /// Read a `Secretfile` from a string.  Currently only used for testing.
    pub fn from_str<S: AsRef<str>>(s: S) -> Result<Secretfile> {
        let mut cursor = io::Cursor::new(s.as_ref().as_bytes());
        Secretfile::read(&mut cursor)
    }

    /// Load the `Secretfile` at the specified path.
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Secretfile> {
        let path = path.as_ref();
        let mkerr = || ErrorKind::FileRead(path.to_owned());
        let mut file = File::open(path).chain_err(&mkerr)?;
        Secretfile::read(&mut file).chain_err(&mkerr)
    }

    /// Load the default `Secretfile`.
    pub fn default() -> Result<Secretfile> {
        let mut path = env::current_dir().chain_err(|| ErrorKind::Secretfile)?;
        path.push("Secretfile");
        Secretfile::from_path(path)
    }

    /// Return an iterator over the environment variables listed in this
    /// file.
    pub fn vars(&self) -> SecretfileKeys {
        SecretfileKeys { keys: self.varmap.keys() }
    }

    /// Return an iterator over the credential files listed in this file.
    pub fn files(&self) -> SecretfileKeys {
        SecretfileKeys { keys: self.filemap.keys() }
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
    assert_eq!(&Location::PathWithKey("secret/foo".to_owned(), "username".to_owned()),
               secretfile.var("FOO_USERNAME").unwrap());
    assert_eq!(&Location::PathWithKey("secret/foo".to_owned(), "password".to_owned()),
               secretfile.var("FOO_PASSWORD").unwrap());
    assert_eq!(&Location::Path("foo_username".to_owned()),
               secretfile.var("FOO_USERNAME2").unwrap());
    assert_eq!(&Location::PathWithKey("secret/ssl".to_owned(), "key_pem".to_owned()),
               secretfile.file("/home/foo/.conf/key.pem").unwrap());

    assert_eq!(vec!["FOO_PASSWORD", "FOO_USERNAME", "FOO_USERNAME2"],
               secretfile.vars().collect::<Vec<_>>());
    assert_eq!(vec!["/home/foo/.conf/key.pem"],
               secretfile.files().collect::<Vec<_>>());
}
