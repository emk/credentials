//! Map application-level credential names to secrets in the backend store.
//!
//! In the case of Vault, this is necessary to transform
//! environment-variable-style credential names into Vault secret paths and
//! keys: from `MY_SECRET_PASSWORD` to the path `secret/my_secret` and the
//! key `"password"`.

use backend::{BoxedError, err};
use regex::{Captures, Regex};
use std::collections::BTreeMap;
use std::env;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

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
    fn from_caps<'a>(caps: &Captures<'a>) -> Result<Location, BoxedError> {
        match (caps.name("path"), caps.name("key")) {
            (Some(path), None) =>
                Ok(Location::Path(try!(interpolate_env(path)))),
            (Some(path), Some(key)) =>
                Ok(Location::PathWithKey(try!(interpolate_env(path)),
                                         key.to_owned())),
            (_, _) =>
                Err(err!("Could not parse location in Secretfile: {}",
                         caps.at(0).unwrap())),
        }
    }
}

/// Interpolate environment variables into a string.
fn interpolate_env(text: &str) -> Result<String, BoxedError> {
    // Only compile this Regex once.
    lazy_static! {
        static ref RE: Regex =
            Regex::new(r"\$(?:(?P<name>[a-zA-Z_][a-zA-Z0-9_]*)|\{(?P<name2>[a-zA-Z_][a-zA-Z0-9_]*)\})").unwrap();
    }

    // Perform the replacement.  This is mostly error-handling logic,
    // because `replace_all` doesn't anticipate any errors.
    let mut undefined_env_var = None;
    let result = RE.replace_all(text, |caps: &Captures| {
        let name =
            caps.name("name").or_else(|| { caps.name("name2") }).unwrap();
        match env::var(name) {
            Ok(s) => s.to_owned(),
            Err(_) => {
                undefined_env_var = Some(name.to_owned());
                "".to_owned()
            }
        }
    });
    match undefined_env_var {
        None => Ok(result),
        Some(var) =>
            Err(err!("Secretfile: Environment variable {} is not defined", var))
    }
}

#[derive(Debug, Clone)]
pub struct Secretfile {
    vars: BTreeMap<String, Location>,
    files: BTreeMap<String, Location>,
}

impl Secretfile {
    /// Read in from an `io::Read` object.
    pub fn read(read: &mut io::Read) -> Result<Secretfile, BoxedError> {
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
            vars: BTreeMap::new(),
            files: BTreeMap::new(),
        };
        let buffer = io::BufReader::new(read);
        for line_or_err in buffer.lines() {
            let line = try!(line_or_err);
            match RE.captures(&line) {
                Some(ref caps) if caps.name("path").is_some() => {
                    let location = try!(Location::from_caps(caps));
                    if caps.name("file").is_some() {
                        let file =
                            try!(interpolate_env(caps.name("file").unwrap()));
                        sf.files.insert(file, location);
                    } else if caps.name("var").is_some() {
                        let var = caps.name("var").unwrap().to_owned();
                        sf.vars.insert(var, location);
                    }
                }
                Some(_) => { /* Blank or comment */ },
                _ =>
                    return Err(err!("Error parsing Secretfile line: {}", &line)),
            }
        }
        Ok(sf)
    }

    /// Read a `Secretfile` from a string.  Currently only used for testing.
    pub fn from_str<S: AsRef<str>>(s: S) -> Result<Secretfile, BoxedError> {
        let mut cursor = io::Cursor::new(s.as_ref().as_bytes());
        Secretfile::read(&mut cursor)
    }

    /// Load the `Secretfile` at the specified path.
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Secretfile, BoxedError>
    {
        Secretfile::read(&mut try!(File::open(path)))
    }

    /// Load the default `Secretfile`.
    pub fn default() -> Result<Secretfile, BoxedError> {
        let mut path = try!(env::current_dir());
        path.push("Secretfile");
        Secretfile::from_path(path)
    }

    /// Fetch the backend path for a variable listed in a `Secretfile`.
    pub fn var(&self, name: &str) -> Option<&Location> {
        self.vars.get(name)
    }

    /// Fetch the backend path for a file listed in a `Secretfile`.
    pub fn file(&self, name: &str) -> Option<&Location> {
        self.files.get(name)
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
    assert_eq!(&Location::PathWithKey("secret/foo".to_owned(),
                                      "username".to_owned()),
               secretfile.var("FOO_USERNAME").unwrap());
    assert_eq!(&Location::PathWithKey("secret/foo".to_owned(),
                                      "password".to_owned()),
               secretfile.var("FOO_PASSWORD").unwrap());
    assert_eq!(&Location::Path("foo_username".to_owned()),
               secretfile.var("FOO_USERNAME2").unwrap());
    assert_eq!(&Location::PathWithKey("secret/ssl".to_owned(),
                                      "key_pem".to_owned()),
               secretfile.file("/home/foo/.conf/key.pem").unwrap());
}
