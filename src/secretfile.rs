//! Map application-level credential names to secrets in the backend store.
//!
//! In the case of Vault, this is necessary to transform
//! environment-variable-style credential names into Vault secret paths and
//! keys: from `MY_SECRET_PASSWORD` to the path `secret/my_secret` and the
//! key `"password"`.

use backend::BoxedError;
use regex::Regex;
use std::collections::BTreeMap;
use std::io::{self, BufRead};

#[derive(Debug, PartialEq, Eq)]
pub enum Location {
    // We'll use this for Keywhiz and other systems which store simple
    // string credentials.
    //Simple(String),
    /// We use this for systems like Vault which store key-value
    /// dictionaries in each secret.
    Keyed(String, String),
}

#[derive(Debug)]
pub struct Secretfile {
    mappings: BTreeMap<String, Location>,
}

impl Secretfile {
    /// Read in from an `io::Read` object.
    pub fn read(read: &mut io::Read) -> Result<Secretfile, BoxedError> {
        // Match a line of our file.
        let re = Regex::new(r"(?x)
^(?:
   # Blank line with optional comment.
   \s*(?:\#.*)?
 |
   # NAME path/to/secret:key
   (?P<name>\S+)
   \s+
   (?P<path>\S+?):(?P<key>\S+)
   \s*
 )$").unwrap();

        // TODO: Environment interpolation.
        let mut sf = Secretfile { mappings: BTreeMap::new() };
        let buffer = io::BufReader::new(read);
        for line_or_err in buffer.lines() {
            let line = try!(line_or_err);
            match re.captures(&line) {
                Some(ref caps) if caps.name("name").is_some() => {
                    let location = Location::Keyed(
                        caps.name("path").unwrap().to_owned(),
                        caps.name("key").unwrap().to_owned(),
                    );
                    sf.mappings.insert(caps.name("name").unwrap().to_owned(),
                                       location);
                }
                Some(_) => { /* Blank or comment */ },
                _ => {
                    let msg =
                        format!("Error parsing Secretfile line: {}", &line);
                    return Err(From::from(msg));
                }
            }
        }
        Ok(sf)
    }

    pub fn from_str<S: AsRef<str>>(s: S) -> Result<Secretfile, BoxedError> {
        let mut cursor = io::Cursor::new(s.as_ref().as_bytes());
        Secretfile::read(&mut cursor)
    }

    pub fn get(&self, name: &str) -> Option<&Location> {
        self.mappings.get(name)
    }
}

#[test]
fn test_parse() {
    let data = "\
# This is a comment.

FOO_USERNAME secret/foo:username\n\
FOO_PASSWORD secret/foo:password\n\
";
    let secretfile = Secretfile::from_str(data).unwrap();
    assert_eq!(&Location::Keyed("secret/foo".to_owned(), "username".to_owned()),
               secretfile.get("FOO_USERNAME").unwrap());
    assert_eq!(&Location::Keyed("secret/foo".to_owned(), "password".to_owned()),
               secretfile.get("FOO_PASSWORD").unwrap());
}
