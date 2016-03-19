//! Map application-level credential names to secrets in the backend store.
//!
//! In the case of Vault, this is necessary to transform
//! environment-variable-style credential names into Vault secret paths and
//! keys: from `MY_SECRET_PASSWORD` to the path `secret/my_secret` and the
//! key `"password"`.

use backend::BoxedError;
use std::collections::BTreeMap;
use std::io::{self, BufRead};

#[derive(Debug, PartialEq, Eq)]
pub enum Location {
    // We'll probably want this for Keywhiz, which uses simpler keys.
    //Simple(String),
    Keyed(String, String),
}

pub struct Secretfile {
    mappings: BTreeMap<String, Location>,
}

impl Secretfile {
    /// Read in from an `io::Read` object.
    pub fn read(read: &mut io::Read) -> Result<Secretfile, BoxedError> {
        // TODO: Remove all `unwrap`.
        // TODO: Comments.
        // TODO: Blank lines.
        // TODO: Environment interpolation.
        let mut result = Secretfile { mappings: BTreeMap::new() };
        let buffer = io::BufReader::new(read);
        for line_or_err in buffer.lines() {
            let line = try!(line_or_err);
            let fields: Vec<_> = line.splitn(2, ' ').collect();
            let location_fields: Vec<_> =
                fields.get(1).unwrap().split(':').collect();
            let location = Location::Keyed(
                location_fields.get(0).unwrap().to_string(),
                location_fields.get(1).unwrap().to_string(),
            );
            
            result.mappings.insert(fields.get(0).unwrap().to_string(),
                                   location);
        }
        Ok(result)
    }
}

#[test]
fn test_parse() {
    let data = "\
FOO_USERNAME secret/foo:username\n\
FOO_PASSWORD secret/foo:password\n\
";
    let mut cursor = io::Cursor::new(data.as_bytes());
    let secretfile = Secretfile::read(&mut cursor).unwrap();
    assert_eq!(&Location::Keyed("secret/foo".to_owned(), "username".to_owned()),
               secretfile.mappings.get("FOO_USERNAME").unwrap());
    assert_eq!(&Location::Keyed("secret/foo".to_owned(), "password".to_owned()),
               secretfile.mappings.get("FOO_PASSWORD").unwrap());
}
