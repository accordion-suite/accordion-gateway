//! The name clients use to reach the server.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

/// The longest name DNS allows, not counting the trailing dot.
const MAX_NAME_LEN: usize = 253;
const MAX_LABEL_LEN: usize = 63;

/// Endings reserved for private networks and testing. No public certificate
/// authority issues certificates for them, so they can't be the server's name.
const PRIVATE_SUFFIXES: &[&str] = &[
    "local",
    "localhost",
    "internal",
    "home.arpa",
    "test",
    "invalid",
];

/// The server's public name, such as `accordion.example.com`.
///
/// It's the name on the server's certificate and the passkey relying party
/// ID, so it's kept in one normal form: lowercase, with no trailing dot.
/// Changing it later means every passkey must be registered again.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ServerName(String);

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum NameError {
    #[error("Enter a name for the server, such as accordion.example.com.")]
    Empty,
    #[error("That name is too long. Names can be up to {MAX_NAME_LEN} characters.")]
    TooLong,
    #[error("A name needs at least two parts separated by a dot, such as accordion.example.com.")]
    SingleLabel,
    #[error("That's a network address, not a name. Enter a name such as accordion.example.com.")]
    Address,
    #[error(
        "\"{0}\" can't be part of a name. Each part between dots can use letters, numbers, and \
         hyphens, up to {MAX_LABEL_LEN} characters, and can't start or end with a hyphen."
    )]
    InvalidLabel(String),
    #[error(
        "Names ending in .{0} work only on a private network, so they can't get a certificate. \
         Enter a name under a domain you control."
    )]
    Private(&'static str),
}

impl ServerName {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for ServerName {
    type Err = NameError;

    fn from_str(input: &str) -> Result<Self, NameError> {
        let trimmed = input.trim();
        let name = trimmed
            .strip_suffix('.')
            .unwrap_or(trimmed)
            .to_ascii_lowercase();

        if name.is_empty() {
            return Err(NameError::Empty);
        }
        if name.parse::<IpAddr>().is_ok() {
            return Err(NameError::Address);
        }
        if name.len() > MAX_NAME_LEN {
            return Err(NameError::TooLong);
        }
        for label in name.split('.') {
            if !is_valid_label(label) {
                return Err(NameError::InvalidLabel(label.to_owned()));
            }
        }
        if !name.contains('.') {
            return Err(NameError::SingleLabel);
        }
        // No top-level domain is all digits, so this is an address written in
        // a form IpAddr doesn't parse, such as 192.168.1.
        if name
            .rsplit('.')
            .next()
            .is_some_and(|tld| tld.bytes().all(|b| b.is_ascii_digit()))
        {
            return Err(NameError::Address);
        }
        if let Some(suffix) = PRIVATE_SUFFIXES
            .iter()
            .find(|suffix| name == **suffix || name.ends_with(&format!(".{suffix}")))
        {
            return Err(NameError::Private(suffix));
        }

        Ok(Self(name))
    }
}

/// Letters, digits, and hyphens, not starting or ending with a hyphen.
/// Names in other scripts must already be in their `xn--` form.
fn is_valid_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= MAX_LABEL_LEN
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

impl fmt::Display for ServerName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for ServerName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(input: &str) -> Result<String, NameError> {
        input.parse::<ServerName>().map(|name| name.to_string())
    }

    #[test]
    fn keeps_names_in_one_form() {
        assert_eq!(
            parse("Accordion.Example.COM"),
            Ok("accordion.example.com".into())
        );
        assert_eq!(
            parse(" accordion.example.com. "),
            Ok("accordion.example.com".into())
        );
        assert_eq!(parse("ourhome.dedyn.io"), Ok("ourhome.dedyn.io".into()));
        assert_eq!(
            parse("xn--bcher-kva.example"),
            Ok("xn--bcher-kva.example".into())
        );
    }

    #[test]
    fn rejects_addresses() {
        assert_eq!(parse("192.168.1.10"), Err(NameError::Address));
        assert_eq!(parse("::1"), Err(NameError::Address));
        assert_eq!(parse("192.168.1"), Err(NameError::Address));
    }

    #[test]
    fn rejects_names_without_a_dot() {
        assert_eq!(parse("accordion"), Err(NameError::SingleLabel));
        assert_eq!(parse(""), Err(NameError::Empty));
        assert_eq!(parse("."), Err(NameError::Empty));
    }

    #[test]
    fn rejects_invalid_labels() {
        for name in [
            "-accordion.example.com",
            "accordion-.example.com",
            "my_home.example.com",
            "a..b",
            "bücher.example",
        ] {
            assert!(
                matches!(parse(name), Err(NameError::InvalidLabel(_))),
                "{name}"
            );
        }
        let long_label = format!("{}.example.com", "a".repeat(64));
        assert!(matches!(
            parse(&long_label),
            Err(NameError::InvalidLabel(_))
        ));
        let long_name = format!("{}.com", "a.".repeat(126));
        assert_eq!(parse(&long_name), Err(NameError::TooLong));
    }

    #[test]
    fn rejects_private_names() {
        assert_eq!(parse("accordion.local"), Err(NameError::Private("local")));
        assert_eq!(
            parse("accordion.home.arpa"),
            Err(NameError::Private("home.arpa"))
        );
        assert_eq!(parse("home.arpa"), Err(NameError::Private("home.arpa")));
        // Only whole labels count, so a domain that merely ends in the same
        // letters is fine.
        assert_eq!(parse("accordion.notlocal"), Ok("accordion.notlocal".into()));
    }
}
