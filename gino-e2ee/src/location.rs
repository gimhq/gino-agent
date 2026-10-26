//! Location strings, the AAD of every envelope (spec §6), and their
//! templates over frames (spec §12.3).

use serde_json::Value;

use crate::Error;

/// The longest scope id in bytes.
const MAX_SCOPE_LEN: usize = 65535;

/// A location: `scope:<S>|<name>:<value>|…`. Names are `[a-z0-9_]+`, values
/// are non-empty and contain no `|`. Nothing is escaped: a part that breaks
/// these rules is `aad_mismatch`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Location {
    text: String,
    scope_end: usize,
}

impl Location {
    /// Starts a location with the `scope:<S>` part.
    pub fn new(scope: &str) -> Result<Self, Error> {
        if scope.len() > MAX_SCOPE_LEN {
            return Err(Error::AadMismatch);
        }
        check_value(scope)?;
        let text = format!("scope:{scope}");
        let scope_end = text.len();
        Ok(Self { text, scope_end })
    }

    /// Appends a `name:value` part.
    pub fn part(mut self, name: &str, value: &str) -> Result<Self, Error> {
        check_name(name)?;
        check_value(value)?;
        self.text.push('|');
        self.text.push_str(name);
        self.text.push(':');
        self.text.push_str(value);
        Ok(self)
    }

    /// Appends a `name:value` part with an integer value in decimal.
    pub fn part_u64(self, name: &str, value: u64) -> Result<Self, Error> {
        self.part(name, &value.to_string())
    }

    /// The location of the epoch link sealed under `k_epoch`:
    /// `scope:<S>|epoch_link:<epoch>`.
    pub fn epoch_link(scope: &str, epoch: u64) -> Result<Self, Error> {
        Self::new(scope)?.part_u64("epoch_link", epoch)
    }

    /// The location of a key-history envelope to a leaf:
    /// `scope:<S>|key_history:<epoch>|leaf:<leaf_index>`.
    pub fn key_history(scope: &str, epoch: u64, leaf_index: u32) -> Result<Self, Error> {
        Self::new(scope)?
            .part_u64("key_history", epoch)?
            .part_u64("leaf", leaf_index.into())
    }

    /// Resolves an AAD template against a frame. A placeholder `{<path>}` is
    /// a whole value; a `[]` segment of its path takes the array element
    /// `element`. A placeholder resolves to a JSON string as is or a
    /// non-negative integer in decimal; anything else is `aad_mismatch`.
    pub fn from_template(
        template: &str,
        frame: &Value,
        element: Option<usize>,
    ) -> Result<Self, Error> {
        Self::from_template_at(template, frame, element.as_slice())
    }

    /// Resolves an AAD template like [`Location::from_template`], with the
    /// `n`-th `[]` segment of a placeholder path taking `elements[n]`.
    pub(crate) fn from_template_at(
        template: &str,
        frame: &Value,
        elements: &[usize],
    ) -> Result<Self, Error> {
        Self::build(template, |value| resolve(value, frame, elements))
    }

    /// Parses a location string, checking every part.
    pub fn parse(text: &str) -> Result<Self, Error> {
        Self::build(text, |value| Ok(value.to_owned()))
    }

    /// Splits `text` into parts and builds the location from each part's
    /// name and its value mapped through `value_of`.
    fn build(text: &str, value_of: impl Fn(&str) -> Result<String, Error>) -> Result<Self, Error> {
        let mut parts = text.split('|');
        let mut location = match split_part(parts.next())? {
            ("scope", value) => Self::new(&value_of(value)?)?,
            _ => return Err(Error::AadMismatch),
        };
        for part in parts {
            let (name, value) = split_part(Some(part))?;
            location = location.part(name, &value_of(value)?)?;
        }
        Ok(location)
    }

    /// The location string.
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The location's UTF-8 bytes, as passed to the AEAD.
    pub fn as_bytes(&self) -> &[u8] {
        self.text.as_bytes()
    }

    /// The scope id of the first part.
    pub fn scope(&self) -> &str {
        self.text.get("scope:".len()..self.scope_end).unwrap_or("")
    }
}

impl std::fmt::Display for Location {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.text)
    }
}

fn check_name(name: &str) -> Result<(), Error> {
    let valid = !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
    if valid {
        Ok(())
    } else {
        Err(Error::AadMismatch)
    }
}

fn check_value(value: &str) -> Result<(), Error> {
    if value.is_empty() || value.contains('|') {
        Err(Error::AadMismatch)
    } else {
        Ok(())
    }
}

fn split_part(part: Option<&str>) -> Result<(&str, &str), Error> {
    part.and_then(|part| part.split_once(':'))
        .ok_or(Error::AadMismatch)
}

/// A literal template value as is, or the value a placeholder names.
fn resolve(value: &str, frame: &Value, elements: &[usize]) -> Result<String, Error> {
    let Some(path) = value
        .strip_prefix('{')
        .and_then(|rest| rest.strip_suffix('}'))
    else {
        return Ok(value.to_owned());
    };
    let mut current = frame;
    let mut elements = elements.iter();
    for segment in path.split('.') {
        let (key, is_array) = match segment.strip_suffix("[]") {
            Some(key) => (key, true),
            None => (segment, false),
        };
        let valid_key =
            !key.is_empty() && key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
        if !valid_key {
            return Err(Error::AadMismatch);
        }
        current = current.get(key).ok_or(Error::AadMismatch)?;
        if is_array {
            let index = elements.next().ok_or(Error::AadMismatch)?;
            current = current
                .as_array()
                .and_then(|items| items.get(*index))
                .ok_or(Error::AadMismatch)?;
        }
    }
    match current {
        Value::String(text) => Ok(text.clone()),
        Value::Number(number) => number
            .as_u64()
            .map(|n| n.to_string())
            .ok_or(Error::AadMismatch),
        _ => Err(Error::AadMismatch),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn builds_parts_in_order() {
        let location = Location::new("t-1")
            .unwrap()
            .part("frame", "thread_message")
            .unwrap()
            .part_u64("seq", 0)
            .unwrap()
            .part("field", "a:b")
            .unwrap();
        assert_eq!(
            location.as_str(),
            "scope:t-1|frame:thread_message|seq:0|field:a:b"
        );
        assert_eq!(location.scope(), "t-1");
        assert_eq!(Location::parse(location.as_str()), Ok(location));
        for text in [
            "",
            "scope:",
            "scope:a||f:x",
            "frame:x",
            "scope:a|F:x",
            "scope:a|f",
        ] {
            assert_eq!(Location::parse(text), Err(Error::AadMismatch), "{text}");
        }
        assert_eq!(
            Location::key_history("t-1", 8, 3).unwrap().as_str(),
            "scope:t-1|key_history:8|leaf:3"
        );
    }

    #[test]
    fn rejects_parts_instead_of_escaping() {
        assert_eq!(Location::new("a|b"), Err(Error::AadMismatch));
        assert_eq!(Location::new(""), Err(Error::AadMismatch));
        assert_eq!(Location::new(&"s".repeat(65536)), Err(Error::AadMismatch));
        let base = Location::new("t").unwrap();
        for (name, value) in [
            ("Field", "x"),
            ("", "x"),
            ("a-b", "x"),
            ("f", ""),
            ("f", "a|b"),
        ] {
            assert_eq!(base.clone().part(name, value), Err(Error::AadMismatch));
        }
    }

    #[test]
    fn resolves_templates() {
        let frame = json!({
            "task_id": "t-1",
            "data": { "seq": 7, "files": [{"id": "a"}, {"id": "b"}] }
        });
        let location = Location::from_template(
            "scope:{task_id}|seq:{data.seq}|file:{data.files[].id}|field:bytes",
            &frame,
            Some(1),
        )
        .unwrap();
        assert_eq!(location.as_str(), "scope:t-1|seq:7|file:b|field:bytes");

        for (template, element) in [
            ("frame:x|scope:{task_id}", None),
            ("scope:{missing}", None),
            ("scope:{data}", None),
            ("scope:{task_id}|file:{data.files[].id}", None),
            ("scope:{task_id}|file:{data.files[].id}", Some(2)),
            ("scope:{task_id}|nocolon", None),
            ("", None),
        ] {
            assert_eq!(
                Location::from_template(template, &frame, element),
                Err(Error::AadMismatch),
                "{template}"
            );
        }
        let negative = json!({"s": "t", "n": -1, "f": 1.5, "p": "a|b"});
        for template in ["scope:{s}|n:{n}", "scope:{s}|f:{f}", "scope:{s}|p:{p}"] {
            assert_eq!(
                Location::from_template(template, &negative, None),
                Err(Error::AadMismatch)
            );
        }
    }
}
