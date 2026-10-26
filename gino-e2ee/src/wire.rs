//! JSON wire encoding (spec §5.1, §12.4): base64url without padding, the
//! sealed form `{"e2ee": "<base64url>"}` and the `text`/`json` plaintexts.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::Value;

use crate::Error;

/// The member name of the sealed form.
const SEALED_MEMBER: &str = "e2ee";

/// Encodes bytes as base64url without padding.
pub fn encode_b64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decodes base64url without padding. Padding, whitespace, characters outside
/// the alphabet and non-zero trailing bits are `malformed`.
pub fn decode_b64url(text: &str) -> Result<Vec<u8>, Error> {
    URL_SAFE_NO_PAD.decode(text).map_err(|_| Error::Malformed)
}

/// The sealed form of an envelope.
pub fn to_sealed_value(envelope: &[u8]) -> Value {
    let mut object = serde_json::Map::new();
    object.insert(SEALED_MEMBER.into(), encode_b64url(envelope).into());
    object.into()
}

/// The envelope bytes of a mapped value. A value that is not an object with
/// an `e2ee` member is `plaintext_rejected`; extra members, a non-string
/// `e2ee` or bad base64url is `malformed`.
pub fn from_sealed_value(value: &Value) -> Result<Vec<u8>, Error> {
    let object = value
        .as_object()
        .filter(|object| object.contains_key(SEALED_MEMBER))
        .ok_or(Error::PlaintextRejected)?;
    if object.len() != 1 {
        return Err(Error::Malformed);
    }
    match object.get(SEALED_MEMBER) {
        Some(Value::String(text)) => decode_b64url(text),
        _ => Err(Error::Malformed),
    }
}

/// The plaintext of a `json` field: its compact serialization.
pub fn json_plaintext(value: &Value) -> Result<Vec<u8>, Error> {
    serde_json::to_vec(value).map_err(|_| Error::SealFailed)
}

/// Decodes an opened `text` plaintext; invalid UTF-8 is `malformed`.
pub fn decode_text(plaintext: Vec<u8>) -> Result<String, Error> {
    String::from_utf8(plaintext).map_err(|_| Error::Malformed)
}

/// Decodes an opened `json` plaintext; anything but one JSON value is
/// `malformed`.
pub fn decode_json(plaintext: &[u8]) -> Result<Value, Error> {
    serde_json::from_slice(plaintext).map_err(|_| Error::Malformed)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn b64url_round_trip_without_padding() {
        let bytes = [0xfb, 0xff, 0x01];
        let text = encode_b64url(&bytes);
        assert_eq!(text, "-_8B");
        assert_eq!(decode_b64url(&text).unwrap(), bytes);
        assert_eq!(encode_b64url(&[1]), "AQ");
    }

    #[test]
    fn b64url_rejects_non_canonical_input() {
        for text in ["AQ==", "AQ=", "AR", "A Q", "AQ\n", "+/8B", "A"] {
            assert_eq!(decode_b64url(text), Err(Error::Malformed), "{text:?}");
        }
    }

    #[test]
    fn sealed_form_is_strict() {
        let sealed = to_sealed_value(&[1, 2, 3]);
        assert_eq!(sealed, json!({"e2ee": "AQID"}));
        assert_eq!(from_sealed_value(&sealed).unwrap(), [1, 2, 3]);
        assert_eq!(
            from_sealed_value(&json!("plain")),
            Err(Error::PlaintextRejected)
        );
        assert_eq!(
            from_sealed_value(&json!({"text": "x"})),
            Err(Error::PlaintextRejected)
        );
        assert_eq!(
            from_sealed_value(&json!({"e2ee": "AQID", "x": 1})),
            Err(Error::Malformed)
        );
        assert_eq!(
            from_sealed_value(&json!({"e2ee": 1})),
            Err(Error::Malformed)
        );
    }

    #[test]
    fn plaintext_decoding() {
        assert_eq!(decode_text(vec![0xff]), Err(Error::Malformed));
        assert_eq!(decode_json(b"{\"a\":1} 2"), Err(Error::Malformed));
        assert_eq!(
            json_plaintext(&json!({"a": [1, "b"]})).unwrap(),
            br#"{"a":[1,"b"]}"#
        );
    }
}
