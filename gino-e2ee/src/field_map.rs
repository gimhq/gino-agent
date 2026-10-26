//! Field maps (spec §12): the sealed values of a profile's frames with their
//! AAD templates, and the engine that seals and opens whole frames over
//! `serde_json::Value`.
//!
//! The tables are generated from `docs/e2ee/*.fieldmap.json` by
//! `sdks/e2ee/scripts/gen-field-map.ts`; the engine reads them as data, so it
//! serves every profile.

#[rustfmt::skip]
mod generated;

use openmls_traits::random::OpenMlsRand;
use serde_json::{Map, Value};

use crate::envelope::KEY_LEN;
use crate::{
    EnvelopeType, Error, Header, Location, Opened, decode_b64url, decode_json, decode_text,
    from_sealed_value, json_plaintext, seal_content, to_sealed_value,
};

pub use generated::{PROFILES, TASK_CONTENT};

/// The member name of the sealed form.
const SEALED_MEMBER: &str = "e2ee";

/// The direction of a frame type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Sent by the host to the agent.
    HostToAgent,
    /// Sent by the agent to the host.
    AgentToHost,
}

/// The kind of a mapped value (spec §12.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A JSON string, sealed as its UTF-8 bytes.
    Text,
    /// Any JSON value, sealed as its compact serialization.
    Json,
    /// An attachment descriptor whose bytes are a file envelope; the
    /// descriptor itself is not replaced.
    Blob,
}

/// The comparison of a [`When`] condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WhenOp {
    /// The string at the path equals the value.
    Eq,
    /// The string at the path is absent or differs from the value.
    Ne,
}

/// A condition on a cleartext string of the frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct When {
    /// The frame path of the string.
    pub path: &'static str,
    /// The comparison.
    pub op: WhenOp,
    /// The compared value.
    pub value: &'static str,
}

/// Plain paths of a `json` value selected by a cleartext discriminator
/// (spec §12.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyedPlain {
    /// The frame path of the discriminator.
    pub key: &'static str,
    /// Discriminator value to the plain paths, relative to the value.
    pub table: &'static [(&'static str, &'static [&'static str])],
}

/// One field rule (spec §12.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldRule {
    /// The frame path; a `[]` segment means every array element.
    pub path: &'static str,
    /// The value kind.
    pub kind: Kind,
    /// The envelope types allowed at the path.
    pub envelopes: &'static [EnvelopeType],
    /// The AAD template (spec §12.3).
    pub aad: &'static str,
    /// The condition under which the rule applies.
    pub when: Option<When>,
    /// Plain paths kept out of sealing.
    pub keyed_plain: Option<KeyedPlain>,
}

/// The rules of one frame type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameRule {
    /// The frame type.
    pub frame_type: &'static str,
    /// The direction of the frame.
    pub direction: Direction,
    /// The frame path of the scope id.
    pub scope: &'static str,
    /// The field rules, in sealing order.
    pub fields: &'static [FieldRule],
}

/// A profile's field map (spec §12.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldMap {
    /// The profile id.
    pub profile: &'static str,
    /// The frame types with sealed fields.
    pub frames: &'static [FrameRule],
}

impl FieldMap {
    /// The generated field map of `profile`.
    pub fn for_profile(profile: &str) -> Option<&'static FieldMap> {
        PROFILES.iter().copied().find(|map| map.profile == profile)
    }

    /// The rules of `frame_type`, if it has sealed fields.
    pub fn frame(&self, frame_type: &str) -> Option<&FrameRule> {
        self.frames
            .iter()
            .find(|frame| frame.frame_type == frame_type)
    }

    /// Seals every mapped value present in `frame` as a content envelope under
    /// `k_e` of the current `epoch`, each at the location its template builds
    /// from the frame's cleartext fields, and returns the frame with the
    /// sealed forms in place. Salts are drawn from `rng` in rule order, then
    /// array order, then split-walk order. A frame type without rules is
    /// returned unchanged; `blob` rules leave their descriptors as they are.
    pub fn seal_frame(
        &self,
        frame_type: &str,
        frame: &Value,
        epoch: u64,
        k_e: &[u8; KEY_LEN],
        rng: &impl OpenMlsRand,
    ) -> Result<Value, Error> {
        let mut output = frame.clone();
        let Some(rules) = self.frame(frame_type) else {
            return Ok(output);
        };
        for rule in sealing_rules(rules, frame) {
            for instance in instances(frame, rule.path) {
                let value = instance.get(frame).ok_or(Error::SealFailed)?;
                let mut seal = |value: &Value, at: &[Segment]| {
                    let location = part_location(rule, frame, &instance.elements, at)?;
                    let plaintext = match rule.kind {
                        Kind::Text => value.as_str().ok_or(Error::SealFailed)?.as_bytes().to_vec(),
                        _ => json_plaintext(value)?,
                    };
                    let envelope = seal_content(k_e, epoch, &location, &plaintext, rng)?;
                    Ok(to_sealed_value(&envelope))
                };
                let sealed = match plain_set(rule, frame) {
                    Some(plain) => seal_split(value, &plain, &mut Vec::new(), &mut seal)?,
                    None => seal(value, &[])?,
                };
                instance.set(&mut output, sealed)?;
            }
        }
        Ok(output)
    }

    /// Opens every mapped value of `frame` from an encrypted scope and returns
    /// the frame with the plaintexts in place. `open` opens one envelope at
    /// its location, resolving its epoch's secrets (for example
    /// [`History::open`](crate::History::open) over the member's key cache
    /// and the scope's epoch links). A mapped value that is not sealed is
    /// `plaintext_rejected`; on any failure nothing is returned but the error.
    /// A frame type without rules is returned unchanged.
    pub fn open_frame(
        &self,
        frame_type: &str,
        frame: &Value,
        mut open: impl FnMut(&[u8], &Location) -> Result<Opened, Error>,
    ) -> Result<Value, Error> {
        let mut output = frame.clone();
        let Some(rules) = self.frame(frame_type) else {
            return Ok(output);
        };
        for rule in sealing_rules(rules, frame) {
            for instance in instances(frame, rule.path) {
                let value = instance.get(frame).ok_or(Error::Malformed)?;
                let mut open_part = |envelope: &[u8], at: &[Segment]| {
                    let location = part_location(rule, frame, &instance.elements, at)?;
                    let header = Header::parse(envelope)?;
                    if !rule.envelopes.contains(&header.envelope_type) {
                        return Err(Error::Malformed);
                    }
                    let plaintext = open(envelope, &location)?.plaintext;
                    match rule.kind {
                        Kind::Text => decode_text(plaintext).map(Value::String),
                        _ => decode_json(&plaintext),
                    }
                };
                let opened = match plain_set(rule, frame) {
                    Some(plain) => open_split(value, &plain, &mut Vec::new(), &mut open_part)?,
                    None => open_part(&from_sealed_value(value)?, &[])?,
                };
                instance.set(&mut output, opened)?;
            }
        }
        Ok(output)
    }
}

/// The `text`/`json` rules of a frame type that apply to `frame`.
fn sealing_rules<'a>(
    rules: &'a FrameRule,
    frame: &'a Value,
) -> impl Iterator<Item = &'a FieldRule> + 'a {
    rules.fields.iter().filter(move |rule| {
        rule.kind != Kind::Blob
            && rule.when.is_none_or(|when| {
                let equal = lookup(frame, when.path).and_then(Value::as_str) == Some(when.value);
                equal == (when.op == WhenOp::Eq)
            })
    })
}

/// The value at a frame path without `[]`; an absent segment or a non-object
/// intermediate is `None`.
fn lookup<'a>(frame: &'a Value, path: &str) -> Option<&'a Value> {
    path.split('.')
        .try_fold(frame, |value, key| value.as_object()?.get(key))
}

/// One concrete step into a JSON value.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Segment {
    Member(String),
    Element(usize),
}

impl Segment {
    fn as_path_part(&self) -> String {
        match self {
            Self::Member(key) => key.clone(),
            Self::Element(index) => index.to_string(),
        }
    }
}

/// A concrete position of a rule path in a frame, with the array index of
/// each `[]` segment.
#[derive(Debug)]
struct Instance {
    at: Vec<Segment>,
    elements: Vec<usize>,
}

impl Instance {
    fn get<'a>(&self, frame: &'a Value) -> Option<&'a Value> {
        self.at
            .iter()
            .try_fold(frame, |value, segment| match segment {
                Segment::Member(key) => value.get(key),
                Segment::Element(index) => value.get(index),
            })
    }

    fn set(&self, frame: &mut Value, new: Value) -> Result<(), Error> {
        let slot = self
            .at
            .iter()
            .try_fold(frame, |value, segment| match segment {
                Segment::Member(key) => value.get_mut(key),
                Segment::Element(index) => value.get_mut(index),
            })
            .ok_or(Error::Malformed)?;
        *slot = new;
        Ok(())
    }
}

/// Every present value of a rule path, in array order. A path does not
/// apply where a segment is absent, an intermediate is not an object (or not
/// an array at `[]`), or the value is `null`.
fn instances(frame: &Value, path: &str) -> Vec<Instance> {
    let segments: Vec<(&str, bool)> = path
        .split('.')
        .map(|segment| match segment.strip_suffix("[]") {
            Some(key) => (key, true),
            None => (segment, false),
        })
        .collect();
    let mut found = Vec::new();
    let mut current = Instance {
        at: Vec::new(),
        elements: Vec::new(),
    };
    collect(frame, &segments, &mut current, &mut found);
    found
}

fn collect(
    value: &Value,
    segments: &[(&str, bool)],
    current: &mut Instance,
    found: &mut Vec<Instance>,
) {
    let Some(((key, is_array), rest)) = segments.split_first() else {
        if !value.is_null() {
            found.push(Instance {
                at: current.at.clone(),
                elements: current.elements.clone(),
            });
        }
        return;
    };
    let Some(child) = value.as_object().and_then(|object| object.get(*key)) else {
        return;
    };
    current.at.push(Segment::Member((*key).to_owned()));
    if *is_array {
        if let Some(items) = child.as_array() {
            for (index, item) in items.iter().enumerate() {
                current.at.push(Segment::Element(index));
                current.elements.push(index);
                collect(item, rest, current, found);
                current.elements.pop();
                current.at.pop();
            }
        }
    } else {
        collect(child, rest, current, found);
    }
    current.at.pop();
}

/// The location of a part at concrete path `at` inside a rule's value: the
/// rule's template with `.<at>` appended to its last (literal) part.
fn part_location(
    rule: &FieldRule,
    frame: &Value,
    elements: &[usize],
    at: &[Segment],
) -> Result<Location, Error> {
    if at.is_empty() {
        return Location::from_template_at(rule.aad, frame, elements);
    }
    let concrete: Vec<String> = at.iter().map(Segment::as_path_part).collect();
    let template = format!("{}.{}", rule.aad, concrete.join("."));
    Location::from_template_at(&template, frame, elements)
}

/// One step of a plain path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step<'a> {
    Member(&'a str),
    Element,
}

impl Step<'_> {
    fn matches(self, segment: &Segment) -> bool {
        match (self, segment) {
            (Self::Member(name), Segment::Member(key)) => name == key,
            (Self::Element, Segment::Element(_)) => true,
            _ => false,
        }
    }
}

/// The plain set selected by the discriminator of a `keyed_plain` rule, or
/// `None` when the value is sealed whole.
fn plain_set(rule: &FieldRule, frame: &Value) -> Option<Vec<Vec<Step<'static>>>> {
    let keyed = rule.keyed_plain?;
    let method = lookup(frame, keyed.key)?.as_str()?;
    let (_, paths) = keyed.table.iter().find(|(key, _)| *key == method)?;
    if paths.is_empty() {
        return None;
    }
    let steps = paths
        .iter()
        .map(|path| {
            path.split('.')
                .flat_map(|segment| match segment.strip_suffix("[]") {
                    Some(name) => vec![Step::Member(name), Step::Element],
                    None => vec![Step::Member(segment)],
                })
                .collect()
        })
        .collect();
    Some(steps)
}

/// The class of a position in the split walk (spec §12.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Position {
    Plain,
    /// A proper prefix of a plain path; the next step says whether the
    /// container is an object (`true`) or an array.
    Descend {
        object: bool,
    },
    Sealed,
}

fn classify(plain: &[Vec<Step<'_>>], at: &[Segment]) -> Position {
    let mut position = Position::Sealed;
    for path in plain {
        let prefix = path.len() >= at.len()
            && path
                .iter()
                .zip(at)
                .all(|(step, segment)| step.matches(segment));
        if !prefix {
            continue;
        }
        match path.get(at.len()) {
            None => return Position::Plain,
            Some(step) => {
                position = Position::Descend {
                    object: matches!(step, Step::Member(_)),
                }
            }
        }
    }
    position
}

/// A member key on a concrete path: non-empty, without `.` and `|`.
fn check_key(key: &str) -> Result<(), Error> {
    if key.is_empty() || key.contains(['.', '|']) {
        Err(Error::AadMismatch)
    } else {
        Ok(())
    }
}

/// The members of an object in ascending byte order of key.
fn sorted_members(object: &Map<String, Value>) -> Vec<(&String, &Value)> {
    let mut members: Vec<_> = object.iter().collect();
    members.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    members
}

/// Seals a split value: plain positions stay, descend containers are
/// walked, everything else is sealed with `seal(value, at)`.
fn seal_split(
    value: &Value,
    plain: &[Vec<Step<'_>>],
    at: &mut Vec<Segment>,
    seal: &mut impl FnMut(&Value, &[Segment]) -> Result<Value, Error>,
) -> Result<Value, Error> {
    match (classify(plain, at), value) {
        (Position::Plain, _) => Ok(value.clone()),
        (Position::Descend { object: true }, Value::Object(object)) => {
            let mut output = Map::new();
            for (key, member) in sorted_members(object) {
                check_key(key)?;
                at.push(Segment::Member(key.clone()));
                let sealed = seal_split(member, plain, at, seal);
                at.pop();
                output.insert(key.clone(), sealed?);
            }
            Ok(Value::Object(output))
        }
        (Position::Descend { object: false }, Value::Array(items)) => {
            let mut output = Vec::with_capacity(items.len());
            for (index, item) in items.iter().enumerate() {
                at.push(Segment::Element(index));
                let sealed = seal_split(item, plain, at, seal);
                at.pop();
                output.push(sealed?);
            }
            Ok(Value::Array(output))
        }
        _ => seal(value, at),
    }
}

/// The base64url text of an object whose only member is `e2ee` with a
/// string value.
fn sealed_part(value: &Value) -> Option<&str> {
    let object = value.as_object().filter(|object| object.len() == 1)?;
    object.get(SEALED_MEMBER)?.as_str()
}

/// Opens a split value: plain positions are accepted as they are, sealed
/// parts are opened with `open(envelope, at)`, descend containers walked.
fn open_split(
    value: &Value,
    plain: &[Vec<Step<'_>>],
    at: &mut Vec<Segment>,
    open: &mut impl FnMut(&[u8], &[Segment]) -> Result<Value, Error>,
) -> Result<Value, Error> {
    let position = classify(plain, at);
    if position == Position::Plain {
        return Ok(value.clone());
    }
    if let Some(text) = sealed_part(value) {
        return open(&decode_b64url(text)?, at);
    }
    match (position, value) {
        (Position::Descend { object: true }, Value::Object(object)) => {
            let mut output = Map::new();
            for (key, member) in sorted_members(object) {
                check_key(key)?;
                at.push(Segment::Member(key.clone()));
                let opened = open_split(member, plain, at, open);
                at.pop();
                output.insert(key.clone(), opened?);
            }
            Ok(Value::Object(output))
        }
        (Position::Descend { object: false }, Value::Array(items)) => {
            let mut output = Vec::with_capacity(items.len());
            for (index, item) in items.iter().enumerate() {
                at.push(Segment::Element(index));
                let opened = open_split(item, plain, at, open);
                at.pop();
                output.push(opened?);
            }
            Ok(Value::Array(output))
        }
        (Position::Sealed, Value::Object(object))
            if object.len() == 1 && object.contains_key(SEALED_MEMBER) =>
        {
            Err(Error::Malformed)
        }
        _ => Err(Error::PlaintextRejected),
    }
}
