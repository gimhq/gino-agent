//! Network allow-rule types and the compiled matcher.

use std::fmt;
use std::net::{IpAddr, SocketAddr};

use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

const MAX_NAME_LEN: usize = 253;
const MAX_LABEL_LEN: usize = 63;

/// Transport protocol of a flow.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    /// TCP (the default for rules).
    #[default]
    Tcp,
    /// UDP.
    Udp,
}

impl Proto {
    /// Stable lowercase name used for logging.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

/// Destination ports of a rule: `"*"` or a list of port numbers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ports {
    /// Any port.
    Any,
    /// Only the listed ports.
    List(Vec<u16>),
}

impl Ports {
    fn contains(&self, port: u16) -> bool {
        match self {
            Self::Any => true,
            Self::List(ports) => ports.contains(&port),
        }
    }
}

impl Serialize for Ports {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Any => serializer.serialize_str("*"),
            Self::List(ports) => ports.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for Ports {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct PortsVisitor;

        impl<'de> Visitor<'de> for PortsVisitor {
            type Value = Ports;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(r#""*" or an array of port numbers"#)
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Ports, E> {
                if v == "*" {
                    Ok(Ports::Any)
                } else {
                    Err(E::invalid_value(de::Unexpected::Str(v), &self))
                }
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Ports, A::Error> {
                let mut ports = Vec::new();
                while let Some(port) = seq.next_element::<u16>()? {
                    ports.push(port);
                }
                Ok(Ports::List(ports))
            }
        }

        deserializer.deserialize_any(PortsVisitor)
    }
}

/// One allow rule as written in the task's network config.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Rule {
    /// Exact name or `*.suffix`; mutually exclusive with `cidr`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// IPv4 or IPv6 network in `addr/prefix` form; mutually exclusive with `host`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cidr: Option<String>,
    /// Allowed destination ports.
    pub ports: Ports,
    /// Protocol; defaults to TCP.
    #[serde(default)]
    pub proto: Proto,
}

impl Rule {
    /// Checks the rule; `index` is its position in the rule list and appears
    /// in the error message.
    #[cfg(test)]
    pub fn validate(&self, index: usize) -> Result<(), RuleError> {
        self.compile(index).map(drop)
    }

    fn compile(&self, index: usize) -> Result<CompiledRule, RuleError> {
        let target = match (&self.host, &self.cidr) {
            (Some(host), None) => {
                Target::Host(parse_host(host, true).map_err(|reason| RuleError::Host {
                    index,
                    host: host.clone(),
                    reason,
                })?)
            }
            (None, Some(cidr)) => {
                Target::Cidr(parse_cidr(cidr).map_err(|reason| RuleError::Cidr {
                    index,
                    cidr: cidr.clone(),
                    reason,
                })?)
            }
            _ => return Err(RuleError::HostOrCidr { index }),
        };
        if let Ports::List(ports) = &self.ports {
            let reason = if ports.is_empty() {
                Some("port list is empty")
            } else if ports.contains(&0) {
                Some("port 0 is not allowed")
            } else {
                None
            };
            if let Some(reason) = reason {
                return Err(RuleError::Ports { index, reason });
            }
        }
        Ok(CompiledRule {
            target,
            ports: self.ports.clone(),
            proto: self.proto,
        })
    }
}

/// An always-allowed TCP endpoint (e.g. the LLM API host).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlwaysAllow {
    /// Exact host name; wildcards are not accepted.
    pub host: String,
    /// TCP port.
    pub port: u16,
}

impl AlwaysAllow {
    /// The `host:port` of an `http(s)://` URL; the port defaults to 443 for
    /// https and 80 for http. `None` when the URL has no usable host or port.
    pub fn from_url(url: &str) -> Option<Self> {
        let (scheme, rest) = url.split_once("://")?;
        let default_port = match scheme.to_ascii_lowercase().as_str() {
            "https" => 443,
            "http" => 80,
            _ => return None,
        };
        let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
        let host_port = authority.rsplit_once('@').map_or(authority, |(_, hp)| hp);
        let (host, port) = if let Some(bracketed) = host_port.strip_prefix('[') {
            // `[v6addr]` or `[v6addr]:port`.
            let (host, rest) = bracketed.split_once(']')?;
            match rest {
                "" => (host, default_port),
                _ => (host, rest.strip_prefix(':')?.parse().ok()?),
            }
        } else {
            match host_port.rsplit_once(':') {
                Some((host, port)) => (host, port.parse().ok()?),
                None => (host_port, default_port),
            }
        };
        if host.is_empty() {
            return None;
        }
        Some(Self {
            host: host.to_owned(),
            port,
        })
    }
}

/// Invalid rule or always-allowed endpoint.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RuleError {
    /// Neither or both of `host` and `cidr` were given.
    #[error(r#"rule {index}: exactly one of "host" or "cidr" is required"#)]
    HostOrCidr { index: usize },
    /// The `host` value is not a valid name pattern.
    #[error(r#"rule {index}: invalid host "{host}": {reason}"#)]
    Host {
        index: usize,
        host: String,
        reason: &'static str,
    },
    /// The `cidr` value is not a valid network.
    #[error(r#"rule {index}: invalid cidr "{cidr}": {reason}"#)]
    Cidr {
        index: usize,
        cidr: String,
        reason: &'static str,
    },
    /// The port list is unusable.
    #[error("rule {index}: {reason}")]
    Ports { index: usize, reason: &'static str },
    /// An always-allowed endpoint is invalid.
    #[error(r#"always-allowed endpoint {index} ("{host}"): {reason}"#)]
    AlwaysAllow {
        index: usize,
        host: String,
        reason: &'static str,
    },
}

/// Outcome of a policy check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Allowed by the rule at `rule_index`, or by an always-allowed endpoint
    /// when `None`.
    Allow { rule_index: Option<usize> },
    /// Refused.
    Deny { reason: DenyReason },
}

/// Why a flow was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyReason {
    /// No rule matched.
    NoMatch,
}

impl DenyReason {
    /// Stable snake_case name used for logging.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoMatch => "no_match",
        }
    }
}

#[derive(Debug, Clone)]
enum HostPattern {
    Exact(String),
    /// Stored with its leading dot, e.g. `.npmjs.org`.
    Suffix(String),
}

impl HostPattern {
    fn matches(&self, name: &str) -> bool {
        match self {
            Self::Exact(host) => host == name,
            Self::Suffix(suffix) => name.len() > suffix.len() && name.ends_with(suffix.as_str()),
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum Cidr {
    V4 { net: u32, mask: u32 },
    V6 { net: u128, mask: u128 },
}

impl Cidr {
    fn contains(self, ip: IpAddr) -> bool {
        match (self, ip) {
            (Self::V4 { net, mask }, IpAddr::V4(ip)) => u32::from(ip) & mask == net,
            (Self::V6 { net, mask }, IpAddr::V6(ip)) => u128::from(ip) & mask == net,
            _ => false,
        }
    }
}

#[derive(Debug, Clone)]
enum Target {
    Host(HostPattern),
    Cidr(Cidr),
    /// Every name and address; forbidden addresses stay refused because this
    /// is not a `cidr` rule.
    Public,
}

#[derive(Debug, Clone)]
struct CompiledRule {
    target: Target,
    ports: Ports,
    proto: Proto,
}

impl CompiledRule {
    fn matches(&self, name: Option<&str>, ip: IpAddr, port: u16, proto: Proto) -> bool {
        let target = match &self.target {
            Target::Host(pattern) => name.is_some_and(|name| pattern.matches(name)),
            Target::Cidr(cidr) => cidr.contains(ip),
            Target::Public => true,
        };
        target && self.proto == proto && self.ports.contains(port)
    }
}

/// Validated rules plus always-allowed endpoints, ready for matching.
#[derive(Debug, Clone)]
pub struct RuleSet {
    rules: Vec<CompiledRule>,
    always: Vec<(String, u16)>,
    /// Always-allowed TCP endpoints given as an IP address.
    always_addrs: Vec<(IpAddr, u16)>,
}

impl RuleSet {
    /// Validates and compiles `rules` and `always_allow`.
    pub fn compile(rules: &[Rule], always_allow: &[AlwaysAllow]) -> Result<Self, RuleError> {
        let rules = rules
            .iter()
            .enumerate()
            .map(|(index, rule)| rule.compile(index))
            .collect::<Result<Vec<_>, _>>()?;
        let always = always_allow
            .iter()
            .enumerate()
            .map(|(index, endpoint)| {
                let err = |reason| RuleError::AlwaysAllow {
                    index,
                    host: endpoint.host.clone(),
                    reason,
                };
                if endpoint.port == 0 {
                    return Err(err("port 0 is not allowed"));
                }
                match parse_host(&endpoint.host, false).map_err(err)? {
                    HostPattern::Exact(host) => Ok((host, endpoint.port)),
                    HostPattern::Suffix(_) => Err(err("wildcards are not allowed")),
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            rules,
            always,
            always_addrs: Vec::new(),
        })
    }

    /// Adds an always-allowed TCP endpoint given as an IP address and port.
    pub fn with_always_addr(mut self, addr: SocketAddr) -> Result<Self, RuleError> {
        if addr.port() == 0 {
            return Err(RuleError::AlwaysAllow {
                index: self.always.len() + self.always_addrs.len(),
                host: addr.ip().to_string(),
                reason: "port 0 is not allowed",
            });
        }
        self.always_addrs
            .push((canonical_ip(addr.ip()), addr.port()));
        Ok(self)
    }

    /// Appends rules allowing every name and public address on any port, TCP
    /// and UDP. Forbidden (local, private, link-local, ...) addresses are not
    /// covered, so the exit still refuses them.
    pub fn allowing_public(mut self) -> Self {
        self.rules
            .extend([Proto::Tcp, Proto::Udp].map(|proto| CompiledRule {
                target: Target::Public,
                ports: Ports::Any,
                proto,
            }));
        self
    }

    /// Decides a flow to `ip:port` dialed by `name` (if known). Always-allowed
    /// endpoints are checked first, then the first matching rule wins.
    pub fn decide(&self, name: Option<&str>, ip: IpAddr, port: u16, proto: Proto) -> Decision {
        let name = name.map(normalize_name);
        let ip = canonical_ip(ip);
        if proto == Proto::Tcp
            && let Some(name) = &name
            && self.always.iter().any(|(h, p)| h == name && *p == port)
        {
            return Decision::Allow { rule_index: None };
        }
        if proto == Proto::Tcp && self.always_addrs.contains(&(ip, port)) {
            return Decision::Allow { rule_index: None };
        }
        match self
            .rules
            .iter()
            .position(|rule| rule.matches(name.as_deref(), ip, port, proto))
        {
            Some(index) => Decision::Allow {
                rule_index: Some(index),
            },
            None => Decision::Deny {
                reason: DenyReason::NoMatch,
            },
        }
    }

    /// True when `name` matches any host rule (any port or protocol) or any
    /// always-allowed host.
    pub fn name_allowed(&self, name: &str) -> bool {
        let name = normalize_name(name);
        self.always.iter().any(|(host, _)| *host == name)
            || self.rules.iter().any(|rule| match &rule.target {
                Target::Host(pattern) => pattern.matches(&name),
                Target::Cidr(_) => false,
                Target::Public => true,
            })
    }

    /// True when a rule covers the endpoint `host:port` over `proto`: a host
    /// rule matching the name, or a `cidr` rule containing the IP literal.
    /// Always-allowed endpoints do not count.
    pub fn rule_covers(&self, host: &str, port: u16, proto: Proto) -> bool {
        let name = normalize_name(host);
        let ip = name.parse::<IpAddr>().ok().map(canonical_ip);
        self.rules.iter().any(|rule| {
            let target = match (&rule.target, ip) {
                (Target::Host(pattern), None) => pattern.matches(&name),
                (Target::Cidr(cidr), Some(ip)) => cidr.contains(ip),
                (Target::Public, _) => true,
                _ => false,
            };
            target && rule.proto == proto && rule.ports.contains(port)
        })
    }

    /// Index of the first `cidr` rule matching `ip`, `port` and `proto`.
    pub fn cidr_covers(&self, ip: IpAddr, port: u16, proto: Proto) -> Option<usize> {
        let ip = canonical_ip(ip);
        self.rules.iter().position(|rule| {
            matches!(rule.target, Target::Cidr(_)) && rule.matches(None, ip, port, proto)
        })
    }
}

/// Lowercases ASCII and strips one trailing dot.
pub fn normalize_name(name: &str) -> String {
    let name = name.strip_suffix('.').unwrap_or(name);
    name.to_ascii_lowercase()
}

fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    }
}

fn parse_host(host: &str, allow_wildcard: bool) -> Result<HostPattern, &'static str> {
    let host = normalize_name(host);
    if host.is_empty() {
        return Err("host is empty");
    }
    if host.len() > MAX_NAME_LEN {
        return Err("name is longer than 253 characters");
    }
    if host.parse::<IpAddr>().is_ok() {
        return Err(r#"IP literals must use "cidr""#);
    }
    let (suffix, wildcard) = match host.strip_prefix("*.") {
        Some(suffix) if allow_wildcard => (suffix, true),
        Some(_) => return Err("wildcards are not allowed"),
        None => (host.as_str(), false),
    };
    if suffix.contains('*') {
        return Err(r#"a wildcard is only allowed as a leading "*.""#);
    }
    if suffix.is_empty() {
        return Err("wildcard suffix is empty");
    }
    for label in suffix.split('.') {
        if label.is_empty() {
            return Err("empty label");
        }
        if label.len() > MAX_LABEL_LEN {
            return Err("label is longer than 63 characters");
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err("invalid character");
        }
    }
    Ok(if wildcard {
        HostPattern::Suffix(format!(".{suffix}"))
    } else {
        HostPattern::Exact(host)
    })
}

fn parse_cidr(cidr: &str) -> Result<Cidr, &'static str> {
    let (addr, prefix) = cidr.split_once('/').ok_or("missing prefix length")?;
    let addr: IpAddr = addr.parse().map_err(|_| "invalid address")?;
    let prefix: u32 = prefix.parse().map_err(|_| "invalid prefix length")?;
    match addr {
        IpAddr::V4(v4) => {
            if prefix > 32 {
                return Err("prefix length out of range");
            }
            let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
            let net = u32::from(v4);
            if net & !mask != 0 {
                return Err("host bits are set");
            }
            Ok(Cidr::V4 { net, mask })
        }
        IpAddr::V6(v6) => {
            if prefix > 128 {
                return Err("prefix length out of range");
            }
            let mask = u128::MAX.checked_shl(128 - prefix).unwrap_or(0);
            let net = u128::from(v6);
            if net & !mask != 0 {
                return Err("host bits are set");
            }
            Ok(Cidr::V6 { net, mask })
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    fn rule(json: &str) -> Rule {
        serde_json::from_str(json).unwrap()
    }

    fn set(rules: &[&str], always: &[AlwaysAllow]) -> RuleSet {
        let rules: Vec<Rule> = rules.iter().map(|r| rule(r)).collect();
        RuleSet::compile(&rules, always).unwrap()
    }

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    const ANY_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));

    #[test]
    fn example_rules_parse() {
        let r = rule(r#"{"host":"github.com","ports":[22,443]}"#);
        assert_eq!(r.host.as_deref(), Some("github.com"));
        assert_eq!(r.ports, Ports::List(vec![22, 443]));
        assert_eq!(r.proto, Proto::Tcp);

        let r = rule(r#"{"host":"*.npmjs.org","ports":[443]}"#);
        assert_eq!(r.host.as_deref(), Some("*.npmjs.org"));

        let r = rule(r#"{"cidr":"10.20.0.0/16","ports":"*","proto":"udp"}"#);
        assert_eq!(r.cidr.as_deref(), Some("10.20.0.0/16"));
        assert_eq!(r.ports, Ports::Any);
        assert_eq!(r.proto, Proto::Udp);

        set(
            &[
                r#"{"host":"github.com","ports":[22,443]}"#,
                r#"{"host":"*.npmjs.org","ports":[443]}"#,
                r#"{"cidr":"10.20.0.0/16","ports":"*","proto":"udp"}"#,
            ],
            &[],
        );
    }

    #[test]
    fn serde_round_trip() {
        for json in [
            r#"{"host":"github.com","ports":[22,443],"proto":"tcp"}"#,
            r#"{"cidr":"10.20.0.0/16","ports":"*","proto":"udp"}"#,
        ] {
            assert_eq!(serde_json::to_string(&rule(json)).unwrap(), json);
        }
    }

    #[test]
    fn serde_rejects_bad_shapes() {
        for json in [
            r#"{"host":"a.com","ports":"any"}"#,
            r#"{"host":"a.com","ports":[70000]}"#,
            r#"{"host":"a.com"}"#,
            r#"{"host":"a.com","ports":[1],"proto":"icmp"}"#,
            r#"{"host":"a.com","ports":[1],"extra":true}"#,
        ] {
            assert!(serde_json::from_str::<Rule>(json).is_err(), "{json}");
        }
    }

    #[test]
    fn invalid_rules_name_their_index() {
        let long_label = format!("{}.com", "a".repeat(64));
        let long_name = format!("{}.com", vec!["a".repeat(60); 5].join("."));
        let cases = [
            r#"{"host":"a.com","cidr":"10.0.0.0/8","ports":[1]}"#.to_owned(),
            r#"{"ports":[1]}"#.to_owned(),
            r#"{"host":"","ports":[1]}"#.to_owned(),
            r#"{"host":".","ports":[1]}"#.to_owned(),
            r#"{"host":"exa mple.com","ports":[1]}"#.to_owned(),
            r#"{"host":"a..com","ports":[1]}"#.to_owned(),
            format!(r#"{{"host":"{long_label}","ports":[1]}}"#),
            format!(r#"{{"host":"{long_name}","ports":[1]}}"#),
            r#"{"host":"*","ports":[1]}"#.to_owned(),
            r#"{"host":"a.*.com","ports":[1]}"#.to_owned(),
            r#"{"host":"*foo.com","ports":[1]}"#.to_owned(),
            r#"{"host":"*.","ports":[1]}"#.to_owned(),
            r#"{"host":"*.*.com","ports":[1]}"#.to_owned(),
            r#"{"host":"10.0.0.1","ports":[1]}"#.to_owned(),
            r#"{"host":"::1","ports":[1]}"#.to_owned(),
            r#"{"cidr":"10.0.0.0","ports":[1]}"#.to_owned(),
            r#"{"cidr":"10.0.0/8","ports":[1]}"#.to_owned(),
            r#"{"cidr":"10.0.0.0/x","ports":[1]}"#.to_owned(),
            r#"{"cidr":"10.0.0.0/33","ports":[1]}"#.to_owned(),
            r#"{"cidr":"fd00::/129","ports":[1]}"#.to_owned(),
            r#"{"cidr":"10.20.0.1/16","ports":[1]}"#.to_owned(),
            r#"{"cidr":"fd00::1/64","ports":[1]}"#.to_owned(),
            r#"{"host":"a.com","ports":[]}"#.to_owned(),
            r#"{"host":"a.com","ports":[443,0]}"#.to_owned(),
        ];
        assert!(long_name.len() > MAX_NAME_LEN);
        let ok = rule(r#"{"host":"ok.com","ports":[1]}"#);
        for case in &cases {
            let rules = [ok.clone(), ok.clone(), rule(case)];
            let err = RuleSet::compile(&rules, &[]).unwrap_err();
            assert!(err.to_string().starts_with("rule 2: "), "{case}: {err}");
            assert_eq!(rules[2].validate(2), Err(err));
        }
        assert_eq!(
            RuleSet::compile(&[rule(&cases[0])], &[])
                .unwrap_err()
                .to_string(),
            r#"rule 0: exactly one of "host" or "cidr" is required"#
        );
    }

    #[test]
    fn invalid_always_allow() {
        for (host, port) in [
            ("*.anthropic.com", 443),
            ("", 443),
            ("1.2.3.4", 443),
            ("a.com", 0),
        ] {
            let endpoint = AlwaysAllow {
                host: host.to_owned(),
                port,
            };
            let err = RuleSet::compile(&[], &[endpoint]).unwrap_err();
            assert!(
                err.to_string().starts_with("always-allowed endpoint 0 "),
                "{err}"
            );
        }
    }

    #[test]
    fn exact_host_and_normalisation() {
        let s = set(&[r#"{"host":"GitHub.COM.","ports":[22,443]}"#], &[]);
        let allow = Decision::Allow {
            rule_index: Some(0),
        };
        for name in ["github.com", "GITHUB.com.", "github.com."] {
            assert_eq!(s.decide(Some(name), ANY_IP, 443, Proto::Tcp), allow);
        }
        assert_eq!(s.decide(Some("github.com"), ANY_IP, 22, Proto::Tcp), allow);
        let deny = Decision::Deny {
            reason: DenyReason::NoMatch,
        };
        assert_eq!(s.decide(Some("github.com"), ANY_IP, 80, Proto::Tcp), deny);
        assert_eq!(s.decide(Some("github.com"), ANY_IP, 443, Proto::Udp), deny);
        assert_eq!(
            s.decide(Some("api.github.com"), ANY_IP, 443, Proto::Tcp),
            deny
        );
        assert_eq!(s.decide(None, ANY_IP, 443, Proto::Tcp), deny);
    }

    #[test]
    fn wildcard_host() {
        let s = set(&[r#"{"host":"*.npmjs.org","ports":"*"}"#], &[]);
        let ok = |name: &str| {
            s.decide(Some(name), ANY_IP, 443, Proto::Tcp)
                == Decision::Allow {
                    rule_index: Some(0),
                }
        };
        assert!(ok("registry.npmjs.org"));
        assert!(ok("a.b.c.npmjs.org"));
        assert!(ok("Registry.NPMJS.org."));
        assert!(!ok("npmjs.org"));
        assert!(!ok("evilnpmjs.org"));
        assert!(!ok("npmjs.org.evil.com"));
        assert_eq!(
            s.decide(Some("x.npmjs.org"), ANY_IP, 1, Proto::Tcp),
            Decision::Allow {
                rule_index: Some(0)
            }
        );
    }

    #[test]
    fn cidr_rules() {
        let s = set(
            &[
                r#"{"cidr":"10.20.0.0/16","ports":"*","proto":"udp"}"#,
                r#"{"cidr":"fd00:1::/32","ports":[443]}"#,
                r#"{"cidr":"0.0.0.0/0","ports":[8080]}"#,
            ],
            &[],
        );
        assert_eq!(
            s.decide(None, v4(10, 20, 3, 4), 53, Proto::Udp),
            Decision::Allow {
                rule_index: Some(0)
            }
        );
        assert!(matches!(
            s.decide(None, v4(10, 21, 0, 1), 53, Proto::Udp),
            Decision::Deny { .. }
        ));
        assert!(matches!(
            s.decide(None, v4(10, 20, 3, 4), 53, Proto::Tcp),
            Decision::Deny { .. }
        ));
        let mapped = IpAddr::V6(Ipv4Addr::new(10, 20, 9, 9).to_ipv6_mapped());
        assert_eq!(
            s.decide(None, mapped, 5353, Proto::Udp),
            Decision::Allow {
                rule_index: Some(0)
            }
        );
        let v6_in = IpAddr::V6(Ipv6Addr::new(0xfd00, 1, 0xabcd, 0, 0, 0, 0, 1));
        let v6_out = IpAddr::V6(Ipv6Addr::new(0xfd00, 2, 0, 0, 0, 0, 0, 1));
        assert_eq!(
            s.decide(None, v6_in, 443, Proto::Tcp),
            Decision::Allow {
                rule_index: Some(1)
            }
        );
        assert!(matches!(
            s.decide(None, v6_out, 443, Proto::Tcp),
            Decision::Deny { .. }
        ));
        // A name does not stop a cidr rule from matching by address.
        assert_eq!(
            s.decide(Some("whatever.com"), v4(1, 2, 3, 4), 8080, Proto::Tcp),
            Decision::Allow {
                rule_index: Some(2)
            }
        );
        assert!(matches!(
            s.decide(None, v6_out, 8080, Proto::Tcp),
            Decision::Deny { .. }
        ));
    }

    #[test]
    fn first_match_wins() {
        let s = set(
            &[
                r#"{"host":"a.com","ports":[80]}"#,
                r#"{"host":"*.example.com","ports":[443]}"#,
                r#"{"host":"api.example.com","ports":[443]}"#,
                r#"{"cidr":"203.0.113.0/24","ports":[443]}"#,
            ],
            &[],
        );
        assert_eq!(
            s.decide(Some("api.example.com"), ANY_IP, 443, Proto::Tcp),
            Decision::Allow {
                rule_index: Some(1)
            }
        );
        assert_eq!(
            s.decide(Some("other.com"), ANY_IP, 443, Proto::Tcp),
            Decision::Allow {
                rule_index: Some(3)
            }
        );
    }

    #[test]
    fn always_allowed_endpoint() {
        let always = [AlwaysAllow {
            host: "API.Anthropic.com.".to_owned(),
            port: 443,
        }];
        let s = set(&[r#"{"cidr":"203.0.113.0/24","ports":[443]}"#], &always);
        assert_eq!(
            s.decide(Some("api.anthropic.com"), ANY_IP, 443, Proto::Tcp),
            Decision::Allow { rule_index: None }
        );
        let other = v4(198, 51, 100, 1);
        assert_eq!(
            s.decide(Some("api.anthropic.com"), other, 80, Proto::Tcp),
            Decision::Deny {
                reason: DenyReason::NoMatch
            }
        );
        assert_eq!(
            s.decide(Some("api.anthropic.com"), other, 443, Proto::Udp),
            Decision::Deny {
                reason: DenyReason::NoMatch
            }
        );
        assert!(matches!(
            s.decide(Some("x.api.anthropic.com"), other, 443, Proto::Tcp),
            Decision::Deny { .. }
        ));
    }

    #[test]
    fn always_allowed_address() {
        let addr: SocketAddr = "172.17.0.1:8080".parse().unwrap();
        let s = set(&[], &[]).with_always_addr(addr).unwrap();
        let ip = v4(172, 17, 0, 1);
        let allow = Decision::Allow { rule_index: None };
        assert_eq!(s.decide(None, ip, 8080, Proto::Tcp), allow);
        let mapped = IpAddr::V6(Ipv4Addr::new(172, 17, 0, 1).to_ipv6_mapped());
        assert_eq!(s.decide(None, mapped, 8080, Proto::Tcp), allow);
        assert!(matches!(
            s.decide(None, ip, 8081, Proto::Tcp),
            Decision::Deny { .. }
        ));
        assert!(matches!(
            s.decide(None, ip, 8080, Proto::Udp),
            Decision::Deny { .. }
        ));
        assert!(matches!(
            s.decide(None, v4(172, 17, 0, 2), 8080, Proto::Tcp),
            Decision::Deny { .. }
        ));
        assert!(!s.name_allowed("172.17.0.1"));

        let v6: SocketAddr = "[fd00::1]:443".parse().unwrap();
        let s = set(&[], &[]).with_always_addr(v6).unwrap();
        assert_eq!(s.decide(None, v6.ip(), 443, Proto::Tcp), allow);

        let err = set(&[], &[])
            .with_always_addr("10.0.0.1:0".parse().unwrap())
            .unwrap_err();
        assert!(
            err.to_string().starts_with("always-allowed endpoint 0 "),
            "{err}"
        );
    }

    #[test]
    fn rule_covers_endpoints() {
        let always = [AlwaysAllow {
            host: "api.anthropic.com".to_owned(),
            port: 443,
        }];
        let s = set(
            &[
                r#"{"host":"*.example.com","ports":[443]}"#,
                r#"{"cidr":"10.0.0.0/8","ports":[8080]}"#,
                r#"{"host":"dns.example.org","ports":[53],"proto":"udp"}"#,
            ],
            &always,
        );
        assert!(s.rule_covers("Proxy.Example.com.", 443, Proto::Tcp));
        assert!(!s.rule_covers("proxy.example.com", 80, Proto::Tcp));
        assert!(!s.rule_covers("proxy.example.com", 443, Proto::Udp));
        assert!(s.rule_covers("10.1.2.3", 8080, Proto::Tcp));
        assert!(!s.rule_covers("10.1.2.3", 443, Proto::Tcp));
        assert!(!s.rule_covers("dns.example.org", 53, Proto::Tcp));
        assert!(!s.rule_covers("api.anthropic.com", 443, Proto::Tcp));
    }

    #[test]
    fn from_url_reads_ip_literals() {
        let endpoint = |url| AlwaysAllow::from_url(url).unwrap();
        let expect = |host: &str, port| AlwaysAllow {
            host: host.to_owned(),
            port,
        };
        assert_eq!(
            endpoint("http://172.17.0.1:8080/llm"),
            expect("172.17.0.1", 8080)
        );
        assert_eq!(endpoint("https://[fd00::1]/v1"), expect("fd00::1", 443));
        assert_eq!(endpoint("http://u:p@[::1]:9000?x"), expect("::1", 9000));
        for url in [
            "http://[::1",
            "http://[::1]x",
            "http://[::1]:",
            "http://[::1]:x",
        ] {
            assert_eq!(AlwaysAllow::from_url(url), None, "{url}");
        }
    }

    #[test]
    fn name_allowed() {
        let always = [AlwaysAllow {
            host: "api.anthropic.com".to_owned(),
            port: 443,
        }];
        let s = set(
            &[
                r#"{"host":"github.com","ports":[22]}"#,
                r#"{"host":"*.npmjs.org","ports":[53],"proto":"udp"}"#,
                r#"{"cidr":"10.0.0.0/8","ports":"*"}"#,
            ],
            &always,
        );
        assert!(s.name_allowed("GitHub.com."));
        assert!(s.name_allowed("registry.npmjs.org"));
        assert!(s.name_allowed("api.anthropic.com"));
        assert!(!s.name_allowed("npmjs.org"));
        assert!(!s.name_allowed("gitlab.com"));
        assert!(!s.name_allowed("10.0.0.1"));
    }

    #[test]
    fn cidr_covers() {
        let s = set(
            &[
                r#"{"host":"internal.corp","ports":"*"}"#,
                r#"{"cidr":"192.168.0.0/16","ports":[22]}"#,
                r#"{"cidr":"192.168.1.0/24","ports":"*","proto":"udp"}"#,
            ],
            &[],
        );
        assert_eq!(s.cidr_covers(v4(192, 168, 1, 5), 22, Proto::Tcp), Some(1));
        assert_eq!(s.cidr_covers(v4(192, 168, 1, 5), 53, Proto::Udp), Some(2));
        assert_eq!(s.cidr_covers(v4(192, 168, 1, 5), 80, Proto::Tcp), None);
        assert_eq!(s.cidr_covers(v4(10, 0, 0, 1), 22, Proto::Tcp), None);
        let mapped = IpAddr::V6(Ipv4Addr::new(192, 168, 7, 7).to_ipv6_mapped());
        assert_eq!(s.cidr_covers(mapped, 22, Proto::Tcp), Some(1));
    }

    #[test]
    fn normalize() {
        assert_eq!(normalize_name("Example.COM."), "example.com");
        assert_eq!(normalize_name("example.com.."), "example.com.");
        assert_eq!(normalize_name(""), "");
    }

    #[test]
    fn as_str() {
        assert_eq!(Proto::Tcp.as_str(), "tcp");
        assert_eq!(Proto::Udp.as_str(), "udp");
        assert_eq!(Proto::default(), Proto::Tcp);
        assert_eq!(DenyReason::NoMatch.as_str(), "no_match");
    }
}
