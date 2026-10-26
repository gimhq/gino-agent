//! Guest DNS resolver: allowed names get a fake IPv4 address, every other name
//! is answered NXDOMAIN.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;

use nsplane_dns::{
    Answer, FakePool, FakePoolConfig, FakePoolConfigError, Query, RecordType, Resolver,
    ResponseCode,
};

use super::rules::RuleSet;

/// Network address of the fake IPv4 prefix (198.18.0.0/15, RFC 2544).
pub const FAKE_V4_NET: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 0);
/// Prefix length of the fake IPv4 prefix.
pub const FAKE_V4_PREFIX_LEN: u8 = 15;
/// Resolver address the guest is pointed at (the TUN gateway).
pub const DNS_ADDR: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 2, 2), 53));

/// Answers guest queries from the rule set: A queries for allowed names get a
/// stable address from the fake pool, other types of allowed names get NODATA,
/// and names no rule allows get NXDOMAIN.
#[derive(Debug)]
pub struct GuestResolver {
    rules: Arc<RuleSet>,
    pool: FakePool,
}

impl GuestResolver {
    /// A resolver for `rules` with an empty fake pool.
    pub fn new(rules: Arc<RuleSet>) -> Result<Self, FakePoolConfigError> {
        let pool = FakePool::new(FakePoolConfig {
            ipv4: Some((FAKE_V4_NET, FAKE_V4_PREFIX_LEN)),
            ipv6: None,
            ..FakePoolConfig::default()
        })?;
        Ok(Self { rules, pool })
    }

    /// The name a fake address was handed out for.
    pub fn lookup(&self, addr: IpAddr) -> Option<String> {
        self.pool.lookup(addr)
    }

    /// True when `addr` lies in the fake IPv4 prefix.
    pub fn is_fake(addr: IpAddr) -> bool {
        let shift = 32 - u32::from(FAKE_V4_PREFIX_LEN);
        match addr {
            IpAddr::V4(v4) => u32::from(v4) >> shift == u32::from(FAKE_V4_NET) >> shift,
            IpAddr::V6(_) => false,
        }
    }
}

impl Resolver for GuestResolver {
    async fn resolve(&self, query: &Query, client: SocketAddr) -> Answer {
        if !self.rules.name_allowed(query.name()) {
            return Answer::Code(ResponseCode::NxDomain);
        }
        if query.record_type() == RecordType::A {
            self.pool.resolve(query, client).await
        } else {
            Answer::Records(Vec::new())
        }
    }
}

#[cfg(test)]
mod tests {
    use nsplane_dns::RecordData;

    use super::*;
    use crate::net::rules::{AlwaysAllow, Rule};

    const CLIENT: SocketAddr =
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 2, 15), 40000));

    fn resolver() -> GuestResolver {
        let rules: Vec<Rule> = [
            r#"{"host":"github.com","ports":[443]}"#,
            r#"{"host":"*.example.org","ports":"*"}"#,
            r#"{"cidr":"203.0.113.0/24","ports":[443]}"#,
        ]
        .iter()
        .map(|r| serde_json::from_str(r).unwrap())
        .collect();
        let always = [AlwaysAllow {
            host: "api.anthropic.com".to_owned(),
            port: 443,
        }];
        GuestResolver::new(Arc::new(RuleSet::compile(&rules, &always).unwrap())).unwrap()
    }

    /// A wire-format query for `name` with record type `ty`, class IN.
    fn query(name: &str, ty: RecordType) -> Query {
        let mut msg = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            msg.push(u8::try_from(label.len()).unwrap());
            msg.extend_from_slice(label.as_bytes());
        }
        msg.push(0);
        msg.extend_from_slice(&ty.0.to_be_bytes());
        msg.extend_from_slice(&[0, 1]);
        Query::decode(&msg).unwrap()
    }

    async fn resolve_a(r: &GuestResolver, name: &str) -> Ipv4Addr {
        match r.resolve(&query(name, RecordType::A), CLIENT).await {
            Answer::Records(records) => match records.as_slice() {
                [record] => match record.data {
                    RecordData::A(addr) => addr,
                    ref other => panic!("unexpected record data {other:?}"),
                },
                other => panic!("expected one record, got {other:?}"),
            },
            other => panic!("unexpected answer {other:?}"),
        }
    }

    #[tokio::test]
    async fn allowed_name_gets_stable_fake_address() {
        let r = resolver();
        let addr = resolve_a(&r, "github.com").await;
        assert!(GuestResolver::is_fake(IpAddr::V4(addr)), "{addr}");
        assert_eq!(resolve_a(&r, "github.com").await, addr);
        assert_eq!(r.lookup(IpAddr::V4(addr)).as_deref(), Some("github.com"));
    }

    #[tokio::test]
    async fn wildcard_rule_allows_subdomain() {
        let r = resolver();
        let addr = resolve_a(&r, "a.example.org").await;
        assert!(GuestResolver::is_fake(IpAddr::V4(addr)));
        assert_ne!(resolve_a(&r, "b.example.org").await, addr);
    }

    #[tokio::test]
    async fn disallowed_name_is_nxdomain() {
        let r = resolver();
        for name in ["evil.com", "example.org", "github.com.evil.com"] {
            assert_eq!(
                r.resolve(&query(name, RecordType::A), CLIENT).await,
                Answer::Code(ResponseCode::NxDomain),
                "{name}"
            );
        }
        assert_eq!(
            r.resolve(&query("evil.com", RecordType::AAAA), CLIENT)
                .await,
            Answer::Code(ResponseCode::NxDomain)
        );
        assert!(r.pool.is_empty());
    }

    #[tokio::test]
    async fn allowed_name_other_types_are_nodata() {
        let r = resolver();
        for ty in [RecordType::AAAA, RecordType::TXT, RecordType::HTTPS] {
            assert_eq!(
                r.resolve(&query("github.com", ty), CLIENT).await,
                Answer::Records(Vec::new()),
                "{ty}"
            );
        }
    }

    #[tokio::test]
    async fn always_allowed_host_resolves() {
        let r = resolver();
        let addr = resolve_a(&r, "api.anthropic.com").await;
        assert!(GuestResolver::is_fake(IpAddr::V4(addr)));
    }

    #[tokio::test]
    async fn names_are_case_insensitive() {
        let r = resolver();
        let addr = resolve_a(&r, "GitHub.COM").await;
        assert_eq!(resolve_a(&r, "github.com").await, addr);
        assert_eq!(r.lookup(IpAddr::V4(addr)).as_deref(), Some("github.com"));
    }

    #[test]
    fn is_fake_boundaries() {
        let v4 = |a, b, c, d| IpAddr::V4(Ipv4Addr::new(a, b, c, d));
        assert!(GuestResolver::is_fake(v4(198, 18, 0, 0)));
        assert!(GuestResolver::is_fake(v4(198, 18, 0, 1)));
        assert!(GuestResolver::is_fake(v4(198, 19, 255, 255)));
        assert!(!GuestResolver::is_fake(v4(198, 17, 255, 255)));
        assert!(!GuestResolver::is_fake(v4(198, 20, 0, 0)));
        assert!(!GuestResolver::is_fake(v4(10, 0, 2, 2)));
        assert!(!GuestResolver::is_fake(
            "::ffff:198.18.0.1".parse().unwrap()
        ));
    }

    #[test]
    fn lookup_of_unknown_address_is_none() {
        let r = resolver();
        assert_eq!(r.lookup(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1))), None);
        assert_eq!(r.lookup(IpAddr::V4(Ipv4Addr::new(10, 0, 2, 2))), None);
    }
}
