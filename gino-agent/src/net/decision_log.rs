//! Structured log line for every network policy decision.

use std::net::IpAddr;

use super::rules::{Decision, Proto};

/// Emits one event on target `gino_agent::net`: `info` for allow, `warn` for
/// deny. `target_name` is `"-"` when unknown; `rule_index` is `"always"` for
/// an always-allowed endpoint.
pub fn log_decision(
    thread_id: &str,
    proto: Proto,
    target_name: Option<&str>,
    target_ip: IpAddr,
    port: u16,
    decision: &Decision,
) {
    let target_name = target_name.unwrap_or("-");
    let proto = proto.as_str();
    match decision {
        Decision::Allow { rule_index } => {
            let rule_index = rule_index.map_or_else(|| "always".to_owned(), |i| i.to_string());
            tracing::info!(
                target: "gino_agent::net",
                thread_id,
                proto,
                target_name,
                %target_ip,
                port,
                decision = "allow",
                %rule_index,
                "network decision"
            );
        }
        Decision::Deny { reason } => {
            tracing::warn!(
                target: "gino_agent::net",
                thread_id,
                proto,
                target_name,
                %target_ip,
                port,
                decision = "deny",
                reason = reason.as_str(),
                "network decision"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::net::Ipv4Addr;
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::net::rules::DenyReason;

    #[derive(Clone, Default)]
    struct Buf(Arc<Mutex<Vec<u8>>>);

    impl io::Write for Buf {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(data);
            Ok(data.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn capture(f: impl FnOnce()) -> String {
        let buf = Buf::default();
        let writer = buf.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .finish();
        tracing::subscriber::with_default(subscriber, f);
        String::from_utf8(buf.0.lock().unwrap().clone()).unwrap()
    }

    const IP: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));

    #[test]
    fn allow_fields() {
        let out = capture(|| {
            log_decision(
                "t-1",
                Proto::Tcp,
                Some("github.com"),
                IP,
                443,
                &Decision::Allow {
                    rule_index: Some(2),
                },
            );
        });
        assert_eq!(out.lines().count(), 1, "{out}");
        for field in [
            " INFO ",
            "gino_agent::net",
            r#"thread_id="t-1""#,
            r#"proto="tcp""#,
            r#"target_name="github.com""#,
            "target_ip=203.0.113.7",
            "port=443",
            r#"decision="allow""#,
            "rule_index=2",
        ] {
            assert!(out.contains(field), "missing {field}: {out}");
        }
        assert!(!out.contains("reason="), "{out}");
    }

    #[test]
    fn always_allowed_fields() {
        let out = capture(|| {
            log_decision(
                "t-1",
                Proto::Tcp,
                Some("api.anthropic.com"),
                IP,
                443,
                &Decision::Allow { rule_index: None },
            );
        });
        assert!(out.contains("rule_index=always"), "{out}");
    }

    #[test]
    fn deny_fields() {
        let out = capture(|| {
            log_decision(
                "t-2",
                Proto::Udp,
                None,
                IP,
                53,
                &Decision::Deny {
                    reason: DenyReason::NoMatch,
                },
            );
        });
        assert_eq!(out.lines().count(), 1, "{out}");
        for field in [
            " WARN ",
            r#"thread_id="t-2""#,
            r#"proto="udp""#,
            r#"target_name="-""#,
            "target_ip=203.0.113.7",
            "port=53",
            r#"decision="deny""#,
            r#"reason="no_match""#,
        ] {
            assert!(out.contains(field), "missing {field}: {out}");
        }
        assert!(!out.contains("rule_index="), "{out}");
    }
}
