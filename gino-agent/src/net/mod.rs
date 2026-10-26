//! Guest network policy building blocks: rules, DNS resolver with fake
//! addresses, upstream connect/relay, limits, TUN and fd passing.

pub mod decision_log;
pub mod dns;
pub mod exit;
pub mod fdpass;
pub mod limits;
pub mod rules;
pub mod tun;
pub mod upstream;
