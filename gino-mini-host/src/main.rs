//! `gino-mini-host`: run the reference host. Settings come from the environment:
//!
//!   MINI_HOST_PORT            listen port                       (default 3100)
//!   MINI_HOST_BIND            listen address                    (default 127.0.0.1)
//!   MINI_HOST_REGISTER_TOKEN  enrollment secret the agent sends (default "dev")
//!   MINI_HOST_DB              SQLite file                       (default ./mini-host.db)
//!   ANTHROPIC_API_KEY / CLAUDE_CODE_OAUTH_TOKEN / ANTHROPIC_BASE_URL / MINI_HOST_MODEL
//!                             forwarded to the agent in `config.engine`

use std::env;
use std::net::IpAddr;
use std::process::ExitCode;

use gino_mini_host::{Config, Host, router};
use serde_json::{Map, Value};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

const ENGINE_ENV: [(&str, &str); 4] = [
    ("ANTHROPIC_API_KEY", "anthropicApiKey"),
    ("CLAUDE_CODE_OAUTH_TOKEN", "claudeCodeOauthToken"),
    ("ANTHROPIC_BASE_URL", "anthropicBaseUrl"),
    ("MINI_HOST_MODEL", "model"),
];

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            error!("{err}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), String> {
    let port: u16 = match env::var("MINI_HOST_PORT") {
        Ok(p) => p
            .parse()
            .map_err(|_| format!("MINI_HOST_PORT must be a port number, got {p:?}"))?,
        Err(_) => 3100,
    };
    let bind: IpAddr = match env::var("MINI_HOST_BIND") {
        Ok(b) => b
            .parse()
            .map_err(|_| format!("MINI_HOST_BIND must be an IP address, got {b:?}"))?,
        Err(_) => IpAddr::from([127, 0, 0, 1]),
    };
    let register_token = env::var("MINI_HOST_REGISTER_TOKEN").unwrap_or_else(|_| "dev".into());
    let db_path = env::var("MINI_HOST_DB").unwrap_or_else(|_| "./mini-host.db".into());
    let mut engine = Map::new();
    for (var, key) in ENGINE_ENV {
        if let Ok(value) = env::var(var).map(|v| v.trim().to_owned())
            && !value.is_empty()
        {
            engine.insert(key.into(), Value::String(value));
        }
    }
    let default_token = register_token == "dev";
    let host = Host::open(Config {
        register_token,
        db_path: db_path.clone().into(),
        engine,
    })
    .map_err(|err| format!("open {db_path}: {err}"))?;
    let listener = tokio::net::TcpListener::bind((bind, port))
        .await
        .map_err(|err| format!("bind {bind}:{port}: {err}"))?;
    info!(
        "mini-host listening on http://{bind}:{port} (db {db_path}, register token {})",
        if default_token {
            "\"dev\" — set MINI_HOST_REGISTER_TOKEN"
        } else {
            "set"
        }
    );
    info!("agent: GINO_HOST_URL=http://{bind}:{port} GINO_REGISTER_TOKEN=... gino-agent run");
    axum::serve(listener, router(host))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .map_err(|err| format!("serve: {err}"))
}
