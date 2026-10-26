//! Local agent API: a newline-delimited JSON protocol on a Unix socket under the
//! workspace (`run/agent.sock`). Same-user, same-namespace peers get operator
//! access; an engine run gets a per-run token scoped to its own task. A VM run
//! reaches the API on its own per-run socket, whose peers are run peers only.

pub(crate) mod client;
mod methods;
pub(crate) mod protocol;
mod scope;
mod server;
#[cfg(test)]
mod tests;

use std::path::{Path, PathBuf};

pub(crate) use methods::ApiContext;
pub(crate) use scope::{RunScope, RunToken, TokenRegistry};
pub(crate) use server::{AgentApiServer, RunPeerServer, serve_run_peers};

/// The API socket under `workspace_dir`.
pub(crate) fn socket_path(workspace_dir: &Path) -> PathBuf {
    workspace_dir.join("run").join("agent.sock")
}
