//! The engine registry — the runner's name → backend map.
//!
//! The executor used to hold ONE [`Engine`] and run everything on it; the
//! registry replaces that with a set of backends keyed by [`Engine::name`], so a
//! run can be dispatched to the backend its task names. With a single backend
//! registered the registry is observationally identical to the old single-engine
//! field: [`EngineRegistry::resolve`] answers the default for every input.
//!
//! DECISION — an unknown engine name NEVER fails a run. It is a forward-compat
//! signal from a newer host naming a backend this build does not ship, not a bad
//! request, so resolution warns once and falls back to the default. This is the
//! same policy `warn_unsupported_engine` applies when the `task_upsert` that
//! carried the name was persisted; failing here would strand a whole task on a
//! field the runner is free to ignore.

use std::collections::BTreeMap;
use std::sync::Arc;

use tracing::warn;

use super::Engine;

/// The backends this build can run, keyed by [`Engine::name`], plus the backend
/// used when a run names none (or names one that is not registered).
///
/// Ordering is the [`BTreeMap`]'s, so [`Self::names`] is stable and sorted — it
/// backs the capabilities advertisement, which must not churn between runs.
///
/// `Clone` is cheap (every backend is an `Arc`) and exists so the executor can
/// rebuild the registry behind its `Arc` when a builder registers another backend.
#[derive(Clone)]
pub(crate) struct EngineRegistry {
    engines: BTreeMap<String, Arc<dyn Engine>>,
    /// Held directly rather than looked up by name, so the fallback path is
    /// infallible (the crate forbids panics in runtime paths).
    default: Arc<dyn Engine>,
}

// `Arc<dyn Engine>` is not `Debug` (the trait is kept minimal and object-safe),
// so the derive is impossible; print the registered names and the default name,
// which is the whole of the registry's observable state.
impl std::fmt::Debug for EngineRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EngineRegistry")
            .field("engines", &self.names())
            .field("default", &self.default_name())
            .finish()
    }
}

impl EngineRegistry {
    /// A registry holding `default_engine` under its own [`Engine::name`], which
    /// also becomes the default backend.
    pub(crate) fn new(default_engine: Arc<dyn Engine>) -> Self {
        let mut engines = BTreeMap::new();
        engines.insert(
            default_engine.name().to_owned(),
            Arc::clone(&default_engine),
        );
        Self {
            engines,
            default: default_engine,
        }
    }

    /// Register another backend under its own [`Engine::name`]; re-registering a
    /// name replaces the backend behind it — including the default, which stays
    /// the same NAME but follows the replacement.
    pub(crate) fn with_engine(mut self, engine: Arc<dyn Engine>) -> Self {
        if engine.name() == self.default.name() {
            self.default = Arc::clone(&engine);
        }
        self.engines.insert(engine.name().to_owned(), engine);
        self
    }

    /// The name of the backend every unnamed (or unknown) run falls back to.
    pub(crate) fn default_name(&self) -> &str {
        self.default.name()
    }

    /// Every registered backend name, sorted.
    pub(crate) fn names(&self) -> Vec<&str> {
        self.engines.keys().map(String::as_str).collect()
    }

    /// Whether `name` names a registered backend.
    #[cfg_attr(
        not(test),
        allow(
            dead_code,
            reason = "second-backend wiring lands with the next engine; exercised by tests today"
        )
    )]
    pub(crate) fn contains(&self, name: &str) -> bool {
        self.engines.contains_key(name)
    }

    /// Resolve a requested backend name to the backend that will actually run,
    /// returning the RESOLVED name alongside it (the caller logs and reports the
    /// resolved name, never the requested one).
    ///
    /// `None` and a blank name both mean "unspecified" and take the default
    /// silently; an unregistered name warns once and takes the default too — an
    /// unknown engine is never fatal (see the module docs).
    pub(crate) fn resolve(&self, requested: Option<&str>) -> (&str, Arc<dyn Engine>) {
        let named = requested.map(str::trim).filter(|name| !name.is_empty());
        if let Some(name) = named {
            if let Some((name, engine)) = self.engines.get_key_value(name) {
                return (name.as_str(), Arc::clone(engine));
            }
            warn!(
                requested = %name,
                fallback = %self.default_name(),
                "unknown engine; running on the default backend"
            );
        }
        (self.default_name(), Arc::clone(&self.default))
    }
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;

    use super::{Arc, EngineRegistry};
    use crate::engine::{Engine, EngineError, Session, SessionCfg};

    /// A backend that only carries a name — resolution never starts a session.
    struct StubEngine(&'static str);

    #[async_trait]
    impl Engine for StubEngine {
        fn name(&self) -> &'static str {
            self.0
        }
        async fn start_session(&self, _cfg: SessionCfg) -> Result<Box<dyn Session>, EngineError> {
            Err(EngineError::Closed)
        }
    }

    fn stub(name: &'static str) -> Arc<dyn Engine> {
        Arc::new(StubEngine(name))
    }

    #[test]
    fn unspecified_resolves_to_the_default() {
        let registry = EngineRegistry::new(stub("claude"));
        let (name, engine) = registry.resolve(None);
        assert_eq!(name, "claude");
        assert_eq!(engine.name(), "claude");
        assert_eq!(registry.default_name(), "claude");
        assert!(registry.contains("claude"));
    }

    #[test]
    fn the_default_resolves_by_name() {
        let registry = EngineRegistry::new(stub("claude"));
        let (name, engine) = registry.resolve(Some("claude"));
        assert_eq!(name, "claude");
        assert_eq!(engine.name(), "claude");
    }

    #[test]
    fn unknown_name_falls_back_to_the_default() {
        let registry = EngineRegistry::new(stub("claude"));
        let (name, engine) = registry.resolve(Some("nope"));
        assert_eq!(name, "claude");
        assert_eq!(engine.name(), "claude");
        assert!(!registry.contains("nope"));
    }

    #[test]
    fn blank_names_resolve_to_the_default() {
        let registry = EngineRegistry::new(stub("claude"));
        for blank in ["", "   "] {
            let (name, engine) = registry.resolve(Some(blank));
            assert_eq!(name, "claude");
            assert_eq!(engine.name(), "claude");
        }
    }

    #[test]
    fn a_second_backend_is_registered_and_resolvable() {
        let registry = EngineRegistry::new(stub("claude")).with_engine(stub("codex"));
        assert_eq!(registry.names(), vec!["claude", "codex"]);
        assert_eq!(registry.default_name(), "claude");

        let (name, engine) = registry.resolve(Some("codex"));
        assert_eq!(name, "codex");
        assert_eq!(engine.name(), "codex");

        // The default is untouched by the extra registration.
        let (name, _) = registry.resolve(None);
        assert_eq!(name, "claude");
    }

    #[test]
    fn re_registering_a_name_replaces_the_backend() {
        let registry = EngineRegistry::new(stub("claude")).with_engine(stub("claude"));
        assert_eq!(registry.names(), vec!["claude"]);
        assert_eq!(registry.resolve(None).0, "claude");
    }
}
