//! Agent and task memory.
//!
//! Two trees live under `<workspace_dir>/memory/`: `agent/`, shared by every task
//! on this agent and exposed to the engine as `GINO_AGENT_MEMORY_DIR`, and
//! `task/<task_id>/`, shared by every thread of one task and exposed as
//! `GINO_MEMORY_DIR`. Each tree holds `index.md` (core memory + map) and
//! `system/definition.md` (how to store, prune and correct), scaffolded on first
//! use and owned by the agent afterwards. [`render_context`] produces the text
//! injected into a new engine session.

use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io::{self, Write as _};
use std::path::{Component, Path, PathBuf};

/// Default soft cap on the total size of one memory tree.
pub(crate) const DEFAULT_MAX_BYTES: u64 = 1_048_576;
/// Max characters of one memory file inlined into the injected context.
pub(crate) const FILE_CHAR_CAP: usize = 16_384;

/// The core-memory file, relative to a tree.
const INDEX_FILE: &str = "index.md";
/// The memory-definition file, relative to a tree.
const DEFINITION_FILE: &str = "system/definition.md";
/// The dir Claude Code's native auto memory is redirected into, relative to a
/// task tree.
const CLAUDE_DIR: &str = "claude";

/// One memory tree kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Tree {
    /// Shared by every task on this agent.
    Agent,
    /// Private to one task.
    Task,
}

impl Tree {
    /// Scaffold templates written when missing, keyed by relative path.
    fn scaffold(self) -> [(&'static str, &'static str); 2] {
        match self {
            Self::Agent => [
                (INDEX_FILE, include_str!("agent-index.md")),
                (DEFINITION_FILE, include_str!("agent-definition.md")),
            ],
            Self::Task => [
                (INDEX_FILE, include_str!("index.md")),
                (DEFINITION_FILE, include_str!("definition.md")),
            ],
        }
    }

    /// Display name used in the injected context.
    fn label(self) -> &'static str {
        match self {
            Self::Agent => "agent memory",
            Self::Task => "task memory",
        }
    }

    /// The engine env var naming this tree.
    fn env_var(self) -> &'static str {
        match self {
            Self::Agent => "$GINO_AGENT_MEMORY_DIR",
            Self::Task => "$GINO_MEMORY_DIR",
        }
    }
}

/// How engines may use the agent memory tree.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum AgentMemoryAccess {
    /// Read and write.
    #[default]
    Rw,
    /// Read only.
    Ro,
    /// No agent tree at all.
    Off,
}

impl AgentMemoryAccess {
    /// Parse `rw`, `ro` or `off`.
    pub(crate) fn parse(raw: &str) -> Option<Self> {
        match raw {
            "rw" => Some(Self::Rw),
            "ro" => Some(Self::Ro),
            "off" => Some(Self::Off),
            _ => None,
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Rw => "rw",
            Self::Ro => "ro",
            Self::Off => "off",
        }
    }

    /// Openness rank: higher is looser.
    fn rank(self) -> u8 {
        match self {
            Self::Rw => 2,
            Self::Ro => 1,
            Self::Off => 0,
        }
    }
}

/// Whether tasks get a task memory tree.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum TaskMemory {
    #[default]
    On,
    Off,
}

impl TaskMemory {
    /// Parse `on` or `off`.
    pub(crate) fn parse(raw: &str) -> Option<Self> {
        match raw {
            "on" => Some(Self::On),
            "off" => Some(Self::Off),
            _ => None,
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::On => "on",
            Self::Off => "off",
        }
    }

    /// Openness rank: higher is looser.
    fn rank(self) -> u8 {
        match self {
            Self::On => 1,
            Self::Off => 0,
        }
    }
}

/// A task's `meta.memory` block; each key may only tighten the agent-local
/// setting.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct MemoryOverride {
    pub(crate) task: Option<TaskMemory>,
    pub(crate) agent: Option<AgentMemoryAccess>,
}

/// A malformed `meta.memory` block.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid task meta.memory: {0}")]
pub(crate) struct MemoryMetaError(String);

/// Parse `meta.memory` out of a task's meta JSON. Absent or non-object meta and
/// a missing `memory` key yield an empty override; unknown keys inside
/// `memory` are ignored; a non-object `memory` or a bad `task` / `agent` value
/// is an error.
pub(crate) fn memory_override_from_meta(
    meta: Option<&str>,
) -> Result<MemoryOverride, MemoryMetaError> {
    let Some(Ok(serde_json::Value::Object(mut map))) = meta.map(serde_json::from_str) else {
        return Ok(MemoryOverride::default());
    };
    let Some(value) = map.remove("memory") else {
        return Ok(MemoryOverride::default());
    };
    let serde_json::Value::Object(memory) = value else {
        return Err(MemoryMetaError(format!("expected an object, got {value}")));
    };
    let task = memory
        .get("task")
        .map(|raw| {
            raw.as_str().and_then(TaskMemory::parse).ok_or_else(|| {
                MemoryMetaError(format!("task must be \"on\" or \"off\", got {raw}"))
            })
        })
        .transpose()?;
    let agent = memory
        .get("agent")
        .map(|raw| {
            raw.as_str()
                .and_then(AgentMemoryAccess::parse)
                .ok_or_else(|| {
                    MemoryMetaError(format!(
                        "agent must be \"rw\", \"ro\" or \"off\", got {raw}"
                    ))
                })
        })
        .transpose()?;
    Ok(MemoryOverride { task, agent })
}

/// The effective task and agent memory settings: per key the tighter of the
/// agent-local value and the override. A looser override value is ignored and
/// reported in the returned warnings.
pub(crate) fn resolve(
    agent_local: (TaskMemory, AgentMemoryAccess),
    ov: MemoryOverride,
) -> (TaskMemory, AgentMemoryAccess, Vec<String>) {
    let (mut task, mut agent) = agent_local;
    let mut warnings = Vec::new();
    if let Some(wanted) = ov.task {
        if wanted.rank() > task.rank() {
            warnings.push(format!(
                "task meta.memory.task `{}` would loosen the agent-local `{}`; ignored",
                wanted.as_str(),
                task.as_str()
            ));
        } else {
            task = wanted;
        }
    }
    if let Some(wanted) = ov.agent {
        if wanted.rank() > agent.rank() {
            warnings.push(format!(
                "task meta.memory.agent `{}` would loosen the agent-local `{}`; ignored",
                wanted.as_str(),
                agent.as_str()
            ));
        } else {
            agent = wanted;
        }
    }
    (task, agent, warnings)
}

/// The task tree of `task_id`: `<workspace_dir>/memory/task/<task_id>`. Check
/// the id with [`valid_task_id`] first.
pub(crate) fn memory_dir(workspace_dir: &Path, task_id: &str) -> PathBuf {
    workspace_dir.join("memory").join("task").join(task_id)
}

/// The agent tree: `<workspace_dir>/memory/agent`.
pub(crate) fn agent_memory_dir(workspace_dir: &Path) -> PathBuf {
    workspace_dir.join("memory").join("agent")
}

/// Whether `task_id` is a single normal path component (non-empty, no `/`, not
/// `.`/`..`, no NUL), so [`memory_dir`] stays inside the task root.
pub(crate) fn valid_task_id(task_id: &str) -> bool {
    if task_id.is_empty() || task_id.contains(['/', '\0']) {
        return false;
    }
    let mut components = Path::new(task_id).components();
    matches!(
        (components.next(), components.next()),
        (Some(Component::Normal(_)), None)
    )
}

/// Create the `tree` at `dir` (owner-only for every directory this call creates
/// below the workspace dir), plus the `claude/` dir of a task tree, and write
/// each missing scaffold file of that tree. Existing files are never touched, even when empty. Idempotent.
pub(crate) fn prepare(dir: &Path, tree: Tree) -> io::Result<()> {
    let root = match tree {
        Tree::Agent => dir.parent(),
        Tree::Task => dir.parent().and_then(Path::parent),
    };
    if let Some(root) = root {
        if let Some(workspace) = root.parent() {
            fs::create_dir_all(workspace)?;
        }
        create_private_dir(root)?;
    }
    if tree == Tree::Task
        && let Some(parent) = dir.parent()
    {
        create_private_dir(parent)?;
    }
    create_private_dir(dir)?;
    create_private_dir(&dir.join("system"))?;
    if tree == Tree::Task {
        create_private_dir(&dir.join(CLAUDE_DIR))?;
    }
    for (file, template) in tree.scaffold() {
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dir.join(file))
        {
            Ok(mut handle) => handle.write_all(template.as_bytes())?,
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

/// Create one directory with mode 0700; an existing directory is left as is.
fn create_private_dir(dir: &Path) -> io::Result<()> {
    match fs::create_dir(dir) {
        Ok(()) => set_private(dir),
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(err) => Err(err),
    }
}

#[cfg(unix)]
fn set_private(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn set_private(_dir: &Path) -> io::Result<()> {
    Ok(())
}

/// Total bytes of the regular files under `dir`, recursive, not following
/// symlinks.
pub(crate) fn dir_size(dir: &Path) -> io::Result<u64> {
    let mut total = 0;
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            total += dir_size(&entry.path())?;
        } else if file_type.is_file() {
            total += entry.metadata()?.len();
        }
    }
    Ok(total)
}

/// The agent tree handed to [`render_context`].
#[derive(Clone, Copy, Debug)]
pub(crate) struct AgentContext<'a> {
    /// The agent tree dir.
    pub(crate) dir: &'a Path,
    /// Whether the engine sees the tree read-only.
    pub(crate) read_only: bool,
}

/// The memory context injected into an engine session: the agent tree, then the
/// task tree, each only when given and existing. Empty when neither renders or
/// a tree cannot be read.
pub(crate) fn render_context(
    agent: Option<AgentContext<'_>>,
    task: Option<&Path>,
    max_bytes: u64,
) -> String {
    try_render_context(agent, task, max_bytes).unwrap_or_default()
}

/// [`render_context`], surfacing read errors instead of yielding nothing.
pub(crate) fn try_render_context(
    agent: Option<AgentContext<'_>>,
    task: Option<&Path>,
    max_bytes: u64,
) -> io::Result<String> {
    let agent = agent.filter(|agent| agent.dir.is_dir());
    let task = task.filter(|dir| dir.is_dir());
    if agent.is_none() && task.is_none() {
        return Ok(String::new());
    }
    let mut out = String::from(
        "# Memory\n\n\
         Persistent memory follows. Read it, and update each tree as described in \
         its `system/definition.md`.\n",
    );
    if let Some(agent) = agent {
        out.push_str(
            "\n## Agent memory (shared by every task on this agent; $GINO_AGENT_MEMORY_DIR",
        );
        if agent.read_only {
            out.push_str("; read-only: you cannot change it");
        }
        out.push_str(")\n");
        render_tree(&mut out, agent.dir, Tree::Agent, max_bytes)?;
    }
    if let Some(dir) = task {
        out.push_str("\n## Task memory (this task only; $GINO_MEMORY_DIR)\n");
        render_tree(&mut out, dir, Tree::Task, max_bytes)?;
        let _ = write!(
            out,
            "\nClaude Code's native auto memory for this task: `{}/{CLAUDE_DIR}/` (managed by \
             Claude, not shown here; read it when useful).\n",
            Tree::Task.env_var()
        );
    }
    Ok(out)
}

/// Append the files of one tree and its size warning to `out`.
fn render_tree(out: &mut String, dir: &Path, tree: Tree, max_bytes: u64) -> io::Result<()> {
    let label = tree.label();
    for file in [INDEX_FILE, DEFINITION_FILE] {
        let _ = write!(out, "\n### {label}: {file}\n\n");
        match fs::read(dir.join(file)) {
            Ok(bytes) => out.push_str(&truncated(tree, file, &String::from_utf8_lossy(&bytes))),
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                let _ = writeln!(out, "_{label}: {file} is missing._");
            }
            Err(err) => return Err(err),
        }
    }
    let size = dir_size(dir)?;
    if size > max_bytes {
        let _ = write!(
            out,
            "\n### {label}: size warning\n\n\
             The {label} directory holds {size} bytes, over the {max_bytes}-byte cap. \
             Prune it as described in its `system/definition.md`.\n"
        );
    }
    Ok(())
}

/// `content` cut to [`FILE_CHAR_CAP`] chars plus a notice naming the tree and
/// `file`, or `content` unchanged when it fits; always newline-terminated.
fn truncated(tree: Tree, file: &str, content: &str) -> String {
    let mut out = match content.char_indices().nth(FILE_CHAR_CAP) {
        Some((end, _)) => {
            let total = content.chars().count();
            format!(
                "{}\n\n[truncated: {} {file} is {total} characters; read the rest at \
                 `{}/{file}`]",
                &content[..end],
                tree.label(),
                tree.env_var()
            )
        }
        None => content.to_owned(),
    };
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out
}

/// Delete the task tree of `task_id`; the agent tree is never touched. An
/// invalid id or a missing dir is a no-op.
pub(crate) fn remove(workspace_dir: &Path, task_id: &str) -> io::Result<()> {
    if !valid_task_id(task_id) {
        return Ok(());
    }
    match fs::remove_dir_all(memory_dir(workspace_dir, task_id)) {
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    use super::{
        AgentContext, AgentMemoryAccess, DEFAULT_MAX_BYTES, FILE_CHAR_CAP, MemoryMetaError,
        MemoryOverride, TaskMemory, Tree, agent_memory_dir, dir_size, memory_dir,
        memory_override_from_meta, prepare, remove, render_context, resolve, valid_task_id,
    };

    fn mode_of(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    /// A tree dir holding `index.md` with `index` and a definition with `rules`.
    fn tree_with(index: &str, rules: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("system")).unwrap();
        fs::write(dir.path().join("index.md"), index).unwrap();
        fs::write(dir.path().join("system/definition.md"), rules).unwrap();
        dir
    }

    fn agent(dir: &Path, read_only: bool) -> AgentContext<'_> {
        AgentContext { dir, read_only }
    }

    #[test]
    fn trees_live_under_workspace_memory() {
        assert_eq!(
            memory_dir(Path::new("/var/lib/gino-agent"), "t1"),
            PathBuf::from("/var/lib/gino-agent/memory/task/t1")
        );
        assert_eq!(
            agent_memory_dir(Path::new("/var/lib/gino-agent")),
            PathBuf::from("/var/lib/gino-agent/memory/agent")
        );
    }

    #[test]
    fn valid_task_id_accepts_single_normal_components() {
        for id in ["t1", "abc-123_x", "a.b", "..x", "x.."] {
            assert!(valid_task_id(id), "{id:?} should be valid");
        }
        for id in ["", ".", "..", "a/b", "/abs", "a/", "x\0y"] {
            assert!(!valid_task_id(id), "{id:?} should be invalid");
        }
    }

    #[test]
    fn agent_memory_access_parses_the_three_modes() {
        assert_eq!(AgentMemoryAccess::default(), AgentMemoryAccess::Rw);
        assert_eq!(AgentMemoryAccess::parse("rw"), Some(AgentMemoryAccess::Rw));
        assert_eq!(AgentMemoryAccess::parse("ro"), Some(AgentMemoryAccess::Ro));
        assert_eq!(
            AgentMemoryAccess::parse("off"),
            Some(AgentMemoryAccess::Off)
        );
        for raw in ["", "RW", "read-only", "on"] {
            assert_eq!(AgentMemoryAccess::parse(raw), None, "{raw:?}");
        }
    }

    #[test]
    fn task_memory_parses_on_and_off() {
        assert_eq!(TaskMemory::parse("on"), Some(TaskMemory::On));
        assert_eq!(TaskMemory::parse("off"), Some(TaskMemory::Off));
        assert_eq!(TaskMemory::parse("OFF"), None);
        assert_eq!(TaskMemory::default(), TaskMemory::On);
    }

    #[test]
    fn memory_override_from_meta_without_memory_is_empty() {
        for meta in [
            None,
            Some(""),
            Some("not json"),
            Some("[1, 2]"),
            Some("{}"),
            Some(r#"{ "isolation": { "mode": "sandbox" } }"#),
            Some(r#"{ "memory": {} }"#),
            Some(r#"{ "memory": { "other": 1 } }"#),
        ] {
            assert_eq!(
                memory_override_from_meta(meta).unwrap(),
                MemoryOverride::default(),
                "{meta:?}"
            );
        }
    }

    #[test]
    fn memory_override_from_meta_parses_each_key() {
        assert_eq!(
            memory_override_from_meta(Some(r#"{ "memory": { "task": "off" } }"#)).unwrap(),
            MemoryOverride {
                task: Some(TaskMemory::Off),
                agent: None
            }
        );
        assert_eq!(
            memory_override_from_meta(Some(r#"{ "memory": { "agent": "ro" } }"#)).unwrap(),
            MemoryOverride {
                task: None,
                agent: Some(AgentMemoryAccess::Ro)
            }
        );
        assert_eq!(
            memory_override_from_meta(Some(r#"{ "memory": { "task": "on", "agent": "off" } }"#))
                .unwrap(),
            MemoryOverride {
                task: Some(TaskMemory::On),
                agent: Some(AgentMemoryAccess::Off)
            }
        );
    }

    #[test]
    fn memory_override_from_meta_rejects_a_malformed_block() {
        for meta in [
            r#"{ "memory": "off" }"#,
            r#"{ "memory": null }"#,
            r#"{ "memory": [] }"#,
            r#"{ "memory": { "task": "maybe" } }"#,
            r#"{ "memory": { "task": false } }"#,
            r#"{ "memory": { "task": null } }"#,
            r#"{ "memory": { "agent": "write" } }"#,
            r#"{ "memory": { "agent": 1 } }"#,
        ] {
            let err: MemoryMetaError = memory_override_from_meta(Some(meta)).unwrap_err();
            assert!(err.to_string().contains("meta.memory"), "{meta}: {err}");
        }
    }

    #[test]
    fn resolve_takes_the_tighter_value_per_key() {
        use AgentMemoryAccess::{Off, Ro, Rw};
        use TaskMemory::{Off as TOff, On};
        let none = MemoryOverride::default();
        assert_eq!(resolve((On, Rw), none), (On, Rw, vec![]));
        assert_eq!(resolve((TOff, Ro), none), (TOff, Ro, vec![]));

        for (local, wanted, effective, warns) in [
            (On, On, On, false),
            (On, TOff, TOff, false),
            (TOff, TOff, TOff, false),
            (TOff, On, TOff, true),
        ] {
            let ov = MemoryOverride {
                task: Some(wanted),
                agent: None,
            };
            let (task, agent, warnings) = resolve((local, Rw), ov);
            assert_eq!((task, agent), (effective, Rw), "{local:?} {wanted:?}");
            assert_eq!(warnings.len(), usize::from(warns), "{local:?} {wanted:?}");
        }

        for (local, wanted, effective, warns) in [
            (Rw, Rw, Rw, false),
            (Rw, Ro, Ro, false),
            (Rw, Off, Off, false),
            (Ro, Rw, Ro, true),
            (Ro, Ro, Ro, false),
            (Ro, Off, Off, false),
            (Off, Rw, Off, true),
            (Off, Ro, Off, true),
            (Off, Off, Off, false),
        ] {
            let ov = MemoryOverride {
                task: None,
                agent: Some(wanted),
            };
            let (task, agent, warnings) = resolve((On, local), ov);
            assert_eq!((task, agent), (On, effective), "{local:?} {wanted:?}");
            assert_eq!(warnings.len(), usize::from(warns), "{local:?} {wanted:?}");
            if warns {
                assert!(warnings[0].contains("meta.memory.agent"), "{warnings:?}");
            }
        }

        let ov = MemoryOverride {
            task: Some(On),
            agent: Some(Rw),
        };
        let (task, agent, warnings) = resolve((TOff, Off), ov);
        assert_eq!((task, agent, warnings.len()), (TOff, Off, 2));
    }

    #[test]
    fn prepare_scaffolds_the_task_tree_in_private_dirs() {
        let ws = tempfile::tempdir().unwrap();
        let dir = memory_dir(ws.path(), "t1");
        prepare(&dir, Tree::Task).unwrap();

        let index = fs::read_to_string(dir.join("index.md")).unwrap();
        assert_eq!(index, include_str!("index.md"));
        assert!(index.contains("## Core memory") && index.contains("## Map"));
        let definition = fs::read_to_string(dir.join("system/definition.md")).unwrap();
        assert!(definition.contains("$GINO_MEMORY_DIR"));
        assert!(definition.contains("$GINO_AGENT_MEMORY_DIR"));
        assert!(definition.contains("$GINO_CONVERSATIONS_DIR"));
        assert!(!definition.contains("conversations-archive"));
        for path in [
            ws.path().join("memory"),
            ws.path().join("memory/task"),
            dir.clone(),
            dir.join("system"),
            dir.join("claude"),
        ] {
            assert_eq!(mode_of(&path), 0o700, "{}", path.display());
        }
        assert_eq!(fs::read_dir(dir.join("claude")).unwrap().count(), 0);
        assert!(definition.contains("$GINO_MEMORY_DIR/claude/"));
        assert!(!agent_memory_dir(ws.path()).exists());
    }

    #[test]
    fn prepare_scaffolds_the_agent_tree_in_private_dirs() {
        let ws = tempfile::tempdir().unwrap();
        let dir = agent_memory_dir(ws.path());
        prepare(&dir, Tree::Agent).unwrap();

        let index = fs::read_to_string(dir.join("index.md")).unwrap();
        assert_eq!(index, include_str!("agent-index.md"));
        assert!(index.contains("## Core memory") && index.contains("## Map"));
        let definition = fs::read_to_string(dir.join("system/definition.md")).unwrap();
        assert_eq!(definition, include_str!("agent-definition.md"));
        assert!(definition.contains("$GINO_AGENT_MEMORY_DIR"));
        assert!(definition.contains("every task on this agent"));
        assert!(definition.contains("different owners"));
        assert!(!definition.contains("conversations-archive"));
        for path in [ws.path().join("memory"), dir.clone(), dir.join("system")] {
            assert_eq!(mode_of(&path), 0o700, "{}", path.display());
        }
        assert!(definition.contains("`claude/` subdir"));
        assert!(!dir.join("claude").exists());
        assert!(!ws.path().join("memory/task").exists());
    }

    #[test]
    fn prepare_never_touches_existing_files() {
        let ws = tempfile::tempdir().unwrap();
        for (dir, tree) in [
            (memory_dir(ws.path(), "t1"), Tree::Task),
            (agent_memory_dir(ws.path()), Tree::Agent),
        ] {
            prepare(&dir, tree).unwrap();
            fs::write(dir.join("index.md"), "edited").unwrap();
            fs::write(dir.join("system/definition.md"), "").unwrap();

            prepare(&dir, tree).unwrap();
            assert_eq!(fs::read_to_string(dir.join("index.md")).unwrap(), "edited");
            assert_eq!(
                fs::read_to_string(dir.join("system/definition.md")).unwrap(),
                ""
            );
        }
    }

    #[test]
    fn prepare_adds_a_missing_claude_dir_to_an_existing_task_tree() {
        let ws = tempfile::tempdir().unwrap();
        let dir = memory_dir(ws.path(), "t1");
        prepare(&dir, Tree::Task).unwrap();
        fs::remove_dir(dir.join("claude")).unwrap();
        fs::write(dir.join("index.md"), "edited").unwrap();
        fs::write(dir.join("notes.md"), "topic").unwrap();

        prepare(&dir, Tree::Task).unwrap();
        assert_eq!(mode_of(&dir.join("claude")), 0o700);
        assert_eq!(fs::read_to_string(dir.join("index.md")).unwrap(), "edited");
        assert_eq!(fs::read_to_string(dir.join("notes.md")).unwrap(), "topic");
        assert_eq!(
            fs::read_to_string(dir.join("system/definition.md")).unwrap(),
            include_str!("definition.md")
        );
    }

    #[test]
    fn prepare_keeps_claude_files_and_dir_mode() {
        let ws = tempfile::tempdir().unwrap();
        let dir = memory_dir(ws.path(), "t1");
        prepare(&dir, Tree::Task).unwrap();
        fs::write(dir.join("claude/MEMORY.md"), "claude index").unwrap();

        prepare(&dir, Tree::Task).unwrap();
        assert_eq!(
            fs::read_to_string(dir.join("claude/MEMORY.md")).unwrap(),
            "claude index"
        );
        assert_eq!(mode_of(&dir.join("claude")), 0o700);
    }

    #[test]
    fn prepare_recreates_only_a_deleted_file() {
        let ws = tempfile::tempdir().unwrap();
        for (dir, tree, template) in [
            (
                memory_dir(ws.path(), "t1"),
                Tree::Task,
                include_str!("definition.md"),
            ),
            (
                agent_memory_dir(ws.path()),
                Tree::Agent,
                include_str!("agent-definition.md"),
            ),
        ] {
            prepare(&dir, tree).unwrap();
            fs::write(dir.join("index.md"), "edited").unwrap();
            fs::remove_file(dir.join("system/definition.md")).unwrap();

            prepare(&dir, tree).unwrap();
            assert_eq!(fs::read_to_string(dir.join("index.md")).unwrap(), "edited");
            assert_eq!(
                fs::read_to_string(dir.join("system/definition.md")).unwrap(),
                template
            );
        }
    }

    #[test]
    fn dir_size_sums_regular_files_recursively_without_following_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a"), "12345").unwrap();
        fs::create_dir(dir.path().join("sub")).unwrap();
        fs::write(dir.path().join("sub/b"), "123").unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("big"), vec![0u8; 4096]).unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join("link")).unwrap();

        assert_eq!(dir_size(dir.path()).unwrap(), 8);
    }

    #[test]
    fn dir_size_counts_claude_files() {
        let ws = tempfile::tempdir().unwrap();
        let dir = memory_dir(ws.path(), "t1");
        prepare(&dir, Tree::Task).unwrap();
        let before = dir_size(&dir).unwrap();
        fs::write(dir.join("claude/MEMORY.md"), "1234567").unwrap();
        assert_eq!(dir_size(&dir).unwrap(), before + 7);
    }

    #[test]
    fn render_context_names_the_claude_dir_without_its_contents() {
        let task_dir = tree_with("task fact", "task rules");
        fs::create_dir(task_dir.path().join("claude")).unwrap();
        fs::write(
            task_dir.path().join("claude/MEMORY.md"),
            "CLAUDE-MEMORY-MARKER",
        )
        .unwrap();
        let agent_dir = tree_with("agent fact", "agent rules");

        let out = render_context(
            Some(agent(agent_dir.path(), false)),
            Some(task_dir.path()),
            DEFAULT_MAX_BYTES,
        );
        let line = "\nClaude Code's native auto memory for this task: `$GINO_MEMORY_DIR/claude/` \
                    (managed by Claude, not shown here; read it when useful).\n";
        let at = out.find(line).expect("claude dir line");
        assert!(at > out.find("### task memory: system/definition.md").unwrap());
        assert_eq!(out.matches("$GINO_MEMORY_DIR/claude/").count(), 1);
        assert!(!out.contains("CLAUDE-MEMORY-MARKER"));

        let agent_only = render_context(
            Some(agent(agent_dir.path(), false)),
            None,
            DEFAULT_MAX_BYTES,
        );
        assert!(!agent_only.contains("claude/"));

        let bare_task = tree_with("task fact", "task rules");
        let out = render_context(None, Some(bare_task.path()), DEFAULT_MAX_BYTES);
        assert!(out.contains(line));
    }

    #[test]
    fn render_context_warns_from_claude_content_alone() {
        let task_dir = tempfile::tempdir().unwrap();
        fs::create_dir(task_dir.path().join("claude")).unwrap();
        fs::write(task_dir.path().join("claude/MEMORY.md"), "0123456789").unwrap();

        let out = render_context(None, Some(task_dir.path()), 9);
        assert!(out.contains("task memory directory holds 10 bytes, over the 9-byte cap"));
        assert!(!out.contains("0123456789"));
    }

    #[test]
    fn render_context_puts_the_agent_tree_before_the_task_tree() {
        let agent_dir = tree_with("agent fact", "agent rules");
        let task_dir = tree_with("task fact", "task rules");

        let out = render_context(
            Some(agent(agent_dir.path(), false)),
            Some(task_dir.path()),
            DEFAULT_MAX_BYTES,
        );
        let agent_header = out
            .find("## Agent memory (shared by every task on this agent; $GINO_AGENT_MEMORY_DIR)\n")
            .expect("agent header");
        let task_header = out
            .find("## Task memory (this task only; $GINO_MEMORY_DIR)\n")
            .expect("task header");
        assert!(out.starts_with("# Memory\n"));
        assert!(agent_header < task_header);
        let agent_index = out
            .find("### agent memory: index.md\n\nagent fact\n")
            .unwrap();
        let agent_rules = out
            .find("### agent memory: system/definition.md\n\nagent rules\n")
            .unwrap();
        let task_index = out
            .find("### task memory: index.md\n\ntask fact\n")
            .unwrap();
        let task_rules = out
            .find("### task memory: system/definition.md\n\ntask rules\n")
            .unwrap();
        assert!(agent_header < agent_index && agent_index < agent_rules);
        assert!(agent_rules < task_header && task_header < task_index);
        assert!(task_index < task_rules);
        assert!(!out.contains("read-only"));
        assert!(!out.contains("truncated"));
        assert!(!out.contains("size warning"));
    }

    #[test]
    fn render_context_marks_a_read_only_agent_tree() {
        let agent_dir = tree_with("agent fact", "agent rules");
        let out = render_context(Some(agent(agent_dir.path(), true)), None, DEFAULT_MAX_BYTES);
        assert!(out.contains(
            "## Agent memory (shared by every task on this agent; $GINO_AGENT_MEMORY_DIR; read-only: you cannot change it)\n"
        ));
    }

    #[test]
    fn render_context_renders_a_single_tree() {
        let agent_dir = tree_with("agent fact", "agent rules");
        let task_dir = tree_with("task fact", "task rules");

        let agent_only = render_context(
            Some(agent(agent_dir.path(), false)),
            None,
            DEFAULT_MAX_BYTES,
        );
        assert!(agent_only.contains("agent fact"));
        assert!(!agent_only.contains("## Task memory"));

        let task_only = render_context(None, Some(task_dir.path()), DEFAULT_MAX_BYTES);
        assert!(task_only.starts_with("# Memory\n"));
        assert!(task_only.contains("task fact"));
        assert!(!task_only.contains("## Agent memory"));

        let missing_agent = agent_dir.path().join("nope");
        let out = render_context(
            Some(agent(&missing_agent, false)),
            Some(task_dir.path()),
            DEFAULT_MAX_BYTES,
        );
        assert!(!out.contains("## Agent memory"));
        assert!(out.contains("task fact"));
    }

    #[test]
    fn render_context_truncates_each_tree_on_a_char_boundary() {
        let content = "é".repeat(FILE_CHAR_CAP + 10);
        let agent_dir = tree_with(&content, "rules");
        let task_dir = tree_with("core", &content);

        let out = render_context(
            Some(agent(agent_dir.path(), false)),
            Some(task_dir.path()),
            u64::MAX,
        );
        let kept = "é".repeat(FILE_CHAR_CAP);
        assert!(out.contains(&format!(
            "### agent memory: index.md\n\n{kept}\n\n[truncated"
        )));
        assert!(out.contains(&format!(
            "### task memory: system/definition.md\n\n{kept}\n\n[truncated"
        )));
        assert!(!out.contains(&"é".repeat(FILE_CHAR_CAP + 1)));
        let total = FILE_CHAR_CAP + 10;
        assert!(out.contains(&format!(
            "agent memory index.md is {total} characters; read the rest at `$GINO_AGENT_MEMORY_DIR/index.md`"
        )));
        assert!(out.contains(&format!(
            "task memory system/definition.md is {total} characters; read the rest at `$GINO_MEMORY_DIR/system/definition.md`"
        )));
    }

    #[test]
    fn render_context_notes_a_missing_file_per_tree() {
        let agent_dir = tempfile::tempdir().unwrap();
        fs::write(agent_dir.path().join("index.md"), "core").unwrap();
        let task_dir = tempfile::tempdir().unwrap();

        let out = render_context(
            Some(agent(agent_dir.path(), false)),
            Some(task_dir.path()),
            DEFAULT_MAX_BYTES,
        );
        assert!(out.contains("_agent memory: system/definition.md is missing._"));
        assert!(!out.contains("_agent memory: index.md is missing._"));
        assert!(out.contains("_task memory: index.md is missing._"));
        assert!(out.contains("_task memory: system/definition.md is missing._"));
    }

    #[test]
    fn render_context_warns_per_tree_only_over_the_cap() {
        let agent_dir = tempfile::tempdir().unwrap();
        fs::write(agent_dir.path().join("index.md"), "0123456789").unwrap();
        let task_dir = tempfile::tempdir().unwrap();
        fs::write(task_dir.path().join("index.md"), "01234").unwrap();

        let render = |max| {
            render_context(
                Some(agent(agent_dir.path(), false)),
                Some(task_dir.path()),
                max,
            )
        };
        assert!(!render(10).contains("size warning"));
        let over = render(9);
        assert!(over.contains("### agent memory: size warning"));
        assert!(over.contains("agent memory directory holds 10 bytes, over the 9-byte cap"));
        assert!(!over.contains("### task memory: size warning"));
        let both = render(4);
        assert!(both.contains("### agent memory: size warning"));
        assert!(both.contains("task memory directory holds 5 bytes, over the 4-byte cap"));
        assert!(agent_dir.path().join("index.md").exists());
        assert!(task_dir.path().join("index.md").exists());
    }

    #[test]
    fn render_context_of_no_existing_tree_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope");
        assert_eq!(render_context(None, None, DEFAULT_MAX_BYTES), "");
        assert_eq!(
            render_context(
                Some(agent(&missing, true)),
                Some(&missing),
                DEFAULT_MAX_BYTES
            ),
            ""
        );
    }

    #[test]
    fn remove_deletes_the_task_tree_and_keeps_the_agent_tree() {
        let ws = tempfile::tempdir().unwrap();
        let dir = memory_dir(ws.path(), "t1");
        prepare(&dir, Tree::Task).unwrap();
        prepare(&agent_memory_dir(ws.path()), Tree::Agent).unwrap();

        remove(ws.path(), "t1").unwrap();
        assert!(!dir.exists());
        assert!(ws.path().join("memory/task").exists());
        assert!(agent_memory_dir(ws.path()).join("index.md").exists());
    }

    #[test]
    fn remove_of_a_missing_dir_is_ok() {
        let ws = tempfile::tempdir().unwrap();
        remove(ws.path(), "t1").unwrap();
    }

    #[test]
    fn remove_with_an_invalid_id_touches_nothing() {
        let ws = tempfile::tempdir().unwrap();
        prepare(&memory_dir(ws.path(), "t1"), Tree::Task).unwrap();
        prepare(&agent_memory_dir(ws.path()), Tree::Agent).unwrap();

        for id in ["", ".", "..", "t1/..", "/"] {
            remove(ws.path(), id).unwrap();
        }
        assert!(ws.path().join("memory/task/t1/index.md").exists());
        assert!(ws.path().join("memory/agent/index.md").exists());
    }
}
