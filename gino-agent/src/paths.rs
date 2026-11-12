//! Shared path safety.
//!
//! [`safe_component`] is the single validator every subsystem uses before
//! joining an attacker-influenced name under a local directory; callers wrap
//! [`UnsafeName`] in their own domain error (`From` impls live beside those
//! error types).
//!
//! The `*_beneath` functions are for trees an engine can write (a thread's work
//! dir, a memory tree): the daemon runs outside the engine's sandbox, so a
//! symlink the engine planted there must never redirect a daemon read or write.
//! They walk from a root one component at a time with `O_NOFOLLOW`, and report
//! a symlink or other non-plain entry as [`io::ErrorKind::InvalidInput`]
//! (see [`is_not_plain`]).

use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::os::fd::OwnedFd;
use std::path::{Component, Path};

use rustix::fs::{AtFlags, CWD, FileType, Mode, OFlags, fstat, mkdirat, openat, unlinkat};
use rustix::io::Errno;

/// A name rejected by [`safe_component`]: used as a path component it could
/// escape its parent directory.
#[derive(Debug)]
pub(crate) struct UnsafeName {
    /// The offending (attacker-influenced) name.
    pub(crate) name: String,
}

/// Validate an attacker-influenced `name` down to a single safe path component:
/// reject empties, `.`/`..`, NULs and separators (`/`/`\`), so the caller can
/// join it under a fixed directory without `../`/absolute-path escape. Returns
/// the name borrowed on success.
pub(crate) fn safe_component(name: &str) -> Result<&str, UnsafeName> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('\0')
        || name.contains('/')
        || name.contains('\\')
    {
        return Err(UnsafeName {
            name: name.to_owned(),
        });
    }
    Ok(name)
}

const DIR_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

fn not_plain() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "a symlink or other non-plain entry is in the path",
    )
}

/// Whether `err` reports a symlink or other non-plain entry met by a
/// `*_beneath` function.
pub(crate) fn is_not_plain(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::InvalidInput
}

/// `O_NOFOLLOW` answers `ELOOP` for a symlink and, with `O_DIRECTORY`,
/// `ENOTDIR` for anything that is not a directory.
fn open_error(errno: Errno) -> io::Error {
    if matches!(errno, Errno::LOOP | Errno::NOTDIR) {
        not_plain()
    } else {
        errno.into()
    }
}

/// Open the directory `rel` beneath `root`, following no symlink at `root`'s
/// last component or below it. `rel` holds normal components only (empty names
/// `root` itself). With `create`, missing directories (including `root`) are
/// created.
pub(crate) fn open_dir_beneath(root: &Path, rel: &Path, create: bool) -> io::Result<OwnedFd> {
    let mut dir = match openat(CWD, root, DIR_FLAGS, Mode::empty()) {
        Ok(dir) => dir,
        Err(Errno::NOENT) if create => {
            std::fs::create_dir_all(root)?;
            openat(CWD, root, DIR_FLAGS, Mode::empty()).map_err(open_error)?
        }
        Err(errno) => return Err(open_error(errno)),
    };
    for component in rel.components() {
        let Component::Normal(name) = component else {
            return Err(not_plain());
        };
        dir = match openat(&dir, name, DIR_FLAGS, Mode::empty()) {
            Ok(next) => next,
            Err(Errno::NOENT) if create => {
                match mkdirat(&dir, name, Mode::from_raw_mode(0o777)) {
                    Ok(()) | Err(Errno::EXIST) => {}
                    Err(errno) => return Err(errno.into()),
                }
                openat(&dir, name, DIR_FLAGS, Mode::empty()).map_err(open_error)?
            }
            Err(errno) => return Err(open_error(errno)),
        };
    }
    Ok(dir)
}

/// Split `rel` into its parent and file name; `rel` must name something.
fn split(rel: &Path) -> io::Result<(&Path, &OsStr)> {
    match (rel.parent(), rel.file_name()) {
        (Some(parent), Some(name)) => Ok((parent, name)),
        _ => Err(not_plain()),
    }
}

/// Open the regular file `rel` beneath `root` for reading, following no
/// symlink at `root`'s last component or below it.
pub(crate) fn open_file_beneath(root: &Path, rel: &Path) -> io::Result<File> {
    let (parent, name) = split(rel)?;
    let dir = open_dir_beneath(root, parent, false)?;
    // Non-blocking so a FIFO cannot stall the open before the type check.
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let file = openat(&dir, name, flags, Mode::empty()).map_err(open_error)?;
    if FileType::from_raw_mode(fstat(&file)?.st_mode) != FileType::RegularFile {
        return Err(not_plain());
    }
    Ok(File::from(file))
}

/// Create the regular file `name` in `dir` for writing, replacing whatever
/// non-directory entry holds the name (a symlink is removed, never followed).
pub(crate) fn create_file_in(dir: &OwnedFd, name: &OsStr) -> io::Result<File> {
    match unlinkat(dir, name, AtFlags::empty()) {
        Ok(()) | Err(Errno::NOENT) => {}
        Err(errno) => return Err(errno.into()),
    }
    let flags = OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let file = openat(dir, name, flags, Mode::from_raw_mode(0o666)).map_err(open_error)?;
    Ok(File::from(file))
}

/// Make sure the directory `rel` exists beneath `root` (see
/// [`open_dir_beneath`]).
pub(crate) fn create_dir_beneath(root: &Path, rel: &Path) -> io::Result<()> {
    open_dir_beneath(root, rel, true).map(drop)
}

/// Make sure the regular file `rel` exists beneath `root`, creating it empty
/// (and its parent directories) when missing; an existing symlink is refused.
pub(crate) fn touch_beneath(root: &Path, rel: &Path) -> io::Result<()> {
    let (parent, name) = split(rel)?;
    let dir = open_dir_beneath(root, parent, true)?;
    let flags = OFlags::WRONLY | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    openat(&dir, name, flags, Mode::from_raw_mode(0o666))
        .map(drop)
        .map_err(open_error)
}

#[cfg(test)]
mod tests {
    use std::io::{Read as _, Write as _};
    use std::os::unix::fs::symlink;
    use std::path::Path;

    use super::{
        create_dir_beneath, create_file_in, is_not_plain, open_dir_beneath, open_file_beneath,
        safe_component, touch_beneath,
    };

    #[test]
    fn safe_component_rejects_traversal_and_absolute_paths() {
        for bad in [
            "../escape",
            "/etc/passwd",
            "..",
            ".",
            "",
            "a/b",
            "a\\b",
            "x\0y",
        ] {
            assert!(
                safe_component(bad).is_err(),
                "expected {bad:?} to be rejected"
            );
        }
    }

    #[test]
    fn safe_component_accepts_plain_names() {
        for good in [
            "report.txt",
            "data-1.json",
            "a_b.csv",
            "naïve.txt",
            "CLAUDE.md",
            "demo-skill",
            "my_config.json",
        ] {
            assert_eq!(safe_component(good).unwrap(), good);
        }
    }

    #[test]
    fn beneath_opens_and_creates_plain_paths() {
        let root = tempfile::tempdir().unwrap();
        let dir = open_dir_beneath(root.path(), Path::new("a/b"), true).unwrap();
        create_file_in(&dir, "f.txt".as_ref())
            .unwrap()
            .write_all(b"data")
            .unwrap();
        let mut read = String::new();
        open_file_beneath(root.path(), Path::new("a/b/f.txt"))
            .unwrap()
            .read_to_string(&mut read)
            .unwrap();
        assert_eq!(read, "data");

        let missing = open_dir_beneath(root.path(), Path::new("nope"), false).unwrap_err();
        assert_eq!(missing.kind(), std::io::ErrorKind::NotFound);
        // A missing root is created with its parents.
        create_dir_beneath(&root.path().join("x/y"), Path::new("z")).unwrap();
        assert!(root.path().join("x/y/z").is_dir());
        touch_beneath(root.path(), Path::new("t/empty")).unwrap();
        assert_eq!(std::fs::read(root.path().join("t/empty")).unwrap(), b"");
    }

    #[test]
    fn beneath_never_follows_a_symlink() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret"), "SECRET").unwrap();
        symlink(outside.path(), root.path().join("dir")).unwrap();
        symlink(outside.path().join("secret"), root.path().join("file")).unwrap();
        symlink(outside.path().join("new"), root.path().join("dangling")).unwrap();

        for create in [false, true] {
            let err = open_dir_beneath(root.path(), Path::new("dir"), create).unwrap_err();
            assert!(is_not_plain(&err), "{err}");
            let err = open_dir_beneath(root.path(), Path::new("dir/sub"), create).unwrap_err();
            assert!(is_not_plain(&err), "{err}");
        }
        assert!(is_not_plain(
            &open_file_beneath(root.path(), Path::new("file")).unwrap_err()
        ));
        assert!(is_not_plain(
            &open_file_beneath(root.path(), Path::new("dir/secret")).unwrap_err()
        ));
        assert!(is_not_plain(
            &touch_beneath(root.path(), Path::new("dangling")).unwrap_err()
        ));
        assert!(is_not_plain(
            &touch_beneath(root.path(), Path::new("dir/new")).unwrap_err()
        ));
        // A root that is itself a symlink is refused too.
        assert!(is_not_plain(
            &open_dir_beneath(&root.path().join("dir"), Path::new(""), false).unwrap_err()
        ));
        // `..` never climbs out.
        assert!(is_not_plain(
            &open_dir_beneath(root.path(), Path::new("../x"), true).unwrap_err()
        ));
        assert!(!outside.path().join("new").exists());
        assert!(!outside.path().join("sub").exists());
    }

    #[test]
    fn create_file_in_replaces_a_symlink_instead_of_writing_through_it() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("victim"), "KEEP").unwrap();
        symlink(outside.path().join("victim"), root.path().join("f")).unwrap();

        let dir = open_dir_beneath(root.path(), Path::new(""), false).unwrap();
        create_file_in(&dir, "f".as_ref())
            .unwrap()
            .write_all(b"new")
            .unwrap();
        assert_eq!(std::fs::read(root.path().join("f")).unwrap(), b"new");
        assert!(!root.path().join("f").is_symlink());
        assert_eq!(
            std::fs::read(outside.path().join("victim")).unwrap(),
            b"KEEP"
        );
    }
}
