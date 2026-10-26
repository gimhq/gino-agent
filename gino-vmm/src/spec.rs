//! The run spec: one JSON object on the first line of stdin, parsed and validated before any
//! libkrun call.

use std::collections::{BTreeMap, HashSet};
use std::io::Read;

use serde::Deserialize;

/// Upper bound for the spec line.
pub const MAX_SPEC_BYTES: usize = 1 << 20;
pub const MAX_VCPUS: u8 = 32;
pub const MIN_MEMORY_MIB: u32 = 64;
pub const MAX_MEMORY_MIB: u32 = 64 * 1024;
/// virtiofs tag of the root filesystem (`KRUN_FS_ROOT_TAG`).
pub const ROOT_TAG: &str = "/dev/root";
/// `VIRTIO_BLK_ID_BYTES`: the disk id is the device's virtio-blk serial.
pub const MAX_DISK_ID_BYTES: usize = 20;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunSpec {
    /// The guest kernel. Required: libkrunfw's bundled kernel is not available.
    pub kernel: Kernel,
    pub root_dir: String,
    #[serde(default)]
    pub shares: Vec<Share>,
    #[serde(default)]
    pub overlay_files: Vec<OverlayFile>,
    /// virtio-blk devices, `vda`, `vdb`, … in order.
    #[serde(default)]
    pub disks: Vec<Disk>,
    pub vcpus: u8,
    pub memory_mib: u32,
    pub exec: Exec,
    #[serde(default)]
    pub vsock_ports: Vec<VsockPort>,
    #[serde(default)]
    pub net: Option<Net>,
    #[serde(default)]
    pub console_ports: Vec<ConsolePort>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Kernel {
    pub path: String,
    pub format: KernelFormat,
    #[serde(default)]
    pub initramfs: Option<String>,
    #[serde(default)]
    pub cmdline: Option<String>,
}

/// `KRUN_KERNEL_FORMAT_*` of libkrun 1.19.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KernelFormat {
    Raw,
    Elf,
    PeGz,
    ImageBz2,
    ImageGz,
    ImageZstd,
}

impl KernelFormat {
    pub fn krun_value(self) -> u32 {
        match self {
            Self::Raw => 0,
            Self::Elf => 1,
            Self::PeGz => 2,
            Self::ImageBz2 => 3,
            Self::ImageGz => 4,
            Self::ImageZstd => 5,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Share {
    pub tag: String,
    pub host_path: String,
    #[serde(default)]
    pub read_only: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OverlayFile {
    pub host_path: String,
    /// `/<name>`: a file at the top level of the root filesystem.
    pub guest_path: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Disk {
    pub id: String,
    pub path: String,
    pub format: DiskFormat,
    #[serde(default)]
    pub read_only: bool,
}

/// `KRUN_DISK_FORMAT_*` of libkrun 1.19 (qcow2 opens its backing chain).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiskFormat {
    Raw,
    Qcow2,
}

impl DiskFormat {
    pub fn krun_value(self) -> u32 {
        match self {
            Self::Raw => 0,
            Self::Qcow2 => 1,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Exec {
    pub path: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub workdir: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VsockPort {
    pub port: u32,
    pub host_socket_path: String,
    #[serde(default)]
    pub listen: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Net {
    pub unixstream_path: String,
    pub mac: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsolePort {
    pub name: String,
    pub in_fd: i32,
    pub out_fd: i32,
}

/// Reads one line without reading past its newline, so the rest of stdin stays available to
/// the guest console.
pub fn read_line(input: &mut impl Read) -> Result<String, String> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match input.read(&mut byte) {
            Ok(0) => break,
            Ok(_) if byte[0] == b'\n' => break,
            Ok(_) => line.push(byte[0]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(format!("read run spec: {e}")),
        }
        if line.len() > MAX_SPEC_BYTES {
            return Err(format!("run spec exceeds {MAX_SPEC_BYTES} bytes"));
        }
    }
    String::from_utf8(line).map_err(|_| "run spec is not UTF-8".to_owned())
}

impl RunSpec {
    pub fn parse(json: &str) -> Result<Self, String> {
        let spec: Self =
            serde_json::from_str(json).map_err(|e| format!("invalid run spec: {e}"))?;
        spec.validate()
            .map_err(|e| format!("invalid run spec: {e}"))?;
        Ok(spec)
    }

    pub fn validate(&self) -> Result<(), String> {
        let k = &self.kernel;
        absolute("kernel.path", &k.path)?;
        if let Some(initramfs) = &k.initramfs {
            absolute("kernel.initramfs", initramfs)?;
        }
        if let Some(cmdline) = &k.cmdline {
            no_nul("kernel.cmdline", cmdline)?;
        }
        absolute("rootDir", &self.root_dir)?;

        let mut tags = HashSet::new();
        for (i, share) in self.shares.iter().enumerate() {
            let field = format!("shares[{i}]");
            if share.tag.is_empty() {
                return Err(format!("{field}.tag: must not be empty"));
            }
            no_nul(&format!("{field}.tag"), &share.tag)?;
            if share.tag == ROOT_TAG {
                return Err(format!("{field}.tag: {ROOT_TAG} is reserved for rootDir"));
            }
            if !tags.insert(share.tag.as_str()) {
                return Err(format!("{field}.tag: duplicate tag {:?}", share.tag));
            }
            absolute(&format!("{field}.hostPath"), &share.host_path)?;
        }

        let mut names = HashSet::new();
        for (i, file) in self.overlay_files.iter().enumerate() {
            let field = format!("overlayFiles[{i}]");
            absolute(&format!("{field}.hostPath"), &file.host_path)?;
            let name = overlay_name(&file.guest_path).ok_or_else(|| {
                format!(
                    "{field}.guestPath: must be /<name> at the top level of the root \
                     filesystem, got {:?}",
                    file.guest_path
                )
            })?;
            if !names.insert(name) {
                return Err(format!(
                    "{field}.guestPath: duplicate path {:?}",
                    file.guest_path
                ));
            }
        }

        let mut ids = HashSet::new();
        for (i, disk) in self.disks.iter().enumerate() {
            let field = format!("disks[{i}]");
            if !(1..=MAX_DISK_ID_BYTES).contains(&disk.id.len()) {
                return Err(format!("{field}.id: must be 1..={MAX_DISK_ID_BYTES} bytes"));
            }
            no_nul(&format!("{field}.id"), &disk.id)?;
            if !ids.insert(disk.id.as_str()) {
                return Err(format!("{field}.id: duplicate id {:?}", disk.id));
            }
            absolute(&format!("{field}.path"), &disk.path)?;
        }

        if !(1..=MAX_VCPUS).contains(&self.vcpus) {
            return Err(format!(
                "vcpus: must be 1..={MAX_VCPUS}, got {}",
                self.vcpus
            ));
        }
        if !(MIN_MEMORY_MIB..=MAX_MEMORY_MIB).contains(&self.memory_mib) {
            return Err(format!(
                "memoryMib: must be {MIN_MEMORY_MIB}..={MAX_MEMORY_MIB}, got {}",
                self.memory_mib
            ));
        }

        self.validate_exec()?;

        let mut ports = HashSet::new();
        for (i, vsock) in self.vsock_ports.iter().enumerate() {
            let field = format!("vsockPorts[{i}]");
            if !ports.insert(vsock.port) {
                return Err(format!("{field}.port: duplicate port {}", vsock.port));
            }
            absolute(&format!("{field}.hostSocketPath"), &vsock.host_socket_path)?;
        }

        if let Some(net) = &self.net {
            absolute("net.unixstreamPath", &net.unixstream_path)?;
            parse_mac(&net.mac).map_err(|e| format!("net.mac: {e}"))?;
        }

        let mut names = HashSet::new();
        for (i, port) in self.console_ports.iter().enumerate() {
            let field = format!("consolePorts[{i}]");
            if port.name.is_empty() {
                return Err(format!("{field}.name: must not be empty"));
            }
            no_nul(&format!("{field}.name"), &port.name)?;
            if !names.insert(port.name.as_str()) {
                return Err(format!("{field}.name: duplicate name {:?}", port.name));
            }
            if port.in_fd < 0 || port.out_fd < 0 {
                return Err(format!("{field}: file descriptors must be >= 0"));
            }
        }
        Ok(())
    }

    /// argv and env travel through the kernel command line as double-quoted words.
    fn validate_exec(&self) -> Result<(), String> {
        let exec = &self.exec;
        absolute("exec.path", &exec.path)?;
        cmdline_word("exec.path", &exec.path)?;
        for (i, arg) in exec.args.iter().enumerate() {
            cmdline_word(&format!("exec.args[{i}]"), arg)?;
        }
        for (key, value) in &exec.env {
            let field = format!("exec.env.{key}");
            if key.is_empty() || key.contains('=') {
                return Err(format!("{field}: name must be non-empty without '='"));
            }
            cmdline_word(&field, key)?;
            cmdline_word(&field, value)?;
        }
        if let Some(workdir) = &exec.workdir {
            absolute("exec.workdir", workdir)?;
        }
        Ok(())
    }

    /// Checks that the host directories and files the VM is built from exist (libkrun does
    /// not check them before booting).
    pub fn check_host_paths(&self) -> Result<(), String> {
        let mut dirs = vec![("rootDir", self.root_dir.as_str())];
        dirs.extend(
            self.shares
                .iter()
                .map(|s| ("shares.hostPath", s.host_path.as_str())),
        );
        let mut files: Vec<_> = self
            .overlay_files
            .iter()
            .map(|f| ("overlayFiles.hostPath", f.host_path.as_str()))
            .collect();
        files.extend(self.disks.iter().map(|d| ("disks.path", d.path.as_str())));
        files.push(("kernel.path", &self.kernel.path));
        files.extend(
            self.kernel
                .initramfs
                .as_deref()
                .map(|p| ("kernel.initramfs", p)),
        );
        for (field, path, want_dir) in dirs
            .into_iter()
            .map(|(f, p)| (f, p, true))
            .chain(files.into_iter().map(|(f, p)| (f, p, false)))
        {
            let meta = std::fs::metadata(path).map_err(|e| format!("{field} {path}: {e}"))?;
            if want_dir && !meta.is_dir() {
                return Err(format!("{field} {path}: not a directory"));
            }
            if !want_dir && !meta.is_file() {
                return Err(format!("{field} {path}: not a regular file"));
            }
        }
        Ok(())
    }
}

/// The overlay file name for `/<name>`.
pub fn overlay_name(guest_path: &str) -> Option<&str> {
    guest_path
        .strip_prefix('/')
        .filter(|n| !n.is_empty() && !n.contains(['/', '\0']) && *n != "." && *n != "..")
}

pub fn parse_mac(mac: &str) -> Result<[u8; 6], String> {
    let mut out = [0u8; 6];
    let mut parts = mac.split(':');
    for byte in &mut out {
        let part = parts
            .next()
            .filter(|p| p.len() == 2 && p.bytes().all(|b| b.is_ascii_hexdigit()))
            .ok_or_else(|| format!("{mac:?} is not xx:xx:xx:xx:xx:xx"))?;
        *byte = u8::from_str_radix(part, 16).map_err(|e| format!("{mac:?}: {e}"))?;
    }
    if parts.next().is_some() {
        return Err(format!("{mac:?} is not xx:xx:xx:xx:xx:xx"));
    }
    if out[0] & 1 != 0 {
        return Err(format!("{mac:?} is a multicast address"));
    }
    if out == [0; 6] {
        return Err(format!("{mac:?} is the zero address"));
    }
    Ok(out)
}

fn no_nul(field: &str, value: &str) -> Result<(), String> {
    if value.contains('\0') {
        Err(format!("{field}: must not contain NUL"))
    } else {
        Ok(())
    }
}

fn absolute(field: &str, path: &str) -> Result<(), String> {
    no_nul(field, path)?;
    if path.starts_with('/') {
        Ok(())
    } else {
        Err(format!("{field}: must be an absolute path, got {path:?}"))
    }
}

fn cmdline_word(field: &str, value: &str) -> Result<(), String> {
    no_nul(field, value)?;
    if value
        .chars()
        .any(|c| c.is_whitespace() || matches!(c, '"' | '\'' | '\\'))
    {
        return Err(format!(
            "{field}: {value:?} contains whitespace, a quote or a backslash, which the kernel \
             command line cannot carry"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const FULL: &str = r#"{
        "kernel": {"path": "/opt/gino/vmlinux", "format": "elf", "initramfs": "/opt/gino/initrd", "cmdline": "console=hvc0 quiet"},
        "rootDir": "/opt/gino/rootfs",
        "shares": [
            {"tag": "work", "hostPath": "/srv/work", "readOnly": false},
            {"tag": "skills", "hostPath": "/srv/skills", "readOnly": true}
        ],
        "overlayFiles": [{"hostPath": "/usr/local/bin/gino-agent", "guestPath": "/gino-agent"}],
        "disks": [{"id": "root", "path": "/var/gino/root.qcow2", "format": "qcow2"}],
        "vcpus": 2,
        "memoryMib": 2048,
        "exec": {"path": "/bin/sh", "args": ["-c", "true"], "env": {"HOME": "/root"}, "workdir": "/srv/work"},
        "vsockPorts": [{"port": 5000, "hostSocketPath": "/run/gino/agent.sock", "listen": false}],
        "net": {"unixstreamPath": "/run/gino/net.sock", "mac": "5a:94:ef:e4:0c:ee"},
        "consolePorts": [{"name": "gino-ctl", "inFd": 3, "outFd": 4}]
    }"#;

    const MINIMAL: &str = r#"{"kernel": {"path": "/k", "format": "elf"}, "rootDir": "/r", "vcpus": 1, "memoryMib": 512, "exec": {"path": "/bin/true"}}"#;

    fn with(edit: impl FnOnce(&mut serde_json::Value)) -> String {
        let mut v: serde_json::Value = serde_json::from_str(FULL).unwrap();
        edit(&mut v);
        v.to_string()
    }

    fn err(json: &str) -> String {
        RunSpec::parse(json).unwrap_err()
    }

    #[test]
    fn parses_full_spec() {
        let spec = RunSpec::parse(FULL).unwrap();
        let kernel = &spec.kernel;
        assert_eq!(kernel.format, KernelFormat::Elf);
        assert_eq!(kernel.initramfs.as_deref(), Some("/opt/gino/initrd"));
        assert_eq!(kernel.cmdline.as_deref(), Some("console=hvc0 quiet"));
        assert_eq!(spec.shares.len(), 2);
        assert!(spec.shares[1].read_only);
        assert_eq!(spec.exec.args, ["-c", "true"]);
        assert_eq!(spec.vsock_ports[0].port, 5000);
        assert_eq!(spec.console_ports[0].out_fd, 4);
        assert_eq!(spec.disks[0].id, "root");
        assert_eq!(spec.disks[0].format, DiskFormat::Qcow2);
        assert!(!spec.disks[0].read_only);
        assert_eq!(
            parse_mac(&spec.net.unwrap().mac),
            Ok([0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee])
        );
    }

    #[test]
    fn parses_minimal_spec() {
        let spec = RunSpec::parse(MINIMAL).unwrap();
        assert!(spec.kernel.initramfs.is_none() && spec.kernel.cmdline.is_none());
        assert!(spec.net.is_none());
        assert!(spec.shares.is_empty() && spec.console_ports.is_empty());
        assert!(spec.disks.is_empty());
        assert!(spec.exec.args.is_empty() && spec.exec.env.is_empty());
    }

    #[test]
    fn kernel_cmdline_is_optional() {
        let spec = RunSpec::parse(&with(|v| {
            v["kernel"].as_object_mut().unwrap().remove("cmdline");
        }))
        .unwrap();
        assert!(spec.kernel.cmdline.is_none());
    }

    #[test]
    fn rejects_unknown_fields() {
        assert!(err(&with(|v| v["bogus"] = 1.into())).contains("unknown field `bogus`"));
        assert!(
            err(&with(|v| v["shares"][0]["mode"] = "rw".into())).contains("unknown field `mode`")
        );
        assert!(err(&with(|v| v["exec"]["user"] = 0.into())).contains("unknown field `user`"));
        let e = err(&with(|v| v["libkrunPath"] = "/opt/libkrun.so.1".into()));
        assert!(e.contains("unknown field `libkrunPath`"), "{e}");
    }

    #[test]
    fn rejects_missing_required_fields() {
        let e = err(
            r#"{"kernel": {"path": "/k", "format": "elf"}, "vcpus": 1, "memoryMib": 512, "exec": {"path": "/bin/true"}}"#,
        );
        assert!(e.contains("missing field `rootDir`"), "{e}");
        let e = err(&with(|v| {
            v.as_object_mut().unwrap().remove("kernel");
        }));
        assert!(e.contains("missing field `kernel`"), "{e}");
    }

    #[test]
    fn rejects_relative_paths() {
        for (edit, field) in [
            (
                Box::new(|v: &mut serde_json::Value| v["rootDir"] = "rootfs".into())
                    as Box<dyn Fn(&mut serde_json::Value)>,
                "rootDir",
            ),
            (
                Box::new(|v| v["kernel"]["path"] = "vmlinux".into()),
                "kernel.path",
            ),
            (
                Box::new(|v| v["shares"][1]["hostPath"] = "".into()),
                "shares[1].hostPath",
            ),
            (
                Box::new(|v| v["vsockPorts"][0]["hostSocketPath"] = "a.sock".into()),
                "vsockPorts[0].hostSocketPath",
            ),
            (
                Box::new(|v| v["net"]["unixstreamPath"] = "n".into()),
                "net.unixstreamPath",
            ),
            (
                Box::new(|v| v["exec"]["workdir"] = "work".into()),
                "exec.workdir",
            ),
            (Box::new(|v| v["exec"]["path"] = "sh".into()), "exec.path"),
        ] {
            let e = err(&with(edit));
            assert!(
                e.contains(&format!("{field}: must be an absolute path")),
                "{e}"
            );
        }
    }

    #[test]
    fn rejects_nul_in_paths() {
        let e = err(&with(|v| v["rootDir"] = "/r\u{0}x".into()));
        assert!(e.contains("rootDir: must not contain NUL"), "{e}");
    }

    #[test]
    fn rejects_bad_macs() {
        for mac in [
            "5a:94:ef:e4:0c",
            "5a:94:ef:e4:0c:ee:01",
            "5a-94-ef-e4-0c-ee",
            "5a:94:ef:e4:0c:zz",
            "5a:94:ef:e4:0c:e",
            "01:00:5e:00:00:01",
            "00:00:00:00:00:00",
            "",
        ] {
            let e = err(&with(|v| v["net"]["mac"] = mac.into()));
            assert!(e.contains("net.mac:"), "{mac}: {e}");
        }
        assert_eq!(
            parse_mac("5A:94:EF:E4:0C:EE"),
            Ok([0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee])
        );
    }

    #[test]
    fn rejects_args_the_cmdline_cannot_carry() {
        for arg in [
            "echo hi",
            "tab\there",
            "a\"b",
            "it's",
            "back\\slash",
            "new\nline",
        ] {
            let e = err(&with(|v| {
                v["exec"]["args"] = serde_json::json!(["-c", arg]);
            }));
            assert!(
                e.contains("exec.args[1]:") && e.contains("kernel command line"),
                "{e}"
            );
        }
        let e = err(&with(|v| {
            v["exec"]["env"]["GREETING"] = "hello world".into();
        }));
        assert!(e.contains("exec.env.GREETING:"), "{e}");
        let e = err(&with(|v| v["exec"]["env"]["A=B"] = "x".into()));
        assert!(e.contains("name must be non-empty"), "{e}");
    }

    #[test]
    fn rejects_duplicates() {
        let e = err(&with(|v| v["shares"][1]["tag"] = "work".into()));
        assert!(e.contains("shares[1].tag: duplicate tag"), "{e}");
        let e = err(&with(|v| {
            v["vsockPorts"] = serde_json::json!([
                {"port": 5000, "hostSocketPath": "/a"},
                {"port": 5000, "hostSocketPath": "/b", "listen": true}
            ]);
        }));
        assert!(e.contains("vsockPorts[1].port: duplicate port 5000"), "{e}");
        let e = err(&with(|v| {
            v["consolePorts"] = serde_json::json!([
                {"name": "c", "inFd": 3, "outFd": 4},
                {"name": "c", "inFd": 5, "outFd": 6}
            ]);
        }));
        assert!(e.contains("consolePorts[1].name: duplicate name"), "{e}");
        let e = err(&with(|v| {
            v["overlayFiles"] = serde_json::json!([
                {"hostPath": "/a", "guestPath": "/x"},
                {"hostPath": "/b", "guestPath": "/x"}
            ]);
        }));
        assert!(
            e.contains("overlayFiles[1].guestPath: duplicate path"),
            "{e}"
        );
        let e = err(&with(|v| {
            v["disks"] = serde_json::json!([
                {"id": "d", "path": "/a", "format": "raw"},
                {"id": "d", "path": "/b", "format": "raw"}
            ]);
        }));
        assert!(e.contains("disks[1].id: duplicate id"), "{e}");
    }

    #[test]
    fn checks_disks() {
        let e = err(&with(|v| v["disks"][0]["path"] = "root.qcow2".into()));
        assert!(e.contains("disks[0].path: must be an absolute path"), "{e}");
        let e = err(&with(|v| v["disks"][0]["id"] = "".into()));
        assert!(e.contains("disks[0].id: must be 1..=20 bytes"), "{e}");
        let e = err(&with(|v| v["disks"][0]["id"] = "x".repeat(21).into()));
        assert!(e.contains("disks[0].id: must be 1..=20 bytes"), "{e}");
        let e = err(&with(|v| v["disks"][0]["format"] = "vmdk".into()));
        assert!(e.contains("unknown variant `vmdk`"), "{e}");
        assert_eq!(DiskFormat::Raw.krun_value(), 0);
        assert_eq!(DiskFormat::Qcow2.krun_value(), 1);
    }

    #[test]
    fn rejects_reserved_and_empty_tags() {
        let e = err(&with(|v| v["shares"][0]["tag"] = ROOT_TAG.into()));
        assert!(e.contains("reserved for rootDir"), "{e}");
        let e = err(&with(|v| v["shares"][0]["tag"] = "".into()));
        assert!(e.contains("shares[0].tag: must not be empty"), "{e}");
    }

    #[test]
    fn checks_resource_bounds() {
        assert!(err(&with(|v| v["vcpus"] = 0.into())).contains("vcpus: must be 1..=32"));
        assert!(err(&with(|v| v["vcpus"] = 33.into())).contains("vcpus: must be 1..=32"));
        assert!(err(&with(|v| v["vcpus"] = 256.into())).contains("invalid run spec"));
        assert!(err(&with(|v| v["memoryMib"] = 63.into())).contains("memoryMib: must be"));
        assert!(err(&with(|v| v["memoryMib"] = 65537.into())).contains("memoryMib: must be"));
        RunSpec::parse(&with(|v| {
            v["vcpus"] = 32.into();
            v["memoryMib"] = 64.into();
        }))
        .unwrap();
    }

    #[test]
    fn rejects_nested_overlay_paths() {
        for path in ["/opt/gino/gino-agent", "gino-agent", "/", "/..", "/a/"] {
            let e = err(&with(|v| v["overlayFiles"][0]["guestPath"] = path.into()));
            assert!(
                e.contains("overlayFiles[0].guestPath: must be /<name>"),
                "{path}: {e}"
            );
        }
        assert_eq!(overlay_name("/gino-agent"), Some("gino-agent"));
    }

    #[test]
    fn rejects_negative_console_fds() {
        let e = err(&with(|v| v["consolePorts"][0]["inFd"] = (-1).into()));
        assert!(
            e.contains("consolePorts[0]: file descriptors must be >= 0"),
            "{e}"
        );
    }

    #[test]
    fn maps_kernel_formats() {
        for (name, value) in [
            ("raw", 0),
            ("elf", 1),
            ("pe_gz", 2),
            ("image_bz2", 3),
            ("image_gz", 4),
            ("image_zstd", 5),
        ] {
            let format: KernelFormat = serde_json::from_value(name.into()).unwrap();
            assert_eq!(format.krun_value(), value, "{name}");
        }
        assert!(serde_json::from_value::<KernelFormat>("bzImage".into()).is_err());
    }

    #[test]
    fn checks_host_paths() {
        let dir = std::env::temp_dir().join(format!("gino-vmm-paths-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("root")).unwrap();
        std::fs::write(dir.join("file"), b"x").unwrap();
        let d = dir.to_str().unwrap();
        let spec_with = |root: &str, overlay: &str, disk: &str| {
            RunSpec::parse(&format!(
                r#"{{"kernel": {{"path": "{d}/file", "format": "elf"}}, "rootDir": "{d}/{root}", "vcpus": 1, "memoryMib": 512, "exec": {{"path": "/bin/true"}},
                    "overlayFiles": [{{"hostPath": "{d}/{overlay}", "guestPath": "/f"}}],
                    "disks": [{{"id": "root", "path": "{d}/{disk}", "format": "raw"}}]}}"#
            ))
            .unwrap()
        };
        let spec = |root: &str, overlay: &str| spec_with(root, overlay, "file");
        spec("root", "file").check_host_paths().unwrap();
        let e = spec_with("root", "file", "root")
            .check_host_paths()
            .unwrap_err();
        assert!(
            e.starts_with("disks.path ") && e.ends_with("not a regular file"),
            "{e}"
        );
        let e = spec("missing", "file").check_host_paths().unwrap_err();
        assert!(
            e.starts_with("rootDir ") && e.contains("No such file"),
            "{e}"
        );
        let e = spec("file", "file").check_host_paths().unwrap_err();
        assert!(e.ends_with("not a directory"), "{e}");
        let e = spec("root", "root").check_host_paths().unwrap_err();
        assert!(e.ends_with("not a regular file"), "{e}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn read_line_stops_at_newline() {
        let mut input: &[u8] = b"{\"a\":1}\nconsole input";
        assert_eq!(read_line(&mut input).unwrap(), "{\"a\":1}");
        assert_eq!(input, b"console input");
        let mut input: &[u8] = b"{}";
        assert_eq!(read_line(&mut input).unwrap(), "{}");
        let mut input: &[u8] = b"\xff\n";
        assert!(read_line(&mut input).unwrap_err().contains("UTF-8"));
        let big = vec![b' '; MAX_SPEC_BYTES + 2];
        assert!(
            read_line(&mut big.as_slice())
                .unwrap_err()
                .contains("exceeds")
        );
    }
}
